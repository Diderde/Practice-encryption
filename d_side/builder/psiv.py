# Copyright (C) 2026 Diderde
# SPDX-License-Identifier: GPL-3.0-only
"""psiv：ChaCha20-Poly1305-PSIV 的 Python 权威实现（容器 v3 分块 AEAD 用）。

按 ePrint 2025/222（Beyne–Chen–Verbauwhede, COSIC；CRYPTO 2026）§3 算法 1–4 与
§3.3 fk/fm/fe 常量布局自实现；官方参考实现（MichielVerbauwhede/ChaCha20-Poly1305-PSIV，
CC0-1.0）用作跨实现 KAT 对照（精神延伸）。零第三方依赖（选材三层为仓内纪律）。

机制（SIV 范式，nonce 误用抵抗 + 密钥承诺，同 ℓ+1 次置换调用）：
  T = φm(K, N, H_L(N ‖ A ‖ pad ‖ M ‖ pad ‖ len))   （标签 = 消息的函数）
  C = M ⊕ keystream(ChaCha20 以 (fe(K), N, T+i) 为状态字)   （标签兼作 IV/计数器）
同 (key, IV) 必同明文 ⇒ 块密钥+IV 复用失效类在结构上不可能（的结构性升级）。

本文件只实现块级原语：调用方（vm_blob v3 路径）以"块序号 nonce + 256B 块明文"为
(消息, 关联数据=空) 使用；域分离由 fk/fm/fe 的常量布局承担（论文原设计）。
"""
import struct

from d_side import chacha20

# 论文 §3.3：ChaCha20 状态 16 字（u32, little-endian 字节序装配）。
# fk/fm/fe 把 32 B 主钥 K = .. 展开到 384 位（12 字），插入 4 个常量字节做
# 域分离；第 13–16 字由调用方填 (N ‖ H/T)（b=96 位 nonce + t=128 位哈希/标签）。
# 布局（字节位）：row1 = .., c, .., c, .., c, , , , c，
# 之后 .. 顺延；c 序列按 fk/fm/fe 分别为 (03,0c,30,c0)/(05,0a,50,a0)/(06,09,60,90)。
_CONST = {
    "k": (0x03, 0x0C, 0x30, 0xC0),
    "m": (0x05, 0x0A, 0x50, 0xA0),
    "e": (0x06, 0x09, 0x60, 0x90),
}
_STATE_WORDS = 16          # ChaCha20 状态字数（512 位）
_KEY_BYTES = 32            # 主钥 256 位
_EXPANDED = 36             # fk/fm/fe 输出（n−t−b = 512−128−96 = 288 位，论文图 3）
_NONCE_BYTES = 12          # b = 96
_TAG_BYTES = 16            # t = 128
_POLY_KEYLEN = 32          # Poly1305 (r, s)


def _expand(kind: str, key: bytes) -> bytes:
    """fk/fm/fe：32 B 主钥 → 48 B 展开钥（论文 §3.3 常量布局逐字节落位）。"""
    if len(key) != _KEY_BYTES:
        raise ValueError("master key must be 32 bytes")
    c1, c2, c3, c4 = _CONST[kind]
    # 逐字节索引（0 基）：.. → 0..2；c → 3；.. → 4..6；c → 7；
    # .. → 8..10；c → 11； → 12； → 13； → 14；c → 15；.. → 16..35
    out = bytearray(_EXPANDED)
    out[0:3] = key[0:3]
    out[3] = c1
    out[4:7] = key[4:7]
    out[7] = c2
    out[8:11] = key[8:11]
    out[11] = c3
    out[12] = key[3]
    out[13] = key[7]
    out[14] = key[11]
    out[15] = c4
    out[16:36] = key[12:32]              # ..
    return bytes(out)


def _perm(block: bytes) -> bytes:
    """裸 ChaCha20 置换 π：64 B 输入按 u32le 装配 16 字 → 20 轮 → feed-forward。

    论文的 π 是任意 512 位置换；ChaCha20 的标准"加密"路径（常量字+钥+计数+nonce 的
    状态装配）不适用，故在此实现裸置换（四分一轮函数与 RFC 8439 §2.3 一致）。"""
    if len(block) != 64:
        raise ValueError("permutation input must be 64 bytes")
    st = list(struct.unpack("<16I", block))

    def qr(a, b, c, d):
        def add(x, y):
            return (x + y) & 0xFFFFFFFF
        st[a] = add(st[a], st[b]); st[d] ^= st[a]; st[d] = ((st[d] << 16) | (st[d] >> 16)) & 0xFFFFFFFF
        st[c] = add(st[c], st[d]); st[b] ^= st[c]; st[b] = ((st[b] << 12) | (st[b] >> 20)) & 0xFFFFFFFF
        st[a] = add(st[a], st[b]); st[d] ^= st[a]; st[d] = ((st[d] << 8) | (st[d] >> 24)) & 0xFFFFFFFF
        st[c] = add(st[c], st[d]); st[b] ^= st[c]; st[b] = ((st[b] << 7) | (st[b] >> 25)) & 0xFFFFFFFF

    for _ in range(10):                  # 20 轮 = 10 次双轮
        qr(0, 4, 8, 12); qr(1, 5, 9, 13); qr(2, 6, 10, 14); qr(3, 7, 11, 15)
        qr(0, 5, 10, 15); qr(1, 6, 11, 12); qr(2, 7, 8, 13); qr(3, 4, 9, 14)
    init = struct.unpack("<16I", block)
    out = [(a + b) & 0xFFFFFFFF for a, b in zip(st, init)]
    return struct.pack("<16I", *out)


def _phi(kind: str, key: bytes, tail: bytes) -> bytes:
    """φx(K, tail) = π(fx(K) ‖ tail) + (fx(K) ‖ tail)（截到 tag 长）。

    KAT 修正：论文公式的"+"就是参考实现 chacha20_core **内置的**
    feed-forward——本文件 _perm 已含该次加法，这里不得再加（首版双重加法，
    跨实现 KAT 抓获）。"""
    return _perm(_expand(kind, key) + tail)[:_TAG_BYTES]


def _poly1305(key: bytes, ad: bytes, msg: bytes) -> bytes:
    """Poly1305（RFC 8439 §2.5 语义——判别实验实锤与 RustCrypto poly1305 v0.8 一致）。

    KAT 复核记录：update_padded 的部分块 = 零垫到 16 B 后整体 +2^128
    （候选 A 判别实验：单字节 0xAB 输入，A 中 B/C 落选）。每段（ad/msg）独立零垫，
    长度块为全块同样 +2^128。（中途误改 B/C 语义两版，KAT 全程把关）"""
    if len(key) != _POLY_KEYLEN:
        raise ValueError("poly1305 key must be 32 bytes")
    r = int.from_bytes(key[:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(key[16:], "little")
    p = (1 << 130) - 5

    def pad(x: bytes) -> bytes:
        return b"\x00" * ((-len(x)) % 16)

    stream = ad + pad(ad) + msg + pad(msg) + struct.pack("<QQ", len(ad), len(msg))
    acc = 0
    for i in range(0, len(stream), 16):
        n = int.from_bytes(stream[i:i + 16], "little") + (1 << 128)
        acc = (acc + n) * r % p
    return ((acc + s) & ((1 << 128) - 1)).to_bytes(16, "little")


def _poly_key(key: bytes) -> bytes:
    """H 的静态密钥 L = φk(K)（论文 §3：trunc_k(π(fk(K)‖0²⁸) + fk(K)‖0²⁸)）。

    KAT 修正：①"+"是 chacha20_core 内置 feed-forward，_perm 已含，
    不得再加（首版双重加法）；②更早一版误用 fk(K) 原始字节（漏整个置换）——两坑
    均由跨实现 KAT 抓获。"""
    return _perm(_expand("k", key) + b"\x00" * 28)[:_POLY_KEYLEN]


def mac(key: bytes, nonce: bytes, aad: bytes, msg: bytes) -> bytes:
    """Algorithm 1：T = φm(K, N, H_L(ad ‖ msg ‖ len))。"""
    if len(nonce) != _NONCE_BYTES:
        raise ValueError("nonce must be 12 bytes")
    h = _poly1305(_poly_key(key), aad, msg)
    return _phi("m", key, nonce + h)[:_TAG_BYTES]


def keystream_block(key: bytes, nonce: bytes, tag: bytes, counter: int) -> bytes:
    """φe(K, N, T+i)：**全宽 64 B**（论文 Algorithm 2——φe 作密钥流不截断；截断的只有
    φm→tag 与 φk→poly key。KAT 修正 [日期略]：_phi 统一截 16 后密钥流短了 48 B，
    32 B 消息后半裸奔（v2 抓获）。"""
    if len(tag) != _TAG_BYTES:
        raise ValueError("tag must be 16 bytes")
    t_plus = (int.from_bytes(tag, "little") + counter) % (1 << 128)
    return _perm(_expand("e", key) + nonce + t_plus.to_bytes(16, "little"))


def encrypt_aead(key: bytes, nonce: bytes, aad: bytes, plaintext: bytes) -> tuple:
    """Algorithm 3 全形（KAT 对照用）：aad 可非空；块级调用走 encrypt_block（aad 空）。"""
    tag = mac(key, nonce, aad, plaintext)
    out = bytearray()
    for i in range(0, len(plaintext), 64):
        ks = keystream_block(key, nonce, tag, i // 64)
        chunk = plaintext[i:i + 64]
        out.extend(a ^ b for a, b in zip(chunk, ks))
    return bytes(out), tag


def decrypt_aead(key: bytes, nonce: bytes, aad: bytes, ciphertext: bytes, tag: bytes) -> bytes:
    """Algorithm 4 全形。"""
    out = bytearray()
    for i in range(0, len(ciphertext), 64):
        ks = keystream_block(key, nonce, tag, i // 64)
        chunk = ciphertext[i:i + 64]
        out.extend(a ^ b for a, b in zip(chunk, ks))
    if mac(key, nonce, aad, bytes(out)) != tag:
        raise ValueError("PSIV tag mismatch")
    return bytes(out)


def encrypt_block(key: bytes, nonce: bytes, plaintext: bytes) -> tuple:
    """Algorithm 3（块级便捷形，aad 恒空——调用方域分离在 nonce）。"""
    return encrypt_aead(key, nonce, b"", plaintext)


def decrypt_block(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes) -> bytes:
    """Algorithm 4（块级便捷形）：tag 不符抛 ValueError（boot 侧映射为 exit 3）。"""
    return decrypt_aead(key, nonce, b"", ciphertext, tag)
