# Copyright (C) 2026 Diderde
# SPDX-License-Identifier: GPL-3.0-only
"""keys：HKDF-SHA256 派生 + nonce 派生 + seed 熵闸门 + 拓扑调度。

域分离（存 seed ⇒ 引导侧必须现场重派生，故标签随产物可见）：
enc 标签 = bytes([sched_id, 0x01])，mac 标签 = bytes([sched_id, 0x02])——中性字节，逐拓扑不同。
两次独立 Expand、各 32 B、显式长度（早期轮次：禁一次取 64 B 对切）。
拓扑（满配 8，0.0.40 起 3 bit 恰好映射 8 拓扑）：差异承载于 **salt 构造 + 标签字节**；串联模加不做任何
"独立性/概率相乘"强度论证（红线，文献综述）。
seed 熵闸门：本模块自带三档阈值，**不触碰** `pyshroud/seeding/derive.py` 共享常量。
"""
import hashlib
import hmac
import time

_MASK256 = (1 << 256) - 1
#  三档（原生产物侧自带，不复用 源码混淆侧 48 位常量）
_MIN_BITS = 128
_REC_BITS = 256


def _extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def _expand(prk: bytes, info: bytes, length: int) -> bytes:
    out = b""
    block = b""
    counter = 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


def ryushen(seed: bytes) -> int:
    """(seed) → 拓扑 id ∈ {1..8}（满配 8，0.0.40）。seed 低 3 bit 确定性选择—— 锚不变（同 seed ⇒ 同拓扑）。

    覆盖口径：3 bit 恰好 8 个值 ⇒ 均匀 1/8 × 8（6 拓扑时代的 2/8 偏斜分布随满配消失；
    ryushen 重映射是预期后果——同 seed 的拓扑选择会变，早期轮次 同款处置，非漂移）。"""
    if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    return (int.from_bytes(seed, "big") & 7) % 8 + 1


def _rivest_mix(seed: bytes, nonce: bytes) -> bytes:
    """Rivest 置换多项式 mod 2^256（三条件：a1 奇、a2 偶、a3 偶 ⇒ 双射；文献整理）。

    系数全部由 seed 派生并按条件强制；输入取 nonce 整数。输出 32 B BE。"""
    s = int.from_bytes(seed, "big")
    a0 = s & _MASK256
    a1 = ((s >> 8) | 1) & _MASK256            # 奇
    a2 = ((s >> 16) & (_MASK256 ^ 1)) & _MASK256  # 偶
    a3 = ((s >> 24) & (_MASK256 ^ 1)) & _MASK256  # 偶
    n = int.from_bytes(nonce, "big")
    return (a0 + a1 * n + a2 * n * n + a3 * n ** 3) & _MASK256


def _tfunc_mix(seed: bytes, nonce: bytes) -> bytes:
    """Klimov-Shamir T-函数局部搅动：x ← x + ((x²) | 5) mod 2^256，4 轮。

    仅作局部原子（不作整轮函数——Mitra-Sarkar 攻击边界，文献整理）。"""
    x = int.from_bytes(seed, "big") ^ int.from_bytes(nonce + nonce, "big")
    for _ in range(4):
        x = (x + ((x * x) | 5)) & _MASK256
    return x


def _feistel3_mix(seed: bytes, nonce: bytes) -> bytes:
    """Luby-Rackoff 3 轮 Feistel（拓扑 4；结构级新原子，骨架首选）。

    轮函数 F_i(x) = k_i + x (mod 2^128)，k_i 由 seed 8 字节行加倍派生——
    Luby–Rackoff 定理：3 轮 Feistel 对**任意**轮函数都是置换（无条件双射，
    闸门只需小位宽穷举确认实现镜像，不需要 F 的任何条件）。"""
    v = bytes(seed[i] ^ nonce[i % 12] for i in range(32))
    l = int.from_bytes(v[:16], "big")
    r = int.from_bytes(v[16:], "big")
    hm = (1 << 128) - 1
    for i in range(3):
        k = int.from_bytes(seed[8 * i:8 * i + 8] * 2, "big")
        t = (k + r) & hm
        l, r = r, l ^ t
    return (l << 128 | r).to_bytes(32, "big")


def _arx_cascade_mix(seed: bytes, nonce: bytes) -> bytes:
    """ARX 级联（拓扑 5）：rotate ⊕ mask + add mask × 4 轮。

    每步（旋转/异或常数/加常数）均为 Z₂²⁵⁶ 上的双射 ⇒ 复合双射（无条件，
    与掩码取值无关）；结构与多项式/T-函数族不同（ARX 形态）。"""
    m = _MASK256
    v = int.from_bytes(nonce, "big")
    for i in range(4):
        r = (seed[4 * i] % 255) + 1
        mk = int.from_bytes(seed[8 * i:8 * i + 8] * 4, "big")
        v = (((v << r) | (v >> (256 - r))) ^ mk) & m
        v = (v + mk) & m
    return v.to_bytes(32, "big")


def _anashin_ergodic_mix(seed: bytes, nonce: bytes) -> bytes:
    """Anashin 遍历变换（拓扑 6；Corollary 1 直用，arXiv:1111.3093）。

    f(x) = 1 + x + 2·Δg(x)，Δg(x) = g(x+1) − g(x)，g(x) = x + ((x² | c) mod 2²⁵⁶)
    为 T-函数（x² 三角性）⇒ f 在 Z₂²⁵⁶ 上**遍历（传递）**——比双射更强，
    定理级保证，与 g 的常数取值无关。"""
    m = _MASK256
    v = int.from_bytes(seed, "big") ^ int.from_bytes(nonce, "big")
    c = (int.from_bytes(seed[:4], "big") | 1) & 0xFFFFFFFF

    def g(x: int) -> int:
        return (x + ((x * x | c) & m)) & m

    dg = (g((v + 1) & m) - g(v)) & m
    return ((1 + v + 2 * dg) & m).to_bytes(32, "big")


def _oddscale_mix(seed: bytes, nonce: bytes) -> bytes:
    """乘法级联（拓扑 6）：×奇数（mod 2²⁵⁶ 双射）⊕ 掩码 + 掩码 × 3 轮。

    每步均为 Z₂²⁵⁶ 双射（乘奇数/异或常数/加常数）⇒ 复合双射（无条件）；
    乘法尺度形态与 ARX/多项式/T-函数族结构不同。
    （曾按 Anashin Corollary 1 试过 f = 1 + x + 2Δg 遍历变换——小位宽穷举
    3/5 实例非传递，未过闸门即弃）"""
    m = _MASK256
    v = int.from_bytes(nonce, "big") ^ int.from_bytes(seed, "big")
    for i in range(3):
        odd = (int.from_bytes(seed[8 * i:8 * i + 8] * 4, "big") | 1) & m
        xk = int.from_bytes(seed[8 * ((i + 1) % 4):8 * ((i + 1) % 4) + 8] * 4, "big")
        ak = int.from_bytes(seed[8 * ((i + 2) % 4):8 * ((i + 2) % 4) + 8] * 4, "big")
        v = (v * odd) & m
        v ^= xk
        v = (v + ak) & m
    return v.to_bytes(32, "big")


def _pairswap_mix(seed: bytes, nonce: bytes) -> bytes:
    """swap-or-not 配对对合（拓扑 7；货架"Thorp shuffle/swap-or-not"，文献整理）。

    每轮：Z = v ⊕ k_i；配对 π(Z) = 128-bit 半交换（无不动点对合，π² = id）；
    决策位 = (规范代表元 a = min(Z, π(Z)) ⊕ k_i) 的最低位——**配对两侧算出同一
    位**，故整对要么同换要么同留，择一映射 τ 是对合；轮 = (⊕k_i) ∘ τ ∘ (⊕k_i)
    为对合的共轭 ⇒ 对合 ⇒ 双射。**精确论证**，无概率/独立性声明。
    （初版按 f(Z)/f(π(Z)) 大小比较择一——决策对配对两侧不对称，两侧可同映射
    到同一点、非对合非双射，w=16 穷举 3 万碰撞被闸门当场抓获后改规范代表元
    形态）4 轮、逐轮 k_i。"""
    m = _MASK256
    hm = (1 << 128) - 1
    v = int.from_bytes(nonce, "big") ^ int.from_bytes(seed, "big")
    for i in range(4):
        k = int.from_bytes(seed[8 * i:8 * i + 8] * 4, "big") & m
        z = v ^ k
        p = ((z & hm) << 128) | (z >> 128)
        canonical = z if z <= p else p
        v = (p if (canonical ^ k) & 1 else z) ^ k
    return v.to_bytes(32, "big")


def _laimassey_mix(seed: bytes, nonce: bytes) -> bytes:
    """Lai–Massey 纤维平移（拓扑 8；IDEA/Fox 骨架族，整态经异或差更新，
    与半更新的 Feistel 异形）。

    轮：a = L ⊕ R；F_i(a) = a + k_i (mod 2¹²⁸)；L' = L ⊕ F_i(a)、R' = R ⊕ F_i(a)
    ——输出的半异或 L' ⊕ R' = a 不变、纤维内映射是平移 ⇒ **精确双射**（与 F
    无关，无概率论证）；轮间插半交换 + 单半加奇常数（各自精确双射）打断
    L⊕R 纤维不变量。3 轮。"""
    m = _MASK256
    hm = (1 << 128) - 1
    v = int.from_bytes(nonce, "big") ^ int.from_bytes(seed, "big")
    l, r = v >> 128, v & hm
    for i in range(3):
        a = (l ^ r) & hm
        f = (a + int.from_bytes(seed[8 * i:8 * i + 8] * 2, "big")) & hm
        l = (l ^ f) & hm
        r = (r ^ f) & hm
        l, r = (r + (int.from_bytes(seed[8 * ((i + 1) % 4):8 * ((i + 1) % 4) + 8] * 2, "big") | 1)) & hm, l
    return ((l << 128) | r).to_bytes(32, "big")


def _schedule_salt(seed: bytes, nonce: bytes, sched_id: int) -> bytes:
    if sched_id == 1:
        return nonce
    if sched_id == 2:
        return nonce + _rivest_mix(seed, nonce).to_bytes(32, "big")
    if sched_id == 3:
        return nonce + _tfunc_mix(seed, nonce).to_bytes(32, "big")
    if sched_id == 4:
        return nonce + _feistel3_mix(seed, nonce)
    if sched_id == 5:
        return nonce + _arx_cascade_mix(seed, nonce)
    if sched_id == 6:
        return nonce + _oddscale_mix(seed, nonce)
    if sched_id == 7:
        return nonce + _pairswap_mix(seed, nonce)
    if sched_id == 8:
        return nonce + _laimassey_mix(seed, nonce)
    raise ValueError("unknown schedule id: %r" % (sched_id,))


def kanae(seed: bytes, nonce: bytes, sched_id: int) -> tuple:
    """(seed, nonce, 拓扑) → (payload_key, mac_key)，各 32 B、相互独立。"""
    if sched_id not in (1, 2, 3, 4, 5, 6, 7, 8):
        raise ValueError("unknown schedule id: %r" % (sched_id,))
    prk = _extract(_schedule_salt(seed, nonce, sched_id), seed)
    enc = _expand(prk, bytes([sched_id, 0x01]), 32)
    mac = _expand(prk, bytes([sched_id, 0x02]), 32)
    return enc, mac


def akabane_youko(seed: bytes, payload_digest: bytes) -> bytes:
    """(seed, 载荷明文摘要) → 12 B nonce。构建侧专用；**拒绝外部指定**。"""
    return _expand(_extract(payload_digest, seed), b"nonce\x01", 12)


def sasaki_saku(seed: bytes) -> tuple:
    """seed 熵闸门（三档）→ (ok, message)。

    < 128 位 ⇒ (False, 拒因)；128–255 位 ⇒ (True, 告警)；≥ 256 位 ⇒ (True, None)。
    判"可证明的熵上界"（位长 + 时间戳形态），不做"看起来随机"黑名单（与 源码混淆侧同纪律）。"""
    if not isinstance(seed, (bytes, bytearray)) or len(seed) == 0:
        return False, "seed must be non-empty bytes"
    n = int.from_bytes(seed, "big")
    bits = n.bit_length()
    if bits < _MIN_BITS:
        return False, ("seed has only %d bits of entropy (need >= %d); "
                       "a small seed space lets an attacker rebuild every candidate artifact offline"
                       % (bits, _MIN_BITS))
    if seed[:16] == b"\x00" * 16:
        tail = int.from_bytes(seed[16:], "big")
        # 滚动怀疑窗（早期轮次 修复）：上界随当前日期滚动，固定上界会随日历过期失效
        hi_ms = int((time.time() + 400 * 86400) * 1000)
        if 1_577_836_800 <= tail <= hi_ms // 1000:
            return True, ("seed low bytes look like a Unix timestamp (seconds); "
                          "real entropy is far below the bit length")
        if 1_577_836_800_000 <= tail <= hi_ms:
            return True, ("seed low bytes look like a Unix timestamp (milliseconds); "
                          "real entropy is far below the bit length")
    if bits < _REC_BITS:
        return True, ("seed has %d bits of entropy (128-255 tier): usable, "
                      "but the recommended tier is >= 256 bits" % bits)
    return True, None
