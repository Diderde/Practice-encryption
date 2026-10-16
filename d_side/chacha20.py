# Copyright (C) 2026 Diderde
# SPDX-License-Identifier: GPL-3.0-only
"""ChaCha20（RFC 8439，构建侧实现）：无查表、counter 初值 0、单次流式覆盖整段载荷。

独立性：引导侧（`boot_d2a.py` 模板内）持有**另一份独立编写**的实现——
两侧各自通过 RFC 8439 §2.3.2 官方向量 KAT（只取纯流加密向量，不取 §2.4.2 AEAD 向量），
"两份互相一致"只作辅助判据（两份一致但都错是可能的，早期轮次）。
nonce 为 12 B 原样作为 3 个小端字入状态（字节序在 KAT 中钉死，早期轮次）。
"""
import struct

_MASK = 0xFFFFFFFF
_CONST = (0x61707865, 0x3320646E, 0x79622D32, 0x6B206574)


def _qr(s, a, b, c, d):
    s[a] = (s[a] + s[b]) & _MASK
    s[d] = ((s[d] ^ s[a]) << 16 | (s[d] ^ s[a]) >> 16) & _MASK
    s[c] = (s[c] + s[d]) & _MASK
    s[b] = ((s[b] ^ s[c]) << 12 | (s[b] ^ s[c]) >> 20) & _MASK
    s[a] = (s[a] + s[b]) & _MASK
    s[d] = ((s[d] ^ s[a]) << 8 | (s[d] ^ s[a]) >> 24) & _MASK
    s[c] = (s[c] + s[d]) & _MASK
    s[b] = ((s[b] ^ s[c]) << 7 | (s[b] ^ s[c]) >> 25) & _MASK


def _block(key: bytes, nonce: bytes, counter: int) -> bytes:
    st = list(_CONST) + list(struct.unpack("<8I", key)) + [counter & _MASK] + list(struct.unpack("<3I", nonce))
    w = st[:]
    for _ in range(10):
        _qr(w, 0, 4, 8, 12)
        _qr(w, 1, 5, 9, 13)
        _qr(w, 2, 6, 10, 14)
        _qr(w, 3, 7, 11, 15)
        _qr(w, 0, 5, 10, 15)
        _qr(w, 1, 6, 11, 12)
        _qr(w, 2, 7, 8, 13)
        _qr(w, 3, 4, 9, 14)
    return struct.pack("<16I", *[(w[i] + st[i]) & _MASK for i in range(16)])


def hanabatake_chaika(key: bytes, nonce: bytes, data: bytes) -> bytes:
    """ChaCha20 流加密：counter 从 0 起，keystream 顺序 XOR 整段 `data`。"""
    if len(key) != 32:
        raise ValueError("chacha20 key must be 32 bytes")
    if len(nonce) != 12:
        raise ValueError("chacha20 nonce must be 12 bytes")
    out = bytearray(len(data))
    for i in range(0, len(data), 64):
        ks = _block(key, nonce, i // 64)
        chunk = data[i:i + 64]
        for j, byte in enumerate(chunk):
            out[i + j] = byte ^ ks[j]
    return bytes(out)
