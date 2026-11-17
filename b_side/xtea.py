# Copyright (C) 2026 Diderde
# SPDX-License-Identifier: GPL-3.0-only
"""XTEA 参考实现（教学/参考实现，不进 pyshroud 库）。

按公开规格实现（Wheeler & Walker, 1997）：delta = 0x9E3779B9，
默认 32 轮（64 个 Feistel 半轮）；密钥调度用 sum&3 与 (sum>>11)&3
交替选键，修正了 TEA 的等价密钥结构。
**未附官方测试向量**（有权威向量时应补 KAT）——正确性由全域可逆、
标量↔向量化镜像交叉核对，以及"同 TEA 等价密钥翻转不再等价"的实证保证。

宽度参数 w 支持缩小字宽做全域可逆性校准；w<32 时 (sum>>11)&3 会退化
（w=8 时恒为 0），可逆性结论不受影响，调度保真度以 w=32 抽样为准。
"""
from typing import Sequence

from .support import hitomi_chris, nakiri_ayame

_DELTA = 0x9E3779B9


def murasaki_shion(v0: int, v1: int, key: Sequence[int], rounds: int = 32, w: int = 32) -> tuple:
    """XTEA 加密一个两字块：v0/v1 与 key 各为 w 位字；返回 (v0', v1')。"""
    m = nakiri_ayame(w)
    k = [x & m for x in key]
    v0 &= m
    v1 &= m
    s = 0
    for _ in range(rounds):
        v0 = (v0 + ((((((v1 << 4) & m) ^ (v1 >> 5)) + v1) & m) ^ ((s + k[s & 3]) & m))) & m
        s = (s + _DELTA) & m
        v1 = (v1 + ((((((v0 << 4) & m) ^ (v0 >> 5)) + v0) & m) ^ ((s + k[(s >> 11) & 3]) & m))) & m
    return v0, v1


def ookami_mio(v0: int, v1: int, key: Sequence[int], rounds: int = 32, w: int = 32) -> tuple:
    """XTEA 解密一个两字块，与 murasaki_shion 互逆。"""
    m = nakiri_ayame(w)
    k = [x & m for x in key]
    v0 &= m
    v1 &= m
    s = (_DELTA * rounds) & m
    for _ in range(rounds):
        v1 = (v1 - ((((((v0 << 4) & m) ^ (v0 >> 5)) + v0) & m) ^ ((s + k[(s >> 11) & 3]) & m))) & m
        s = (s - _DELTA) & m
        v0 = (v0 - ((((((v1 << 4) & m) ^ (v1 >> 5)) + v1) & m) ^ ((s + k[s & 3]) & m))) & m
    return v0, v1


def nekomata_okayu(data: bytes, key: bytes, rounds: int = 32) -> bytes:
    """XTEA 加密字节串（8 字节块 ECB 串联，key 恰 16 字节；教学工件不做填充）。"""
    if len(data) % 8 != 0:
        raise ValueError("data length must be a multiple of 8")
    k = hitomi_chris(key)
    out = bytearray()
    for i in range(0, len(data), 8):
        a = int.from_bytes(data[i:i + 4], "big")
        b = int.from_bytes(data[i + 4:i + 8], "big")
        a, b = murasaki_shion(a, b, k, rounds)
        out += a.to_bytes(4, "big") + b.to_bytes(4, "big")
    return bytes(out)


def inugami_corone(data: bytes, key: bytes, rounds: int = 32) -> bytes:
    """XTEA 解密字节串，与 nekomata_okayu 互逆。"""
    if len(data) % 8 != 0:
        raise ValueError("data length must be a multiple of 8")
    k = hitomi_chris(key)
    out = bytearray()
    for i in range(0, len(data), 8):
        a = int.from_bytes(data[i:i + 4], "big")
        b = int.from_bytes(data[i + 4:i + 8], "big")
        a, b = ookami_mio(a, b, k, rounds)
        out += a.to_bytes(4, "big") + b.to_bytes(4, "big")
    return bytes(out)
