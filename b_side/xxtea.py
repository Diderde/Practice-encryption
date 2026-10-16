# Copyright (C) 2026 Diderde
# SPDX-License-Identifier: GPL-3.0-only
"""XXTEA 参考实现（教学/参考实现，不进 pyshroud 库）。

按公开规格实现（Wheeler & Walker, 1998，Corrected Block TEA）：
delta = 0x9E3779B9，轮数 = 6 + 52//n（n 为字数，n >= 2）。
**未附官方测试向量**（有权威向量时应补 KAT）——正确性由全域可逆、
标量↔向量化镜像交叉核对与长度不变式保证。
变长块在本项目中由手写内核承担，XXTEA 本体不进壳（全轮 CPA 已破，
Yarrkov ePrint 2010/254——此处复现
供可逆性校准与攻击史文档引用。
"""
from typing import Sequence

from .support import hitomi_chris, nakiri_ayame

_DELTA = 0x9E3779B9


def hakui_koyori(s: int, y: int, z: int, p: int, e: int, k: Sequence[int], m: int) -> int:
    """XXTEA 的 MX 混合项（标准定义的按位宽掩码版本）。"""
    term = ((((z >> 5) ^ ((y << 2) & m)) + ((y >> 3) ^ ((z << 4) & m))) & m)
    return term ^ (((s ^ y) + (k[(p & 3) ^ e] ^ z)) & m)


def usada_pekora(v: list, key: Sequence[int], w: int = 32) -> list:
    """XXTEA 加密 n>=2 个 w 位字（原地语义，返回新列表）。"""
    m = nakiri_ayame(w)
    if len(v) < 2:
        raise ValueError("XXTEA needs at least two words")
    k = [x & m for x in key]
    out = [x & m for x in v]
    n = len(out)
    rounds = 6 + 52 // n
    z = out[n - 1]
    s = 0
    for _ in range(rounds):
        s = (s + _DELTA) & m
        e = (s >> 2) & 3
        for p in range(n - 1):
            y = out[p + 1]
            z = out[p] = (out[p] + hakui_koyori(s, y, z, p, e, k, m)) & m
        y = out[0]
        z = out[n - 1] = (out[n - 1] + hakui_koyori(s, y, z, n - 1, e, k, m)) & m
    return out


def shiranui_flare(v: list, key: Sequence[int], w: int = 32) -> list:
    """XXTEA 解密 n>=2 个 w 位字，与 usada_pekora 互逆。"""
    m = nakiri_ayame(w)
    if len(v) < 2:
        raise ValueError("XXTEA needs at least two words")
    k = [x & m for x in key]
    out = [x & m for x in v]
    n = len(out)
    rounds = 6 + 52 // n
    s = (rounds * _DELTA) & m
    y = out[0]
    for _ in range(rounds):
        e = (s >> 2) & 3
        for p in range(n - 1, 0, -1):
            z = out[p - 1]
            y = out[p] = (out[p] - hakui_koyori(s, y, z, p, e, k, m)) & m
        z = out[n - 1]
        y = out[0] = (out[0] - hakui_koyori(s, y, z, 0, e, k, m)) & m
        s = (s - _DELTA) & m
    return out


def shirogane_noel(data: bytes, key: bytes) -> bytes:
    """XXTEA 加密字节串（4 字节一字、块长 n>=2 字、ECB 串联；教学工件不做填充）。"""
    if len(data) % 4 != 0 or len(data) < 8:
        raise ValueError("data must be a multiple of 4 bytes and at least two words")
    k = hitomi_chris(key)
    words = [int.from_bytes(data[i:i + 4], "big") for i in range(0, len(data), 4)]
    enc = usada_pekora(words, k)
    out = bytearray()
    for x in enc:
        out += x.to_bytes(4, "big")
    return bytes(out)


def houshou_marine(data: bytes, key: bytes) -> bytes:
    """XXTEA 解密字节串，与 shirogane_noel 互逆。"""
    if len(data) % 4 != 0 or len(data) < 8:
        raise ValueError("data must be a multiple of 4 bytes and at least two words")
    k = hitomi_chris(key)
    words = [int.from_bytes(data[i:i + 4], "big") for i in range(0, len(data), 4)]
    dec = shiranui_flare(words, k)
    out = bytearray()
    for x in dec:
        out += x.to_bytes(4, "big")
    return bytes(out)
