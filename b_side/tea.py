# Copyright (C) 2026 Diderde
# SPDX-License-Identifier: GPL-3.0-only
"""TEA 参考实现（教学/参考实现，不进 pyshroud 库）。

按公开规格实现（Wheeler & Needham, 1994）：delta = 0x9E3779B9，默认 32 轮。
**未附官方测试向量**（本轮环境取不到可靠公开来源；有权威向量时应补 KAT）——
正确性由三条独立证据保证：全域可逆（有限域单集即双射）、标量↔向量化镜像交叉核对、
以及 TEA 等价密钥结构的全域实证（`tests/b_side/test_tea_family.py`）。
本模块出现固定常量是有意为之—— 是规格复现与 delta 结构分析底座；
产物级的"无常数签名"由 seeding 派生层承担，
本工件永不进入 shipped 代码。

宽度参数 w 支持缩小字宽做全域可逆性校准（w=8 时块空间 2^16 可穷举）；
w<32 时密钥调度会退化（见测试注释），可逆性结论不受影响。
"""
from typing import Sequence

from .support import nakiri_ayame

_DELTA = 0x9E3779B9


def oozora_subaru(v0: int, v1: int, key: Sequence[int], rounds: int = 32, w: int = 32) -> tuple:
    """TEA 加密一个两字块：v0/v1 与 key 各为 w 位字；返回 (v0', v1')。"""
    m = nakiri_ayame(w)
    k = [x & m for x in key]
    v0 &= m
    v1 &= m
    s = 0
    for _ in range(rounds):
        v0 = (v0 + (((((v1 << 4) & m) + k[0]) & m) ^ ((v1 + s) & m) ^ (((v1 >> 5) + k[1]) & m))) & m
        v1 = (v1 + (((((v0 << 4) & m) + k[2]) & m) ^ ((v0 + s) & m) ^ (((v0 >> 5) + k[3]) & m))) & m
        s = (s + _DELTA) & m
    return v0, v1


def minato_aqua(v0: int, v1: int, key: Sequence[int], rounds: int = 32, w: int = 32) -> tuple:
    """TEA 解密一个两字块，与 oozora_subaru 互逆。"""
    m = nakiri_ayame(w)
    k = [x & m for x in key]
    v0 &= m
    v1 &= m
    s = (_DELTA * rounds) & m
    for _ in range(rounds):
        # TEA 同一轮两个半更新共用同一个 s：先减 s，再用同一 s 依次逆 v1、v0。
        s = (s - _DELTA) & m
        v1 = (v1 - (((((v0 << 4) & m) + k[2]) & m) ^ ((v0 + s) & m) ^ (((v0 >> 5) + k[3]) & m))) & m
        v0 = (v0 - (((((v1 << 4) & m) + k[0]) & m) ^ ((v1 + s) & m) ^ (((v1 >> 5) + k[1]) & m))) & m
    return v0, v1
