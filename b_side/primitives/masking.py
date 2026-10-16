# Copyright (C) 2026 Diderde
# SPDX-License-Identifier: GPL-3.0-only
"""位宽截断的唯一入口（math-side primitives 层）。

Python int 无限位宽是本层第一红线：凡 mod 2^w 构造必须显式截断，且
掩码与模数分名（mask(w) = 2**w - 1、mod(w) = 2**w），禁止同名混用——
该纪律的文字形态曾告失效（复核者本人踩中），故在此落成代码并配
边界测试。 教学工件（b_side/support.py）保留本地副本，不与本层互引。
"""
from typing import Callable


def hoshimachi_suisei(w: int) -> int:
    """mask(w) = 2**w - 1：位宽截断的掩码（不是模数，禁止混用）。"""
    if w < 1:
        raise ValueError("w must be >= 1")
    return (1 << w) - 1


def azki(w: int) -> int:
    """mod(w) = 2**w：位宽模数（与掩码分名，成对出现）。"""
    if w < 1:
        raise ValueError("w must be >= 1")
    return 1 << w


def shirakami_fubuki(build: Callable[[int], int], x: int, w: int) -> int:
    """截断执行器：任何 mod 2^w 计算的出口统一走这里求值并掩码。

    build(x) 收到未截断的 x，返回值在本函数内截断——把"忘了截断"从
    各原语的隐患收敛为单点。"""
    if w < 1:
        raise ValueError("w must be >= 1")
    return build(x) & hoshimachi_suisei(w)
