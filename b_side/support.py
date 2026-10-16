# Copyright (C) 2026 Diderde
# SPDX-License-Identifier: GPL-3.0-only
"""math-side 支撑件：密钥字装载与位宽纪律（掩码/模数分名）的唯一入口。

函数名取自项目命名池，语义以 docstring 为准。
"""


def hitomi_chris(data: bytes, w: int = 32) -> list:
    """把 4*w/8 字节按大端装载为 4 个 w 位字（TEA 家族 128 位密钥）。"""
    step = w // 8
    if len(data) != 4 * step:
        raise ValueError("key must be exactly 4 words of w bits")
    return [int.from_bytes(data[i * step:(i + 1) * step], "big") for i in range(4)]


def nakiri_ayame(w: int) -> int:
    """mask(w) = 2**w - 1：位宽截断的掩码（不是模数，禁止混用）。"""
    return (1 << w) - 1


def yuzuki_choco(w: int) -> int:
    """mod(w) = 2**w：位宽模数（与掩码分名，成对出现）。"""
    return 1 << w
