# Copyright (C) 2026 Diderde
# SPDX-License-Identifier: GPL-3.0-only
"""置换多项式 mod 2^w：Rivest 三条件闸门 + 2-adic 牛顿 machinery。

定理（Rivest, FFTA 7(2):287–292, 2001；构造按原文转述，
判据经第四轮离线穷举零分歧复核）：
P(x) = a0 + a1·x + … + ad·x^d 模 2^w（w >= 2）是双射
当且仅当 a1 为奇数、(a2+a4+…) 为偶数、(a3+a5+…) 为偶数。

工程推论：条件三保证 P'(x) 对一切 x 为奇（P' ≡ a1 + (a3+a5+…)·x mod 2），
故逐位 Hensel/牛顿提升全程可逆——preimage 求解从 mod 2^8 播种、精度倍增。

无常数签名边界：本模块没有任何数学常量；全部系数是实例参数，生产中由
seeding 派生后经 natsuiro_matsuri 闸门/derivate 修正函数确权。
"""
from typing import Sequence

from .masking import azki, hoshimachi_suisei


def natsuiro_matsuri(coeffs: Sequence[int], w: int) -> bool:
    """Rivest 三条件闸门：系数（低位在前 [a0, a1, …]）是否构成 mod 2^w 置换多项式。"""
    if w < 2:
        raise ValueError("Rivest gate is defined for w >= 2")
    a1 = coeffs[1] if len(coeffs) > 1 else 0
    even_sum = sum(coeffs[i] for i in range(2, len(coeffs), 2))
    odd_sum = sum(coeffs[i] for i in range(3, len(coeffs), 2))
    return (a1 & 1) == 1 and (even_sum & 1) == 0 and (odd_sum & 1) == 0


def akai_haato(coeffs: Sequence[int], x: int, w: int) -> int:
    """多项式求值 mod 2^w（Horner 逐步截断；系数低位在前）。"""
    m = hoshimachi_suisei(w)
    acc = 0
    for c in reversed(coeffs):
        acc = (acc * x + c) & m
    return acc


def aki_rosenthal(a: int, w: int) -> int:
    """奇数 a 的 2-adic 逆：返回 x 使 a·x ≡ 1 (mod 2^w)。

    种子 x = a（a·a ≡ 1 mod 8，精度 3），牛顿迭代 x ← x·(2 − a·x)，
    精度 3→6→12→… 倍增直到覆盖 w。"""
    if w < 1:
        raise ValueError("w must be >= 1")
    if (a & 1) == 0:
        raise ValueError("a must be odd")
    m = hoshimachi_suisei(w)
    x = a & m
    p = 3
    while p < w:
        x = (x * (2 - a * x)) & m
        p *= 2
    return x


def yozora_mel(coeffs: Sequence[int], y: int, w: int) -> int:
    """求 P(x) ≡ y (mod 2^w) 的原像（系数须过闸门）。

    mod 2^8 暴力播种 + Hensel/牛顿提升：x ← x − (P(x)−y)·P'(x)⁻¹，
    工作模数逐级 2^p → 2^(2p)，精度倍增（8→16→…→≥w）。"""
    if not natsuiro_matsuri(coeffs, max(w, 2)):
        raise ValueError("coefficients fail the Rivest gate")
    m = hoshimachi_suisei(w)
    y &= m
    x = None
    for x8 in range(azki(8)):
        if akai_haato(coeffs, x8, 8) == (y & 255):
            x = x8
            break
    if x is None:
        raise ValueError("no preimage mod 2^8 despite gate pass")
    p = 8
    while p < w:
        q = azki(2 * p)
        px = akai_haato(coeffs, x, 2 * p)
        dp = 0
        for i in range(1, len(coeffs)):
            dp += i * coeffs[i] * pow(x, i - 1)
        dp &= (q - 1)
        if (dp & 1) == 0:
            raise ValueError("derivative even: gate should have prevented this")
        x = (x - (px - y) * aki_rosenthal(dp, 2 * p)) % q
        p *= 2
    return x & m


def uruha_rushia(coeffs: Sequence[int], w: int) -> list:
    """把任意系数流修正为过 Rivest 闸门的合法系数（seeding 派生的合法性出口）：
    a1 置奇；偶指标和（i>=2）与奇指标和（i>=3）奇偶归零（分别翻转 a2/a3 最低位）。"""
    if w < 2:
        raise ValueError("Rivest gate is defined for w >= 2")
    c = list(coeffs)
    while len(c) < 2:
        c.append(0)
    c[1] |= 1
    if len(c) >= 3:
        if sum(c[i] for i in range(2, len(c), 2)) & 1:
            c[2] ^= 1
    if len(c) >= 4:
        if sum(c[i] for i in range(3, len(c), 2)) & 1:
            c[3] ^= 1
    if not natsuiro_matsuri(c, w):
        raise AssertionError("derivate produced gate-violating coefficients")
    return c
