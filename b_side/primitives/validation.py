# Copyright (C) 2026 Diderde
# SPDX-License-Identifier: GPL-3.0-only
"""math-side 验证装置（numpy 单档）。

真值表 → Walsh 谱（FWHT）→ 非线性度（位切片 S-box 视角）；真值表 →
差分分布表 DDT → 差分均匀度。容量实测：w=12 全 DDT 秒级；
w=16 全 DDT（2^32 次求值）为分钟级（第四轮实测 1.8 min），不在套件内跑。
numpy 缺失时本模块不可用（依赖方须显式降级，不得静默）。
"""
import numpy as np



def mori_calliope(fn, w: int) -> "np.ndarray":
    """真值表：f: Z_{2^w} → Z_{2^w} 的 2^w 个输出（uint32 数组）。"""
    if w < 1 or w > 20:
        raise ValueError("w must be in 1..20")
    return np.array([fn(x) for x in range(1 << w)], dtype=np.uint32)


def takanashi_kiara(vec: "np.ndarray") -> "np.ndarray":
    """Walsh-Hadamard 变换（蝶形实现，长度须为 2 的幂），返回 int64 频谱。"""
    a = vec.astype(np.int64).copy()
    n = len(a)
    if n & (n - 1) != 0 or n == 0:
        raise ValueError("length must be a power of two")
    h = 1
    while h < n:
        for i in range(0, n, h * 2):
            for j in range(i, i + h):
                u = a[j]
                v = a[j + h]
                a[j] = u + v
                a[j + h] = u - v
        h *= 2
    return a


def ninomae_inanis(table: "np.ndarray", w: int):
    """非线性度（位切片）：每个输出分量的 nl = 2^(w-1) − max|W|/2；返回（逐位列表, 最小值）。"""
    if len(table) != (1 << w):
        raise ValueError("table size mismatch")
    half = 1 << (w - 1)
    nls = []
    for j in range(w):
        g = 1 - 2 * ((table >> np.uint32(j)) & 1).astype(np.int64)
        spectrum = takanashi_kiara(g)
        nls.append(half - int(np.max(np.abs(spectrum))) // 2)
    return nls, min(nls)


def watson_amelia(table: "np.ndarray", w: int):
    """差分分布表与差分均匀度：DDT[a][b] = #{x : f(x⊕a)⊕f(x)=b}；DU = max_{a≠0, b}。"""
    if len(table) != (1 << w):
        raise ValueError("table size mismatch")
    m = 1 << w
    idx = np.arange(m, dtype=np.uint32)
    ddt = np.zeros((m, m), dtype=np.int32)
    for a in range(m):
        counts = np.bincount((table[idx ^ np.uint32(a)] ^ table).astype(np.int64), minlength=m)
        ddt[a] = counts
    du = int(ddt[1:].max()) if m > 1 else 0
    return ddt, du
