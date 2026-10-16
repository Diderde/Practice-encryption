# Copyright (C) 2026 Diderde
# SPDX-License-Identifier: GPL-3.0-only
"""不透明谓词工厂（收尾切片）。

强度边界：
  - 数论式（负 Pell）与 Collatz 式的具体实例**可直接求值**，静态即可常量折叠——
    定位为**防手工阅读**，不计入强度阶梯；
  - 强度只挂**动态关联式**（真值依赖运行时状态的不变量）。

数论材料（数学原语）：x² − D·y² = −1 有整数解 ⟺ √D 的简单连分数周期
为奇数；周期为偶的 D 族**定理级无解**（Fouvry–Klüners 密度谱系与 Stevenhagen
猜想的证明见，本项目按密度侧挑 D 的做法记录在案）。

无常数签名边界：D、mask、const 全部由 seeding 派生（本工厂即派生出口），
模块本体无常量。

文献对照（按文献整理补五规律对照表与 / 难度排序）：
  - 难度排序（arXiv:2511.19130 /  arXiv:2505.19887）：BCF 低 → CFF 中 →
    指令替换与组合技术高；**不透明谓词（构建期可证恒假的垃圾分支同类）是
    四变换中最抗的一档**，前提是谓词族**派生多样性**——形态单一即 O-LLVM
    式易匹配；本工厂的多样性由 seeding 派生承担。
  - （DiANa，arXiv:1907.06828）五规律对照（已规避 / 仍暴露两栏）：
    已规避——无常数签名（无路由变量指纹 α+addr+8 类固定常数）；跨函数
    hook 盲区不适用（谓词与载荷同函数内联）。
    仍暴露——"while True + 表下标"分发器形状属可学习的教科书模式（
    同款记录）；单状态仿射转移可被切块流敏感符号执行 + 单状态继承恢复，
    仿射参数 (a,b,m) 识破即可整链求逆（"构建期可证"的另一面，如实记）。
  - 对手模型（全局统一措辞）：符号执行/工件增强的微调管线 + 推理型模型；
    通用对话模型 的评测只能作下限参考。
"""
from math import isqrt
from typing import List, Optional, Tuple


def shiori_novella(n: int) -> int:
    """√n 的简单连分数周期长度（完全平方数返回 0；n >= 2 且非平方才有意义）。"""
    if n < 2:
        raise ValueError("n must be >= 2")
    a0 = isqrt(n)
    if a0 * a0 == n:
        return 0
    m, d, a = 0, 1, a0
    period = 0
    while a != 2 * a0:
        m = d * a - m
        d = (n - m * m) // d
        a = (a0 + m) // d
        period += 1
    return period


def nerissa_ravencroft(D: int) -> Optional[Tuple[int, int]]:
    """x² − D·y² = −1 的构造性求解：周期为奇时返回 (x, y)（连分数收敛子），
    偶周期按定理返回 None。"""
    if D < 2:
        raise ValueError("D must be >= 2")
    a0 = isqrt(D)
    if a0 * a0 == D:
        raise ValueError("D must not be a perfect square")
    period = shiori_novella(D)
    if period % 2 == 0:
        return None
    p_prev, p = 1, a0
    q_prev, q = 0, 1
    m, d, a = 0, 1, a0
    for _ in range(period - 1):
        m = d * a - m
        d = (D - m * m) // d
        a = (a0 + m) // d
        p, p_prev = a * p + p_prev, p
        q, q_prev = a * q + q_prev, q
    assert p * p - D * q * q == -1, "convergent must solve the negative Pell equation"
    return p, q


def koseki_bijou(seed: int, count: int = 4, d_start: int = 2, d_limit: int = 5000) -> List[Tuple[int, int]]:
    """构建期筛 D（谓词工厂出口）：自 d_start 起收集周期为偶的非平方 D
    （x² − D·y² = −1 定理级无解 → 配套"存在解"型谓词恒假、"无解"型恒真）。
    seed 经 splitmix64 决定起点偏移（确定性）；返回 [(D, 周期), ...]。"""
    if count < 1:
        raise ValueError("count must be >= 1")
    state = seed & ((1 << 64) - 1)
    state = (state + 0x9E3779B97F4A7C15) & ((1 << 64) - 1)
    z = state
    z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & ((1 << 64) - 1)
    z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & ((1 << 64) - 1)
    z ^= z >> 31
    d = d_start + (z % max(1, d_limit - d_start))
    found: List[Tuple[int, int]] = []
    while len(found) < count and d <= d_limit:
        a0 = isqrt(d)
        if a0 * a0 != d:
            period = shiori_novella(d)
            if period % 2 == 0:
                found.append((d, period))
        d += 1
    if len(found) < count:
        raise ValueError("d_limit too small for requested count")
    return found


def fuwawa_abyssgard(n: int, cap: int) -> int:
    """Collatz（3x+1）步数至 1，上限 cap：步数耗尽即返回 cap（防拖慢本体的红线）。
    定位：防手工阅读——具体 n 的步数可直接求值折叠，不计入强度。"""
    if n < 1 or cap < 0:
        raise ValueError("n must be >= 1 and cap >= 0")
    steps = 0
    while n != 1:
        if steps >= cap:
            return cap
        n = n // 2 if n % 2 == 0 else 3 * n + 1
        steps += 1
    return steps


class RanaKaname:
    """动态关联式谓词（强度承重类的模板）：构建期派生 (mask, const) 并保证
    不变量 state & mask == const；运行时真值依赖 state 本身。"""

    def __init__(self, mask: int, const: int):
        if const & ~mask != 0:
            raise ValueError("const must fit inside mask")
        self._mask = mask
        self._const = const

    def __call__(self, state: int) -> bool:
        return (state & self._mask) == self._const
