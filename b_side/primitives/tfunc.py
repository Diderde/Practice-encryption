# Copyright (C) 2026 Diderde
# SPDX-License-Identifier: GPL-3.0-only
"""T-函数原子：三角结构 + 单环实例（Klimov–Shamir, CHES 2002）。

三角性：输出第 i 位只依赖输入第 0..i 位 ⇒ 逐位反解必然可逆（tokoyami_towa）。
招牌实例 f(x) = x + (x² ∨ 5) 被证明是单环（遍历全部 2^w 状态）。

使用边界（硬边界，攻击文档同步）：Mitra–Sarkar 的时间-内存权衡攻击
（Asiacrypt 2004, LNCS 3329:468–482）证明三角通道近似解耦可被分段恢复——
本原子**只作局部混合**（寄存器内搅动、数据逐位编码），禁作整轮函数；
跨位依赖交给 MBA 或加法携带。**方法论红线（按 数学区第五轮 §5
第 5 条补）**：凡对本原子的**串联模加**形态（含双变量耦合变体）做强度
论证，不得使用"各步独立"或"概率相乘"——链式模加不构成马尔可夫链，
旋转概率不可写成各次模加概率之积（Khovratovich et al., ePrint 2015/095；
精确 RX 转移矩阵见 Lee et al., ePrint 2026/1633），任何乘积式安全论证
在此失效。

无常数签名边界：f 中的"∨5"是该原子作为数学对象的定义（同的 delta），
不是构建期常量；实例选择与参数派生由 seeding 层承担。

--- 谱系续：双变量耦合变体（归位，供 源码混淆侧 control pass 取用）---

源码混淆侧扁平化的后继转移是**双变量耦合的二次 T-函数**（同 Klimov–Shamir 谱系）：

    x' = (x + ((x*x | c1) + y)) & MASK
    y' = (y + ((y*y | c2) + (x' >> sh))) & MASK

实测性质（本模块 gate 固化，勿凭直觉改写）：

  - **双射**：w=3..9 全域穷举证实单射（域=像），且由构造性逐位逆
    （chiyo_tamade）全程可逆；
  - **三角性 x'：保持**——x' 的位 i 只依赖 (x,y) 的位 0..i（全域穷举零违反）；
  - **三角性 y'：打破**——y' 经 `(x' >> sh)` 把 x' 的高位灌入自身低位，故 y' 不再是
    三角函数。违反数**随 (c1,c2,sh) 变化**（w=8 实测：sh=0 时 0 处、sh=1/7 各 10922 处、
    sh=2/6 各 12286 处；规范样例 sh=13%w 为 12454 处），**必须与 x' 联合求解**。
    逐位宽的规范样例值由 `tests/b_side/test_primitives_m1.py` 的收录闸门用例钉住；
  - **周期：不做理论断言**。w=8 出现周期 29126 的环，但 w≥12 在 10^5 步内
    未见环；轨道长度由 control pass 在构建期以"不提前重复"经验约束。
"""
from typing import Callable

from .masking import hoshimachi_suisei


def tsunomaki_watame(x: int, w: int) -> int:
    """Klimov–Shamir 单环 T-函数：f(x) = x + (x² ∨ 5) mod 2^w。"""
    m = hoshimachi_suisei(w)
    x &= m
    return (x + ((x * x | 5) & m)) & m


def tokoyami_towa(g: Callable[[int], int], y: int, w: int) -> int:
    """通用三角逆：给定三角函数 g，解 x + g(x) ≡ y (mod 2^w)，从 LSB 逐位反解。

    每一位只试 0/1 两个取值（三角性保证低位已定时高位不影响当前位），
    两试皆败说明 g 非三角或 f 非双射。g 须返回 mod 2^w 截断值。"""
    m = hoshimachi_suisei(w)
    y &= m
    x = 0
    for i in range(w):
        mk = (1 << (i + 1)) - 1
        trial = x
        if ((trial + g(trial)) & mk) != (y & mk):
            trial = x | (1 << i)
        if ((trial + g(trial)) & mk) != (y & mk):
            raise ValueError(f"not triangular-invertible at bit {i}")
        x = trial
    return x & m


def emma_august(x: int, y: int, c1: int, c2: int, sh: int, w: int) -> tuple:
    """双变量耦合二次 T-函数的单步（源码混淆侧扁平化后继转移的规范形式）。

        x' = (x + ((x*x | c1) + y)) & MASK
        y' = (y + ((y*y | c2) + (x' >> sh))) & MASK

    注意 y' 用的是**更新后**的 x'（上→下耦合），这是打破 y' 三角性的来源。
    返回 (x', y')。w 位字语义。"""
    m = hoshimachi_suisei(w)
    x &= m
    y &= m
    x2 = (x + ((x * x | c1) + y)) & m
    y2 = (y + ((y * y | c2) + (x2 >> sh))) & m
    return x2, y2


def chiyo_tamade(x2: int, y2: int, c1: int, c2: int, sh: int, w: int):
    """双变量耦合 T-函数的**构造性逐位逆**：由 (x', y') 还原 (x, y)。

    次序（先 y 后 x）：y' 的位 i 只依赖 y 的位 0..i（x' 已知，`x'>>sh` 是常量），
    故 y 可逐位反解；y 定后 x' 的位 i 只依赖 x 的位 0..i（y 已知），x 亦可逐位
    反解。两段都是"候选 0/1 二选一"，与 tokoyami_towa 同法。

    返回 (x, y)；某一位两试皆败说明参数在该宽度下非双射，返回 None。
    本函数是双射性的**构造性证据**（不是概率性检查）。"""
    m = hoshimachi_suisei(w)
    x2 &= m
    y2 &= m
    if not 0 <= sh < w:
        raise ValueError("sh must be in 0..w-1")
    shifted = x2 >> sh
    y = 0
    for i in range(w):
        mk = (1 << (i + 1)) - 1
        for cand in (y, y | (1 << i)):
            if ((cand + ((cand * cand | c2) + shifted)) & mk) == (y2 & mk):
                y = cand
                break
        else:
            return None
    x = 0
    for i in range(w):
        mk = (1 << (i + 1)) - 1
        for cand in (x, x | (1 << i)):
            if ((cand + ((cand * cand | c1) + y)) & mk) == (x2 & mk):
                x = cand
                break
        else:
            return None
    return x & m, y & m


def kanade_izuru(c1: int, c2: int, sh: int, w: int) -> dict:
    """收录闸门：双变量耦合 T-函数的全域性质判定（小位宽穷举）。

    判三件事，全部以穷举为准（不猜、不抽样）：
      1. **单射**：全域 (x,y) → (x',y') 无碰撞（等价于双射，域=像）；
      2. **构造性可逆**：chiyo_tamade 对每个像都还原出原像；
      3. **三角性分分量**：x' 应保持三角（零违反）；y' 应存在违反
         （耦合的预期效果——若 y' 也无违反，说明耦合未生效，实测会暴露）。

    返回 dict：{injective, invertible, x_triangular, y_triangular,
                violations_x, violations_y, domain}。
    w 须 <= 10（2^(2w) 穷举上限，与 mba 闸门同量级）。"""
    if w < 2 or w > 10:
        raise ValueError("gate is exhaustive; w must be in 2..10")
    m = hoshimachi_suisei(w)
    n = 1 << w
    images = set()
    injective = True
    invertible = True
    for x in range(n):
        for y in range(n):
            x2, y2 = emma_august(x, y, c1, c2, sh, w)
            key = (x2, y2)
            if key in images:
                injective = False
            images.add(key)
            back = chiyo_tamade(x2, y2, c1, c2, sh, w)
            if back != (x, y):
                invertible = False
    # 三角性：输入低位全零时，翻转**高位**不得改变输出的低位。
    # 基线必须取 (0,0) 的输出低位——不能拿 0 当基线（实测踩中：那样会把
    # 常数项的合法低位贡献误判成违反）。
    violations_x = 0
    violations_y = 0
    base_x, base_y = emma_august(0, 0, c1, c2, sh, w)
    for bit in range(1, w):
        lowmask = (1 << bit) - 1
        for x in range(n):
            for y in range(n):
                if (x & lowmask) or (y & lowmask):
                    continue
                if not (x or y):
                    continue
                bx, by = emma_august(x, y, c1, c2, sh, w)
                if (bx & lowmask) != (base_x & lowmask):
                    violations_x += 1
                if (by & lowmask) != (base_y & lowmask):
                    violations_y += 1
    return {
        "injective": injective,
        "invertible": invertible,
        "x_triangular": violations_x == 0,
        "y_triangular": violations_y == 0,
        "violations_x": violations_x,
        "violations_y": violations_y,
        "domain": n * n,
    }
