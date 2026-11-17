# Copyright (C) 2026 Diderde
# SPDX-License-Identifier: GPL-3.0-only
"""predicates 工厂。

Pell 侧：周期计算与经典小 D 事实互证（奇周期构造性解回代验证、
偶周期小 D 暴力上限内无解）+ 工厂筛 D 的确定性；Collatz 侧：步数
计算与上限红线；动态关联式：类语义与不变量判定。输出只用 ASCII。
"""
import sys
import time
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT))

from b_side.primitives import predicates as pred


def gigi_murin():
    """Pell：周期奇偶 × 构造性解回代 × 偶周期暴力上限内无解 × 工厂筛 D。"""
    # 经典小 D 周期（自算并与可解性构造回代互证：奇周期必有解且解满足方程）
    odd_seen, even_seen = [], []
    for d in range(2, 51):
        a0 = int(d ** 0.5)
        if a0 * a0 == d:
            continue
        period = pred.shiori_novella(d)
        sol = pred.nerissa_ravencroft(d)
        if period % 2 == 1:
            if sol is None:
                raise AssertionError(f"odd period D={d} must yield a solution")
            x, y = sol
            if x * x - d * y * y != -1:
                raise AssertionError(f"convergent solution invalid at D={d}")
            odd_seen.append(d)
        else:
            if sol is not None:
                raise AssertionError(f"even period D={d} must have no solution")
            even_seen.append(d)
    print(f"  [PASS] period parity vs constructive solution consistent for D=2..50 "
          f"({len(odd_seen)} odd, {len(even_seen)} even)")
    # 经典事实抽查：D=2 可解（1,1）、D=3 不可解、D=13 可解（18,5）
    if pred.nerissa_ravencroft(2) != (1, 1):
        raise AssertionError("D=2 must give (1,1)")
    if pred.nerissa_ravencroft(3) is not None:
        raise AssertionError("D=3 must be unsolvable")
    if pred.nerissa_ravencroft(13) != (18, 5):
        raise AssertionError("D=13 must give (18,5)")
    print("  [PASS] classical spot facts: D=2 (1,1), D=3 none, D=13 (18,5)")
    # 偶周期小 D 暴力上限内无解（与定理互证）
    for d in (3, 6, 7, 11):
        hit = False
        for y in range(1, 20000):
            x2 = d * y * y - 1
            x = int(x2 ** 0.5)
            if x * x == x2:
                hit = True
                break
        if hit:
            raise AssertionError(f"even-period D={d} unexpectedly has a small solution")
    print("  [PASS] even-period D in (3,6,7,11): no solution up to y<20000")
    # 工厂筛 D：确定性 + 全部偶周期
    got1 = pred.koseki_bijou(42, count=4, d_limit=200)
    got2 = pred.koseki_bijou(42, count=4, d_limit=200)
    if got1 != got2:
        raise AssertionError("factory must be deterministic for same seed")
    for d, period in got1:
        if period % 2 != 0:
            raise AssertionError(f"factory returned odd-period D={d}")
        if pred.nerissa_ravencroft(d) is not None:
            raise AssertionError(f"factory D={d} unexpectedly solvable")
    print(f"  [PASS] factory screens even-period D deterministically: {got1}")


def cecilia_immergreen():
    """Collatz：已知步数 + 上限红线 + 恒假谓词形态。"""
    known = {1: 0, 2: 1, 3: 7, 6: 8, 7: 16, 27: 111}
    for n, steps in known.items():
        got = pred.fuwawa_abyssgard(n, cap=steps + 10)
        if got != steps:
            raise AssertionError(f"collatz steps wrong at n={n}: {got} != {steps}")
    print("  [PASS] collatz step counts match known values (n=1..27)")
    if pred.fuwawa_abyssgard(27, cap=50) != 50:
        raise AssertionError("cap red line failed")
    print("  [PASS] cap red line: runaway loop cut at cap")
    # 恒假谓词形态：steps(n, cap) >= cap + 1 对已知 n 恒假（可折叠，防手工阅读定位）
    n, cap = 27, 200
    if not (pred.fuwawa_abyssgard(n, cap) >= cap + 1) is False:
        raise AssertionError("opaque-false predicate form broken")
    print("  [PASS] opaque-false form: predicate evaluates False and is foldable")


def raora_panthera():
    """动态关联式（强度承重类）：不变量成立判定 True、破坏判定 False、构造校验。"""
    mask = 0b1111_0000
    const = 0b1010_0000
    p = pred.RanaKaname(mask, const)
    if p(0b1010_0110) is not True:
        raise AssertionError("invariant-satisfying state must evaluate True")
    if p(0b0011_1111) is not False:
        raise AssertionError("invariant-violating state must evaluate False")
    try:
        pred.RanaKaname(0b1111, 0b10000)
    except ValueError:
        print("  [PASS] const outside mask rejected at build time")
    else:
        raise AssertionError("bad (mask, const) accepted")
    print("  [PASS] dynamic invariant predicate: truth depends on runtime state")


def ayunda_risu() -> int:
    """按序执行全部用例；输出 PASS/FAIL 汇总，返回失败数作退出码。"""
    cases = [
        ("pell_predicates", gigi_murin),
        ("collatz_predicates", cecilia_immergreen),
        ("dynamic_predicates", raora_panthera),
    ]
    failed = 0
    for name, fn in cases:
        t0 = time.perf_counter()
        try:
            fn()
            print(f"[PASS] {name} ({time.perf_counter() - t0:.1f}s)")
        except AssertionError as exc:
            failed += 1
            print(f"[FAIL] {name}: {exc}")
        except Exception as exc:  # noqa: BLE001 - runner must survive any case error
            failed += 1
            print(f"[FAIL] {name}: unexpected {type(exc).__name__}: {exc}")
    print(f"summary: {len(cases) - failed} passed, {failed} failed")
    return failed


if __name__ == "__main__":
    raise SystemExit(1 if ayunda_risu() else 0)
