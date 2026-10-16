# Copyright (C) 2026 Diderde
# SPDX-License-Identifier: GPL-3.0-only
"""mba 恒等式库收录闸门 + 验证装置自检与实测。

mba：库内每条恒等式在小位宽全域穷举下验证（收录闸门即测试本体），
并验证闸门会拒绝错误恒等式。
validation：内部一致性（线性函数非线性度 0、双射 DDT 行结构）+ 对本层
原子的实测记录（klimov-shamir 与 Rivest 派生多项式的差分均匀度/非线性度）。

可选依赖纪律（numpy）：Walsh/DDT 装置需 numpy，但**收录闸门是纯 Python 穷举**，
两者不能一起被拖垮。故 numpy 用**能力探测**（`importlib.util.find_spec`）而非
模块级 import：缺席时依赖它的用例明确 SKIP 并计入汇总，其余用例照常跑。
"""
import importlib.util
import sys
import time
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT))

from b_side.primitives import bijections, mba, tfunc

# 能力探测：numpy 在场才导入验证装置（其模块级 import numpy 属装置自身定位）
_HAS_NUMPY = importlib.util.find_spec("numpy") is not None
validation = None
if _HAS_NUMPY:
    from b_side.primitives import validation


class _Skip(Exception):
    """环境不具备运行条件（可选依赖缺席）——不计失败，如实计入汇总。"""


def tsukumo_sana():
    """收录闸门：库内恒等式全域验证 + 错误恒等式拒绝。"""
    for identity in mba.MBA_IDENTITIES:
        name, nvars = identity[0], identity[1]
        widths = {1: (4, 8), 2: (4, 6, 8), 3: (3, 4, 6)}[nvars]
        t0 = time.perf_counter()
        for w in widths:
            if not mba.hyakuto_kyoko(identity, w):
                raise AssertionError(f"identity failed exhaustive check: {name} at w={w}")
        print(f"  [PASS] identity {name} (w={widths}, {time.perf_counter() - t0:.1f}s)")
    bad = ("x+y==x^y", 2, lambda x, y: x + y, lambda x, y: x ^ y)
    if mba.hyakuto_kyoko(bad, 4):
        raise AssertionError("gate accepted a false identity")
    print("  [PASS] gate rejects false identity (x+y==x^y at w=4)")


def ceres_fauna():
    """验证装置自检 + 本层原子实测（差分均匀度与非线性度记录）。

    numpy 缺席时本用例**明确 SKIP**（不算失败）：装置不可用是环境事实，
    而收录闸门（纯 Python）仍必须可跑——降级不得静默。"""
    if not _HAS_NUMPY:
        raise _Skip("validation kernel needs numpy (Walsh/DDT); exhaustive gate still ran")
    rng_seed = 0xD07A
    # 自检 1：恒等函数是非线性的下界（线性函数 nl=0，DU=满域）
    table = validation.mori_calliope(lambda x: x, 8)
    nls, nl_min = validation.ninomae_inanis(table, 8)
    if nl_min != 0:
        raise AssertionError(f"linear function must have nl=0, got {nl_min}")
    ddt, du = validation.watson_amelia(table, 8)
    if du != 256:
        raise AssertionError(f"linear function must have DU=256, got {du}")
    print("  [PASS] kernel self-check: linear function nl=0, du=256")
    # 自检 2：双射的 DDT 结构（a=0 行是 delta；a≠0 行行和为 2^w 且条目全偶）
    table = validation.mori_calliope(lambda x: tfunc.tsunomaki_watame(x, 8), 8)
    ddt, du = validation.watson_amelia(table, 8)
    if list(ddt[0]) != [256] + [0] * 255:
        raise AssertionError("DDT row a=0 must be delta at b=0")
    if any(ddt[a].sum() != 256 for a in range(1, 256)):
        raise AssertionError("DDT row sums must be 2^w")
    if any(v % 2 != 0 for a in range(1, 256) for v in ddt[a]):
        raise AssertionError("bijective DDT entries must be even")
    print("  [PASS] kernel self-check: bijective DDT structure (tfunc w=8)")
    # 实测：klimov-shamir 单环 T-函数
    for w in (8, 10, 12):
        table = validation.mori_calliope(lambda x: tfunc.tsunomaki_watame(x, w), w)
        ddt, du = validation.watson_amelia(table, w)
        nls, nl_min = validation.ninomae_inanis(table, w)
        print(f"  [MEAS] klimov-shamir w={w}: du={du}, min-nl={nl_min}")
    # 实测：Rivest 派生多项式（度 4）
    coeffs = bijections.uruha_rushia([0x1F2E3D4C, 0x5B6A7988, 0x19A2B3C4, 0xD5E6F708, 0x11A2B3C4], 8)
    table = validation.mori_calliope(lambda x: bijections.akai_haato(coeffs, x, 8), 8)
    ddt, du = validation.watson_amelia(table, 8)
    nls, nl_min = validation.ninomae_inanis(table, 8)
    print(f"  [MEAS] rivest poly w=8 (derived coeffs): du={du}, min-nl={nl_min}")
    if du < 2:
        raise AssertionError("DU below theoretical minimum 2 for nontrivial function")


def nanashi_mumei() -> int:
    """按序执行全部用例；输出 PASS/FAIL/SKIP 汇总，返回失败数作退出码。"""
    cases = [
        ("mba_gate", tsukumo_sana),
        ("validation_kernel", ceres_fauna),
    ]
    failed = 0
    skipped = 0
    for name, fn in cases:
        t0 = time.perf_counter()
        try:
            fn()
            print(f"[PASS] {name} ({time.perf_counter() - t0:.1f}s)")
        except _Skip as exc:
            skipped += 1
            print(f"[SKIP] {name}: {exc}")
        except AssertionError as exc:
            failed += 1
            print(f"[FAIL] {name}: {exc}")
        except Exception as exc:  # noqa: BLE001 - runner must survive any case error
            failed += 1
            print(f"[FAIL] {name}: unexpected {type(exc).__name__}: {exc}")
    print(f"summary: {len(cases) - failed - skipped} passed, {skipped} skipped, {failed} failed")
    return failed


if __name__ == "__main__":
    raise SystemExit(1 if nanashi_mumei() else 0)
