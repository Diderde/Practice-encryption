# Copyright (C) 2026 Diderde
# SPDX-License-Identifier: GPL-3.0-only
"""递归边界验收：深层嵌套输入的可用面与失败形态。

背景：passes 的 AST 访问器、`ast.parse`、`ast.unparse`、`compile` **都是递归的**，
故深嵌套输入会先于解释器触顶。此前实测（运算符链）管线只到深度 326，
而解释器可到 2995——只有 11% 的可用面。`pipeline._recursion_budget()` 修正后，
管线达到与解释器同级的边界。

本套件锁三件事：
  1. **可用面**：管线接受的嵌套深度须达到解释器自身上限的 95% 以上；
  2. **失败形态**：超出时抛**可捕获的 RecursionError**，不是段错误/静默；
  3. **上限还原**：跑完后调用方的 `sys.getrecursionlimit()` 必须恢复原值
     （含异常路径）——否则会悄悄改变宿主进程的行为。
"""
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT))

from pyshroud.pipeline import _PASS_RECURSION_BUDGET, kageyama_shien, yukina_minato

_STD = kageyama_shien("standard")


def _binop_chain(n):
    """n 层运算符链：1 + 1 + ... + 1（解释器可接受约 2995 层）。"""
    return "x = " + " + ".join(["1"] * (n + 1)) + "\n"


def _interpreter_accepts(depth):
    try:
        compile(_binop_chain(depth), "<probe>", "exec")
        return True
    except (SyntaxError, MemoryError, RecursionError):
        return False


def _pipeline_accepts(depth):
    try:
        yukina_minato(_binop_chain(depth), 42, passes=_STD)
        return True
    except RecursionError:
        return False
    except SyntaxError:
        return False


def hikawa_hina():
    """可用面：管线须覆盖解释器上限的 95% 以上。"""
    lo, hi = 1, 3000
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if _interpreter_accepts(mid):
            lo = mid
        else:
            hi = mid - 1
    interp_max = lo
    if not _pipeline_accepts(interp_max):
        # find the pipeline's own ceiling
        lo2, hi2 = 1, interp_max
        while lo2 < hi2:
            mid = (lo2 + hi2 + 1) // 2
            if _pipeline_accepts(mid):
                lo2 = mid
            else:
                hi2 = mid - 1
        pipe_max = lo2
    else:
        pipe_max = interp_max
    ratio = pipe_max / interp_max * 100 if interp_max else 0.0
    if ratio < 95.0:
        raise AssertionError(
            "pipeline covers only %.1f%% of the interpreter's nesting capacity "
            "(pipeline=%d, interpreter=%d)" % (ratio, pipe_max, interp_max)
        )
    print(f"  [PASS] op-chain nesting: pipeline={pipe_max} vs interpreter={interp_max} ({ratio:.1f}%)")


def shirasagi_chisato():
    """失败形态：超出边界时抛可捕获的 RecursionError（非段错误/静默）。"""
    ok = _pipeline_accepts(2996)
    if ok:
        return  # 解释器若接受，本项无从触发（不同 CPython 版本边界不同）
    try:
        yukina_minato(_binop_chain(2996), 42, passes=_STD)
    except RecursionError:
        print("  [PASS] beyond the boundary: catchable RecursionError (not a crash)")
        return
    except Exception as exc:  # noqa: BLE001 - 形态本身就是要区分的东西
        raise AssertionError(f"expected RecursionError, got {type(exc).__name__}: {exc}")
    raise AssertionError("expected the pipeline to reject depth 2996")


def yamato_maya():
    """上限还原：跑完后调用方的递归上限必须恢复（含异常路径）。"""
    before = sys.getrecursionlimit()
    yukina_minato(_binop_chain(2000), 42, passes=_STD)
    after = sys.getrecursionlimit()
    if after != before:
        raise AssertionError(f"recursion limit not restored: {before} -> {after}")

    # 异常路径同样要还原
    lowered = 60
    sys.setrecursionlimit(lowered)
    try:
        try:
            yukina_minato(_binop_chain(500), 42, passes=_STD)
        except RecursionError:
            pass
        if sys.getrecursionlimit() != lowered:
            raise AssertionError(
                "recursion limit not restored on the exception path: %d" % sys.getrecursionlimit()
            )
    finally:
        sys.setrecursionlimit(before)
    print(f"  [PASS] recursion limit restored on both normal and exception paths")
    if _PASS_RECURSION_BUDGET < 2000:
        raise AssertionError("budget too small to cover realistic nesting")


def hoshizora_rin() -> int:
    """按序执行全部用例；输出 PASS/FAIL 汇总，返回失败数作退出码。"""
    cases = [
        ("recursion_coverage", hikawa_hina),
        ("recursion_failure_mode", shirasagi_chisato),
        ("recursion_limit_restored", yamato_maya),
    ]
    failed = 0
    for name, fn in cases:
        try:
            fn()
            print(f"[PASS] {name}")
        except AssertionError as exc:
            failed += 1
            print(f"[FAIL] {name}: {exc}")
        except Exception as exc:  # noqa: BLE001 - runner must survive any case error
            failed += 1
            print(f"[FAIL] {name}: unexpected {type(exc).__name__}: {exc}")
    print(f"summary: {len(cases) - failed} passed, {failed} failed")
    return failed


if __name__ == "__main__":
    raise SystemExit(1 if hoshizora_rin() else 0)
