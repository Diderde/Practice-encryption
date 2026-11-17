# Copyright (C) 2026 Diderde
# SPDX-License-Identifier: GPL-3.0-only
"""套件运行器：按序跑全部自带运行器的验收套件，聚合成单一退出码。

为什么需要它：本项目的每个 test_*.py 都是**自带运行器**（顶层函数名不是
test_*，pytest 收集不到），靠退出码判成败。本地手跑要敲十几条命令，
CI 也需要一个稳定入口——本脚本即该入口，本地与 CI 共用同一条命令。

用法：
    python scripts/run_suites.py              # 全部套件
    python scripts/run_suites.py --fast       # 跳过耗时套件（真实项目 E2E 与 TEA 家族）
    python scripts/run_suites.py --list       # 只列套件

退出码：0 = 全通过（可能带**已登记**的环境性空档）；非 0 = 失败套件数
（上限 125，避免与信号码混淆）。

**绿灯必须可信**：只看返回码会把"全跳过"与"全通过"变成同一件事——依赖缺席
（z3 / GUI / rustc / 工作区外项目）时，一个什么都没跑的套件照样返回 0。故：
  - 每个套件统计**已执行检查数**（套件自报 summary 优先，退回数 `[PASS]` 行）；
    `[SKIP]` 只计数、**不计入已执行**；
  - 已执行 = 0 的套件标 `EMPTY` 并按失败计，除非在 `_ACK_EMPTY` 里**显式登记**
    （只有"该环境本来就跑不了"的套件才登记，且必须在输出里以空档形式列出来）；
  - 任何情况下"全局已执行 = 0"一律判失败；
  - 有已登记空档时打印 `PASS WITH GAPS`（附已执行/跳过/空档数），与 `ALL PASS` 不同形。
耗时套件单独标记：CI 的快速作业跳过它们，全量作业必跑。
"""
import argparse
import os
import re
import subprocess
import sys
import time
from pathlib import Path

# 父进程输出统一 UTF-8（errors=replace）：失败尾部的替换字符在 GBK 控制台上直接
# print 会 UnicodeEncodeError 并中断整个聚合器、吞掉后续套件结果（实测坑）。
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

_ROOT = Path(__file__).resolve().parents[1]

# (相对路径, 是否耗时)
_SUITES = [
    ("tests/pyshroud/test_exec_surface.py", False),
    ("tests/pyshroud/test_pipeline_m2.py", False),
    ("tests/pyshroud/test_loader_m4.py", False),
    ("tests/pyshroud/test_release_surface.py", False),
    ("tests/pyshroud/test_validation_m5.py", False),
    ("tests/pyshroud/test_differential_m5.py", False),
    ("tests/pyshroud/test_bugfix_regressions.py", False),
    ("tests/pyshroud/test_fuzz_scopes.py", False),
    ("tests/pyshroud/test_cross_instrument.py", False),
    ("tests/pyshroud/test_strength_metrics.py", False),
    ("tests/pyshroud/test_seed_policy.py", False),
    ("tests/pyshroud/test_fstring.py", False),
    ("tests/pyshroud/test_tree_level.py", False),
    ("tests/pyshroud/test_recursion_bound.py", False),
    ("tests/pyshroud/test_design_ceilings.py", False),
    ("tests/pyshroud/test_gui_smoke.py", False),
    ("tests/b_side/test_primitives_m1.py", False),
    ("tests/b_side/test_permuter_m1.py", False),
    ("tests/b_side/test_predicates_m1.py", False),
    ("tests/b_side/test_mba_validation_m1.py", False),
    ("tests/d_side/test_dside_v0.py", False),
    ("tests/d_side/test_dside_codec.py", False),
    ("tests/d_side/test_native_blake2s.py", False),
    ("tests/d_side/test_topology_gates.py", False),
    ("tests/d_side/test_d3_guards.py", False),
    ("tests/d_side/test_vm_gates.py", False),
    ("tests/d_side/test_native_builder.py", True),
    ("tests/d_side/test_native_vm.py", True),
    ("tests/d_side/test_deadpath.py", True),
    ("tests/pyshroud/test_realprojects_m5.py", True),
    ("tests/b_side/test_tea_family.py", True),
]


# 环境性空档登记：这些套件在**依赖/外部项目缺席**时整份跳过是设计内行为，登记后
# 只作为"空档"如实列出（不判失败）；未登记的套件一旦"什么都没跑"就是失败。
# 判据是实测：登记项必须在依赖齐备的环境里自己消失（跑出非 0 已执行数）。
_ACK_EMPTY = {
    "tests/pyshroud/test_realprojects_m5.py":
        "工作区外项目（markdown-reader / bili-dl）与网络（markdown2）缺席",
}

_SUMMARY_RX = re.compile(r"summary:\s*(\d+)\s*passed,\s*(\d+)\s*failed")


def _counts(stdout: str):
    """返回 (已执行检查数, 跳过数)。已执行优先取套件自报 summary，退回数 `[PASS]` 行。"""
    text = stdout or ""
    passed = len(re.findall(r"\[PASS\]", text))
    skipped = len(re.findall(r"\[SKIP\]", text))
    m = _SUMMARY_RX.search(text)
    if m:
        passed = max(passed, int(m.group(1)))
    return passed, skipped


def main() -> int:
    parser = argparse.ArgumentParser(prog="run_suites", description="run every self-hosted suite")
    parser.add_argument("--fast", action="store_true", help="skip slow suites")
    parser.add_argument("--list", action="store_true", help="list suites and exit")
    args = parser.parse_args()

    if args.list:
        for rel, slow in _SUITES:
            print("%-46s %s" % (rel, "SLOW" if slow else "fast"))
        return 0

    selected = [(r, s) for r, s in _SUITES if not (args.fast and s)]
    failures = []
    gaps = []
    executed_total = 0
    skipped_total = 0
    print("running %d suite(s)%s" % (len(selected), " [--fast]" if args.fast else ""))
    print()
    for rel, slow in selected:
        path = _ROOT / rel
        if not path.is_file():
            print("  %-46s MISSING" % rel)
            failures.append((rel, "missing"))
            continue
        started = time.perf_counter()
        # CI（Windows runner）stdout 默认 charmap，中文 PASS 行会 UnicodeEncodeError——子套件统一 UTF-8
        env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUTF8="1")
        proc = subprocess.run([sys.executable, rel], cwd=str(_ROOT), env=env,
                              capture_output=True, text=True, errors="replace", shell=False)
        elapsed = time.perf_counter() - started
        executed, skipped = _counts(proc.stdout)
        executed_total += executed
        skipped_total += skipped
        if proc.returncode != 0:
            status = "FAIL(%d)" % proc.returncode
            failures.append((rel, proc.returncode))
        elif executed == 0:
            if rel in _ACK_EMPTY:
                status = "EMPTY(ack)"
                gaps.append((rel, skipped, _ACK_EMPTY[rel]))
            else:
                status = "EMPTY(no checks)"
                failures.append((rel, "no checks executed"))
        else:
            status = "ok"
        print("  %-46s %-16s e=%-4d s=%-4d %6.1fs"
              % (rel, status, executed, skipped, elapsed))
        if proc.returncode != 0:
            tail = (proc.stdout or "").strip().splitlines()[-40:]
            for line in tail:
                print("        | %s" % line[:130])
            err = (proc.stderr or "").strip().splitlines()[-6:]
            for line in err:
                print("        ! %s" % line[:130])

    print()
    print("checks: executed=%d skipped=%d (skipped 不计入 executed)"
          % (executed_total, skipped_total))
    if executed_total == 0:
        failures.append(("<all suites>", "no checks executed anywhere"))
    if failures:
        print("FAILED: %d/%d suites" % (len(failures), len(selected)))
        for rel, rc in failures:
            print("  %s (%s)" % (rel, rc))
        return min(len(failures), 125)
    if gaps:
        print("PASS WITH GAPS: %d/%d suites, empty=%d (环境性空档，已在上面逐条标注)"
              % (len(selected), len(selected), len(gaps)))
        for rel, skipped, why in gaps:
            print("  %s：%s（跳过 %d 项）" % (rel, why, skipped))
        return 0
    print("ALL PASS: %d/%d suites (executed=%d, skipped=%d)"
          % (len(selected), len(selected), executed_total, skipped_total))
    return 0


if __name__ == "__main__":
    sys.exit(main())
