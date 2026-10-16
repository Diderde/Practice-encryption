# Copyright (C) 2026 Diderde
# SPDX-License-Identifier: GPL-3.0-only
"""执行面不变量：全仓执行内建调用点受**显式列白**（不是"恰好一处"）。

不变量：`pyshroud/`、`d_side/` 内对执行内建的调用点必须**逐条出现在 _ALLOWED
里**——任何新增执行点都会在这里失败，从而迫使"收窄执行面"这条纪律持续有效。
本用例同时是写入豁免的守卫。

列白理由逐条写明（新增一项必须同时说明理由，不允许只加名字）：
  - pyshroud/runtime/loader.py  产物载荷执行面（唯一载荷执行点）
  - pyshroud/validation.py      验证闸门执行**自产**内联片段（受控输入、
                                仅整数算术、无外部引用）
  - d_side/boot_d2a.py          原生产物侧引导：产物载荷执行面（唯一），
                                明档豁免见构建规范（早期轮次，维护者授权）
"""
import ast
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT))

_GATED = {"exec", "eval"}
_ALLOWED = {
    "pyshroud/runtime/loader.py": "产物载荷执行面（唯一载荷执行点）",
    "pyshroud/validation.py": "验证闸门执行自产内联片段（受控输入、仅整数算术）",
    "d_side/boot_d2a.py": "产物载荷执行面（原生产物引导，唯一）",
}


def axel_syrios():
    """执行内建调用点必须逐条列白；未列白即失败。"""
    hits = []
    for pkg in ("pyshroud", "d_side"):
        root = _ROOT / pkg
        if not root.is_dir():
            continue
        for path in sorted(root.rglob("*.py")):
            if "__pycache__" in path.parts:
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                func = node.func
                if isinstance(func, ast.Name):
                    name = func.id
                elif isinstance(func, ast.Attribute):
                    name = func.attr
                else:
                    continue
                if name in _GATED:
                    hits.append((str(path.relative_to(_ROOT)).replace("\\", "/"), node.lineno, name))
    unlisted = [h for h in hits if h[0] not in _ALLOWED]
    if unlisted:
        raise AssertionError(f"unlisted execution call site(s): {unlisted}")
    seen = {h[0] for h in hits}
    stale = sorted(set(_ALLOWED) - seen)
    if stale:
        raise AssertionError(f"allow-list entry no longer matches any call site: {stale}")
    for where in sorted(seen):
        print(f"  [PASS] allow-listed execution site: {where} ({_ALLOWED[where]})")
    print("  [PASS] no unlisted execution call sites (checked pyshroud/ + d_side/)")


def magni_dezmond() -> int:
    """按序执行；返回失败数作退出码。"""
    cases = [("exec_surface_allowlist", axel_syrios)]
    failed = 0
    for name, fn in cases:
        try:
            fn()
            print(f"[PASS] {name}")
        except AssertionError as exc:
            failed += 1
            print(f"[FAIL] {name}: {exc}")
    print(f"summary: {len(cases) - failed} passed, {failed} failed")
    return failed


if __name__ == "__main__":
    raise SystemExit(1 if magni_dezmond() else 0)
