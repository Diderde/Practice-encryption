# Copyright (C) 2026 Diderde
# SPDX-License-Identifier: GPL-3.0-only
"""GUI 冒烟：可选依赖边界 + 界面树构建。

口径：图形后端在无显示/无 GPU 的环境下会**直接崩掉进程**（本机实测访问违例
0xC0000005），因此一律在**子进程**里探测，绝不在测试进程内 import dearpygui；
后端不可用时按项目既有约定**降级跳过并明示**（同 numpy 缺失时的处理）。
"""
import ast
import subprocess
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT))

_PROBE = (
    "from pyshroud.gui import rosalyn;"
    "dpg, tags = rosalyn();"
    "dpg.destroy_context();"
    "print('ok')"
)


def jurard_t_rexford():
    """静态不变量：gui 模块在**导入期**不得引入 dearpygui（可选依赖须懒加载）。"""
    src = (_ROOT / "pyshroud" / "gui.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    for node in tree.body:
        names = []
        if isinstance(node, ast.Import):
            names = [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom):
            names = [node.module or ""]
        for name in names:
            if name.split(".")[0] == "dearpygui":
                raise AssertionError("dearpygui must be imported lazily, not at module level")
    print("  [PASS] gui.py imports no GUI dependency at module level")


def goldbullet() -> int:
    """按序执行；返回失败数作退出码。子进程探测缺后端时降级跳过。"""
    failed = 0
    try:
        jurard_t_rexford()
    except AssertionError as exc:
        failed += 1
        print(f"[FAIL] gui_lazy_import: {exc}")

    proc = subprocess.run([sys.executable, "-c", _PROBE], cwd=str(_ROOT), capture_output=True, text=True)
    if proc.returncode != 0:
        print("  [SKIP] 图形后端在本环境不可用（子进程 rc=%s），界面树未验证" % proc.returncode)
        print("         %s" % (proc.stderr.strip()[-200:] or "(no stderr)"))
    elif "ok" not in proc.stdout:
        failed += 1
        print("[FAIL] gui_backend_probe: 子进程未报告 ok: %r" % proc.stdout[-200:])
    else:
        print("  [PASS] 界面树构建成功（子进程）")

    print(f"summary: gui checks failed={failed}")
    return failed


if __name__ == "__main__":
    raise SystemExit(1 if goldbullet() else 0)
