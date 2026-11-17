# Copyright (C) 2026 Diderde
# SPDX-License-Identifier: GPL-3.0-only
"""树级可用性验收：多模块包的逐文件混淆。

口径来源：README 称本工具面向「可分发的 Python **源码树**」，而工具入口是
**单文件**（`pipeline.sayo_hikawa(in_path, out_path, ...)`）。本套件回答这个
组合是否可用，并把答案钉成可执行断言：

  - 逐文件混淆（**每文件独立 seed**，即最弱的协调）后，包仍可导入与运行，
    输出与原样逐字一致；
  - 含**相对导入**（`from .util import ...`）与 **`__init__` 再导出**的包同样成立；
  - **带壳**模块（自解密壳包裹）同样成立——壳不破坏模块身份；
  - 全树**共享单一 seed** 同样成立。

为什么三档都要测：它们对应三种调用策略（每文件派生 seed / 逐文件壳化 / 统一
seed）。任一档失败即说明树级使用需要额外协调，而当前实现没有该协调。

**这不是树级 CLI 的验收**：本套件只证明"逐文件构建多模块包可用"，
目录/包模式的入口属未实现的便利项（见 README 说明）。
"""
import subprocess
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT))

from pyshroud.passes.shell import regis_altare
from pyshroud.pipeline import kageyama_shien, yukina_minato
from tests.scratch import scratch

# 最小包：绝对导入、相对导入、__init__ 再导出、跨模块常量
_PKG = {
    "__init__.py": (
        '"""Demo package."""\n'
        "from .core import compute\n"
        "from . import util\n"
    ),
    "core.py": (
        '"""Core module."""\n'
        "from .util import scale\n"
        "from .constants import LIMIT\n"
        "\n"
        "def compute(n):\n"
        "    total = scale(n) + LIMIT\n"
        "    return total\n"
    ),
    "util.py": (
        '"""Utility module."""\n'
        "FACTOR = 3\n"
        "\n"
        "def scale(x):\n"
        "    return x * FACTOR\n"
    ),
    "constants.py": (
        '"""Constants."""\n'
        "LIMIT = 100\n"
    ),
}
_MAIN = (
    "import demo\n"
    "from demo.core import compute\n"
    "from demo.util import scale\n"
    "print('pkg', demo.util.scale(2))\n"
    "print('abs', compute(5))\n"
    "print('rel', scale(4))\n"
)

_STD = kageyama_shien("standard")


def _materialize(root: Path, obfuscate: str):
    """在 root 下铺一份包：obfuscate ∈ {none, per-file, per-file-shelled, shared}。"""
    pkg = root / "demo"
    pkg.mkdir(parents=True, exist_ok=True)
    (root / "main.py").write_text(_MAIN, encoding="utf-8")
    for i, name in enumerate(sorted(_PKG)):
        src = _PKG[name]
        if obfuscate == "none":
            art = src
            seed = None
        elif obfuscate == "per-file":
            seed = 4200 + i
            art = yukina_minato(src, seed, passes=_STD)
        elif obfuscate == "per-file-shelled":
            seed = 4200 + i
            art = regis_altare(seed, yukina_minato(src, seed, passes=_STD), 0)
        elif obfuscate == "shared":
            seed = 4200
            art = yukina_minato(src, seed, passes=_STD)
        else:
            raise ValueError(obfuscate)
        (pkg / name).write_text(art, encoding="utf-8")


def _run(root: Path):
    proc = subprocess.run([sys.executable, "main.py"], cwd=str(root),
                          capture_output=True, text=True, shell=False)
    return proc.returncode, proc.stdout, proc.stderr


def _check(mode: str, label: str):
    """在临时目录里跑 pristine 与指定模式，比对 (rc, stdout)。"""
    with scratch(prefix="tree-") as tmp:
        base = Path(tmp)
        a, b = base / "orig", base / "obf"
        _materialize(a, "none")
        _materialize(b, mode)
        rc0, out0, _ = _run(a)
        rc1, out1, err1 = _run(b)
    if rc0 != 0:
        raise AssertionError(f"pristine run failed rc={rc0} (test harness broken)")
    if (rc0, out0) != (rc1, out1):
        raise AssertionError(
            f"{label}: artifact run diverged\n  pristine rc={rc0} out={out0!r}\n"
            f"  artifact rc={rc1} out={out1!r}\n  stderr={err1[-300:]!r}"
        )
    print(f"  [PASS] {label}: multi-module package runs identically (rc=0)")


def ogata_ran():
    """逐文件独立 seed：多模块包仍可运行（核心口径）。"""
    _check("per-file", "per-file seeds (weakest coordination)")


def mitake_ran():
    """带壳模块：壳不破坏模块身份与相对导入。"""
    _check("per-file-shelled", "per-file seeds + shelled modules")


def hazawa_tsugumi():
    """全树共享单一 seed：亦成立（调用方可选策略）。"""
    _check("shared", "single shared seed across the tree")


def aoba_moca() -> int:
    """按序执行全部用例；输出 PASS/FAIL 汇总，返回失败数作退出码。"""
    cases = [
        ("tree_per_file_seeds", ogata_ran),
        ("tree_shelled_modules", mitake_ran),
        ("tree_shared_seed", hazawa_tsugumi),
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
    raise SystemExit(1 if aoba_moca() else 0)
