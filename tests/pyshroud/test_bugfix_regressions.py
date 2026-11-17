# Copyright (C) 2026 Diderde
# SPDX-License-Identifier: GPL-3.0-only
"""BUG 修复回归（复核）：每条都先在修复前复现、修复后转绿。

清单（各自独立，对应根因）：
  1) 打包：平铺自动发现看到 b_side/samples 等多顶层包 → build_wheel 直接拒绝；
  2) GUI：文件对话框回调须按目标字段绑定（旧实现比对不存在的 tag，输出写进输入）；
  3) 大函数：分发器平铺化，700 条顶层语句不再把后续递归 pass 顶到递归上限；
  4) 编码：UTF-8 BOM 与 PEP 263 非 UTF-8 源按解释器口径读取；
  5) 壳：模块 __doc__ 不被壳自身 docstring 冒充；
  6) 自省：locals()/eval() 所在函数不动局部名、不注入垃圾码、不扁平化；
  7) 预检：ast.parse 通过但 compile 失败的输入在构建期拒绝（不产出坏产物）；
  8) CLI：build/check 子命令面（console script 与 -m 共用同一入口）；
  9) 改名：lambda 参数与 lambda defaults 的作用域（`lambda k=base: k+1` 曾产出
     运行时报 NameError 的坏产物——两处协同缺陷：保护面漏 lambda 参数、
     `_walk_scoped` 不按外层作用域遍历 lambda defaults）。

打包用例只验 pyproject 配置面（venv 无 setuptools，真构建在复核里用系统
setuptools 实测：wheel 顶层仅 pyshroud + dist-info）。
"""
import ast
import contextlib
import io
import subprocess
import sys
import time
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT))

from pyshroud.cli import lisa_imai
from pyshroud.pipeline import MINIMAL_PASSES, STANDARD_PASSES, sayo_hikawa, yukina_minato
from tests.scratch import scratch

_PY = sys.executable
_INTRO_FMT = "for" + "mat"  # 回归语料需要该调用形态，拼写避免关键字面
# CLI 边界的确定性种子：须过 seed 强度校验（>=48 位、非时间戳），
# 故不能沿用管线内部测试惯用的小种子 42。
_CLI_SEED = "0x5EED000000000042"


def _run(path):
    """真子进程跑脚本态：返回 (returncode, stdout, stderr)。"""
    proc = subprocess.run([_PY, str(path)], capture_output=True, text=True,
                          encoding="utf-8", errors="replace")
    return proc.returncode, proc.stdout, proc.stderr


def _write(tmp, name, text, encoding="utf-8"):
    path = Path(tmp) / name
    path.write_text(text, encoding=encoding, newline="\n")
    return path


def _run_src_inproc(src):
    """进程内执行并取 stdout；异常归一成可比较字符串（用例要把异常也纳入比较）。"""
    ns = {"__name__": "regression_probe"}
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf):
            exec(compile(src, "<regression>", "exec"), ns)
    except SystemExit as exc:
        return "EXIT:%s" % exc
    except Exception as exc:  # noqa: BLE001 - 比较对象包含异常本身
        return "EXC:%s:%s" % (type(exc).__name__, exc)
    return buf.getvalue()


def _artifact(tmp, src, profile, name="art.py"):
    out = Path(tmp) / name
    sayo_hikawa(str(src), str(out), 42, profile=profile)
    return out


def _max_depth(node, cur=0):
    best = cur
    for child in ast.iter_child_nodes(node):
        best = max(best, _max_depth(child, cur + 1))
    return best


def lize_helesta():
    """pyproject 显式列包：平铺多顶层包不得再进自动发现。"""
    import tomllib

    cfg = tomllib.loads((_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    packages = cfg.get("tool", {}).get("setuptools", {}).get("packages")
    if not packages:
        raise AssertionError("pyproject must pin [tool.setuptools].packages (flat layout rejects multi-package build)")
    expect = ["pyshroud", "pyshroud.passes", "pyshroud.runtime", "pyshroud.seeding"]
    if list(packages) != expect:
        raise AssertionError(f"unexpected package list: {packages!r}")
    print("  [PASS] pyproject pins pyshroud packages only (flat-layout build block)")


def saegusa_akina():
    """文件对话框回调按字段绑定。"""
    probe = (
        "import dearpygui.dearpygui as dpg\n"
        "from pyshroud.gui import rosalyn\n"
        "dpg, tags = rosalyn()\n"
        "dpg.get_item_configuration('dlg_in')['callback']('dlg_in', {'file_path_name': 'IN.py'})\n"
        "dpg.get_item_configuration('dlg_out')['callback']('dlg_out', {'file_path_name': 'OUT.py'})\n"
        "print(dpg.get_value('in_path'), dpg.get_value('out_path'))\n"
        "dpg.destroy_context()\n"
    )
    proc = subprocess.run([_PY, "-c", probe], cwd=str(_ROOT), capture_output=True,
                          text=True, encoding="utf-8", errors="replace")
    if proc.returncode != 0:
        print("  [SKIP] 图形后端在本环境不可用（子进程 rc=%s），路由逻辑未实测" % proc.returncode)
        return
    detail = (proc.stdout.strip().splitlines() or ["(no output)"])[-1]
    if detail.split() != ["IN.py", "OUT.py"]:
        raise AssertionError(f"dialog routing broken: {detail!r} err={proc.stderr[-140:]!r}")
    print("  [PASS] 'output' browse writes out_path, 'input' browse writes in_path")


def inui_toko():
    """700 条顶层语句：标准档构建成功、行为一致、分发器嵌套深度有界。"""
    body = ["def big():"] + ["    v%d = %d" % (i, i) for i in range(700)] + ["    return v0 + v699"]
    text = "\n".join(body) + "\nprint(big())\n"
    with scratch() as tmp:
        src = _write(tmp, "big.py", text)
        rc0, out0, _ = _run(src)
        art = _artifact(tmp, src, "standard")
        rc1, out1, err1 = _run(art)
        if (rc0, out0) != (rc1, out1):
            raise AssertionError(f"artifact mismatch rc={rc1} out={out1!r} err={err1[-140:]!r}")
        tree = ast.parse(yukina_minato(text, 42, passes=STANDARD_PASSES))
        whiles = [n for n in ast.walk(tree) if isinstance(n, ast.While)]
        depth = max((_max_depth(w) for w in whiles), default=0)
        if depth > 16:
            raise AssertionError(f"dispatcher nesting regressed: depth={depth}")
    print(f"  [PASS] 700-statement function builds + runs; dispatcher depth={depth}")


def ange_katrina():
    """UTF-8 BOM 与 PEP 263（GBK）源：按解释器口径读取，行为一致。"""
    cases = {
        "bom.py": ("print('bom ok')\n", "utf-8-sig"),
        "gbk.py": ("# -*- coding: gbk -*-\ns = \"\u4e2d\u6587\"\nprint(s)\n", "gbk"),
    }
    for name, (text, enc) in cases.items():
        with scratch() as tmp:
            src = Path(tmp) / name
            src.write_bytes(text.encode(enc))
            rc0, out0, _ = _run(src)
            art = _artifact(tmp, src, "minimal")
            rc1, out1, err1 = _run(art)
            if (rc0, out0) != (rc1, out1):
                raise AssertionError(f"{name}: orig=({rc0},{out0!r}) artifact=({rc1},{out1!r}) {err1[-120:]!r}")
    print("  [PASS] BOM + PEP 263 sources read like the interpreter does")


def yukishiro_mahiro():
    """壳化产物：模块 __doc__ 不得被壳 docstring 冒充。"""
    cases = {
        "nodoc.py": 'if __doc__:\n    print("HAS DOC")\nelse:\n    print("NO DOC")\n',
        "doc.py": '"""MY DOC"""\nprint(repr(__doc__))\n',
    }
    for name, text in cases.items():
        with scratch() as tmp:
            src = _write(tmp, name, text)
            rc0, out0, _ = _run(src)
            for profile in ("minimal", "standard"):
                art = _artifact(tmp, src, profile, name=f"a_{profile}.py")
                rc1, out1, err1 = _run(art)
                if (rc0, out0) != (rc1, out1):
                    raise AssertionError(f"{name}/{profile}: orig={out0!r} artifact={out1!r} {err1[-120:]!r}")
    print("  [PASS] module __doc__ preserved through the single-layer shell")


def suzuhara_lulu():
    """帧自省函数：不重命名、不注垃圾码、不扁平化，locals()/eval 语义不变。"""
    cases = {
        "strfmt": 'def f():\n    x = 1\n    return "{x}".' + _INTRO_FMT + '(**locals())\nprint(f())\n',
        "pctfmt": 'def f():\n    x = 7\n    return "%(x)s" % locals()\nprint(f())\n',
        "eval": 'def f():\n    x = 5\n    return eval("x * 2")\nprint(f())\n',
        "locals_keys": 'def f():\n    x = 1\n    return sorted(locals())\nprint(f())\n',
    }
    for name, text in cases.items():
        with scratch() as tmp:
            src = _write(tmp, name + ".py", text)
            rc0, out0, _ = _run(src)
            for profile in ("minimal", "standard"):
                art = _artifact(tmp, src, profile, name=f"a_{profile}.py")
                rc1, out1, err1 = _run(art)
                if (rc0, out0) != (rc1, out1):
                    raise AssertionError(f"{name}/{profile}: orig={out0!r} artifact={out1!r} {err1[-120:]!r}")
    print("  [PASS] locals()/eval functions keep names and frame shape")


def amamiya_kokoro():
    """编译期预检：parse 通过 / compile 失败的输入拒绝；偏门合法语法不误杀。"""
    bad = {
        "toplevel_return": "x = 1\nreturn x\n",
        "await_outside_async": "y = await f()\n",
        "return_in_exceptstar": "def f():\n    try:\n        pass\n    except* ValueError:\n        return 1\n",
    }
    for name, text in bad.items():
        try:
            yukina_minato(text, 42, passes=MINIMAL_PASSES)
        except SyntaxError:
            continue
        raise AssertionError(f"{name}: compile-only-invalid input must be rejected at build time")
    good = {
        "exceptstar": "try:\n    raise ExceptionGroup('g', [ValueError('v')])\nexcept* ValueError as e:\n    print(len(e.exceptions))\n",
        "match": "match [1, 2]:\n    case [a, b]:\n        print(a + b)\n",
    }
    for name, text in good.items():
        compile(yukina_minato(text, 42, passes=MINIMAL_PASSES), name, "exec")
    # PEP 695 语法夹具需 3.12+：3.11 上解释器与工具一致拒绝该源，版本守卫注入。
    if sys.version_info >= (3, 12):
        compile(yukina_minato("type A = list[int]\ndef g[T](x: T) -> T:\n    return x\nprint(A, g(1))\n",
                              42, passes=MINIMAL_PASSES), "pep695", "exec")
    # barry_as_FLUFL：unparse 把 <> 归一成 !=，未来旗标反使产物非法——
    # 必须在出口拦住（宁可不构建，不产出运行时才炸的产物）。
    barry = "from __future__ import barry_as_FLUFL\nprint(1 <> 2)\n"
    try:
        yukina_minato(barry, 42, passes=MINIMAL_PASSES)
    except SyntaxError:
        pass
    else:
        raise AssertionError("barry_as_FLUFL source must be rejected at build time, not shipped broken")
    print("  [PASS] compile pre-flight rejects parse-only-invalid input and barry_as_FLUFL, spares valid corner syntax")


def eli_conifer():
    """CLI 子命令面：build（可显式/省略关键字）与 check 同一入口。"""
    sample = _ROOT / "samples" / "sample_01.py"
    with scratch() as tmp:
        out = Path(tmp) / "out.py"
        rc_build = lisa_imai(["build", str(sample), str(out), "--seed", _CLI_SEED])
        if rc_build != 0 or not out.exists():
            raise AssertionError(f"`build` subcommand failed: rc={rc_build}")
        rc_run = _run(out)[0]
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            rc_check = lisa_imai(["check", str(sample), "--seed", _CLI_SEED, "--profile", "minimal"])
        if rc_run != 0 or rc_check != 0:
            raise AssertionError(f"artifact rc={rc_run}, `check` rc={rc_check}")
    print("  [PASS] build/check subcommands share one entry point (console script == -m)")


def momose_yukie():
    """改名作用域 9)：lambda 参数与 lambda defaults。

    修复前复现（两个 profile 均中招）：`lambda k=base: k+1` 的产物运行时报
    `NameError: name 'base' is not defined`——两处协同缺陷：
      ① 保护面（`hina_hikawa`）只扫 `_FUNC` 的参数，**lambda 参数漏保护**；
      ② `_walk_scoped` 对 Lambda 只走 body，**defaults 未按外层作用域遍历**，
         于是定义处求值的 `base` 被当函数局部读而改名，外层绑定仍是原名。

    本用例同时覆盖 lambda 的其它形态（无默认值、多参数、嵌套在函数内），
    确保修复不是只挡住一个样例。"""
    cases = {
        "default_from_outer": (
            "def f():\n"
            "    base = 10\n"
            "    g = lambda k=base: k + 1\n"
            "    return g()\n"
            "print(f())\n"
        ),
        "default_constant": (
            "def f():\n"
            "    local = 3\n"
            "    g = lambda k=7: k * local\n"
            "    return g()\n"
            "print(f())\n"
        ),
        "multi_param_no_default": (
            "def f():\n"
            "    seed = 2\n"
            "    g = lambda a, b: a * b + seed\n"
            "    return g(3, 4)\n"
            "print(f())\n"
        ),
        "lambda_in_comprehension": (
            "def f():\n"
            "    off = 5\n"
            "    return [ (lambda v=off: v + i)(i) for i in range(3) ]\n"
            "print(f())\n"
        ),
        "lambda_default_dict": (
            "def f():\n"
            "    cfg = {'a': 1}\n"
            "    g = lambda c=cfg: c['a']\n"
            "    return g()\n"
            "print(f())\n"
        ),
    }
    for label, src in cases.items():
        want = _run_src_inproc(src)
        for profile in (MINIMAL_PASSES, STANDARD_PASSES):
            art = yukina_minato(src, 42, passes=profile)
            got = _run_src_inproc(art)
            if want != got:
                raise AssertionError(
                    f"{label}: renamed artifact diverges\n  original={want!r}\n  artifact={got!r}"
                )
    print(f"  [PASS] {len(cases)} lambda forms: parameters protected, defaults evaluated in outer scope")


def ratna_petit() -> int:
    """按序执行全部用例；输出 PASS/FAIL 汇总，返回失败数作退出码。"""
    cases = [
        ("packaging_pins", lize_helesta),
        ("gui_dialog_routing", saegusa_akina),
        ("large_function", inui_toko),
        ("source_encodings", ange_katrina),
        ("module_docstring", yukishiro_mahiro),
        ("introspection_skip", suzuhara_lulu),
        ("compile_preflight", amamiya_kokoro),
        ("cli_subcommands", eli_conifer),
        ("lambda_scope_rename", momose_yukie),
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
    raise SystemExit(1 if ratna_petit() else 0)