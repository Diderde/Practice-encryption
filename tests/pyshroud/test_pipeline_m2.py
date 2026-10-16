# Copyright (C) 2026 Diderde
# SPDX-License-Identifier: GPL-3.0-only
"""示例语义快照等价验收。

快照口径：main() 的 stdout 与返回行为一致。本切片用
importlib 进程内加载（samples 均为纯计算夹具）；真实子进程隔离的快照在
 真实项目验收升级（届时执行外部解释器）。另验：可复现性（同种子逐字节
一致）、种子敏感性（异种子产物必异）、作用域边界（docstring、f-string 字面量、
参数名、全局名不受影响；局部名已换；字符串已加密）。
"""
import contextlib
import importlib.util
import io
import sys
import time
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT))

from pyshroud.cli import lisa_imai
from pyshroud.pipeline import MAX_PASSES, MINIMAL_PASSES, STANDARD_PASSES, yukina_minato
from tests.scratch import scratch

# sample_09（multiprocessing spawn 样本）必须排除：进程内 exec 调 Pool 会在
# Windows 触发 spawn 子进程（本测试无子进程隔离）；它由 test_realprojects_m5
# 的真子进程 spawn E2E 覆盖。
_SAMPLES = [p for p in sorted((_ROOT / "samples").glob("sample_*.py")) if p.name != "sample_09.py"]

# CLI 边界的确定性种子：必须过 seed 强度校验（>=48 位、非时间戳），
# 故不能沿用管线内部测试惯用的小种子 42。数值本身无语义，只需稳定且够强。
_CLI_SEED = "0x5EED000000000042"


def _run_main(path: Path, modname: str):
    """进程内加载模块并运行其 main()：返回 (退出码, stdout 文本)。"""
    spec = importlib.util.spec_from_file_location(modname, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[modname] = module  # pickle 按名寻址要求模块已注册（sample_07 夹具）
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        spec.loader.exec_module(module)
        rc = module.main()
    return (0 if rc is None else int(rc)), buf.getvalue()


def ako_udagawa():
    """快照等价：全部 samples 原样 vs 混淆（seed=42）的 main() 输出一致 + CLI 冒烟。"""
    for idx, sample in enumerate(_SAMPLES):
        rc0, out0 = _run_main(sample, f"orig_{idx}")
        obf_src = yukina_minato(sample.read_text(encoding="utf-8"), 42)
        with scratch() as tmp:
            out_file = Path(tmp) / f"obf_{sample.name}"
            out_file.write_text(obf_src, encoding="utf-8")
            rc1, out1 = _run_main(out_file, f"obf_{idx}")
        if (rc0, out0) != (rc1, out1):
            raise AssertionError(f"snapshot mismatch at {sample.name}: {out0!r} vs {out1!r}")
        print(f"  [PASS] {sample.name}: main() stdout + return identical")
    # CLI 冒烟：lisa_imai 构建 → 产物加载运行一致
    sample = _SAMPLES[0]
    rc0, out0 = _run_main(sample, "cli_orig")
    with scratch() as tmp:
        out_file = Path(tmp) / "cli_out.py"
        rc_build = lisa_imai([str(sample), str(out_file), "--seed", _CLI_SEED])
        if rc_build != 0:
            raise AssertionError("CLI build returned nonzero")
        rc1, out1 = _run_main(out_file, "cli_art")
    if (rc0, out0) != (rc1, out1):
        raise AssertionError("CLI-built artifact snapshot mismatch")
    print("  [PASS] CLI smoke (lisa_imai): artifact runs identically")


def rinko_shirokane():
    """可复现性：同种子逐字节一致；种子敏感性：异种子产物必异。"""
    for sample in _SAMPLES:
        src = sample.read_text(encoding="utf-8")
        a = yukina_minato(src, 42)
        b = yukina_minato(src, 42)
        c = yukina_minato(src, 43)
        if a != b:
            raise AssertionError(f"same seed must give byte-identical output: {sample.name}")
        if a == c:
            raise AssertionError(f"different seed gave identical output: {sample.name}")
    print("  [PASS] same-seed byte-identical, different-seed different (all samples)")


def kokonoe_suzu():
    """作用域边界：docstring/参数名/全局名不受影响；局部名已换；字符串已加密
    （含 f-string 的字面量片段，替换字段保留）。"""
    s01 = yukina_minato(_SAMPLES[0].read_text(encoding="utf-8"), 42)
    s02 = yukina_minato(_SAMPLES[1].read_text(encoding="utf-8"), 42)
    s03 = yukina_minato(_SAMPLES[2].read_text(encoding="utf-8"), 42)
    s04 = yukina_minato(_SAMPLES[3].read_text(encoding="utf-8"), 42)
    if "Sample one: module constant" not in s01:
        raise AssertionError("module docstring must survive")
    if "obfuscate me" in s01 or "hello, " in s01:
        raise AssertionError("plain string literals must be encrypted")
    if "MOTTO" not in s01:
        raise AssertionError("module-level names must be preserved in v0")
    for param in ("base", "exp"):
        if param not in s02:
            raise AssertionError(f"parameter name {param} must be preserved (kwargs compatibility)")
    for local in ("squares", "add3", "text"):
        if local in s02:
            raise AssertionError(f"function-local {local} must be renamed")
    if "must survive" not in s03:
        raise AssertionError("class docstring must survive")
    # f-string：字面量片段须被加密（对齐普通字符串的覆盖口径），
    # 替换字段与格式说明符原样保留——故断言"字面量不泄露"而非"原样存活"。
    if "count=" in s03:
        raise AssertionError("f-string literal fragment must be encrypted, not left in place")
    # 替换字段须保留为替换字段。注意**不能**断言具体名字：`c` 是函数局部名，
    # 按设计会被 layout 改名（实测踩中：断言 "c.value" 会误判为失败）。
    # 判据取结构：产物中应仍存在"值为属性访问"的替换字段。
    import ast as _ast

    _fields = [n for n in _ast.walk(_ast.parse(s03)) if isinstance(n, _ast.FormattedValue)]
    if not _fields:
        raise AssertionError("f-string replacement field must survive as a FormattedValue")
    if not any(isinstance(f.value, _ast.Attribute) for f in _fields):
        raise AssertionError("the attribute-access replacement field must be preserved")
    if "alpha" in s04:
        raise AssertionError("dict key strings must be encrypted")
    print("  [PASS] scope boundaries hold: docstring/f-string/params/globals in, locals/strings out")


def yakushiji_suzaku():
    """结构验证：整数入池（池赋值存在、字面量已下标化）、垃圾分支注入且构建期可证恒假。"""
    import ast as ast_mod

    s01 = yukina_minato(_SAMPLES[0].read_text(encoding="utf-8"), 42)
    tree = ast_mod.parse(s01)
    pools = [n for n in tree.body if isinstance(n, ast_mod.Assign) and isinstance(n.value, ast_mod.List)]
    if not pools:
        raise AssertionError("int pool assignment missing")
    if not all(type(item.value) is int for item in pools[0].value.elts):
        raise AssertionError("pool must contain plain ints only")
    if "range(5)" in s01:
        raise AssertionError("int literal not pooled")
    mains = [n for n in tree.body if isinstance(n, ast_mod.FunctionDef) and n.name == "main"]
    if len(mains) != 1:
        raise AssertionError("main must remain a named module function")
    branches = [n for n in mains[0].body if isinstance(n, ast_mod.If)]
    if not branches:
        raise AssertionError("junk branch missing in main body")
    for f in branches:
        t = f.test
        shape_ok = (
            isinstance(t, ast_mod.Compare)
            and isinstance(t.left, ast_mod.BinOp) and isinstance(t.left.op, ast_mod.Mod)
            and isinstance(t.left.left, ast_mod.BinOp) and isinstance(t.left.left.op, ast_mod.Mult)
            and isinstance(t.left.left.left, ast_mod.Constant) and isinstance(t.left.left.right, ast_mod.Constant)
            and isinstance(t.left.right, ast_mod.Constant)
            and isinstance(t.comparators[0], ast_mod.Constant)
        )
        if not shape_ok:
            raise AssertionError("junk branch test shape unexpected")
        a = t.left.left.left.value
        b = t.left.left.right.value
        m = t.left.right.value
        r = t.comparators[0].value
        if (a * b) % m == r:
            raise AssertionError("junk branch must be provably false at build time")
    print("  [PASS] int pool present + literals indexed; junk branches provably false")


def tsukishita_kaoru():
    """control 结构验证：standard 构建下函数体被压平为分发器；模块级出现
    分支函数对与键表构建函数（二次 T-函数轨道 + Linn-Debray 分支函数）；global 函数跳过并计数。"""
    import ast as ast_mod

    sample = [p for p in _SAMPLES if p.name == "sample_06.py"][0]
    stats = {}
    s06 = yukina_minato(sample.read_text(encoding="utf-8"), 42, passes=STANDARD_PASSES, stats=stats)
    flattened = stats.get("control_flattened", 0)
    if flattened < 3:
        raise AssertionError(f"expected >=3 functions flattened, got {stats}")
    tree = ast_mod.parse(s06)
    orig_src = sample.read_text(encoding="utf-8")
    orig_names = {n.name for n in ast_mod.parse(orig_src).body if isinstance(n, ast_mod.FunctionDef)}
    orig_count = len(orig_names)
    module_fns = [n for n in tree.body if isinstance(n, ast_mod.FunctionDef)]
    # 模块级 = 原函数 + 每扁平化函数 1 个步进函数 + 1 个轨道构建函数 + data pass 解码器 1 个
    if len(module_fns) != orig_count + 2 * flattened + 1:
        raise AssertionError(f"expected {orig_count}+2*{flattened}+1 module functions, got {len(module_fns)}")
    step_fns = [
        n for n in module_fns
        if n.name not in orig_names
        and len(n.body) == 3
        and isinstance(n.body[-1], ast_mod.Return)
        and isinstance(n.body[-1].value, ast_mod.Tuple)
    ]
    if len(step_fns) != flattened:
        raise AssertionError(f"expected {flattened} step functions, got {len(step_fns)}")
    for st in step_fns:
        ops = [type(n.op) for n in ast_mod.walk(st) if isinstance(n, ast_mod.BinOp)]
        shape_ok = (
            ops.count(ast_mod.Mult) >= 2
            and ops.count(ast_mod.BitOr) >= 1
            and ops.count(ast_mod.BitAnd) >= 2
            and ops.count(ast_mod.RShift) >= 1
            and ops.count(ast_mod.Add) >= 3
        )
        if not shape_ok:
            raise AssertionError(f"step function {st.name} must implement the coupled quadratic T-function update")
    for fn in [n for n in module_fns if n.name in orig_names]:
        if not any(isinstance(n, ast_mod.While) for n in fn.body):
            raise AssertionError(f"function {fn.name} lacks dispatcher while-loop")
    subs_seen = 0
    for node in ast_mod.walk(tree):
        if isinstance(node, ast_mod.Compare) and any(isinstance(c, ast_mod.Subscript) for c in node.comparators):
            subs_seen += 1
    if subs_seen < flattened:
        raise AssertionError("dispatcher comparisons must reference key tables via subscripts")
    # global 函数跳过：构建期计数，且其函数体不含分发器
    src_g = "GG = 0\n\ndef setter():\n    global GG\n    GG = 5\n"
    stats_g = {}
    out_g = yukina_minato(src_g, 42, passes=STANDARD_PASSES, stats=stats_g)
    if stats_g.get("control_skipped", 0) < 1:
        raise AssertionError("global-declaring function must be skipped and counted")
    tree_g = ast_mod.parse(out_g)
    setter = [n for n in tree_g.body if isinstance(n, ast_mod.FunctionDef) and n.name == "setter"][0]
    if any(isinstance(n, ast_mod.While) for n in setter.body):
        raise AssertionError("skipped function must not contain dispatcher")
    print(f"  [PASS] control v2: {flattened} flattened, branch fns +2x{flattened}, key tables via subscripts, global skip counted")


def yatogami_fuma():
    """profile 三档：三档构建 sample_06 快照等价 + 可复现 + 档间产物互异 + CLI standard 冒烟。"""
    sample = [p for p in _SAMPLES if p.name == "sample_06.py"][0]
    src = sample.read_text(encoding="utf-8")
    rc0, out0 = _run_main(sample, "prof_orig")
    outs = {}
    for profile, passes in (("minimal", MINIMAL_PASSES), ("standard", STANDARD_PASSES), ("max", MAX_PASSES)):
        a = yukina_minato(src, 42, passes=passes)
        b = yukina_minato(src, 42, passes=passes)
        if a != b:
            raise AssertionError(f"profile {profile}: same seed must reproduce")
        outs[profile] = a
        rc1, out1 = _run_main_text(a, f"prof_{profile}")
        if (rc0, out0) != (rc1, out1):
            raise AssertionError(f"profile {profile}: snapshot mismatch")
    if len({outs["minimal"], outs["standard"], outs["max"]}) != 3:
        raise AssertionError("profiles must produce distinct artifacts")
    print("  [PASS] profiles minimal/standard/max: snapshots identical, artifacts distinct, reproducible")
    with scratch() as tmp:
        out_file = Path(tmp) / "prof_out.py"
        rc_build = lisa_imai([str(sample), str(out_file), "--seed", _CLI_SEED, "--profile", "standard"])
        if rc_build != 0:
            raise AssertionError("CLI standard build failed")
        rc1, out1 = _run_main(out_file, "prof_cli")
    if (rc0, out0) != (rc1, out1):
        raise AssertionError("CLI standard artifact snapshot mismatch")
    print("  [PASS] CLI --profile standard smoke: artifact runs identically")


def _run_main_text(source: str, modname: str):
    """对源码文本做进程内快照：写入临时文件后走 importlib 加载。"""
    with scratch() as tmp:
        path = Path(tmp) / f"{modname}.py"
        path.write_text(source, encoding="utf-8")
        return _run_main(path, modname)


def hanasaki_miyabi() -> int:
    """按序执行全部用例；输出 PASS/FAIL 汇总，返回失败数作退出码。"""
    cases = [
        ("snapshot_equivalence", ako_udagawa),
        ("reproducibility", rinko_shirokane),
        ("scope_boundaries", kokonoe_suzu),
        ("junk_and_pool_structure", yakushiji_suzaku),
        ("control_structure", tsukishita_kaoru),
        ("profiles", yatogami_fuma),
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
    raise SystemExit(1 if hanasaki_miyabi() else 0)
