# Copyright (C) 2026 Diderde
# SPDX-License-Identifier: GPL-3.0-only
"""设计天花板记录（#4 #5 #6 #7）：边界实测 + 防漂移断言。

这四项是项目已知的**设计边界**，此前只有定性描述（"只覆盖顶层直线语句"之类）。
本套件把它们变成**实测量值**并固化为断言，作用有二：

  1. 任何一项**悄悄变宽或变窄**都会在此暴露（例如有人放开重命名作用域，
     却忘了同步强度口径与兼容性承诺）；
  2. 对外表述有据可依——定性形容词换成可复现的数字。

量值口径（语料 = samples 4 份 + pyshroud 9 份 + markdown-reader/md_core 全部）：

  #4 扁平化可达面    : 函数体内**深度 1** 的语句占全部语句的 35%
                       （且深度 1 里还含循环/try/with/match，本 pass 故意不拆，
                        故真实可拆比例更低）
  #5 重命名可达面    : 标识符宇宙中 **26%** 可重命名（函数作用域 Store/Delete 名），
                       74% 按设计保留（参数、模块/类级名、属性）
  #6 壳强度          : 第 1 档——静态即可还原（密钥同住产物），另有实测：
                       解密流合成周期 256 字节（长载荷复用流片段）
  #7 Z3 可验证面     : BinOp 中 **89%** 在可判定子集内；% // / 占 11% 无验证路径，
                       比较与布尔运算（320 节点）同样在子集外

断言取**区间**而非精确值：语料会随开发变化，钉死小数会让本套件变成噪音。
区间的作用是守护"量级与方向"，这正是天花板口径需要的东西。
"""
import ast
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT))

from pyshroud.validation import _SUPPORTED_BINOPS

_VERIFIED_BINOPS = {t.__name__ for t in _SUPPORTED_BINOPS}


def _corpus():
    """量值语料：样本 + 构建端 + 真实项目（缺失的跳过，不因此失败）。"""
    out = {}
    for nm in ("sample_06", "sample_10", "sample_11", "sample_12"):
        p = _ROOT / "samples" / f"{nm}.py"
        if p.is_file():
            out[nm] = p.read_text(encoding="utf-8")
    for nm in ("pipeline", "metrics", "validation", "cli"):
        p = _ROOT / "pyshroud" / f"{nm}.py"
        if p.is_file():
            out[nm] = p.read_text(encoding="utf-8")
    for nm in ("layout", "control", "data", "shell", "base"):
        p = _ROOT / "pyshroud" / "passes" / f"{nm}.py"
        if p.is_file():
            out[nm] = p.read_text(encoding="utf-8")
    mrd = _ROOT.parent / "markdown-reader" / "md_core"
    if mrd.is_dir():
        for p in sorted(mrd.glob("*.py")):
            out["mr/" + p.name] = p.read_text(encoding="utf-8")
    return out


def _poset_partition(src):
    """返回 (depth1, deeper) 语句计数；depth1 = 函数体直接子语句。"""
    tree = ast.parse(src)
    d1 = deeper = 0
    for fn in [n for n in ast.walk(tree)
               if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]:
        body = fn.body
        start = 1 if (body and isinstance(body[0], ast.Expr)
                      and isinstance(body[0].value, ast.Constant)
                      and isinstance(body[0].value.value, str)) else 0
        top = body[start:]
        d1 += len(top)
        for stmt in top:
            deeper += sum(1 for c in ast.walk(stmt) if isinstance(c, ast.stmt) and c is not stmt)
    return d1, deeper


def _rename_partition(src):
    """返回 (universe, renamable)；两类**互斥**（renamable ⊆ universe）。"""
    tree = ast.parse(src)

    module_stores = set()
    for stmt in tree.body:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue  # 绝不进入 def/class 内部（曾因此把函数内名字当模块级）
        for sub in ast.walk(stmt):
            if isinstance(sub, ast.Name) and isinstance(sub.ctx, (ast.Store, ast.Del)):
                module_stores.add(sub.id)

    fn_stores = set()
    for fn in [n for n in ast.walk(tree)
               if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]:
        for sub in ast.walk(fn):
            if isinstance(sub, ast.Name) and isinstance(sub.ctx, (ast.Store, ast.Del)):
                fn_stores.add(sub.id)

    args = {n.arg for n in ast.walk(tree) if isinstance(n, ast.arg)}
    renamable = (fn_stores - module_stores) - args

    universe = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            universe.add(node.id)
        elif isinstance(node, ast.arg):
            universe.add(node.arg)
        elif isinstance(node, ast.Attribute):
            universe.add(node.attr)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            universe.add(node.name)
    return universe, renamable


def _ratio_in(name, value, lo, hi, unit="%"):
    if not (lo <= value <= hi):
        raise AssertionError("%s = %.1f%s is outside the recorded band [%.0f, %.0f]%s"
                             % (name, value, unit, lo, hi, unit))
    print("  [PASS] %s = %.1f%s (recorded band %.0f-%.0f)" % (name, value, unit, lo, hi))


def hoshino_ichika():
    """#4 扁平化可达面：深度 1 语句占比应落在记录区间。"""
    d1 = deep = 0
    for src in _corpus().values():
        a, b = _poset_partition(src)
        d1 += a
        deep += b
    total = d1 + deep
    if total == 0:
        raise AssertionError("empty corpus")
    pct = d1 / total * 100
    _ratio_in("#4 depth-1 statement share", pct, 25.0, 50.0)
    print("             (deeper statements, never eligible: %.0f%%)" % (deep / total * 100))


def shiina_yuika():
    """#5 重命名可达面：可重命名标识符占比应落在记录区间。"""
    uni = ren = 0
    for src in _corpus().values():
        u, r = _rename_partition(src)
        # invariant: renamable must be a subset of the universe
        if not r <= u:
            raise AssertionError("renamable set is not a subset of the identifier universe")
        uni += len(u)
        ren += len(r)
    if uni == 0:
        raise AssertionError("empty corpus")
    pct = ren / uni * 100
    _ratio_in("#5 renamable identifier share", pct, 15.0, 40.0)
    print("             (preserved by design: %.0f%%)" % (100 - pct))


def uzuki_kou():
    """#7 Z3 可验证面：BinOp 子集覆盖率应落在记录区间。"""
    ok = out = 0
    for src in _corpus().values():
        for node in ast.walk(ast.parse(src)):
            if isinstance(node, ast.BinOp):
                if type(node.op).__name__ in _VERIFIED_BINOPS:
                    ok += 1
                else:
                    out += 1
    total = ok + out
    if total == 0:
        raise AssertionError("no BinOp in corpus")
    pct = ok / total * 100
    _ratio_in("#7 BinOp in verifiable subset", pct, 75.0, 98.0)
    print("             (no verification path: %d nodes = %s)" % (
        out, "Mod/FloorDiv/Div"))


def yagi_michiyuki():
    """#6 壳强度：第 1 档定位与流周期须与文档一致（防表述漂移）。"""
    loader = (_ROOT / "pyshroud" / "runtime" / "loader.py").read_text(encoding="utf-8")
    for token, why in (
        ("强度第 1 档", "tier label must stay stated"),
        ("不提供机密性", "no-confidentiality statement must stay stated"),
        ("流周期", "measured stream period must stay documented"),
    ):
        if token not in loader:
            raise AssertionError("loader.py lost the shell-strength statement: %s (%s)" % (token, why))
    print("  [PASS] #6 shell tier-1 label + no-confidentiality + stream period all documented")


def suzumori_ema() -> int:
    """按序执行全部用例；输出 PASS/FAIL 汇总，返回失败数作退出码。"""
    cases = [
        ("ceiling_flattening_reach", hoshino_ichika),
        ("ceiling_rename_reach", shiina_yuika),
        ("ceiling_z3_subset", uzuki_kou),
        ("ceiling_shell_strength", yagi_michiyuki),
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
    raise SystemExit(1 if suzumori_ema() else 0)
