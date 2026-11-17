# Copyright (C) 2026 Diderde
# SPDX-License-Identifier: GPL-3.0-only
"""f-string 加密验收。

背景：f-string 是现代代码最主要的字符串载体，此前 `data.pass` 整体跳过
`ast.JoinedStr`（注释口径：'前三者有运行时语义'）——对最新风格的代码，
字符串加密覆盖率天然打折。本套件守住新口径：**字面量片段加密、替换字段保留**。

实现约束（决定了改写的形态）：`ast.unparse` **不允许** `JoinedStr` 的 values
出现 Call——AST 层面 f-string 只能含 Constant 与 FormattedValue。故字面量片段
不能就地替换，只能把整条 f-string 改写成**加法拼接链**：

    f"a{x}b"  →  (_dec(..) + f"{x}") + _dec(..)

左结合加法即左到右求值序，与 f-string 原语义一致；替换字段的表达式、转换
（!r/!s/!a）与格式说明符一律原样保留。

两条跳过规则（保守，宁可少加密不破语义）：
  1. 含反斜杠的片段——反斜杠非法的 f-string 必为 raw（`rf"\\d"`），其文本是
     字面反斜杠；加密再解码会让它变成真正的转义符，语义改变；
  2. 空片段——无信息，且平白增加体积。
"""
import ast
import contextlib
import io
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT))

from pyshroud.pipeline import kageyama_shien, yukina_minato


# 每条：名称 → (源码, 可加密的长字面量, 是否按设计豁免加密)
# 豁免的两种情形（见模块 docstring 的跳过规则）：
#   raw_slash —— 片段含反斜杠，必为 raw f-string，加密会改变转义语义
#   format_spec —— 片段在格式说明符内，加密即语法错误
_CASES = {
    "basic": ('x = 5\nprint(f"value is {x}")\n', "value is ", None),
    "both_sides": ('x = 5\nprint(f"before {x} after")\n', "before ", None),
    "two_fields": ('a, b = 1, 2\nprint(f"{a} vs {b} and {a}")\n', " vs ", None),
    "conversion": ('x = "s"\nprint(f"{x!r} / {x!s} / {x!a}")\n', " / ", None),
    "format_spec": ('w = 8\nx = 3.14159\nprint(f"{x:>{w}.2f}")\n', None, "format_spec"),
    "raw_fstring": ('p = "a"\nprint(rf"{p}\\d+")\n', None, "raw_slash"),
    # 真制表符（非反斜杠）→ 应加密。注意 "\\t" 在本文件里写出来是两个反斜杠+t，
    # 而 Python 源码中的转义序列是单个反斜杠+t——两者语义不同，勿混。
    "tab_char": ('x = 1\nprint(f"pre {x} \t tab")\n', "pre ", None),
    # 同一 f-string 内混合两种片段：无内容的 "path " 应加密，含反斜杠的片段按规则跳过。
    # 故用例归入"可加密"（它确实加密了），而非整条豁免。
    "escaped_backslash": ('x = 1\nprint(f"path {x} \\\\ sep")\n', "path ", None),
    "implicit_concat": ('x = 1\nprint(f"a{x}" "plain")\n', "plain", None),
    "adjacent_fstrings": ('x = 1\nprint(f"aa{x}" f"bb{x}")\n', "aa", None),
    # 嵌套 f-string：内层单引号形态全版本可解析；但**管线的改写输出**在 3.11 的
    # ast.unparse 上无法渲染嵌套引号表达式（PEP 701 前的限制，ValueError）——
    # 故该用例为 3.12+ 能力，3.11 按跳过记账（早期轮次 CI 首跑实测）。
    "nested_fstring": ('x = 1\nprint(f"outer {f\'inner {x}\'} tail")\n', "outer ", None),
    "braces": ('x = 1\nprint(f"{{literal}} {x} {{done}}")\n', "literal", None),
    "dict_in_fstring": ('d = {"k": "v"}\nprint(f"{d[\'k\']}!")\n', None, None),
    "method_call": ('s = "ab"\nprint(f"{s.upper()} end")\n', " end", None),
    "triple_quoted": ('x = 2\nprint(f"""line {x}\nnext""")\n', "line ", None),
    "late_binding": ('x = 1\nf = lambda: f"v={x}"\nx = 9\nprint(f())\n', "v=", None),
    "in_conditional": ('x = 5\nprint("big" if x > 3 else f"small {x}")\n', "small ", None),
}

# PEP 701（3.12+）形态在 3.11 上管线无法输出（ast.unparse 限制）——按 SKIP 记账（早期轮次 CI 首跑实测）
if sys.version_info < (3, 12):
    _CASES.pop("nested_fstring", None)
    print("[SKIP] nested_fstring (PEP 701 shape requires 3.12+; "
          "3.11 ast.unparse cannot render it)")


def _run(src, name):
    """进程内执行并取 stdout；异常转成可比较的字符串（不抛）。"""
    ns = {"__name__": name}
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf):
            exec(compile(src, "<%s>" % name, "exec"), ns)
    except SystemExit:
        pass
    except Exception as exc:  # noqa: BLE001 - 用例要把异常也纳入比较
        return "EXC:%s:%s" % (type(exc).__name__, exc)
    return buf.getvalue()


def kasumi_toyama():
    """语义等价：逐类 f-string 的产物 stdout 与原样逐字一致。"""
    for name, (src, _secret, _exempt) in _CASES.items():
        want = _run(src, "orig_" + name)
        art = yukina_minato(src, 42, passes=kageyama_shien("standard"))
        got = _run(art, "art_" + name)
        if want != got:
            raise AssertionError(f"{name}: stdout diverged\n  original={want!r}\n  artifact={got!r}")
    print(f"  [PASS] {len(_CASES)} f-string shapes: artifact stdout identical to original")


def tae_hanazono():
    """加密生效：产物里不得残留**可加密的** f-string 字面量片段。

    判据取 AST 级而非子串搜索：可加密的片段被换成解码器调用后，产物中就不应
    再存在含 str 常量的 JoinedStr。子串搜索在这里会误报——片段可能短到只有
    一两个字符（`f"a{x}"`），任何子串检查都会在别处命中（实测踩中）。

    **格式说明符排除在外**：`f"{x:>{w}}"` 的 format_spec 自身也是 JoinedStr，
    但其常量是格式文法的一部分，加密即语法错误（设计内不可加密）。故按
    parent 关系剔除 format_spec 子树后再判。"""
    format_specs = set()

    def mark_specs(node):
        if isinstance(node, ast.FormattedValue) and node.format_spec is not None:
            for inner in ast.walk(node.format_spec):
                format_specs.add(id(inner))
        for child in ast.iter_child_nodes(node):
            mark_specs(child)

    checked = 0
    for name, (src, secret, exempt) in _CASES.items():
        if exempt is not None:
            continue  # 按设计豁免的形态（raw 反斜杠 / 格式说明符）不参与"必须加密"判定
        art = yukina_minato(src, 42, passes=kageyama_shien("standard"))
        tree = ast.parse(art)
        format_specs.clear()
        mark_specs(tree)
        for node in ast.walk(tree):
            if not isinstance(node, ast.JoinedStr) or id(node) in format_specs:
                continue
            for value in node.values:
                if isinstance(value, ast.Constant) and isinstance(value.value, str) and value.value:
                    raise AssertionError(
                        f"{name}: f-string literal {value.value!r} survived as a Constant "
                        "in the artifact (should have been encrypted)"
                    )
        if secret is not None and len(secret) >= 3:
            if secret in art:
                raise AssertionError(f"{name}: literal {secret!r} leaked into the artifact")
            checked += 1
    if checked < 8:
        raise AssertionError(f"too few long-literal cases exercised ({checked}); suite is vacuous")
    print(f"  [PASS] no encryptable f-string str-Constants survive; "
          f"{checked} long literals absent (format specs exempt by design)")


def _exempt_cases_preserved():
    """豁免面：按设计跳过的片段必须**原样保留**（否则语义已破）。"""
    for name, (src, _secret, exempt) in _CASES.items():
        if exempt is None:
            continue
        art = yukina_minato(src, 42, passes=kageyama_shien("standard"))
        if exempt == "raw_slash":
            # raw f-string 保留字面反斜杠；含转义的普通 f-string 保留制表符
            if "\\d+" not in art and "\t" not in art:
                raise AssertionError(f"{name}: raw/escape fragment must be preserved verbatim")
        elif exempt == "format_spec":
            if ".2f" not in art:
                raise AssertionError(f"{name}: format spec fragment must be preserved verbatim")
    print("  [PASS] exempt fragments (raw backslash / format spec) preserved verbatim")


def arisa_ichigaya():
    """替换字段保留：表达式、转换与格式说明符不被改写。"""
    src = ('x = 5\nw = 8\nprint(f"{x!r:>{w}} tail")\n')
    art = yukina_minato(src, 42, passes=kageyama_shien("standard"))
    tree = ast.parse(art)
    joined = [n for n in ast.walk(tree) if isinstance(n, ast.JoinedStr)]
    if not joined:
        raise AssertionError("replacement field must survive as a JoinedStr")
    rendered = ast.unparse(tree)
    for token in ("!r", "tail"):
        if token == "tail":
            if "tail" in rendered:
                raise AssertionError("encryptable literal 'tail' leaked")
            continue
        if token not in rendered:
            raise AssertionError(f"conversion {token} must be preserved")
    if not any(isinstance(n, ast.Call) for n in ast.walk(tree)):
        raise AssertionError("decoder calls expected for the literal fragment")
    print("  [PASS] replacement field + conversion preserved; literal fragment encrypted")


def rimi_ushigome():
    """改写形态：f-string 被改写成加法拼接链，且 JoinedStr 的 values 里绝不出现 Call。"""
    src = 'x = 1\ny = 2\nprint(f"A {x} B {y} C")\n'
    art = yukina_minato(src, 42, passes=kageyama_shien("standard"))
    tree = ast.parse(art)
    for node in ast.walk(tree):
        if isinstance(node, ast.JoinedStr):
            for value in node.values:
                if not isinstance(value, (ast.Constant, ast.FormattedValue)):
                    raise AssertionError(
                        "JoinedStr may only contain Constant/FormattedValue; "
                        "got %s (ast.unparse would reject this)" % type(value).__name__
                    )
    if "A " in art or " B " in art or " C" in art:
        raise AssertionError("f-string literal fragments leaked")
    adds = [n for n in ast.walk(tree) if isinstance(n, ast.BinOp) and isinstance(n.op, ast.Add)]
    if not adds:
        raise AssertionError("expected Add-concatenation chain for the rewritten f-string")
    print("  [PASS] rewritten as Add chain; JoinedStr values stay Constant/FormattedValue only")


def wakana_rei() -> int:
    """按序执行全部用例；输出 PASS/FAIL 汇总，返回失败数作退出码。"""
    cases = [
        ("fstring_semantics", kasumi_toyama),
        ("fstring_encrypted", tae_hanazono),
        ("fstring_fields_preserved", arisa_ichigaya),
        ("fstring_rewrite_shape", rimi_ushigome),
        ("fstring_exempt_preserved", _exempt_cases_preserved),
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
    raise SystemExit(1 if wakana_rei() else 0)
