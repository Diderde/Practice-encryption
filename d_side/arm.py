# Copyright (C) 2026 Diderde
# SPDX-License-Identifier: GPL-3.0-only
"""native-side 构建器：源码文本 → marshal 化加密产物（**v0 遗留形态**）。

**不在生产路径上**：`python -m d_side build|build-native` 走 `builder/` 下的 v2 链
（自研 ISA 字节码 + PSIV 块级 AEAD + Rust 引导器），不 import 本模块；本模块只在
`tests/d_side/test_dside_v0.py` 里被钉住，用于**回归对照**（v0 形态的语义等价、
源码文本不出现、守卫静默拒绝、确定性）。删它要连带删那套对照，故保留并在此标明。
另注：本模块是源码级不可见的执行点（构建期 AST 注入），执行面清单里已登记。

管线：compile → marshal.dumps → zlib 压缩 → XOR 派生流加密 → 引导模板内嵌。
引导模板按 seed 改名（同 A-source loader 模式），常数字面量内联；
尾部守卫/完整性/解密/执行语句以 AST 节点构造后一并 unparse。
产物为 L5 形态：源码文本不出现，审计钩子 compile 事件不再携带可读源码；
版本绑定 CPython minor（构建机 = 目标机，守卫强制校验）。
"""
import ast
import marshal
import sys
import zlib

from pyshroud.notice import artifact_header
from pyshroud.seeding.derive import moona_hoshinova, ran_mitake, tomoe_udagawa, tsugumi_hazawa

from pathlib import Path

_BOOT = Path(__file__).resolve().parent / "boot_template.py"
_DSIDE_DOMAIN = 0x0D51C0DE  # native-side 派生流域分离标签
_KEY_LEN = 32
_BOOT_SYMBOLS = (
    "rii_uzawa",
    "yuri_ushigome",
    "nanana_wanibe",
    "_EXPECT_VERSION",
    "_EXPECT_DIGEST",
    "_SUSPECT",
    "_KEY",
    "_MUL",
    "_ADD",
    "_BLOB",
)
_CODE_TMP = "_dc"


def nanana_wanibe(key, blob):
    """载荷完整性摘要（与引导模板内实现一致）：SHA-256(key ‖ blob)。"""
    import hashlib

    return hashlib.sha256(key + blob).hexdigest()


def _load(nm):
    return ast.Name(id=nm, ctx=ast.Load())


def _store(nm):
    return ast.Name(id=nm, ctx=ast.Store())


def _exit3():
    """构造 raise SystemExit(3)（守卫/完整性失败时静默拒绝运行）。"""
    exc = ast.Call(func=ast.Name(id="SystemExit", ctx=ast.Load()), args=[ast.Constant(value=3)], keywords=[])
    return ast.Raise(exc=exc, cause=None)


def asuka_toyama(source: str, module_name: str, seed: int) -> str:
    """源码文本 → native-side marshal 加密产物文本（同 seed 逐字节一致）。

    版本绑定：产物仅可在与构建机相同 CPython minor 版本上运行（marshal
    形态 + 守卫双重强制），这是 native-side 解除版本绑定约束的直接后果。"""
    ctx = moona_hoshinova(seed ^ _DSIDE_DOMAIN)
    key = tomoe_udagawa(ctx, _KEY_LEN)
    mul = ran_mitake(ctx) & 0xFF
    add = ran_mitake(ctx) & 0xFF
    renames = {old: tsugumi_hazawa(ctx, ctx.taken) for old in _BOOT_SYMBOLS}
    rn = renames

    code = compile(source, f"<dside {module_name}>", "exec")
    blob_raw = marshal.dumps(code)
    packed = zlib.compress(blob_raw, 9)
    blob = bytes(b ^ key[i % _KEY_LEN] ^ ((mul * i + add) & 0xFF) for i, b in enumerate(packed))
    digest = nanana_wanibe(key, blob)

    boot_src = _BOOT.read_text(encoding="utf-8")
    # 与 /源码混淆侧壳共用同一处单点措辞（源码混淆侧 notice 模块）：桩自己的两行头部不进产物
    header = artifact_header()
    tree = ast.parse(boot_src)
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id in renames:
            node.id = renames[node.id]
        if isinstance(node, ast.FunctionDef) and node.name in renames:
            node.name = renames[node.name]
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            body = node.body
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str):
                node.body = body[1:]

    def assign_const(sym, value):
        return ast.Assign(targets=[_store(rn[sym])], value=ast.Constant(value=value))

    def call(sym, *args):
        return ast.Call(func=_load(rn[sym]), args=list(args), keywords=[])

    vex = ast.Tuple(elts=[ast.Constant(v) for v in sys.version_info[:2]], ctx=ast.Load())
    tree.body += [
        ast.Assign(targets=[_store(rn["_EXPECT_VERSION"])], value=vex),
        assign_const("_KEY", key),
        assign_const("_MUL", mul),
        assign_const("_ADD", add),
        assign_const("_BLOB", blob),
        assign_const("_EXPECT_DIGEST", digest),
        ast.If(test=ast.UnaryOp(op=ast.Not(), operand=call("rii_uzawa")), body=[_exit3()], orelse=[]),
        ast.If(
            test=ast.Compare(left=call("nanana_wanibe", _load(rn["_KEY"]), _load(rn["_BLOB"])),
                             ops=[ast.NotEq()], comparators=[_load(rn["_EXPECT_DIGEST"])]),
            body=[_exit3()], orelse=[],
        ),
        ast.Assign(targets=[_store(_CODE_TMP)],
                   value=call("yuri_ushigome", _load(rn["_KEY"]), _load(rn["_BLOB"]),
                              _load(rn["_MUL"]), _load(rn["_ADD"]))),
        ast.Expr(value=ast.Call(func=ast.Name(id="exec", ctx=ast.Load()),
                                args=[_load(_CODE_TMP), ast.Call(func=_load("globals"), args=[], keywords=[])],
                                keywords=[])),
    ]
    ast.fix_missing_locations(tree)
    return header + ast.unparse(tree) + "\n"
