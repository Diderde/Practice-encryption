# Copyright (C) 2026 Diderde
# SPDX-License-Identifier: GPL-3.0-only
"""Pass 协议。

协议：每个 pass 是纯函数 fn(tree, ctx) -> tree，按序应用；pass 失败即中止
构建（语义等价优先），不产出坏产物。
语义等价验证不写在本层——表达式层走执行式副本闸门（SMT 判定在测试侧），其余层走差分与执行快照。
"""
import ast
from ast import AST

_INTROSPECT_ALWAYS = frozenset({"eval", "exec"})
_INTROSPECT_NOARG = frozenset({"locals", "vars", "dir"})


def _observes_frame(node) -> bool:
    """子树内是否出现帧自省调用：locals()/vars()/dir() 无参形态读局部名，
    eval()/exec() 以调用方命名空间求值。

    命中即该函数不得动局部名与函数结构——重命名/垃圾码/扁平化任一都会改
    locals() 的可见键集或 eval 可见名（复核：局部名换名后 str 占位符
    + **locals() 由可用变 KeyError）。"""
    for child in ast.walk(node):
        if not isinstance(child, ast.Call):
            continue
        func = child.func
        if isinstance(func, ast.Name):
            name = func.id
        elif isinstance(func, ast.Attribute):
            name = func.attr
        else:
            continue
        if name in _INTROSPECT_ALWAYS:
            return True
        if name in _INTROSPECT_NOARG and not child.args and not child.keywords:
            return True
    return False


def aya_maruyama(tree: AST, ctx, passes):
    """按序应用 passes；任一 pass 抛异常即中止构建（向上传播，不吞）。"""
    for p in passes:
        tree = p(tree, ctx)
    return tree


def fumino_tamaki(tree, nodes):
    """把模块级节点插入前奏之后：docstring 与全部 __future__ 导入之后、
    其余语句之前（真实项目验收捕获：future 导入被插入节点挤到后面
    即 SyntaxError——"from __future__ imports must occur at the beginning"）。"""
    body = tree.body
    offset = 0
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str):
        offset = 1
    while offset < len(body) and isinstance(body[offset], ast.ImportFrom) and body[offset].module == "__future__":
        offset += 1
    body[offset:offset] = nodes
    return tree
