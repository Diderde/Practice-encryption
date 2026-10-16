# Copyright (C) 2026 Diderde
# SPDX-License-Identifier: GPL-3.0-only
"""data.pass 字符串加密（v0 范围：XOR 流 + 模块内联解码器）。

边界（**覆盖什么**）：
  - **普通 str 常量**照常加密；
  - **f-string 的字面量片段**也加密（现代代码的主要字符串载体，此前整体跳过）：
    改写成加法拼接链，替换字段的表达式、转换（!r/!s/!a）与格式说明符一律原样保留；
    嵌在替换字段里的内层 f-string 同样处理（逐层自内向外）。
  - **跳过**：docstring（Module/FunctionDef/ClassDef 首语句）、注解内字符串、
    空串、bytes，以及两类**按设计豁免**的片段——
      ① 含反斜杠的片段：反斜杠非法的 f-string 必为 raw（`rf"\\d"`），其文本是
         字面反斜杠，加密再解码会把它变成真正的转义符，语义改变；
      ② 格式说明符内的片段：那里是格式文法，放入调用即语法错误。
    前三者（docstring/注解/空串）有运行时可观测语义（__doc__/前向引用），不碰；
  - 解码器与种子常量在构建期生成并内联进模块（runtime 双重身份的前身），
    其全部常数（乘子/加数/移位量/种子）由 seeding 派生——产物无常数签名；
  - 强度定位：编码式，强度第 1 档，诚实标注。**实测数字**（见
    tests/pyshroud/test_strength_metrics.py）：密钥流 4096 字节窗口熵
    7.9499 bit/byte、卡方 233.5（df=255）；1 比特 salt 翻转（bit 1..7）
    改变约 0.5 的密文比特，**bit 0 为无操作**（salt 被 `| 1` 强制置奇）；
    逐字节 XOR 不隐藏明文统计指纹，密文≠明文比例约 1/256 与明文内容无关。
"""
import ast

from pyshroud.seeding.derive import ran_mitake, tsugumi_hazawa

_MASK64 = (1 << 64) - 1
_DOC_HOSTS = (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)

_DECODER_TMPL = (
    "def {dname}({bname}, {sname}):\n"
    "    st = ({sconst} ^ (({sname} | 1) * {m1})) & 0xFFFFFFFFFFFFFFFF\n"
    "    buf = bytearray()\n"
    "    for c in {bname}:\n"
    "        st = (st + {a1}) & 0xFFFFFFFFFFFFFFFF\n"
    "        z = st\n"
    "        z = ((z ^ (z >> {sh1})) * {m2}) & 0xFFFFFFFFFFFFFFFF\n"
    "        z = ((z ^ (z >> {sh2})) * {m1}) & 0xFFFFFFFFFFFFFFFF\n"
    "        z = (z ^ (z >> {sh3})) & 255\n"
    "        buf.append(c ^ z)\n"
    "    return buf.decode(\"utf-8\")\n"
)


class _Join:
    """f-string 改写用的槽位标记：此 hit 不是"就地替换常量"，

    而是"把所在槽位的 f-string 换成 拼接链"（见 eve_wakamiya 的 _build_join）。

    为什么必须改写槽位：`ast.unparse` **不允许** JoinedStr 里出现 Call——
    AST 层面 f-string 的 values 只能含 Constant 与 FormattedValue。故
    `f"a{x}b"` 只能改写成 `(_enc(..) + f"{x}") + _enc(..)`，即把整条拼接
    表达式放回**持有该 f-string 的槽位**，而不是往 values 里塞调用。"""

    __slots__ = ("node",)

    def __init__(self, node):
        self.node = node


def _joined_hits(node: ast.JoinedStr, slot):
    """收集 f-string 的字面量片段：返回 [(parent, field, index, piece), ...]。

    `slot` 为该 f-string 在树中的持有位置 (parent, field, index)，由调用方在
    收集时给出（此时必然已知）；index 为 None 表示单值字段。**槽位随 hits 带回**，
    改写阶段因此无需再遍历全树定位。

    f-string 由字面量片段与替换字段（FormattedValue）交替组成；本函数只取前者，
    替换字段的表达式、转换（!r/!s/!a）与格式说明符一律原样保留。

    两条安全规则（任一命中即跳过该片段）：

      1. **含反斜杠的片段跳过**：反斜杠非法的 f-string 必须是 raw（`rf"\\d"`），
         其文本是字面反斜杠；加密后再解码会让反斜杠变成真正的转义符，**语义改变**。
         故保守跳过（反斜杠在 f-string 字面量里罕见，代价可接受）。
      2. **空片段跳过**：与普通字符串一致（空串无信息，且平白增加体积）。

    格式说明符内的片段**天然被隔离**：format_spec 恒为 FormattedValue 的子节点，
     而本函数只遍历顶层 values，不进入 FormattedValue。"""
    pieces = [p for p in node.values
              if isinstance(p, ast.Constant) and isinstance(p.value, str)
              and p.value and "\\" not in p.value]
    if not pieces or slot is None:
        return []
    return [(_Join(node), slot, None, piece) for piece in pieces]


def _nested_joined(node: ast.JoinedStr):
    """收集嵌在替换字段里的内层 f-string（PEP 701 允许 f-string 嵌套）。

    返回 [(parent, field, index, inner_joined), ...]：parent 为 FormattedValue，
    槽位即其 `value` 字段。**等价改写**——FormattedValue 内是任意表达式，
    内层 f-string 被换成加法链后仍是合法表达式：

        f"outer {f'inner {x}'} tail"  →  f"outer {_dec(..) + f'{x}'} tail"

    只下探 FormattedValue 的 value，**不进 format_spec**（那属格式文法）。"""
    out = []
    for part in node.values:
        if isinstance(part, ast.FormattedValue) and isinstance(part.value, ast.JoinedStr):
            out.append((part, "value", None, part.value))
    return out


def maya_yamato(tree: ast.AST):
    """收集可加密字符串常量：返回 (hits, nested)。

    hits：[(parent, field, index, node), ...]——普通字符串常量与 f-string 字面量
    片段；index 为 None 表示单值字段（setattr 替换），否则为列表下标。
    nested：[(FormattedValue, "value", None, inner_joined), ...]——嵌在替换字段里
    的内层 f-string，其槽位由调用方在同一轮内继续展开（可多级嵌套）。

    跳过：docstring、注解、空串、bytes、含反斜杠的片段。
    覆盖：普通字符串常量 + f-string 字面量片段（含嵌套 f-string）。"""
    hits = []
    nested = []

    def visit(node):
        if isinstance(node, ast.Match):
            # match 模式必须是字面量/类形：pattern 子树整体跳过（差分测试捕获，
            # 模式常量被换解码器调用后运行时报 "called match pattern must be a class"）；
            # subject/guard/body 是普通表达式与语句，照常处理。
            visit(node.subject)
            for case in node.cases:
                if case.guard:
                    visit(case.guard)
                for stmt in case.body:
                    visit(stmt)
            return
        if isinstance(node, _DOC_HOSTS):
            body = node.body
            start = 0
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str):
                start = 1
            for stmt in body[start:]:
                visit(stmt)
            for dec in getattr(node, "decorator_list", []):
                visit(dec)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for d in node.args.defaults:
                    visit(d)
                for d in node.args.kw_defaults:
                    if d:
                        visit(d)
            if isinstance(node, ast.ClassDef):
                for base in node.bases:
                    visit(base)
                for kw in node.keywords:
                    visit(kw.value)
            return
        for field, value in ast.iter_fields(node):
            if isinstance(value, ast.Constant):
                if isinstance(value.value, str) and value.value and "\\" not in value.value:
                    hits.append((node, field, None, value))
                continue
            if isinstance(value, ast.AST):
                _scan_value(node, field, None, None, value)
            elif isinstance(value, list):
                for idx, item in enumerate(value):
                    if isinstance(item, ast.AST):
                        _scan_value(node, field, idx, value, item)

    def _scan_value(parent, field, idx, holder, child):
        if isinstance(child, ast.JoinedStr):
            # f-string 不再整体跳过：本层字面量片段照常加密，替换字段原样保留；
            # 替换字段内若再嵌 f-string，登记其槽位交给后面的 pending 循环处理。
            # 槽位在**收集时**就已知（parent/field/index），随 hit 一并带回——
            # 否则改写阶段要拿整树 walk 去找持有位置（代价 O(f-strings × 树)）。
            slot = None if isinstance(parent, _Join) else (parent, field,
                                                           idx if holder is not None else None)
            hits.extend(_joined_hits(child, slot))
            nested.extend(_nested_joined(child))
            return
        if isinstance(child, ast.FormattedValue):
            # 替换字段的值是**任意表达式**，其间可能再嵌 f-string（PEP 701 允许）。
            # 只下探 value，**绝不进 format_spec**——那里是格式文法，放入调用即语法错误。
            if child.value is not None:
                _scan_value(child, "value", None, None, child.value)
            return
        if isinstance(child, ast.Constant):
            if isinstance(child.value, str) and child.value and "\\" not in child.value:
                hits.append((parent, field, idx if holder is not None else None, child))
            return
        if isinstance(child, ast.arg):
            return
        if isinstance(child, ast.AnnAssign):
            visit(child.target)
            if child.value:
                visit(child.value)
            return
        visit(child)

    visit(tree)
    return hits, nested


def eve_wakamiya(tree: ast.AST, ctx):
    """字符串加密 pass：派生解码器常数、内联解码器、逐串加盐加密替换。"""
    hits, nested = maya_yamato(tree)
    if not hits and not nested:
        return tree
    # 派生序固定：先解码器身份，再常数与逐串盐——同种子必同（seeding 契约）
    taken = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    taken |= {n.arg for n in ast.walk(tree) if isinstance(n, ast.arg)}
    taken |= {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    dname = tsugumi_hazawa(ctx, taken)
    sname = tsugumi_hazawa(ctx, ctx.taken)
    bname = tsugumi_hazawa(ctx, ctx.taken)
    seed_const = ran_mitake(ctx)
    m1 = ran_mitake(ctx) | 1
    m2 = ran_mitake(ctx) | 1
    a1 = ran_mitake(ctx) | 1
    sh1 = 18 + ctx.rng.below(20)
    sh2 = 14 + ctx.rng.below(18)
    sh3 = 22 + ctx.rng.below(20)

    def enc(data: bytes, salt: int) -> bytes:
        st = (seed_const ^ ((salt | 1) * m1)) & _MASK64
        out = bytearray()
        for c in data:
            st = (st + a1) & _MASK64
            z = st
            z = ((z ^ (z >> sh1)) * m2) & _MASK64
            z = ((z ^ (z >> sh2)) * m1) & _MASK64
            z = (z ^ (z >> sh3)) & 255
            out.append(c ^ z)
        return bytes(out)

    def _call_for(node):
        """为一个字符串片段生成解码器调用（逐串独立盐）。"""
        salt = ran_mitake(ctx)
        cipher = enc(node.value.encode("utf-8"), salt)
        call = ast.Call(
            func=ast.Name(id=dname, ctx=ast.Load()),
            args=[ast.Constant(value=cipher), ast.Constant(value=salt)],
            keywords=[],
        )
        ast.copy_location(call, node)
        return call

    # f-string 的片段按**所属 f-string** 归组：同一条 f-string 只改写一次槽位，
    # 改写成左结合加法链；片段保持原相对次序（左结合加法即左到右求值序）。
    # 槽位由收集阶段随 hit 带回，**不再整树 walk 定位**。
    joins = {}
    plain = []
    for parent, slot, idx, node in hits:
        if isinstance(parent, _Join):
            joins.setdefault(id(parent.node), (parent.node, slot, []))[2].append(node)
        else:
            plain.append((parent, slot, idx, node))

    for parent, field, idx, node in plain:
        call = _call_for(node)
        if idx is None:
            setattr(parent, field, call)
        else:
            holder = getattr(parent, field)
            holder[idx] = call

    def _rewrite_joined(jnode, slot):
        """把一条 f-string 改写为加法拼接链，并写回给定槽位。

        逐段重建：字面量片段 → 解码器调用；替换字段游程 → 只含这些字段的 f-string；
        片段之间以 Add 左结合相连（左结合即左到右求值序，与 f-string 原语义一致）。"""
        parts = []
        run = []
        for value in jnode.values:
            if isinstance(value, ast.Constant):
                if run:
                    parts.append(_as_joined(run, jnode))
                    run = []
                parts.append(_call_for(value))
            else:
                run.append(value)
        if run:
            parts.append(_as_joined(run, jnode))
        if not parts:
            return False
        chain = parts[0]
        for nxt in parts[1:]:
            chain = ast.BinOp(left=chain, op=ast.Add(), right=nxt)
        ast.copy_location(chain, jnode)
        s_parent, s_field, s_idx = slot
        if s_idx is None:
            setattr(s_parent, s_field, chain)
        else:
            holder = getattr(s_parent, s_field)
            holder[s_idx] = chain
        return True

    for jnode, jslot, pieces in joins.values():
        if jslot is None:
            continue  # 收集期未拿到槽位：保守放弃（不产出坏产物）
        _rewrite_joined(jnode, jslot)

    # 嵌套 f-string：槽位由收集阶段显式登记（FormattedValue.value），
    # 自内向外逐层改写。用登记槽位而非查树定位——查树会误命中外层，
    # 曾把 f-string 的 values 整个换成调用，触发 'Call' object is not iterable。
    pending = list(nested)
    while pending:
        parent, field, idx, inner = pending.pop()
        # 内层若还有更内层，先入队（后进先出 → 内层先改）
        pending.extend(_nested_joined(inner))
        _rewrite_joined(inner, (parent, field, idx))

    decoder_src = _DECODER_TMPL.format(
        dname=dname, bname=bname, sname=sname,
        sconst=repr(seed_const), m1=repr(m1), m2=repr(m2), a1=repr(a1),
        sh1=sh1, sh2=sh2, sh3=sh3,
    )
    decoder_tree = ast.parse(decoder_src)
    seed_assign = ast.parse(f"{sname} = {seed_const!r}")
    from pyshroud.passes.base import fumino_tamaki

    fumino_tamaki(tree, seed_assign.body + decoder_tree.body)
    ast.fix_missing_locations(tree)
    return tree


def _as_joined(values, location_from):
    """把一串 FormattedValue 包成 f-string（JoinedStr 的 values 只许含
    Constant 与 FormattedValue，故这里必然合法）。"""
    node = ast.JoinedStr(values=list(values))
    ast.copy_location(node, location_from)
    return node
