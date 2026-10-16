# Copyright (C) 2026 Diderde
# SPDX-License-Identifier: GPL-3.0-only
"""layout.pass 重命名（v0 范围：函数局部变量，语义等价重命名）。

保守边界（每一条都是语义安全线，放宽前必须过差分与快照验收）：
  1. 只重命名**函数作用域内的 Store/Delete 名**（含 comprehension、walrus、
     except..as、with..as、del）；
  2. 函数参数一律不动——关键字调用兼容（跨文件调用面不可见）；
  3. 模块/类体级名字一律不动——全局名可被 from-import 引用（跨文件逃逸面）；
  4. global/nonlocal 声明名一律不动——绑定跨作用域；
  5. 同名既在函数内又在模块级的标识符整体跳过（保守去重）；
  6. 函数体内类体（cif）对闭包名的 **Load** 跟随重命名（LOAD_CLASSDEREF），
     但类体自身的 Store/Delete 是类属性，一律不动。
  重命名在同一模块内全局一致（alpha 重换名），闭包引用自然一致。
  同形字路线已否决（文献整理负面结论），新名来自 seeding 派生（无常数签名）。
"""
import ast

from pyshroud.passes.base import _observes_frame
from pyshroud.seeding.derive import ran_mitake, tsugumi_hazawa

_FUNC = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)
_DOC_HOSTS = (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)


def _arg_names(args_node):
    names = [x.arg for x in list(getattr(args_node, "posonlyargs", [])) + list(args_node.args) + list(args_node.kwonlyargs)]
    if args_node.vararg:
        names.append(args_node.vararg.arg)
    if args_node.kwarg:
        names.append(args_node.kwarg.arg)
    return names


def _walk_scoped(node, scope, on_func_store=None, on_name=None):
    """四作用域遍历：module / class / func / cif（函数体内类体）。

    on_func_store(name)：func 作用域的 Store/Delete 名回调；
    on_name(name_node, scope)：每个 Name 节点回调（重命名用）。
    函数的 decorators/defaults/annotations 在外层作用域求值，按外层遍历。

    作用域切换在**入口**判定（差分修复）：类定义作为节点进入本函数时
    （函数体逐语句调用形态），其体必须在 cif/class 作用域——旧实现只处理
    "类定义作为子节点"的形态，函数体内类体的类属性被误标为函数局部名，
    类属性访问（attr 不改名）随改名断裂。"""
    if isinstance(node, ast.ClassDef):
        scope = "cif" if scope == "func" else "class"
    if isinstance(node, ast.Name):
        # Name-as-节点必须就地处理（真实项目差分捕获：AnnAssign 分支把
        # target 以节点形态递归进来，旧实现只有 Name-as-子节点分支——嵌套在
        # while/if 里的注解赋值目标因此漏改名，读写断裂 NameError）。
        if on_name:
            on_name(node, scope)
        if on_func_store and scope == "func" and isinstance(node.ctx, (ast.Store, ast.Delete)):
            on_func_store(node.id)
        return
    for child in ast.iter_child_nodes(node):
        if isinstance(child, _FUNC):
            scope_enc = scope
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                # Lambda 无 decorator_list（真实代码差分捕获），装饰器处理须在 Def 守卫内。
                for dec in child.decorator_list:
                    _walk_scoped(dec, scope_enc, on_func_store, on_name)
                if child.returns:
                    _walk_scoped(child.returns, scope_enc, on_func_store, on_name)
                for a in list(getattr(child.args, "posonlyargs", [])) + list(child.args.args) + list(child.args.kwonlyargs):
                    if a.annotation:
                        _walk_scoped(a.annotation, scope_enc, on_func_store, on_name)
                for d in child.args.defaults:
                    _walk_scoped(d, scope_enc, on_func_store, on_name)
                for d in child.args.kw_defaults:
                    if d:
                        _walk_scoped(d, scope_enc, on_func_store, on_name)
                for stmt in child.body:
                    _walk_scoped(stmt, "func", on_func_store, on_name)
            else:  # Lambda
                # lambda 的参数同时也是它的局部名，**一律不重命名**（与普通函数
                # 参数同口径）；其 defaults 在外层作用域求值，按外层遍历。
                # 旧实现只走 body，导致 `lambda k=base: k+1` 里的 base（定义处求值、
                # 属外层）被当函数局部读而改名，外层绑定仍是原名 => 读写断裂
                # NameError（实测两个 profile 均复现，构建期静默）。
                for d in child.args.defaults:
                    _walk_scoped(d, scope, on_func_store, on_name)
                for d in child.args.kw_defaults:
                    if d:
                        _walk_scoped(d, scope, on_func_store, on_name)
                for a in list(getattr(child.args, "posonlyargs", [])) + list(child.args.args) + list(child.args.kwonlyargs):
                    if a.annotation:
                        _walk_scoped(a.annotation, scope, on_func_store, on_name)
                _walk_scoped(child.body, "func", on_func_store, on_name)
            continue
        if isinstance(child, (ast.Global, ast.Nonlocal)):
            continue
        if isinstance(child, ast.ClassDef):
            inner = "cif" if scope == "func" else "class"
            for dec in child.decorator_list:
                _walk_scoped(dec, scope, on_func_store, on_name)
            for base in child.bases:
                _walk_scoped(base, scope, on_func_store, on_name)
            for kw in child.keywords:
                _walk_scoped(kw.value, scope, on_func_store, on_name)
            for stmt in child.body:
                _walk_scoped(stmt, inner, on_func_store, on_name)
            continue
        if isinstance(child, ast.arg):
            if child.annotation:
                _walk_scoped(child.annotation, scope, on_func_store, on_name)
            continue
        if isinstance(child, ast.AnnAssign):
            # 注解整体跳过（前向引用字符串与类型名不做任何变换）
            _walk_scoped(child.target, scope, on_func_store, on_name)
            if child.value:
                _walk_scoped(child.value, scope, on_func_store, on_name)
            continue
        if isinstance(child, ast.Name):
            if on_name:
                on_name(child, scope)
            if on_func_store and scope == "func" and isinstance(child.ctx, (ast.Store, ast.Delete)):
                on_func_store(child.id)
            continue
        _walk_scoped(child, scope, on_func_store, on_name)


def _observed_names(tree) -> set:
    """自省保护面：出现自省调用的函数，其绑定的局部名整体不重命名。

    过近似：含嵌套函数体与 defaults 里的名字；宁可少改名，不改语义。"""
    out = set()
    for node in ast.walk(tree):
        if isinstance(node, _FUNC) and _observes_frame(node):
            _walk_scoped(node, "func", on_func_store=out.add)
    return out


def hina_hikawa(tree: ast.AST):
    """作用域扫描：返回 (可重命名局部名, 受保护名, 自省跳过局部名) 三元组。"""
    func_locals = set()
    protected = set()

    # 作用域无关的保护面：参数、函数/类定义名、global/nonlocal 声明名
    for node in ast.walk(tree):
        if isinstance(node, _FUNC):
            protected.update(_arg_names(node.args))
        # **lambda 参数也必须保护**：它们与普通函数参数同类（局部名，不可重命名），
        # 但 `_FUNC` 不含 Lambda，旧实现因此漏保护——与 _walk_scoped 的 lambda
        # defaults 缺陷叠加，产出运行时报 NameError 的坏产物（实测复现）。
        elif isinstance(node, ast.Lambda):
            protected.update(_arg_names(node.args))
        # 定义名保护：FunctionDef/AsyncFunctionDef 同属 _FUNC，写成 if/elif 会让
        # 本支永不执行（盲区修复）。函数名不是 Name 节点、改名改不到它，
        # 一旦漏保护，模块级 alpha 换名会改掉 def 之外的同名引用 => 读写断裂。
        # 同名的函数局部变量一并保守跳过（与保守边界 5 的去重口径一致）。
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            protected.add(node.name)
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            protected.update(node.names)

    # 作用域敏感：func 作用域 Store/Delete 记入候选，其余作用域的 Store/Delete 受保护
    def on_name(node, scope):
        if isinstance(node.ctx, (ast.Store, ast.Delete)):
            if scope == "func":
                func_locals.add(node.id)
            else:
                protected.add(node.id)

    _walk_scoped(tree, "module", on_func_store=None, on_name=on_name)
    observed = _observed_names(tree)
    protected |= observed
    return func_locals - protected, protected, func_locals & observed


def chisato_shirasagi(tree: ast.AST, ctx):
    """重命名 pass：按派生标识符一致重命名函数局部名（模块内 alpha 换名）；
    含帧自省的函数其局部名跳过并计入 ctx.stats（成功标准第 4 条）。"""
    locals_, _protected, skipped = hina_hikawa(tree)
    if skipped:
        ctx.stats["layout_skipped"] = ctx.stats.get("layout_skipped", 0) + len(skipped)
    if not locals_:
        return tree
    taken = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    taken |= {n.arg for n in ast.walk(tree) if isinstance(n, ast.arg)}
    taken |= {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    mapping = {}
    for name in sorted(locals_):
        new = tsugumi_hazawa(ctx, taken)
        mapping[name] = new
        taken.add(new)

    def rename(node, scope):
        if scope == "func":
            node.id = mapping[node.id]
        elif scope == "cif" and isinstance(node.ctx, ast.Load):
            node.id = mapping[node.id]

    _walk_scoped(
        tree,
        "module",
        on_name=lambda node, scope: rename(node, scope) if node.id in mapping else None,
    )
    return tree


_MATCH_NODES = (ast.Match, ast.match_case)


def kagami_kira(tree: ast.AST):
    """收集可入池的整数常量：返回 [(parent, field, index, node), ...]。
    跳过 bool（type 恰为 int 才收）、JoinedStr 子树、match 模式（模式须字面量）、
    注解、arg。"""
    hits = []

    def visit(node):
        if isinstance(node, ast.JoinedStr) or isinstance(node, _MATCH_NODES):
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
                if type(value.value) is int:
                    hits.append((node, field, None, value))
                continue
            if isinstance(value, ast.AST):
                _scan_value(node, field, None, None, value)
            elif isinstance(value, list):
                for idx, item in enumerate(value):
                    if isinstance(item, ast.AST):
                        _scan_value(node, field, idx, value, item)

    def _scan_value(parent, field, idx, holder, child):
        if isinstance(child, ast.JoinedStr) or isinstance(child, _MATCH_NODES):
            return
        if isinstance(child, ast.Constant):
            if type(child.value) is int:
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
    return hits


def arurandeisu(tree: ast.AST, ctx):
    """代码分离 pass：整数常量收入模块级派生命名池，引用改为池下标（值保持）。"""
    hits = kagami_kira(tree)
    if not hits:
        return tree
    taken = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    taken |= {n.arg for n in ast.walk(tree) if isinstance(n, ast.arg)}
    taken |= {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    pname = tsugumi_hazawa(ctx, taken)
    pool = []
    for parent, field, idx, node in hits:
        pool.append(node.value)
        sub = ast.Subscript(
            value=ast.Name(id=pname, ctx=ast.Load()),
            slice=ast.Constant(value=len(pool) - 1),
            ctx=ast.Load(),
        )
        ast.copy_location(sub, node)
        if idx is None:
            setattr(parent, field, sub)
        else:
            getattr(parent, field)[idx] = sub
    assign = ast.parse(f"{pname} = {pool!r}")
    from pyshroud.passes.base import fumino_tamaki

    fumino_tamaki(tree, assign.body)
    ast.fix_missing_locations(tree)
    return tree


def rikka(tree: ast.AST, ctx):
    """垃圾代码 pass：函数体顶部插入派生语句——死赋值与**构建期可证恒假**分支
    （a*b%m 与 (a*b%m+1)%m 比较，整数精确故永假）。恒假分支运行时不可达，
    不引入执行成本；静态可折叠是其强度上界（第 1 档，诚实标注）。"""
    taken = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    taken |= {n.arg for n in ast.walk(tree) if isinstance(n, ast.arg)}
    taken |= {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    taken |= ctx.taken
    for node in [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]:
        if not node.body:
            continue
        if _observes_frame(node):  # 自省函数：注入局部名会被 locals() 看见
            ctx.stats["junk_skipped"] = ctx.stats.get("junk_skipped", 0) + 1
            continue
        count = 1 + ctx.rng.below(3)
        stmts = []
        for _ in range(count):
            if ctx.rng.below(2) == 0:
                name = tsugumi_hazawa(ctx, taken)
                stmts.append(ast.parse(f"{name} = {ran_mitake(ctx)!r}").body[0])
            else:
                a = ran_mitake(ctx)
                b = ran_mitake(ctx)
                m = 2 + ctx.rng.below(999)
                r = ((a * b) % m + 1) % m
                n1 = tsugumi_hazawa(ctx, taken)
                n2 = tsugumi_hazawa(ctx, taken)
                src = (
                    f"if {a!r} * {b!r} % {m!r} == {r!r}:\n"
                    f"    {n1} = {ran_mitake(ctx)!r}\n"
                    f"    {n2} = {ran_mitake(ctx)!r}\n"
                )
                stmts.append(ast.parse(src).body[0])
        body = node.body
        offset = 1 if (
            body
            and isinstance(body[0], ast.Expr)
            and isinstance(body[0].value, ast.Constant)
            and isinstance(body[0].value.value, str)
        ) else 0
        body[offset:offset] = stmts
    ast.fix_missing_locations(tree)
    return tree
