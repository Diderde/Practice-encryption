# Copyright (C) 2026 Diderde
# SPDX-License-Identifier: GPL-3.0-only
"""control.pass 控制流扁平化（完成形态，obfuscation-side 简化件口径）。

变换（保守形态，正确性优先）：
  - 只压平**函数顶层语句序列**：相邻直线语句按派生粒度合并成块（每块 2~4 条，
    逐块从 seeding 取用；循环/try/with/match 不拆开，break/continue 的目标
    关系原样保留；顶层不可能出现 break/continue——源码层面即非法）；
  - 块链进入 `while True` 分发器：`if state == _sk[i] and guard == _jg[i]:`
    ——键表在产物运行期按派生标量循环重建（Cappaert–Preneel 强化①的变体：
    少量派生标量替代 N 个键字面，产物体积不再随块数线性膨胀），构建期已
    验证轨道不提前重复；
  - 后继转移为**双变量耦合的二次 T-函数**（多字/多变量方向，Klimov–Shamir
    谱系；强化②）。**规范定义在 数学区** `b_side.primitives.tfunc.emma_august`，
    本文件与产物与之逐位一致由 tests/pyshroud/test_validation_m5.py 钉死：

        state = (state + ((state*state | c1) + guard)) & MASK
        guard = (guard + ((guard*guard | c2) + (state >> sh))) & MASK

    三角性按**实测口径**（数学区 tfunc 模块 docstring 固化，勿凭直觉改写）：
    x' 分量**保持**三角（低位输入全零时翻转高位不改输出低位，全域穷举零违反）；
    y' 分量因 `(x' >> sh)` 把 x' 高位灌入自身低位而**打破**三角（违反数随参数变化：
    w=8 全域穷举实测 sh=0→0、sh=1/7→10922、sh=2/6→12286，规范样例 sh=13%w 为 12454，
    见 数学区 tfunc 的逐位宽钉住用例）——故两条链必须**联合**求解，这正是相对经典单字 T-函数
    （LSB 短周期与逐位恢复弱点，TF-0/TF-1 谱系）的增量所在。双射性由 数学区
    `chiyo_tamade` 的**构造性逐位逆**给出（w≤9 全域实证，非概率检查）。
    乘法型更新（M-函数思路）以移位下移替代以避免引入未实证的周期断言。
    后继计算在**模块级步进函数**内完成（Linn–Debray 分支函数形态，强化③）；
    键序列即轨道——键表由构建期传入的 (c1, c2, sh, 起点) 在产物内**运行期
    重建**，构建期派生轨道与产物两份副本（重建 mk / 步进 st）的一致性由
    validation.momosuzu_nene 在表达式层判定。注意判定的是副本一致与
    轨道可复现，**不是密码强度声明**，也不是周期断言；
  - `return` 在块内自然返回，不改写；双状态变量联合判别即**动态关联式谓词**——
    其真值依赖运行时状态，因此构建期无法常量折叠（这是本 pass 选用它的理由）。

适用性（不适用即跳过并计数入 ctx.stats，成功标准第 4 条）：
  顶层含 Global/Nonlocal（文本序语义敏感）或无可执行语句的函数跳过。
  全部常数（T-函数参数、移位量、键表重建参数、块粒度序列、状态变量名、
  步进函数名）由 seeding 派生——无常数签名。每函数一组独立参数；模块级
  增补（轨道构建函数/步进函数/键表与守卫表）由 pass 统一插回 docstring 之后。

强度如实标注：扁平化对数据流求解器（stadeo 类）与符号执行的抵抗有限——
状态变量一旦被识别，转移函数体在产物内可读，整链即可复算；本 pass 的增量
在抬高该识别与求解的成本（双变量耦合、非仿射二次转移、键表运行期重建、
块粒度派生）。
"""
import ast

from pyshroud import validation
from pyshroud.passes.base import _observes_frame
from pyshroud.seeding.derive import ran_mitake, tsugumi_hazawa

_FUNC = (ast.FunctionDef, ast.AsyncFunctionDef)
_MASK64 = (1 << 64) - 1


def astel_leda(fn):
    """适用性判定：可压平返回 True；顶层含 Global/Nonlocal、含帧自省调用
    （扁平化会注入 state/guard 局部名，进 locals()）或无可执行语句返回 False。"""
    if _observes_frame(fn):
        return False
    body = fn.body
    start = 0
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str):
        start = 1
    stmts = body[start:]
    if not stmts:
        return False
    for s in stmts:
        if isinstance(s, (ast.Global, ast.Nonlocal)):
            return False
    return True


def yukoku_roberu(ctx, count: int):
    """派生双变量耦合 T-函数轨道与参数：state/guard 两条链按

        x' = (x + ((x*x | c1) + y)) & MASK
        y' = (y + ((y*y | c2) + (x' >> sh))) & MASK

    交替推进（y 的更新混入 x' 的中高位——上→下耦合打破逐位三角性）。
    返回 (keys, guards, (c1, c2, sh))；构建期验证 (x, y) 二元组不提前重复，
    8 次重派仍失败则返回 None。规范形式见 数学区 `tfunc.emma_august`（本函数
    与之逐位一致，由测试钉死）。**周期性质不做理论断言**（不声称轨道长度或
    遍历性）；但**轨道与产物副本的一致性**已由 validation.momosuzu_nene 在
    表达式层判定，不再是经验验证。"""
    for _ in range(8):
        c1 = ran_mitake(ctx) | 1
        c2 = ran_mitake(ctx) | 1
        sh = 13 + ran_mitake(ctx) % 40
        x = ran_mitake(ctx)
        y = ran_mitake(ctx)
        seen = {(x, y)}
        keys, guards = [x], [y]
        ok = True
        for _ in range(count):
            x = (x + ((x * x | c1) + y)) & _MASK64
            y = (y + ((y * y | c2) + (x >> sh))) & _MASK64
            if (x, y) in seen:
                ok = False
                break
            seen.add((x, y))
            keys.append(x)
            guards.append(y)
        if ok:
            return keys, guards, (c1, c2, sh)
    return None


def harusaki_air(stmts, ctx):
    """相邻直线语句按派生粒度合并成块：每块 2~4 条（逐块派生），余数原样收尾。

    块粒度变粗只减少块数——分发器比较与后继转移按块计，块内语句仍按文本序
    执行，语义不变。粒度范围（2~4）是设计参数（同 _KEY_LEN 的地位），逐块
    取值走 seeding 派生，无常数签名。"""
    groups = []
    i = 0
    while i < len(stmts):
        k = 2 + ran_mitake(ctx) % 3
        groups.append(stmts[i:i + k])
        i += k
    return groups


def kishido_temma(tree, fn, ctx, params, groups):
    """执行压平：分块后的顶层语句块序列 → 双变量分发器（键表引用 + 统一赋值
    + 步进函数）。返回需插入模块级的增补节点列表。"""
    keys, guards, (c1, c2, sh) = params
    body = fn.body
    start = 0
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str):
        start = 1
    if not groups:
        return []
    taken = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    taken |= {n.arg for n in ast.walk(tree) if isinstance(n, ast.arg)}
    taken |= {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    sv = tsugumi_hazawa(ctx, taken)
    jv = tsugumi_hazawa(ctx, ctx.taken)
    sk = tsugumi_hazawa(ctx, ctx.taken)
    jg = tsugumi_hazawa(ctx, ctx.taken)
    st = tsugumi_hazawa(ctx, ctx.taken)
    mk = tsugumi_hazawa(ctx, ctx.taken)

    def name_load(nm):
        return ast.Name(id=nm, ctx=ast.Load())

    def name_store(nm):
        return ast.Name(id=nm, ctx=ast.Store())

    def make_subscript(tbl, i):
        return ast.Subscript(value=name_load(tbl), slice=ast.Constant(value=i), ctx=ast.Load())

    # 平铺兄弟 if + continue（而非嵌套 if/else 链）：块链语义不变（任一时刻至多一个
    # 键匹配；转移后 continue 回顶，全不匹配落到收尾 break），但分发器嵌套深度恒为
    # O(1)——旧形态把 N 块折成 N 层嵌套 If，N 大时先把后续递归 pass 顶到递归上限
    # （复核捕获：单函数约 600 条顶层语句即 RecursionError，且为未捕获裸栈）。
    handlers = []
    for i, block in enumerate(groups):
        test = ast.BoolOp(
            op=ast.And(),
            values=[
                ast.Compare(left=name_load(sv), ops=[ast.Eq()], comparators=[make_subscript(sk, i)]),
                ast.Compare(left=name_load(jv), ops=[ast.Eq()], comparators=[make_subscript(jg, i)]),
            ],
        )
        step = [
            *block,
            ast.Assign(
                targets=[ast.Tuple(elts=[name_store(sv), name_store(jv)], ctx=ast.Store())],
                value=ast.Call(func=name_load(st), args=[name_load(sv), name_load(jv)], keywords=[]),
            ),
            ast.Continue(),
        ]
        handlers.append(ast.If(test=test, body=step, orelse=[]))
    handlers.append(ast.Break())
    prelude = [
        ast.Assign(targets=[name_store(sv)], value=ast.Constant(value=keys[0])),
        ast.Assign(targets=[name_store(jv)], value=ast.Constant(value=guards[0])),
    ]
    dispatcher = ast.While(test=ast.Constant(value=True), body=handlers, orelse=[])
    fn.body = body[:start] + prelude + [dispatcher]

    # 键表/守卫表运行期重建：N 对 64 位键字面收敛为每对轨道 3 个派生标量
    # (c1, c2, sh) + 起点对 + 几行重建循环；轨道值与构建期验证的序列逐项相同
    # （纯整数运算，同参数必同序列，确定性锚不受影响）。
    additions = ast.parse(
        f"def {mk}(c1, c2, sh, x, y):\n"
        f"    tx = [x]\n"
        f"    ty = [y]\n"
        f"    for _ in range({len(groups)}):\n"
        f"        x = (x + ((x * x | c1) + y)) & 0xFFFFFFFFFFFFFFFF\n"
        f"        y = (y + ((y * y | c2) + (x >> sh))) & 0xFFFFFFFFFFFFFFFF\n"
        f"        tx.append(x)\n"
        f"        ty.append(y)\n"
        f"    return tuple(tx), tuple(ty)\n"
        f"{sk}, {jg} = {mk}({c1!r}, {c2!r}, {sh!r}, {keys[0]!r}, {guards[0]!r})\n"
        f"def {st}(x, y):\n"
        # 步进函数的自由常数必须内联为字面量：mk 的参数不出它的作用域。
        f"    x = (x + ((x * x | {c1!r}) + y)) & 0xFFFFFFFFFFFFFFFF\n"
        f"    y = (y + ((y * y | {c2!r}) + (x >> {sh!r}))) & 0xFFFFFFFFFFFFFFFF\n"
        f"    return x, y\n"
    ).body
    return additions


def aragami_oga(tree: ast.AST, ctx):
    """control 扁平化 pass：逐函数尝试；顶层直线语句先按派生粒度分块再压平；
    跳过计数入 ctx.stats（成功标准第 4 条）；增补统一插回模块 docstring 之后。"""
    stats = ctx.stats
    additions = []
    for node in [n for n in ast.walk(tree) if isinstance(n, _FUNC)]:
        if not astel_leda(node):
            stats["control_skipped"] = stats.get("control_skipped", 0) + 1
            continue
        body = node.body
        start = 0
        if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str):
            start = 1
        groups = harusaki_air(body[start:], ctx)
        params = yukoku_roberu(ctx, len(groups))
        if params is None:
            stats["control_skipped"] = stats.get("control_skipped", 0) + 1
            continue
        adds = kishido_temma(tree, node, ctx, params, groups)
        if not adds:
            stats["control_skipped"] = stats.get("control_skipped", 0) + 1
            continue
        # 表达式层自检：产物内的两份 T-函数副本（内联重建 mk / 步进 st）
        # 与构建期派生轨道必须逐项一致。此前这条只靠经验验证；现在由
        # validation.momosuzu_nene 判定——判的是**实际产物文本**（adds 反 unparse
        # 后的源码），故能抓住"改了模板一处、漏了另一处"。该闸门走执行法、
        # **不依赖 z3**（z3 只服务词法等价判定），故不受可选依赖缺席影响。
        keys, guards, tparams = params
        emitted_src = ast.unparse(ast.Module(body=adds, type_ignores=[]))
        verdict = validation.momosuzu_nene(
            tparams, keys, guards, len(groups), emitted_src=emitted_src
        )
        stats["tfunc_gate"] = verdict["status"]
        if verdict["status"] == "not-equivalent":
            raise ValueError(
                "control.pass expression gate failed (T-function copies diverged): %s"
                % verdict["detail"]
            )
        additions.extend(adds)
        stats["control_flattened"] = stats.get("control_flattened", 0) + 1
    if additions:
        from pyshroud.passes.base import fumino_tamaki

        fumino_tamaki(tree, additions)
    ast.fix_missing_locations(tree)
    return tree
