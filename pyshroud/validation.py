# Copyright (C) 2026 Diderde
# SPDX-License-Identifier: GPL-3.0-only
"""validation：pass 层表达式一致性校验（执行式闸门 + SMT 判定）。

范围（早期轮次 收窄后于扩入 T-函数步进一致性，见下）：**仅表达式层**——
MBA 恒等式与整数/位向量算术重写走 SMT 等价判定；**扁平化 T-函数的步进/轨道
一致性**走执行式副本闸门（实跑产物内联片段、逐轨道比对，不含 SMT）。布局、分离、
壳层两者都不做（只走差分与执行快照）。

范围变更记录：原 早期轮次 声明「扁平化不做 SMT 判定」。扁平化的**控制流**
仍不做 SMT（那是差分与执行快照的职责，原判断不变）；但扁平化在 `control.py`
内存在**三份必须逐位一致的 T-函数算术副本**（构建期派生、产物内联重建函数、
产物步进函数），其一致性是可判定命题且此前只靠经验验证——故按表达式层纳入。
两个入口：词法判定 tsukino_mito（既有）、T-函数副本闸门 momosuzu_nene（新）。

语义域（与 b_side 穷举闸门同域，逐条对齐）：
  输入 = w 位字（全部 2^w 个位模式——穷举闸门的 [0, 2^w) 与 BitVec 全域
  恰好同域）；运算语义 = Python 非负 w 位字语义：+ - * 与 & | ^ ~ 在 mod
  2^w 下同态（BitVec 天然一致）；>> 为**逻辑右移**（LShR：闸门域内移位
  对象恒为非负子项，Python >> 即逻辑移）；<< 为 SHL（溢出即掩码，与
  Python"无界左移后末端截断"在 mod 2^w 下一致）。% 与 / 不在本层子集
  （v1 恒等式库不含除法/取模；遇到即报 unsupported，不猜语义）。

判定：Solver 添加 (lhs != rhs) 求 unsat ⇒ 等价（对全部 2^(w·v) 输入成立）；
sat ⇒ 不等价；z3 unknown ⇒ unknown。超时 10s 防挂死。
z3-solver 为可选依赖（pass 验证件）：**懒加载**，缺失时调用方
得到明确 ImportError 提示，构建主路径不经过本模块（4.4 可选依赖纪律）。

执行面：momosuzu_nene 为验证产物**内联片段**而对其做 exec（受控输入、仅整数
算术、无外部引用）。这是本模块第二个执行点（另一个是 loader 的载荷执行），
由 tests/pyshroud/test_exec_surface.py 显式列白。
"""
import ast
import inspect
import types

_SUPPORTED_BINOPS = (ast.Add, ast.Sub, ast.Mult, ast.LShift, ast.RShift, ast.BitAnd, ast.BitOr, ast.BitXor)


def crimzon_ruze(node, w, env):
    """表达式 AST → z3 BitVec 表达式（w 位字语义，见模块 docstring）。

    env: {变量名: z3 BitVec 表达式}。子集外的节点抛 ValueError("unsupported: …")。"""
    z3 = env["__z3__"]
    if isinstance(node, ast.Expression):
        return crimzon_ruze(node.body, w, env)
    if isinstance(node, ast.Constant):
        if isinstance(node.value, bool) or not isinstance(node.value, int):
            raise ValueError(f"unsupported: constant {node.value!r}")
        return z3.BitVecVal(node.value, w)
    if isinstance(node, ast.Name):
        if node.id not in env:
            raise ValueError(f"unsupported: unknown name {node.id!r}")
        return env[node.id]
    if isinstance(node, ast.BinOp):
        lhs = crimzon_ruze(node.left, w, env)
        rhs = crimzon_ruze(node.right, w, env)
        op = type(node.op)
        if op is ast.Add:
            return lhs + rhs
        if op is ast.Sub:
            return lhs - rhs
        if op is ast.Mult:
            return lhs * rhs
        if op is ast.LShift:
            return lhs << rhs
        if op is ast.RShift:
            return z3.LShR(lhs, rhs)
        if op is ast.BitAnd:
            return lhs & rhs
        if op is ast.BitOr:
            return lhs | rhs
        if op is ast.BitXor:
            return lhs ^ rhs
        raise ValueError(f"unsupported: BinOp {op.__name__}")
    if isinstance(node, ast.UnaryOp):
        operand = crimzon_ruze(node.operand, w, env)
        op = type(node.op)
        if op is ast.Invert:
            return ~operand
        if op is ast.USub:
            return -operand
        if op is ast.UAdd:
            return operand
        raise ValueError(f"unsupported: UnaryOp {op.__name__}")
    raise ValueError(f"unsupported: node {type(node).__name__}")


def tsukino_mito(lhs_src, rhs_src, w, var_names):
    """两段表达式源码的等价判定：返回
    "equivalent" | "not-equivalent" | "unknown" | "unsupported: …"。"""
    try:
        z3 = _z3()
        lhs_tree = ast.parse(lhs_src, mode="eval")
        rhs_tree = ast.parse(rhs_src, mode="eval")
        env = {"__z3__": z3}
        for name in var_names:
            env[name] = z3.BitVec(name, w)
        lhs = crimzon_ruze(lhs_tree, w, env)
        rhs = crimzon_ruze(rhs_tree, w, env)
    except ValueError as exc:
        return str(exc)
    solver = _z3().Solver()
    solver.set(timeout=10000)
    solver.add(lhs != rhs)
    result = solver.check()
    if result == z3.unsat:
        return "equivalent"
    if result == z3.sat:
        return "not-equivalent"
    return "unknown"


def shibuya_hajime(pairs, w):
    """批量判定：[(name, lhs_src, rhs_src, var_names)] → [(name, verdict)]。"""
    return [(name, tsukino_mito(lhs, rhs, w, vars_)) for name, lhs, rhs, vars_ in pairs]


def _z3():
    """懒加载 z3（可选依赖纪律：缺失时给明确指引，不进构建主路径）。"""
    try:
        import z3
    except ImportError as exc:  # pragma: no cover - env-dependent
        raise ImportError(
            "z3-solver is required for expression validation: pip install z3-solver"
        ) from exc
    return z3


def momosuzu_nene(params, keys, guards, steps: int, emitted_src: str = None, w: int = 64):
    """扁平化 T-函数副本一致性判定（control.pass 的表达式层闸门）。

    params = (c1, c2, sh)；keys/guards 为构建期派生轨道（逐项 Python int）；
    emitted_src = control.kishido_temma 生成的产物内联源码（可选，传入即启用
    对**实际产物文本**的判定）。

    **不依赖 z3**：本闸门走执行法（下面第 2、3 项），z3 只在词法判定
    `tsukino_mito` 里用。历史教训：早先这里用 `_peek_z3()` 做准入，z3 缺席就整段
    降级为 unsupported——而闸门本体根本不用 z3，等于让"依赖没装"和"检查没跑"
    混为一谈（读者会以为闸门跑过了）。

    判三件事：

      1. **构建期轨道自洽**：Python int 复算 keys/guards，须逐项相等
         （抓"参数与轨道表配错"）；
      2. **产物文本副本等价**（传入 emitted_src 时）：解析产物内联源码，抽取
         重建形式（mk）与步进形式（st）的算术表达式，逐条判等价；
      3. **产物文本与构建期轨道一致**：产物表达式在起点上求值所得的整条轨道，
         须逐项等于 keys/guards。

    第 2、3 项针对**产物实际文本**，故能抓住"改了模板一处、漏了另一处"这类
    漂移（见 tests/pyshroud/test_validation_m5.py 的反例用例）。
    返回 dict：{status, detail, steps, width}；status 为 equivalent 表示全部通过。
    """
    c1, c2, sh = params
    if len(keys) < steps + 1 or len(guards) < steps + 1:
        return {"status": "unsupported", "detail": "trajectory shorter than steps", "steps": steps, "width": w}
    mask = (1 << w) - 1

    def builder_step(x, y):
        """构建期算术：与 control.yukoku_roberu 同源（x 先更新，y 混入 x' 高位）。"""
        x = (x + ((x * x | c1) + y)) & mask
        y = (y + ((y * y | c2) + (x >> sh))) & mask
        return x, y

    bx, by = keys[0], guards[0]
    for i in range(1, steps + 1):
        bx, by = builder_step(bx, by)
        if bx != keys[i] or by != guards[i]:
            return {
                "status": "not-equivalent",
                "detail": f"derived trajectory disagrees with recomputation at step {i}",
                "steps": steps,
                "width": w,
            }

    if emitted_src is None:
        return {
            "status": "equivalent",
            "detail": f"build-time trajectory self-consistent over {steps} steps (emitted text not checked)",
            "steps": steps,
            "width": w,
        }

    # 产物侧判定走**执行**而非 AST 形状匹配：把产物内联片段原样 exec，取出
    # 重建函数与步进函数直接调用。此前用正则/AST 形状重建算术，因「数值相同、
    # 写法不同」（mk 的形参名 vs st 的内联字面量）与算子优先级反复误判，且
    # 重建本身可能与被测文本不一致——执行法排除整类误判（实测确认）。
    ns = {}
    try:
        module = ast.parse(emitted_src)
        exec(compile(module, "<Practice-encryption emitted>", "exec"), ns)  # noqa: S102 - 执行面受守卫
    except SyntaxError as exc:
        return {"status": "unsupported", "detail": f"emitted source unparsable: {exc}", "steps": steps, "width": w}
    funcs = [v for k, v in ns.items() if isinstance(v, types.FunctionType)]
    rebuild = next((f for f in funcs if len(inspect.signature(f).parameters) == 5), None)
    stepper = next((f for f in funcs if len(inspect.signature(f).parameters) == 2), None)
    if rebuild is None or stepper is None:
        return {
            "status": "unsupported",
            "detail": f"emitted source lacks rebuild(5-arg)/step(2-arg) pair (found {len(funcs)} functions)",
            "steps": steps,
            "width": w,
        }

    # 判 1：重建形式必须复现构建期轨道
    rebuilt = rebuild(c1, c2, sh, keys[0], guards[0])
    if not (isinstance(rebuilt, tuple) and len(rebuilt) == 2):
        return {"status": "not-equivalent", "detail": f"rebuild returned {type(rebuilt).__name__}", "steps": steps, "width": w}
    rk, rg = list(rebuilt[0]), list(rebuilt[1])
    if rk[: steps + 1] != list(keys[: steps + 1]) or rg[: steps + 1] != list(guards[: steps + 1]):
        return {
            "status": "not-equivalent",
            "detail": "emitted rebuild trajectory disagrees with build-time derived trajectory",
            "steps": steps,
            "width": w,
        }

    # 判 2：步进形式逐步推进必须落在同一条轨道上
    sx, sy = keys[0], guards[0]
    for i in range(1, steps + 1):
        sx, sy = stepper(sx, sy)
        if sx != keys[i] or sy != guards[i]:
            return {
                "status": "not-equivalent",
                "detail": f"emitted step function diverges from trajectory at step {i}",
                "steps": steps,
                "width": w,
            }
    return {
        "status": "equivalent",
        "detail": "emitted rebuild + step both reproduce the derived trajectory",
        "steps": steps,
        "width": w,
    }
