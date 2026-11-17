# Copyright (C) 2026 Diderde
# SPDX-License-Identifier: GPL-3.0-only
"""vm_compiler：marshal code object → VM IR 编译器（"线性+分支+调用"子集）。

由 `.tmp/u16_probe/p2/compiler.py` 升格，翻译规则与探针**逐式对齐**（双路径互钉的前提）：
栈机 → 寄存器机（编译期虚拟栈保存临时寄存器号，栈条目带静态类型标签）；局部变量按
`co_varnames` 固定寄存器（r0.. = 参数）；全局/内建在编译期解析为全局表索引（运行期不出现
名字字符串）。

覆盖的 3.12.10 实测字节码：RESUME / LOAD_CONST(int|bool|None|str|tuple) / STORE_NAME /
LOAD_NAME / MAKE_FUNCTION / RETURN_CONST / RETURN_VALUE / LOAD_FAST / STORE_FAST /
COMPARE_OP / POP_JUMP_IF_FALSE / **POP_JUMP_IF_TRUE / POP_JUMP_IF_NONE /
POP_JUMP_IF_NOT_NONE**（升格期新增：ISA 没有"jump-if-truthy"，等价展开成
`JZ→下一条 + JMP→目标` 两拍）/ BINARY_OP(+ - * ^) / **BINARY_SUBSCR**（：GETITEM）/
JUMP_BACKWARD / LOAD_GLOBAL / CALL / GET_ITER / FOR_ITER / END_FOR / POP_TOP / PUSH_NULL /
**EXTENDED_ARG**（升格期新增：`dis` 已把 oparg 折叠进后继指令，本指令只需跳过）。

（ISA v2）新增接入：字符串常量走模块级去重池（LOADS，u16 索引）、bool 常量（LOADB）、
None 常量（LOADN）、字符串拼接（BINARY_OP + 两侧静态已知 str 时发 CONCAT——与 CPython +
同界，混合已知类型即拒）、print 多参（native print 任意 argc，空格连接）。
（ISA v2）新增：元组常量按"逐元素装载 + TUPLE 运行期构建"编译（等价于常量池语义、
免一类 blob 解析面；对原登记项"globals 段加 kind 字节"的替代已在设计文档登记），
下标取值 BINARY_SUBSCR → GETITEM（越界运行期故障，不给错值）。

子集外语义（异常表 / 闭包 / 推导式 / 容器构造（list/dict/set）/ 方法调用 / SWAP / COPY /
f-string / 越出 repr 子集的元组字符串元素等）**一律 fail-closed 抛出**，绝不静默错译：
v2 子集能保护什么由这张表定义。
"""
import dis

from d_side.builder.vm_isa import G_ARGV_LEN, G_STDIN_LEN, INTRINSICS, OP_WIDTHS

# 早期轮次 输入依赖：main(argv, stdin) 形态下，这两个名字**不是值**而是"输入窗口句柄"
# 的编译期标签——只有 `x[i]` 与 `len(x)` 两种用法被翻译成输入原语，其余用法一律子集拒。
_INPUT_KIND = {"argv": G_ARGV_LEN, "stdin": G_STDIN_LEN}
_NB = {0: "ADD", 10: "SUB", 5: "MUL", 2: "FLOORDIV", 12: "XOR"}   # BINARY_OP oparg → 逻辑操作
# 早期轮次+C（ISA v5）：`rotl32(a, k)` 这类**内建**在调用位点直接展开成操作码——名字来自
# vm_isa.INTRINSICS 单源（同一张表还带 CPython 参考实现，供出厂门与 harness 用）。
# 内建不进全局表、不占寄存器、名字不落产物（v2 blob 里没有符号名，只有索引）。
_INTRINSIC = {n: (op, ar) for n, (op, ar, _ref) in INTRINSICS.items()}
_CMP = {0: "LT", 2: "EQ"}                   # COMPARE_OP oparg>>4 → 逻辑操作（其余派生）
_STG_BASE = 32                              # CALL 暂存窗基址：临时寄存器硬上限（fresh()
_MAX_CALL_ARGS = 8                          # 永不越过）——旧设计覆写 bug 正是缺这道闸
_NATIVE = {"print": 0, "range": 1, "len": 2}
_SKIP = ("RESUME", "END_FOR", "EXTENDED_ARG")


class TaeHanazono(Exception):
    """编译器拒绝：v2 语义子集之外（闸门钉死，绝不静默错译）。"""


def _tuple_str_ok(s: str) -> bool:
    """元组内字符串的 repr 子集判定——与 vm_interp.naraka / vm.rs quote 同一条纪律。
    KAT 修正：CPython repr 对**可打印非 ASCII 原样保留**（PEP 3138 系），
    旧版误限纯 ASCII——放宽为：拒绝控制符/反斜杠/双引号并存，其余（含中文）放行。
    """
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in s) or "\\" in s:
        return False
    return not ("'" in s and '"' in s)


def axia_krone(root_code):
    """input 档入口识别：模块体只 **定义** `def main(argv, stdin)`、不执行任何语句时
    返回该函数 code object，否则 None（= 维持"模块级顺序执行"的旧形态）。

    这就是 早期轮次 的载荷 API 契约（设计稿）：`main(argv, stdin)` 里 argv/stdin
    是输入窗口句柄，输出走 print（与现行 v2 完全一致，不开新的 stdout 通道）。
    模块级还允许 def/常量赋值（`RESUME`+`MAKEFUNC`+`STORE_NAME`+`RETURN_CONST None`
    的形态），任何其它字节码（真语句、调用、循环）都判为"非 main 形态"→ None，
    由出厂门拒（仓外文档§1.1 的"不消费输入即拒出厂"）。"""
    wants = ("RESUME", "LOAD_CONST", "MAKE_FUNCTION", "STORE_NAME", "LOAD_NONE",
             "RETURN_CONST", "END_RESUME", "PUSH_NULL", "POP_JUMP_IF_TRUE",
             "JUMP_FORWARD", "LOAD_SPECIAL", "GET_AITER")
    for c in root_code.co_consts:
        if not hasattr(c, "co_code"):
            continue
        if c.co_name != "main" or c.co_argcount != 2 or c.co_flags & 0x08:
            continue
        if tuple(c.co_varnames[:2]) != ("argv", "stdin"):
            continue
        if any(ins.opname not in wants for ins in dis.get_instructions(root_code)):
            continue
        return c
    return None


def _child_codes(code):
    """直接子函数 code object（co_consts 序）——fid 赋序的唯一出处。"""
    for c in code.co_consts:
        if hasattr(c, "co_code"):
            yield c


def _walk_order(code):
    """walk() 的遍历序（前序深度优先）：`umise_yotsuha` 与 `walk` 共用，杜绝两处各写一遍。"""
    for c in _child_codes(code):
        yield c
        yield from _walk_order(c)


def umise_yotsuha(root_code, input_mode: bool = False) -> int:
    """blob 的 `entry_fid`：input 档 = `main` 的函数号；否则模块 code（恒末位）。

    旧形态（模块级顺序执行）不变；新形态把入口交给 main，参数位不传值——
    输入经 ARGV/STDIN 原语从 VM 数据窗读取（见 vm_isa 的 v4 说明）。"""
    order = list(_walk_order(root_code))
    if input_mode:
        target = axia_krone(root_code)
        if target is None:
            raise TaeHanazono("umise_yotsuha(input_mode=True) 但未认出 main 形态")
        return order.index(target)
    return len(order)


def yamagami_karuta(root_code, input_mode: bool = False) -> tuple:
    """code object → (funcs, gtable, strings)。

    funcs = [(nregs, instrs)]，模块 code 恒为末位（入口由 blob 头 `entry_fid` 显式声明）；
    gtable = [(kind, val)]：0=None 1=Func(fid) 2=Native(id) 3=len(argv) 4=len(stdin)；
    strings = 模块级去重字符串池（LOADS 索引序）。

    `input_mode=True`（早期轮次）：入口改走 `axia_krone` 认出的 `main(argv, stdin)`，
    两个形参成为输入句柄（只可 `x[i]` / `len(x)`）；认不出形态即 `TaeHanazono` 硬拒，
    **绝不静默退回模块级形态**（同  "子集外不许回落 v1" 的纪律）。"""
    funcs = []
    fid_by_code = {}
    gidx = {}
    gtable = []
    strings = []
    sidx = {}
    main_code = axia_krone(root_code) if input_mode else None
    if input_mode and main_code is None:
        raise TaeHanazono("input 档要求载荷形如 `def main(argv, stdin): ...` 且模块体"
                          "不含其它语句（识别函数 axia_krone）——不消费输入的样本"
                          "不得出厂（早期轮次 强制输入依赖）")

    def igslot(name):
        """输入长度全局槽（kind 3/4）：`len(argv)` 的**运行期**长度。
        绝不折叠成编译期常量——那会把输入规模作为明文留在产物里。"""
        key = "len:" + name
        if key not in gidx:
            if len(gtable) > 0xFF:
                raise TaeHanazono("global table exceeds u8 (LOADG/STOREG index width)")
            gidx[key] = len(gtable)
            gtable.append((_INPUT_KIND[name], 0))
        return gidx[key]

    def gslot(name):
        if name not in gidx:
            if len(gtable) > 0xFF:
                raise TaeHanazono("global table exceeds u8 (LOADG/STOREG index width); "
                                  "扩宽索引属 ISA 变更，登记为 P3′ 边界")
            if name in _NATIVE:
                gidx[name] = len(gtable)
                gtable.append((2, _NATIVE[name]))
            else:
                gidx[name] = len(gtable)
                gtable.append(("pending", name))
        return gidx[name]

    def sslot(s):
        if s not in sidx:
            if len(strings) > 0xFFFF:
                raise TaeHanazono("string pool exceeds u16")
            sidx[s] = len(strings)
            strings.append(s)
        return sidx[s]

    def new_fid(code_obj):
        fid = len(funcs)
        fid_by_code[id(code_obj)] = fid
        funcs.append(None)
        return fid

    class _Frame:
        """一个 code object 的翻译现场：局部寄存器表 + 编译期虚拟栈 + IR 与回填位。

        栈条目 = (reg, ty)（ty ∈ {"i","s","n","t",None}——int/bool、str、None、tuple、
        静态未知）或 ("code", code)（MAKE_FUNCTION 的标记，无寄存器）。"""

        def __init__(self, code):
            # 局部 = r0..co_nlocals-1（参数在前）；临时寄存器必须从 co_nlocals 起，
            # 否则 fresh() 覆写局部（实测坑：fib 返回 bool）
            self.nregs = code.co_nlocals
            self.ttop = code.co_nlocals     # 临时寄存器高水位（硬上限 _STG_BASE）
            self.local = {n: i for i, n in enumerate(code.co_varnames)}
            self.stack = []
            self.free = []
            self.handles = set()   # 输入句柄寄存器号（只许 x[i]/len(x) 两处消费）
            self.nat = {}          # 寄存器 → 内建名（LOAD_GLOBAL 登记，供 CALL 识别 len）
            self.ir = []
            self.b2i = {}
            self.patches = []   # (ir_idx, 元组内目标操作数位, 字节目标)

        def emit(self, name, *ops):
            widths = OP_WIDTHS.get(name)
            if widths is None or len(ops) != len(widths):
                raise TaeHanazono("operand count: %s %r" % (name, ops))
            for v, w in zip(ops, widths):
                if not 0 <= v < (1 << (8 * w)):
                    raise TaeHanazono("operand width: %s %r (%dB)" % (name, v, w))
            self.ir.append((name,) + tuple(ops))

        def fresh(self):
            if self.free:
                # FIFO（pop(0)）而非 LIFO：LIFO 会让复用寄存器倒序分派，嵌套元组常量
                # 的元素序列失去连续性，触发 TUPLE 搬移分支、水位暴涨（实测：
                # 6×12 常量在 32 预算下爆掉——FIFO 后峰值 18）
                v = self.free.pop(0)
                # free 寄存器可能是早前大表达式的遗留（ttop 已回落）——重用必须回抬
                # 帧尺寸，否则 TUPLE 窗口越出帧（实测 human-bytes 产物）
                self.nregs = max(self.nregs, v + 1)
                return v
            if self.ttop >= _STG_BASE:
                raise TaeHanazono("temp register budget (%d) exceeded — 表达式过深，"
                                  "不在 v2 子集" % _STG_BASE)
            self.ttop += 1
            self.nregs = max(self.nregs, self.ttop)
            return self.ttop - 1

        def pop(self, allow_handle: bool = False, allow_intr: bool = False):
            """弹栈。输入句柄寄存器**只能**在 BINARY_SUBSCR / `len(x)` 两处被消费，
            其余任何一处弹出即编译期硬拒——否则句柄会以 None 值静默流进算术/打印，
            错译比拒绝危险得多（同  "子集外不许静默回落" 的纪律）。

            句柄槽用完不回 `free`：那格寄存器从此不再分配，避免"号被回收后
            pop 误判成句柄"这种自造分叉。"""
            v = self.stack.pop()
            if isinstance(v, tuple) and v[0] == "intr" and not allow_intr:
                # 内建标记只许被 CALL 位点消费；当值用（赋值/传参/打印）一律编译期硬拒
                raise TaeHanazono("内建 %r 不能当值使用（只在调用位点展开成操作码）" % (v[1],))
            if isinstance(v, tuple) and v[0] not in ("code", "intr"):
                if v[0] in self.handles:
                    if not allow_handle:
                        raise TaeHanazono("输入句柄 %r 不能当值使用（argv/stdin 只支持 "
                                          "x[i] 与 len(x)）" % (v[1],))
                    self.handles.discard(v[0])
                    return v
                self.free.append(v[0])
            return v

        def ibrahim(self, n):
            """连续块分配：返回 n 个**编号连续**的寄存器（TUPLE 读窗语义是 base..base+n-1，
            逐个 fresh() 拿到的散落号会让窗口错值或越帧——）。

            ① 先在 free 里找最靠前的一段连续 run（free∩live=∅ 不变量保证不会取到活跃寄存器），
               命中则把这段逐项摘出 free（只摘一次，重复项属上游漏放，不在这里掩盖）；
            ② 否则从 ttop 整块切，预算闸与 fresh() 同款（ttop+n 不得越过 _STG_BASE=32，
               CALL 暂存窗 [_STG_BASE, +argc) 与临时空间两不侵犯）；
            ③ 两条路径都把 nregs 抬到块尾——复用旧号不等于帧尺寸够大，漏抬即 TUPLE 越帧。
            调用方必须在**活跃寄存器尚未回收**时取号（否则窗口与待搬源重叠）。"""
            in_free = set(self.free)
            for base in sorted(in_free):
                if not all((base + k) in in_free for k in range(1, n)):
                    continue
                want = set(range(base, base + n))
                kept, taken = [], set()
                for v in self.free:
                    if v in want and v not in taken:
                        taken.add(v)
                    else:
                        kept.append(v)
                self.free = kept
                self.nregs = max(self.nregs, base + n)
                return list(range(base, base + n))
            if self.ttop + n > _STG_BASE:
                raise TaeHanazono("temp register budget (%d) exceeded — 表达式过深，"
                                  "不在 v2 子集" % _STG_BASE)
            base = self.ttop
            self.ttop += n
            self.nregs = max(self.nregs, base + n)
            return list(range(base, base + n))

    def _load_const(f, v) -> tuple:
        """常量 → 装载指令 + (reg, ty)（不经栈；元组递归构建后调用方负责回收寄存器）。"""
        if isinstance(v, bool):
            r = f.fresh()
            f.emit("LOADB", r, 1 if v else 0)
            return r, "i"
        if isinstance(v, int):
            if not (-(1 << 15) <= v < (1 << 15)):
                raise TaeHanazono("const too wide for i16: %r" % (v,))
            r = f.fresh()
            f.emit("LOADK", r, v & 0xFFFF)
            return r, "i"
        if v is None:
            r = f.fresh()
            f.emit("LOADN", r)
            return r, "n"
        if isinstance(v, str):
            r = f.fresh()
            f.emit("LOADS", r, sslot(v))
            return r, "s"
        if isinstance(v, tuple):
            if len(v) > 0xFF:
                raise TaeHanazono("tuple const arity %d > 255" % len(v))
            regs = []
            for e in v:
                if isinstance(e, str) and not _tuple_str_ok(e):
                    raise TaeHanazono("tuple 元素字符串越出 repr 子集（可打印 ASCII、"
                                      "无反斜杠、不含双引号冲突）")
                regs.append(_load_const(f, e))
            rs = [r for r, _ in regs]
            base = rs[0]
            if rs != list(range(base, base + len(rs))):
                # 元素寄存器不连续（嵌套表达式理论可达）：搬进**连续**暂存窗再构建；
                # 逐个 fresh() 会把刚回收的散落号发回来，窗口读到错值/越帧
                staged = f.ibrahim(len(rs))
                for dst, src in zip(staged, rs):
                    f.emit("MOVE", dst, src)
                f.free.extend(rs)
                base, rs = staged[0], staged
            d = f.fresh()
            f.emit("TUPLE", d, base, len(rs))
            f.free.extend(rs)
            return d, "t"
        raise TaeHanazono("const type %r 不在 v2 子集" % (type(v),))

    def translate(code):
        f = _Frame(code)
        # 早期轮次：input 档下 main 的形参 argv/stdin 打成"输入句柄"标签——它们**没有值**，
        # 只有两种合法用法：`argv[i]` → ARGV、`len(argv)` → LOADG(长度 kind)。
        # 其它用法（当值传参、切片、拼接、返回）在下面的守卫里当场子集拒，不静默错译。
        in_names = set()
        if input_mode and code is main_code:
            in_names = {n for n in code.co_varnames[:2] if n in _INPUT_KIND}
        for ins in dis.get_instructions(code):
            # 坐标纪律（坑）：字节偏移 → IR 索引只在这里登记，回填只认这张表。
            # EXTENDED_ARG 不产 IR，但其偏移登记为后继指令的 IR 索引——万一跳转目标
            # 落在扩展前缀上，也能解析到正确指令，而不是 fail 成"非边界"。
            f.b2i[ins.offset] = len(f.ir)
            op, arg = ins.opname, ins.arg
            if op in _SKIP:
                continue
            if op == "LOAD_CONST":
                c = code.co_consts[arg]
                if hasattr(c, "co_code"):
                    f.stack.append(("code", c))     # MAKE_FUNCTION 的标记，不产 IR
                else:
                    f.stack.append(_load_const(f, c))
            elif op == "STORE_NAME":
                r, _ty = f.pop()
                f.emit("STOREG", gslot(code.co_names[arg]), r)
            elif op == "LOAD_NAME":
                r = f.fresh()
                f.emit("LOADG", r, gslot(code.co_names[arg]))
                f.stack.append((r, None))
            elif op == "MAKE_FUNCTION":
                if arg != 0:
                    raise TaeHanazono("MAKE_FUNCTION arg=%r（defaults/annotations 不在子集）" % (arg,))
                marker = f.stack.pop()
                if not (isinstance(marker, tuple) and marker[0] == "code"):
                    raise TaeHanazono("MAKE_FUNCTION without code const")
                r = f.fresh()
                f.emit("MAKEFUNC", r, fid_by_code[id(marker[1])])
                f.stack.append((r, None))
            elif op == "STORE_FAST":
                if ins.argrepr in in_names:
                    raise TaeHanazono("输入句柄 %r 不可重新绑定（argv/stdin 由运行期填充，"
                                      "改写它等于伪造输入）" % (ins.argrepr,))
                r, _ty = f.pop()
                f.emit("MOVE", f.local[ins.argrepr], r)
            elif op == "LOAD_FAST":
                if ins.argrepr in in_names:
                    # 输入句柄（早期轮次）：占一格寄存器（运行期恒 None，永不当作值读）
                    # + 类型标签。真取值只发生在 BINARY_SUBSCR → ARGV/STDIN 与
                    # len(x) → LOADG(kind 3/4) 两处，其余路径由 pop() 当场硬拒。
                    r = f.fresh()
                    f.emit("LOADN", r)
                    f.handles.add(r)
                    f.stack.append((r, "in:" + ins.argrepr))
                    continue
                r = f.fresh()
                f.emit("MOVE", r, f.local[ins.argrepr])
                f.stack.append((r, None))
            elif op == "BINARY_OP":
                b, bty = f.pop()
                a, aty = f.pop()
                if arg == 0 and aty == "s" and bty == "s":
                    d = f.fresh()
                    f.emit("CONCAT", d, a, b)
                    f.stack.append((d, "s"))
                    continue
                if aty == "s" or bty == "s":
                    raise TaeHanazono("str 与非 str 的 + 不在子集（CONCAT 仅两侧静态 str）")
                nb = _NB.get(arg)
                if nb is None:
                    raise TaeHanazono("BINARY_OP oparg=%r 不在子集（仅 + - * ^）" % (arg,))
                d = f.fresh()
                f.emit(nb, d, a, b)
                f.stack.append((d, "i" if (aty == "i" and bty == "i") else None))
            elif op == "BUILD_TUPLE":
                if arg == 0 or arg > 0xFF:
                    raise TaeHanazono("BUILD_TUPLE arity %d 不在子集" % (arg,))
                # 元素序 = 自底向上：3.12 实测 BUILD_TUPLE 把栈顶填到元组**末位**，与解释器/
                # Rust 端 `r[base:base+n]` 的正序读窗同向。旧版按 pop 序（栈顶=元素 0）建窗，
                # 产出的元组整体逆序——只因 UNPACK 也逆序压栈而互相抵消，常量元组参与比较时即露

                rs = [f.stack[-arg + k][0] for k in range(arg)]   # 预读，先不弹出
                base = rs[0]
                contiguous = rs == list(range(base, base + arg))
                # 取号必须在 rs 仍活跃时完成（free∩live=∅）：
                # · d 若等 pop 之后再 fresh()，free 头部正是 rs[0]，目标落进窗口内 ⇒ 运行期边读边写；
                # · window 若等 pop 之后再取，ibrahim 的 free 复用会把**搬运源自己**发回当窗口，
                #   MOVE(dst,src) 成对互覆（实测 (1,2) 译成 (2,2)）
                d = f.fresh()
                window = None if contiguous else f.ibrahim(arg)
                for _ in range(arg):
                    f.pop()                                       # 元素寄存器在此回收
                if contiguous:
                    f.emit("TUPLE", d, base, arg)
                else:
                    # 不连续 → 整块搬进连续窗口（逐个 fresh() 会把刚回收的散落号发回来，
                    # 窗口读到错值、窗尾越出 nregs）
                    for dst, sreg in zip(window, rs):
                        f.emit("MOVE", dst, sreg)
                    f.emit("TUPLE", d, window[0], arg)
                    # rs 已由 pop 回收，此处只回收窗口；不得再 extend(rs)——重复项会让
                    # 后续取号发回活跃寄存器（实测 free=[7,7,7]）
                    f.free.extend(window)
                f.stack.append((d, "t"))
            elif op == "UNPACK_SEQUENCE":
                # 解包赋值（真实程序高频：a, b = t）。元组寄存器在整段 GETITEM 期间必须**活跃**：
                # 一进分支就 pop 会把 tup 回收进 free，循环里的 fresh() 随即把它发回当下标寄存器，
                # LOADK 就地覆写元组 → 运行期 "GETITEM on non-tuple"（实测 T3 show()，

                if arg == 0 or arg > 0xFF:
                    raise TaeHanazono("UNPACK_SEQUENCE arity %d 不在子集" % (arg,))
                tup, tty = f.stack[-1]
                if tty == "s":
                    raise TaeHanazono("字符串解包不在子集")
                tmps = []
                for idx in range(arg - 1, -1, -1):
                    iv = f.fresh()
                    f.emit("LOADK", iv, idx & 0xFFFF)
                    item = f.fresh()
                    f.emit("GETITEM", item, tup, iv)
                    tmps.append(item)
                    f.free.extend([iv])
                f.pop()                       # 元素已全部读出，此刻才回收元组寄存器
                # 压栈序 = 元素 0 在栈顶：3.12 实测 UNPACK_SEQUENCE 之后 STORE_FAST 按源序
                # （a, b, c 依次 store），旧版把末位元素发给第一个目标——与 BUILD_TUPLE 的
                # 逆序建窗互相抵消，跨路径（常量元组 ↔ 解包）才暴露
                for item in tmps:
                    f.stack.append((item, None))
            elif op == "BINARY_SUBSCR":
                i, ity = f.pop()
                t, tty = f.pop(allow_handle=True)
                if tty in ("in:argv", "in:stdin"):
                    # 早期轮次：句柄下标 → 输入原语（基址寄存器是占位值，不参与运行期）
                    d = f.fresh()
                    f.emit("ARGV" if tty == "in:argv" else "STDIN", d, i)
                    f.stack.append((d, "i"))
                    continue
                if tty == "s":
                    raise TaeHanazono("字符串下标不在子集")
                if ity not in ("i", None):
                    raise TaeHanazono("GETITEM 下标须整型")
                d = f.fresh()
                f.emit("GETITEM", d, t, i)
                f.stack.append((d, None))
            elif op == "COMPARE_OP":
                b, _b = f.pop()
                a, _a = f.pop()
                cname = _CMP.get(arg >> 4)
                if cname is not None:
                    d = f.fresh()
                    f.emit(cname, d, a, b)
                    f.stack.append((d, "i"))
                else:
                    # 其余比较从 LT/EQ 派生（零 ISA 变更；CPython bool↔int 强转双端已备）：
                    # != → EQ(EQ(a,b),0)；<= → EQ(LT(b,a),0)；>= → EQ(LT(a,b),0)；> → LT(b,a)
                    kind = arg >> 4
                    if kind == 4:                       # >：直接换参
                        d = f.fresh()
                        f.emit("LT", d, b, a)
                    else:
                        if kind == 3:                   # !=（T4/T7 实测需要）
                            t = f.fresh()
                            f.emit("EQ", t, a, b)
                        elif kind == 1:                 # <=（T1/T6 边界校验实测需要）
                            t = f.fresh()
                            f.emit("LT", t, b, a)
                        elif kind == 5:                 # >=
                            t = f.fresh()
                            f.emit("LT", t, a, b)
                        else:
                            raise TaeHanazono("COMPARE_OP oparg=%r 不在子集" % (arg,))
                        zero = f.fresh()
                        f.emit("LOADK", zero, 0)
                        d = f.fresh()
                        f.emit("EQ", d, t, zero)
                        f.free.extend([t, zero])
                    f.stack.append((d, "i"))
            elif op == "POP_JUMP_IF_FALSE":
                c, _ty = f.pop()
                f.emit("JZ", c, 0)
                f.patches.append((len(f.ir) - 1, 2, ins.argval))
            elif op == "POP_JUMP_IF_TRUE":
                # 子集里没有"jump-if-truthy"：等价展开成 JZ→下一条 + JMP→目标
                # （3.12.10 实测 `if not (a == b)` 走这一形，属常见写法）
                c, _ty = f.pop()
                cur = len(f.ir)
                f.emit("JZ", c, cur + 2)
                f.emit("JMP", 0)
                f.patches.append((cur + 1, 1, ins.argval))
            elif op == "POP_JUMP_IF_NONE":
                # v 是 None 就跳：JN 直接指向目标
                r, _ty = f.pop()
                f.emit("JN", r, 0)
                f.patches.append((len(f.ir) - 1, 2, ins.argval))
            elif op == "POP_JUMP_IF_NOT_NONE":
                # v 不是 None 才跳：ISA 没有 jump-if-not-None，展开成 JN→落空 + JMP→目标
                r, _ty = f.pop()
                cur = len(f.ir)
                f.emit("JN", r, cur + 2)
                f.emit("JMP", 0)
                f.patches.append((cur + 1, 1, ins.argval))
            elif op == "JUMP_BACKWARD":
                f.emit("JMP", 0)
                f.patches.append((len(f.ir) - 1, 1, ins.argval))
            elif op == "PUSH_NULL":
                rn = f.fresh()
                f.emit("LOADN", rn)
                f.stack.append((rn, "n"))
            elif op == "LOAD_GLOBAL":
                # 3.12 编码：oparg = (名字索引 << 1) | **只有调用点才置**的 NULL 位。
                # 调用点实测压栈序 NULL 先、callable 后；非调用点的全局名读取（如 UNITS[unit]）
                # 只压一个值。旧版无条件多压一格 NULL，随后的 CALL 便把值寄存器当成 callee
                # （实测 T3 show()："vm: call on non-callable"）
                if arg & 1:
                    rn = f.fresh()
                    f.emit("LOADN", rn)
                    f.stack.append((rn, "n"))
                gname = code.co_names[arg >> 1]
                if gname in _INTRINSIC:
                    # 内建（早期轮次+C）：不取寄存器、不发 LOADG、不建全局槽——只压一枚编译期
                    # 标记，由下面的 CALL 位点展开成那一枚操作码。名字因此绝不进产物。
                    f.stack.append(("intr", gname))
                    continue
                rv = f.fresh()
                f.emit("LOADG", rv, gslot(gname))
                if gname in _NATIVE:
                    f.nat[rv] = gname          # 供 CALL 分支识别 len（输入长度改写）
                f.stack.append((rv, None))
            elif op == "CALL":
                if arg > _MAX_CALL_ARGS:
                    raise TaeHanazono("CALL argc=%d > %d" % (arg, _MAX_CALL_ARGS))
                top = f.stack[-1] if f.stack else None
                callee_e = f.stack[-2] if len(f.stack) >= 2 else None
                if (arg == 1 and isinstance(top, tuple) and top[1] in ("in:argv", "in:stdin")
                        and isinstance(callee_e, tuple)
                        and f.nat.get(callee_e[0]) == "len"):
                    # 早期轮次：`len(argv)` / `len(stdin)` → 运行期长度（LOADG kind 3/4）。
                    # 长度绝不容纳成编译期常量——那等于把输入规模写进产物明文。
                    in_name = top[1][3:]
                    f.pop(allow_handle=True)        # 句柄槽
                    f.pop()                         # callee（len）
                    f.pop()                         # NULL 槽
                    d = f.fresh()
                    f.emit("LOADG", d, igslot(in_name))
                    f.stack.append((d, "i"))
                    continue
                callee_slot = f.stack[-(arg + 1)] if len(f.stack) >= arg + 1 else None
                if isinstance(callee_slot, tuple) and callee_slot[0] == "intr":
                    # 内建调用位点（早期轮次+C）：栈形 = [..., NULL, 标记, 末参, …, 首参]，
                    # callee 恒在 -(arg+1)（NULL 在它下面）。写死成 -2 只对 argc=1 成立——
                    # 那是"换个实参个数就分叉"的面。
                    iname = callee_slot[1]
                    opname, arity = _INTRINSIC[iname]
                    if arg != arity:
                        raise TaeHanazono("内建 %s 需要 %d 个实参，实得 %d" % (iname, arity, arg))
                    d = f.fresh()                             # 取号在参数仍活跃时完成
                    srcs = [f.pop() for _ in range(arg)]      # 弹序 = 末参先（寄存器, 类型）
                    srcs.reverse()                            # 倒过来才是形参正序
                    f.pop(allow_intr=True)                    # 内建标记
                    f.pop()                                   # NULL 槽
                    # 早期轮次 复核修正：旧式检查弹的是寄存器号（恒为 int，检查恒真空转）。
                    # 静态可判的串/元组/None 实参这里就拒；类型未知（tag None，如
                    # 调用返回）放行，交 ROTL32 的运行期非负域守卫兜底，fail-closed
                    # 不变
                    if not all(ty in ("i", None) for _r, ty in srcs):
                        raise TaeHanazono("内建 %s 的实参不在子集" % iname)
                    f.emit(opname, d, *(r for r, _ty in srcs))
                    f.stack.append((d, "i"))
                    continue
                # 3.12 实测栈序：顶 = args…，其下 callable，最底 NULL
                # 弹序 args → callable → NULL（凭记忆写反被当场抓获）
                args = [f.pop() for _ in range(arg)]
                callee = f.pop()
                f.pop()  # NULL 槽
                if isinstance(callee, tuple) and callee[0] == "code":
                    raise TaeHanazono("CALL on code-const callee")
                # 暂存窗 = 固定 [_STG_BASE, _STG_BASE+argc)，跨调用复用、永不释放——
                # 与临时寄存器空间以 _STG_BASE 硬闸分离（两不侵犯）。CALLV 的 argbase
                # 是运行期寄存器号，双端语义不因窗口位置改变。
                for k in range(arg):
                    f.emit("MOVE", _STG_BASE + k, args[arg - 1 - k][0])
                f.nregs = max(f.nregs, _STG_BASE + arg)
                d = f.fresh()
                f.emit("CALLV", d, callee[0], _STG_BASE, arg)
                f.stack.append((d, None))
            elif op == "GET_ITER":
                pass      # range 的结果已是可迭代对象：原样保留
            elif op == "FOR_ITER":
                it = f.stack[-1][0]
                t = f.fresh()
                f.emit("ITERNEXT", t, it)
                f.emit("JN", t, 0)    # 仅 None（耗尽）退出——k=0 是合法值（坑五）
                f.patches.append((len(f.ir) - 1, 2, ins.argval))
                f.stack.append((t, None))
            elif op == "POP_TOP":
                f.pop()
            elif op == "RETURN_VALUE":
                r, _ty = f.pop()
                f.emit("RET", r)
                f.stack.clear()
            elif op == "RETURN_CONST":
                #  扩围：常量返回（真实程序高频形态）——int/str/bool/None 各走
                # 对应装载指令 + RET；此前一律拒（设计稿 #12 的另一面）
                c = code.co_consts[arg]
                if c is None or isinstance(c, (bool, int, str)):
                    r, _ty = _load_const(f, c)
                    f.emit("RET", r)
                    f.stack.clear()
                else:
                    raise TaeHanazono("RETURN_CONST %r 不在子集" % (c,))
            else:
                raise TaeHanazono("opcode %r 不在 v2 子集" % op)
        for ir_idx, tup_pos, byte_target in f.patches:
            if byte_target not in f.b2i:
                raise TaeHanazono("jump into non-boundary 0x%x" % byte_target)
            ir = f.ir[ir_idx]
            f.ir[ir_idx] = ir[:tup_pos] + (f.b2i[byte_target],) + ir[tup_pos + 1:]
        return f.nregs, f.ir

    def walk(code):
        for c in _child_codes(code):      # 与 umise_yotsuha/_walk_order 同一遍历序（单源）
            new_fid(c)
            walk(c)

    def fill(fid, code):
        nregs, ir = translate(code)
        funcs[fid] = (nregs, ir)
        for c in code.co_consts:
            if hasattr(c, "co_code"):
                fill(fid_by_code[id(c)], c)

    walk(root_code)
    fill(new_fid(root_code), root_code)
    # finalize：pending 全局槽 → Func(fid)（函数名）或 (0, None)（数据全局占位——
    # 模块级 ANCHORS = ... 这类非函数绑定由运行期 STOREG 写入；此前一律 reject，
    # 模块级常量赋值被误拒（修正，真实项目载荷必踩））
    for i, (kind, val) in enumerate(gtable):
        if kind == "pending":
            target = _code_by_name(root_code, val)
            if target is not None:
                gtable[i] = (1, fid_by_code[id(target)])
            else:
                gtable[i] = (0, 0)
    return funcs, gtable, strings


def _code_by_name(root_code, name):
    for c in root_code.co_consts:
        if hasattr(c, "co_code") and c.co_name == name:
            return c
    return None
