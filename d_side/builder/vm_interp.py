# Copyright (C) 2026 Diderde
# SPDX-License-Identifier: GPL-3.0-only
"""vm_interp：VM blob v2 的 Python 权威解释器（双路径的语义端）。

由 `.tmp/u16_probe/p2/ref_interp.py` 升格。与探针的**语义差异**全部来自设计稿的
缺陷清单（这些差异是刻意的，Rust 侧逐条镜像）：
- 输出走**字节通道**：`print(v)` 产出 `str(v) + "\n"` 的 UTF-8 字节，与 CPython 逐字节一致
  （探针把 Python 对象塞进列表、Rust 把字符串折成长度哨兵——两侧本就不等价）；
- 真值判定用 Python 自己的真值协议（`""` 为假）——探针两侧都把 `""` 判真，与 CPython 不符；
- `LOADS` 读满 u16 池索引（探针 Rust 侧只取低字节，>256 条即双端分叉）；
- 取指**不允许跨块**（指令边界对齐分块后，跨块即结构违规 → fail-closed）；
- 帧返回用显式父帧号，不依赖对象 `id()`；VM 故障抛 `SaayaYamabuki`，不冒充 `SystemExit`。
"""
import struct

from d_side.builder import vm_blob, vm_isa

DEFAULT_STEP_BUDGET = 20_000_000


class SaayaYamabuki(Exception):
    """VM 故障：结构非法、类型不符、步数预算耗尽——boot 侧一律静默 exit 3。"""


class MocaAoba(tuple):
    """用户态元组值：与解释器内部标签元组（"Iter"/"Func"/"Native"）类型区分，
    杜绝 `("Iter", 1, 2)` 形态的用户元组被误当迭代器。"""


def naraka(s: str) -> str:
    """CPython repr 的子集形态（双端同式）：控制符/反斜杠拒绝；可打印字符（含
    非 ASCII）原样保留（PEP 3138 系语义）；引号冲突即拒。越界字符串不在 v2
    子集（fail-closed），编译器对常量先行同款检查。"""
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in s) or "\\" in s:
        raise SaayaYamabuki("tuple 元素字符串含控制符/反斜杠")
    if "'" in s and '"' not in s:
        return '"' + s + '"'
    if '"' in s and "'" not in s:
        return "'" + s + "'"
    if "'" in s and '"' in s:
        raise SaayaYamabuki("tuple 元素字符串同时含两种引号")
    return "'" + s + "'"


class RimiUshigome:
    """blob v2 解释器。值模型：int / bool / None / str / ("Iter",next,end) /
    ("Func",fid) / ("Native",id)。"""

    def __init__(self, blob: bytes, container_key: bytes, isa_seed: bytes,
                 step_budget: int = DEFAULT_STEP_BUDGET,
                 argv: bytes = b"", stdin: bytes = b"",
                 argv_cap: int = vm_isa.INPUT_WINDOW,
                 stdin_cap: int = vm_isa.INPUT_WINDOW):
        mao = vm_blob.matsukai_mao(container_key)
        self.info = vm_blob.shirayuki_tomoe(blob, mao)
        self.mao = mao
        self.cs = self.info["chunk_size"]
        self.nslots = self.info["nslots"]
        self.step_budget = step_budget
        self.inv = {v: k for k, v in vm_isa.hayase_sou(isa_seed).items()}
        meta = vm_blob.meta_unpack(self.info, mao)
        self.funcs = meta["funcs"]
        # 早期轮次 输入窗：与 boot 填窗同式（argv 已由调用方按本格连接字节扁平化）。
        # 超过本格上限一律拒，**不静默截断**——截断会让"程序看到的输入"与验收方给出的
        # 不一致，那是比拒绝更贵的失败。
        # 早期轮次 Phase 2：上限是**逐格契约值**（`argv_cap`/`stdin_cap`，出处
        # native_build.koyanagi_rou）；默认值只服务不带契约的库调用，产品路径必须显式传。
        if len(argv) > argv_cap or len(stdin) > stdin_cap:
            raise SaayaYamabuki("input beyond the window (ap=%d sp=%d)"
                                 % (argv_cap, stdin_cap))
        # 早期轮次：本格链剖面。派生源是 VM 根密钥（与 chunk 置换、分派槽置换同一条
        # 层级），所以它既不在 blob 里、也不在产物镜像里——建 VM 时现算，两侧同式
        # （vm.rs 的 ops::chain_decode 是它的原生镜像）。
        self.chain = vm_isa.kaburaki_roco(mao["root"])
        # 早期轮次 （定长吸收）：两窗一律补齐到上限，补齐字节逐格派生（VM 根密钥的函数，
        # 运行期零随机）。补齐之后 `len(argv)`/`len(stdin)` 是常数 ⇒ 载荷的**运行步数与输入
        # 长度无关**， 实测的长度侧信道（空 argv 191 次 MAC 迭代 vs "hello" 63,743 次）
        # 与"逐字节消化的字节数就是长度"这条结构事实一起关掉。
        self.argv_win = vm_isa.hibachi_mana(self.chain, argv, argv_cap)
        self.stdin_win = vm_isa.hibachi_mana(self.chain, stdin, stdin_cap)
        # W 低危残项（对镜 Rust read_globals）：Native 号仅 0(print)/1(range)/
        # 2(len) 合法，越界一律拒——防双端语义分叉。
        # kind 3/4（早期轮次）= 输入窗长度，在建 VM 时就能定值（窗是运行期输入，绝不进产物，
        # 所以长度也不会作为明文被编译进 blob）； 之后它报的是**吸收后**的上限。
        self.globals = [({0: None, 1: ("Func", v), 2: ("Native", v),
                          vm_isa.G_ARGV_LEN: len(self.argv_win),
                          vm_isa.G_STDIN_LEN: len(self.stdin_win)}[k])
                        if k not in (2,) or v <= 2
                        else (_ for _ in ()).throw(
                            SaayaYamabuki("Native id %d out of range" % v))
                        for k, v in meta["gtable"]]
        self.strings = meta["strings"]
        self.entry_fid = meta["entry_fid"]
        # 函数表里的 start 是 **IR 区内偏移**；IR 区在 blob 的块数组里从第 nmeta 块开始
        # ——取指时必须加这个基址（Rust 侧同一约定）。
        self.ir_base = self.info["nmeta"]
        self.ir_used = meta["ir_used"]
        self._slots = []                       # [(logical, bytes)]，最多 nslots 项
        self.out = bytearray()
        self.steps = 0                         # 上一次 run() 走过的 VM 步数（定长吸收门用）
        self.trace = None                      # 置为列表即记录 (pc, 逻辑名, 帧深)——仅诊断用

    def _chunk_plain(self, logical: int) -> bytes:
        """按需解密 + 有限驻留槽（LRU 逐出即丢引用；boot 侧对应页隔离 + 清零）。"""
        for i, (idx, _data) in enumerate(self._slots):
            if idx == logical:
                data = self._slots.pop(i)[1]
                self._slots.append((logical, data))
                return data
        data = vm_blob.fuwa_minato(self.info, logical, self.mao)
        self._slots.append((logical, data))
        while len(self._slots) > self.nslots:
            self._slots.pop(0)
        return data

    def _fetch(self, pc: int, n: int) -> bytes:
        logical = self.ir_base + pc // self.cs
        off = pc % self.cs
        if off + n > self.cs:
            raise SaayaYamabuki("fetch crosses chunk boundary at %d" % pc)
        # 野跳转界检必须在解密取块之前——否则越界 logical 会让 fuwa_minato 的
        # RanMitake 从 run() 穿出，击穿「一切 VM 故障 = SaayaYamabuki」协议
        # （实测 JMP 目标 0xF000 复现）
        if (logical - self.ir_base >= len(self.ir_used)
                or off >= self.ir_used[logical - self.ir_base]):
            raise SaayaYamabuki("pc %d inside filler region (structure violation)" % pc)
        data = self._chunk_plain(logical)
        if off + n > self.ir_used[logical - self.ir_base]:
            raise SaayaYamabuki("instruction runs into filler at %d" % pc)
        return data[off:off + n]

    def _advance(self, pc: int) -> int:
        """顺序执行的跨块推进：落到某块已用长度末尾时，跳过 PRF 填充到下一块块首。"""
        idx = pc // self.cs
        if idx >= len(self.ir_used):
            raise SaayaYamabuki("pc %d beyond IR region" % pc)
        off = pc % self.cs
        if off == self.ir_used[idx]:
            return (idx + 1) * self.cs
        if off > self.ir_used[idx]:
            raise SaayaYamabuki("pc %d inside filler region" % pc)
        return pc

    def _operand(self, pc: int, width: int) -> int:
        raw = self._fetch(pc, width)
        return int.from_bytes(raw, "little") if width == 1 else struct.unpack("<H", raw)[0]

    @staticmethod
    def _repr(v, _depth: int = 0) -> str:
        """CPython repr 在 v2 值域上的等价形式（tuple 打印/嵌套元素用）。"""
        if _depth > 8:
            raise SaayaYamabuki("tuple nesting beyond repr budget")
        if isinstance(v, MocaAoba):
            inner = ", ".join(RimiUshigome._repr(e, _depth + 1) for e in v)
            return "(" + inner + ("," if len(v) == 1 else "") + ")"
        if v is None or isinstance(v, (bool, int)):
            return RimiUshigome._text(v)
        if isinstance(v, str):
            return naraka(v)
        raise SaayaYamabuki("repr of non-reprable %r" % (type(v),))

    @staticmethod
    def _text(v) -> str:
        if v is None:
            return "None"
        if v is True:
            return "True"
        if v is False:
            return "False"
        if isinstance(v, MocaAoba):
            return RimiUshigome._repr(v)
        if isinstance(v, str):
            return v
        if isinstance(v, int):
            return str(v)
        raise SaayaYamabuki("print of non-printable %r" % (type(v),))

    def run(self) -> bytes:
        start, nregs = self.funcs[self.entry_fid]
        frames = [{"regs": [None] * nregs, "pc": start, "ret": None}]
        steps = 0
        trace = self.trace
        while frames:
            steps += 1
            if steps > self.step_budget:
                raise SaayaYamabuki("step budget %d exceeded" % self.step_budget)
            f = frames[-1]
            name = self.inv.get(self._fetch(f["pc"], 1)[0])
            if name is None:
                raise SaayaYamabuki("unknown physical opcode 0x%02x at pc=%d"
                                    % (self._fetch(f["pc"], 1)[0], f["pc"]))
            if trace is not None:
                trace.append((f["pc"], name, len(frames)))
            widths = vm_isa.OP_WIDTHS[name]
            ops = []
            at = f["pc"] + 1
            for w in widths:
                ops.append(self._operand(at, w))
                at += w
            # （安全审计）：寄存器/全局/函数/字符串号在译码点验界——越界
            # IndexError 会击穿「一切 VM 故障 = SaayaYamabuki」协议（Rust 侧
            # 装载扫描待单源化后移植）
            for kind, op in zip(vm_isa.OP_KINDS[name], ops):
                if kind == "R" and not 0 <= op < len(f["regs"]):
                    raise SaayaYamabuki("register %d out of range" % op)
                if kind == "G" and not 0 <= op < len(self.globals):
                    raise SaayaYamabuki("global %d out of range" % op)
                if kind == "F" and not 0 <= op < len(self.funcs):
                    raise SaayaYamabuki("func id %d out of range" % op)
                if kind == "S" and not 0 <= op < len(self.strings):
                    raise SaayaYamabuki("string %d out of range" % op)
            # 顺序后继要先跨过块尾 PRF 填充（JZ/JN 的落空分支与返回地址都走这里）
            nxt = self._advance(f["pc"] + 1 + sum(widths))
            r = f["regs"]

            if name == "HALT":
                break
            elif name == "LOADK":
                r[ops[0]] = ops[1] - 0x10000 if ops[1] >= 0x8000 else ops[1]
            elif name == "MOVE":
                r[ops[0]] = r[ops[1]]
            elif name in ("ADD", "SUB", "MUL", "FLOORDIV"):
                a, b = r[ops[1]], r[ops[2]]
                if isinstance(a, str) or isinstance(b, str):
                    raise SaayaYamabuki("%s on str (字符串拼接走 CONCAT)" % name)
                if not isinstance(a, int) or not isinstance(b, int):
                    raise SaayaYamabuki("%s on non-int" % name)
                # 逐名分支（KAT/实测坑：字典字面量急切求值——b=0 时任何 op 都会
                # 先算 a//b 而炸掉非除法运算）
                if name == "ADD":
                    r[ops[0]] = a + b
                elif name == "SUB":
                    r[ops[0]] = a - b
                elif name == "MUL":
                    r[ops[0]] = a * b
                else:
                    if b == 0:
                        raise SaayaYamabuki("FLOORDIV by zero")
                    r[ops[0]] = a // b
            elif name in ("XOR", "ROTL32"):
                # 早期轮次+C（ISA v5）ARX 步进：值域为**非负整数**——负操作数与非整型、str
                # 一样走既有故障 → 桶码 → 静默 exit 3 通道，不新增可见行为（同 ARGV/STDIN
                # 一族）。ROTL32 取 a 的低 32 位、k 取 mod 32，结果恒 < 2^32（与 vm.rs 的
                # OP_XOR|OP_ROTL32 臂逐位同式，KAT 见 tests/d_side/test_vm_gates.py）。
                a, b = r[ops[1]], r[ops[2]]
                if isinstance(a, str) or isinstance(b, str):
                    raise SaayaYamabuki("%s on str" % name)
                if not isinstance(a, int) or not isinstance(b, int):
                    raise SaayaYamabuki("%s on non-int" % name)
                if a < 0 or b < 0:
                    raise SaayaYamabuki("%s on negative operand" % name)
                if name == "XOR":
                    r[ops[0]] = a ^ b
                else:
                    j = a % vm_isa.U32
                    k = b % 32
                    r[ops[0]] = ((j << k) | (j >> (32 - k))) % vm_isa.U32
            elif name == "HSTEP":
                # 早期轮次：链步进原语。d = shishido_akari(chain, regs[a], regs[b])——闭式与
                # CPython 参考腿**同一份**（vm_isa.shishido_akari），剖面与 vm.rs 的 Chain 同式。
                # 值域与非负判据同 XOR/ROTL32：负数/非整数走既有故障 → 桶码 → 静默 exit 3。
                a, b = r[ops[1]], r[ops[2]]
                if isinstance(a, str) or isinstance(b, str):
                    raise SaayaYamabuki("HSTEP on str")
                if not isinstance(a, int) or not isinstance(b, int):
                    raise SaayaYamabuki("HSTEP on non-int")
                if a < 0 or b < 0:
                    raise SaayaYamabuki("HSTEP on negative operand")
                r[ops[0]] = vm_isa.shishido_akari(self.chain, a, b)
            elif name in ("LT", "EQ"):
                a, b = r[ops[1]], r[ops[2]]
                # 深查中危项复核（晚）：**EQ on tuple 是合法语义**
                # （Rust OP_EQ 结构等价本就支持，夹具 build(1,2)==(1,2) 即回归
                # 齿），此前一刀切拒绝属修复过界，已回滚；LT 保持双端同拒
                # （Rust as_int 对元组拒绝，Python 同拒对齐）
                if name == "LT":
                    if isinstance(a, MocaAoba) or isinstance(b, MocaAoba):
                        raise SaayaYamabuki("LT on tuple")
                    if isinstance(a, str) or isinstance(b, str):
                        raise SaayaYamabuki("LT on str")
                r[ops[0]] = (a < b) if name == "LT" else (a == b)
            elif name == "JMP":
                f["pc"] = ops[0]
                continue
            elif name == "JZ":
                v = r[ops[0]]
                f["pc"] = ops[1] if not v else nxt
                continue
            elif name == "JN":
                v = r[ops[0]]
                f["pc"] = ops[1] if v is None else nxt
                continue
            elif name == "ITERNEW":
                src = r[ops[1]]
                if not isinstance(src, int):
                    raise SaayaYamabuki("ITERNEW on non-int")
                r[ops[0]] = ("Iter", 1, src)          # 1..=src 含端（探针 fixture 语义）
            elif name == "ITERNEXT":
                it = r[ops[1]]
                if it is None or not (isinstance(it, tuple) and not isinstance(it, MocaAoba)
                                      and it[0] == "Iter"):
                    raise SaayaYamabuki("ITERNEXT on non-iterator")
                cur, end = it[1], it[2]
                if cur <= end:
                    r[ops[1]] = ("Iter", cur + 1, end)
                    r[ops[0]] = cur
                else:
                    r[ops[1]] = None
                    r[ops[0]] = None
            elif name == "LOADN":
                r[ops[0]] = None
            elif name == "LOADS":
                if ops[1] >= len(self.strings):
                    raise SaayaYamabuki("LOADS index out of pool")
                r[ops[0]] = self.strings[ops[1]]
            elif name == "CONCAT":
                a, b = r[ops[1]], r[ops[2]]
                if not (isinstance(a, str) and isinstance(b, str)):
                    raise SaayaYamabuki("CONCAT on non-string")
                r[ops[0]] = a + b
            elif name == "LOADB":
                if ops[1] > 1:
                    raise SaayaYamabuki("LOADB payload %d not boolean" % ops[1])
                r[ops[0]] = bool(ops[1])
            elif name == "TUPLE":
                base, n = ops[1], ops[2]
                if base + n > len(r):
                    raise SaayaYamabuki("TUPLE register window out of frame")
                r[ops[0]] = MocaAoba(r[base:base + n])
            elif name == "GETITEM":
                tup, idx = r[ops[1]], r[ops[2]]
                if not isinstance(tup, MocaAoba):
                    raise SaayaYamabuki("GETITEM on non-tuple")
                if not isinstance(idx, int) or isinstance(idx, MocaAoba):
                    raise SaayaYamabuki("GETITEM index not integer")
                if not 0 <= idx < len(tup):
                    raise SaayaYamabuki("GETITEM index %d out of range %d" % (idx, len(tup)))
                r[ops[0]] = tup[idx]
            elif name == "LOADG":
                if ops[1] >= len(self.globals):
                    raise SaayaYamabuki("LOADG index out of table")
                r[ops[0]] = self.globals[ops[1]]
            elif name == "STOREG":
                self.globals[ops[0]] = r[ops[1]]
            elif name == "MAKEFUNC":
                if ops[1] >= len(self.funcs):
                    raise SaayaYamabuki("MAKEFUNC bad fid")
                r[ops[0]] = ("Func", ops[1])
            elif name in ("CALL", "CALLV"):
                dst, base, argc = ops[0], ops[2], ops[3]
                # 参数窗验界——base+argc 越过当前帧会被 newr[i] = r[base+i]
                # 打成 IndexError
                if not 0 <= base <= len(r) or not 0 <= argc <= len(r) - base:
                    raise SaayaYamabuki("%s register window out of frame" % name)
                if name == "CALL":
                    if ops[1] >= len(self.funcs):
                        raise SaayaYamabuki("CALL bad fid")
                    callee = ("Func", ops[1])
                else:
                    callee = r[ops[1]]
                if isinstance(callee, tuple) and callee[0] == "Func":
                    fstart, fnregs = self.funcs[callee[1]]
                    # / 单源化：目标帧宽度也要验——`argc > fnregs` 时 newr[i]
                    # 会裸 IndexError 击穿 SaayaYamabuki 协议，Rust 侧同式拒

                    if argc > fnregs:
                        raise SaayaYamabuki("%s arg count %d exceeds frame" % (name, argc))
                    newr = [None] * fnregs
                    for i in range(argc):
                        newr[i] = r[base + i]
                    f["pc"] = nxt                     # 返回地址先落盘（坑一）
                    frames.append({"regs": newr, "pc": fstart, "ret": dst})
                    continue
                if isinstance(callee, tuple) and callee[0] == "Native":
                    if callee[1] == 0:                          # print(*args)：CPython 语义
                        line = " ".join(self._text(r[base + i]) for i in range(argc))
                        self.out += (line + "\n").encode("utf-8")
                        r[dst] = None
                    elif callee[1] == 1 and argc == 1:          # range(n) → 0..n-1
                        n = r[base]
                        if not isinstance(n, int):
                            raise SaayaYamabuki("range on non-int")
                        r[dst] = ("Iter", 0, n - 1)
                    elif callee[1] == 2 and argc == 1:          # len(t) → 元组长度
                        t = r[base]
                        if not isinstance(t, MocaAoba):
                            raise SaayaYamabuki("len on non-tuple")
                        r[dst] = len(t)
                    else:
                        raise SaayaYamabuki("native call arity/type mismatch")
                else:
                    raise SaayaYamabuki("CALLV on non-callable")
            elif name == "RET":
                done = frames.pop()
                if not frames:
                    break
                dst = done["ret"]
                if dst is not None:
                    frames[-1]["regs"][dst] = done["regs"][ops[0]]
            elif name in ("ARGV", "STDIN"):
                # 早期轮次 输入原语：下标来自寄存器，结果是一个字节值（0..255，i128 域）。
                # 越界 = VM 故障（与 GETITEM 同族），Rust 侧同式同码（互钉）。
                win = self.argv_win if name == "ARGV" else self.stdin_win
                j = r[ops[1]]
                if not isinstance(j, int):
                    # bool 在本 VM 值模型里就是 0/1（Rust 侧同为整型），单验"是整数"
                    raise SaayaYamabuki("%s index on non-int" % name)
                if not 0 <= j < len(win):
                    raise SaayaYamabuki("%s index %d out of window (%dB)"
                                        % (name, j, len(win)))
                r[ops[0]] = win[j]
            elif name == "PRINT":
                self.out += (self._text(r[ops[0]]) + "\n").encode("utf-8")
            else:
                raise SaayaYamabuki("unhandled op %r" % name)
            f["pc"] = nxt
        # 早期轮次：步数如实留档（定长吸收门 work_factor_flatness 断言的是"步数对输入长度
        # 不敏感"，这一步在权威腿上是精确量，不必借道有噪声的墙钟）
        self.steps = steps
        return bytes(self.out)


def gwelu_os_gar(blob: bytes, container_key: bytes, isa_seed: bytes,
                 step_budget: int = DEFAULT_STEP_BUDGET,
                 argv: bytes = b"", stdin: bytes = b"",
                 argv_cap: int = vm_isa.INPUT_WINDOW,
                 stdin_cap: int = vm_isa.INPUT_WINDOW) -> bytes:
    """blob + 容器密钥 + ISA seed → 载荷的 stdout 字节（权威语义端入口）。

    `argv`/`stdin` 是 早期轮次 的输入窗内容（argv 须已由调用方按**本格连接字节**
    扁平化）；`argv_cap`/`stdin_cap` 是本格契约里的窗上限（默认 64 只服务不带契约的
    库调用）。boot 侧填窗与本入口**同式**，双端互钉见 tests/d_side/test_vm_gates.py
    的输入原语 KAT 与 test_native_vm.py 的接口腿。"""
    return RimiUshigome(blob, container_key, isa_seed, step_budget, argv=argv,
                        stdin=stdin, argv_cap=argv_cap, stdin_cap=stdin_cap).run()
