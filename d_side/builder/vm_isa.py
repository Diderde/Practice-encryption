# Copyright (C) 2026 Diderde
# SPDX-License-Identifier: GPL-3.0-only
"""vm_isa： VM 指令集、seed 派生物理映射、汇编器与分块规划器。

由 `.tmp/u16_probe/p2/isa.py` 升格，语义与探针**逐式对齐**（双路径互钉的前提）：
- 逻辑操作码 32 个，物理操作码字节 = seed 派生置换（Fisher-Yates 于 0..255 空间取前
  N 项，随机源 `keys._expand`——HKDF-SHA256，**不用 random 模块**，仓内纪律）；
- 坐标纪律（实测坑）：跳转目标一律写**同函数内绝对 IR 索引**，IR 索引→字节偏移
  的换算只在本文件的 `shellin_burgundy` 一处发生；
- 分块规划（拍板）：正式档把块边界**向后对齐到指令边界**（取指永不跨块 ⇒ 单块
  明文在场由结构保证）；定长档（含探针的 13 B 质数）只作闸门形态，跨块取指由它覆盖。
- 迭代原语保留探针的两套形态（ITERNEW 的 fixture 语义 + ITERNEXT），删减会动 KAT，
  列为后子集整理项（设计稿第 12 条）。
"""
import struct

from d_side import keys

ISA_VER = 6          # 操作码语义 + 操作数宽度表版本（v2：+LOADB/TUPLE/GETITEM；
                     #  v3：+FLOORDIV——既有真实目标源码的格式化数学实测需要；
                     #  v4：+ARGV/STDIN——早期轮次 输入依赖，让"抄输出"不再是可行捷径；
                     #  v5：+XOR/ROTL32——早期轮次+C 输入函数硬化（B 形状与链的 ARX 步进）；
                     #  v6：+HSTEP——早期轮次 链步进原生化（链逻辑与链常量一起离开字节码））
# 说明（并存口径）：v4/v5/v6 都是**追加**扩表——旧形态载荷（模块级 print、完全不碰输入）
# 照样在最新档下编译运行，`input_mode` 只由构建方显式开启。已经出厂的 v3/v4/v5 产物由它
# 自己那代 boot 运行（旧产物冻结不动），所以新 boot 不接受 isa_ver≠6：
# 单值校验比"白名单 + 版本↔操作码数配对"少一处双端分叉面。
PHYSMAP_VER = 1      # seed→物理字节映射派生算法版本
CHUNK_SIZE = 256     # 正式档块大小（实测最优：256B/2 槽 = 8.2x CPython）
RESIDENT_SLOTS = 2   #  拍板：明文驻留槽数（每槽一页，页尾恒零）——双端都按此校验
_OPSPACE = 256

# 输入窗口上限（早期轮次）：argv 扁平化后与 stdin 各 64 B、argv 至多 64 项。
# 越界不新增可见行为——一律走 VM 故障 → 桶码 → 静默 exit 3（同 GETITEM 越界一族）。
# 同值常量也出现在 vm.rs（INPUT_WINDOW / INPUT_ARG_MAX）与 boot 填窗处，
# 由 tests/d_side/test_vm_gates.py 的 source-literal 检查钉住双端一致。
INPUT_WINDOW = 64
INPUT_ARG_MAX = 64
G_ARGV_LEN = 3       # 全局表新 kind：len(argv) 的运行期长度（不得编译期常量，否则泄漏输入）
G_STDIN_LEN = 4
# 早期轮次 （定长吸收）：两窗在建 VM 时一律补齐到本格上限，所以 kind 3/4 报的是**补齐后**
# 的定长（= 上限，逐格常数），运行步数因此与输入长度无关—— 实测的长度侧信道
# （空 argv 191 次迭代 vs "hello" 63,743 次）就此关掉。
# 口径登记：这里**没有**"真实长度"那一档全局 kind。参考腿（CPython）拿到的就是补齐后的
# 字节串，它自己也分不出"补齐前的长度"；多设两枚 kind 只会造出一对载荷取不到的死槽
#。将来若要暴露真实长度，得先给参考腿一条同样自洽的读法。

# (逻辑名, 操作数字段宽 bytes)。操作码字节本身 1B。
LOGICAL_OPS = (
    ("HALT", ()),
    ("LOADK", (1, 2)),        # r, imm:i16
    ("MOVE", (1, 1)),         # a, b
    ("ADD", (1, 1, 1)),       # d = a + b
    ("SUB", (1, 1, 1)),
    ("MUL", (1, 1, 1)),
    ("FLOORDIV", (1, 1, 1)),  # d = a // b（b=0 → VM 故障；ISA v3，既有目标源码需要）
    ("LT", (1, 1, 1)),        # d = a < b
    ("EQ", (1, 1, 1)),
    ("JMP", (2,)),            # t:u16 绝对 IR 索引
    ("JZ", (1, 2)),           # r falsey → t
    ("ITERNEW", (1, 1)),      # d = iter(1..=src)（探针 fixture 形态）
    ("ITERNEXT", (1, 1)),     # d = next(it) 或 None
    ("CALL", (1, 1, 1, 1)),   # dst, func_idx, argbase, argc
    ("RET", (1,)),
    ("PRINT", (1,)),
    ("LOADN", (1,)),          # r = None
    ("LOADG", (1, 1)),        # r, gidx:u8（全局/内建表）
    ("STOREG", (1, 1)),       # gidx:u8, r
    ("MAKEFUNC", (1, 1)),     # r, fid:u8
    ("CALLV", (1, 1, 1, 1)),  # dst, callee_reg, argbase, argc
    ("JN", (1, 2)),           # r is None → t（FOR_ITER 专用；k=0 是合法值）
    ("LOADS", (1, 2)),        # r, sidx:u16 字符串常量池
    ("CONCAT", (1, 1, 1)),    # d = str(a) + str(b)（两侧须 str——与 CPython + 同界）
    ("LOADB", (1, 1)),        # r, b:1（0/1 → False/True； bool 常量）
    ("TUPLE", (1, 1, 1)),     # d = (regs[base..base+n])（n:1； 运行期构元组）
    ("GETITEM", (1, 1, 1)),   # d = tup[i]（i 越界即 VM 故障，不给错值）
    # 早期轮次 输入依赖（ISA v4）。两枚都是"从进程输入窗口取一个字节"：下标来自寄存器
    # （可循环），结果落寄存器（i128，值域 0..255）。输入不进产物、不进 blob，
    # 运行期由 boot 填窗（argv 扁平化 = 各参数以 0x00 分隔，截 64 B；stdin 截 64 B）。
    ("ARGV", (1, 1)),         # d = argv_win[regs[r]]（r 持下标；越界即 VM 故障）
    ("STDIN", (1, 1)),        # d = stdin_win[regs[r]]
    # 早期轮次+C（ISA v5）：ARX 步进的逻辑操作码。两枚都**追加在表尾**——逻辑号 0..28 逐字
    # 不变，`hayase_sou` 的置换只按 _NAMES 序取前 N 项，所以扩表不漂移已出厂形态的物理字节。
    # 值域为非负整数：负操作数与非整型同走既有故障 → 桶码 → 静默 exit 3 通道（同 ARGV/STDIN
    # 一族），不新增可见行为。ROTL32 先取 a 的低 32 位、k 取 mod 32，结果恒 < 2^32。
    ("XOR", (1, 1, 1)),        # d = a ^ b
    ("ROTL32", (1, 1, 1)),     # d = rotl32(a, k)
    # 早期轮次 （ISA v6）：链步进原语。d = hstep(a, b)——a 是链状态、b 是消息字，结果 < 2^32。
    # 三轮 ARX 步进（含半折/乘性回灌/耦合注入）与它用到的**全部链常量**一起搬进原生 handler：
    # 内存取证在这里看到的是一枚操作码 + 两个寄存器号，读不到步进结构，也抄不到常量表（关）。
    # 步进**形状**（轮数/半折位置与次数/回灌形式/耦合档/轮序）逐格派生，派生源是 VM 根密钥，
    # 与 chunk 置换/分派槽置换同一条层级（vm_isa.chain_profile ↔ vm.rs ops::chain_decode）。
    ("HSTEP", (1, 1, 1)),
)
_NAMES = tuple(n for n, _ in LOGICAL_OPS)
OP_WIDTHS = {n: w for n, w in LOGICAL_OPS}   # 公开：编译器/闸门与 vm_isa 共用同一张宽度表
_WIDTHS = OP_WIDTHS
_INSTR_BYTES = {n: 1 + sum(w) for n, w in LOGICAL_OPS}

# （安全审计）：逐操作数的种类表（与 LOGICAL_OPS 同序同长，加指令须两处同步）。
# R=寄存器（译码点必须验界，越界 IndexError 会击穿 SaayaYamabuki 协议）；G=全局表
# 号；F=函数号；S=字符串池号；T=跳转目标（运行期 _fetch/_advance 已验）；I=立即数。
OP_KINDS = {
    "HALT": (), "LOADK": ("R", "I"), "MOVE": ("R", "R"),
    "ADD": ("R", "R", "R"), "SUB": ("R", "R", "R"), "MUL": ("R", "R", "R"),
    "FLOORDIV": ("R", "R", "R"), "LT": ("R", "R", "R"), "EQ": ("R", "R", "R"),
    "JMP": ("T",), "JZ": ("R", "T"), "ITERNEW": ("R", "R"), "ITERNEXT": ("R", "R"),
    "CALL": ("R", "F", "W", "C"), "RET": ("R",), "PRINT": ("R",), "LOADN": ("R",),
    "LOADG": ("R", "G"), "STOREG": ("G", "R"), "MAKEFUNC": ("R", "F"),
    "CALLV": ("R", "R", "W", "C"), "JN": ("R", "T"), "LOADS": ("R", "I"),
    "CONCAT": ("R", "R", "R"), "LOADB": ("R", "B"), "TUPLE": ("R", "R", "C"),
    "GETITEM": ("R", "R", "R"),
    # 早期轮次：两个操作数都是寄存器（目标 + 下标）——译码点的验界必须两条都过，
    # 只验其一就是"两错相消"的温床（[[u16-vm-status]] 记过的元组维度教训）
    "ARGV": ("R", "R"), "STDIN": ("R", "R"),
    # 早期轮次+C：与 ADD/SUB/MUL 同形（d = op(a, b)，三个都是寄存器）
    "XOR": ("R", "R", "R"), "ROTL32": ("R", "R", "R"),
    # 早期轮次：同形（d = hstep(regs[a], regs[b])）——译码点三个操作数都要验界
    "HSTEP": ("R", "R", "R"),
}

_MAX_U16 = 0xFFFF

# ROTL32 的位宽（与 vm.rs 的 `U32_RANGE` 同值，双端由 test_vm_gates 的 source-literal 检查钉住）。
U32 = 1 << 32
_U32_MASK = U32 - 1

# 载荷源可用的**内建**（intrinsic）：名字 → (逻辑操作码, 参个数, CPython 参考实现)。
# 内建不是"运行期的可调用对象"——vm_compiler 在调用位点把它直接展开成那一枚操作码，
# 因此它绝不进全局表、名字也绝不落进产物。第三项是给参考 harness / 出厂门用的
# **同一语义的 CPython 形式**：单源放在这里，避免每个探针各抄一遍闭式（抄一份就是
# 一份可能漂移的分叉面）。负操作数与 VM 侧同判据：拒。
INTRINSICS = {
    "rotl32": ("ROTL32", 2, lambda v, k: (
        ((v & _U32_MASK) << (k % 32) | (v & _U32_MASK) >> (32 - k % 32)) & _U32_MASK)
        if v >= 0 and k >= 0
        else (_ for _ in ()).throw(ValueError("rotl32 只在非负整数域"))),
    # hstep 的闭式**逐格剖面依赖**（轮数/半折/回灌形式都由 VM 根密钥派生），所以这里放
    # None：没有任何一份"随手就能用"的闭式抄本可写。参考腿必须经 usami_rito(root)
    # 绑定，VM 腿在建 VM 时解同一份剖面——三腿同源，少一处双端分叉面。
    "hstep": ("HSTEP", 2, None),
}

# ---------------- 早期轮次：链剖面派生与 HSTEP 规范闭式（的单源） ----------------

# 域标签续中性短码序列（i1..i17 已被密钥层级 / 守卫顺序置换 / 变体选择 / 分派槽置换 /
# 死路径用掉）：i18 形状字段、i19 常量流、i20 掩码流、i21 补齐字节。派生源是 **VM 根密钥**
# （= HKDF(容器 enc_key, i3)），与 chunk 置换（i7）、分派槽置换（i15）同一条层级：
# 构建侧 vm_blob.matsukai_mao(container_key)["root"] ↔ 运行期 vm.rs 的 `root`，两侧同一个值。
# 运行期零随机：剖面是 root 的纯函数，root 是 (seed, nonce, 拓扑) 的纯函数（不破）。
CHAIN_CFG_LABEL = b"i18"
CHAIN_K_LABEL = b"i19"
CHAIN_MASK_LABEL = b"i20"
CHAIN_PAD_LABEL = b"i21"
CHAIN_CFG_BYTES = 12
CHAIN_K_BYTES = 64
_CHAIN_WORDS = 16       # 有效常量枚数（下标表见 _K_*）
_CHAIN_ROUNDS_MAX = 4
# 掩码流与常量流**同位异或**后才是有效常量：产物镜像与内存里因此都不存在"一枚枚轮常量"
# 这种连续可抄的形态，只有两段各自高熵的流（诚实定位：拖延档，不是边界——持有产物者
# 照样能重建 KDF 层级，与 /chunk 置换同级）。

# 16 枚 u32 有效常量（下标 = 流内字位，两侧共用这一张表）：
#   0..3   KADD[0..3]  各轮加数
#   4      IV          入口状态折叠量（载荷侧初值恒 0，IR 里因此没有 IV）
#   5      KM          回灌形式 1 的加数
#   6..8   TA,TB,TC    生成映射系数（表查档的旋转量选择 + 耦合项共用这一张概念表）
#   9      TPM         该映射的模数种子
#   10..13 MUL[0..3]   各轮的乘性回灌系数（把半折压掉的位宽重新摊开）
#   14     KEND        收尾混合步的加数
#   15     KF          末态的后置异或量
_K_ADD, _K_IV, _K_KM, _K_TA, _K_TPM, _K_MUL, _K_END, _K_KF = (0, 4, 5, 6, 9, 10, 14, 15)


def _word(stream: bytes, i: int) -> int:
    return int.from_bytes(stream[4 * i:4 * i + 4], "little")


def _fold(ks: bytes, mask: bytes, i: int) -> int:
    """第 i 枚有效常量 = 常量流字 ⊕ 掩码流字（模 2^32 域内）。"""
    return (_word(ks, i) ^ _word(mask, i)) & _U32_MASK


def _perm_n(pool_len: int, idx: int) -> list:
    """0..pool_len-1 的第 idx 个排列（阶乘数制）。两侧同式：Rust 侧 `chain_order` 逐字复刻，
    剖面 KAT 用同一组 root 对拍。

    先对 pool_len! 取模再展开——不取模时 idx 可以大到让第一跳的 `pick` 越出池长
    （R=2 时 24 个序数里只有 2 个是合法排列）。"""
    total = 1
    for x in range(2, pool_len + 1):
        total *= x
    idx %= total
    pool = list(range(pool_len))
    out = []
    for size in range(pool_len, 0, -1):
        fact = 1
        for x in range(2, size):
            fact *= x
        pick, idx = divmod(idx, fact)
        out.append(pool.pop(pick))
    return out


def kaburaki_roco(root: bytes) -> dict:
    """VM 根密钥(32B) → 本格链剖面（形状字段 + 有效常量 + 两段未解码的流）。

    `ks`/`mask` 是原样两段流，`k*` 系列是解码后的有效值——原生侧只允许携带前者并在每步
    现算后者（见 vm.rs 的 `Chain`），Python 腿把两者都给，是为了让
    `constants_not_table_gate` 能算出"哪些值不许在内存里成表"。"""
    if len(root) != 32:
        raise ValueError("chain root must be 32 bytes")
    cfg = keys._expand(root, CHAIN_CFG_LABEL, CHAIN_CFG_BYTES)
    ks = keys._expand(root, CHAIN_K_LABEL, CHAIN_K_BYTES)
    mask = keys._expand(root, CHAIN_MASK_LABEL, CHAIN_K_BYTES)
    rounds = 2 + cfg[0] % 3                                  # r ∈ {2,3,4}
    return {
        "rounds": rounds,
        "fold_pos": cfg[1] % rounds,                         # 半折位
        "fold_cnt": 1 + cfg[2] % 2,                          # 半折次数 ∈ {1,2}
        "inject": cfg[3] % 3,                                # 回灌形式（三档全非线性）
        "couple": cfg[4] & 1,                                # 耦合注入档
        "tail_rot": cfg[11] & 1,                             # 末转档（步进顺序轴的另一半）
        "rot": [1 + cfg[5 + k] % 31 for k in range(_CHAIN_ROUNDS_MAX)],
        "order": _perm_n(rounds, cfg[9]),                    # 步进顺序逐格
        "kadd": [_fold(ks, mask, _K_ADD + k) for k in range(_CHAIN_ROUNDS_MAX)],
        "iv": _fold(ks, mask, _K_IV),
        "km": _fold(ks, mask, _K_KM),
        "tbl": [_fold(ks, mask, _K_TA + i) for i in range(3)],
        "tbl_mod": 32768 + _fold(ks, mask, _K_TPM) % 60000,  # 模数恒 > 0
        "mul": [_fold(ks, mask, _K_MUL + i) | 1 for i in range(_CHAIN_ROUNDS_MAX)],
        "kend": _fold(ks, mask, _K_END),
        "kf": _fold(ks, mask, _K_KF),
        "fold_val": [8 if (cfg[10] >> i) & 1 else 16 for i in range(2)],
        # cfg[0..12] 的用法（Rust 侧 chain_* 逐字对镜）：0 轮数、1 半折位、2 半折次数、
        # 3 回灌形式、4 耦合档、5..8 四轮移量、9 步序排列序数、10 两个半折量位、11 末转档。
        "pad": keys._expand(root, CHAIN_PAD_LABEL, 1)[0],
        # 三段未解码的流一并给出：Rust 的 Chain 携的就是这三段，剖面 KAT 与
        # constants_not_table_gate 都要按同一份输入对拍（少给一段就多一处各算各的面）
        "cfg": cfg, "ks": ks, "mask": mask,
    }


def _chain_map(z: int, c: list, mod: int) -> int:
    """概念上的 256 项表查：T(z) = (z²·A + z·B + C) mod M，**算法生成、不落表**。
    工作书把的回灌形式之一写作"表查"；把表物化在内存里正是要禁的形态，
    所以这里按 BC 代二次表同一条纪律（g4 目标源码的 _Q_BLOCK 就是它）现算。
    定义域恒为 z ∈ 0..255，中间量 ≤ 255²·(2^32-1) + 255·(2^32-1) + 2^32 < 2^56——
    u64 内精确，两侧都不需要取模技巧。"""
    return (z * z * c[0] + z * c[1] + c[2]) % mod


def shishido_akari(prf: dict, st: int, m: int) -> int:
    """HSTEP 的规范闭式（CPython 参考腿与 VM 权威腿共用；Rust 腿逐式镜像 + 三条变体）。

    值域与非负判据同 XOR/ROTL32：负数/非整数由调用方拒（vm_interp SaayaYamabuki /
    vm.rs E-116），这里只管模 2^32 的代数。
      a  = (st + IV) mod 2^32                IV 折叠在状态入口——载荷侧初值恒 0，
                                             所以 IR 里没有任何链常量
      x  = m mod 2^32
      y0 = INJECT(x)                         形式逐格：0:x·x 1:(x+KM)·x 2:ROTL32(x, T(x&0xFF)&31)
      y0 = 按耦合档再 + Q[(a ^ x) & 0xFF]（b-couple 注入，逐格）
      每轮 j = order[k]：t = ROTL32(a + y0 + KADD[j], rot[j])，命中半折位再
      t ^= ROTL32(t, fv)——fv ∈ {8,16} 就是"把高低两半折起来"那一步
      收尾再走一步**不折**的混合 ROTL32(s + y0 + KEND, rot[3])（输出宽度恒为满 32 位），
      按 tail_rot 档可再转一次，最后 ⊕ KF
    每一步都收在模 2^32 内 ⇒ 结果恒 < 2^32（与 ROTL32 同一条值域纪律）。
    """
    a = (st + prf["iv"]) & _U32_MASK
    x = m & _U32_MASK
    # 回灌形式恒**非线性**（的三档）。实测教训：首版把"纯 m 直注"也列成一档，
    # 那 shape 下 col1 平均翻转只有 4.22 位——链是 CBC 形的，消息项线性时最后一个字节的
    # 差分原样穿过，雪崩当场不成立。指导稿列的三档
    # （m·m / (m+K)·m / 表查）都是非线性的，就按那三档。
    if prf["inject"] == 0:
        y0 = (x * x) & _U32_MASK
    elif prf["inject"] == 1:
        y0 = (((x + prf["km"]) & _U32_MASK) * x) & _U32_MASK
    else:
        # 表查档：表项**选旋转量**而不是当加数——加数形 (m + T(m&0xFF)) 对 m 高位
        # 只贡献 Δm（线性，同样的塌缩），而按表项旋转把 8 位表值摊到整字上。
        # 表本身不落盘，按 BC 代二次表同一条纪律现算。
        y0 = _rotl32_u32(x, _chain_map(x & 0xFF, prf["tbl"], prf["tbl_mod"]) & 31)
    if prf["couple"]:
        y0 = (y0 + _chain_map((a ^ x) & 0xFF, prf["tbl"], prf["tbl_mod"])) & _U32_MASK
    s = a
    prev = a
    for k in range(prf["rounds"]):
        j = prf["order"][k]
        t = (s + y0 + prf["kadd"][j]) & _U32_MASK
        t = _rotl32_u32(t, prf["rot"][j])
        if k == prf["fold_pos"]:
            t ^= _rotl32_u32(t, prf["fold_val"][0])
        if prf["fold_cnt"] == 2 and k == (prf["fold_pos"] + 1) % prf["rounds"]:
            t ^= _rotl32_u32(t, prf["fold_val"][1])
        # 乘性回灌：半折 t ^= ROTL32(t,·) 是把状态**压掉一半位宽**的操作（核是 2^16
        # 或 2^24 量级），纯加法链会把首字节差值一路带到输出为 0——实测 64 格里 41 格
        # 雪崩不达标、最差一格平均只有 2.3 位。v5 手写块里"第三轮 g·g1"就是同一手，
        # 只是那时它是硬编码；这里做成逐格系数（乘数恒置奇数，模 2^32 下是双射）。
        t = (t + prev * prf["mul"][j]) & _U32_MASK
        prev = s
        s = t
    # 收尾混合步：**恒不折**。半折 t ^= ROTL32(t,16) 的输出形如 (v,v)，只有 16 位有效宽度；
    # 折位落在末轮就把整个状态的熵当场砍掉一半（实测 col2 最小翻转 0 位）。补一步不折的
    # 混合让输出宽度恒为满 32 位——v5 手写块里"第三轮只混合不折"是同一件事，只是那时它
    # 是巧合，现在是结构不变量。
    s = _rotl32_u32((s + y0 + prf["kend"]) & _U32_MASK, prf["rot"][3])
    if prf["tail_rot"]:
        s = _rotl32_u32(s, prf["rot"][prf["order"][0]])
    return (s ^ prf["kf"]) & _U32_MASK


def _rotl32_u32(v: int, k: int) -> int:
    return ((v << k) | (v >> (32 - k))) & _U32_MASK


def akagi_wen(root: bytes) -> int:
    """定长吸收的补齐字节：逐格、构建期即可算、运行期由 root 现算——两侧同式。"""
    return keys._expand(root, CHAIN_PAD_LABEL, 1)[0]


def hibachi_mana(prf: dict, window: bytes, cap: int = INPUT_WINDOW) -> bytes:
    """把一个输入窗补齐到上限（定长吸收的**唯一**表达式，参考腿与 VM 腿共用）。

    补齐而不是"少跑几轮"，运行步数才与输入长度无关；补齐字节逐格（root 的函数）所以
    短输入不会与任何真输入撞车。超上限**不进来**——那是拒绝通道（两侧 E-112/E-113），
    截断永远不允许。"""
    if len(window) > cap:
        raise ValueError("window %dB exceeds cap %dB (refuse, never truncate)"
                         % (len(window), cap))
    return bytes(window) + bytes([prf["pad"]]) * (cap - len(window))


def usami_rito(target: dict, root: bytes = None) -> dict:
    """把 INTRINSICS 绑进一个 CPython 命名空间（参考腿的**唯一**绑定出口）。

    剖面依赖的内建（闭式为 None 的那些，即 hstep）在没有 root 时绑一枚**一调用即 raise**
    的桩：装载一份不碰它的目标源码照样可以（旧代产物、消融臂都用它），但"少了剖面还算出
    一个答案"是最贵的一类双端分叉，必须当场炸而不是静默错。"""
    prf = kaburaki_roco(root) if root is not None else None
    for name, (_op, _ar, ref) in INTRINSICS.items():
        if ref is not None:
            target[name] = ref
            continue
        if prf is None:
            def _need_profile(_n=name):
                raise ValueError("内建 %r 逐格剖面依赖 root：调用方必须经 usami_rito 提供"
                                 % _n)
            target[name] = lambda *a, **k: _need_profile()
        else:
            target[name] = (lambda st, m, _p=prf: shishido_akari(_p, st, m))
    return target


def lain_paterson(funcs) -> bool:
    """IR 是否真的**消费输入**（含 ARGV/STDIN）——早期轮次 出厂门的单源判据。

    只看"出现"：编译器已保证 `argv`/`stdin` 只能经这两条指令取值（句柄当值用一律
    编译期硬拒，见 vm_compiler._Frame.pop），所以出现即读取。"""
    return any(ins[0] in ("ARGV", "STDIN")
               for _nregs, instrs in funcs for ins in instrs)


# 跳转目标操作数在指令元组中的位置（0 基，含操作码名之后）
_JPOS = {"JMP": 0, "JZ": 1, "JN": 1}


def hayase_sou(seed: bytes) -> dict:
    """seed(32B) → {逻辑名: 物理字节}。确定性置换，逐构建随机（同源派生）。

    域标签与 `PHYSMAP_VER` 绑定：换算法必须换标签，否则同 seed 会产不同形态却自称同版本。
    +（既有审计结论）：标签改无语义短码与 Rust 端 L_ISA_EXTRACT/L_ISA_PERM
    对齐（i1/i2）——语义化标签曾让 外部分析者直接认出 ISA 置换的存在。
    PHYSMAP_VER 演进时须与 vm.rs 双端同升（算法版本改由标签外字段承载）。"""
    if len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    prk = keys._extract(b"i1", seed)
    stream = keys._expand(prk, b"i2", _OPSPACE * 3)
    order = list(range(_OPSPACE))
    j = 0
    for i in range(_OPSPACE - 1, 0, -1):
        j = stream[j] % (i + 1)
        order[i], order[j] = order[j], order[i]
        j += 1
        if j >= len(stream):
            j = 0
    return {name: order[i] for i, name in enumerate(_NAMES)}


def _inverse(mapping: dict) -> dict:
    inv = {v: k for k, v in mapping.items()}
    if len(inv) != len(mapping):
        raise ValueError("physmap not injective")
    for phys in inv:
        if not 0 <= phys < _OPSPACE:
            raise ValueError("phys byte out of range")
    return inv


def _instr_stream_layout(funcs, mapping):
    """funcs → 每条指令的**流内字节偏移**列表（按函数分组）。坐标换算的唯一出处。"""
    starts = []
    total = 0
    layouts = []
    for _nregs, instrs in funcs:
        starts.append(total)
        offs = []
        b = 0
        for name, *_ in instrs:
            if name not in _WIDTHS:
                raise ValueError("unknown op %r" % name)
            offs.append(b)
            b += _INSTR_BYTES[name]
        layouts.append(offs)
        total += b
    return starts, layouts


def shellin_burgundy(funcs, mapping: dict) -> tuple:
    """funcs=[(nregs, instrs)] → (物理指令流 bytes, [(start_byte, nregs)])。

    越界即拒（不静默截断）：跳转目标必须落在同函数指令边界、操作数必须装进声明宽度、
    流总长必须 ≤ u16 可表达跳转范围（`limits.max_jump_target`，layout.json 登记）。"""
    starts, layouts = _instr_stream_layout(funcs, mapping)
    if starts and layouts[-1] and (starts[-1] + (layouts[-1][-1] + 1)) > _MAX_U16:
        raise ValueError("ir stream %d B exceeds u16 jump range" % starts[-1])
    out = bytearray()
    for fi, (_nregs, instrs) in enumerate(funcs):
        base = starts[fi]
        offs = layouts[fi]
        for ii, (name, *ops) in enumerate(instrs):
            widths = _WIDTHS[name]
            if len(ops) != len(widths):
                raise ValueError("%s operand count" % name)
            out.append(mapping[name])
            for k, (w, val) in enumerate(zip(widths, ops)):
                if name in _JPOS and k == _JPOS[name]:
                    if not 0 <= val < len(offs):
                        raise ValueError("%s target %r out of function" % (name, val))
                    out.extend(struct.pack("<H", base + offs[val]))
                    continue
                if not (0 <= val < (1 << (8 * w))):
                    raise ValueError("%s operand %r exceeds %dB" % (name, val, w))
                if w == 1:
                    out.append(val)
                else:
                    out.extend(struct.pack("<H", val & _MAX_U16))
    return bytes(out), list(zip(starts, [n for n, _ in funcs]))


def _instr_starts(stream: bytes, mapping: dict) -> list:
    """按物理操作码宽度走一遍流，返回每条指令的起始偏移（同时校验结构自洽）。"""
    inv = _inverse(mapping)
    offs = []
    pc = 0
    while pc < len(stream):
        name = inv.get(stream[pc])
        if name is None:
            raise ValueError("bad phys opcode 0x%02x at %d" % (stream[pc], pc))
        offs.append(pc)
        pc += _INSTR_BYTES[name]
    if pc != len(stream):
        raise ValueError("stream not closed at instruction boundary")
    return offs


def fumi(stream: bytes, mapping: dict, chunk_size: int = CHUNK_SIZE,
         align: bool = True) -> tuple:
    """ 分块规划：返回 ([(chunk_start, chunk_len)], 跨块指令数)。

    align=True（正式档）：块边界向后对齐到**指令边界**——每块装得下的最长指令前缀，
      块尾空出的字节由构建侧 PRF 填充补齐；跨块指令数必为 0（结构保证单块在场）。
      最后一条指令必然进最后一块，块数 = ceil(覆盖后的长度/块大小)。
    align=False（闸门档）：定长切块，跨块指令如实报告（探针 13 B 质数档依赖它）。
    """
    if chunk_size < 1 or chunk_size > 0xFFFF:
        raise ValueError("chunk_size out of range")
    if chunk_size < max(_INSTR_BYTES.values()):
        # 单条指令比块还长 ⇒ 对齐规划无解（也是规划循环的前进性前提）
        raise ValueError("chunk_size smaller than widest instruction")
    starts = _instr_starts(stream, mapping)
    n = len(stream)
    bounds = []
    if align:
        if not starts:
            raise ValueError("empty instruction stream")
        cur = 0
        i = 0
        while i < len(starts):
            if i + 1 < len(starts) and starts[i + 1] - starts[cur] >= chunk_size:
                bounds.append((starts[cur], starts[i] - starts[cur]))
                cur = i
            else:
                i += 1
                if i == len(starts):
                    bounds.append((starts[cur], n - starts[cur]))
    else:
        for lo in range(0, n, chunk_size):
            bounds.append((lo, min(chunk_size, n - lo)))
    straddles = 0
    if not align:
        inv = _inverse(mapping)
        for off in starts:
            name = inv.get(stream[off])
            if name is None:
                raise ValueError("bad phys opcode at %d" % off)
            last = off + _INSTR_BYTES[name] - 1
            if off // chunk_size != last // chunk_size:
                straddles += 1
    return bounds, straddles
