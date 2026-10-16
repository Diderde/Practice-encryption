// Copyright (C) 2026 Diderde
// SPDX-License-Identifier: GPL-3.0-only
//!  VM blob v2 的原生解释器（boot 的 `mod vm;`，与 Python 权威端互钉）。
//!
//! 这一模块只在 boot 编译单元里存在（`super::*` 即 boot 的密码学原语：
//! `blake2s::sister_claire` / `joe_rikiichi`(HMAC-SHA256) / `machita_chima`(HKDF-Expand) /
//! `belmond_banderas`(ChaCha20 流)），所以双路径互钉走**真实产物**而不是另编一个
//! 探针 exe——被测代码路径与出货代码路径同一份（探针形态会漂移）。
//!
//! 与 Python 权威端 `d_side/builder/vm_interp.py` 的语义逐式对齐，差异只允许出现在
//! 设计稿已登记的修复项上：LOADS 满 u16、PRINT 逐字节、真值协议、取指不跨块、
//! 显式 entry、填充区结构校验、槽数与页隔离。
//!
//! 整数宽度：v1 子集用 i128，**溢出即 fail-closed 拒绝执行**（绝不给错数）。
//! 这是子集边界之一，与"不支持 dict"同级：构建期无法判定，运行期拒绝。

use std::convert::TryInto;

//   的变体池（早期轮次 批2-2.1）。零依赖，所以验收齿能把**全部** 24 条实现编进
// 一个小二进制做 (op × variant × 边界输入) 全矩阵差分；产品里每格只留被选中那一条
// （`crate::pins::V_*` 是构建期常量，未选分支在 MIR 常量折叠后不可达 ⇒ 不生成代码，
// 产物扫描按 `vm_ops.rs` 的 TAG_* 标签取证：在场当且仅当被选中）。
#[path = "vm_ops.rs"]
mod ops;

/// 变体选择宏：`$sel` 必须是构建期常量（`pins::V_<OP>`），否则三条都会被生成。
/// `macro_rules!` 在这里充当"变体注册 + 别名表"的生成器（方案书 §2.1）。
macro_rules! hot_call {
    ($sel:expr, $f0:path, $f1:path, $f2:path; $($arg:expr),+) => {
        if $sel == 0 { $f0($($arg),+) }
        else if $sel == 1 { $f1($($arg),+) }
        else { $f2($($arg),+) }
    };
}

/// 搬运类闸门宏：判定走选定变体，失败沿**该操作码原有**的那条错误码走静默通道
/// （错误码与判定顺序与引入变体池之前逐字相同——变体只换"怎么判"，不换"判什么"）。
macro_rules! hot_gate {
    ($sel:expr, $f0:path, $f1:path, $f2:path; $idx:expr, $len:expr, $code:expr) => {
        match hot_call!($sel, $f0, $f1, $f2; $idx, $len) {
            Some(v) => v,
            None => return Err($code.to_string()),
        }
    };
}

/// 搬运类热操作码在判定前读到的容器长度。`depth` 越界 ⇒ 长度为 0 ⇒ 闸门必判失败
/// ⇒ 落回该操作码原有的那条错误码，与 `melissa_kinrenka`/`genzuki_tojiro` 同口径
/// （不新增可见行为）。
fn hot_len(frames: &[Frame], depth: usize) -> usize {
    frames.get(depth).map(|f| f.regs.len()).unwrap_or(0)
}

const OP_HALT: usize = 0;
const OP_LOADK: usize = 1;
const OP_MOVE: usize = 2;
const OP_ADD: usize = 3;
const OP_SUB: usize = 4;
const OP_MUL: usize = 5;
const OP_LT: usize = 7;
const OP_EQ: usize = 8;
const OP_JMP: usize = 9;
const OP_JZ: usize = 10;
const OP_ITERNEW: usize = 11;
const OP_ITERNEXT: usize = 12;
const OP_CALL: usize = 13;
const OP_RET: usize = 14;
const OP_PRINT: usize = 15;
const OP_LOADN: usize = 16;
const OP_LOADG: usize = 17;
const OP_STOREG: usize = 18;
const OP_MAKEFUNC: usize = 19;
const OP_CALLV: usize = 20;
const OP_JN: usize = 21;
const OP_LOADS: usize = 22;
const OP_CONCAT: usize = 23;
const OP_LOADB: usize = 24;
const OP_TUPLE: usize = 25;
const OP_GETITEM: usize = 26;
const OP_FLOORDIV: usize = 6;
// 早期轮次 输入原语（ISA v4）：下标来自寄存器、结果是一个字节值（0..255）。
// 追加在表尾——逻辑号 0..26 逐字不变，所以旧 IR 的语义不因扩表而漂移。
const OP_ARGV: usize = 27;
const OP_STDIN: usize = 28;
// 早期轮次+C（ISA v5）ARX 步进的逻辑操作码。同样**追加在表尾**：`physmap` 只按顺序取置换的
// 前 N_LOGICAL 项，所以旧 29 名的物理字节逐格不变，扩表不漂移已出厂形态。
const OP_XOR: usize = 29;
const OP_ROTL32: usize = 30;
// 早期轮次 （ISA v6）链步进原语。同样**追加在表尾**：旧 30 名的物理字节逐格不变，
// 扩表不漂移已出厂形态。
const OP_HSTEP: usize = 31;
const N_LOGICAL: usize = 32;

/// ROTL32 的位宽（= 1 << 32；与 `vm_isa.` 同值，双端由 test_vm_gates 的 source-literal
/// 检查钉住）。非负整数域外的操作数（负数）一律走桶码 E-116，与 vm_interp 的
/// SaayaYamabuki 同判据。
const U32_RANGE: i128 = 4294967296;

// 输入窗上限（早期轮次 Phase 2 起**逐格**）：上一代这里是两枚字面常量，与 boot 同值——
// 但"同值"本身就是全局契约的一部分（读一次八格通用）。现在窗上限来自构建期注入的
// `pins::IFACE_AP` / `pins::IFACE_SP`（项数上限由 boot 侧用 `pins::IFACE_ARG_MAX` 把关，
// VM 只看到已扁平化的窗、不再数项），出处 native_build.koyanagi_rou。
// `vm_isa.INPUT_WINDOW` 退为**库侧默认值**（不带契约调用时按它走），产品路径必须显式
// 传本格上限；两侧同式由 tests/d_side 的接口齿与 native 腿端到端用例钉。
// 越界一律走桶码，**不静默截断**。

/// 操作数字节宽（下标 = 逻辑操作码号，与 vm_isa.LOGICAL_OPS 逐条对应）
const OP_WIDTHS: [usize; N_LOGICAL] =
    [0, 3, 2, 3, 3, 3, 3, 3, 3, 2, 3, 2, 2, 4, 1, 1, 1, 2, 2, 2, 4, 3, 3, 3, 2, 3, 3, 2, 2,
     3, 3, 3];

const OPSPACE: usize = 256;
const MAX_CHUNK: usize = 512;
const MAX_SLOTS: usize = 2;
const RESIDENT_SLOTS: usize = 2;   // 与 vm_isa.RESIDENT_SLOTS 同一常量（双端校验）
const MAX_OP: usize = 8;
const HEADER_LEN: usize = 64;
const FLAG_PERM: u8 = 0x01;
const STEP_BUDGET: usize = 20_000_000;

// +（既有审计结论）：域分离标签原为语义明文（"vm-root"/
// "vm-stream-mac"/…）——外部分析者据 .rdata 标签集直接画出密钥层级。
// HKDF info 只要求**互异**，不要求可读：全部换为无语义短标签。改值即新代际
// （旧产物标签集被还原的结论对新构建失效）。对应 Python 参考端不消费这些
// 标签（已核实），单端改动安全
const L_ISA_EXTRACT: &[u8] = b"i1";
const L_ISA_PERM: &[u8] = b"i2";
const L_VM_ROOT: &[u8] = b"i3";
const L_CHUNK_KEY: &[u8] = b"i4";
const L_STREAM_MAC: &[u8] = b"i5";
const L_CHUNK_NONCE: &[u8] = b"i6";
const L_CHUNK_PERM: &[u8] = b"i7";
// 早期轮次：逐格链剖面的四条域标签（续中性短码序列，与 vm_isa 的
// CHAIN_CFG_LABEL/CHAIN_K_LABEL/CHAIN_MASK_LABEL/CHAIN_PAD_LABEL 一一对应）。
const L_CHAIN_CFG: &[u8] = b"i18";
const L_CHAIN_K: &[u8] = b"i19";
const L_CHAIN_MASK: &[u8] = b"i20";
const L_CHAIN_PAD: &[u8] = b"i21";
/// 三条流的长度（与 vm_isa.CHAIN_CFG_BYTES / CHAIN_K_BYTES 同值，双端 source-literal 齿钉住）。
const CHAIN_CFG_LEN: usize = ops::CHAIN_CFG_LEN;
const CHAIN_K_LEN: usize = ops::CHAIN_K_LEN;

#[derive(Clone)]
enum Val {
    I(i128),
    B(bool),
    N,
    S(Vec<u8>),
    T(Vec<Val>),
    It { next: i128, end: i128 },
    Func(usize),
    Native(u8),
}

/// Python 真值协议在 v2 值域上的等价形式：None / False / 0 / "" 为假，其余为真。
fn truthy(v: &Val) -> bool {
    match v {
        Val::N => false,
        Val::B(b) => *b,
        Val::I(i) => *i != 0,
        Val::S(s) => !s.is_empty(),
        _ => true,
    }
}

/// CPython 语义：bool 参与算术/比较时按 0/1 强转（True + True == 2）。
fn as_int(v: &Val) -> Result<i128, String> {
    match v {
        Val::I(i) => Ok(*i),
        Val::B(b) => Ok(i128::from(*b)),
        _ => Err("E-42".to_string()),
    }
}

/// EQ 的结构等价（W 深查中危项修复）：S 比字节、N/N 真、B/B、I/I 数值、
/// T/T 递归逐元素；跨型假——与 Python 权威端的元组 == 对齐（此前 T 落
/// as_int 拒，双端分叉）。
/// 早期轮次 复核补漏：不透明值（It/Func/Native）原落兜底臂 as_int 双 None 判等——
/// (Func(1),Func(2)) 给真而权威端结构比较为假（`f == g` 同源码双端答案相反）。
/// 改为同型按负载比较（函数相等 = fid 相等，与 CPython 函数对象身份语义一致）、
/// 跨型一律假；B↔I 仍按数值（CPython `True == 1`）。
fn eq_val(a: &Val, b: &Val) -> bool {
    match (a, b) {
        (Val::S(x), Val::S(y)) => x == y,
        (Val::N, Val::N) => true,
        (Val::B(x), Val::B(y)) => x == y,
        (Val::I(x), Val::I(y)) => x == y,
        (Val::T(x), Val::T(y)) => {
            x.len() == y.len()
                && x.iter().zip(y.iter()).all(|(u, v)| eq_val(u, v))
        }
        (Val::It { next: n1, end: e1 }, Val::It { next: n2, end: e2 }) => n1 == n2 && e1 == e2,
        (Val::Func(f1), Val::Func(f2)) => f1 == f2,
        (Val::Native(t1), Val::Native(t2)) => t1 == t2,
        (Val::B(_), Val::I(_)) | (Val::I(_), Val::B(_)) => as_int(a).ok() == as_int(b).ok(),
        (Val::S(_), _) | (_, Val::S(_)) => false,
        (Val::N, _) | (_, Val::N) => false,
        _ => false,
    }
}

/// print 的字节契约：与 CPython `str()` 在 v2 值域上逐字节一致。
fn text(v: &Val) -> Result<Vec<u8>, String> {
    Ok(match v {
        Val::I(i) => i.to_string().into_bytes(),
        Val::B(true) => b"True".to_vec(),
        Val::B(false) => b"False".to_vec(),
        Val::N => b"None".to_vec(),
        Val::S(s) => s.clone(),
        Val::T(_) => repr_val(v, 0)?,
        _ => return Err("E-43".to_string()),
    })
}

/// 元组内字符串的 repr 子集（与 vm_interp.naraka 同一条纪律）：控制符/反斜杠拒绝；
/// 可打印字符（含非 ASCII，UTF-8 字节 ≥0x80 不撞检查）原样保留；引号规则同 CPython。
fn quote(s: &[u8]) -> Result<Vec<u8>, String> {
    if s.iter().any(|&c| c < 0x20 || c == 0x7f) || s.contains(&b'\\') {
        return Err("E-44".to_string());
    }
    let has_s = s.contains(&b'\'');
    let has_d = s.contains(&b'"');
    if has_s && has_d {
        return Err("E-45".to_string());
    }
    let q = if has_s { b'"' } else { b'\'' };
    let mut out = vec![q];
    out.extend_from_slice(s);
    out.push(q);
    Ok(out)
}

/// CPython repr 在 v2 值域上的等价形式（tuple 打印/嵌套元素用，深度上限与 Python 端同）。
fn repr_val(v: &Val, depth: usize) -> Result<Vec<u8>, String> {
    if depth > 8 {
        return Err("E-46".to_string());
    }
    match v {
        Val::T(t) => {
            let mut out = vec![b'('];
            for (i, e) in t.iter().enumerate() {
                if i > 0 {
                    out.extend_from_slice(b", ");
                }
                out.extend_from_slice(&repr_val(e, depth + 1)?);
            }
            if t.len() == 1 {
                out.push(b',');
            }
            out.push(b')');
            Ok(out)
        }
        Val::S(s) => quote(s),
        other => text(other),
    }
}

struct Slot {
    logical: usize,
    page: super::visprobe::PageBuf,
}

impl Slot {
    fn empty() -> Slot {
        Slot { logical: usize::MAX, page: super::visprobe::PageBuf::new() }
    }
}

struct Frame {
    pc: usize,
    regs: Vec<Val>,
    ret_dst: Option<usize>,
}

/// 单步上下文（批2-2.2）。handler 需要的输入（操作数、顺序后继、帧深、逻辑操作码）
/// 与输出（是否已自管 pc / 是否终止 / 待压入的新帧）都在这里面；`frames` 单独传，
/// 否则 handler 同时借 `&mut Vm` 和 Step 内的 frames 会撞双可变借用。
pub struct Step {
    li: usize,
    ops: [u8; MAX_OP],
    nxt: usize,
    depth: usize,
    jumped: bool,
    halt: bool,
    new_frame: Option<Frame>,
}

/// handler 签名。表元素是这个类型——**函数指针**，不是编号，所以表必须在运行期
/// 填好（静态填好就又变回一张 .rdata 跳表，既有审计读的正是那种表）。
type Handler = fn(vm: &mut Vm, frames: &mut Vec<Frame>, st: &mut Step) -> Result<(), String>;

/// （Rust 侧）：寄存器**读**的唯一出口。旧写法 `regs[ops[i]]` 是直接下标，
/// 持 seed 者构造越界操作数即 panic（exit 101），既破"一切 VM 故障 = 静默 exit 3"
/// 契约，panic 文本又泄 `regs.len()`（长度差分 oracle）——一律改 Err 走静默通道
///。与 Python 权威端 `vm_interp` 译码点的 `OP_KINDS` 验界同式。
fn melissa_kinrenka(frames: &[Frame], depth: usize, idx: usize) -> Result<&Val, String> {
    frames
        .get(depth)
        .and_then(|f| f.regs.get(idx))
        .ok_or_else(|| "E-47".to_string())
}

/// （Rust 侧）：寄存器**写**的同式出口。
fn genzuki_tojiro(
    frames: &mut [Frame],
    depth: usize,
    idx: usize,
    value: Val,
) -> Result<(), String> {
    let cell = frames
        .get_mut(depth)
        .and_then(|f| f.regs.get_mut(idx))
        .ok_or_else(|| "E-48".to_string())?;
    *cell = value;
    Ok(())
}

fn le16(b: &[u8]) -> usize {
    u16::from_le_bytes(b[0..2].try_into().unwrap()) as usize
}

fn le32(b: &[u8]) -> usize {
    u32::from_le_bytes(b[0..4].try_into().unwrap()) as usize
}

fn label_idx(label: &[u8], idx: usize) -> Vec<u8> {
    let mut v = label.to_vec();
    v.extend_from_slice(&(idx as u32).to_le_bytes());
    v
}

/// 按逻辑块号解出明文：v2 = 裸 ChaCha20（belmond_banderas 即"数据⊕密钥流"，
/// 加解密同式，不得再叠 XOR）；v3 = PSIV 块级 AEAD（tag 不符即 Err，fail-closed）。
fn decrypt_slot(
    ct: &[u8],
    place: &[usize],
    cs: usize,
    aead: bool,
    chunk_key: &[u8; 32],
    root: &[u8],
    logical: usize,
) -> Result<Vec<u8>, String> {
    let phys = *place.get(logical).ok_or_else(|| "E-49".to_string())?;
    let overhead = if aead { 16usize } else { 0 };
    let slot = cs + overhead;
    let seg = ct
        .get(phys * slot..phys * slot + cs)
        .ok_or("E-50".to_string())?;
    let nonce: [u8; 12] = super::machita_chima(root, &label_idx(L_CHUNK_NONCE, logical), 12)
        [..12]
        .try_into()
        .unwrap();
    if aead {
        let tag_start = phys * slot + cs;
        let tag: [u8; 16] = ct
            .get(tag_start..tag_start + 16)
            .ok_or("E-51".to_string())?
            .try_into()
            .unwrap();
        super::psiv::decrypt_block(chunk_key, &nonce, seg, &tag)
    } else {
        Ok(super::belmond_banderas(chunk_key, &nonce, seg))
    }
}

/// seed → 逻辑操作码号的物理字节表（顺序 = LOGICAL_OPS）。与 `vm_isa.hayase_sou` 逐式一致。
pub fn physmap(seed: &[u8]) -> Vec<u8> {
    let prk = super::joe_rikiichi(L_ISA_EXTRACT, seed);
    let stream = super::machita_chima(&prk, L_ISA_PERM, OPSPACE * 3);
    let mut order: Vec<u8> = (0..OPSPACE as u32).map(|x| x as u8).collect();
    // 游标语义必须与 `hayase_sou` 逐字一致：j 先被赋成**本轮交换目标**，再 j += 1
    // 作为下一轮的流游标。把它"整理"成独立变量 k 会改写取字节序列（实测双端分叉，

    let mut j = 0usize;
    for i in (1..OPSPACE).rev() {
        j = (stream[j] as usize) % (i + 1);
        order.swap(i, j);
        j += 1;
        if j >= stream.len() {
            j = 0;
        }
    }
    order[..N_LOGICAL].to_vec()
}

/// place[logical] = physical slot。与 `vm_blob._perm` 逐式一致（含取字节的两步推进）。
fn chunk_place(root: &[u8], nchunks: usize) -> Vec<usize> {
    if nchunks < 2 {
        return (0..nchunks).collect();
    }
    let stream = super::machita_chima(root, L_CHUNK_PERM, std::cmp::max(1024, nchunks * 4));
    let mut order: Vec<usize> = (0..nchunks).collect();
    let mut j = 0usize;
    for i in (1..nchunks).rev() {
        // 同 physmap：j 先取本轮交换目标，再从该位置前进 2 字节（与 `_perm` 逐字一致）
        j = ((stream[j] as usize) << 8 | (stream[j + 1] as usize)) % (i + 1);
        order.swap(i, j);
        j = (j + 2) % stream.len();
    }
    order
}

pub struct Vm {
    chunk_size: usize,
    nmeta: usize,
    nslots: usize,
    root: Vec<u8>,
    chunk_key: [u8; 32],
    ct: Vec<u8>,
    place: Vec<usize>,
    aead: bool,
    funcs: Vec<(usize, usize)>,
    ir_used: Vec<usize>,
    globals: Vec<Val>,
    strings: Vec<Vec<u8>>,
    entry: usize,
    // 早期轮次 输入窗（boot 填；上限 = 本格 pins::IFACE_AP/IFACE_SP，构造时校验，
    // 不静默截断）。
    // 早期轮次：入 VM 即补齐到上限，所以这里存的是**补齐后**的定长窗，kind 3/4 报的
    // 也就是这个常数——运行步数因此与输入长度无关。
    argv_win: Vec<u8>,
    stdin_win: Vec<u8>,
    // 早期轮次：本格链剖面（只携三段未解码的流，常量在用的时候现算）
    chain: ops::Chain,
    slots: [Slot; MAX_SLOTS],
    rr: usize,
    inv: [usize; OPSPACE],
    out: Vec<u8>,
    // 批2-2.2：启动期建好的分派表 + 逐格槽位置换（都只在堆上，静态数据里没有）
    dtab: Vec<Handler>,
    dslot: Vec<u8>,
}

impl Vm {
    /// 把逻辑块解成明文向量（不可变借用 `self`，写入页缓冲由调用方分开做——
    /// 否则 `decrypt_into(&self, &mut self.slots[..])` 会同时借两次 self）。
    /// v3 的 PSIV tag 不符即 Err（fail-closed：静默空块 = 给篡改产物放行）。
    fn plain_of(&self, logical: usize) -> Result<Vec<u8>, String> {
        decrypt_slot(&self.ct, &self.place, self.chunk_size, self.aead,
                     &self.chunk_key, &self.root, logical)
    }

    fn slot_of(&mut self, logical: usize) -> Result<usize, String> {
        for s in 0..self.nslots {
            if self.slots[s].logical == logical {
                return Ok(s);
            }
        }
        let victim = self.rr % self.nslots;
        self.rr += 1;
        let mut plain = self.plain_of(logical)?;
        self.slots[victim].page.write(&plain);
        // （安全审计）：交换用临时明文即抛即焚——volatile 防 DCE 把清零优化掉；
        // 驻留与逐出已由 PageBuf 页管理覆零
        for b in plain.iter_mut() {
            unsafe { std::ptr::write_volatile(b, 0u8) };
        }
        self.slots[victim].logical = logical;
        Ok(victim)
    }

    /// 取指：只在 IR 区的**已用长度**内取，跨块或落进块尾填充即结构违规（fail-closed）。
    fn fetch_into(&mut self, pc: usize, n: usize, out: &mut [u8; MAX_OP]) -> Result<(), String> {
        if n == 0 {
            return Ok(());
        }
        let idx = pc / self.chunk_size;
        let off = pc % self.chunk_size;
        let used = *self.ir_used.get(idx).ok_or("E-52".to_string())?;
        if off >= used || off + n > used {
            return Err("E-53".to_string());
        }
        let slot = self.slot_of(self.nmeta + idx)?;
        let cs = self.chunk_size;
        let bytes = self.slots[slot].page.slice(cs);
        out[..n].copy_from_slice(&bytes[off..off + n]);
        Ok(())
    }

    /// 顺序后继：正好落到某块已用长度末尾时，跳过 PRF 填充到下一块块首。
    fn advance(&self, pc: usize) -> Result<usize, String> {
        let idx = pc / self.chunk_size;
        let used = *self.ir_used.get(idx).ok_or("E-54".to_string())?;
        let off = pc % self.chunk_size;
        if off == used {
            Ok((idx + 1) * self.chunk_size)
        } else if off > used {
            Err("E-55".to_string())
        } else {
            Ok(pc)
        }
    }

    /// 解析 + 流 MAC 校验 + 元数据逐段解密。任一步失败即 Err（boot 侧静默 exit 3）。
    /// `isa_physmap` = boot 侧用 seed 预先算好的 N_LOGICAL 项"逻辑号→物理字节"表
    /// （seed 本身不进 VM——早期轮次 步骤 3 的"运行中途 seed 不在场"断言要求）；
    /// `argv_win`/`stdin_win` = 早期轮次 的输入窗内容（boot 从进程取，构造时验上限）。
    pub fn new(blob: &[u8], container_key: &[u8], isa_physmap: &[u8],
               argv_win: &[u8], stdin_win: &[u8]) -> Result<Vm, String> {
        let (ap, sp) = (crate::pins::IFACE_AP, crate::pins::IFACE_SP);
        if argv_win.len() > ap || stdin_win.len() > sp {
            // 与 vm_interp 的入口校验同式：超窗一律拒，绝不静默截断
            return Err("E-112".to_string());
        }
        if blob.len() < HEADER_LEN {
            return Err("E-56".to_string());
        }
        let h = &blob[..32];
        // 早期轮次 2.4：魔数以 XOR 0x5A 态存储、运行时重组比较（明文 "VMB1" 曾是
        // 静态还原根块格式的静态证据；与后门混淆同式）
        const MAGIC_X: [u8; 4] = [0x56 ^ 0x5A, 0x4D ^ 0x5A, 0x42 ^ 0x5A, 0x31 ^ 0x5A];
        if h[0..4] != MAGIC_X {
            return Err("E-57".to_string());
        }
        let fmt_ver = le16(&h[4..6]);
        let isa_ver = le16(&h[6..8]);
        let pm_ver = le16(&h[8..10]);
        let op_count = le16(&h[10..12]);
        let cs = le32(&h[12..16]);
        let nchunks = le32(&h[16..20]);
        let nmeta = le32(&h[20..24]);
        let nslots = le16(&h[24..26]);
        let align = h[28];
        let flags = h[29];
        let reserved = le16(&h[30..32]);
        if fmt_ver != 2 && fmt_ver != 3 {
            // v3 = PSIV 块级 AEAD（槽 = ct+tag 16B）；v2 = 裸 ChaCha20（双版本并存）
            return Err("E-58".to_string());
        }
        if isa_ver != 6 || pm_ver != 1 {
            // isa_ver 与 vm_isa.ISA_VER 同源（v6：+HSTEP，早期轮次 链步进原生化）
            return Err("E-59".to_string());
        }
        if op_count != N_LOGICAL {
            return Err("E-60".to_string());
        }
        if reserved != 0 {
            return Err("E-61".to_string());
        }
        if align != 1 {
            return Err("E-62".to_string());
        }
        if nslots != RESIDENT_SLOTS {
            // 驻留槽数是设计常量（双端各自校验，不接受自报的其他值）
            return Err("E-63".to_string());
        }
        if cs == 0 || cs > MAX_CHUNK || nchunks == 0 {
            return Err("E-64".to_string());
        }
        if nmeta > nchunks {
            return Err("E-65".to_string());
        }
        let ct = &blob[HEADER_LEN..];
        let aead = fmt_ver == 3;
        let slot_overhead = if aead { 16usize } else { 0 };
        if ct.len() != nchunks * (cs + slot_overhead) {
            return Err("E-66".to_string());
        }
        let root = super::machita_chima(container_key, L_VM_ROOT, 32);
        // 早期轮次：逐格链剖面。三条流都由 root 现算（root 本身 = HKDF(容器密钥, i3)，
        // 容器密钥含 seed），所以**没有一条常量进过 blob、也没有一条常量躺在镜像里**；
        // 长度与域标签必须与 vm_isa.kaburaki_roco 逐字相同（双端 source-literal 齿 +
        // 剖面 KAT 双重钉住，见 tests/d_side/test_vm_gates.py / test_native_vm.py）。
        let mut cfg_b = [0u8; CHAIN_CFG_LEN];
        cfg_b.copy_from_slice(&super::machita_chima(&root, L_CHAIN_CFG, CHAIN_CFG_LEN));
        let mut ks_b = [0u8; CHAIN_K_LEN];
        ks_b.copy_from_slice(&super::machita_chima(&root, L_CHAIN_K, CHAIN_K_LEN));
        let mut mk_b = [0u8; CHAIN_K_LEN];
        mk_b.copy_from_slice(&super::machita_chima(&root, L_CHAIN_MASK, CHAIN_K_LEN));
        let chain = ops::Chain { cfg: cfg_b, ks: ks_b, mask: mk_b };
        // 早期轮次 （定长吸收）：窗补齐到上限，补齐字节逐格（root 的函数）——载荷因此
        // 恒跑同样多的轮数， 实测的长度侧信道（空 argv 191 次迭代 vs "hello" 63,743 次）
        // 连同"逐字节消化的字节数就是长度"这条结构事实一起关掉。
        let pad = super::machita_chima(&root, L_CHAIN_PAD, 1)[0];
        let argv_pad = vec![pad; ap - argv_win.len()];
        let stdin_pad = vec![pad; sp - stdin_win.len()];
        let argv_win: Vec<u8> = [argv_win, &argv_pad].concat();
        let stdin_win: Vec<u8> = [stdin_win, &stdin_pad].concat();        let mut chunk_key = [0u8; 32];
        chunk_key.copy_from_slice(&super::machita_chima(&root, L_CHUNK_KEY, 32));
        let mut mac_key = [0u8; 32];
        mac_key.copy_from_slice(&super::machita_chima(&root, L_STREAM_MAC, 32));
        // MAC 先于任何解密（与容器层同一拒绝顺序）。（安全审计）：输入 =
        // 头(32B) ‖ ct——旧实现只盖 ct，头部可一致性篡改（如清 perm 位关置换）

        let mut mac_input = Vec::with_capacity(HEADER_LEN + ct.len());
        mac_input.extend_from_slice(&blob[..32]);
        mac_input.extend_from_slice(ct);
        if super::blake2s::sister_claire(&mac_key, &mac_input)[..] != blob[32..HEADER_LEN][..] {
            return Err("E-67".to_string());
        }
        let place = if flags & FLAG_PERM != 0 {
            chunk_place(&root, nchunks)
        } else {
            (0..nchunks).collect()
        };

        let mut reader = MetaReader::new();
        for i in 0..nmeta {
            let plain = decrypt_slot(ct, &place, cs, aead, &chunk_key, &root, i)?;
            reader.push(&plain);
        }
        let funcs = reader.read_funcs()?;
        let nfuncs = funcs.len();
        let globals = reader.read_globals(nfuncs, argv_win.len(), stdin_win.len())?;
        let strings = reader.read_strings()?;
        let entry_fid = reader.read_u16()?;
        let ir_used = reader.read_used()?;
        reader.wipe();
        if entry_fid >= funcs.len() {
            return Err("E-68".to_string());
        }
        if nmeta + ir_used.len() != nchunks {
            return Err("E-69".to_string());
        }
        // （安全审计）：取指判据是 off < used——used 越过 chunk_size 会让
        // 取指进入 PRF 填充区，"取指不进填充区"的结构保证被一条元数据关闭

        for &u in ir_used.iter() {
            if u > cs {
                return Err("E-70".to_string());
            }
        }
        for (start, _nregs) in funcs.iter() {
            if *start >= ir_used.len() * cs {
                return Err("E-71".to_string());
            }
        }

        let mut inv = [0xFFusize; OPSPACE];
        let mut seen = [false; OPSPACE];
        // 早期轮次 步骤 3：物理映射表由 boot 侧算好后递进来（`physmap(&seed32)` 的
        // N_LOGICAL 项"逻辑号→物理字节"表），递完 seed 立刻覆零——VM 执行期不再
        // 有任何 seed 在场拷贝。表形不对沿用同一枚桶码（都是"physmap 表不可用"，
        // 不新增可见行为）
        if isa_physmap.len() != N_LOGICAL {
            return Err("E-72".to_string());
        }
        for (li, &byte) in isa_physmap.iter().enumerate() {
            if seen[byte as usize] {
                return Err("E-72".to_string());
            }
            seen[byte as usize] = true;
            inv[byte as usize] = li;
        }
        let (dtab, dslot) = build_dispatch(&root);
        Ok(Vm {
            chunk_size: cs, nmeta, nslots, root, chunk_key, ct: ct.to_vec(), place, aead,
            funcs, ir_used, globals, strings, entry: entry_fid,
            argv_win, stdin_win, chain,
            slots: [Slot::empty(), Slot::empty()], rr: 0, inv, out: Vec::new(),
            dtab, dslot,
        })
    }

    /// 执行到载荷自然结束（顶层 RET 或 HALT）。返回写入 stdout 的字节。
    /// `hold_at`：可见量探针齿——在第 N 步暂停，供**另一个进程**抓取"峰值时刻"的内存。
    /// 不设暂停点时抓不到明文：`run_blob` 返回即 drop，槽页已被覆零释放（实测过这一点，
    /// 对安全性是好事，但判据必须量在执行中途）。
    pub fn run(&mut self, hold_at: Option<usize>) -> Result<Vec<u8>, String> {
        let (start0, nregs0) = *self.funcs.get(self.entry)
            .ok_or_else(|| "E-73".to_string())?;
        let mut frames = vec![Frame { pc: start0, regs: vec![Val::N; nregs0], ret_dst: None }];
        let mut steps = 0usize;
        let mut ob = [0u8; MAX_OP];
        while !frames.is_empty() {
            steps += 1;
            if steps > STEP_BUDGET {
                return Err("E-74".to_string());
            }
            if hold_at == Some(steps) {
                super::visprobe::hold("m2");
            }
            let depth = frames.len() - 1;
            let pc = frames[depth].pc;
            self.fetch_into(pc, 1, &mut ob)?;
            let li = self.inv[ob[0] as usize];
            if li == 0xFF {
                // （安全审计）：拒绝串剥离 pc/chunk/off/used 等内部状态数字
                // ——它们对持密者是冗余、对外部读内存者是位置/长度差分 oracle

                return Err("E-75".to_string());
            }
            let w = OP_WIDTHS[li];
            let mut raw = [0u8; MAX_OP];
            self.fetch_into(pc + 1, w, &mut raw)?;
            let nxt = self.advance(pc + 1 + w)?;
            let mut st = Step { li, ops: raw, nxt, depth, jumped: false,
                                halt: false, new_frame: None };
            // 批2-2.2：分派走**启动期建好的间接调用表**——静态 .rdata 跳表曾是
            // 既有审计"读跳表定位 dispatcher"的第一落点（指纹 0x372b0）。表内容与
            // 槽位顺序由 root（= HKDF(容器密钥, i3)，容器密钥含 seed）派生的逐格
            // 置换决定，只在堆上存在；`mutate=False` 的消融档退化为恒等置换
            // （语义逐位不变，只关漂移）。
            // 表元素是 fn 指针，取指/验界/写回全在表外，handler 只搬语义。
            let h = self.dtab[self.dslot[li] as usize];
            h(self, &mut frames, &mut st)?;
            if st.halt {
                break;
            }
            if let Some(fr) = st.new_frame.take() {
                frames.push(fr);
                continue;
            }
            if !st.jumped {
                // 与拆分前同一条判据：`!jumped && li != OP_RET` 里"RET 不自管 pc"
                // 改由 g_ret 显式置 jumped=true 表达，条件本身不再看 li
                frames[depth].pc = nxt;
            }
        }
        Ok(std::mem::take(&mut self.out))
    }

    /// HALT 组（原 `OP_HALT => break`）。
    fn g_halt(&mut self, _frames: &mut Vec<Frame>, st: &mut Step) -> Result<(), String> {
        let _ = &mut self.out;
        st.halt = true;
        Ok(())
    }

    /// 算术/比较/装载组：LOADK、MOVE、ADD/SUB/MUL/FLOORDIV、XOR/ROTL32、HSTEP、LT/EQ。
    /// 每组都是"取出 frames → 原样跑该组的操作码臂 → 写回"，臂体与拆分前**逐字相同**
    /// （只有 jumped/new_frame/halt 三个输出改走 Step），这是这轮重构唯一的改动面。
    fn g_arith(&mut self, frames_out: &mut Vec<Frame>, st: &mut Step) -> Result<(), String> {
        let mut frames = std::mem::take(frames_out);
        let ops: &[u8] = &st.ops;
        let depth = st.depth;
        let li = st.li;
        let nxt = st.nxt;
        let _ = nxt;
        let mut jumped = false;
        let mut new_frame: Option<Frame> = None;
        match li {
                OP_LOADK => {
                    // 16 位补码立即数的符号扩展：三条互等价实现按格子选
                    let imm = hot_call!(crate::pins::V_LOADK, ops::loadk_0,
                                        ops::loadk_1, ops::loadk_2;
                                        u16::from_le_bytes([ops[1], ops[2]]));
                    genzuki_tojiro(&mut frames, depth, ops[0] as usize, Val::I(imm))?;
                }
                OP_MOVE => {
                    // 搬运类：边界判定走选定变体（src 先、dst 后——与拆分前同序，
                    // E-47/E-48 各归各位），读写仍走的两个唯一出口
                    let len = hot_len(&frames, depth);
                    let src = hot_gate!(crate::pins::V_MOVE, ops::move_gate_0,
                                        ops::move_gate_1, ops::move_gate_2;
                                        ops[1] as usize, len, "E-47");
                    let v = melissa_kinrenka(&frames, depth, src)?.clone();
                    let dst = hot_gate!(crate::pins::V_MOVE, ops::move_gate_0,
                                        ops::move_gate_1, ops::move_gate_2;
                                        ops[0] as usize, len, "E-48");
                    genzuki_tojiro(&mut frames, depth, dst, v)?;
                }
                OP_ADD | OP_SUB | OP_MUL | OP_FLOORDIV => {
                    let a = as_int(melissa_kinrenka(&frames, depth, ops[1] as usize)?)?;
                    let b = as_int(melissa_kinrenka(&frames, depth, ops[2] as usize)?)?;
                    let v = match li {
                        OP_ADD => hot_call!(crate::pins::V_ADD, ops::add_0,
                                            ops::add_1, ops::add_2; a, b),
                        OP_SUB => a.checked_sub(b),
                        OP_FLOORDIV => {
                            if b == 0 {
                                return Err("E-76".to_string());
                            }
                            // Python floor 语义：Rust / 向零截断，负数非整除时
                            // 会静默差 1（-7//2 应为 -4 得 -3）。
                            // 全程 Option 链（checked_div 只兜 i128::MIN/-1；
                            // floor 校正项 q-1 的下溢同样走 E-77）。
                            a.checked_div(b).and_then(|q| {
                                let r = a - q * b;
                                if r != 0 && (r < 0) != (b < 0) {
                                    q.checked_sub(1)
                                } else {
                                    Some(q)
                                }
                            })
                        }
                        _ => hot_call!(crate::pins::V_MUL, ops::mul_0,
                                      ops::mul_1, ops::mul_2; a, b),
                    };
                    let value = Val::I(v.ok_or_else(|| "E-77".to_string())?);
                    genzuki_tojiro(&mut frames, depth, ops[0] as usize, value)?;
                }
                OP_XOR => {
                    // 早期轮次：XOR 入池。此前它是单实现——"链被保护、这两码反汇编一次
                    // 全格复用"正是之后最直接的摊销路径。值域判据不变（非负整数，
                    // 越域走 E-116），只把"怎么算"换成选定变体。
                    let a = as_int(melissa_kinrenka(&frames, depth, ops[1] as usize)?)?;
                    let b = as_int(melissa_kinrenka(&frames, depth, ops[2] as usize)?)?;
                    if a < 0 || b < 0 {
                        return Err("E-116".to_string());
                    }
                    let v = hot_call!(crate::pins::V_XOR, ops::xor_0,
                                      ops::xor_1, ops::xor_2; a, b);
                    genzuki_tojiro(&mut frames, depth, ops[0] as usize, Val::I(v))?;
                }
                OP_ROTL32 => {
                    // 同上（扩池）。a 取低 32 位、k 取 mod 32，结果恒 < 2^32；
                    // k=0 时三条实现都落"不移位"（Python 端 `j >> 32` 天然是 0，同值）
                    let a = as_int(melissa_kinrenka(&frames, depth, ops[1] as usize)?)?;
                    let b = as_int(melissa_kinrenka(&frames, depth, ops[2] as usize)?)?;
                    if a < 0 || b < 0 {
                        return Err("E-116".to_string());
                    }
                    let v = hot_call!(crate::pins::V_ROTL32, ops::rotl32_0,
                                      ops::rotl32_1, ops::rotl32_2; a, b);
                    genzuki_tojiro(&mut frames, depth, ops[0] as usize, Val::I(v))?;
                }
                OP_HSTEP => {
                    // 早期轮次：链步进整条离开字节码。状态与消息都先收进 32 位域，
                    // 步进形状与常量取自本格剖面（self.chain，建 VM 时由 root 现算）。
                    // 值域判据与 XOR/ROTL32 同族：非整型/字符串由 as_int 落 E-42，
                    // 负数落 E-116——都沿既有静默通道，不新增可见行为类。
                    let a = as_int(melissa_kinrenka(&frames, depth, ops[1] as usize)?)?;
                    let b = as_int(melissa_kinrenka(&frames, depth, ops[2] as usize)?)?;
                    if a < 0 || b < 0 {
                        return Err("E-116".to_string());
                    }
                    let st = (a % U32_RANGE) as u32;
                    let msg = (b % U32_RANGE) as u32;
                    let v = hot_call!(crate::pins::V_HSTEP, ops::hstep_0,
                                      ops::hstep_1, ops::hstep_2; &self.chain, st, msg);
                    genzuki_tojiro(&mut frames, depth, ops[0] as usize, Val::I(v as i128))?;
                }
                OP_LT | OP_EQ => {
                    let a = melissa_kinrenka(&frames, depth, ops[1] as usize)?.clone();
                    let b = melissa_kinrenka(&frames, depth, ops[2] as usize)?.clone();
                    if li == OP_LT {
                        // LT 不给字符串（与 Python 端同拒）：str 上 < 不是本子集语义
                        let (a, b) = (as_int(&a)?, as_int(&b)?);
                        // 有符号小于：三条互等价判据按格子选（同号退化无符号 /
                        // 符号分路 / 保序异或映射）
                        let less = hot_call!(crate::pins::V_LT, ops::lt_0,
                                             ops::lt_1, ops::lt_2; a, b);
                        genzuki_tojiro(&mut frames, depth, ops[0] as usize,
                                       Val::B(less))?;
                    } else {
                        // EQ：结构等价（S/S 比字节、N/N 为真、T/T 递归逐元素——
                        // W 深查中危项修复：此前 T 落 as_int 拒，与 Python 权威端
                        // 的元组 == 分叉；其余按 int 强转）
                        let eq = eq_val(&a, &b);
                        genzuki_tojiro(&mut frames, depth, ops[0] as usize, Val::B(eq))?;
                    }
                }
                // 组内兜底：注册表若与本组臂集不一致（漏登记/多登记），必须落
                // fail-closed 的 E-98，绝不静默什么也不做
                _ => return Err("E-98".to_string()),
        }
        st.jumped = jumped;
        st.new_frame = new_frame.take();
        *frames_out = frames;
        Ok(())
    }

    /// 控制流组：JMP、JZ、JN（三条都自管 pc ⇒ jumped=true）。
    fn g_jump(&mut self, frames_out: &mut Vec<Frame>, st: &mut Step) -> Result<(), String> {
        let mut frames = std::mem::take(frames_out);
        let ops: &[u8] = &st.ops;
        let depth = st.depth;
        let li = st.li;
        let nxt = st.nxt;
        let mut jumped = false;
        let mut new_frame: Option<Frame> = None;
        match li {
                OP_JMP => {
                    frames[depth].pc = u16::from_le_bytes([ops[0], ops[1]]) as usize;
                    jumped = true;
                }
                OP_JZ => {
                    let t = u16::from_le_bytes([ops[1], ops[2]]) as usize;
                    let falsy = !truthy(melissa_kinrenka(&frames, depth, ops[0] as usize)?);
                    frames[depth].pc = if falsy { t } else { nxt };
                    jumped = true;
                }
                OP_JN => {
                    let t = u16::from_le_bytes([ops[1], ops[2]]) as usize;
                    let is_none = matches!(
                        melissa_kinrenka(&frames, depth, ops[0] as usize)?, Val::N);
                    frames[depth].pc = if is_none { t } else { nxt };
                    jumped = true;
                }
                // 组内兜底：注册表若与本组臂集不一致（漏登记/多登记），必须落
                // fail-closed 的 E-98，绝不静默什么也不做
                _ => return Err("E-98".to_string()),
        }
        st.jumped = jumped;
        st.new_frame = new_frame.take();
        *frames_out = frames;
        Ok(())
    }

    /// 迭代子组：ITERNEW、ITERNEXT（写序纪律原样保留：先迭代子后目标值）。
    fn g_iter(&mut self, frames_out: &mut Vec<Frame>, st: &mut Step) -> Result<(), String> {
        let mut frames = std::mem::take(frames_out);
        let ops: &[u8] = &st.ops;
        let depth = st.depth;
        let li = st.li;
        let nxt = st.nxt;
        let _ = nxt;
        let mut jumped = false;
        let mut new_frame: Option<Frame> = None;
        match li {
                OP_ITERNEW => {
                    let n = as_int(melissa_kinrenka(&frames, depth, ops[1] as usize)?)?;
                    genzuki_tojiro(&mut frames, depth, ops[0] as usize,
                                   Val::It { next: 1, end: n })?;
                }
                OP_ITERNEXT => {
                    let it = melissa_kinrenka(&frames, depth, ops[1] as usize)?.clone();
                    match it {
                        Val::It { next, end } => {
                            // 写序与 Python 端一致（先迭代子后目标值）：ops[0]==ops[1]
                            // 时后写覆盖前写，两侧必须同序
                            if next <= end {
                                genzuki_tojiro(&mut frames, depth, ops[1] as usize,
                                               Val::It { next: next + 1, end })?;
                                genzuki_tojiro(&mut frames, depth, ops[0] as usize,
                                               Val::I(next))?;
                            } else {
                                genzuki_tojiro(&mut frames, depth, ops[1] as usize, Val::N)?;
                                genzuki_tojiro(&mut frames, depth, ops[0] as usize, Val::N)?;
                            }
                        }
                        _ => return Err("E-78".to_string()),
                    }
                }
                // 组内兜底：注册表若与本组臂集不一致（漏登记/多登记），必须落
                // fail-closed 的 E-98，绝不静默什么也不做
                _ => return Err("E-98".to_string()),
        }
        st.jumped = jumped;
        st.new_frame = new_frame.take();
        *frames_out = frames;
        Ok(())
    }

    /// 常量/字符串装载组：LOADN、LOADS、CONCAT、LOADB。
    fn g_ldstr(&mut self, frames_out: &mut Vec<Frame>, st: &mut Step) -> Result<(), String> {
        let mut frames = std::mem::take(frames_out);
        let ops: &[u8] = &st.ops;
        let depth = st.depth;
        let li = st.li;
        let nxt = st.nxt;
        let _ = nxt;
        let mut jumped = false;
        let mut new_frame: Option<Frame> = None;
        match li {
                OP_LOADN => {
                    let dst = hot_gate!(crate::pins::V_LOADN, ops::loadn_gate_0,
                                        ops::loadn_gate_1, ops::loadn_gate_2;
                                        ops[0] as usize, hot_len(&frames, depth), "E-48");
                    genzuki_tojiro(&mut frames, depth, dst, Val::N)?
                }
                OP_LOADS => {
                    // 满 u16 池索引（探针 Rust 侧只取低字节，>256 条即双端分叉——已修）
                    let sidx = u16::from_le_bytes([ops[1], ops[2]]) as usize;
                    let plain = self.strings.get(sidx)
                        .ok_or_else(|| "E-79".to_string())?.clone();
                    genzuki_tojiro(&mut frames, depth, ops[0] as usize, Val::S(plain))?;
                }
                OP_CONCAT => {
                    let a = melissa_kinrenka(&frames, depth, ops[1] as usize)?.clone();
                    let b = melissa_kinrenka(&frames, depth, ops[2] as usize)?.clone();
                    match (a, b) {
                        (Val::S(mut x), Val::S(y)) => {
                            x.extend_from_slice(&y);
                            genzuki_tojiro(&mut frames, depth, ops[0] as usize, Val::S(x))?;
                        }
                        _ => return Err("E-80".to_string()),
                    }
                }
                OP_LOADB => {
                    if ops[1] > 1 {
                        return Err("E-81".to_string());
                    }
                    genzuki_tojiro(&mut frames, depth, ops[0] as usize, Val::B(ops[1] == 1))?;
                }
                // 组内兜底：注册表若与本组臂集不一致（漏登记/多登记），必须落
                // fail-closed 的 E-98，绝不静默什么也不做
                _ => return Err("E-98".to_string()),
        }
        st.jumped = jumped;
        st.new_frame = new_frame.take();
        *frames_out = frames;
        Ok(())
    }

    /// 索引/取元素组：TUPLE、GETITEM、ARGV、STDIN。
    fn g_index(&mut self, frames_out: &mut Vec<Frame>, st: &mut Step) -> Result<(), String> {
        let mut frames = std::mem::take(frames_out);
        let ops: &[u8] = &st.ops;
        let depth = st.depth;
        let li = st.li;
        let nxt = st.nxt;
        let _ = nxt;
        let mut jumped = false;
        let mut new_frame: Option<Frame> = None;
        match li {
                OP_TUPLE => {
                    let base = ops[1] as usize;
                    let n = ops[2] as usize;
                    let cur_len = frames.get(depth).map(|f| f.regs.len()).unwrap_or(0);
                    if base + n > cur_len {
                        return Err("E-82".to_string());
                    }
                    let elems: Vec<Val> = frames[depth].regs[base..base + n].to_vec();
                    genzuki_tojiro(&mut frames, depth, ops[0] as usize, Val::T(elems))?;
                }
                OP_GETITEM => {
                    let tup = melissa_kinrenka(&frames, depth, ops[1] as usize)?.clone();
                    let idx_v = melissa_kinrenka(&frames, depth, ops[2] as usize)?.clone();
                    match tup {
                        Val::T(t) => {
                            let i = as_int(&idx_v)?;
                            if i < 0 || i as usize >= t.len() {
                                return Err("E-83".to_string());
                            }
                            let picked = t[i as usize].clone();
                            genzuki_tojiro(&mut frames, depth, ops[0] as usize, picked)?;
                        }
                        _ => return Err("E-84".to_string()),
                    }
                }
                OP_ARGV | OP_STDIN => {
                    // 早期轮次 输入原语：下标来自寄存器、结果是一个字节值（0..255）。
                    // 越界/非整型下标 = VM 故障 → 桶码 → 静默 exit 3，与 vm_interp 的
                    // SaayaYamabuki 同一条判据（双端互钉）。
                    let idx_v = melissa_kinrenka(&frames, depth, ops[1] as usize)?.clone();
                    let j = as_int(&idx_v)?;
                    let win: &[u8] = if li == OP_ARGV {
                        &self.argv_win
                    } else {
                        &self.stdin_win
                    };
                    if j < 0 || j as usize >= win.len() {
                        return Err("E-111".to_string());
                    }
                    let picked = Val::I(win[j as usize] as i128);
                    genzuki_tojiro(&mut frames, depth, ops[0] as usize, picked)?;
                }
                // 组内兜底：注册表若与本组臂集不一致（漏登记/多登记），必须落
                // fail-closed 的 E-98，绝不静默什么也不做
                _ => return Err("E-98".to_string()),
        }
        st.jumped = jumped;
        st.new_frame = new_frame.take();
        *frames_out = frames;
        Ok(())
    }

    /// 全局表/函数号组：LOADG、STOREG、MAKEFUNC。
    fn g_global(&mut self, frames_out: &mut Vec<Frame>, st: &mut Step) -> Result<(), String> {
        let mut frames = std::mem::take(frames_out);
        let ops: &[u8] = &st.ops;
        let depth = st.depth;
        let li = st.li;
        let nxt = st.nxt;
        let _ = nxt;
        let mut jumped = false;
        let mut new_frame: Option<Frame> = None;
        match li {
                OP_LOADG => {
                    // 全局表下标先过选定闸门（E-85），目标寄存器仍走写出口（E-48）
                    let gi = hot_gate!(crate::pins::V_LOADG, ops::loadg_gate_0,
                                       ops::loadg_gate_1, ops::loadg_gate_2;
                                       ops[1] as usize, self.globals.len(), "E-85");
                    let g = self.globals.get(gi)
                        .ok_or_else(|| "E-85".to_string())?.clone();
                    genzuki_tojiro(&mut frames, depth, ops[0] as usize, g)?;
                }
                OP_STOREG => {
                    // 语义端：ops[0]=全局槽号，ops[1]=源寄存器（与 ref_interp 同式）
                    // 判定顺序 = 源寄存器（E-47）先、全局槽（E-86）后——与拆分前一致
                    let src = hot_gate!(crate::pins::V_STOREG, ops::storeg_gate_0,
                                        ops::storeg_gate_1, ops::storeg_gate_2;
                                        ops[1] as usize, hot_len(&frames, depth), "E-47");
                    let v = melissa_kinrenka(&frames, depth, src)?.clone();
                    let gi = hot_gate!(crate::pins::V_STOREG, ops::storeg_gate_0,
                                       ops::storeg_gate_1, ops::storeg_gate_2;
                                       ops[0] as usize, self.globals.len(), "E-86");
                    let cell = self.globals.get_mut(gi)
                        .ok_or_else(|| "E-86".to_string())?;
                    *cell = v;
                }
                OP_MAKEFUNC => {
                    let fid = ops[1] as usize;
                    if self.funcs.get(fid).is_none() {
                        return Err("E-87".to_string());
                    }
                    genzuki_tojiro(&mut frames, depth, ops[0] as usize, Val::Func(fid))?;
                }
                // 组内兜底：注册表若与本组臂集不一致（漏登记/多登记），必须落
                // fail-closed 的 E-98，绝不静默什么也不做
                _ => return Err("E-98".to_string()),
        }
        st.jumped = jumped;
        st.new_frame = new_frame.take();
        *frames_out = frames;
        Ok(())
    }

    /// 调用组：CALL、CALLV（含三个 Native 内建：print/range/len）。
    fn g_call(&mut self, frames_out: &mut Vec<Frame>, st: &mut Step) -> Result<(), String> {
        let mut frames = std::mem::take(frames_out);
        let ops: &[u8] = &st.ops;
        let depth = st.depth;
        let li = st.li;
        let nxt = st.nxt;
        let mut jumped = false;
        let mut new_frame: Option<Frame> = None;
        match li {
                OP_CALL | OP_CALLV => {
                    let dst = ops[0] as usize;
                    let base = ops[2] as usize;
                    let argc = ops[3] as usize;
                    //参数窗在译码点验界（与 vm_interp 的 CALL/CALLV 窗检同式）。
                    // 旧写法只有逐次 `.get(base+i)`——挡得住源越界，挡不住目标帧
                    // `newr[i]`／`regs[dst]` 越界
                    let cur_len = frames.get(depth).map(|f| f.regs.len()).unwrap_or(0);
                    if base > cur_len || argc > cur_len - base {
                        return Err("E-88".to_string());
                    }
                    let callee = if li == OP_CALL {
                        let fid = ops[1] as usize;
                        if self.funcs.get(fid).is_none() {
                            return Err("E-89".to_string());
                        }
                        Val::Func(fid)
                    } else {
                        melissa_kinrenka(&frames, depth, ops[1] as usize)?.clone()
                    };
                    match callee {
                        Val::Func(fid) => {
                            let (fstart, fnregs) = *self.funcs.get(fid)
                                .ok_or_else(|| "E-90".to_string())?;
                            if argc > fnregs {
                                return Err("E-91".to_string());
                            }
                            let mut newr = vec![Val::N; fnregs];
                            for i in 0..argc {
                                newr[i] = melissa_kinrenka(&frames, depth, base + i)?.clone();
                            }
                            frames[depth].pc = nxt; // 返回地址先落盘（坑一）
                            new_frame = Some(Frame { pc: fstart, regs: newr, ret_dst: Some(dst) });
                        }
                        Val::Native(0) => {
                            // print(*args)：CPython 语义——str(args) 空格连接 + 换行
                            let mut line: Vec<u8> = Vec::new();
                            for i in 0..argc {
                                if i > 0 {
                                    line.push(b' ');
                                }
                                let v = melissa_kinrenka(&frames, depth, base + i)?.clone();
                                line.extend_from_slice(&text(&v)?);
                            }
                            self.out.extend_from_slice(&line);
                            self.out.push(b'\n');
                            genzuki_tojiro(&mut frames, depth, dst, Val::N)?;
                        }
                        Val::Native(1) => {
                            if argc != 1 {
                                return Err("E-92".to_string());
                            }
                            let v = melissa_kinrenka(&frames, depth, base)?.clone();
                            let n = as_int(&v)?;
                            // W 深查：i128::MIN 经 n-1 会回绕成 i128::MAX（release
                            // 下静默）——与 Python 空 range 语义并轨
                            let end = n.checked_sub(1).ok_or_else(|| "E-77".to_string())?;
                            genzuki_tojiro(&mut frames, depth, dst, Val::It { next: 0, end })?;
                        }
                        Val::Native(2) => {
                            // len(t)：仅元组（与 Python 端同拒非元组）
                            if argc != 1 {
                                return Err("E-93".to_string());
                            }
                            let v = melissa_kinrenka(&frames, depth, base)?.clone();
                            let n = match v {
                                Val::T(t) => t.len() as i128,
                                _ => return Err("E-94".to_string()),
                            };
                            genzuki_tojiro(&mut frames, depth, dst, Val::I(n))?;
                        }
                        _ => return Err("E-95".to_string()),
                    }
                }
                // 组内兜底：注册表若与本组臂集不一致（漏登记/多登记），必须落
                // fail-closed 的 E-98，绝不静默什么也不做
                _ => return Err("E-98".to_string()),
        }
        st.jumped = jumped;
        st.new_frame = new_frame.take();
        *frames_out = frames;
        Ok(())
    }

    /// 输出组：PRINT。
    fn g_print(&mut self, frames_out: &mut Vec<Frame>, st: &mut Step) -> Result<(), String> {
        let mut frames = std::mem::take(frames_out);
        let ops: &[u8] = &st.ops;
        let depth = st.depth;
        let li = st.li;
        let nxt = st.nxt;
        let _ = nxt;
        let mut jumped = false;
        let mut new_frame: Option<Frame> = None;
        match li {
                OP_PRINT => {
                    let v = melissa_kinrenka(&frames, depth, ops[0] as usize)?.clone();
                    let s = text(&v)?;
                    self.out.extend_from_slice(&s);
                    self.out.push(b'\n');
                }
                // 组内兜底：注册表若与本组臂集不一致（漏登记/多登记），必须落
                // fail-closed 的 E-98，绝不静默什么也不做
                _ => return Err("E-98".to_string()),
        }
        st.jumped = jumped;
        st.new_frame = new_frame.take();
        *frames_out = frames;
        Ok(())
    }

    /// 返回组：RET。
    fn g_ret(&mut self, frames_out: &mut Vec<Frame>, st: &mut Step) -> Result<(), String> {
        let mut frames = std::mem::take(frames_out);
        let ops: &[u8] = &st.ops;
        let depth = st.depth;
        let li = st.li;
        let nxt = st.nxt;
        let _ = nxt;
        let _ = depth;
        let mut jumped = false;
        let mut new_frame: Option<Frame> = None;
        match li {
                OP_RET => {
                    let done = frames.pop().ok_or_else(|| "E-96".to_string())?;
                    let v = done.regs.get(ops[0] as usize)
                        .ok_or_else(|| "E-97".to_string())?.clone();
                    if frames.is_empty() {
                        *frames_out = frames;
                        st.halt = true;
                        return Ok(());
                    }
                    if let Some(dst) = done.ret_dst {
                        let last = frames.len() - 1;
                        genzuki_tojiro(&mut frames, last, dst, v)?;
                    }
                    // 拆分前主循环用 `!jumped && li != OP_RET` 排除 RET 的 pc 回写；
                    // 分派成 handler 后"主循环不该再写 pc"是 RET 自己的事，故显式置位
                    // （语义逐位不变：RET 之后 pc 由被弹出的父帧与 ret_dst 决定）
                    jumped = true;
                }
                // 不带内部编号（：编号本身就是布局 oracle）
                _ => return Err("E-98".to_string()),
        }
        st.jumped = jumped;
        st.new_frame = new_frame.take();
        *frames_out = frames;
        Ok(())
    }

    /// 未注册槽位的兜底：与"未知操作码/未覆盖臂"共用 E-98 这一条 fail-closed 通道，
    /// 不新增桶码（融合档里未启用的 SU 号也落这里）。
    fn g_unmapped(&mut self, _frames: &mut Vec<Frame>, _st: &mut Step) -> Result<(), String> {
        Err("E-98".to_string())
    }

    /// 别名表（逻辑号 → 组 handler）。**顺序 push，绝不写成 match**——match 会被
    /// 编译成 .rdata 静态跳表，而那正是 既有审计定位 dispatcher 的第一落点。
    fn registered() -> Vec<(usize, Handler)> {
        let mut reg: Vec<(usize, Handler)> = Vec::with_capacity(N_LOGICAL);
        reg.push((OP_HALT, Vm::g_halt));
        for li in [OP_LOADK, OP_MOVE, OP_ADD, OP_SUB, OP_MUL, OP_FLOORDIV,
                   OP_LT, OP_EQ, OP_XOR, OP_ROTL32, OP_HSTEP].iter() {
            reg.push((*li, Vm::g_arith));
        }
        for li in [OP_JMP, OP_JZ, OP_JN].iter() {
            reg.push((*li, Vm::g_jump));
        }
        for li in [OP_ITERNEW, OP_ITERNEXT].iter() {
            reg.push((*li, Vm::g_iter));
        }
        for li in [OP_LOADN, OP_LOADS, OP_CONCAT, OP_LOADB].iter() {
            reg.push((*li, Vm::g_ldstr));
        }
        for li in [OP_TUPLE, OP_GETITEM, OP_ARGV, OP_STDIN].iter() {
            reg.push((*li, Vm::g_index));
        }
        for li in [OP_LOADG, OP_STOREG, OP_MAKEFUNC].iter() {
            reg.push((*li, Vm::g_global));
        }
        reg.push((OP_CALL, Vm::g_call));
        reg.push((OP_CALLV, Vm::g_call));
        reg.push((OP_PRINT, Vm::g_print));
        reg.push((OP_RET, Vm::g_ret));
        reg
    }
}

// ---------- 批2-2.2：启动期建表 ----------
/// 槽位置换的 HKDF 域标签（续中性短码序列；与 root 同一条密钥层级）。
const L_DPERM: &[u8] = b"i15";

/// 逐格槽位置换（Fisher-Yates，游标纪律与 `physmap` 逐字一致）。
/// `MUTATE=false` 的消融档退化为恒等：表仍在、handler 仍是这些 handler，
/// 只是"逻辑号落在哪个槽"不再随格子漂移——这样消融矩阵量到的差异
/// 就只归因于变异层本身，不掺进"有没有间接调用"这一维。
fn dslot_perm(root: &[u8], n: usize) -> Vec<u8> {
    if !crate::pins::MUTATE {
        return (0..n).map(|x| x as u8).collect();
    }
    let stream = super::machita_chima(root, L_DPERM, n * 3 + 8);
    let mut order: Vec<u8> = (0..n).map(|x| x as u8).collect();
    let mut j = 0usize;
    for i in (1..n).rev() {
        j = (stream[j] as usize) % (i + 1);
        order.swap(i, j);
        j += 1;
        if j >= stream.len() {
            j = 0;
        }
    }
    order
}

/// 建表：`tab[dslot[li]] = handler_of(li)`。表内容只在堆上，静态数据里没有；
/// 未注册的槽（融合档的空白 SU 号等）落 g_unmapped ⇒ E-98 fail-closed。
fn build_dispatch(root: &[u8]) -> (Vec<Handler>, Vec<u8>) {
    let n = N_LOGICAL;
    let slot = dslot_perm(root, n);
    let mut tab = vec![Vm::g_unmapped as Handler; n];
    for (li, h) in Vm::registered().into_iter() {
        tab[slot[li] as usize] = h;
    }
    (tab, slot)
}

/// 元数据读取游标：逐块喂进明文缓冲、按需解析。解析完成后整体 `buf` 随游标一起丢弃。
struct MetaReader {
    buf: Vec<u8>,
    off: usize,
}

impl MetaReader {
    fn new() -> MetaReader {
        MetaReader { buf: Vec::new(), off: 0 }
    }

    fn push(&mut self, chunk: &[u8]) {
        self.buf.extend_from_slice(chunk);
    }

    fn take(&mut self, n: usize) -> Result<Vec<u8>, String> {
        if self.off + n > self.buf.len() {
            return Err("E-99".to_string());
        }
        let out = self.buf[self.off..self.off + n].to_vec();
        self.off += n;
        Ok(out)
    }

    fn read_u16(&mut self) -> Result<usize, String> {
        Ok(le16(&self.take(2)?))
    }

    fn read_funcs(&mut self) -> Result<Vec<(usize, usize)>, String> {
        let n = self.read_u16()?;
        if n == 0 || n > 0xFFFF {
            return Err("E-100".to_string());
        }
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            let b = self.take(6)?;
            out.push((le32(&b[0..4]), le16(&b[4..6])));
        }
        Ok(out)
    }

    fn read_globals(&mut self, nfuncs: usize, argv_len: usize,
                    stdin_len: usize) -> Result<Vec<Val>, String> {
        let n = self.read_u16()?;
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            let b = self.take(3)?;
            out.push(match b[0] {
                0 => Val::N,
                1 => {
                    let fid = le16(&b[1..3]);
                    if fid >= nfuncs {
                        return Err("E-101".to_string());
                    }
                    Val::Func(fid)
                }
                2 => {
                    // W 低危残项：Native 号是 u16，原实现只取低字节——val≥256
                    // 的 blob 双端分叉（Python 载 256，Rust 截 0 变 print）

                    let v = le16(&b[1..3]);
                    if v > 2 {
                        return Err("E-102".to_string());
                    }
                    Val::Native(v as u8)
                }
                // 早期轮次：kind 3/4 = len(argv)/len(stdin)。早期轮次之后这两枚是
                // **吸收后**的窗长（逐格常数，所以运行步数与输入长度无关）。窗是运行期输入，
                // 长度绝不作明文编译进 blob；与 vm_interp 同式。
                3 => Val::I(argv_len as i128),
                4 => Val::I(stdin_len as i128),
                _ => return Err("E-102".to_string()),
            });
        }
        Ok(out)
    }

    fn read_strings(&mut self) -> Result<Vec<Vec<u8>>, String> {
        let n = self.read_u16()?;
        let mut out = Vec::with_capacity(n.min(1024));
        for _ in 0..n {
            let slen = self.read_u16()?;
            if slen > MAX_CHUNK * 64 {
                return Err("E-103".to_string());
            }
            out.push(self.take(slen)?);
        }
        Ok(out)
    }

    fn read_used(&mut self) -> Result<Vec<usize>, String> {
        let n = self.read_u16()?;
        let mut out = Vec::with_capacity(n.min(4096));
        for _ in 0..n {
            out.push(self.read_u16()?);
        }
        Ok(out)
    }

    /// 元数据明文用完即清零（best-effort：先覆零再清空，不留整段明文在堆上）。
    fn wipe(&mut self) {
        // W 低危残项：volatile 防 DCE 把清零优化掉（与同口径，

        for b in self.buf.iter_mut() {
            unsafe { std::ptr::write_volatile(b, 0u8) };
        }
        self.buf.clear();
        self.off = 0;
    }
}

/// boot 的 v2 路径入口：blob + 容器 enc_key + 预计算的 ISA 物理映射表
/// + 两枚输入窗（早期轮次，boot 从进程 argv/stdin 填）→ 应写入 stdout 的字节。
/// `hold_at` 只在带可见量探针齿的闸门构建里给出，产品路径传 None。
pub fn run_blob(blob: &[u8], container_key: &[u8], isa_physmap: &[u8],
                argv_win: &[u8], stdin_win: &[u8],
                hold_at: Option<usize>) -> Result<Vec<u8>, String> {
    let mut vm = Vm::new(blob, container_key, isa_physmap, argv_win, stdin_win)?;
    vm.run(hold_at)
}
