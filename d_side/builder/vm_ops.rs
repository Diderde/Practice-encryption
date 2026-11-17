// Copyright (C) 2026 Diderde
// SPDX-License-Identifier: GPL-3.0-only
//! vm_ops：早期轮次 批2-2.1 的 handler 变体池 + 早期轮次 的原生链剖面——**热操作码的语义值级实现**。
//!
//! 为什么在这里而不是 vm.rs：本文件**零依赖**（只用 i128/usize/u16 与
//! `std::hint::black_box`），所以验收齿可以把三个变体**全部**编进一个几百 KB 的
//! 探针二进制，对 (操作码 × 变体 × 边界输入) 全矩阵逐位比对——产品构建里每个格子
//! 只留一条路径（未选变体被链接器剥掉），"全部变体都对"这件事只能在探针里验，
//! 这正是把"变体矩阵差分"做便宜的唯一办法（两错相消纪律的机械化：单条实现自己
//! 说了不算，三条实现 + 规范预言机三方互证）。
//!
//! 选池依据（不是拍脑袋）：`.tmp/opstats_dyn.py` 用 vm_interp 的 trace 齿把
//! 套件真实跑过的 v2 载荷（r10 fib 靶 / 混合循环 / 早期轮次 输入依赖 canonical 源）
//! 跑一遍，按**执行次数**统计：
//!   MOVE 42.8% / ADD 9.3% / LOADK 8.7% / LOADG 7.9% / JMP 4.6% / LT 4.4% /
//!   JZ 4.4% / LOADN 4.3% / STOREG 2.4% / MUL 2.0% …（top8 覆盖 86.4%）
//! 控制流三枚（JMP/JZ/JN）与 CALL/RET 不入选池——它们的全部可写实现就是
//! "改 pc / 换帧"，做成三份只会是同一件事的三种排版，没有语义差异可测；
//! 于是热池取 **算术/比较/装载/搬运** 类的前八：
//!   ADD, MUL, LT, LOADK（值级——本文件）
//!   MOVE, LOADG, LOADN, STOREG（搬运级——实现体在 vm.rs，标签与选择轴在本文件）
//!
//! 变体选择的唯一出处是构建期常量 `pins::V_<OP>`（0/1/2），由
//! `native_build.kuramochi_meruto(seed, nonce)` 现算并钉死；运行期零随机。
//! 未选变体不出现在产物里：每条实现头一行 `black_box(TAG)`，标签是 8 B 高熵
//! 立即数，验收齿直接在最终 exe 镜像里扫这 24 枚标签——**在场当且仅当被选中**。

/// 变体标签：每 (操作码, 变体) 一枚 8 B 高熵值（blake2s("r12b2-variant-tag‖op#idx")
/// 前 8 字节，构建侧与测试侧同源重算，见 native_build.KURAMICHI_TAGS）。
/// 它们不是密钥、不参与任何计算，只作为"这条实现到底有没有被链进来"的可扫证据。
/// 两枚标签在任何非目标代码里巧合出现的概率约 2^-64，实测按 24 枚全扫。
pub const TAG_ADD_0: u64 = 0x9e4b7c15_a2d3f861;
pub const TAG_ADD_1: u64 = 0x37c8e2a4_51bd9f26;
pub const TAG_ADD_2: u64 = 0xb5a1e639_4c07da8d;
pub const TAG_MUL_0: u64 = 0x1f6c3ba8_d7e04592;
pub const TAG_MUL_1: u64 = 0x8d2b70f4_6c31ae59;
pub const TAG_MUL_2: u64 = 0x4ca0d857_93b6f12e;
pub const TAG_LT_0: u64 = 0xe391a45c_78db02f6;
pub const TAG_LT_1: u64 = 0x62bd0c73_a9f4581d;
pub const TAG_LT_2: u64 = 0xf07a39c5_16e8b3d4;
pub const TAG_LOADK_0: u64 = 0x5b8e2f0c_d417a693;
pub const TAG_LOADK_1: u64 = 0xa7d346b8_29ce15f0;
pub const TAG_LOADK_2: u64 = 0x214e97da_6fb8c035;
pub const TAG_MOVE_0: u64 = 0xcd60b831_57a2e9f4;
pub const TAG_MOVE_1: u64 = 0x78f3ad26_b5904e1c;
pub const TAG_MOVE_2: u64 = 0x30c59e68_d2ab7f14;
pub const TAG_LOADG_0: u64 = 0xbc17e94a_2d635f08;
pub const TAG_LOADG_1: u64 = 0x0e4a8d63_71bfc295;
pub const TAG_LOADG_2: u64 = 0x96d2b5f0_3a7c1e68;
pub const TAG_LOADN_0: u64 = 0x44f7c3a9_81d02b5e;
pub const TAG_LOADN_1: u64 = 0xd109286b_5fe7c4a3;
pub const TAG_LOADN_2: u64 = 0x6b35d801_ac92f47e;
pub const TAG_STOREG_0: u64 = 0xf5a26c10_3d7e89b4;
pub const TAG_STOREG_1: u64 = 0x2c8b41ef_96d370a5;
pub const TAG_STOREG_2: u64 = 0xa073e6d9_5c142b8f;
// 早期轮次扩池：ISA v5 新增的 XOR/ROTL32 此前各只有一条实现——"链被保护、
// 这两码反汇编一次全格复用"是之后最直接的摊销路径，所以补齐三条互异实现；
// HSTEP作为新的热码同样入池。
pub const TAG_XOR_0: u64 = 0x0f524421_c723442a;
pub const TAG_XOR_1: u64 = 0x2373a047_491f9640;
pub const TAG_XOR_2: u64 = 0x84d0148f_f15be9a0;
pub const TAG_ROTL32_0: u64 = 0xcfb7b2e8_76bd8eed;
pub const TAG_ROTL32_1: u64 = 0x0bd5c07f_7301433b;
pub const TAG_ROTL32_2: u64 = 0x075f8e4a_62ae38b4;
pub const TAG_HSTEP_0: u64 = 0xdcd7a983_e7999449;
pub const TAG_HSTEP_1: u64 = 0xe95f9d08_37a6f0c6;
pub const TAG_HSTEP_2: u64 = 0x57f4888f_0be676fb;

// ---------------- ADD ----------------

/// v0：唯一"参考形"——Rust 自带的 checked_add（溢出即 None → 调用方出桶码 E-77）。
#[inline(never)]
pub fn add_0(a: i128, b: i128) -> Option<i128> {
    std::hint::black_box(TAG_ADD_0);
    a.checked_add(b)
}

/// v1：逐位行波进位全加器（128 轮，模 2^128 求和后按补码溢出判据拒）。
/// 判据与 checked_add 同集合：仅当两加数同号且结果异号时溢出——
/// `((a ^ r) & (b ^ r)) < 0` 是它的位形式。
#[inline(never)]
pub fn add_1(a: i128, b: i128) -> Option<i128> {
    std::hint::black_box(TAG_ADD_1);
    let x = a as u128;
    let y = b as u128;
    let mut r: u128 = 0;
    let mut c: u128 = 0;
    for i in 0..128 {
        let xb = (x >> i) & 1;
        let yb = (y >> i) & 1;
        r |= (xb ^ yb ^ c) << i;
        c = ((xb & yb) | ((xb | yb) & c)) & 1;
    }
    let rr = r as i128;
    if ((a ^ rr) & (b ^ rr)) < 0 {
        None
    } else {
        Some(rr)
    }
}

/// v2：MBA 形进位迭代 `a + b = (a ^ b) + 2*(a & b)`，直到进位为 0。
/// 与 v1 同一判据收口；移位一律 wrapping——`(x & y) << 1` 在最高位会丢，
/// 那正是模 2^128 的语义，普通 `<<` 在 debug 构建里不 panic 但口径不稳。
#[inline(never)]
pub fn add_2(a: i128, b: i128) -> Option<i128> {
    std::hint::black_box(TAG_ADD_2);
    let mut x = a as u128;
    let mut y = b as u128;
    while y != 0 {
        let carry = (x & y).wrapping_shl(1);
        x ^= y;
        y = carry;
    }
    let rr = x as i128;
    if ((a ^ rr) & (b ^ rr)) < 0 {
        None
    } else {
        Some(rr)
    }
}

// ---------------- MUL ----------------

/// v0：checked_mul 参考形。
#[inline(never)]
pub fn mul_0(a: i128, b: i128) -> Option<i128> {
    std::hint::black_box(TAG_MUL_0);
    a.checked_mul(b)
}

/// v1：符号-幅值分路 + 64位 limb 竖式（128×128→256 精确积，高位非零即拒）。
/// `|i128::MIN| = 2^127` 落在 u128 内，所以幅值取绝对值这一步本身不会溢出；
/// 收口判据：幅值必须 ≤ 2^127，且等于 2^127 时只允许积为负（即 MIN）——
/// 与 checked_mul 的失败集合逐点相同（正 2^127 溢出、负 2^127 = MIN 合法）。
#[inline(never)]
pub fn mul_1(a: i128, b: i128) -> Option<i128> {
    std::hint::black_box(TAG_MUL_1);
    let neg = (a < 0) ^ (b < 0);
    let ua = if a < 0 { (a as i128).wrapping_neg() as u128 } else { a as u128 };
    let ub = if b < 0 { (b as i128).wrapping_neg() as u128 } else { b as u128 };
    let (u0, u1) = (ua as u64, (ua >> 64) as u64);
    let (v0, v1) = (ub as u64, (ub >> 64) as u64);
    // 四个 64×64→128 部分积按 64 位列对齐相加
    let p00 = (u0 as u128) * (v0 as u128);
    let p01 = (u0 as u128) * (v1 as u128);
    let p10 = (u1 as u128) * (v0 as u128);
    let p11 = (u1 as u128) * (v1 as u128);
    let mid = (p00 >> 64) + (p01 as u64 as u128) + (p10 as u64 as u128);
    let hi = (p01 >> 64) + (p10 >> 64) + (p11 as u128) + (mid >> 64);
    // 128 位幅值 = (mid 的低 64 位)<<64 | (p00 的低 64 位)——写成 `mid | p00<<64`
    // 是把两个 limb 拼反了，(1,1) 直接得 2^64（差分矩阵当场抓红）
    let mag = ((mid as u64 as u128) << 64) | (p00 as u64 as u128);
    if hi != 0 {
        return None;                      // 256 位积的高 128 位非零 ⇒ 必然越界
    }
    const LIM: u128 = 1u128 << 127;
    if mag > LIM {
        return None;
    }
    if mag == LIM {
        return if neg { Some(i128::MIN) } else { None };
    }
    Some(if neg { (mag as i128).wrapping_neg() } else { mag as i128 })
}

/// v2：wrapping 乘 + 除法回验（编译器内置溢出检查的经典代数形）。
/// `r.checked_div(a)` 只在 MIN/-1 处返回 None，而那恰好是乘积越界的场景，
/// 与 checked_mul 同集合（a=0 单独放行：0*b=0 恒合法）。
#[inline(never)]
pub fn mul_2(a: i128, b: i128) -> Option<i128> {
    std::hint::black_box(TAG_MUL_2);
    let r = a.wrapping_mul(b);
    if a == 0 {
        return Some(0);
    }
    match r.checked_div(a) {
        Some(q) if q == b => Some(r),
        _ => None,
    }
}

// ---------------- LT ----------------

/// v0：`a < b` 参考形。
#[inline(never)]
pub fn lt_0(a: i128, b: i128) -> bool {
    std::hint::black_box(TAG_LT_0);
    a < b
}

/// v1：符号分路——同号时退化成无符号比较，异号时"负数较小"直接定。
#[inline(never)]
pub fn lt_1(a: i128, b: i128) -> bool {
    std::hint::black_box(TAG_LT_1);
    if (a < 0) == (b < 0) {
        (a as u128) < (b as u128)
    } else {
        a < 0
    }
}

/// v2：保序双射 `x ↘ x ^ SIGN`（补码 → 无符号单调映射）后单一无符号比较。
#[inline(never)]
pub fn lt_2(a: i128, b: i128) -> bool {
    std::hint::black_box(TAG_LT_2);
    ((a as u128) ^ (1u128 << 127)) < ((b as u128) ^ (1u128 << 127))
}

// ---------------- LOADK ----------------

/// v0：i16 原生符号扩展（vm.rs 参考形取的是同一个 16 位补码值）。
#[inline(never)]
pub fn loadk_0(raw: u16) -> i128 {
    std::hint::black_box(TAG_LOADK_0);
    raw as i16 as i128
}

/// v1：显式阈值减法（≥0x8000 减 0x10000）。
#[inline(never)]
pub fn loadk_1(raw: u16) -> i128 {
    std::hint::black_box(TAG_LOADK_1);
    let v = raw as i128;
    if v >= 0x8000 {
        v - 0x10000
    } else {
        v
    }
}

/// v2：移位符号扩展——左推到最高位再算术右移回来。
/// 位移量按 128-16=112；两侧都不做条件分支，形态与 v0/v1 都不同。
#[inline(never)]
pub fn loadk_2(raw: u16) -> i128 {
    std::hint::black_box(TAG_LOADK_2);
    ((raw as u128) << 112) as i128 >> 112
}

// ---------------- 下标闸门（MOVE / LOADG / LOADN / STOREG 的选择轴） ----------------
// 搬运类热操作码的全部语义就是"验界 + 搬"，所以它们的变体轴是**边界判定路径**：
// 三条互等价的判据，判定后的读写仍走 vm.rs 里的两个唯一出口
// （`melissa_kinrenka` / `genzuki_tojiro`），错误码与判定顺序一字未动。
// 三条判据的等价域是有界的，且这个界来自 ISA 本身：`idx` 永远是一个 u8/u16 操作数
// （≤0xFFFF），`len` 是真实容器长度（< 2^63），于是 v2 的"wrap 后看最高位"不会撞上
// |idx-len| ≥ 2^63 的反例（那需要 len 接近 2^64，产品里不可达）。隐藏约束登记在此。

/// 判定形 A：`idx < len`（参考形）。
macro_rules! gate_lt {
    ($name:ident, $tag:expr) => {
        #[inline(never)]
        pub fn $name(idx: usize, len: usize) -> Option<usize> {
            std::hint::black_box($tag);
            if idx < len { Some(idx) } else { None }
        }
    };
}

/// 判定形 B：`len - idx > 0` 的 checked_sub 形。
macro_rules! gate_sub {
    ($name:ident, $tag:expr) => {
        #[inline(never)]
        pub fn $name(idx: usize, len: usize) -> Option<usize> {
            std::hint::black_box($tag);
            match len.checked_sub(idx) {
                Some(d) if d != 0 => Some(idx),
                _ => None,
            }
        }
    };
}

/// 判定形 C：wrapping 差 + 符号位（无分支形）。
macro_rules! gate_sign {
    ($name:ident, $tag:expr) => {
        #[inline(never)]
        pub fn $name(idx: usize, len: usize) -> Option<usize> {
            std::hint::black_box($tag);
            let d = idx.wrapping_sub(len) as usize;
            if (d >> (usize::BITS - 1)) == 1 { Some(idx) } else { None }
        }
    };
}

// 变体注册：一枚热操作码 × 三条判定形。没有 `paste!`（外部 crate，零依赖纪律禁止），
// 所以逐个实例化——少一处"宏名拼接出错但测试仍绿"的面。
gate_lt!(move_gate_0, TAG_MOVE_0);
gate_sub!(move_gate_1, TAG_MOVE_1);
gate_sign!(move_gate_2, TAG_MOVE_2);
gate_lt!(loadg_gate_0, TAG_LOADG_0);
gate_sub!(loadg_gate_1, TAG_LOADG_1);
gate_sign!(loadg_gate_2, TAG_LOADG_2);
gate_lt!(loadn_gate_0, TAG_LOADN_0);
gate_sub!(loadn_gate_1, TAG_LOADN_1);
gate_sign!(loadn_gate_2, TAG_LOADN_2);
gate_lt!(storeg_gate_0, TAG_STOREG_0);
gate_sub!(storeg_gate_1, TAG_STOREG_1);
gate_sign!(storeg_gate_2, TAG_STOREG_2);

// ---------------- 早期轮次：逐格链剖面的原生侧（的 Rust 镜像） ----------------

/// 配置流长度（形状字段）/常量流与掩码流长度。与 `vm_isa.CHAIN_CFG_BYTES` /
/// `CHAIN_K_BYTES` 同值，双端由 tests/d_side/test_vm_gates.py 的 source-literal 齿钉住。
pub const CHAIN_CFG_LEN: usize = 12;
pub const CHAIN_K_LEN: usize = 64;
/// 有效常量枚数（0..15，下标表见 vm_isa 的 _K_*）。
pub const CHAIN_WORDS: usize = 16;
/// 轮数上限（r ∈ {2,3,4}，剖面只用前 4 个移量槽）。
pub const CHAIN_ROUNDS_MAX: usize = 4;
/// 模数种子的下移与跨度（与 vm_isa 的 `32768 + w % 60000` 同式）。
const CHAIN_MOD_LO: u32 = 32768;
const CHAIN_MOD_SPAN: u32 = 60000;

/// 本格链剖面。**只存两段未解码的流**（常量流 + 掩码流）与配置流：
/// 有效常量一律在用的时候现算（`word(i)`），算完即随调用栈消失——镜像里与内存里都不
/// 存在"一枚枚轮常量排在一起"的形态。诚实定位：拖延档，不是边界；持有产物者
/// 重建 KDF 层级就能重算，与 /chunk 置换同级。
pub struct Chain {
    pub cfg: [u8; CHAIN_CFG_LEN],
    pub ks: [u8; CHAIN_K_LEN],
    pub mask: [u8; CHAIN_K_LEN],
}

/// 第 i 枚有效常量 = 常量流字 ⊕ 掩码流字（小端、模 2^32 域内）。
/// `i` 恒取自本文件内的 0..15 常量下标，越界不可达；这里不做 unwrap/panic 面
/// （产物热路径的"一切越界皆拒绝"纪律见 vm.rs）。
#[inline(always)]
fn w4(a: &[u8; CHAIN_K_LEN], b: &[u8; CHAIN_K_LEN], i: usize) -> u32 {
    let o = i * 4;
    let x = u32::from_le_bytes([a[o], a[o + 1], a[o + 2], a[o + 3]]);
    let y = u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]);
    x ^ y
}

/// `idx` → 0..n-1 的第 idx 个排列（阶乘数制）。与 `vm_isa._perm_n` 逐字对镜：
/// 先对 n! 取模（不取模时第一跳的 pick 会越出池长），再按 (size-1)! 一位位定pick。
/// `out` 只前 n 项有效，其余留 0（调用方按 rounds 取用）。
pub fn chain_order(n: usize, idx: u8) -> [usize; CHAIN_ROUNDS_MAX] {
    let mut total: usize = 1;
    for x in 2..=n {
        total *= x;
    }
    let mut idx = idx as usize % total;
    let mut pool = [0usize, 1, 2, 3];
    let mut plen = n;
    let mut out = [0usize; CHAIN_ROUNDS_MAX];
    for oi in 0..n {
        let mut fact = 1;
        for x in 2..plen {
            fact *= x;
        }
        let pick = if idx / fact < plen { idx / fact } else { plen - 1 };
        idx %= fact;
        out[oi] = pool[pick];
        for k in pick..plen - 1 {
            pool[k] = pool[k + 1];
        }
        plen -= 1;
    }
    out
}

impl Chain {
    pub fn rounds(&self) -> usize {
        2 + (self.cfg[0] % 3) as usize
    }

    #[inline(always)]
    pub fn word(&self, i: usize) -> u32 {
        w4(&self.ks, &self.mask, i)
    }

    pub fn fold_pos(&self) -> usize {
        self.cfg[1] as usize % self.rounds()
    }

    pub fn fold_cnt(&self) -> usize {
        1 + self.cfg[2] as usize % 2
    }

    pub fn inject(&self) -> u8 {
        self.cfg[3] % 3
    }

    pub fn couple(&self) -> bool {
        self.cfg[4] & 1 == 1
    }

    /// 第 i 轮的移量（1..31，i ∈ 0..3）
    pub fn rot(&self, i: usize) -> u32 {
        1 + (self.cfg[5 + i] % 31) as u32
    }

    pub fn order(&self) -> [usize; CHAIN_ROUNDS_MAX] {
        chain_order(self.rounds(), self.cfg[9])
    }

    pub fn tail_rot(&self) -> bool {
        self.cfg[11] & 1 == 1
    }

    /// 半折量 ∈ {8,16}：把高低两半（或两个 8 位段）折起来那一步的位移。
    pub fn fold_val(&self, i: usize) -> u32 {
        if (self.cfg[10] >> i) & 1 == 1 {
            8
        } else {
            16
        }
    }

    pub fn kadd(&self, i: usize) -> u32 {
        self.word(i)                     // 0..3
    }

    pub fn iv(&self) -> u32 {
        self.word(4)
    }

    pub fn km(&self) -> u32 {
        self.word(5)
    }

    pub fn tbl(&self, i: usize) -> u32 {
        self.word(6 + i)                 // 6..8
    }

    /// 各轮乘性回灌系数。恒置最低位为 1：模 2^32 下奇乘数是双射，乘不会把差值抹掉
    /// （与 vm_isa 的 `... | 1` 同形）。
    pub fn mul(&self, i: usize) -> u32 {
        self.word(10 + i) | 1            // 10..13
    }

    /// 概念表 T(z) = (z²·A + z·B + C) mod M 的模数（z 恒 ∈ 0..255，故永不物化这张表）。
    /// 表查档的旋转量与耦合项**共用这一张概念表**（换下标不换配方）。
    pub fn tbl_mod(&self) -> u32 {
        CHAIN_MOD_LO + self.word(9) % CHAIN_MOD_SPAN
    }

    pub fn kend(&self) -> u32 {
        self.word(14)
    }

    pub fn kf(&self) -> u32 {
        self.word(15)
    }
}

/// 概念上的 256 项表查，**算法生成、不落表**。定义域恒为 z ∈ 0..255，中间量
/// ≤ 255²·(2^32−1) + 255·(2^32−1) + (2^32−1) < 2^56 ⇒ u64 内精确，无需取模技巧。
/// 与 `vm_isa._chain_map` 同式。
#[inline(always)]
pub fn chain_map(z: u32, c0: u32, c1: u32, c2: u32, m: u32) -> u32 {
    let zz = z as u64;
    let v = zz * zz * (c0 as u64) + zz * (c1 as u64) + (c2 as u64);
    (v % (m as u64)) as u32
}

/// XOR 的规范值（供变体矩阵与 vm.rs 的 OP_XOR 臂共用）。
#[inline(always)]
pub fn xor_norm(a: i128, b: i128) -> i128 {
    a ^ b
}

/// ROTL32 的规范值：a 取低 32 位、k 取 mod 32，结果恒 < 2^32。
/// 非负域由调用方保证（vm.rs E-116 / vm_interp SaayaYamabuki）。
pub fn rotl32_norm(a: i128, k: i128) -> i128 {
    let j = (a % U32_RANGE_I) as u32;
    let r = (k % 32) as u32;
    j.rotate_left(r) as i128
}

const U32_RANGE_I: i128 = 4_294_967_296;   // 2^32，与 vm.rs 的 U32_RANGE / vm_isa. 同值
const U32_RANGE_U: u64 = 4_294_967_296;    // 同一枚模数的 u64 形（v1 的累加归约用）

// ---------------- XOR（早期轮次：扩池，此前单实现） ----------------

/// v0：`a ^ b` 参考形。
#[inline(never)]
pub fn xor_0(a: i128, b: i128) -> i128 {
    std::hint::black_box(TAG_XOR_0);
    xor_norm(a, b)
}

/// v1：逐字节异或后重组（`to_le_bytes`/`from_le_bytes` 是双射，故与 v0 恒等）。
#[inline(never)]
pub fn xor_1(a: i128, b: i128) -> i128 {
    std::hint::black_box(TAG_XOR_1);
    let x = a.to_le_bytes();
    let y = b.to_le_bytes();
    let mut z = [0u8; 16];
    let mut i = 0;
    while i < 16 {
        z[i] = x[i] ^ y[i];
        i += 1;
    }
    i128::from_le_bytes(z)
}

/// v2：MBA 形 `(a|b) ^ (a&b)`——并集去掉交集即对称差。
#[inline(never)]
pub fn xor_2(a: i128, b: i128) -> i128 {
    std::hint::black_box(TAG_XOR_2);
    (a | b) ^ (a & b)
}

// ---------------- ROTL32（早期轮次：扩池，此前单实现） ----------------

/// v0：`rotate_left` 参考形。
#[inline(never)]
pub fn rotl32_0(a: i128, k: i128) -> i128 {
    std::hint::black_box(TAG_ROTL32_0);
    rotl32_norm(a, k)
}

/// v1：显式位移对，`32 - r` 在 r=0 时越出 u32 位移域——用 checked_shr 落 0
/// （Python 侧 `j >> 32` 在整数域天然是 0，两侧同值）。
#[inline(never)]
pub fn rotl32_1(a: i128, k: i128) -> i128 {
    std::hint::black_box(TAG_ROTL32_1);
    let j = (a % U32_RANGE_I) as u32;
    let r = (k % 32) as u32;
    let hi = j.checked_shr(32 - r).unwrap_or(0);
    (((j << r) | hi) as i128) & (U32_RANGE_I - 1)
}

/// v2：乘法形 `rotl(v,r) = (v·2^r mod 2^32) + (v >> (32-r))`，r=0 时第二项落 0。
#[inline(never)]
pub fn rotl32_2(a: i128, k: i128) -> i128 {
    std::hint::black_box(TAG_ROTL32_2);
    let j = (a % U32_RANGE_I) as u32;
    let r = (k % 32) as u32;
    let lo = j.wrapping_mul(1u32 << r);
    let hi = j.checked_shr(32 - r).unwrap_or(0);
    ((lo | hi) as i128) & (U32_RANGE_I - 1)
}

// ---------------- HSTEP（早期轮次：链步进离开字节码） ----------------

/// 三条实现共用的内部件：32 位循环左移（v1/v2 走不同算路，见各自注释）。
#[inline(always)]
fn r32_shift_pair(v: u32, r: u32) -> u32 {
    let hi = v.checked_shr(32 - r).unwrap_or(0);
    (v << r) | hi
}

#[inline(always)]
fn r32_mul(v: u32, r: u32) -> u32 {
    let lo = v.wrapping_mul(1u32 << r);
    let hi = v.checked_shr(32 - r).unwrap_or(0);
    lo | hi
}

/// v0：参考形——与 `vm_isa.shishido_akari` 逐式对应，逐步收在模 2^32。
#[inline(never)]
pub fn hstep_0(ch: &Chain, st: u32, msg: u32) -> u32 {
    std::hint::black_box(TAG_HSTEP_0);
    let a = st.wrapping_add(ch.iv());
    let x = msg;
    let mut y0 = match ch.inject() {
        0 => x.wrapping_mul(x),
        1 => x.wrapping_add(ch.km()).wrapping_mul(x),
        _ => x.rotate_left(chain_map(x & 0xff, ch.tbl(0), ch.tbl(1), ch.tbl(2),
                                     ch.tbl_mod()) & 31),
    };
    if ch.couple() {
        y0 = y0.wrapping_add(chain_map(
            (a ^ x) & 0xff, ch.tbl(0), ch.tbl(1), ch.tbl(2), ch.tbl_mod()));
    }
    let rounds = ch.rounds();
    let order = ch.order();
    let mut s = a;
    let mut prev = a;
    for k in 0..rounds {
        let j = order[k];
        let mut t = s.wrapping_add(y0).wrapping_add(ch.kadd(j));
        t = t.rotate_left(ch.rot(j));
        if k == ch.fold_pos() {
            t ^= r32_shift_pair(t, ch.fold_val(0));
        }
        if ch.fold_cnt() == 2 && k == (ch.fold_pos() + 1) % rounds {
            t ^= r32_shift_pair(t, ch.fold_val(1));
        }
        // 乘性回灌（半折会压掉状态位宽，纯加法链会把首字节差值一路归零，见 vm_isa 注释）
        t = t.wrapping_add(prev.wrapping_mul(ch.mul(j)));
        prev = s;
        s = t;
    }
    // 收尾混合步恒不折（见 vm_isa.shishido_akari 的注释）：半折形如 (v,v)，折在末轮会把
    // 输出宽度砍到 16 位——那一条被雪崩门当场抓红
    s = s.wrapping_add(y0).wrapping_add(ch.kend()).rotate_left(ch.rot(3));
    if ch.tail_rot() {
        s = s.rotate_left(ch.rot(order[0]));
    }
    s ^ ch.kf()
}

/// v1：加法走 u64 累加再一次归约、旋转换用显式位移对、表查换 Horner 形。
/// 与 v0 的值恒等，但代码路径完全不同（同一操作码的三条实现互为差分齿）。
#[inline(never)]
pub fn hstep_1(ch: &Chain, st: u32, msg: u32) -> u32 {
    std::hint::black_box(TAG_HSTEP_1);
    let m = U32_RANGE_U;
    let a = ((st as u64 + ch.iv() as u64) % m) as u32;
    let x = msg;
    let mut y0 = match ch.inject() {
        0 => ((x as u64 * x as u64) % m) as u32,
        1 => {
            let s = (x as u64 + ch.km() as u64) % m;
            ((s * x as u64) % m) as u32
        }
        _ => {
            // Horner：((z·A + B)·z + C) mod M，与展开形逐项同余（z ≤ 255，中间量 < 2^56）；
            // 表项在这里**选旋转量**，不当加数（理由见 vm_isa.shishido_akari）
            let z = (x & 0xff) as u64;
            let mm = ch.tbl_mod() as u64;
            let acc = (z * (ch.tbl(0) as u64) + ch.tbl(1) as u64) % mm;
            let q = ((acc * z + ch.tbl(2) as u64) % mm) as u32;
            r32_shift_pair(x, q & 31)
        }
    };
    if ch.couple() {
        let z = ((a ^ x) & 0xff) as u64;
        let mm = ch.tbl_mod() as u64;
        let acc = (z * (ch.tbl(0) as u64) + ch.tbl(1) as u64) % mm;
        let q = (acc * z + ch.tbl(2) as u64) % mm;
        y0 = ((y0 as u64 + q) % m) as u32;
    }
    let rounds = ch.rounds();
    let order = ch.order();
    let fold_at = (ch.fold_pos() + 1) % rounds;
    let mut s = a;
    let mut prev = a;
    for k in 0..rounds {
        let j = order[k];
        let mut t = ((s as u64 + y0 as u64 + ch.kadd(j) as u64) % m) as u32;
        t = r32_shift_pair(t, ch.rot(j));
        if k == ch.fold_pos() {
            t ^= r32_shift_pair(t, ch.fold_val(0));
        }
        if ch.fold_cnt() == 2 && k == fold_at {
            t ^= r32_shift_pair(t, ch.fold_val(1));
        }
        // prev·mul 的积在 u64 内精确（(2^32−1)² < 2^64），两次归约与一次归约同余
        t = ((t as u64 + (prev as u64 * ch.mul(j) as u64) % m) % m) as u32;
        prev = s;
        s = t;
    }
    s = r32_shift_pair(((s as u64 + y0 as u64 + ch.kend() as u64) % m) as u32, ch.rot(3));
    if ch.tail_rot() {
        s = r32_shift_pair(s, ch.rot(order[0]));
    }
    s ^ ch.kf()
}

/// v2：加法转成 MBA 恒等式 `(x+y) = (x^y) + 2·(x&y)`（进位在 32 位 wrapping 域内
/// 有限步收敛）、旋转换用乘法形、对称差用 `(x|y) ^ (x&y)`。
#[inline(never)]
pub fn hstep_2(ch: &Chain, st: u32, msg: u32) -> u32 {
    std::hint::black_box(TAG_HSTEP_2);
    // 32 位加法的 MBA 形：与 wrapping_add 恒等。移位一律 wrapping——`carry << 1`
    // 在最高位丢的那一位正是 mod 2^32 的语义（与 add_2 同一条纪律）
    fn add32(x0: u32, y0: u32) -> u32 {
        let mut x = x0;
        let mut y = y0;
        while y != 0 {
            let carry = (x & y).wrapping_shl(1);
            x ^= y;
            y = carry;
        }
        x
    }
    fn symdiff(x: u32, y: u32) -> u32 {
        (x | y) ^ (x & y)
    }
    let a = add32(st, ch.iv());
    let x = msg;
    let mut y0 = match ch.inject() {
        0 => x.wrapping_mul(x),
        1 => add32(x, ch.km()).wrapping_mul(x),
        _ => r32_mul(x, chain_map(x & 0xff, ch.tbl(0), ch.tbl(1), ch.tbl(2),
                                  ch.tbl_mod()) & 31),
    };
    if ch.couple() {
        y0 = add32(y0, chain_map(
            (a ^ x) & 0xff, ch.tbl(0), ch.tbl(1), ch.tbl(2), ch.tbl_mod()));
    }
    let rounds = ch.rounds();
    let order = ch.order();
    let fold_at = (ch.fold_pos() + 1) % rounds;
    let mut s = a;
    let mut prev = a;
    for k in 0..rounds {
        let j = order[k];
        let mut t = r32_mul(add32(add32(s, y0), ch.kadd(j)), ch.rot(j));
        if k == ch.fold_pos() {
            t ^= r32_mul(t, ch.fold_val(0));
        }
        if ch.fold_cnt() == 2 && k == fold_at {
            t ^= r32_mul(t, ch.fold_val(1));
        }
        t = add32(t, prev.wrapping_mul(ch.mul(j)));
        prev = s;
        s = t;
    }
    s = r32_mul(add32(add32(s, y0), ch.kend()), ch.rot(3));
    if ch.tail_rot() {
        s = r32_mul(s, ch.rot(order[0]));
    }
    symdiff(s, ch.kf())
}

#[cfg(test)]
mod tests {
    // 本模块不进产品构建（产品用 rustc 单 crate 编译，不带 --test）；
    // 真正的矩阵差分在 tests/d_side/test_native_vm.py 的变体矩阵用例里跑。
}
