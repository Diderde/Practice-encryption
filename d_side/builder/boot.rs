// Copyright (C) 2026 Diderde
// SPDX-License-Identifier: GPL-3.0-only
//!  native boot 正式模板（零 crate）。
//!
//! 流程（拒绝顺序：守卫 1a → 门槛 → KAT → MAC 先于解密）：
//! 原生层守卫（反调试三件套 / 可疑模块枚举 / `.text` 摘要自校验，D-3）→
//! CPUID x86-64-v2 门槛（`REQUIRE_V2` 钉子开启时）→ 四原语 KAT 自检 →
//! RCDATA 读密文 → BLAKE2s-MAC 校验 → 三件套解密 → CPython 嵌入（初始化后
//! 先过 Python 层守卫 1b，再执行 marshal）。
//!
//! 钉子（`crate::pins`）全部由构建侧 Python 权威计算生成，零手抄期望值；
//! 本文件不含任何构建机路径：python DLL 按产物头内 minor 版本在 exe 同目录解析；
//! 构建期开 EMBED_HOME 时改为内嵌 home 资源（首启释放到 LocalAppData 缓存，逐文件
//! BLAKE2s 校验复用，见文件内 B 方案段）。头部偏移绑定 layout.json format_version 1（57B）。

#[path = "blake2s.rs"]
mod blake2s;

//  VM blob v2 的原生解释器（`super::*` 即本模块的密码学原语，零 crate）
#[path = "vm.rs"]
mod vm;

//  容器升级：PSIV 块级 AEAD（fmt_ver=3 槽内认证；ePrint 2025/222，CC0 参考实现对照）
#[path = "psiv.rs"]
mod psiv;

//  可见量断言齿（执行中途暂停，供外部进程抓取）+ VM 明文槽的页隔离分配
#[path = "visprobe.rs"]
mod visprobe;

use std::convert::TryInto;
use std::ffi::{c_char, c_int, c_void, CString};
use std::ptr;

use crate::pins;

// ---------- kernel32 ----------
#[link(name = "kernel32")]
extern "system" {
    fn LoadLibraryExW(w: *const u16, f: *mut c_void, flags: u32) -> *mut c_void;
    fn GetProcAddress(h: *mut c_void, name: *const u8) -> *mut c_void;
    fn FindResourceA(h: *mut c_void, name: *const u8, ty: *const u8) -> *mut c_void;
    fn LoadResource(h: *mut c_void, r: *mut c_void) -> *mut c_void;
    fn LockResource(r: *mut c_void) -> *mut u8;
    fn SizeofResource(h: *mut c_void, r: *mut c_void) -> u32;
    fn LocalAlloc(uflags: u32, ubytes: usize) -> *mut c_void;
    // D-3 守卫 1a（§8）：反调试 + 可疑模块枚举 + 自身文件定位
    fn IsDebuggerPresent() -> i32;
    fn CheckRemoteDebuggerPresent(h: *mut c_void, flag: *mut i32) -> i32;
    fn GetCurrentProcess() -> *mut c_void;
    fn CreateToolhelp32Snapshot(flags: u32, pid: u32) -> *mut c_void;
    fn Module32FirstW(h: *mut c_void, e: *mut ModuleEntryW) -> i32;
    fn Module32NextW(h: *mut c_void, e: *mut ModuleEntryW) -> i32;
    fn CloseHandle(h: *mut c_void) -> i32;
    fn GetModuleFileNameW(h: *mut c_void, buf: *mut u16, len: u32) -> u32;
}

const _TH32CS_SNAPMODULE: u32 = 0x0000_0008;

#[repr(C)]
struct ModuleEntryW {
    dw_size: u32,
    th32_module_id: u32,
    th32_process_id: u32,
    glblcnt_usage: u32,
    proccnt_usage: u32,
    mod_base_addr: *mut u8,
    mod_base_size: u32,
    h_module: *mut c_void,
    sz_module: [u16; 256],
    sz_exe_path: [u16; 260],
}

const _LMEM_FIXED_ZERO: u32 = 0x0040; // LMEM_ZEROINIT（LPTR = FIXED|ZEROINIT）

// ---------- version / wintrust（T7 信任锚） ----------
#[link(name = "version")]
extern "system" {
    fn GetFileVersionInfoSizeW(lptstr_filename: *const u16, dw_handle: *mut u32) -> u32;
    fn GetFileVersionInfoW(
        lptstr_filename: *const u16,
        dw_handle: u32,
        dw_len: u32,
        lp_data: *mut c_void,
    ) -> i32;
    fn VerQueryValueW(
        p_block: *const c_void,
        lp_sub_block: *const u16,
        pp_buffer: *mut *mut c_void,
        pu_len: *mut u32,
    ) -> i32;
}

#[repr(C)]
struct Guid {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}

#[repr(C)]
struct WintrustFileInfo {
    cb_struct: u32,
    pcwsz_file_path: *const u16,
    h_file: *mut c_void,
    pg_known_subject: *mut c_void,
}

#[repr(C)]
union WintrustUnion {
    p_file: *mut WintrustFileInfo,
}

#[repr(C)]
struct WintrustData {
    cb_struct: u32,
    p_policy_callback_data: *mut c_void,
    p_sip_client_data: *mut c_void,
    dw_ui_choice: u32,
    fdw_revocation_checks: u32,
    dw_union_choice: u32,
    u: WintrustUnion,
    dw_state_action: u32,
    h_wvt_state_data: *mut c_void,
    pwsz_url_reference: *mut c_void,
    dw_prov_flags: u32,
    dw_ui_context: u32,
    p_signature_settings: *mut c_void,
}

#[link(name = "wintrust")]
extern "system" {
    fn WinVerifyTrust(hwnd: *mut c_void, pg_action_id: *mut Guid, p_wvt_data: *mut c_void) -> i32;
}

// ---------- shell32 / ole32（B 方案：单文件 home 的缓存根） ----------
#[link(name = "shell32")]
extern "system" {
    fn SHGetKnownFolderPath(rfid: *const Guid, flags: u32, token: *mut c_void,
                            path: *mut *mut u16) -> i32;
}
#[link(name = "ole32")]
extern "system" {
    fn CoTaskMemFree(p: *mut c_void);
}

// ---------- CPython FFI（PyStatus 是结构体，x64 按值返回走 sret） ----------
#[repr(C)]
#[derive(Clone, Copy)]
struct PyStatus {
    _type: i32,
    func: *const c_char,
    err_msg: *const c_char,
    usage: *const c_char,
    exitcode: i32,
}
type InitIsolated = unsafe extern "C" fn(*mut c_void);
type SetBytesArgv = unsafe extern "C" fn(*mut c_void, isize, *mut *mut c_char) -> PyStatus;
type InitFromConfig = unsafe extern "C" fn(*mut c_void) -> PyStatus;
type Finalize = unsafe extern "C" fn(*mut c_void) -> c_int;
type MarshalLoads = unsafe extern "C" fn(*const c_char, isize) -> *mut c_void;
type AddModule = unsafe extern "C" fn(*const c_char) -> *mut c_void;
type GetDict = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
type EvalCode = unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void) -> *mut c_void;
type ErrOccurred = unsafe extern "C" fn() -> *mut c_void;
type ErrPrint = unsafe extern "C" fn();
type RunSimple = unsafe extern "C" fn(*const c_char) -> c_int;

fn wid(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn proc_addr(h: *mut c_void, name: &str) -> *mut c_void {
    let c = CString::new(name).unwrap();
    unsafe { GetProcAddress(h, c.as_ptr() as *const u8) }
}

// ---------- 早期轮次 Phase 2：逐格接口契约的运行时读取口 ----------
/// `IFACE_JOIN == 256` 是"无连接符"档（各项直接拼接）。分隔符曾经是全局常量 0x00，
/// 一次实验就能问出来、八格通用（既有审计中多次独立还原到同一份契约之一）。
fn iface_join() -> Option<u8> {
    match pins::IFACE_JOIN {
        256 => None,
        b => Some(b as u8),
    }
}

/// 本格 `--key-file` 的剥离档：bit0 = 剥空格式（`--key-file <path>`，连同 path 一起），
/// bit1 = 剥等号式（`--key-file=<path>`）。四档 = 0b01/0b10/0b11/0b00。
/// 不剥的档会把旗标与路径留在载荷可见窗里——这是刻意的逐格差异，代价是这些格的
/// 输出随密钥文件路径变化，验收侧必须按本格契约供钥并记录同一串 argv。
/// 注意：这只影响**载荷看得见什么**；取钥本身（`ex_albio`）恒按空格式读，不受影响。
fn iface_strips() -> (bool, bool) {
    let space = matches!(pins::IFACE_KEYSTRIP & 0b01, 1);
    let equals = matches!(pins::IFACE_KEYSTRIP & 0b10, 0b10);
    (space, equals)
}

/// 拒绝出口：与守卫通道同口径——默认静默 exit 3，只在诊断钉开时打印短码。
/// 旧实现无条件 eprintln，等于给模糊测试一个"为什么被拒"的预言机。
/// 批2-1.2：出口前先跑 `REJECT_PAD` 轮 dummy blake2s——失败时序均匀化。轮数由构建期
/// (seed, nonce) 派生并钉死，运行期零随机；纯计算、不写任何通道，所以 rc=3 与
/// stderr 恒空的静默契约一字不破。
fn _exit3(msg: &str) -> ! {
    std::hint::black_box(oliver_evans(pins::REJECT_PAD));
    if guard_diagnostic() {
        eprintln!("{}", msg);
    }
    std::process::exit(3);
}

/// 早期轮次 Phase 2：超限拒绝出口。这条通道**只服务"进程输入超出本格窗口"**，退出码逐格
/// ∈ {3,4}——上一代恒 3 也是全局契约的一部分（"超限就是 3"），逐格化后必须逐格问。
/// 完整性拒绝（守卫 / MAC / KAT）一律不走这里：它们的 rc=3 + 零输出是被十几处断言
/// 钉住的静默契约，不因接口逐格化而新增可观察行为类。
fn _exit_iface(msg: &str) -> ! {
    std::hint::black_box(oliver_evans(pins::REJECT_PAD));
    if guard_diagnostic() {
        eprintln!("{}", msg);
    }
    std::process::exit(pins::IFACE_REJECT_EXIT as i32);
}

// ---------- u256（[u64; 4]，limb0 最低位；仅模 2^256 环运算） ----------
fn _u256_from_be(b: &[u8]) -> [u64; 4] {
    let mut out = [0u64; 4];
    let mut buf = [0u8; 32];
    buf[32 - b.len()..].copy_from_slice(b);
    for i in 0..4 {
        out[i] = u64::from_be_bytes(buf[24 - 8 * i..32 - 8 * i].try_into().unwrap());
    }
    out
}

fn _u256_to_be(x: &[u64; 4]) -> [u8; 32] {
    let mut buf = [0u8; 32];
    for i in 0..4 {
        buf[24 - 8 * i..32 - 8 * i].copy_from_slice(&x[i].to_be_bytes());
    }
    buf
}

fn _u256_add(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let mut out = [0u64; 4];
    let mut carry = 0u128;
    for i in 0..4 {
        let s = a[i] as u128 + b[i] as u128 + carry;
        out[i] = s as u64;
        carry = s >> 64;
    }
    out
}

fn _u256_mul(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let mut out = [0u64; 4];
    for i in 0..4 {
        let mut carry = 0u128;
        for j in 0..4 {
            if i + j >= 4 {
                break;
            }
            let cur = out[i + j] as u128 + (a[i] as u128) * (b[j] as u128) + carry;
            out[i + j] = cur as u64;
            carry = cur >> 64;
        }
    }
    out
}

fn _u256_shr(a: &[u64; 4], bits: usize) -> [u64; 4] {
    let (words, bits) = (bits / 64, bits % 64);
    let mut out = [0u64; 4];
    for i in 0..4 {
        if i + words < 4 {
            out[i] = a[i + words] >> bits;
            if bits > 0 && i + words + 1 < 4 {
                out[i] |= a[i + words + 1] << (64 - bits);
            }
        }
    }
    out
}

fn _u256_xor(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let mut out = [0u64; 4];
    for i in 0..4 {
        out[i] = a[i] ^ b[i];
    }
    out
}

fn _u256_sub(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let mut out = [0u64; 4];
    let mut borrow = 0u64;
    for i in 0..4 {
        let (d1, b1) = a[i].overflowing_sub(b[i]);
        let (d2, b2) = d1.overflowing_sub(borrow);
        out[i] = d2;
        borrow = (b1 as u64) | (b2 as u64);
    }
    out
}

fn _u256_rotl(a: &[u64; 4], r: u32) -> [u64; 4] {
    let r = r % 256;
    if r == 0 {
        return *a;
    }
    let words = (r / 64) as usize;
    let bits = r % 64;
    let mut out = [0u64; 4];
    for i in 0..4 {
        let src = (i + 4 - words) % 4;
        let src2 = (src + 3) % 4;
        out[i] = if bits == 0 {
            a[src]
        } else {
            (a[src] << bits) | (a[src2] >> (64 - bits))
        };
    }
    out
}

// ---------- 拓扑 salt 镜像（与 d_side/keys.py 逐语义对应） ----------
fn _rivest_mix(seed: &[u8; 32], nonce: &[u8; 12]) -> [u8; 32] {
    let s = _u256_from_be(seed);
    let mut a1 = _u256_shr(&s, 8);
    a1[0] |= 1; // 奇
    let mut a2 = _u256_shr(&s, 16);
    a2[0] &= !1u64; // 偶
    let mut a3 = _u256_shr(&s, 24);
    a3[0] &= !1u64; // 偶
    let n = _u256_from_be(nonce);
    let t = _u256_add(&_u256_mul(&a3, &n), &a2);
    let t = _u256_add(&_u256_mul(&t, &n), &a1);
    let t = _u256_add(&_u256_mul(&t, &n), &s);
    _u256_to_be(&t)
}

fn _tfunc_mix(seed: &[u8; 32], nonce: &[u8; 12]) -> [u8; 32] {
    // x0 = seed ^ (nonce||nonce)（24B 零扩展到 32B——高 8 字节继承 seed）
    let s = _u256_from_be(seed);
    let mut nn = [0u8; 32];
    nn[8..20].copy_from_slice(nonce);
    nn[20..32].copy_from_slice(nonce);
    let mut x = _u256_xor(&s, &_u256_from_be(&nn));
    for _ in 0..4 {
        let sq = _u256_mul(&x, &x);
        let mut inc = sq;
        inc[0] |= 5;
        x = _u256_add(&x, &inc);
    }
    _u256_to_be(&x)
}

// ----------  完整版拓扑 4–6 的混合原子（与 keys.py 逐字节镜像； 双路径 KAT 由套件钉） ----------

fn _feistel3_mix(seed: &[u8; 32], nonce: &[u8; 12]) -> [u8; 32] {
    let mut v = [0u8; 32];
    for i in 0..32 {
        v[i] = seed[i] ^ nonce[i % 12];
    }
    let mut l = u128::from_be_bytes(v[0..16].try_into().unwrap());
    let mut r = u128::from_be_bytes(v[16..32].try_into().unwrap());
    for i in 0..3u32 {
        let mut k = [0u8; 16];
        for j in 0..16 {
            k[j] = seed[8 * i as usize + (j % 8)];
        }
        let kf = u128::from_be_bytes(k);
        let t = kf.wrapping_add(r);
        let nl = r;
        let nr = l ^ t;
        l = nl;
        r = nr;
    }
    let mut out = [0u8; 32];
    out[0..16].copy_from_slice(&l.to_be_bytes());
    out[16..32].copy_from_slice(&r.to_be_bytes());
    out
}

fn _arx_cascade_mix(seed: &[u8; 32], nonce: &[u8; 12]) -> [u8; 32] {
    let mut v = _u256_from_be(nonce);
    for i in 0..4u32 {
        let r = (seed[4 * i as usize] % 255) as u32 + 1;
        let mut mk = [0u8; 32];
        mk.copy_from_slice(&seed[8 * i as usize..8 * i as usize + 8].repeat(4));
        let mku = _u256_from_be(&mk);
        v = _u256_xor(&_u256_rotl(&v, r), &mku);
        v = _u256_add(&v, &mku);
    }
    _u256_to_be(&v)
}

fn _oddscale_mix(seed: &[u8; 32], nonce: &[u8; 12]) -> [u8; 32] {
    let s = _u256_from_be(seed);
    let mut v = _u256_xor(&_u256_from_be(nonce), &s);
    for i in 0..3u32 {
        let mut lane = [0u8; 32];
        lane.copy_from_slice(&seed[8 * i as usize..8 * i as usize + 8].repeat(4));
        let mut odd = _u256_from_be(&lane);
        odd[0] |= 1;
        let mut xk = [0u8; 32];
        xk.copy_from_slice(&seed[8 * ((i + 1) % 4) as usize..8 * ((i + 1) % 4) as usize + 8].repeat(4));
        let mut ak = [0u8; 32];
        ak.copy_from_slice(&seed[8 * ((i + 2) % 4) as usize..8 * ((i + 2) % 4) as usize + 8].repeat(4));
        v = _u256_mul(&v, &odd);
        v = _u256_xor(&v, &_u256_from_be(&xk));
        v = _u256_add(&v, &_u256_from_be(&ak));
    }
    _u256_to_be(&v)
}

// 拓扑 7 pairswap（swap-or-not 配对对合）：决策位取自**规范代表元**
// a = min(z, π(z)) ⊕ k 的最低位——配对两侧算出同一位，整对同换或同留，
// τ 为对合，轮 = (⊕k) ∘ τ ∘ (⊕k) 是对合的共轭 ⇒ 对合 ⇒ 双射（精确）。
// （初版按 f(z)/f(π(z)) 大小择一——决策不对称、非对合，闸门 w=16 穷举
// 当场抓获后改规范代表元形态）
fn _pairswap_mix(seed: &[u8; 32], nonce: &[u8; 12]) -> [u8; 32] {
    let mut v = _u256_xor(&_u256_from_be(nonce), &_u256_from_be(seed));
    for i in 0..4u32 {
        let mut kb = [0u8; 32];
        kb.copy_from_slice(&seed[8 * i as usize..8 * i as usize + 8].repeat(4));
        let k = _u256_from_be(&kb);
        let z = _u256_xor(&v, &k);
        let p = _u256_rotl(&z, 128);
        let canonical = if (z[3], z[2], z[1], z[0]) <= (p[3], p[2], p[1], p[0]) {
            z
        } else {
            p
        };
        let bit = _u256_xor(&canonical, &k)[0] & 1;
        let y = if bit == 1 { p } else { z };
        v = _u256_xor(&y, &k);
    }
    _u256_to_be(&v)
}

// 拓扑 8 laimassey（Lai–Massey 纤维平移）：轮内 L⊕R 纤维不变 + 纤维内平移
// ⇒ 精确双射（与 F 无关）；轮间半交换 + 单半加奇常数打断纤维不变量。
fn _laimassey_mix(seed: &[u8; 32], nonce: &[u8; 12]) -> [u8; 32] {
    // 初始化与 keys.py 同为**整数**异或（nonce 零扩展到 256 位——高 160 位
    // 不受 nonce 影响；逐字节 nonce[i%12] 循环是另一种语义，E2E MAC 当场抓获）
    let xb = _u256_to_be(&_u256_xor(&_u256_from_be(nonce), &_u256_from_be(seed)));
    let mut l = u128::from_be_bytes(xb[0..16].try_into().unwrap());
    let mut r = u128::from_be_bytes(xb[16..32].try_into().unwrap());
    for i in 0..3u32 {
        let a = l ^ r;
        let mut kb = [0u8; 16];
        kb.copy_from_slice(&seed[8 * i as usize..8 * i as usize + 8].repeat(2));
        let f = a.wrapping_add(u128::from_be_bytes(kb));
        l ^= f;
        r ^= f;
        let mut cb = [0u8; 16];
        cb.copy_from_slice(
            &seed[8 * ((i + 1) % 4) as usize..8 * ((i + 1) % 4) as usize + 8].repeat(2),
        );
        let mut odd = u128::from_be_bytes(cb);
        odd |= 1;
        let nl = r.wrapping_add(odd);
        r = l;
        l = nl;
    }
    let mut out = [0u8; 32];
    out[0..16].copy_from_slice(&l.to_be_bytes());
    out[16..32].copy_from_slice(&r.to_be_bytes());
    out
}

fn _schedule_salt(seed: &[u8; 32], nonce: &[u8; 12], sched: u8) -> Vec<u8> {
    match sched {
        1 => nonce.to_vec(),
        2 => {
            let mut v = nonce.to_vec();
            v.extend_from_slice(&_rivest_mix(seed, nonce));
            v
        }
        3 => {
            let mut v = nonce.to_vec();
            v.extend_from_slice(&_tfunc_mix(seed, nonce));
            v
        }
        4 => {
            let mut v = nonce.to_vec();
            v.extend_from_slice(&_feistel3_mix(seed, nonce));
            v
        }
        5 => {
            let mut v = nonce.to_vec();
            v.extend_from_slice(&_arx_cascade_mix(seed, nonce));
            v
        }
        6 => {
            let mut v = nonce.to_vec();
            v.extend_from_slice(&_oddscale_mix(seed, nonce));
            v
        }
        7 => {
            let mut v = nonce.to_vec();
            v.extend_from_slice(&_pairswap_mix(seed, nonce));
            v
        }
        8 => {
            let mut v = nonce.to_vec();
            v.extend_from_slice(&_laimassey_mix(seed, nonce));
            v
        }
        _ => _exit3("E-01"),
    }
}

// ---------- SHA-256 / HMAC / HKDF（FIPS 180-4 / RFC 2104 / RFC 5869） ----------
const _K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

pub fn rindou_mikoto(msg: &[u8]) -> [u8; 32] {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];
    let bitlen = (msg.len() as u64) * 8;
    let mut m = msg.to_vec();
    m.push(0x80);
    while m.len() % 64 != 56 {
        m.push(0);
    }
    m.extend_from_slice(&bitlen.to_be_bytes());
    for chunk in m.chunks(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes(chunk[4 * i..4 * i + 4].try_into().unwrap());
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh.wrapping_add(s1).wrapping_add(ch).wrapping_add(_K[i]).wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g; g = f; f = e; e = d.wrapping_add(t1);
            d = c; c = b; b = a; a = t1.wrapping_add(t2);
        }
        h[0] = h[0].wrapping_add(a); h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c); h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e); h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g); h[7] = h[7].wrapping_add(hh);
    }
    let mut out = [0u8; 32];
    for i in 0..8 {
        out[4 * i..4 * i + 4].copy_from_slice(&h[i].to_be_bytes());
    }
    out
}

/// 早期轮次 步骤 3（内存自证）：显式覆零一段缓冲，且不让优化器把覆零当死代码删掉。
///
/// 用途：外钥档下 seed 只在"重建头部 + 派生工作密钥 + ISA 物理映射"这三步里
/// 出现，用完立刻抹掉——运行中途的全内存抓取才可能给出"seed 零命中"这种
/// 可验证的断言（既有审计实证：内嵌档下内存提取比破密码便宜）。
pub fn suo_sango(buf: &mut [u8]) {
    unsafe { std::ptr::write_bytes(buf.as_mut_ptr(), 0, buf.len()) };
    std::hint::black_box(&*buf);
}

pub fn joe_rikiichi(key: &[u8], data: &[u8]) -> Vec<u8> {
    // RFC 2104：超过块长的 key 先哈希再使用——Python 侧 hmac.new 同语义，
    // 缺此分支会让长 key 在两侧静默分叉（修复，早期轮次）
    let k = if key.len() > 64 {
        rindou_mikoto(key).to_vec()
    } else {
        key.to_vec()
    };
    let mut kp = [0u8; 64];
    kp[..k.len()].copy_from_slice(&k);
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= kp[i];
        opad[i] ^= kp[i];
    }
    // 两条拼接待缓冲都可能装着 ikm（外钥档下就是 seed）——用完覆零再释放，
    // 否则 freed heap 里留一份完整的 32 B seed（早期轮次 步骤 3）
    let mut inner_msg = [&ipad[..], data].concat();
    let inner = rindou_mikoto(&inner_msg);
    suo_sango(&mut inner_msg);
    let mut outer_msg = [&opad[..], &inner].concat();
    let outer = rindou_mikoto(&outer_msg);
    suo_sango(&mut outer_msg);
    outer.to_vec()
}

pub fn machita_chima(prk: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut t = Vec::new();
    let mut counter = 1u8;
    while out.len() < len {
        let mut input = t.clone();
        input.extend_from_slice(info);
        input.push(counter);
        t = joe_rikiichi(prk, &input);
        out.extend_from_slice(&t);
        counter += 1;
    }
    out.truncate(len);
    out
}

// ---------- ChaCha20（RFC 8439；counter=0 起的整段流，与 d_side 语义一致） ----------
fn _qr(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(7);
}

pub fn sakura_ritsuki(key: &[u8; 32], nonce: &[u8; 12], counter: u32) -> [u8; 64] {
    let mut st = [0u32; 16];
    st[0] = 0x61707865;
    st[1] = 0x3320646e;
    st[2] = 0x79622d32;
    st[3] = 0x6b206574;
    for i in 0..8 {
        st[4 + i] = u32::from_le_bytes([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]]);
    }
    st[12] = counter;
    for i in 0..3 {
        st[13 + i] = u32::from_le_bytes([nonce[4 * i], nonce[4 * i + 1], nonce[4 * i + 2], nonce[4 * i + 3]]);
    }
    let mut w = st;
    for _ in 0..10 {
        _qr(&mut w, 0, 4, 8, 12); _qr(&mut w, 1, 5, 9, 13);
        _qr(&mut w, 2, 6, 10, 14); _qr(&mut w, 3, 7, 11, 15);
        _qr(&mut w, 0, 5, 10, 15); _qr(&mut w, 1, 6, 11, 12);
        _qr(&mut w, 2, 7, 8, 13); _qr(&mut w, 3, 4, 9, 14);
    }
    let mut out = [0u8; 64];
    for i in 0..16 {
        out[4 * i..4 * i + 4].copy_from_slice(&w[i].wrapping_add(st[i]).to_le_bytes());
    }
    out
}

pub fn belmond_banderas(key: &[u8; 32], nonce: &[u8; 12], data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    for (i, b) in data.iter().enumerate() {
        let blk = sakura_ritsuki(key, nonce, (i / 64) as u32);
        out.push(b ^ blk[i % 64]);
    }
    out
}

// ---------- 原语 KAT（期望值由构建侧 Python 权威计算，见 pins） ----------
pub fn yumeoi_kakeru() -> bool {
    // （安全审计补完）：ChaCha20/SHA-256/BLAKE2s 的 KAT 输入同样取随机形
    // （RFC 8439 §2.3.2 公开向量与 "abc" 都是原语确认通道，与 native_build 逐字
    // 一致）
    let mut key = [0u8; 32];
    for (i, b) in [
        0x3a, 0x7f, 0x2c, 0x91, 0xbe, 0x5d, 0x60, 0x84, 0xa1, 0xc3, 0xf7, 0xe2, 0x9b, 0x4d,
        0x68, 0x50, 0x1f, 0x8a, 0x4c, 0x62, 0xe9, 0xb0, 0xd7, 0x35, 0x77, 0x0a, 0xd3, 0x96,
        0x42, 0xcb, 0x18, 0xef,
    ]
    .iter()
    .enumerate()
    {
        key[i] = *b;
    }
    let nonce: [u8; 12] = [
        0x5c, 0x8e, 0x21, 0xa9, 0x4d, 0x7f, 0x0b, 0x36, 0xc1, 0xa2, 0xd4, 0x66,
    ];
    if sakura_ritsuki(&key, &nonce, 1) != pins::KAT_CHACHA {
        return false;
    }
    let kat_msg: [u8; 8] = [0x8d, 0x21, 0xc4, 0x9f, 0x57, 0x0e, 0xb3, 0x6a];
    if rindou_mikoto(&kat_msg) != pins::KAT_SHA256 {
        return false;
    }
    // （既有审计结论）：KAT 输入取随机形（与 native_build._KAT_HKDF_* 逐字一致），
    // 原 'salt-fixed-01' 系字面量是原语确认通道
    let prk = joe_rikiichi(
        b"\x9f\x2c\x7a\x41\xd8\xe6\x3b\x05",
        b"\xc4\xe1\xa8\xf2\xb6\x7d\x09\x35\xad\x41\xc2\xf8",
    );
    if machita_chima(&prk, b"\x73\xbd\x9e\x4c", 32) != pins::KAT_HKDF {
        return false;
    }
    if blake2s::sister_claire(&[], &kat_msg) != pins::KAT_BLAKE2S {
        return false;
    }
    true
}

// ---------- CPUID x86-64-v2 门槛（leaf 1 ECX：SSE3/SSSE3/CMPXCHG16B/SSE4.1/SSE4.2/POPCNT） ----------
#[cfg(target_arch = "x86_64")]
pub fn yaguruma_rine() -> bool {
    // __cpuid 在现行工具链已是安全函数
    let r = std::arch::x86_64::__cpuid(1);
    let ecx = r.ecx;
    ecx & 1 != 0
        && ecx & (1 << 9) != 0
        && ecx & (1 << 13) != 0
        && ecx & (1 << 19) != 0
        && ecx & (1 << 20) != 0
        && ecx & (1 << 23) != 0
}

#[cfg(not(target_arch = "x86_64"))]
pub fn yaguruma_rine() -> bool {
    true
}

// ---------- D-3 守卫（§8，拖延档定位：非边界、抬升≈0，如实标注） ----------
// 自身完整性摘要槽：post-link patcher（d_side/builder/patcher.py）把**在场节 keyed
// 摘要**（旧口径是无键 blake2s(.text)）就地写入本节（占位非零——零内容会被
// ICF 同内容合并、无引用会被 CGU 整节弃置，任一都让槽节消失）——摘要绝不写回被盖节
// 本体（§8：写回即自我指涉）。运行期对文件自解析重算比对。

#[link_section = ".v0"]
static SELF_DIGEST_SLOT: [u8; 32] = [0xD3; 32];

/// 完整性密钥 —— 与 `patcher.kaida_haru` 逐字同式：
/// `HKDF-Expand(HKDF-Extract(salt="", ikm=nonce), info="integ", L=32)`。
/// nonce 取头部前 25 B 内的 `head[13..25]`：它由 pins 携带，**外部密钥档只置零 seed**，
/// 所以两种模式都能自校验；摘要与载荷密钥不同 PRK，域分离靠 info 标签
///
pub fn sorahoshi_kirame() -> Vec<u8> {
    let nonce = &pins::HEAD_PREFIX[13..25];
    let prk = joe_rikiichi(b"", nonce);
    // +（既有审计结论）：INTEG_KEY 的 HKDF info 标签由 "integ" 改中性短码
    // （与 vm.rs 域分离标签同批中性化；改值即新代际）
    machita_chima(&prk, b"i8", 32)
}

/// 早期轮次 2.1：守卫快照解码——blake2s 计数器 keystream XOR，构建期
/// `_guard_encode` 的自逆。键材料（域 ‖ INTEG_KEY）与 `_guard_stream_key` 逐字一致。
fn guard_decode(enc: &[u8]) -> Vec<u8> {
    // 早期轮次 2.4：域串中性化（b"dk1"/b"ks1"，与 native_build._guard_* 双端同式）
    // 早期轮次 步骤 3：键材料从 seed‖nonce 改为**只由 nonce 派生的 INTEG_KEY**——
    // 旧形把真实 seed 明文钉在外钥档产物的 .rdata 里， 当场失效

    let integ = sorahoshi_kirame();
    let mut key_material = Vec::with_capacity(3 + integ.len());
    key_material.extend_from_slice(b"dk1");
    key_material.extend_from_slice(&integ);
    let key = joe_rikiichi(&key_material, b"");
    let mut out = Vec::with_capacity(enc.len());
    let mut i = 0usize;
    while i < enc.len() {
        let mut counter = Vec::with_capacity(3 + 32 + 8);
        counter.extend_from_slice(b"ks1");
        counter.extend_from_slice(&key);
        counter.extend_from_slice(&(i as u64).to_le_bytes());
        let ks = joe_rikiichi(&counter, b"");
        for (c, k) in enc[i..(i + 32).min(enc.len())].iter().zip(ks.iter()) {
            out.push(c ^ k);
        }
        i += 32;
    }
    out
}

/// 早期轮次 2.2：诊断通道已移除——产物不再读取任何环境变量（外部分析者解出
/// GUARD_DEBUG 字面名并做 20 种注入测绘的面归零）。诊断/桶码输出只存在于
/// 探针构建（`pins::DIAGNOSTIC`，经 pins_override 注入；生产恒 false）。
/// 拒绝出口恒静默 exit(3)（§6「拒绝即静默」）
fn guard_diagnostic() -> bool {
    pins::DIAGNOSTIC
}

/// 守卫拒绝出口：默认静默 exit(3)（§6「拒绝即静默」），诊断模式下只打印短码本身。
/// 短码不携带语义，语义只在私有解码表（公开面纪律）。
/// 批2-1.2：与 `_exit3` 同一枚确定性时序垫（`REJECT_PAD` 轮 dummy blake2s），
/// 使**所有**拒绝路径都付同一下界代价——原先只有自检失败路径被拉长（面⑥行为钩），
/// 其余拒绝按"读到哪一步失败"计时即可分桶。
fn mayuzumi_kai(reason: &str) -> ! {
    std::hint::black_box(oliver_evans(pins::REJECT_PAD));
    if guard_diagnostic() {
        eprintln!("{}", reason);
    }
    std::process::exit(3);
}

/// 反调试三件套：IsDebuggerPresent / CheckRemoteDebuggerPresent / PEB
/// BeingDebugged（gs:[0x60] → PEB +0x02）。返回 true = 拒绝。
/// fail-closed：API 本身失败同样判不信任（§8 硬要求）。
#[cfg(target_arch = "x86_64")]
fn yorumi_rena() -> bool {
    unsafe {
        if IsDebuggerPresent() != 0 {
            return true;
        }
        let mut remote: i32 = 0;
        if CheckRemoteDebuggerPresent(GetCurrentProcess(), &mut remote) == 0 || remote != 0 {
            return true;
        }
        let peb: *const u8;
        core::arch::asm!("mov {}, gs:[0x60]", out(reg) peb, options(nostack, preserves_flags));
        if peb.is_null() {
            return true;
        }
        *peb.add(2) != 0
    }
}

#[cfg(not(target_arch = "x86_64"))]
fn yorumi_rena() -> bool {
    false
}

/// 可疑模块枚举：Toolhelp 模块快照，模块基名按**前缀精确表**匹配（早期轮次
/// 修正口径：不做任意子串匹配，合法依赖不被误杀）。快照/首枚举失败一律
/// fail-closed（与 layout.json d3_guards.failure_semantics 口径一致）。
fn kagami_hayato() -> bool {
    // 拖延档如实标注：只对知名注入/调试工具族抬升随手 attach 的成本
    const DENY_PREFIX: [&str; 7] = [
        "frida", "x64dbg", "x32dbg", "x96dbg", "cheatengine", "detours", "sbiedll",
    ];
    unsafe {
        let snap = CreateToolhelp32Snapshot(_TH32CS_SNAPMODULE, 0);
        if snap as isize == -1 {
            return true;
        }
        let mut e: ModuleEntryW = std::mem::zeroed();
        e.dw_size = std::mem::size_of::<ModuleEntryW>() as u32;
        if Module32FirstW(snap, &mut e) == 0 {
            // 首枚举失败 = 快照态不可信：静默放行会与 fail-closed 纪律相反
            // （0.0.40 审查）
            CloseHandle(snap);
            return true;
        }
        let mut hit = false;
        loop {
            let len = e.sz_module.iter().position(|&c| c == 0).unwrap_or(256);
            let name = String::from_utf16_lossy(&e.sz_module[..len]).to_lowercase();
            if DENY_PREFIX.iter().any(|d| name.starts_with(d)) {
                hit = true;
                break;
            }
            if Module32NextW(snap, &mut e) == 0 {
                break;
            }
        }
        CloseHandle(snap);
        hit
    }
}

/// 自身完整性·解析（批2-1.1 拆分）：读自身文件 → 走节表 → 产出
/// `(覆盖字节, .v0 槽前 32 B, 几何纯度)`。任何读取/解析失败 → `None`，
/// 两枚子检查同判 fail-closed（与拆分前 `!ars_almal()` 的整体拒绝等价）。
/// 纯度 = 槽节在场且 ≥32 B 且尾部全零 **且** `.text` 在场、≥64 B、真的进了覆盖集
/// ——即 patcher 两条前置的镜像（layout.json d3_guards.self_digest.prerequisites）。
/// 拆成两枚的理由：槽纯度与节摘要**语义独立、失败后果同构**（同一条静默 exit 3），
/// 于是可以进入顺序置换；一次解析供两处，不重复读 13 MB。
fn shikinagi_akira() -> Option<(Vec<u8>, [u8; 32], bool)> {
    let path = match std::env::current_exe() {
        Ok(p) => p,
        Err(_) => return None,
    };
    let blob = match std::fs::read(&path) {
        Ok(b) => b,
        Err(_) => return None,
    };
    if blob.len() < 0x40 || blob[0..2] != [0x4D, 0x5A] {
        return None;
    }
    let pe = u32::from_le_bytes(blob[0x3C..0x40].try_into().unwrap()) as usize;
    if pe + 24 > blob.len() || blob[pe..pe + 4] != [0x50, 0x45, 0x00, 0x00] {
        return None;
    }
    let num = u16::from_le_bytes(blob[pe + 6..pe + 8].try_into().unwrap()) as usize;
    let opt = u16::from_le_bytes(blob[pe + 20..pe + 22].try_into().unwrap()) as usize;
    let table = pe + 24 + opt;
    let (mut text, mut slot) = (None, None);
    let mut text_covered = false;
    // 覆盖集 = 节表顺序上所有**在场**节的 raw bytes（跳过 .v0 槽自身，
    // .reloc 含入）——与 patcher._covered_image 同式同序。旧口径只盖 .text，
    // .rdata（字符串池/标签/错误串）与 .rsrc（RCDATA 载荷、版本资源）裸奔，
    // f 已实测"改代码 + 重算无键摘要"走通
    // 注：覆盖集的**拼接顺序**仍是节表顺序，不参与顺序置换——那是双端同式的数据
    // 不变量（改它要 patcher 与 boot 同时升版），本批置换的只是"哪枚检查先跑"。
    let mut covered: Vec<u8> = Vec::with_capacity(blob.len());
    for i in 0..num {
        let base = table + 40 * i;
        if base + 40 > blob.len() {
            return None;
        }
        let name = blob[base..base + 8]
            .iter()
            .take_while(|&&c| c != 0)
            .map(|&c| c as char)
            .collect::<String>(); // 首 NUL 截断（与 patcher.py 对镜统一）
        let rsize = u32::from_le_bytes(blob[base + 16..base + 20].try_into().unwrap()) as usize;
        let rptr = u32::from_le_bytes(blob[base + 20..base + 24].try_into().unwrap()) as usize;
        if rptr.checked_add(rsize).map(|e| e > blob.len()).unwrap_or(true) {
            return None;
        }
        match name.as_str() {
            ".text" => text = Some((rptr, rsize)),
            ".v0" => slot = Some((rptr, rsize)),
            _ => {}
        }
        if name == ".v0" || rptr == 0 || rsize == 0 {
            continue;   // 槽节不参与（自我指涉）；不在场节无 raw 内容可读
        }
        if name == ".text" {
            text_covered = true;
        }
        covered.extend_from_slice(&blob[rptr..rptr + rsize]);
    }
    let (sptr, ssize) = match slot {
        Some(v) if v.1 >= 32 => v,
        _ => return None,
    };
    let mut slot32 = [0u8; 32];
    slot32.copy_from_slice(&blob[sptr..sptr + 32]);
    let pure = !blob[sptr..sptr + ssize].iter().skip(32).any(|&b| b != 0)   // 槽尾洁净
        && matches!(text, Some(v) if v.1 >= 64) && text_covered && !covered.is_empty();
    Some((covered, slot32, pure))
}

/// 自身完整性·节摘要子检查（与 `patcher._covered_image` 同式）。
/// 槽值必须读自文件本体（post-link patcher 写入的字节）——不能读镜像内
/// 静态：同 crate 不可变静态会被 IPSCCP 折叠回编译期占位值，链接后补丁
/// 对编译器不可见，live 读法对合法产物必然误拒（实测）
fn watarai_hibari(image: &(Vec<u8>, [u8; 32], bool)) -> bool {
    blake2s::sister_claire(&sorahoshi_kirame(), &image.0)[..] == image.1[..]
}

// ---------- 批2-1.1：子检查执行顺序 = 构建期派生置换 ----------
// HKDF 域标签续用中性短码序列（真标签 i1..i9 已占用；A 组提取/展开 i10/i11，
// B 组 i12/i13——与诱饵面④的语义假标签混编同一片人群里）。
const L_PERM_A_SALT: &[u8] = b"i10";
const L_PERM_A_INFO: &[u8] = b"i11";
const L_PERM_B_SALT: &[u8] = b"i12";
const L_PERM_B_INFO: &[u8] = b"i13";
const N_GUARD_CHECKS: usize = 5;
const N_PREDECRYPT_CHECKS: usize = 3;

/// ikm → `0..n` 的确定性置换（Fisher-Yates，游标纪律与 `vm::physmap` 一致：
/// j 先取本轮交换目标，再前进 1，越界回绕）。构建侧镜像 =
/// `native_build.seraph_dazzlegarden`，两侧同式由 `pins::CHECK_SEAL_A/B` 钉住：
/// 任一侧漂移 ⇒ 运行期封印不符 ⇒ 走同一条静默拒绝，所有真跑用例当场致死。
/// 诚实边界：封印**不是**保密量——持产物者可枚举 n! 个置换撞它（120/6 种）。
/// 它的用途是双端一致性齿；顺序的价值在于"静态代码里读不出直线序列"，
/// 不在于把顺序当秘密。
fn fura_kanato(ikm: &[u8], salt: &[u8], info: &[u8], n: usize) -> Vec<usize> {
    let prk = joe_rikiichi(salt, ikm);
    let stream = machita_chima(&prk, info, n * 4 + 4);
    let mut order: Vec<usize> = (0..n).collect();
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

/// 置换 → 16 B 封印（keyed blake2s，key = INTEG_KEY；消息 = 置换字节 ‖ 枚数）。
fn amagi_yuni(order: &[usize], n: usize) -> [u8; 16] {
    let mut msg: Vec<u8> = order.iter().map(|&x| x as u8).collect();
    msg.push(n as u8);
    let mut seal = [0u8; 16];
    seal.copy_from_slice(&blake2s::sister_claire(&sorahoshi_kirame(), &msg)[..16]);
    seal
}

/// 守卫 1a 编排（§6：原生层守卫先于一切）。GUARDS 钉关闭时整体跳过；
/// GUARD_FAULT 为构建期故障注入（测试齿，生产恒 0）：1=调试器 2=模块
/// 3=自身完整性（纯度与节摘要两枚同判），走与真实命中完全相同的拒绝路径。
/// 批2-1.1：**五枚语义独立、失败后果同构**（一律静默 exit 3，且全部在任何密钥
/// 材料被读取之前）的子检查——反调试 / 模块枚举 / 槽纯度 / 节摘要 / DLL 钉——
/// 执行顺序 = nonce 派生置换。红线由**分组**而非组内序号保证：A 组整体先于
/// `ex_albio` 与密钥派生，B 组（`debidebi_debiru`）整体先于外层解密，
/// 所以"MAC 先于解密"这条 早期轮次 教训内的不变量与置换无关。
/// 面⑥收尾（批2-4.4）：诱饵链痕迹长度里加一项**运行期输入派生量**。
/// 只取 argv 的**项数**（不看内容、绝不碰 stdin——读 stdin 会把交互式启动挂在
/// EOF 上，那是真实行为分叉，与的 `input_on` 判据同源）。效果：同一个格子
/// 在不同调用形态下，"自检失败到底算了多久"不再是常数，删除实验与模糊测试
/// 都拿不到干净的时长基线。
fn argv_trace_extra() -> u32 {
    let n = std::env::args().count() as u32;
    (n % 8) * 256
}

fn aiba_uiha() {
    if !pins::GUARDS {
        return;
    }
    let order = fura_kanato(&pins::HEAD_PREFIX[13..25], L_PERM_A_SALT,
                            L_PERM_A_INFO, N_GUARD_CHECKS);
    if amagi_yuni(&order, N_GUARD_CHECKS) != pins::CHECK_SEAL_A {
        mayuzumi_kai("E-114");
    }
    let image = shikinagi_akira();
    for &k in order.iter() {
        match k {
            0 => if pins::GUARD_FAULT == 1 || yorumi_rena() { mayuzumi_kai("E-05"); },
            1 => if pins::GUARD_FAULT == 2 || kagami_hayato() { mayuzumi_kai("E-06"); },
            2 => if pins::GUARD_FAULT == 3 || !image.as_ref().map_or(false, |t| t.2) {
                std::hint::black_box(oliver_evans(
                    pins::FACE_STEPS.saturating_add(argv_trace_extra())));
                mayuzumi_kai("E-07");
            },
            3 => if pins::GUARD_FAULT == 3 || !image.as_ref().map_or(false, watarai_hibari) {
                std::hint::black_box(oliver_evans(
                    pins::FACE_STEPS.saturating_add(argv_trace_extra())));
                mayuzumi_kai("E-07");
            },
            _ => kingyozaka_meiro(),
        }
    }
}

/// `pythonXY.dll` 做实蜜罐（D-3 层，守卫默认静默）。
///
/// `DLL_DIGEST` 钉在场时，exe 同目录的那颗 DLL 必须逐字节等于钉值——**缺席、改名、
/// 换零、代理 DLL**（既有审计的四类实验）从此
/// 一律致死；构建期解析不到 canonical DLL 时发射全零钉 = 蜜罐关闭（feature 可退化）。
/// 与构建侧 `native_build._dll_honeypot_digest` 同式：`blake2s(key=INTEG_KEY, dll)`。
/// 文件名由 pins 的 py_minor 两字节现拼，产物里不出现完整 DLL 名串。
fn kingyozaka_meiro() {
    if pins::DLL_DIGEST.iter().all(|&b| b == 0) {
        return;
    }
    let dll_name = format!("python{}{}.dll", pins::HEAD_PREFIX[7], pins::HEAD_PREFIX[8]);
    let exe_dir = match std::env::current_exe().ok().as_ref().and_then(|e| e.parent()) {
        Some(d) => d.to_path_buf(),
        None => mayuzumi_kai("E-02"),
    };
    let blob = match std::fs::read(exe_dir.join(&dll_name)) {
        Ok(b) => b,
        Err(_) => mayuzumi_kai("E-03"),
    };
    if blake2s::sister_claire(&sorahoshi_kirame(), &blob)[..] != pins::DLL_DIGEST[..] {
        mayuzumi_kai("E-04");
    }
}

/// 确定性 blake2s 长链。两个用途共用一条实现，轮数各自钉死：
/// - **面⑥行为钩**（早期轮次 步骤 4）：`aiba_uiha` 的**自身完整性**失败分支先跑
///   `pins::FACE_STEPS`（步数由构建期"在场诱饵量"派生，逐格不同）。删除任一诱饵节
///   ⇒ keyed 摘要失配 ⇒ 先跑完这条链再拒——"证伪=删除"实验从此留下行为痕迹
///   （时长 + 全链内存足迹），但痕迹不透露删了哪一枚，静默拒绝契约（stderr 恒空）
///   一字不破（收口）；
/// - **批2-1.2 时序垫**：`_exit3` / `mayuzumi_kai` 出口前跑 `pins::REJECT_PAD`，
///   使**每条**拒绝路径都付同一下界代价（原先只有自检分支被拉长，其余按"读到哪一步
///   失败"计时即可分桶）。轮数是构建期 (seed, nonce) 派生常量，运行期零随机。
/// 返回值一律 `black_box` 消费，防止 DCE 把整条链当死代码删掉（实测坑）。
fn oliver_evans(steps: u32) -> [u8; 32] {
    let mut acc = [0u8; 32];
    for i in 0..steps {
        acc = blake2s::sister_claire(&acc, &i.to_le_bytes());
    }
    acc
}

// ---------- RCDATA 读取（整型资源 ID 10 = RT_RCDATA，MAKEINTRESOURCE 形态） ----------
pub fn read_rcdata(name: &str) -> Option<Vec<u8>> {
    let cname = CString::new(name).unwrap();
    unsafe {
        let hr = FindResourceA(ptr::null_mut(), cname.as_ptr() as *const u8, 10usize as *const u8);
        if hr.is_null() {
            return None;
        }
        let hg = LoadResource(ptr::null_mut(), hr);
        if hg.is_null() {
            return None;
        }
        let sz = SizeofResource(ptr::null_mut(), hr) as usize;
        if sz == 0 {
            return Some(Vec::new());
        }
        let p = LockResource(hg);
        if p.is_null() {
            return None;
        }
        Some(std::slice::from_raw_parts(p, sz).to_vec())
    }
}

pub fn kuroi_shiba() -> Vec<u8> {
    match read_rcdata("seg0") {
        Some(b) => b,
        None => _exit3("E-08"),
    }
}

// ---------- 密钥重派生（：seed 在场 ⇒ 引导侧现场派生，绝不落盘） ----------
pub fn naruto_kogane(head: &[u8; 57]) -> ([u8; 32], [u8; 32], [u8; 12]) {
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&head[25..57]);
    // （既有安全审计）：sched 是 seed 的纯函数（keys.py 同式），boot 现场
    // 派生——pins 钉子把 seed 低 3 bit 明文写进产物，外部密钥档下构成同钥关联
    // oracle
    let sched = ((seed[31] & 7) % 8) + 1;
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&head[13..25]);
    let prk = joe_rikiichi(&_schedule_salt(&seed, &nonce, sched), &seed);
    let enc = machita_chima(&prk, &[sched, 0x01], 32);
    let mac = machita_chima(&prk, &[sched, 0x02], 32);
    let mut enc32 = [0u8; 32];
    let mut mac32 = [0u8; 32];
    enc32.copy_from_slice(&enc);
    mac32.copy_from_slice(&mac);
    // 本函数自己的那份 seed 拷贝用完即抹（派生结果是 HMAC 输出，不含 seed 明文）
    suo_sango(&mut seed);
    (enc32, mac32, nonce)
}

// ---------- T7 信任锚：PE 版本资源 → Authenticode ----------
// 版本资源四元组 (major, minor, patch, serial) 与 sys.version_info 非线性同构
// （实例：3.12.10 的 DLL 资源是 (3, 12, 10150, 1013)），故按原始值全等钉死；
// Authenticode action GUID 取自 SDK SoftPub.h 的 WINTRUST_ACTION_GENERIC_VERIFY_V2
// （{00AAC56B-CD44-11D0-8CC2-00C04FC295EE}——凭记忆手抄必错）

pub fn warabeda_meiji(path: &std::path::Path) -> Option<[u16; 4]> {
    let wide = wid(path.to_str()?);
    unsafe {
        let size = GetFileVersionInfoSizeW(wide.as_ptr(), ptr::null_mut());
        if size == 0 {
            return None;
        }
        let mut data = vec![0u8; size as usize];
        if GetFileVersionInfoW(wide.as_ptr(), 0, size, data.as_mut_ptr() as *mut c_void) == 0 {
            return None;
        }
        let mut pbuf: *mut c_void = ptr::null_mut();
        let mut len = 0u32;
        let sub = wid("\\");
        if VerQueryValueW(
            data.as_ptr() as *const c_void,
            sub.as_ptr(),
            &mut pbuf,
            &mut len,
        ) == 0
        {
            return None;
        }
        let fi = pbuf as *const u32;
        if *fi != 0xFEEF04BD {
            return None; // VS_FIXEDFILEINFO 魔数（防御纵深；builder 探针侧同检）
        }
        let ms = *fi.add(2); // dwFileVersionMS
        let ls = *fi.add(3); // dwFileVersionLS
        Some([(ms >> 16) as u16, ms as u16, (ls >> 16) as u16, ls as u16])
    }
}

pub fn yuzuki_roa(path: &std::path::Path) -> i32 {
    let wide = match path.to_str() {
        Some(s) => wid(s),
        None => return -1,
    };
    let mut action = Guid {
        data1: 0x00AAC56B,
        data2: 0xCD44,
        data3: 0x11D0,
        data4: [0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE],
    };
    let mut fi = WintrustFileInfo {
        cb_struct: std::mem::size_of::<WintrustFileInfo>() as u32,
        pcwsz_file_path: wide.as_ptr(),
        h_file: ptr::null_mut(),
        pg_known_subject: ptr::null_mut(),
    };
    let mut wd = WintrustData {
        cb_struct: std::mem::size_of::<WintrustData>() as u32,
        p_policy_callback_data: ptr::null_mut(),
        p_sip_client_data: ptr::null_mut(),
        dw_ui_choice: 2,          // WTD_UI_NONE
        fdw_revocation_checks: 0, // WTD_REVOKE_NONE
        dw_union_choice: 1,       // WTD_CHOICE_FILE
        u: WintrustUnion { p_file: &mut fi },
        dw_state_action: 0, // WTD_STATEACTION_IGNORE
        h_wvt_state_data: ptr::null_mut(),
        pwsz_url_reference: ptr::null_mut(),
        dw_prov_flags: 0,
        dw_ui_context: 0,
        p_signature_settings: ptr::null_mut(),
    };
    unsafe { WinVerifyTrust(ptr::null_mut(), &mut action, &mut wd as *mut WintrustData as *mut c_void) }
}

// ---------- B 方案：单文件 home（内嵌资源 → 首启释放 → 逐文件哈希复用） ----------
// 资源 "home"（RT_RCDATA）＝自定义 PHM1 包：magic + u32 条目数 +
// [u16 名长, 名, u64 大小, 32B BLAKE2s, 数据]…。包整体哈希进 pins（.text，自校验
// 覆盖）；释放到 LocalAppData 缓存后按包内逐文件哈希复用；发现漂移即重释放。
// 依赖解析：vcruntime 不再内嵌（微软专有再分发件），pythonXY.dll 的
// VCRUNTIME140(_1) 依赖由系统安装的 VC++ 2015-2022 x64 运行库满足——
// LoadLibraryExW 的 SYSTEM32 搜索面覆盖，缺席时走 E-26 拒绝出口（exe 自身
// 也导入 VCRUNTIME140，缺件时 OS 加载器先行提示）。
const _HOME_CACHE_SUBDIR: &str = "PracticeEncryption";
const _HOME_PACK_MAGIC: [u8; 4] = [0x50, 0x48, 0x4D, 0x31]; // "PHM1"

struct PackEntry {
    name: String,
    size: u64,
    hash: [u8; 32],
    data_at: usize,
}

fn hex16(b: &[u8; 32]) -> String {
    let mut s = String::with_capacity(16);
    for i in 0..8 {
        s.push_str(&format!("{:02x}", b[i]));
    }
    s
}

fn safe_rel_name(n: &str) -> bool {
    !n.is_empty()
        && !n.contains(':')
        && !n.contains('\\')
        && !n.contains("..")
        && n.split('/').all(|p| !p.is_empty() && p != "." && p != "..")
}

fn pack_entries(pack: &[u8]) -> Option<Vec<PackEntry>> {
    if pack.len() < 8 || pack[0..4] != _HOME_PACK_MAGIC {
        return None;
    }
    let count = u32::from_le_bytes(pack[4..8].try_into().ok()?) as usize;
    let mut out = Vec::with_capacity(count);
    let mut off = 8usize;
    for _ in 0..count {
        if off + 2 > pack.len() {
            return None;
        }
        let nlen = u16::from_le_bytes(pack[off..off + 2].try_into().ok()?) as usize;
        off += 2;
        if off + nlen > pack.len() {
            return None;
        }
        let name = match std::str::from_utf8(&pack[off..off + nlen]) {
            Ok(s) => s.to_string(),
            Err(_) => return None,
        };
        off += nlen;
        if !safe_rel_name(&name) || off + 8 + 32 > pack.len() {
            return None;
        }
        let size = u64::from_le_bytes(pack[off..off + 8].try_into().ok()?);
        off += 8;
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&pack[off..off + 32]);
        off += 32;
        if size > (pack.len() - off) as u64 {
            return None;
        }
        out.push(PackEntry { name: name, size: size, hash: hash, data_at: off });
        off += size as usize;
    }
    if off != pack.len() {
        return None;
    }
    Some(out)
}

fn file_matches(path: &std::path::Path, size: u64, hash: &[u8; 32]) -> bool {
    // 先量大小再整读：缓存被替换成超大文件时不至于触发大额分配（本地对抗面加固）。
    match std::fs::metadata(path) {
        Ok(m) if m.is_file() && m.len() == size => {}
        _ => return false,
    }
    match std::fs::read(path) {
        Ok(b) => b.len() as u64 == size && blake2s::sister_claire(&[], &b) == *hash,
        Err(_) => false,
    }
}

fn home_valid(entries: &[PackEntry], home: &std::path::Path) -> bool {
    for e in entries.iter() {
        let p = home.join(e.name.replace('/', "\\"));
        if !file_matches(&p, e.size, &e.hash) {
            return false;
        }
    }
    true
}

fn extract_home(pack: &[u8], entries: &[PackEntry], dest: &std::path::Path) -> bool {
    for e in entries.iter() {
        let data = &pack[e.data_at..e.data_at + e.size as usize];
        let target = dest.join(e.name.replace('/', "\\"));
        if let Some(parent) = target.parent() {
            if std::fs::create_dir_all(parent).is_err() {
                return false;
            }
        }
        if std::fs::write(&target, data).is_err() {
            return false;
        }
        if !file_matches(&target, e.size, &e.hash) {
            return false;
        }
    }
    true
}

/// 缓存根：生产 = KnownFolder(LocalAppData) + 产品子目录；测试齿
/// `HOME_CACHE_ROOT` 非空时**整体替换**（钉子即完整根，不再叠加子目录）。
fn cache_root() -> std::path::PathBuf {
    if !pins::HOME_CACHE_ROOT.is_empty() {
        return std::path::PathBuf::from(pins::HOME_CACHE_ROOT);
    }
    local_appdata().join(_HOME_CACHE_SUBDIR)
}

fn local_appdata() -> std::path::PathBuf {
    let folder = Guid {
        data1: 0xF1B32785,
        data2: 0x6FBA,
        data3: 0x4FCF,
        data4: [0x9D, 0x55, 0x7B, 0x8E, 0x7F, 0x15, 0x70, 0x91],
    };
    let mut pw: *mut u16 = ptr::null_mut();
    unsafe {
        let hr = SHGetKnownFolderPath(&folder, 0, ptr::null_mut(), &mut pw);
        if hr == 0 && !pw.is_null() {
            let mut len = 0usize;
            while *pw.add(len) != 0 {
                len += 1;
            }
            let s = String::from_utf16_lossy(std::slice::from_raw_parts(pw, len));
            CoTaskMemFree(pw as *mut c_void);
            return std::path::PathBuf::from(s);
        }
    }
    match std::env::var("LOCALAPPDATA") {
        Ok(s) if !s.is_empty() => std::path::PathBuf::from(s),
        _ => std::env::temp_dir(),
    }
}

fn prune_old_homes(root: &std::path::Path, current: &std::path::Path) {
    if let Ok(rd) = std::fs::read_dir(root) {
        for ent in rd.flatten() {
            let p = ent.path();
            if p == current {
                continue;
            }
            let is_home = p.file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.starts_with("home-"))
                .unwrap_or(false);
            if is_home {
                let _ = std::fs::remove_dir_all(&p);
            }
        }
    }
}

fn ensure_embedded_home() -> std::path::PathBuf {
    let pack = match read_rcdata("home") {
        Some(b) => b,
        None => _exit3("E-09"),
    };
    let digest = blake2s::sister_claire(&[], &pack);
    if digest != pins::HOME_PACK_HASH {
        _exit3("E-10");
    }
    let entries = match pack_entries(&pack) {
        Some(e) if !e.is_empty() => e,
        _ => _exit3("E-11"),
    };
    let root = cache_root();
    let home = root.join(format!("home-{}", hex16(&digest)));
    if home_valid(&entries, &home) {
        return home;
    }
    if std::fs::create_dir_all(&root).is_err() {
        _exit3("E-12");
    }
    let tmp = root.join(format!("home-{}.tmp-{}", hex16(&digest), std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    if std::fs::create_dir_all(&tmp).is_err() {
        _exit3("E-13");
    }
    if !extract_home(&pack, &entries, &tmp) {
        let _ = std::fs::remove_dir_all(&tmp);
        _exit3("E-14");
    }
    if std::fs::rename(&tmp, &home).is_err() {
        // 并发首启或旧缓存残留：有效者胜出，否则腾位置重放。
        if home_valid(&entries, &home) {
            let _ = std::fs::remove_dir_all(&tmp);
        } else {
            let _ = std::fs::remove_dir_all(&home);
            if std::fs::rename(&tmp, &home).is_err() {
                let _ = std::fs::remove_dir_all(&tmp);
                _exit3("E-15");
            }
        }
    }
    prune_old_homes(&root, &home);
    home
}

/// home 解析：exe 旁 DLL 在场 = 文件夹档快速路径（旧行为原样）；否则若构建期
/// 开启 EMBED_HOME，释放/复用内嵌 home。
fn resolve_home_dir(head: &[u8; 57]) -> std::path::PathBuf {
    let dll_name = format!("python{}{}.dll", head[7], head[8]);
    let exe_dir = match std::env::current_exe().ok().as_ref().and_then(|e| e.parent())
        .map(|d| d.to_path_buf()) {
        Some(d) => d,
        None => _exit3("E-16"),
    };
    if exe_dir.join(&dll_name).is_file() {
        return exe_dir;
    }
    if !pins::EMBED_HOME {
        _exit3("E-17");
    }
    ensure_embedded_home()
}

/// 进程内只解析一次：gundo_mirei 与 seto_miyako 两个调用者共享同一产物头，
/// 重复解析会二次复制 home 包资源并对全部释放文件二次重哈希（热启动实测开销）。
static HOME_DIR_CACHE: std::sync::OnceLock<std::path::PathBuf> =
    std::sync::OnceLock::new();

fn home_dir(head: &[u8; 57]) -> std::path::PathBuf {
    HOME_DIR_CACHE.get_or_init(|| resolve_home_dir(head)).clone()
}

/// T7 一/二/三级：home（exe 旁或内嵌释放缓存）钉死 → 版本资源全等 → Authenticode（按钉强制）。
/// 通过则返回待加载 DLL 的宽字符路径；任一级不过即 exit 3（加载前拒绝）。
pub fn gundo_mirei(head: &[u8; 57]) -> Vec<u16> {
    let dll_name = format!("python{}{}.dll", head[7], head[8]);
    let dir = home_dir(head);
    let cand = dir.join(&dll_name);
    if !cand.is_file() {
        _exit3("E-18");
    }
    match warabeda_meiji(&cand) {
        Some(v) if v == pins::DLL_VERSION => {}
        _ => _exit3("E-19"),
    }
    if pins::REQUIRE_AUTHENTICODE {
        let st = yuzuki_roa(&cand);
        if st != 0 {
            _exit3("E-20");
        }
    }
    // W 低危残项：expect 走 panic（stderr 泄模块路径 + exit 101），改显式
    // _exit3 静默 exit 3
    match cand.to_str() {
        Some(s) => wid(s),
        None => _exit3("E-21"),
    }
}

/// 早期轮次 显式 module_search_paths：`home` = 解析后的 home（exe 旁或内嵌缓存），搜索面 = home 内真实存在的
/// [python312.zip, DLLs, Lib] + home 本体——盘根推导等隐式探针条目全部消失。
/// 偏移来自构建期真头文件现算（kataribe_tsumugu）；越界守卫不过即拒绝启动。
pub fn seto_miyako(cfg: *mut c_void, head: &[u8; 57]) {
    let base = cfg as usize;
    if pins::CFG_SIZEOF == 0
        || pins::CFG_SIZEOF > 8192
        || pins::CFG_OFF_MSSP + 16 > 8192
        || pins::CFG_OFF_HOME + 8 > 8192
        || pins::CFG_OFF_MSSP_SET + 4 > 8192
        || pins::CFG_OFF_SITE_IMPORT + 4 > 8192
    {
        _exit3("E-22");
    }
    // 解释器版本从产物头派生（与 DLL 名同源）——zip 名不再硬编码 3.12（修复）
    let zip_name = format!("python{}{}.zip", head[7], head[8]);
    let dir = home_dir(head);
    let mut entries: Vec<String> = Vec::new();
    let zip = dir.join(&zip_name);
    if zip.is_file() {
        entries.push(zip.to_string_lossy().into_owned());
    }
    entries.push(dir.to_string_lossy().into_owned());
    for sub in ["DLLs", "Lib"].iter() {
        let p = dir.join(sub);
        if p.is_dir() {
            entries.push(p.to_string_lossy().into_owned());
        }
    }
    unsafe {
        // 进程期存活的分配：配置在 init_cfg 消费后仍被解释器引用
        let alloc = |s: &str| -> *mut u16 {
            let mut wide = wid(s);
            wide.push(0);
            let bytes = wide.len() * 2;
            let p = LocalAlloc(_LMEM_FIXED_ZERO, bytes) as *mut u16;
            if p.is_null() {
                _exit3("E-23");
            }
            ptr::copy_nonoverlapping(wide.as_ptr(), p, wide.len());
            p
        };
        let home_w = match dir.to_str() {
            Some(s) => alloc(s),
            None => _exit3("E-24"),
        };
        let items = LocalAlloc(_LMEM_FIXED_ZERO, entries.len() * 8) as *mut *mut u16;
        if items.is_null() {
            _exit3("E-25");
        }
        for (i, s) in entries.iter().enumerate() {
            *items.add(i) = alloc(s);
        }
        ((base + pins::CFG_OFF_HOME) as *mut *mut u16).write(home_w);
        ((base + pins::CFG_OFF_MSSP_SET) as *mut i32).write(1);
        // Py_ssize_t（8B）为 CPython 3.12 x64 的实测宽度——字段宽度绑定 3.12，
        // T7 的 DLL 版本钉使升级必然伴随重验（注记）
        ((base + pins::CFG_OFF_MSSP) as *mut i64).write(entries.len() as i64);
        ((base + pins::CFG_OFF_MSSP + 8) as *mut *mut *mut u16).write(items);
        // site.py 会在显式列表之后追加 site-packages（pathconfig 地标可能把
        // prefix 解析回盘根）——密封产物关掉 site 语义，追加面归零
        ((base + pins::CFG_OFF_SITE_IMPORT) as *mut i32).write(0);
    }
}

// ---------- CPython 嵌入执行 ----------
pub fn tsukimi_shizuku(head: &[u8; 57], marshal: &[u8]) {
    let target = gundo_mirei(head);
    unsafe {
        // LOAD_LIBRARY_SEARCH_DEFAULT_DIRS：绝对路径加载下与 SYSTEM32 语义等效
        // （规格文本写 SYSTEM32——绝对路径加载体内两者不可区分，注释统一口径）
        let h = LoadLibraryExW(target.as_ptr(), ptr::null_mut(), 0x0000_1000);
        if h.is_null() {
            _exit3("E-26");
        }
        let init_iso: InitIsolated = std::mem::transmute(proc_addr(h, "PyConfig_InitIsolatedConfig"));
        let set_argv: SetBytesArgv = std::mem::transmute(proc_addr(h, "PyConfig_SetBytesArgv"));
        let init_cfg: InitFromConfig = std::mem::transmute(proc_addr(h, "Py_InitializeFromConfig"));
        let add_module: AddModule = std::mem::transmute(proc_addr(h, "PyImport_AddModule"));
        let get_dict: GetDict = std::mem::transmute(proc_addr(h, "PyModule_GetDict"));
        let marshal_loads: MarshalLoads = std::mem::transmute(proc_addr(h, "PyMarshal_ReadObjectFromString"));
        let eval_code: EvalCode = std::mem::transmute(proc_addr(h, "PyEval_EvalCode"));
        let err_occurred: ErrOccurred = std::mem::transmute(proc_addr(h, "PyErr_Occurred"));
        let err_print: ErrPrint = std::mem::transmute(proc_addr(h, "PyErr_Print"));
        let finalize: Finalize = std::mem::transmute(proc_addr(h, "Py_FinalizeEx"));
        let mut cfg = vec![0u8; 8192];
        init_iso(cfg.as_mut_ptr() as *mut c_void);
        if pins::EXPLICIT_PATHS {
            seto_miyako(cfg.as_mut_ptr() as *mut c_void, head);
        }
        // --key-file 及其值不进载荷的 sys.argv（boot 旗标对载荷不可见）
        let raw_args: Vec<String> = std::env::args().collect();
        let mut argv: Vec<CString> = Vec::with_capacity(raw_args.len());
        let mut skip_next = false;
        for (i, a) in raw_args.iter().enumerate() {
            if skip_next {
                skip_next = false;
                continue;
            }
            if i > 0 && a == "--key-file" {
                skip_next = true;
                continue;
            }
            argv.push(CString::new(a.as_str()).unwrap());
        }
        let mut argvp: Vec<*mut c_char> = argv.iter().map(|a| a.as_ptr() as *mut c_char).collect();
        let st = set_argv(cfg.as_mut_ptr() as *mut c_void, argvp.len() as isize, argvp.as_mut_ptr());
        if st._type != 0 {
            _exit3("E-27");
        }
        let st = init_cfg(cfg.as_mut_ptr() as *mut c_void);
        if st._type != 0 {
            _exit3("E-28");
        }
        // 1b Python 层守卫（§6：必须在初始化之后、载荷之前）。快照只用 sys、
        // 不 import os——隔离启动下 os 本不在 sys.modules，导入它会制造可观测
        // 分叉。命中路径 raise SystemExit(3)：PyErr_Print 语义内直接以 3 退出、
        // 无回溯；其余异常 = 检查过程本身失败 → fail-closed。
        if pins::GUARDS {
            if pins::GUARD_FAULT == 4 {
                mayuzumi_kai("E-29");
            }
            let run_simple: RunSimple = std::mem::transmute(proc_addr(h, "PyRun_SimpleString"));
            // 早期轮次 2.1：守卫快照密文态解码——blake2s 计数器 keystream，
            // 与构建期 _guard_encode 同式（自逆）。明文只存在于堆上局部缓冲，
            // 产物无明文
            let snippet: Vec<u8> = if guard_diagnostic() {
                guard_decode(&pins::PY_GUARD_DIAG_ENC)
            } else {
                guard_decode(&pins::PY_GUARD_ENC)
            };
            // W 低危残项同口径：快照是构建期钉死的守卫源，正常无内嵌 NUL；万一被改坏
            // 宁可 fail-closed 静默 exit 3，不走 panic
            let c = match CString::new(snippet) {
                Ok(c) => c,
                Err(_) => mayuzumi_kai("E-30"),
            };
            if run_simple(c.as_ptr()) != 0 {
                mayuzumi_kai("E-30");
            }
        }
        // v1 阴性对照齿：放在 python DLL 已加载、marshal 明文仍在本进程手里的那一刻
        // （`plain` 活着、DLL 镜像已映射）——两个对照证据同时成立，才算证明抓取有齿。
        // 放在 LoadLibrary 之前会只看见 marshal、看不见 DLL 镜像（实测踩到）。
        if pins::VM_VISIBILITY_PROBE {
            visprobe::hold("m1");
        }
        let code = marshal_loads(marshal.as_ptr() as *const c_char, marshal.len() as isize);
        if code.is_null() {
            _exit3("E-31");
        }
        let main_mod = add_module(CString::new("__main__").unwrap().as_ptr());
        let globals = get_dict(main_mod);
        let _ = eval_code(code, globals, globals);
        //  修复（早期轮次）：载荷的异常/退出码必须传播——此前 `let _ = eval_code`
        // 让 sys.exit(n) 或未捕获异常的产物仍以 0 退出，与解释器语义分叉。
        // SystemExit(n) 由 PyErr_Print 按 CPython 语义直接以 n 结束进程；
        // 其余异常打印回溯后以 1 退出（与 `python file.py` 一致）。
        if !err_occurred().is_null() {
            err_print();
            let _ = finalize(ptr::null_mut()); // 冲刷 stdout 后再退出
            std::process::exit(1);
        }
        let _ = finalize(ptr::null_mut());
    }
}

fn _hex_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        out.push(u8::from_str_radix(&s[i..i + 2], 16).ok()?);
    }
    Some(out)
}

/// 早期轮次 Phase 2（关）：把进程输入折成两枚窗口，**全部形态参数来自本格契约**。
///
/// 上一代这里的一切都是字面常量：跳过 argv[0]、剥掉空格式 `--key-file` 一对、以
/// `0x00` 连接、项数 ≤ 64、扁平长度 ≤ 64 B、stdin ≤ 64 B。多次独立审计互不知情却
/// 还原出同一份契约——读一次用八格、跨代还能用。现在这七个量全部来自构建期派生
/// （`pins::IFACE_*`，出处 native_build.koyanagi_rou），运行期零随机。
///
/// - 调用方只在**头部 flags 位 5 置位**（载荷声明消费进程输入）时才走到这里：没置位
///   的产物 IR 里既没有 ARGV 也没有 STDIN，窗折出来没人读，却会因 argv[0] 超长把产品
///   自己拒在启动阶段——所以那条路径不折窗，也不读 stdin（读会把交互式启动挂在 EOF 上，
///   那是一条真实的行为分叉）；
/// - 超任一上限一律 None → 调用方走桶码，**不静默截断**：截断会让"程序看到的输入"
///   与验收方给出的不一致，那是比拒绝更贵的失败。
///
/// 诚实边界：①Windows 下 `std::env::args()` 走 lossy UTF-8，未配对代理项会变 U+FFFD，
/// 与 CPython 对同一 argv 的编码在极端字符上可能分叉——产物输入表因此只用 ASCII 与
/// 常见 UTF-8；②"不剥 key-file"的格子把路径留在载荷可见窗里，这些格的输出因此
/// 随密钥文件路径变化，验收侧必须按本格契约供钥并记录同一串 argv。
fn amagase_muyu() -> Option<(Vec<u8>, Vec<u8>)> {
    let args: Vec<String> = std::env::args().collect();
    let (strip_space, strip_equals) = iface_strips();
    let mut items: Vec<&String> = Vec::new();
    if pins::IFACE_ARGV0 {
        if let Some(a0) = args.first() {
            items.push(a0);
        }
    }
    let mut i = 1usize;
    while i < args.len() {
        let a = args[i].as_str();
        if strip_space && a == "--key-file" {
            i += 2;
            continue;
        }
        if strip_equals && a.starts_with("--key-file=") {
            i += 1;
            continue;
        }
        items.push(&args[i]);
        i += 1;
    }
    if items.len() > pins::IFACE_ARG_MAX {
        return None;
    }
    let sep = iface_join();
    let mut flat: Vec<u8> = Vec::new();
    for (k, it) in items.iter().enumerate() {
        flat.extend_from_slice(it.as_bytes());
        if sep.is_some() && k + 1 < items.len() {
            flat.push(sep?);
        }
    }
    if flat.len() > pins::IFACE_AP {
        return None;
    }
    let mut stdin_v: Vec<u8> = Vec::new();
    use std::io::Read;
    if std::io::stdin().read_to_end(&mut stdin_v).is_err() {
        return None;
    }
    if stdin_v.len() > pins::IFACE_SP {
        return None;
    }
    Some((flat, stdin_v))
}

/// 运行时读取 32 B 外部密钥。--key-file <path> 优先（32 B 裸字节或
/// 64 字符 hex），其次 EXE_SEED 环境变量（64 字符 hex）——早期轮次 2.4 中性化
/// （原名含项目身份前缀）。
pub fn ex_albio() -> [u8; 32] {
    let args: Vec<String> = std::env::args().collect();
    let mut raw: Vec<u8> = Vec::new();
    let mut have = false;
    let mut i = 1;
    while i < args.len() {
        if args[i] == "--key-file" {
            if let Some(p) = args.get(i + 1) {
                match std::fs::read(p) {
                    Ok(b) => {
                        raw = b;
                        have = true;
                    }
                    Err(_) => _exit3("E-32"),
                }
            }
            break;
        }
        i += 1;
    }
    if !have {
        match std::env::var("EXE_SEED") {
            Ok(h) => match _hex_decode(&h) {
                Some(b) => raw = b,
                None => _exit3("E-33"),
            },
            Err(_) => _exit3("E-34"),
        }
    }
    let mut out = [0u8; 32];
    if raw.len() == 64 {
        if let Some(b) = _hex_decode(std::str::from_utf8(&raw).unwrap_or("")) {
            if b.len() == 32 {
                out.copy_from_slice(&b);
                suo_sango(&mut raw);
                return out;
            }
        }
    }
    if raw.len() != 32 {
        suo_sango(&mut raw);
        _exit3("E-35");
    }
    out.copy_from_slice(&raw);
    // 读进来的那份（32 B 裸 key 文件 = seed 本体）不留 freed heap——早期轮次 步骤 3
    // 内存自证的前提之一
    suo_sango(&mut raw);
    out
}

// ---------- 早期轮次 批2-4.3（设计方案 §3.3）：死路径伪装 ----------

// 需求原文："boot 内逻辑可达、行为学等价的曲线运算死路径（~8KB 预算），消费
// SIKE 诱饵块但不影响主流程"。§3.1 的 SIKE 诱饵块由另一条探针线在产、本批没接
// 进产物，面⑤的三条假链也仍默认关，所以这里消费的是一块**恒在场**的诱饵：
// 面①的伪容器节 `.v3`（64 B 假根块头 + 1 KB PRF 体，`decoy_faces.nishizono_chigusa`，
// 构建侧经 `pins::DEADPATH_FEED` 把同一节字节交给这里）。域参数按公开曲线的
// "域参数清单"长相从**固定偏移**取——取到什么算什么。

// 算的是什么（两条腿，全是 Montgomery 形 GF(p) 算术，CIOS）：
//  ①群运算腿（E1: y² = x³ + a x + b）：判别式 Δ = −16(4a³+27b²) 的奇异性见证 →
//    清单里声明的 G 是否在 E1 上 → 拿清单的 "n" 槽当标量做定长 Jacobian 梯形，
//    并检验 [n]G ≟ O（SEC1 域参数校验的常规三件，一件都不求逆）；
//  ②等源腿（E2: y² = x³ + A x² + B x，SIDH/SIKE 一侧公钥本来就是"A + 一组射影
//    x 坐标"这个长相）：拿①的射影输出当起点走定长 2-等源链，
//    (A,B) → (−2A, A²−4B)，x 按 (x:z) → (x²+Bz² : xz) 推进。
// 两条腿的结果折成一枚 keyed blake2s "收据"后丢弃。

// 三条纪律（由调用点 + `tests/d_side/test_deadpath.py` 钉死，不由"看起来像"承担）：
//  ①**可达**：唯一入口 `lunlun` 挂在 `debidebi_debiru` 的主流程上，进入条件是
//    运行期装载的头部字节与资源长度（不是源码字面量），反汇编在这里看到的是一条
//    活调用点；`pins::DEADPATH` 关闭时整段被常量折叠剪掉（off 臂可测）。
//  ②**不可观察**：不写任何通道、不改退出码、段内**没有任何拒绝出口**——拒绝通道
//    的"唯一出口"性质不许被死路径新增一类（诱饵内容不合格 ⇒ 只是少跑几条边）。
//    返回值一律在调用点被 `std::hint::black_box` 丢弃（与 `oliver_evans` 同一条
//    纪律：不 black_box 就被 DCE 整段删掉，尺寸消融当场测不出东西）。
//  ③**零随机 + seed 不在场**：标量/基/折叠键全是构建期 (seed, nonce) 的确定性派生，
//    HKDF 的 ikm 取 **MAC 钉 ‖ nonce**（与 B 组置换同式），**绝不**把裸 seed 喂进
//    新 HKDF（早期轮次 步骤 3 内存自证红线）；自建临时缓冲用完一律 `suo_sango` 覆零。

// 诚实定位（与 layout.json `deadpath` 记录同口径）：**拖延档、非边界**。它买到的
// 只是"静态读者多读一遍一段像模像样的曲线算术 + 一条活调用点"，删掉它行为一字
// 不变；先确定"运行期真正消费哪一节字节"的分析师照样能识破。不写"挡住某类攻击"。

/// 域参数在 `.v3` 里的固定偏移（`nishizono_chigusa` 的字节布局：0..64 假根块头、
/// 26..58 是"密钥字段"位、64 起是 1024 B PRF 体）。p 取那个"看起来最像密钥"的
/// 槽位正是本意——读诱饵的人第一眼会把它当成曲线侧的私料去解。
const _DP_OFF_P: usize = 26;
const _DP_OFF_A: usize = 64;
const _DP_OFF_B: usize = 96;
const _DP_OFF_GX: usize = 128;
const _DP_OFF_GY: usize = 160;
const _DP_OFF_N: usize = 192;
const _DP_OFF_BIGA: usize = 224;
const _DP_OFF_BIGB: usize = 256;
const _DP_FEED_MIN: usize = 288;
/// 梯形窗口宽度的值域（构建期从派生流取，逐格不同；时长只差常数，不给时序面
/// 添新的可分叉点）与 2-等源行走的步数值域。
const _DP_STEPS: u32 = 112;
const _DP_WALK: u32 = 4;
/// 死路径自己的中性域分离标签：续 `i1..i9`（真层级）与 `i10..i15`（守卫顺序
/// 置换 A/B、变体选择、dispatch 槽位置换）之后的 `i16`/`i17`。
const L_DP_SALT: &[u8] = b"i16";
const L_DP_INFO: &[u8] = b"i17";

const _DP_ZERO: [u64; 4] = [0u64; 4];

/// 模 p 域（Montgomery 形）。`p` 由 `sakaki_ness` 归一化成"2^255 ≤ p < 2^256 且
/// 为奇"：诱饵字节是什么不重要，重要的是每条分支都**定义良好**——不除零、不空转、
/// 不越界、不 panic（panic 会被 hook 成 exit 3，那等于给死路径新增可观察行为）。
#[derive(Clone, Copy)]
struct DpField {
    p: [u64; 4],
    np: u64,
    r2: [u64; 4],
    one: [u64; 4],
}

/// Jacobian 射影点（三个坐标全在 Montgomery 域里）。
#[derive(Clone, Copy)]
struct DpPoint {
    x: [u64; 4],
    y: [u64; 4],
    z: [u64; 4],
}

/// 域参数清单 + Montgomery 形预计算。E1: y² = x³ + a x + b 走群运算腿，
/// E2: y² = x³ + A x² + B x 走等源腿（SIDH/SIKE 一侧公钥本来就是"A + x 坐标"
/// 这个长相，所以第二条腿只要 x）。
#[derive(Clone, Copy)]
struct DpDomain {
    f: DpField,
    a_m: [u64; 4],
    b_m: [u64; 4],
    gx_m: [u64; 4],
    gy_m: [u64; 4],
    big_a_m: [u64; 4],
    big_b_m: [u64; 4],
    k: [u64; 4],
    steps: u32,
    walk: u32,
}

#[inline(never)]
fn _dp_bit(x: &[u64; 4], i: usize) -> u64 {
    (x[i / 64] >> (i % 64)) & 1
}

#[inline(never)]
fn _dp_eq(a: &[u64; 4], b: &[u64; 4]) -> bool {
    (a[0] ^ b[0]) | (a[1] ^ b[1]) | (a[2] ^ b[2]) | (a[3] ^ b[3]) == 0
}

#[inline(never)]
fn _dp_ge(a: &[u64; 4], b: &[u64; 4]) -> bool {
    for i in (0..4).rev() {
        if a[i] != b[i] {
            return a[i] > b[i];
        }
    }
    true
}

#[inline(never)]
fn _dp_add(x: &[u64; 4], y: &[u64; 4]) -> ([u64; 4], u64) {
    let mut o = [0u64; 4];
    let mut carry = 0u128;
    for i in 0..4 {
        let s = x[i] as u128 + y[i] as u128 + carry;
        o[i] = s as u64;
        carry = s >> 64;
    }
    (o, carry as u64)
}

#[inline(never)]
fn _dp_sub(x: &[u64; 4], y: &[u64; 4]) -> ([u64; 4], u64) {
    let mut o = [0u64; 4];
    let mut borrow = 0u64;
    for i in 0..4 {
        let (d1, b1) = x[i].overflowing_sub(y[i]);
        let (d2, b2) = d1.overflowing_sub(borrow);
        o[i] = d2;
        borrow = (b1 as u64) | (b2 as u64);
    }
    (o, borrow)
}

/// 大端 32 B → u256（复用 `_u256_from_be`，limb0 最低位）。长度前置由
/// `sakaki_ness` 的 `_DP_FEED_MIN` 判定保证：本段所有偏移都落在 `off+32 ≤ 288`。
fn _dp_load(feed: &[u8], off: usize) -> [u64; 4] {
    _u256_from_be(&feed[off..off + 32])
}

/// -p^{-1} mod 2^64（Newton 六步，精度 1→2→4→…→64 位；p0 奇 ⇒ 逆必存在）。
fn _dp_nprime(p0: u64) -> u64 {
    let mut x = 1u64;
    for _ in 0..6 {
        x = x.wrapping_mul(2u64.wrapping_sub(p0.wrapping_mul(x)));
    }
    x.wrapping_neg()
}

/// R² mod p（R = 2^256）：512 次"自加 + 条件减"，只用 p 本身。
#[inline(never)]
fn _dp_r2(p: &[u64; 4]) -> [u64; 4] {
    let mut r = [1u64, 0, 0, 0];
    for _ in 0..512 {
        let (mut s, carry) = _dp_add(&r, &r);
        if carry != 0 || _dp_ge(&s, p) {
            s = _dp_sub(&s, p).0;
        }
        r = s;
    }
    r
}

// 以下场算术体全部 `#[inline(never)]`：这是**尺寸预算件**不是风格件。这一段有
// 二十多个调用点，放任 `-O` 逐点内联（4 limb 的循环再被完全展开）会把死路径撑到
// ~13 KB，超出 §3.3 的 ~8 KB 预算；每个体只发射一份即可（与 `vm_ops.rs` 的变体体
// 同一条口径，实测数字见 layout.json `deadpath.measured_text_delta_bytes`）。
#[inline(never)]
fn _dp_addm(a: &[u64; 4], b: &[u64; 4], f: &DpField) -> [u64; 4] {
    // a、b < p 且 p < 2^256 ⇒ a+b < 2p：一次条件减法即归位
    let (mut s, carry) = _dp_add(a, b);
    if carry != 0 || _dp_ge(&s, &f.p) {
        s = _dp_sub(&s, &f.p).0;
    }
    s
}

#[inline(never)]
fn _dp_subm(a: &[u64; 4], b: &[u64; 4], f: &DpField) -> [u64; 4] {
    let (mut s, borrow) = _dp_sub(a, b);
    if borrow != 0 {
        s = _dp_add(&s, &f.p).0;
    }
    s
}

#[inline(never)]
fn _dp_dblm(a: &[u64; 4], f: &DpField) -> [u64; 4] {
    _dp_addm(a, a, f)
}

#[inline(never)]
fn _dp_negm(a: &[u64; 4], f: &DpField) -> [u64; 4] {
    _dp_subm(&_DP_ZERO, a, f)
}

#[inline(never)]
fn _dp_red(a: &[u64; 4], f: &DpField) -> [u64; 4] {
    if _dp_ge(a, &f.p) {
        _dp_sub(a, &f.p).0
    } else {
        *a
    }
}

#[inline(never)]
fn _dp_to_m(a: &[u64; 4], f: &DpField) -> [u64; 4] {
    _dp_montm(&_dp_red(a, f), &f.r2, f)
}

#[inline(never)]
fn _dp_from_m(a: &[u64; 4], f: &DpField) -> [u64; 4] {
    _dp_montm(a, &[1u64, 0, 0, 0], f)
}

/// Montgomery 乘 a·b·R^{-1} mod p（CIOS 逐字形）。越出 512 位窗口的进位收在
/// `hi`（数学上 T < 2pR ⇒ hi ≤ 1，一次条件减法即归位）。`#[inline(never)]` 的理由
/// 同下面那组场算术体（尺寸预算件）。
#[inline(never)]
fn _dp_montm(a: &[u64; 4], b: &[u64; 4], f: &DpField) -> [u64; 4] {
    // CIOS（Koc 等 1996 的 Algorithm 4 交错形）：累加器只有五个字，乘与约在同一次
    // 扫里完成，右移一个字即把 t[0] 消成 0。不摆 8 字窗口、不写进位传播循环——
    // 那两条各值几百字节，而本层的预算是按 .text 字节算的。
    let p = &f.p;
    let mut t = [0u64; 5];
    let mut hi = 0u64;
    for i in 0..4 {
        let mut carry = 0u128;
        for j in 0..4 {
            let v = t[j] as u128 + (a[i] as u128) * (b[j] as u128) + carry;
            t[j] = v as u64;
            carry = v >> 64;
        }
        let v = t[4] as u128 + carry;
        t[4] = v as u64;
        hi += (v >> 64) as u64;
        // m 的取法让 t[0] + m·p[0] ≡ 0 (mod 2^64) 恰好归零
        let m = t[0].wrapping_mul(f.np);
        let mut c = (t[0] as u128 + (m as u128) * (p[0] as u128)) >> 64;
        for j in 0..3 {
            let v = t[j + 1] as u128 + (m as u128) * (p[j + 1] as u128) + c;
            t[j] = v as u64;
            c = v >> 64;
        }
        let v = t[4] as u128 + (m as u128) * (p[3] as u128) + c;
        t[3] = v as u64;
        t[4] = (v >> 64) as u64;
    }
    // CIOS 不变量：末值 < 2p ⇒ t[4] ∈ {0,1}、hi 恒 0（留着当阴性保险，
    // 真非零也只是让下面多减一次 p，仍然同余）
    let mut r = [t[0], t[1], t[2], t[3]];
    if hi != 0 || t[4] != 0 || _dp_ge(&r, p) {
        r = _dp_sub(&r, p).0;
    }
    r
}

/// Jacobian 倍点（短 Weierstrass 通用 a 形，M = 3X² + aZ⁴）。
#[inline(never)]
fn _dp_jdbl(p: &DpPoint, d: &DpDomain) -> DpPoint {
    let f = &d.f;
    if _dp_eq(&p.z, &_DP_ZERO) {
        return *p; // 2·O = O
    }
    let zz = _dp_montm(&p.z, &p.z, f);
    let xx = _dp_montm(&p.x, &p.x, f);
    let m = _dp_addm(&_dp_addm(&xx, &xx, f), &xx, f);
    let m = _dp_addm(&m, &_dp_montm(&d.a_m, &_dp_montm(&zz, &zz, f), f), f);
    let yy = _dp_montm(&p.y, &p.y, f);
    let s = _dp_dblm(&_dp_dblm(&_dp_montm(&p.x, &yy, f), f), f); // S = 4XY²
    let x3 = _dp_subm(&_dp_subm(&_dp_montm(&m, &m, f), &s, f), &s, f);
    let y4 = _dp_montm(&yy, &yy, f);
    let t8 = _dp_dblm(&_dp_dblm(&_dp_dblm(&y4, f), f), f); // 8Y⁴
    let y3 = _dp_subm(&_dp_montm(&m, &_dp_subm(&s, &x3, f), f), &t8, f);
    let z3 = _dp_dblm(&_dp_montm(&p.y, &p.z, f), f);
    DpPoint { x: x3, y: y3, z: z3 }
}

/// Jacobian 加法（含同点退化与 P+(-P)=O 两条边——两条都**返回**，不判失败）。
#[inline(never)]
fn _dp_jadd(p: &DpPoint, q: &DpPoint, d: &DpDomain) -> DpPoint {
    let f = &d.f;
    if _dp_eq(&p.z, &_DP_ZERO) {
        return *q;
    }
    if _dp_eq(&q.z, &_DP_ZERO) {
        return *p;
    }
    let z1z1 = _dp_montm(&p.z, &p.z, f);
    let z2z2 = _dp_montm(&q.z, &q.z, f);
    let u1 = _dp_montm(&p.x, &z2z2, f);
    let u2 = _dp_montm(&q.x, &z1z1, f);
    let s1 = _dp_montm(&p.y, &_dp_montm(&z2z2, &q.z, f), f);
    let s2 = _dp_montm(&q.y, &_dp_montm(&z1z1, &p.z, f), f);
    let h = _dp_subm(&u2, &u1, f);
    let r = _dp_subm(&s2, &s1, f);
    if _dp_eq(&h, &_DP_ZERO) {
        if _dp_eq(&r, &_DP_ZERO) {
            return _dp_jdbl(p, d);
        }
        return DpPoint { x: f.one, y: f.one, z: _DP_ZERO };
    }
    let hh = _dp_montm(&h, &h, f);
    let hhh = _dp_montm(&hh, &h, f);
    let u1hh = _dp_montm(&u1, &hh, f);
    let x3 = _dp_subm(&_dp_subm(&_dp_montm(&r, &r, f), &hhh, f), &_dp_dblm(&u1hh, f), f);
    let y3 = _dp_subm(&_dp_montm(&r, &_dp_subm(&u1hh, &x3, f), f),
                      &_dp_montm(&s1, &hhh, f), f);
    let z3 = _dp_montm(&h, &_dp_montm(&p.z, &q.z, f), f);
    DpPoint { x: x3, y: y3, z: z3 }
}

/// y² ≟ x³ + a x + b（仿射校验，全在 Montgomery 域里比，省往返转换）。返回"在/不在"，
/// 不在也只是见证位多一枚——**不是**失败出口。校验对象是**清单里声明的基点**，
/// 所以整段不需要任何求逆（费马逆那条模幂连同它的 512 次 Montgomery 乘一起出局：
/// 死路径的预算既按 .text 字节算，也按运行毫秒算）。
fn _dp_on_curve(x: &[u64; 4], y: &[u64; 4], d: &DpDomain) -> bool {
    let f = &d.f;
    let xx = _dp_montm(x, x, f);
    let rhs = _dp_addm(&_dp_addm(&_dp_montm(&xx, x, f), &_dp_montm(&d.a_m, x, f), f),
                       &d.b_m, f);
    _dp_eq(&_dp_montm(y, y, f), &rhs)
}

/// `.v3` 伪容器节 → 域参数清单（偏移见 `_DP_OFF_*`）。字节不够就判"这块字节
/// 不成曲线"返回 None：注意这是**死路径内部**的判据，它只让计算少跑几条边，
/// 不产生任何拒绝（新增拒绝类别 = 新增可观察行为）。
fn sakaki_ness(feed: &[u8], stream: &[u8]) -> Option<DpDomain> {
    if feed.len() < _DP_FEED_MIN || stream.len() < 96 {
        return None;
    }
    let mut p = _dp_load(feed, _DP_OFF_P);
    p[3] |= 1u64 << 63; // 归一化：2^255 ≤ p < 2^256（"256 位素域"这个长相）
    p[0] |= 1; // 且为奇：Montgomery 逆存在、R 与 p 互素
    let mut f = DpField { p, np: _dp_nprime(p[0]), r2: _DP_ZERO, one: _DP_ZERO };
    f.r2 = _dp_r2(&p);
    f.one = _dp_montm(&[1u64, 0, 0, 0], &f.r2, &f);
    Some(DpDomain {
        a_m: _dp_to_m(&_dp_load(feed, _DP_OFF_A), &f),
        b_m: _dp_to_m(&_dp_load(feed, _DP_OFF_B), &f),
        gx_m: _dp_to_m(&_dp_load(feed, _DP_OFF_GX), &f),
        gy_m: _dp_to_m(&_dp_load(feed, _DP_OFF_GY), &f),
        big_a_m: _dp_to_m(&_dp_load(feed, _DP_OFF_BIGA), &f),
        big_b_m: _dp_to_m(&_dp_load(feed, _DP_OFF_BIGB), &f),
        // "n" 槽既进清单也当标量用（下面的序检验 [n]G ≟ O 就是拿它乘的）
        k: _dp_load(feed, _DP_OFF_N),
        steps: _DP_STEPS + (stream[32] as u32) % 17,
        walk: _DP_WALK + (stream[33] as u32) % 4,
        f,
    })
}

/// 域参数的**奇异性见证**：Δ = −16(4a³ + 27b²)（短 Weierstrass 的标准判别式，
/// SEC1 的域参数校验本来就算这一项）。Δ ≡ 0 说明这堆字节根本不构成曲线。
/// 只出一位见证、不进任何判据——奇异也照样走完标量乘与等源腿：死路径的每条边
/// 都回到主流程，"诱饵字节不合格"绝不能变成一条新的拒绝路径。
/// 倍乘全用重复加法（不引入新常量、也省掉一条模幂）。
fn shiga_riko(d: &DpDomain) -> u32 {
    let f = &d.f;
    let a3 = _dp_montm(&_dp_montm(&d.a_m, &d.a_m, f), &d.a_m, f);
    let b2 = _dp_montm(&d.b_m, &d.b_m, f);
    let four_a3 = _dp_dblm(&_dp_dblm(&a3, f), f);
    let b2_2 = _dp_dblm(&b2, f);
    let b2_8 = _dp_dblm(&_dp_dblm(&b2_2, f), f);
    let b2_16 = _dp_dblm(&b2_8, f);
    let twenty_seven_b2 = _dp_addm(&_dp_addm(&_dp_addm(&b2_16, &b2_8, f), &b2_2, f),
                                   &b2, f);
    let inner = _dp_addm(&four_a3, &twenty_seven_b2, f);
    let sixteen = _dp_dblm(&_dp_dblm(&_dp_dblm(&_dp_dblm(&inner, f), f), f), f);
    let disc = _dp_negm(&sixteen, f);
    if _dp_eq(&disc, &_DP_ZERO) { 1 } else { 0 }
}

/// 群运算腿：定长"逐位无条件加 + 选择"的 Jacobian 标量乘（常时形写法，
/// 窗口宽度 `steps` 由构建期派生流定，逐格不同但值域只有 112..128）。
/// **没有**数据相关分支 ⇒ 每个格花同样的钟。
fn tamanoi_nana(d: &DpDomain) -> DpPoint {
    let f = &d.f;
    let mut acc = DpPoint { x: f.one, y: f.one, z: _DP_ZERO };
    let mut q = DpPoint { x: d.gx_m, y: d.gy_m, z: f.one };
    for i in (0..d.steps as usize).rev() {
        let t = _dp_jadd(&acc, &q, d);
        acc = if _dp_bit(&d.k, i) != 0 { t } else { acc };
        q = _dp_jdbl(&q, d);
    }
    acc
}

/// 等源腿：E2: y² = x³ + A x² + B x 上的定长 2-等源行走（Vélu 核 ⟨(0,0)⟩）：
/// 每步 (A, B) → (-2A, A² - 4B)，起点用群运算腿的**射影输出** (X : Z) 直接续上，
/// 按 (x : z) → (x² + B z² : x z) 推进（全程无需求逆）。
/// 起点即便"不在曲线上"也照样走完——SIDH/SIKE 一侧本来就把"A + 一组射影 x 坐标"
/// 当公钥读，这条腿要的就是这个长相。
fn kisara(d: &DpDomain, x0: &[u64; 4], z0: &[u64; 4]) -> ([u64; 4], [u64; 4]) {
    let f = &d.f;
    let mut a = d.big_a_m;
    let mut b = d.big_b_m;
    let mut x = *x0;
    let mut z = *z0;
    for _ in 0..d.walk {
        let zz = _dp_montm(&z, &z, f);
        let nx = _dp_addm(&_dp_montm(&x, &x, f), &_dp_montm(&b, &zz, f), f);
        let nz = _dp_montm(&x, &z, f);
        let na = _dp_negm(&_dp_dblm(&a, f), f);
        let nb = _dp_subm(&_dp_montm(&a, &a, f), &_dp_dblm(&_dp_dblm(&b, f), f), f);
        x = nx;
        z = nz;
        a = na;
        b = nb;
    }
    (x, z)
}

/// 死路径的唯一入口（被 `debidebi_debiru` 调用）。返回一份"曲线算术的收据"，
/// 调用点 `black_box` 丢弃；所有派生量都不含裸 seed（纪律③）。
///
/// `#[inline(never)]` 是这条伪装的**结构件**：入口一旦被内联进主流程，反汇编里
/// 就没有"调用点"可看了（实测：不标时 `lunlun` 被并进 `debidebi_debiru`）。
#[inline(never)]
fn lunlun(nonce: &[u8]) -> [u8; 32] {
    // ikm = MAC 钉 ‖ nonce：MAC 本身由含 seed 的头部算出并已钉在 .rdata，
    // "seed 派生"经此传递仍然成立，而这里不新增任何 seed 在场拷贝
    // （与 B 组置换同一口径）。
    let mut ikm = [0u8; 44];
    ikm[..32].copy_from_slice(&pins::MAC);
    ikm[32..].copy_from_slice(nonce);
    let mut prk = joe_rikiichi(L_DP_SALT, &ikm);
    suo_sango(&mut ikm);
    let mut stream = machita_chima(&prk, L_DP_INFO, 96);
    suo_sango(&mut prk);
    let dom = sakaki_ness(pins::DEADPATH_FEED, &stream);
    let mut mask = dom.as_ref().map_or(0u32, |d| shiga_riko(d));
    let mut jx = _DP_ZERO;
    let mut jy = _DP_ZERO;
    let mut jz = _DP_ZERO;
    let mut wx = _DP_ZERO;
    let mut wz = _DP_ZERO;
    if let Some(d) = dom.as_ref() {
        // 清单里声明的 G 是否在 E1 上（SEC1 域参数校验的常规一枚，仿射即可，
        // 无需求逆）
        mask |= if _dp_on_curve(&d.gx_m, &d.gy_m, d) { 0x2 } else { 0 };
        let pt = tamanoi_nana(d);
        // "n" 槽（`_DP_OFF_N`）直接当标量用：一份像样的清单应当满足 [n]G = O，
        // 这条比对就是那个序检验。不成立也只多一位见证——进折叠，不进判据。
        mask |= if _dp_eq(&pt.z, &_DP_ZERO) { 0x4 } else { 0 };
        jx = _dp_from_m(&pt.x, &d.f);
        jy = _dp_from_m(&pt.y, &d.f);
        jz = _dp_from_m(&pt.z, &d.f);
        let (x, z) = kisara(d, &pt.x, &pt.z);
        wx = _dp_from_m(&x, &d.f);
        wz = _dp_from_m(&z, &d.f);
    }
    // 折叠成一条"收据"：键 = 派生流尾 32 B（定长，绝不超 blake2s 的 32 B 键上限），
    // 消息 = 见证位图 ‖ 标量乘的射影坐标 ‖ 等源终点（都换回普通形，序列化曲线
    // 参数的标准一步）。这条摘要没有任何消费者——它的全部作用就是让上面那堆算术
    // **不能被证明是死的**（结果被调用点的 black_box 消费掉）。
    let mut key = [0u8; 32];
    key.copy_from_slice(&stream[64..96]);
    let mut msg = [0u8; 164];
    msg[..4].copy_from_slice(&mask.to_le_bytes());
    msg[4..36].copy_from_slice(&_u256_to_be(&jx));
    msg[36..68].copy_from_slice(&_u256_to_be(&jy));
    msg[68..100].copy_from_slice(&_u256_to_be(&jz));
    msg[100..132].copy_from_slice(&_u256_to_be(&wx));
    msg[132..164].copy_from_slice(&_u256_to_be(&wz));
    let out = blake2s::sister_claire(&key, &msg);
    // 派生流是 seed 的纯函数：键、消息、流本身用完一律覆零，不留 freed heap 拷贝
    // （内存自证口径，与 `joe_rikiichi` 里那两条拼接缓冲同纪律）。栈上数组同样
    // 覆零——不用 Vec 是为了少一份堆拷贝。
    suo_sango(&mut msg);
    suo_sango(&mut key);
    suo_sango(&mut stream);
    out
}

// ---------- 引导主流程 ----------
pub fn debidebi_debiru() {
    // W 低危残项：panic hook 兜底——残留的 assert/unwrap panic（含 stdlib）
    // 一律静默 exit 3，不再无条件向 stderr 打印 panic 报文（含模块路径），
    // 与「默认通道静默」纪律并轨
    std::panic::set_hook(Box::new(|_info| {
        std::process::exit(3);
    }));
    // 摘要槽活性引用：无引用的静态会被 CGU/链接器整节弃置（实测坑）——
    // black_box 触碰必须无条件挂在主流程最前，不随 GUARDS/GUARD_FAULT 钉
    // 的常量传播折叠（这两类钉在单 crate 内对优化器透明）
    std::hint::black_box(&SELF_DIGEST_SLOT);
    // §6 顺序：原生层守卫（1a）先于一切（反调试三件套 / 可疑模块枚举 / 槽纯度 /
    // 自身覆盖摘要 / DLL 钉——五枚的**执行次序**由 nonce 派生置换决定，静态代码里
    // 读不出直线序列）；GUARDS 钉关闭时整体跳过（--no-guards 构建档）
    aiba_uiha();
    let mut head = [0u8; 57];
    head[..25].copy_from_slice(&pins::HEAD_PREFIX);
    // 外部密钥档：seed 运行时由 --key-file / 环境变量提供，
    // 绝不从钉子取（EXTERNAL_MODE 下 SEED_EMBED 钉死为全零）
    let mut seed32: [u8; 32] = if pins::EXTERNAL_MODE {
        ex_albio()
    } else {
        pins::SEED_EMBED
    };
    head[25..57].copy_from_slice(&seed32);
    if (head[0] != 1 && head[0] != 2) || head[2] as usize != head.len() {
        _exit3("E-38");
    }
    let ct = kuroi_shiba();
    // 批2-4.3 死路径伪装（设计方案 §3.3、`lunlun` 的 docstring）：唯一入口挂在
    // 主流程这里，进入条件全部是**运行期**装载/取回的量——头部 flags 的保留位
    // （layout.json `flags_bits."6-7"`：构建期硬门保证为 0）与 RCDATA 的真实长度
    // （loader 给的回值，编译期不可知）——不是源码字面量，反汇编在这里看到的
    // 是一条活调用点。`pins::DEADPATH` 是构建期 **const**（写成 static 会让常量
    // 折叠失效、off 臂剪不掉，本项目的变异层已经实测过一次）。
    // 结果一律丢弃且被 black_box 钉住：不写通道、不改退出码、不参与任何判据。
    if pins::DEADPATH && (head[1] & 0xC0) == 0 && !ct.is_empty() {
        std::hint::black_box(lunlun(&head[13..25]));
    }
    let payload_len =
        u32::from_le_bytes([head[3], head[4], head[5], head[6]]) as usize;
    let (enc, mac_key, nonce) = naruto_kogane(&head);
    // 拒绝顺序：MAC 先于解密。待缓冲显式建、用完覆零——`&[..].concat()` 的临时
    // Vec 装着含 seed 的整头部，释放后会在 freed heap 里留下一份完整 seed
    // （早期轮次 步骤 3 内存自证）
    let mut mac_msg = Vec::with_capacity(head.len() + ct.len());
    mac_msg.extend_from_slice(&head);
    mac_msg.extend_from_slice(&ct);
    let tag = blake2s::sister_claire(&mac_key, &mac_msg);
    suo_sango(&mut mac_msg);
    // 批2-1.1 B 组：**先于外层解密**的三枚独立门（CPUID 门槛 / 原语 KAT / 容器 MAC）
    // 的执行顺序 = (seed‖nonce) 派生置换。它们彼此语义独立、失败后果同构（同一条
    // 静默 exit 3），且整组位于 `belmond_banderas` 之前——"MAC 先于解密"这条红线由
    // 分组保证，与组内序号无关（早期轮次 教训）。
    // 位移说明：KAT 原先在密钥读取之前，现落入置换组、可能后于 `naruto_kogane`。
    // 不变量"未经验证的原语不得用于解密"仍然成立——`naruto_kogane` 只算出两把
    // 派生密钥，其唯一消费点（外层 ChaCha20 解密）在本组全部通过之后；且原语被
    // 篡改时 keyed MAC 自身必然失配，拒绝发生在任何解密之前（fail-closed 同向）。
    // ikm 取 **MAC 钉 ‖ 头部 nonce**，绝不取裸 seed：首版用 seed‖nonce 做 HKDF 输入，
    // HMAC/SHA-256 内部的分块缓冲把一份完整 seed 留在了已释放堆里，早期轮次 步骤 3 的
    // 内存自证当场抓红（实测）。MAC 本身已由含 seed 的头部算出并
    // 钉在 .rdata——"seed 派生"经此传递仍然成立，且不再新增任何 seed 在场拷贝。
    let mut ikm_b: Vec<u8> = Vec::with_capacity(44);
    ikm_b.extend_from_slice(&pins::MAC);
    ikm_b.extend_from_slice(&pins::HEAD_PREFIX[13..25]);
    let order_b = fura_kanato(&ikm_b, L_PERM_B_SALT, L_PERM_B_INFO, N_PREDECRYPT_CHECKS);
    suo_sango(&mut ikm_b);
    if amagi_yuni(&order_b, N_PREDECRYPT_CHECKS) != pins::CHECK_SEAL_B {
        _exit3("E-115");
    }
    for &k in order_b.iter() {
        match k {
            0 => if pins::REQUIRE_V2 && !yaguruma_rine() { _exit3("E-36"); },
            1 => if !yumeoi_kakeru() { _exit3("E-37"); },
            _ => if tag != pins::MAC { _exit3("E-39"); },
        }
    }
    let mut nonce12 = [0u8; 12];
    nonce12.copy_from_slice(&nonce);
    let plain = belmond_banderas(&enc, &nonce12, &ct);
    if plain.len() < payload_len {
        _exit3("E-40");
    }
    //  v2 路径：载荷是 VM blob（IR 仍逐块加密），不进 CPython、不做 marshal.loads，
    // 因此"交接即失效"（§6 第 6′ 条）与 §8 运行时信任锚缺口在本形态整面不存在。
    // 拒绝顺序不变：守卫 → 门槛 → KAT → MAC → 外层解密 → VM（VM 内部再逐块验 MAC/解密）。
    if head[0] == 2 {
        // 齿开着时在第 512 步暂停（此刻明文槽是热的）；产品路径 None，不暂停、不打印
        let hold_at = if pins::VM_VISIBILITY_PROBE { Some(512usize) } else { None };
        // 早期轮次：flags 位 5 决定要不要取进程输入（不置位连 stdin 都不碰）。
        // 超上限一律走桶码——静默截断会让产物看到的输入与验收方给的不一致。

        // 早期轮次：位 5 没置位的产物**没有接口可执行**——编译器只在 input_mode 下发射
        // ARGV/STDIN，窗折出来没有任何指令读它，却会因 argv[0]（= 产物自己的启动路径，
        // 实测 60–80 B）超出本格 ap（48..80）而走 E-113：那是"产品拒绝启动"，不是
        // "输入超出本格窗口"。uniform 档 ap 恒 64 且跳过 argv[0]，把这个形状掩盖住了；
        // iface.mode 铺开成 per_cell 后三个非输入档用例当场 exit 4（八拓扑 / CLI 端到端 /
        // 变体剥离消融档，实测）。消费输入那一档仍按本格契约全量执行，判据一条没少

        let win = if head[1] & 0x20 != 0 {
            match amagase_muyu() {
                Some(w) => w,
                None => _exit_iface("E-113"),
            }
        } else {
            (Vec::new(), Vec::new())
        };
        // seed 在这里最后一次被消费（ISA 物理映射），拿到表的同一刻就把
        // seed 的两处在场拷贝抹掉——运行中途的抓取因此可以断言"seed 不在场"
        // （早期轮次 步骤 3）
        let pmap = vm::physmap(&seed32);
        suo_sango(&mut seed32);
        suo_sango(&mut head[25..57]);
        match vm::run_blob(&plain[..payload_len], &enc, &pmap, &win.0, &win.1, hold_at) {
            Ok(out) => {
                use std::io::Write;
                // 注意：可见量的抓取点在 `vm::run` 内部（hold_at），不在这里——
                // run_blob 返回即 drop Vm，明文槽已覆零释放，此处什么都看不到。
                let so = std::io::stdout();
                let mut lock = so.lock();
                if lock.write_all(&out).is_err() {
                    _exit3("E-41");
                }
                // flush 失败（断管）不得吞成 exit 0——与上面 write_all 同走 E-41
                // 静默通道
                if lock.flush().is_err() {
                    _exit3("E-41");
                }
                std::process::exit(0);
            }
            // VM 任何故障都走同一条静默通道；`e` 本身就是短码，不再包语义壳
            Err(e) => _exit3(&e),
        }
    }
    // v1 的对照齿不在这里——见 tsukimi_shizuku 内"DLL 已加载且 marshal 仍在本进程手里"
    // 的那一刻（两个对照证据要同时成立）。
    // seed 的最后一次消费到此结束（头重建/密钥派生/MAC 都已完成）——两处在场
    // 拷贝立即抹掉，v1 载荷交接期内存里不再有更 seed
    suo_sango(&mut seed32);
    suo_sango(&mut head[25..57]);
    // 成功路径保持静默——native stdout 必须与原程序逐字一致
    tsukimi_shizuku(&head, &plain[..payload_len]);
}
