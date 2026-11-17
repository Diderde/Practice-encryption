// Copyright (C) 2026 Diderde
// SPDX-License-Identifier: GPL-3.0-only
//!  可见量断言的**外部抓取**齿 + VM 明文槽的页隔离分配。
//!
//! 为什么不是"自进程扫描"：探针若在产物进程内扫描，它必须先把"期望明文"读进自己的
//! 堆——于是扫描必然命中探针自身持有的那份拷贝，判据恒假（实测：v2 自扫报出了完整的
//! marshal 字节数，等于自己把明文请进来再"发现"它）。断言要可信，抓取必须来自
//! **另一个进程**——那也正是外部进程的手法（冻结线程 + ReadProcessMemory），
//! 现由测试侧实现（`tests/d_side/test_vm_gates.py`），产物侧只留一个暂停点。
//!
//! 本模块因此只做两件事：
//! 1. `hold`：带探针齿的构建在"明文最可能在场的时点"暂停，等测试侧写完标记文件再走。
//!    生产构建的齿为 false，这段路径不进入，产物里也不含任何期望明文；
//! 2. `PageBuf`：VM 明文槽**每槽一页**的独立分配。块只占页首 `used` 字节、页尾保持零
//!    ⇒ "最长连续明文 ≤ 1 chunk" 由内存布局结构保证，与两槽是否相邻无关（的
//!    guard gap 落点）。逐出与 Drop 都先覆零再释放（best-effort 清零）。

use std::ffi::c_void;
use std::path::Path;
use std::time::{Duration, Instant};

const PAGE_SIZE: usize = 4096;
const HOLD_POLL: Duration = Duration::from_millis(50);
const HOLD_TIMEOUT: Duration = Duration::from_secs(20);

#[link(name = "kernel32")]
extern "system" {
    fn VirtualAlloc(addr: *const c_void, size: usize, alloc_type: u32, protect: u32) -> *mut c_void;
    fn VirtualFree(addr: *mut c_void, size: usize, free_type: u32) -> i32;
}

const MEM_COMMIT_RESERVE: u32 = 0x3000;    // MEM_COMMIT | MEM_RESERVE
const MEM_DECOMMIT: u32 = 0x4000;

/// 暂停点：stderr 打 `vispause <tag>`，然后轮询等待测试侧创建的标记文件。
/// 超时（20 s）自行继续——宁可闸门因缺记录而红，也不让产物侧无限挂死。
///
/// （既有审计结论）：环境变量名与标记串曾以明文入 .rdata——外部分析者的全部
/// 内存取证工具都靠这个开关把 15–40ms 的进程钉住再 dump。改为拆分异或运行时
/// 重组（key 0x33），套件行为不变、明文情报消失
/// 早期轮次 2.2：**后门整体移除**——hold 信号路径改由构建期
/// pin（`pins::VISI_HOLD_PATH`，仅探针构建经 pins_override 注入；生产构建
/// 常量为空串且 hold 直接返回）。产物不再含任何环境变量名（异或态也没有），
/// 此类"解出字面名 + 20 种注入测绘"的面归零
pub fn hold(tag: &str) {
    let path = crate::pins::VISI_HOLD_PATH;
    if path.is_empty() {
        return;
    }
    eprintln!("vispause{}", tag);
    let deadline = Instant::now() + HOLD_TIMEOUT;
    while Instant::now() < deadline {
        if Path::new(path).exists() {
            return;
        }
        std::thread::sleep(HOLD_POLL);
    }
}

/// 每槽一页的明文缓冲：块只占页首，页尾恒零 ⇒ 连续明文 run 由布局限制在 1 chunk。
pub struct PageBuf {
    ptr: *mut u8,
}

impl PageBuf {
    pub fn new() -> PageBuf {
        let p = unsafe {
            VirtualAlloc(std::ptr::null(), PAGE_SIZE, MEM_COMMIT_RESERVE, 0x04) as *mut u8
        };
        assert!(!p.is_null(), "E-106");
        unsafe { std::ptr::write_bytes(p, 0, PAGE_SIZE) };
        PageBuf { ptr: p }
    }

    /// 写入并保证页尾恒零：明文段之后不残留旧内容，也就拼不出更长的连续 run。
    pub fn write(&mut self, data: &[u8]) {
        assert!(data.len() <= PAGE_SIZE, "E-107");
        unsafe {
            std::ptr::copy_nonoverlapping(data.as_ptr(), self.ptr, data.len());
            let tail = PAGE_SIZE - data.len();
            if tail > 0 {
                std::ptr::write_bytes(self.ptr.add(data.len()), 0, tail);
            }
        }
    }

    pub fn slice(&self, n: usize) -> &[u8] {
        assert!(n <= PAGE_SIZE, "E-108");
        unsafe { std::slice::from_raw_parts(self.ptr, n) }
    }
}

impl Drop for PageBuf {
    fn drop(&mut self) {
        unsafe {
            std::ptr::write_bytes(self.ptr, 0, PAGE_SIZE);
            VirtualFree(self.ptr as *mut c_void, 0, MEM_DECOMMIT);
        }
    }
}

/// 供 vm 模块做块上限校验。
pub fn page_size() -> usize {
    PAGE_SIZE
}
