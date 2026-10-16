// Copyright (C) 2026 Diderde
// SPDX-License-Identifier: GPL-3.0-only
//! BLAKE2s-256 正式端口（RFC 7693）——原生产物侧 native boot 的 MAC 原语。
//!
//! 口径：
//! - 仅 BLAKE2s-256；keyed（key ≤ **32B**——BLAKE2s 上限，64 是 BLAKE2b 的）
//!   与 unkeyed 同一入口；
//! - t 计数语义：key 块计 64B，消息块计实际字节数（与参考实现一致）；
//! - 空输入（key 与 data 均空）必须压缩一个全零末块；
//! - G 调用网络为 RFC 7693 §3.2 标准形：列 G0–G3 + 对角 G4–G7。
//!   （探针版此处曾写坏——八个 G 调用次序/坐标均非标准，输出与 hashlib
//!   不一致）
//!
//! 验收：RFC 7693 A.1 向量 + `tests/d_side/test_native_blake2s.py`
//! 对 hashlib 的运行时交叉钉死（零手抄期望值）。

// 裸 rustc（2015 edition）下 TryInto 不在 prelude——显式导入保持 edition 无关
use std::convert::TryInto;

const IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

const SIGMA: [[usize; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

fn _g(v: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, x: u32, y: u32) {
    // BLAKE2 的四个旋转全为右旋（16/12/8/7）——与 ChaCha 的左旋不同
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(12);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(8);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(7);
}

fn _compress(h: &mut [u32; 8], block: &[u8; 64], t: u64, last: bool) {
    let mut m = [0u32; 16];
    for i in 0..16 {
        m[i] = u32::from_le_bytes(block[4 * i..4 * i + 4].try_into().unwrap());
    }
    let mut v = [0u32; 16];
    v[..8].copy_from_slice(h);
    v[8..].copy_from_slice(&IV);
    v[12] ^= t as u32;
    v[13] ^= (t >> 32) as u32;
    if last {
        v[14] = !v[14];
    }
    for r in 0..10 {
        let s = &SIGMA[r];
        _g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
        _g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
        _g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
        _g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
        _g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
        _g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        _g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
        _g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
    }
    for i in 0..8 {
        h[i] ^= v[i] ^ v[i + 8];
    }
}

/// BLAKE2s-256 摘要：key 非空即 keyed 模式（key ≤ 32B，超限 panic）。
pub fn sister_claire(key: &[u8], data: &[u8]) -> [u8; 32] {
    assert!(key.len() <= 32, "E-105");
    let mut h = IV;
    h[0] ^= 0x0101_0000 ^ ((key.len() as u32) << 8) ^ 32;
    let mut t: u64 = 0;
    let mut block = [0u8; 64];
    if !key.is_empty() {
        block[..key.len()].copy_from_slice(key);
        t += 64;
        _compress(&mut h, &block, t, data.is_empty());
        block = [0u8; 64];
    }
    if key.is_empty() && data.is_empty() {
        _compress(&mut h, &block, 0, true);
    }
    let mut off = 0usize;
    while off < data.len() {
        let end = (off + 64).min(data.len());
        block[..end - off].copy_from_slice(&data[off..end]);
        t += (end - off) as u64;
        _compress(&mut h, &block, t, end == data.len());
        block = [0u8; 64];
        off = end;
    }
    let mut out = [0u8; 32];
    for i in 0..8 {
        out[4 * i..4 * i + 4].copy_from_slice(&h[i].to_le_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::sister_claire;

    // RFC 7693 附录 A.1：BLAKE2s-256(b"abc")
    const RFC_A1: [u8; 32] = [
        0x50, 0x8c, 0x5e, 0x8c, 0x32, 0x7c, 0x14, 0xe2, 0xe1, 0xa7, 0x2b, 0xa3, 0x4e, 0xeb, 0x45,
        0x2f, 0x37, 0x45, 0x8b, 0x20, 0x9e, 0xd6, 0x3a, 0x29, 0x4d, 0x99, 0x9b, 0x4c, 0x86, 0x67,
        0x59, 0x82,
    ];

    #[test]
    fn rfc7693_a1_unkeyed() {
        assert_eq!(sister_claire(&[], b"abc"), RFC_A1);
    }

    #[test]
    #[should_panic]
    fn key_over_32_panics() {
        let _ = sister_claire(&[0u8; 33], b"x");
    }
}
