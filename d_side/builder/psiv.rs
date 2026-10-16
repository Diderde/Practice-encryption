// Copyright (C) 2026 Diderde
// SPDX-License-Identifier: GPL-3.0-only
// PSIV 块级 AEAD 的 Rust 镜像（容器 fmt_ver=3； 容器升级）。

// 与 `d_side/builder/psiv.py` 逐式同构（双路径互钉），仓内可复跑的锚 = 双端 blob
// 互证 + 本文件的 KAT 期望值。另有一条**历史**锚：曾与官方 CC0 参考实现的 10 组向量
// 逐条对照通过（对照脚本 `psiv_kat_check.py` 从未入版控，本仓不可复跑，措辞如实）。
// 论文：Beyne–Chen–Verbauwhede ePrint 2025/222（CRYPTO 2026）；参考实现 CC0-1.0。
// KAT 实测坑（Python 端抓获，此处不再犯）：
// ①论文 φ 公式里的"+"是 chacha20_core 内置 feed-forward——`perm` 已含，不得再加；
// ②Poly1305 部分块 = 零垫到 16B 后整体 +2^128（判别实验定案，非"1 紧邻数据"形）；
// ③φe 密钥流全宽 64B 不截断（截断只属于 φm→tag 与 φk→poly key）。
// （用普通注释而非 //! 本文件会被 include! 进 KAT 探针，内文档注释在宏展开非法。）
use std::convert::TryInto; // native_build 的 rustc 口径无 2021 prelude（cargo 抽检编译过、真管线报 E0599）

const TAG: usize = 16;
const BLOCK: usize = 64;
const NONCE: usize = 12;

/// 裸 ChaCha20 置换：64B → 20 轮 → feed-forward（与 psiv.py `_perm` 同式）。
fn perm(block: &[u8; BLOCK]) -> [u8; BLOCK] {
    let mut x = [0u32; 16];
    for i in 0..16 {
        x[i] = u32::from_le_bytes(block[4 * i..4 * i + 4].try_into().unwrap());
    }
    let init = x;
    for _ in 0..10 {
        qr(&mut x, 0, 4, 8, 12);
        qr(&mut x, 1, 5, 9, 13);
        qr(&mut x, 2, 6, 10, 14);
        qr(&mut x, 3, 7, 11, 15);
        qr(&mut x, 0, 5, 10, 15);
        qr(&mut x, 1, 6, 11, 12);
        qr(&mut x, 2, 7, 8, 13);
        qr(&mut x, 3, 4, 9, 14);
    }
    let mut out = [0u8; BLOCK];
    for i in 0..16 {
        out[4 * i..4 * i + 4]
            .copy_from_slice(&x[i].wrapping_add(init[i]).to_le_bytes());
    }
    out
}

fn qr(x: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    x[a] = x[a].wrapping_add(x[b]);
    x[d] ^= x[a];
    x[d] = x[d].rotate_left(16);
    x[c] = x[c].wrapping_add(x[d]);
    x[b] ^= x[c];
    x[b] = x[b].rotate_left(12);
    x[a] = x[a].wrapping_add(x[b]);
    x[d] ^= x[a];
    x[d] = x[d].rotate_left(8);
    x[c] = x[c].wrapping_add(x[d]);
    x[b] ^= x[c];
    x[b] = x[b].rotate_left(7);
}

/// fk/fm/fe：32B 主钥 → 36B 展开钥（论文 §3.3 常量布局；kind ∈ b'k'/b'm'/b'e'）。
fn expand(kind: u8, key: &[u8; 32]) -> [u8; 36] {
    let (c1, c2, c3, c4) = match kind {
        b'k' => (0x03u8, 0x0cu8, 0x30u8, 0xc0u8),
        b'm' => (0x05, 0x0a, 0x50, 0xa0),
        _ => (0x06, 0x09, 0x60, 0x90),
    };
    let mut out = [0u8; 36];
    out[0..3].copy_from_slice(&key[0..3]);
    out[3] = c1;
    out[4..7].copy_from_slice(&key[4..7]);
    out[7] = c2;
    out[8..11].copy_from_slice(&key[8..11]);
    out[11] = c3;
    out[12] = key[3];
    out[13] = key[7];
    out[14] = key[11];
    out[15] = c4;
    out[16..36].copy_from_slice(&key[12..32]);
    out
}

/// H 的静态密钥 L = φk(K) = trunc32(perm(fk(K) ‖ 0²⁸))（perm 已含 feed-forward）。
fn poly_key(key: &[u8; 32]) -> [u8; 32] {
    let mut blk = [0u8; BLOCK];
    blk[..36].copy_from_slice(&expand(b'k', key));
    let out = perm(&blk);
    let mut k = [0u8; 32];
    k.copy_from_slice(&out[..32]);
    k
}

// ---- 130 位小大数（[u64; 3] 小端腿）——Poly1305 专用，零 crate ----

/// acc = (acc + block + 2^128) · r mod (2^130-5)。
fn poly_step(acc: &mut [u64; 3], block: &[u8; 16], r: &[u64; 2]) {
    let n0 = u64::from_le_bytes(block[0..8].try_into().unwrap());
    let n1 = u64::from_le_bytes(block[8..16].try_into().unwrap());
    let n = [n0, n1, 1u64]; // +2^128 ⇒ limb2 bit0
    let mut sum = [0u64; 3];
    let mut carry = 0u128;
    for i in 0..3 {
        let v = acc[i] as u128 + n[i] as u128 + carry;
        sum[i] = v as u64;
        carry = v >> 64;
    }
    debug_assert_eq!(carry, 0); // acc < p 且 n < 2^129 ⇒ 和 < 2^131，3 腿必容
    // prod = sum × r（≤259 位，5 腿）
    let mut prod = [0u64; 5];
    for i in 0..3 {
        let mut carry: u128 = 0;
        for j in 0..2 {
            let t = (sum[i] as u128) * (r[j] as u128) + prod[i + j] as u128 + carry;
            prod[i + j] = t as u64;
            carry = t >> 64;
        }
        let mut k = i + 2;
        while carry != 0 && k < 5 {
            let t = prod[k] as u128 + carry;
            prod[k] = t as u64;
            carry = t >> 64;
            k += 1;
        }
        debug_assert_eq!(carry, 0);
    }
    // 归约 mod 2^130-5：2^130 ≡ 5 ⇒ x ≡ x_lo130 + 5·x_hi。≤259 位三轮折叠收敛。
    for _round in 0..3 {
        // h = prod >> 130（2 腿）
        let h0 = (prod[2] >> 2) | (prod[3] << 62);
        let h1 = (prod[3] >> 2) | (prod[4] << 62);
        if h0 == 0 && h1 == 0 {
            break;
        }
        prod[2] &= 3;
        prod[3] = 0;
        prod[4] = 0;
        // prod += 5 · h（进位最多渗入 prod[2]，后续轮次继续折叠）
        let t0 = prod[0] as u128 + 5 * (h0 as u128);
        prod[0] = t0 as u64;
        let mut c = t0 >> 64;
        let t1 = prod[1] as u128 + 5 * (h1 as u128) + c;
        prod[1] = t1 as u64;
        c = t1 >> 64;
        let mut k = 2;
        while c != 0 && k < 5 {
            let t = prod[k] as u128 + c;
            prod[k] = t as u64;
            c = t >> 64;
            k += 1;
        }
    }
    // 收尾小折叠（此时 prod < 2^131：高 2 位若有余量，×5 折回；进位不会渗回高位）
    let high = prod[2] >> 2;
    if high != 0 {
        let mut carry: u128 = 5 * high as u128;
        for i in 0..3 {
            let t = prod[i] as u128 + carry;
            prod[i] = t as u64;
            carry = t >> 64;
        }
        prod[2] &= 3;
    }
    // 条件减 p = 2^130-5 = [2^64-5, 2^64-1, 0b11]
    let pv = [u64::MAX - 4, u64::MAX, 3u64];
    let ge = prod[2] > pv[2]
        || (prod[2] == pv[2] && (prod[1] > pv[1] || (prod[1] == pv[1] && prod[0] >= pv[0])));
    if ge {
        let mut borrow = 0i128;
        for i in 0..3 {
            let t = prod[i] as i128 - pv[i] as i128 - borrow;
            prod[i] = t as u64;
            borrow = if t < 0 { 1 } else { 0 };
        }
    }
    *acc = [prod[0], prod[1], prod[2]];
}

/// Poly1305(key, ad, msg) → 16B tag（各段零垫、全块 +2^128、尾接 le64 长度块）。
fn poly1305(key: &[u8; 32], ad: &[u8], msg: &[u8]) -> [u8; TAG] {
    let mut rbuf = [0u8; 16];
    rbuf.copy_from_slice(&key[..16]);
    let rv = u128::from_le_bytes(rbuf) & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF;
    let r = [rv as u64, (rv >> 64) as u64];
    let mut sbuf = [0u8; 16];
    sbuf.copy_from_slice(&key[16..]);
    let s = u128::from_le_bytes(sbuf);

    let mut acc = [0u64; 3];
    for data in [ad, msg] {
        let padded = (16 - data.len() % 16) % 16;
        let total = data.len() + padded;
        for off in (0..total).step_by(16) {
            let mut block = [0u8; 16];
            let end = (off + 16).min(data.len());
            if off < data.len() {
                block[..end - off].copy_from_slice(&data[off..end]);
            }
            poly_step(&mut acc, &block, &r);
        }
    }
    let mut lb = [0u8; 16];
    lb[..8].copy_from_slice(&(ad.len() as u64).to_le_bytes());
    lb[8..].copy_from_slice(&(msg.len() as u64).to_le_bytes());
    poly_step(&mut acc, &lb, &r);

    let a128 = (acc[0] as u128) | ((acc[1] as u128) << 64);
    (a128.wrapping_add(s)).to_le_bytes()
}

/// Algorithm 1：T = φm(K, N, H(ad‖msg))（perm 已含 feed-forward，截 16B）。
fn mac(key: &[u8; 32], nonce: &[u8; NONCE], ad: &[u8], msg: &[u8]) -> [u8; TAG] {
    let h = poly1305(&poly_key(key), ad, msg);
    let mut tblk = [0u8; BLOCK];
    tblk[..36].copy_from_slice(&expand(b'm', key));
    tblk[36..48].copy_from_slice(nonce);
    tblk[48..64].copy_from_slice(&h);
    let out = perm(&tblk);
    let mut tag = [0u8; TAG];
    tag.copy_from_slice(&out[..TAG]);
    tag
}

/// φe 密钥流块：全宽 64B（KAT 坑③：不截断）。
fn keystream_block(key: &[u8; 32], nonce: &[u8; NONCE], tag: &[u8; TAG], counter: u64) -> [u8; BLOCK] {
    let t128 = u128::from_le_bytes(*tag);
    let t_plus = t128.wrapping_add(counter as u128); // 与 Python %2^128 同界
    let mut blk = [0u8; BLOCK];
    blk[..36].copy_from_slice(&expand(b'e', key));
    blk[36..48].copy_from_slice(nonce);
    blk[48..64].copy_from_slice(&t_plus.to_le_bytes());
    perm(&blk)
}

/// Algorithm 3（块级）：返回 (ct, tag)。
pub fn encrypt_block(key: &[u8; 32], nonce: &[u8; NONCE], plaintext: &[u8]) -> (Vec<u8>, [u8; TAG]) {
    let tag = mac(key, nonce, &[], plaintext);
    let ct = stream_xor(plaintext, key, nonce, &tag);
    (ct, tag)
}

/// Algorithm 4（块级）：先解后验；tag 不符 → Err（boot 侧静默 exit 3）。
pub fn decrypt_block(
    key: &[u8; 32],
    nonce: &[u8; NONCE],
    ciphertext: &[u8],
    tag: &[u8; TAG],
) -> Result<Vec<u8>, String> {
    let pt = stream_xor(ciphertext, key, nonce, tag);
    if mac(key, nonce, &[], &pt) != *tag {
        return Err("E-104".to_string());
    }
    Ok(pt)
}

fn stream_xor(data: &[u8], key: &[u8; 32], nonce: &[u8; NONCE], tag: &[u8; TAG]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    for (i, chunk) in data.chunks(BLOCK).enumerate() {
        let ks = keystream_block(key, nonce, tag, i as u64);
        for (b, k) in chunk.iter().zip(ks.iter()) {
            out.push(b ^ k);
        }
    }
    out
}
