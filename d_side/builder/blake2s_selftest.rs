// Copyright (C) 2026 Diderde
// SPDX-License-Identifier: GPL-3.0-only
//! blake2s.rs 自检驱动（零 crate）：内部断言 RFC 7693 A.1， stdout 打印
//! 确定性 (key_len × data_len) 摘要矩阵，供
//! `tests/d_side/test_native_blake2s.py` 与 hashlib 运行时交叉钉死。
//! 输入模式（与该测试逐字一致，禁 random）：
//!   data[i] = (i * 89 + 17) & 0xff ; key[i] = (i * 31 + 7) & 0xff
//! 退出码 0 当且仅当内部向量断言通过。

#[path = "blake2s.rs"]
mod blake2s;

use blake2s::sister_claire;

const RFC_A1_HEX: &str =
    "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn pattern(step: usize, bias: usize, len: usize) -> Vec<u8> {
    (0..len).map(|i| ((i * step + bias) & 0xff) as u8).collect()
}

fn main() {
    let abc = sister_claire(&[], b"abc");
    if hex(&abc) != RFC_A1_HEX {
        eprintln!("RFC 7693 A.1 mismatch: {}", hex(&abc));
        std::process::exit(1);
    }
    println!("rfc7693_a1 {}", hex(&abc));

    let key_lens = [0usize, 1, 16, 32]; // BLAKE2s key 上限 32B
    let data_lens = [0usize, 1, 55, 56, 63, 64, 65, 127, 128, 129, 250];
    for kl in key_lens {
        for dl in data_lens {
            let key = pattern(31, 7, kl);
            let data = pattern(89, 17, dl);
            let digest = sister_claire(&key, &data);
            println!("case k={} n={} {}", kl, dl, hex(&digest));
        }
    }
}
