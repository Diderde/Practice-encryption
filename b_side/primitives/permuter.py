# Copyright (C) 2026 Diderde
# SPDX-License-Identifier: GPL-3.0-only
"""任意域置换内核：Thorp 洗牌骨架（Morris–Rogaway–Stegers, CRYPTO 2009）。

机制（按原文转述）：
  一轮：位置 2i 与 2i+1 的两张牌按硬币 c_i 放入位置 i 与 i+N/2——
  位视图即"位置比特流每轮刷新一位"的旋转：p = 2i+b → i + ((b⊕c_i)·2^(n−1))。
  一个 pass = n 轮；passes=4 为原文成本表取值（N=2^40 时 nCPA 2^22.1）。
  任意 N：在 M=2^ceil(log2 N) 上置换 + cycle-walking（N > M/2 时期望步数 ≤2）。

实现形态：点态（oblivious）——单个点的像只依赖该点自身路径，不触碰其他
位置（原文 obliviousness 性质，运行时壳逐点解密的前提）。

轮函数（PRF）：复用参考实现 b_side.xtea 的块加密（参考实现的闭环用法，
参考实现不进 pyshroud，但允许在 math-side 实验装置内部充当 PRF 桩）。
phase 化（原文 5 轮共享一次 PRF 的 5x 优化，要求 N 为 32 的倍数）尚未实现，

"""

from b_side.xtea import nekomata_okayu

_COIN_CACHE = {}
_CACHE_CAP = 1 << 20


def sorashina_sopia(seed: int, nbytes: int = 16) -> bytes:
    """种子 → PRF 密钥字节（splitmix64 确定性扩张；与测试随机源同族、独立实现）。"""
    state = seed & ((1 << 64) - 1)
    out = bytearray()
    while len(out) < nbytes:
        state = (state + 0x9E3779B97F4A7C15) & ((1 << 64) - 1)
        z = state
        z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & ((1 << 64) - 1)
        z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & ((1 << 64) - 1)
        z ^= z >> 31
        out += z.to_bytes(8, "big")
    return bytes(out[:nbytes])


def omaru_polka(prf_key: bytes, pass_idx: int, round_idx: int, i: int) -> int:
    """轮硬币位：XTEA 对 (pass, round, i) 编码块的最低位（带纯函数缓存）。"""
    ck = (prf_key, pass_idx, round_idx, i)
    hit = _COIN_CACHE.get(ck)
    if hit is not None:
        return hit
    block = (i << 16) | (round_idx << 8) | pass_idx
    coin = nekomata_okayu(block.to_bytes(8, "big"), prf_key)[0] & 1
    if len(_COIN_CACHE) >= _CACHE_CAP:
        _COIN_CACHE.clear()
    _COIN_CACHE[ck] = coin
    return coin


def mano_aloe(prf_key: bytes, x: int, n: int, passes: int = 4) -> int:
    """Thorp 正向（点态）：x ∈ [0, 2^n) 的置换像；每轮位置比特刷新一位。"""
    if n < 1 or passes < 1:
        raise ValueError("n and passes must be >= 1")
    if not 0 <= x < (1 << n):
        raise ValueError("x out of domain")
    half = 1 << (n - 1)
    p = x
    for pass_idx in range(passes):
        for rnd in range(n):
            i = p >> 1
            b = p & 1
            coin = omaru_polka(prf_key, pass_idx, rnd, i)
            p = i + ((b ^ coin) << (n - 1))
    return p


def la_darknesss(prf_key: bytes, y: int, n: int, passes: int = 4) -> int:
    """Thorp 反向（点态），与 mano_aloe 互逆：逆序逐轮 undo。"""
    if n < 1 or passes < 1:
        raise ValueError("n and passes must be >= 1")
    if not 0 <= y < (1 << n):
        raise ValueError("y out of domain")
    half = 1 << (n - 1)
    imask = half - 1
    p = y
    for pass_idx in reversed(range(passes)):
        for rnd in reversed(range(n)):
            i = p & imask
            btop = p >> (n - 1)
            coin = omaru_polka(prf_key, pass_idx, rnd, i)
            p = (i << 1) | (btop ^ coin)
    return p


def takane_lui(prf_key: bytes, x: int, domain_size: int, passes: int = 4) -> int:
    """任意域 N 的置换像：在 M=2^ceil(log2 N) 上 Thorp 后 cycle-walking 回 [0,N)。"""
    if domain_size < 1:
        raise ValueError("domain_size must be >= 1")
    if not 0 <= x < domain_size:
        raise ValueError("x out of domain")
    if domain_size == 1:
        return 0
    m = (domain_size - 1).bit_length()
    y = mano_aloe(prf_key, x, m, passes)
    while y >= domain_size:
        y = mano_aloe(prf_key, y, m, passes)
    return y


def isaki_riona(prf_key: bytes, y: int, domain_size: int, passes: int = 4) -> int:
    """任意域 N 的置换原像（逆方向 cycle-walking），与 takane_lui 互逆。"""
    if domain_size < 1:
        raise ValueError("domain_size must be >= 1")
    if not 0 <= y < domain_size:
        raise ValueError("y out of domain")
    if domain_size == 1:
        return 0
    m = (domain_size - 1).bit_length()
    x = la_darknesss(prf_key, y, m, passes)
    while x >= domain_size:
        x = la_darknesss(prf_key, x, m, passes)
    return x
