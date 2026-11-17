# Copyright (C) 2026 Diderde
# SPDX-License-Identifier: GPL-3.0-only
"""permuter（Thorp 骨架 + cycle-walking）。

可逆性论证形态与一致：有限域上 dec(enc(x)) = x 全域成立 + 全域像集合
恰为 [0,N)（单射即双射）。PRF 复用  XTEA 参考实现（确定性，同种子必同
置换）。输出只用 ASCII 标记。
"""
import sys
import time
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT))

from b_side.primitives import permuter


def gawr_gura():
    """2 的幂域：全域双射 + 互逆（n=1..12 逐级）。"""
    rng = permuter.sorashina_sopia(0x7402)
    for n in (1, 2, 3, 4, 6, 8, 12):
        size = 1 << n
        t0 = time.perf_counter()
        images = set()
        for x in range(size):
            y = permuter.mano_aloe(rng, x, n)
            if permuter.la_darknesss(rng, y, n) != x:
                raise AssertionError(f"thorp inverse failed at n={n}, x={x}")
            images.add(y)
        if images != set(range(size)):
            raise AssertionError(f"thorp not bijective at n={n}")
        print(f"  [PASS] thorp full domain 2^{n}: bijective + inverse ({time.perf_counter() - t0:.1f}s)")


def irys():
    """任意域 N（cycle-walking）：全域双射 + 互逆，含奇数与 2^m±1 边界。"""
    key = permuter.sorashina_sopia(0xC1A9)
    for size in (1, 2, 3, 5, 10, 99, 100, 255, 256, 999, 1000, 4095):
        t0 = time.perf_counter()
        images = set()
        for x in range(size):
            y = permuter.takane_lui(key, x, size)
            if permuter.isaki_riona(key, y, size) != x:
                raise AssertionError(f"kernel inverse failed at N={size}, x={x}")
            images.add(y)
        if images != set(range(size)):
            raise AssertionError(f"kernel not bijective at N={size}")
        print(f"  [PASS] kernel N={size}: bijective + inverse ({time.perf_counter() - t0:.1f}s)")


def ouro_kronii():
    """确定性（同种子必同）、种子敏感性（异种子必异）、域越界报错。"""
    k1 = permuter.sorashina_sopia(1234)
    k2 = permuter.sorashina_sopia(1234)
    if k1 != k2:
        raise AssertionError("same seed must derive same PRF key")
    table_a = [permuter.takane_lui(k1, x, 256) for x in range(256)]
    table_b = [permuter.takane_lui(k1, x, 256) for x in range(256)]
    if table_a != table_b:
        raise AssertionError("same seed must yield identical permutation")
    print("  [PASS] determinism: same seed -> identical permutation (N=256)")
    k3 = permuter.sorashina_sopia(1235)
    table_c = [permuter.takane_lui(k3, x, 256) for x in range(256)]
    if table_a == table_c:
        raise AssertionError("different seeds produced identical permutation (unexpected)")
    if table_a != list(range(256)) and table_c != list(range(256)):
        print("  [PASS] seed sensitivity: different seed -> different permutation")
    else:
        raise AssertionError("a seed produced the identity permutation (unexpected)")
    for bad_x in (-1, 256, 4096):
        try:
            permuter.takane_lui(k1, bad_x, 256)
        except ValueError:
            continue
        raise AssertionError(f"domain violation accepted: x={bad_x}")
    print("  [PASS] out-of-domain x rejected")


def shiore_miyuki():
    """**点态（oblivious）性质的代理测试**——这条性质是"运行时逐点解密"的正确性前提。

    `permuter` 的 docstring 声明"单个点的像只依赖该点自身路径，不触碰其他位置"。
    严格证明访问模式要读实现，这里用三条**可证伪**的代理断言把性质钉住：
      1. **内存与域大小无关**：n=16 与 n=24 单点求像的峰值分配几乎相同——物化整表的
         实现会随 2^n 增长（n=24 时至少 16 MB），一测就露；
      2. **无跨调用状态**：先算一遍，再灌入一批不同 key/点的调用，重算同一结果不变；
      3. **记忆化是纯的**：清空 `_COIN_CACHE` 前后结果一致（缓存只该省时间，不改结果）。"""
    import tracemalloc

    key = permuter.sorashina_sopia(0x5EED)
    key2 = permuter.sorashina_sopia(0x5EEE)

    def peak(n):
        tracemalloc.start()
        try:
            permuter.mano_aloe(key, (1 << (n - 1)) | 3, n)
            return tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()

    p16, p24 = peak(16), peak(24)
    if p24 - p16 > 65536:
        raise AssertionError("单点求像的内存随域增长（点态性存疑）：n=16 %d B, n=24 %d B"
                             % (p16, p24))

    x, n = 0x1234, 16
    before = permuter.mano_aloe(key, x, n)
    for i in range(64):                       # 灌入无关调用（换 key、换点、换域）
        permuter.mano_aloe(key2, (i * 37) % (1 << 12), 12)
    after = permuter.mano_aloe(key, x, n)
    if before != after:
        raise AssertionError("同一 (key, x) 在无关调用后结果改变（存在跨调用状态）")

    cached = permuter.mano_aloe(key, x, n)
    permuter._COIN_CACHE.clear()
    cleared = permuter.mano_aloe(key, x, n)
    if cached != cleared:
        raise AssertionError("清缓存前后结果不一致（记忆化不是纯函数）")
    print("  [PASS] pointwise/oblivious proxies: O(1) memory in domain, stateless, pure cache")


def hakos_baelz() -> int:
    """按序执行全部用例；输出 PASS/FAIL 汇总，返回失败数作退出码。"""
    cases = [
        ("thorp_power_of_two", gawr_gura),
        ("kernel_arbitrary_domain", irys),
        ("determinism_and_seeds", ouro_kronii),
        ("thorp_pointwise_proxies", shiore_miyuki),
    ]
    failed = 0
    for name, fn in cases:
        t0 = time.perf_counter()
        try:
            fn()
            print(f"[PASS] {name} ({time.perf_counter() - t0:.1f}s)")
        except AssertionError as exc:
            failed += 1
            print(f"[FAIL] {name}: {exc}")
        except Exception as exc:  # noqa: BLE001 - runner must survive any case error
            failed += 1
            print(f"[FAIL] {name}: unexpected {type(exc).__name__}: {exc}")
    print(f"summary: {len(cases) - failed} passed, {failed} failed")
    return failed


if __name__ == "__main__":
    raise SystemExit(1 if hakos_baelz() else 0)
