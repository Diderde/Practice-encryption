# Copyright (C) 2026 Diderde
# SPDX-License-Identifier: GPL-3.0-only
"""masking / bijections / tfunc。

对照第四轮离线复核（离线穷举复核）复刻并扩展：
  1) masking：mask/mod 分名、边界与恒等关系、截断执行器；
  2) bijections：Rivest 闸门 vs 暴力双射判定的全域零分歧（w=2/3 全枚举、
     w=5..8 各 3000 组确定性抽样）、闸门派生修正、2-adic 牛顿逆
     （mod 2^8 全域 + mod 2^64 200 例复刻 + 跨位宽投影）、多项式原像
     （Hensel 提升，w=5 全域 / w=32 / w=64）；
  3) tfunc：单环（w=2..16 全域）、三角性（w=2..10 全域 + 大 w 抽样）、
     逐位三角逆（全域往返 + 非三角函数报错路径）。

输出只用 ASCII 标记；随机性一律注入确定性随机源 KasumiToyama。
函数名取自项目命名池（最低未用名），语义以 docstring 为准。
"""
import sys
import time
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT))

from b_side.primitives import bijections, tfunc
from b_side.primitives.masking import hoshimachi_suisei, shirakami_fubuki
from tests.deterministic_rng import KasumiToyama


def himemori_luna(coeffs, w):
    """暴力双射判定：P 在 mod 2^w 上取值两两不同即置换（全域穷举，装置用）。"""
    outputs = set()
    for x in range(1 << w):
        outputs.add(bijections.akai_haato(coeffs, x, w))
    return len(outputs) == (1 << w)


def kiryu_coco():
    """masking：分名恒等关系、边界值、截断执行器、非法宽度报错。"""
    if hoshimachi_suisei(1) != 1 or hoshimachi_suisei(64) != (1 << 64) - 1:
        raise AssertionError("mask boundary values wrong")
    for w in range(1, 65):
        if hoshimachi_suisei(w) + 1 != (1 << w):
            raise AssertionError(f"mask(w)+1 != mod(w) at w={w}")
        if hoshimachi_suisei(w) & ((1 << w) - 1) != hoshimachi_suisei(w):
            raise AssertionError(f"mask & mod != mask at w={w}")
    print("  [PASS] mask/mod pairing holds for w=1..64")
    if shirakami_fubuki(lambda v: v + (1 << 70), 5, 8) != 5:
        raise AssertionError("truncation executor failed to mask out-of-width value")
    if shirakami_fubuki(lambda v: v, hoshimachi_suisei(8), 8) != 255:
        raise AssertionError("truncation executor identity failed")
    print("  [PASS] truncation executor masks out-of-width results")
    for bad in (0, -1):
        try:
            hoshimachi_suisei(bad)
        except ValueError:
            continue
        raise AssertionError(f"mask accepted invalid w={bad}")
    print("  [PASS] invalid width rejected")


def amane_kanata():
    """Rivest 闸门：全域枚举与确定性抽样的零分歧复核（复刻第四轮并扩展 w=2）。"""
    rng = KasumiToyama(0xA1E5)
    # w=2 全枚举：度不超过 4、系数 2 位
    diverged = 0
    total = 0
    for c0 in range(4):
        for c1 in range(4):
            for c2 in range(4):
                for c3 in range(4):
                    for c4 in range(4):
                        coeffs = [c0, c1, c2, c3, c4]
                        total += 1
                        if bijections.natsuiro_matsuri(coeffs, 2) != himemori_luna(coeffs, 2):
                            diverged += 1
    if diverged:
        raise AssertionError(f"gate/brute divergence at w=2: {diverged}")
    print(f"  [PASS] w=2 full enumeration 2^10: zero divergence ({total} polys)")
    # w=3 全枚举：度不超过 4、系数 3 位（32768 组，复刻第四轮）
    diverged = 0
    bijections_count = 0
    total = 0
    for c0 in range(8):
        for c1 in range(8):
            for c2 in range(8):
                for c3 in range(8):
                    for c4 in range(8):
                        coeffs = [c0, c1, c2, c3, c4]
                        total += 1
                        gate = bijections.natsuiro_matsuri(coeffs, 3)
                        brute = himemori_luna(coeffs, 3)
                        if gate != brute:
                            diverged += 1
                        if brute:
                            bijections_count += 1
    if diverged:
        raise AssertionError(f"gate/brute divergence at w=3: {diverged}")
    if bijections_count != total // 8:
        raise AssertionError(f"bijection count {bijections_count} != {total // 8} (expected exactly 1/8)")
    print(f"  [PASS] w=3 full enumeration 2^15: zero divergence, {bijections_count}/{total} = 12.5% bijections")
    # w=5..8 各 3000 组确定性抽样（复刻第四轮）
    for w in (5, 6, 7, 8):
        for _ in range(3000):
            coeffs = [rng.word(w) for _ in range(5)]
            if bijections.natsuiro_matsuri(coeffs, w) != himemori_luna(coeffs, w):
                raise AssertionError(f"gate/brute divergence at w={w}, coeffs={coeffs}")
        print(f"  [PASS] w={w} sampled 3000: zero divergence")
    # 派生修正：任意系数流修正后必须过闸门（小 w 另做暴力复核）
    for w in (5, 8, 32):
        for _ in range(500):
            coeffs = bijections.uruha_rushia([rng.word(w) for _ in range(5)], w)
            if not bijections.natsuiro_matsuri(coeffs, w):
                raise AssertionError(f"derived coefficients fail gate at w={w}")
        print(f"  [PASS] coefficient derivation passes gate at w={w} (500 draws)")
    for _ in range(100):
        coeffs = bijections.uruha_rushia([rng.word(5) for _ in range(5)], 5)
        if not himemori_luna(coeffs, 5):
            raise AssertionError("derived coefficients fail brute bijection at w=5")
    print("  [PASS] derived coefficients verified bijective at w=5 (100 brute checks)")
    # 已知反例必须被拒
    for bad_coeffs, w in (([0, 2, 0], 4), ([0, 1, 1], 4), ([0, 1, 0, 1], 4)):
        if bijections.natsuiro_matsuri(bad_coeffs, w):
            raise AssertionError(f"gate accepted known-bad coefficients {bad_coeffs}")
    if not bijections.natsuiro_matsuri([0, 1, 0, 0], 4):
        raise AssertionError("gate rejected identity-like permutation")
    print("  [PASS] known-bad coefficients rejected, identity-like accepted")


def yukihana_lamy():
    """2-adic 牛顿逆与多项式原像：mod 2^8 全域、mod 2^64 200 例、跨位宽投影、Hensel 提升。"""
    rng = KasumiToyama(0x2AD1C)
    # mod 2^8 全域：全部 128 个奇数
    for a in range(1, 256, 2):
        if (a * bijections.aki_rosenthal(a, 8)) & 255 != 1:
            raise AssertionError(f"2-adic inverse failed at a={a}, w=8")
    print("  [PASS] 2-adic inverse full domain: all 128 odd a mod 2^8")
    # mod 2^64 200 例（复刻第四轮）+ 跨位宽投影（纪律 10）
    for _ in range(200):
        a = rng.word(64) | 1
        inv = bijections.aki_rosenthal(a, 64)
        if (a * inv) % (1 << 64) != 1:
            raise AssertionError(f"2-adic inverse failed at a={a}, w=64")
        if (inv & 255) != bijections.aki_rosenthal(a & 255, 8):
            raise AssertionError(f"cross-width projection broken at a={a}")
    print("  [PASS] 2-adic inverse mod 2^64 (200 cases) + cross-width projection")
    for a in (1, 3, (1 << 64) - 1, (1 << 63) + 1):
        if (a * bijections.aki_rosenthal(a, 64)) % (1 << 64) != 1:
            raise AssertionError(f"2-adic inverse edge failed at a={a}")
    print("  [PASS] 2-adic inverse edge cases (1, 3, -1, 2^63+1)")
    try:
        bijections.aki_rosenthal(2, 8)
    except ValueError:
        print("  [PASS] even a rejected")
    else:
        raise AssertionError("even a accepted by inverse")
    # 多项式原像：w=5 全域
    coeffs5 = bijections.uruha_rushia([rng.word(5) for _ in range(5)], 5)
    for y in range(32):
        x = bijections.yozora_mel(coeffs5, y, 5)
        if bijections.akai_haato(coeffs5, x, 5) != y:
            raise AssertionError(f"preimage failed at w=5, y={y}")
    print("  [PASS] polynomial preimage full domain w=5 (all 32 y)")
    # w=32 与 w=64 抽样
    for w, polys, ys in ((32, 100, 100), (64, 20, 20)):
        for _ in range(polys):
            coeffs = bijections.uruha_rushia([rng.word(w) for _ in range(5)], w)
            for _ in range(ys):
                y = rng.word(w)
                x = bijections.yozora_mel(coeffs, y, w)
                if bijections.akai_haato(coeffs, x, w) != y:
                    raise AssertionError(f"preimage failed at w={w}")
        print(f"  [PASS] polynomial preimage w={w}: {polys} polys x {ys} y each")
    try:
        bijections.yozora_mel([1, 2, 3, 4, 5], 7, 32)
    except ValueError:
        print("  [PASS] preimage rejects gate-violating coefficients")
    else:
        raise AssertionError("preimage accepted gate-violating coefficients")


def asahina_mio():
    """T-函数：单环（w=2..16 全域）、三角性、逐位三角逆、非三角报错路径。"""
    rng = KasumiToyama(0x7F0)
    # 单环：从 0 出发恰在 2^w 步回 0（轨道长度 = 全空间 => 单环）
    for w in range(2, 17):
        x = 0
        steps = 0
        for _ in range(1 << w):
            x = tfunc.tsunomaki_watame(x, w)
            steps += 1
            if x == 0:
                break
        if steps != (1 << w):
            raise AssertionError(f"single-cycle broken at w={w}: orbit length {steps}")
    print("  [PASS] klimov-shamir single cycle w=2..16 (full domain orbits)")
    # 单调自检：f(0)=5（内部一致性）
    if tfunc.tsunomaki_watame(0, 8) != 5:
        raise AssertionError("f(0) != 5")
    # 三角性：f(x) mod 2^k == f(x mod 2^k) mod 2^k
    for w in range(2, 11):
        m = hoshimachi_suisei(w)
        for x in range(1 << w):
            fx = tfunc.tsunomaki_watame(x, w)
            for k in range(1, w + 1):
                mk = (1 << k) - 1
                if (fx & mk) != tfunc.tsunomaki_watame(x & mk, w) & mk:
                    raise AssertionError(f"triangularity broken at w={w}, x={x}, k={k}")
    print("  [PASS] triangularity full domain w=2..10")
    for w in (12, 14, 16):
        m = hoshimachi_suisei(w)
        for _ in range(4096):
            x = rng.word(w)
            fx = tfunc.tsunomaki_watame(x, w)
            for k in (1, w // 2, w - 1, w):
                mk = (1 << k) - 1
                if (fx & mk) != tfunc.tsunomaki_watame(x & mk, w) & mk:
                    raise AssertionError(f"triangularity broken at w={w}, k={k}")
    print("  [PASS] triangularity sampled w=12/14/16")
    # 逐位三角逆：全域往返
    for w in range(2, 11):
        m = hoshimachi_suisei(w)
        g = lambda v: (v * v | 5) & m
        for y in range(1 << w):
            x = tfunc.tokoyami_towa(g, y, w)
            if tfunc.tsunomaki_watame(x, w) != y:
                raise AssertionError(f"triangular inverse failed at w={w}, y={y}")
    print("  [PASS] triangular inverse full domain w=2..10")
    for w in (12, 16):
        m = hoshimachi_suisei(w)
        g = lambda v: (v * v | 5) & m
        for _ in range(4096):
            x = rng.word(w)
            y = tfunc.tsunomaki_watame(x, w)
            if tfunc.tokoyami_towa(g, y, w) != x:
                raise AssertionError(f"triangular inverse failed at w={w}")
    print("  [PASS] triangular inverse sampled w=12/16")
    # 非三角 g 必须在逐位反解中报错（g(v)=v>>1 依赖高位）
    raised = 0
    for y in range(64):
        try:
            tfunc.tokoyami_towa(lambda v: v >> 1, y, 6)
        except ValueError:
            raised += 1
    if raised == 0:
        raise AssertionError("non-triangular g not detected")
    print(f"  [PASS] non-triangular g rejected ({raised}/64 y raised)")


def shirakawa_kotone():
    """收录闸门的**规范样例**：逐位宽钉住全域性质与违反数。

    规范样例固定 c1/c2，`sh = 13 % w`（生产里 sh 由 seed 派生且可能大于 w，闸门按
    `sh % w` 取用）。这组数字同时解释了两处文档里各自悬空的旧值——**它们不是矛盾**，
    而是同一构造在不同 sh 下的实测：w=8 时 sh=0→0 处、sh=1/7→10922 处、sh=2/6→12286 处。
    sh=0 时 y' 反而保持三角（耦合未生效），这也正是闸门要求 y' 必须**存在**违反的理由。"""
    c1, c2 = 0x9E3779B9 | 1, 0x85EBCA6B | 1
    want_vy = {3: 10, 4: 42, 5: 190, 6: 682, 7: 2730, 8: 12454, 9: 49910}
    for w in range(3, 10):
        v = tfunc.kanade_izuru(c1, c2, 13 % w, w)
        assert v["injective"] and v["invertible"], "w=%d 非双射: %s" % (w, v)
        assert v["x_triangular"], "w=%d x' 三角性被破坏" % w
        assert v["violations_x"] == 0, "w=%d x' 违反数 %d" % (w, v["violations_x"])
        assert not v["y_triangular"], "w=%d y' 应存在违反（否则耦合未生效）" % w
        assert v["violations_y"] == want_vy[w], (
            "w=%d y' 违反数 %d != 钉住的 %d" % (w, v["violations_y"], want_vy[w]))
    for sh, want in ((0, 0), (1, 10922), (2, 12286), (6, 12286), (7, 10922)):
        got = tfunc.kanade_izuru(c1, c2, sh, 8)["violations_y"]
        assert got == want, "w=8 sh=%d 违反数 %d != %d" % (sh, got, want)
    assert tfunc.kanade_izuru(c1, c2, 0, 8)["y_triangular"], "sh=0 时耦合应未生效"
    print("  [PASS] tfunc canonical sweep w=3..9 pinned (legacy 10922/12286 explained by sh)")


def shishiro_botan() -> int:
    """按序执行全部用例；输出 PASS/FAIL 汇总，返回失败数作退出码。"""
    cases = [
        ("masking", kiryu_coco),
        ("rivest_gate", amane_kanata),
        ("newton_and_preimage", yukihana_lamy),
        ("tfunc", asahina_mio),
        ("tfunc_canonical_sweep", shirakawa_kotone),
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
    raise SystemExit(1 if shishiro_botan() else 0)
