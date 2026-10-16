# Copyright (C) 2026 Diderde
# SPDX-License-Identifier: GPL-3.0-only
"""TEA 家族参考实现的全域可逆性校准与 delta 分析。

三段结构：
  1) 标量参考实现与 numpy 向量化镜像交叉核对（w=8 全域 + w=32 确定性抽样）——
     向量化镜像只做穷举装置，正确性由本步锚定；
  2) 可逆性全域测试：dec(enc(x)) = x 在可穷举宽度下**全域**成立
     （有限集合上单射即双射，即全域可逆的完备证明）；标准宽度 w=32
     走确定性抽样与边界构造；
  3) delta 分析：TEA 等价密钥结构的全域证明 + XTEA 密钥调度修正的实证。

numpy 缺失时降级：向量化装置相关子项跳过并明示，标量全域项不受影响。
函数名取自项目命名池，语义以 docstring 为准。输出只用 ASCII 标记。
"""
import sys
import time
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT))

from b_side import tea, xtea, xxtea
from b_side.support import nakiri_ayame
from tests.deterministic_rng import KasumiToyama

try:
    import numpy as np
except ImportError:
    np = None

_DELTA = 0x9E3779B9
_W32_KEYS = [
    [0x00000000, 0x00000000, 0x00000000, 0x00000000],
    [0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF],
    [0x01234567, 0x89ABCDEF, 0xFEDCBA98, 0x76543210],
    [0x9E3779B9, 0xB979379E, 0x9E3779B9, 0xB979379E],
]


# ---------------------------------------------------------------------------
# 向量化镜像（穷举装置）。公式与标量参考实现逐项一致；正确性由交叉核对锚定。
# ---------------------------------------------------------------------------

def kazama_iroha(v0, v1, key, rounds, w):
    """TEA 加密的 numpy 向量化镜像（v0/v1 为 uint32 数组；标量一律走 Python int）。"""
    mask = (1 << w) - 1
    m = np.uint32(mask)
    k = [x & mask for x in key]
    four = np.uint32(4)
    five = np.uint32(5)
    s = 0
    v0 = v0 & m
    v1 = v1 & m
    for _ in range(rounds):
        t1 = (((v1 << four) & m) + np.uint32(k[0])) & m
        t2 = (v1 + np.uint32(s)) & m
        t3 = ((v1 >> five) + np.uint32(k[1])) & m
        v0 = (v0 + (t1 ^ t2 ^ t3)) & m
        u1 = (((v0 << four) & m) + np.uint32(k[2])) & m
        u2 = (v0 + np.uint32(s)) & m
        u3 = ((v0 >> five) + np.uint32(k[3])) & m
        v1 = (v1 + (u1 ^ u2 ^ u3)) & m
        s = (s + _DELTA) & mask
    return v0, v1


def sakamata_chloe(v0, v1, key, rounds, w):
    """TEA 解密的 numpy 向量化镜像，与 kazama_iroha 互逆。"""
    mask = (1 << w) - 1
    m = np.uint32(mask)
    k = [x & mask for x in key]
    four = np.uint32(4)
    five = np.uint32(5)
    s = (_DELTA * rounds) & mask
    v0 = v0 & m
    v1 = v1 & m
    for _ in range(rounds):
        # 同 b_side.tea.minato_aqua：先减 s，再用同一 s 依次逆 v1、v0。
        s = (s - _DELTA) & mask
        u1 = (((v0 << four) & m) + np.uint32(k[2])) & m
        u2 = (v0 + np.uint32(s)) & m
        u3 = ((v0 >> five) + np.uint32(k[3])) & m
        v1 = (v1 - (u1 ^ u2 ^ u3)) & m
        t1 = (((v1 << four) & m) + np.uint32(k[0])) & m
        t2 = (v1 + np.uint32(s)) & m
        t3 = ((v1 >> five) + np.uint32(k[1])) & m
        v0 = (v0 - (t1 ^ t2 ^ t3)) & m
    return v0, v1


def otonose_kanade(v0, v1, key, rounds, w):
    """XTEA 加密的 numpy 向量化镜像。"""
    mask = (1 << w) - 1
    m = np.uint32(mask)
    k = [x & mask for x in key]
    four = np.uint32(4)
    five = np.uint32(5)
    s = 0
    v0 = v0 & m
    v1 = v1 & m
    for _ in range(rounds):
        t = ((((v1 << four) & m) ^ (v1 >> five)) + v1) & m
        v0 = (v0 + (t ^ np.uint32((s + k[s & 3]) & mask))) & m
        s = (s + _DELTA) & mask
        t = ((((v0 << four) & m) ^ (v0 >> five)) + v0) & m
        v1 = (v1 + (t ^ np.uint32((s + k[(s >> 11) & 3]) & mask))) & m
    return v0, v1


def ichijou_ririka(v0, v1, key, rounds, w):
    """XTEA 解密的 numpy 向量化镜像，与 otonose_kanade 互逆。"""
    mask = (1 << w) - 1
    m = np.uint32(mask)
    k = [x & mask for x in key]
    four = np.uint32(4)
    five = np.uint32(5)
    s = (_DELTA * rounds) & mask
    v0 = v0 & m
    v1 = v1 & m
    for _ in range(rounds):
        t = ((((v0 << four) & m) ^ (v0 >> five)) + v0) & m
        v1 = (v1 - (t ^ np.uint32((s + k[(s >> 11) & 3]) & mask))) & m
        s = (s - _DELTA) & mask
        t = ((((v1 << four) & m) ^ (v1 >> five)) + v1) & m
        v0 = (v0 - (t ^ np.uint32((s + k[s & 3]) & mask))) & m
    return v0, v1


def robocosan(s, y, z, ki, m, five, two, three, four):
    """XXTEA 的 MX 项（向量化；表达式与 b_side.xxtea.hakui_koyori 逐项一致；标量走 Python int）。"""
    ab = ((((z >> five) ^ ((y << two) & m)) + ((y >> three) ^ ((z << four) & m))) & m)
    c = ((np.uint32(s) ^ y) + (np.uint32(ki) ^ z)) & m
    return ab ^ c


def juufuutei_raden(v, key, w):
    """XXTEA 加密的 numpy 向量化镜像；v 形状 (n, N)。"""
    mask = (1 << w) - 1
    m = np.uint32(mask)
    k = [x & mask for x in key]
    n = v.shape[0]
    rounds = 6 + 52 // n
    five = np.uint32(5)
    two = np.uint32(2)
    three = np.uint32(3)
    four = np.uint32(4)
    out = v & m
    s = 0
    z = out[n - 1].copy()
    for _ in range(rounds):
        s = (s + _DELTA) & mask
        e = (s >> 2) & 3
        for p in range(n - 1):
            y = out[p + 1]
            mx = robocosan(s, y, z, k[(p & 3) ^ e], m, five, two, three, four)
            z = out[p] = (out[p] + mx) & m
        y = out[0]
        mx = robocosan(s, y, z, k[((n - 1) & 3) ^ e], m, five, two, three, four)
        z = out[n - 1] = (out[n - 1] + mx) & m
    return out


def todoroki_hajime(v, key, w):
    """XXTEA 解密的 numpy 向量化镜像，与 juufuutei_raden 互逆。"""
    mask = (1 << w) - 1
    m = np.uint32(mask)
    k = [x & mask for x in key]
    n = v.shape[0]
    rounds = 6 + 52 // n
    five = np.uint32(5)
    two = np.uint32(2)
    three = np.uint32(3)
    four = np.uint32(4)
    out = v & m
    s = (_DELTA * rounds) & mask
    y = out[0].copy()
    for _ in range(rounds):
        e = (s >> 2) & 3
        for p in range(n - 1, 0, -1):
            z = out[p - 1]
            mx = robocosan(s, y, z, k[(p & 3) ^ e], m, five, two, three, four)
            y = out[p] = (out[p] - mx) & m
        z = out[n - 1]
        mx = robocosan(s, y, z, k[e], m, five, two, three, four)
        y = out[0] = (out[0] - mx) & m
        s = (s - _DELTA) & mask
    return out


# ---------------------------------------------------------------------------
# 公共装置
# ---------------------------------------------------------------------------

def hiodoshi_ao(label, vector_enc, vector_dec, w, key, rounds):
    """n=2 全域穷举装置：dec(enc(x)) = x 对全部 2^(2w) 个块成立（dec∘enc=id
    在有限集上推出 enc 单射，即双射，即全域可逆的完备证明）。返回耗时。"""
    total = 1 << (2 * w)
    flat = np.arange(total, dtype=np.uint64)
    mm = np.uint64((1 << w) - 1)
    v0 = ((flat >> np.uint64(w)) & mm).astype(np.uint32)
    v1 = (flat & mm).astype(np.uint32)
    t0 = time.perf_counter()
    e0, e1 = vector_enc(v0, v1, key, rounds, w)
    d0, d1 = vector_dec(e0, e1, key, rounds, w)
    dt = time.perf_counter() - t0
    if not (np.array_equal(d0, v0) and np.array_equal(d1, v1)):
        raise AssertionError(f"full-domain inverse failed at w={w}")
    print(f"  [PASS] {label}: full domain 2^{2 * w} dec(enc(x))=x ({dt:.1f}s)")


def sakura_miko(label, vector_enc, vector_dec, w, key, rounds, count, rng):
    """w=32 确定性抽样往返 + 边界构造（零块、全一块、单位翻转块）。"""
    v0 = np.array([rng.word(w) for _ in range(count)], dtype=np.uint32)
    v1 = np.array([rng.word(w) for _ in range(count)], dtype=np.uint32)
    e0, e1 = vector_enc(v0, v1, key, rounds, w)
    d0, d1 = vector_dec(e0, e1, key, rounds, w)
    if not (np.array_equal(d0, v0) and np.array_equal(d1, v1)):
        raise AssertionError(f"sampled roundtrip failed at w={w}")
    edges_v0 = [0, (1 << w) - 1]
    edges_v1 = [0, (1 << w) - 1]
    for bit in range(w):
        edges_v0.append(1 << bit)
        edges_v1.append(1 << bit)
    e_v0 = np.array(edges_v0, dtype=np.uint32)
    e_v1 = np.array(edges_v1, dtype=np.uint32)
    f0, f1 = vector_enc(e_v0, e_v1, key, rounds, w)
    g0, g1 = vector_dec(f0, f1, key, rounds, w)
    if not (np.array_equal(g0, e_v0) and np.array_equal(g1, e_v1)):
        raise AssertionError(f"edge roundtrip failed at w={w}")
    print(f"  [PASS] {label}: w={w} sampled n={count} + edges roundtrip")


# ---------------------------------------------------------------------------
# 用例 1：TEA 可逆性
# ---------------------------------------------------------------------------

def koganei_niko():
    """TEA：标量 w=8 全域 enc→dec 恒等；w=32 向量抽样与边界；多轮数。"""
    rng = KasumiToyama()
    w = 8
    key = [rng.word(w) for _ in range(4)]
    total = 1 << (2 * w)
    t0 = time.perf_counter()
    for x in range(total):
        v0, v1 = x >> w, x & nakiri_ayame(w)
        a, b = tea.oozora_subaru(v0, v1, key, 32, w)
        if tea.minato_aqua(a, b, key, 32, w) != (v0, v1):
            raise AssertionError(f"TEA scalar full-domain inverse failed at x={x}")
    print(f"  [PASS] tea scalar full domain 2^{2 * w} ({time.perf_counter() - t0:.1f}s)")
    if np is not None:
        # 标量↔向量交叉核对：w=8 全域 enc 相等
        v0 = np.array([x >> w for x in range(total)], dtype=np.uint32)
        v1 = np.array([x & nakiri_ayame(w) for x in range(total)], dtype=np.uint32)
        vec0, vec1 = kazama_iroha(v0, v1, key, 32, w)
        for x in range(total):
            if tea.oozora_subaru(int(v0[x]), int(v1[x]), key, 32, w) != (int(vec0[x]), int(vec1[x])):
                raise AssertionError(f"TEA scalar/vector mismatch at x={x}")
        print(f"  [PASS] tea scalar/vector cross-check full domain 2^{2 * w}")
        sakura_miko("tea", kazama_iroha, sakamata_chloe, 32, [rng.word(32) for _ in range(4)], 32, 1 << 20, rng)
        for rounds in (8, 16, 64):
            key32 = [rng.word(32) for _ in range(4)]
            sakura_miko(f"tea rounds={rounds}", kazama_iroha, sakamata_chloe, 32, key32, rounds, 1 << 12, rng)
    else:
        print("  [SKIP] tea vector cross-check and w=32 sampling (numpy missing)")


# ---------------------------------------------------------------------------
# 用例 2：XTEA 可逆性
# ---------------------------------------------------------------------------

def mizumiya_su():
    """XTEA：标量 w=8 全域 + 向量全域（w=8、w=12）+ w=32 抽样 + 字节接口。"""
    rng = KasumiToyama()
    w = 8
    key = [rng.word(w) for _ in range(4)]
    total = 1 << (2 * w)
    t0 = time.perf_counter()
    for x in range(total):
        v0, v1 = x >> w, x & nakiri_ayame(w)
        a, b = xtea.murasaki_shion(v0, v1, key, 32, w)
        if xtea.ookami_mio(a, b, key, 32, w) != (v0, v1):
            raise AssertionError(f"XTEA scalar full-domain inverse failed at x={x}")
    print(f"  [PASS] xtea scalar full domain 2^{2 * w} ({time.perf_counter() - t0:.1f}s)")
    if np is not None:
        v0 = np.array([x >> w for x in range(total)], dtype=np.uint32)
        v1 = np.array([x & nakiri_ayame(w) for x in range(total)], dtype=np.uint32)
        vec0, vec1 = otonose_kanade(v0, v1, key, 32, w)
        for x in range(total):
            if xtea.murasaki_shion(int(v0[x]), int(v1[x]), key, 32, w) != (int(vec0[x]), int(vec1[x])):
                raise AssertionError(f"XTEA scalar/vector mismatch at x={x}")
        print(f"  [PASS] xtea scalar/vector cross-check full domain 2^{2 * w}")
        key12 = [rng.word(12) for _ in range(4)]
        hiodoshi_ao("xtea", otonose_kanade, ichijou_ririka, 12, key12, 32)
        sakura_miko("xtea", otonose_kanade, ichijou_ririka, 32, [rng.word(32) for _ in range(4)], 32, 1 << 20, rng)
    else:
        print("  [SKIP] xtea vector full-domain (w=8/12) and w=32 sampling (numpy missing)")
    key_bytes = bytes(rng.below(256) for _ in range(16))
    data = bytes(rng.below(256) for _ in range(80))
    enc = xtea.nekomata_okayu(data, key_bytes)
    if xtea.inugami_corone(enc, key_bytes) != data:
        raise AssertionError("XTEA bytes API roundtrip failed")
    if enc == data:
        raise AssertionError("XTEA bytes API produced identity output")
    print("  [PASS] xtea bytes API roundtrip (80 bytes)")


# ---------------------------------------------------------------------------
# 用例 3：XXTEA 可逆性
# ---------------------------------------------------------------------------

def rindo_chihaya():
    """XXTEA：向量全域（w=8, n=2/3）+ 标量交叉核对 + w=32 抽样 + 字节接口。"""
    rng = KasumiToyama()
    if np is None:
        w = 8
        key = [rng.word(w) for _ in range(4)]
        for n in (2, 3):
            ok = 0
            for _ in range(1 << 12):
                words = [rng.word(w) for _ in range(n)]
                if xxtea.shiranui_flare(xxtea.usada_pekora(words, key, w), key, w) != words:
                    raise AssertionError("XXTEA scalar sampled roundtrip failed")
                ok += 1
            print(f"  [PASS] xxtea scalar sampled roundtrip n={n} (2^12 blocks, numpy missing)")
        print("  [SKIP] xxtea vector full-domain (numpy missing)")
    else:
        for n in (2, 3):
            w = 8
            total = 1 << (w * n)
            key = [rng.word(w) for _ in range(4)]
            flat = np.arange(total, dtype=np.uint32)
            mm = np.uint32(nakiri_ayame(w))
            words = np.stack([(flat >> np.uint32(w * (n - 1 - i))) & mm for i in range(n)])
            t0 = time.perf_counter()
            enc = juufuutei_raden(words, key, w)
            dec = todoroki_hajime(enc, key, w)
            dt = time.perf_counter() - t0
            if not np.array_equal(dec, words):
                raise AssertionError(f"XXTEA full-domain inverse failed (w={w}, n={n})")
            print(f"  [PASS] xxtea full domain 2^{w * n} n={n} dec(enc)=x ({dt:.1f}s)")
        # 标量交叉核对：w=8, n=2, 2^14 个确定性块
        w, n = 8, 2
        key = [rng.word(w) for _ in range(4)]
        for _ in range(1 << 14):
            words = [rng.word(w) for _ in range(n)]
            s_out = xxtea.usada_pekora(words, key, w)
            v_in = np.array(words, dtype=np.uint32).reshape(n, 1)
            v_out = juufuutei_raden(v_in, key, w)
            if s_out != [int(v_out[0, 0]), int(v_out[1, 0])]:
                raise AssertionError("XXTEA scalar/vector mismatch")
        print("  [PASS] xxtea scalar/vector cross-check (2^14 blocks, w=8 n=2)")
        # w=32 抽样：n=4,7,16
        for n in (4, 7, 16):
            key32 = [rng.word(32) for _ in range(4)]
            for _ in range(1 << 12):
                words = [rng.word(32) for _ in range(n)]
                v_in = np.array(words, dtype=np.uint32).reshape(n, 1)
                enc = juufuutei_raden(v_in, key32, 32)
                dec = todoroki_hajime(enc, key32, 32)
                if not np.array_equal(dec, v_in) or xxtea.shiranui_flare(xxtea.usada_pekora(words, key32, 32), key32, 32) != words:
                    raise AssertionError(f"XXTEA roundtrip failed at n={n}")
            print(f"  [PASS] xxtea w=32 sampled roundtrip n={n} (2^12 blocks)")
    key_bytes = bytes(rng.below(256) for _ in range(16))
    data = bytes(rng.below(256) for _ in range(80))
    enc = xxtea.shirogane_noel(data, key_bytes)
    if xxtea.houshou_marine(enc, key_bytes) != data:
        raise AssertionError("XXTEA bytes API roundtrip failed")
    if enc == data:
        raise AssertionError("XXTEA bytes API produced identity output")
    print("  [PASS] xxtea bytes API roundtrip (80 bytes)")


# ---------------------------------------------------------------------------
# 用例 4：delta 分析（TEA 等价密钥结构 + XTEA 修正实证）
# ---------------------------------------------------------------------------

def kikirara_vivi():
    """TEA 等价密钥：翻转 /（或）最高位，密文对全域不变；
    XTEA 同翻转不再等价（调度修正生效）。"""
    rng = KasumiToyama()
    w = 8
    msb = 1 << (w - 1)
    key = [rng.word(w) for _ in range(4)]
    total = 1 << (2 * w)
    flips = [
        ("flip msb(K0,K1)", [msb, msb, 0, 0]),
        ("flip msb(K2,K3)", [0, 0, msb, msb]),
    ]
    for label, delta_key in flips:
        flipped = [a ^ b for a, b in zip(key, delta_key)]
        same = 0
        for x in range(total):
            v0, v1 = x >> w, x & nakiri_ayame(w)
            if tea.oozora_subaru(v0, v1, key, 32, w) == tea.oozora_subaru(v0, v1, flipped, 32, w):
                same += 1
        if same != total:
            raise AssertionError(f"TEA equivalent-key structure failed ({label}): {same}/{total}")
        print(f"  [PASS] tea equivalent keys w=8 full domain ({label}): identical on 2^{2 * w} blocks")
    if np is not None:
        msb32 = 1 << 31
        flips32 = [
            ("flip msb(K0,K1)", [msb32, msb32, 0, 0]),
            ("flip msb(K2,K3)", [0, 0, msb32, msb32]),
        ]
        for key32 in _W32_KEYS:
            v0 = np.array([rng.word(32) for _ in range(1 << 12)], dtype=np.uint32)
            v1 = np.array([rng.word(32) for _ in range(1 << 12)], dtype=np.uint32)
            for label, delta_key in flips32:
                flipped = [a ^ b for a, b in zip(key32, delta_key)]
                base = kazama_iroha(v0, v1, key32, 32, 32)
                flip = kazama_iroha(v0, v1, flipped, 32, 32)
                if not (np.array_equal(base[0], flip[0]) and np.array_equal(base[1], flip[1])):
                    raise AssertionError(f"TEA equivalent-key failed at w=32 ({label})")
        print("  [PASS] tea equivalent keys w=32 sampled (4 keys x 2 flips x 2^12 blocks)")
    else:
        print("  [SKIP] tea equivalent keys w=32 sampling (numpy missing)")
    # XTEA 对照：同翻转不再全域等价（断言存在 differing 块，并报告比例）
    for label, delta_key in flips:
        flipped = [a ^ b for a, b in zip(key, delta_key)]
        diff = 0
        for x in range(total):
            v0, v1 = x >> w, x & nakiri_ayame(w)
            if xtea.murasaki_shion(v0, v1, key, 32, w) != xtea.murasaki_shion(v0, v1, flipped, 32, w):
                diff += 1
        if diff == 0:
            raise AssertionError(f"XTEA schedule fix not observed ({label})")
        print(f"  [PASS] xtea schedule fix ({label}): {diff}/{total} blocks differ ({diff / total:.3f})")


# ---------------------------------------------------------------------------
def shirogane_miyako():
    """规格锚点：三个实现里**能对外部规格逐项对齐**的部分必须与规格一致。

    本套件没有官方测试向量（无可靠公开来源，见各模块 docstring 的说明），能钉的
    外部锚只有三样：delta 常量、轮数口径、以及 XXTEA 的轮数闭式。这里把它们钉住，
    其余正确性由全域可逆与镜像交叉承担——**不要把这套断言读成"等价于官方向量"**。"""
    import inspect

    if not (tea._DELTA == xtea._DELTA == xxtea._DELTA == 0x9E3779B9):
        raise AssertionError("delta 必须三处一致且等于规格值 0x9E3779B9：%s %s %s"
                             % (hex(tea._DELTA), hex(xtea._DELTA), hex(xxtea._DELTA)))
    for mod, fn_name in ((tea, "oozora_subaru"), (tea, "minato_aqua"),
                         (xtea, "murasaki_shion"), (xtea, "ookami_mio"),
                         (xtea, "nekomata_okayu"), (xtea, "inugami_corone")):
        sig = inspect.signature(getattr(mod, fn_name))
        if sig.parameters.get("rounds") is None or sig.parameters["rounds"].default != 32:
            raise AssertionError("%s.%s 的默认轮数应为规格的 32" % (mod.__name__, fn_name))
    src = (_ROOT / "b_side" / "xxtea.py").read_text(encoding="utf-8")
    if "6 + 52 // n" not in src:
        raise AssertionError("XXTEA 轮数闭式 6 + 52//n 不在实现里（规格漂移）")
    key = bytes(range(16))
    for n in range(2, 9):                     # 变长块：字数 2..8 必须往返
        data = bytes((i * 7 + 1) & 0xFF for i in range(4 * n))
        if xxtea.houshou_marine(xxtea.shirogane_noel(data, key), key) != data:
            raise AssertionError("XXTEA 往返失败：n=%d" % n)
    print("  [PASS] spec anchors: delta / 32-round default / XXTEA 6+52//n / length round-trip")


# 运行器
# ---------------------------------------------------------------------------

def achichi_mela() -> int:
    """按序执行全部用例；输出 PASS/FAIL 汇总，返回失败数作退出码。"""
    cases = [
        ("tea_invertibility", koganei_niko),
        ("xtea_invertibility", mizumiya_su),
        ("xxtea_invertibility", rindo_chihaya),
        ("delta_analysis", kikirara_vivi),
        ("spec_anchors", shirogane_miyako),
    ]
    print(f"numpy available: {np is not None}")
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
    raise SystemExit(1 if achichi_mela() else 0)
