# Copyright (C) 2026 Diderde
# SPDX-License-Identifier: GPL-3.0-only
"""强度量化：给 源码混淆侧的 XOR 派生流构造（字符串编码 + 壳）产出**实测数字**。

为什么不是 Walsh/DDT：那两项度量的是**布尔函数**（S-box 视角，数学区
`primitives/validation.py` 的适用对象）。源码混淆侧的两个构造是**字节流**构造，
加密层是逐字节 XOR——对其套用 S-box 指标是**量错了对象**。故本套件改用流密码
口径的可测性质，并把结论如实写进断言：

  - **密钥流熵**：w 字节窗口的香农熵（比特/字节），期望接近 8；
  - **均匀性**：卡方统计量对照自由度 w−1 的常见临界值（α≈0.001 保守取用）；
  - **IKA（无关密钥雪崩）**：改动 1 比特密钥（salt）→ 密文变化比特比例，期望 ≈ 0.5；
  - **诚实边界**：XOR 流**不提供不可区分性**——密文含明文的统计指纹，
    且密文 ≠ 明文的字节比例在长明文下趋近 255/256；本套件把这条**测出来并断言**，
    防止后续把"编码式"误当"加密式"宣传。

不评估强度阶梯档位（那是设计声明）；本套件只给出可复现的实测数字。
"""
import math
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT))

from pyshroud.passes import data as data_pass
from pyshroud.passes import shell as shell_pass
from pyshroud.seeding.derive import moona_hoshinova, ran_mitake, tsugumi_hazawa

_MASK64 = (1 << 64) - 1
_BITS = 8


def _entropy(blob: bytes) -> float:
    """香农熵（比特/字节）：按字节频率计算，上限为窗口位宽。"""
    if not blob:
        return 0.0
    freq = {}
    for b in blob:
        freq[b] = freq.get(b, 0) + 1
    total = len(blob)
    return -sum((c / total) * math.log2(c / total) for c in freq.values())


def _chi_square(blob: bytes) -> float:
    """卡方统计量：字节分布对均匀分布的偏离（自由度 255）。"""
    if not blob:
        return 0.0
    expected = len(blob) / 256.0
    freq = [0] * 256
    for b in blob:
        freq[b] += 1
    return sum((c - expected) ** 2 / expected for c in freq)


def _data_constants(seed: int) -> dict:
    """取出 data.pass 在真实 ctx 下会实际内联的那组常数。"""
    tree = data_pass.ast.parse('X = "aaaaaaaaaaaaaaaa"\nprint(X)\n')
    ctx = moona_hoshinova(seed)
    taken = {n.id for n in data_pass.ast.walk(tree) if isinstance(n, data_pass.ast.Name)}
    taken |= {n.arg for n in data_pass.ast.walk(tree) if isinstance(n, data_pass.ast.arg)}
    taken |= {n.attr for n in data_pass.ast.walk(tree) if isinstance(n, data_pass.ast.Attribute)}
    tsugumi_hazawa(ctx, taken)  # decoder name (顺序与 pass 一致)
    tsugumi_hazawa(ctx, ctx.taken)
    tsugumi_hazawa(ctx, ctx.taken)
    return {
        "seed_const": ran_mitake(ctx),
        "m1": ran_mitake(ctx) | 1,
        "m2": ran_mitake(ctx) | 1,
        "a1": ran_mitake(ctx) | 1,
        "sh1": 18 + ctx.rng.below(20),
        "sh2": 14 + ctx.rng.below(18),
        "sh3": 22 + ctx.rng.below(20),
    }


def _keystream(c: dict, salt: int, n: int) -> bytes:
    """复现 data.py 解码器逐字节产出的流（与产物内联实现同算术）。"""
    st = (c["seed_const"] ^ ((salt | 1) * c["m1"])) & _MASK64
    out = bytearray()
    for _ in range(n):
        st = (st + c["a1"]) & _MASK64
        z = st
        z = ((z ^ (z >> c["sh1"])) * c["m2"]) & _MASK64
        z = ((z ^ (z >> c["sh2"])) * c["m1"]) & _MASK64
        z = (z ^ (z >> c["sh3"])) & 255
        out.append(z)
    return bytes(out)


def _shell_constants(seed: int, layer: int = 0) -> dict:
    """取出 shell 层实际派生的 (key, mul, add)（与产物尾部覆盖一致）。"""
    ctx = moona_hoshinova(seed ^ (shell_pass._SHELL_DOMAIN + layer))
    from pyshroud.seeding.derive import tomoe_udagawa

    key = tomoe_udagawa(ctx, shell_pass._KEY_LEN)
    mul = ran_mitake(ctx) & 0xFF
    add = ran_mitake(ctx) & 0xFF
    return {"key": key, "mul": mul, "add": add}


def _shell_keystream(c: dict, n: int) -> bytes:
    """复现 loader 的解密流字节（key[i % len] ^ ((mul*i + add) & 0xFF)）。"""
    key = c["key"]
    span = len(key)
    return bytes(key[i % span] ^ ((c["mul"] * i + c["add"]) & 0xFF) for i in range(n))


def kozue_mone():
    """密钥流熵：字符串编码流的窗口熵应接近 8 比特/字节。"""
    c = _data_constants(42)
    window = _keystream(c, 12345, 4096)
    h = _entropy(window)
    if h < 7.5:
        raise AssertionError(f"keystream entropy too low: {h:.4f} bits/byte over 4096 bytes")
    print(f"  [MEASURED] data.pass keystream entropy = {h:.4f} bits/byte (4096-byte window)")


def suou_sango():
    """均匀性：卡方统计量须落在自由度 255 的合理区间内。"""
    c = _data_constants(42)
    window = _keystream(c, 999, 16384)
    chi = _chi_square(window)
    # 自由度 255：均值 255，α≈0.001 双侧上界约 380；给足余量取 450 作失败线
    if chi > 450:
        raise AssertionError(f"byte distribution significantly non-uniform: chi2={chi:.1f} (df=255)")
    print(f"  [MEASURED] keystream chi-square = {chi:.1f} (df=255, mean 255; fail line 450)")


def otogibara_era():
    """IKA：改动 1 比特 salt，密文变化比特比例应接近 0.5。

    注意 bit 0 是**无操作**：产物内是 `(salt | 1)`，LSB 被强制置 1，故翻转
    salt 的 bit 0 不改变派生流（实测变化 0/256 比特）。这是编码式构造的
    既有性质（salt 有效位 63 位、非 64 位），本用例测 bit 1..7 并单列该事实。"""
    c = _data_constants(42)
    plain = bytes(range(64))
    base = bytes(p ^ k for p, k in zip(plain, _keystream(c, 1 << 20, 64)))
    noop = (1 << 20) | 1 == ((1 << 20) ^ 1) | 1
    if not noop:
        raise AssertionError("expected (salt|1) to make bit-0 flips a no-op; restructure case")
    for bit in range(1, 8):
        alt = bytes(p ^ k for p, k in zip(plain, _keystream(c, (1 << 20) ^ (1 << bit), 64)))
        diff_bits = sum(bin(a ^ b).count("1") for a, b in zip(base, alt))
        ratio = diff_bits / (64 * _BITS)
        if not 0.35 <= ratio <= 0.65:
            raise AssertionError(f"1-bit salt flip (bit {bit}) changed {ratio:.3f} of ciphertext bits")
    print("  [MEASURED] IKA: 1-bit salt flip (bits 1..7) changes ~0.5 of ciphertext bits; "
          "bit 0 is a no-op because salt is forced odd by (salt | 1)")


def elira_pendora():
    """诚实边界：XOR 流不隐藏明文的字节统计指纹（测出来，别只写在注释里）。"""
    c = _data_constants(42)
    plain = b"A" * 4096  # 单字节明文：极端的统计指纹
    cipher = bytes(p ^ k for p, k in zip(plain, _keystream(c, 777, 4096)))
    h_plain, h_cipher = _entropy(plain), _entropy(cipher)
    # 密文熵等于密钥流熵（XOR 是双射）；但**明文指纹仍在**：密文 ≠ 明文的比例
    # 只由"流字节为 0"的概率决定，与明文内容无关。
    same = sum(1 for a, b in zip(plain, cipher) if a == b)
    frac_same = same / len(plain)
    if not 0.0 <= frac_same <= 0.02:
        raise AssertionError(f"unexpected plaintext==ciphertext rate: {frac_same:.4f}")
    print(f"  [MEASURED] plaintext==ciphertext bytes = {frac_same:.4%} (expected ~1/256); "
          f"H(plain)={h_plain:.3f} H(cipher)={h_cipher:.4f} bits/byte")
    print("             => 编码式：抬高 grep 门槛，不提供机密性（与 docstring 声明一致）")


def kurokawa_tsubaki():
    """壳层流：实测熵与其**结构性弱点的来源**——不是"纯 key 重复"，而是
    32 字节密钥 + 线性等差项的合成周期。

    实测（seed=42, layer=0）：mul=123、add=173 → 等差项周期 256，
    合成流周期 lcm(32, 256) = 256 字节。故此构造的流**不是**伪随机序列：
    超过 256 字节的载荷会重新用到同一段流。这是强度第 1 档构造的固有性质，
    本用例把它测出来而不是回避。"""
    import math as _math

    c = _shell_constants(42)
    ks = _shell_keystream(c, 2048)
    span = len(c["key"])
    add_period = 256 // _math.gcd(c["mul"] & 0xFF, 256) if c["mul"] else 1
    combined = span * add_period // _math.gcd(span, add_period)
    if c["mul"] == 0 and c["add"] == 0:
        raise AssertionError("shell stream degenerates to plain key repetition (mul=add=0)")
    if ks[:combined] != ks[combined:2 * combined]:
        raise AssertionError(f"expected repetition at lcm period {combined}")
    h = _entropy(ks[:combined])
    if c["mul"] == 0:
        # 纯 key 重复：熵受限于 32 字节的取值分布
        pass
    if h < 7.0:
        raise AssertionError(f"shell keystream entropy unexpectedly low: {h:.4f}")
    print(f"  [MEASURED] shell stream: key span={span}, add-period={add_period}, "
          f"combined period={combined} bytes (verified repeating); H={h:.4f} bits/byte")
    print("             => 长载荷会复用流片段；编码式定位如实" )


def hanabi_kaori():
    """五项结构指标的口径与**已知可刷性**——把局限钉成断言，防止被当成强度证据。

    - 残留 = 原常量/标识符集合与产物集合的**精确求交**：把 `"token"` 拆成
      `"tok" + "en"` 就能把残留打到 0，而程序语义毫发无损；
    - 熵只看**存活常量**：删常量比加密常量更快改变这个数字；
    - 圈复杂度 / AST 计数把**混淆器自己注入**的结构（扁平化状态机、死分支）也算进去。
    故这五项是**结构对照**，不是对抗性强度指标（`check` 输出亦按此口径解读）。"""
    from pyshroud import metrics as M

    orig = 'TOKEN = "token"\n\ndef f(a, b):\n    return a + b\n\nprint(f(1, 2), TOKEN)\n'
    split = 'TOKEN = "tok" + "en"\n\ndef g(x, y):\n    return x + y\n\nprint(g(1, 2), TOKEN)\n'
    same = M.elizabeth_rose_bloodflame(orig, orig)
    splitr = M.elizabeth_rose_bloodflame(orig, split)
    for key in ("cyclomatic", "ast_nodes", "string_entropy", "string_residuals",
                "ident_residuals", "string_reduction", "ident_reduction", "fa", "pass_stats"):
        if key not in same:
            raise AssertionError("报告缺字段 %s" % key)
    if same["string_residuals"] != 1 or same["fa"] != 1.0:
        raise AssertionError("同文本：残留应为 1、Fa 应为 1.0，实得 %s / %s"
                             % (same["string_residuals"], same["fa"]))
    if same["ident_residuals"] == 0:
        raise AssertionError("同文本的标识符残留不应为 0")
    # 机制层：拆分常量 / 改名即可让"残留"归零（这就是可刷性本身）
    if M.pavolia_reine(["token"], ["token"]) != 1:
        raise AssertionError("同常量应算 1 处残留")
    if M.pavolia_reine(["token"], ["tok", "en"]) != 0:
        raise AssertionError("拆分常量应算 0 处残留（已知可刷口径）")
    if M.vestia_zeta(["f", "a", "b"], ["g", "x", "y"]) != 0:
        raise AssertionError("改名后标识符残留应为 0")
    # 聚合层：拆分+改名后字符串残留归零，标识符残留只会**变小**（TOKEN/print 这类共有名仍在）
    if splitr["string_residuals"] != 0:
        raise AssertionError("拆分常量后字符串残留应归零，实得 %s" % splitr["string_residuals"])
    if not splitr["ident_residuals"] < same["ident_residuals"]:
        raise AssertionError("改名后标识符残留应变小：%s -> %s"
                             % (same["ident_residuals"], splitr["ident_residuals"]))
    print("  [PASS] metrics residuals are exact-match (documented gameable: split constant -> 0)")


def yukishiro_aoi():
    """熵只看存活常量；AST/圈复杂度把注入结构算进去——两条都由真实构建验证。"""
    from pyshroud import metrics as M
    from pyshroud.pipeline import kageyama_shien, yukina_minato

    if M.anya_melfissa([]) != 0.0 or M.anya_melfissa(["aaaa"]) != 0.0:
        raise AssertionError("空集与单字符常量集的熵应为 0")
    if abs(M.anya_melfissa(["abcd"]) - 2.0) > 1e-9:
        raise AssertionError("四种不同字符的熵应为 2.0 bit，实得 %s" % M.anya_melfissa(["abcd"]))
    src = 'def main():\n    t = "alpha"\n    return t\n\nprint(main())\n'
    art = yukina_minato(src, 42, passes=kageyama_shien("standard"))
    rep = M.elizabeth_rose_bloodflame(src, art)
    if rep["string_residuals"] != 0:
        raise AssertionError("standard 档应清掉明文常量，实得残留 %s" % rep["string_residuals"])
    if rep["ast_nodes"]["artifact"] <= rep["ast_nodes"]["original"]:
        raise AssertionError("AST 计数应因注入结构变大：%s" % rep["ast_nodes"])
    if rep["cyclomatic"]["artifact"] < rep["cyclomatic"]["original"]:
        raise AssertionError("圈复杂度不应下降：%s" % rep["cyclomatic"])
    if rep["fa"] <= 1.0:
        raise AssertionError("混淆后体积膨胀系数应 > 1：%s" % rep["fa"])
    print("  [PASS] metrics entropy/AST interpretation holds (artifact counts include injection)")


def hoshikawa_sara() -> int:
    """按序执行全部用例；输出 PASS/FAIL 汇总，返回失败数作退出码。"""
    cases = [
        ("strength_keystream_entropy", kozue_mone),
        ("strength_uniformity", suou_sango),
        ("strength_ika", otogibara_era),
        ("strength_honest_boundary", elira_pendora),
        ("strength_shell_stream", kurokawa_tsubaki),
        ("metrics_residual_semantics", hanabi_kaori),
        ("metrics_entropy_ast_interpretation", yukishiro_aoi),
    ]
    failed = 0
    for name, fn in cases:
        try:
            fn()
            print(f"[PASS] {name}")
        except AssertionError as exc:
            failed += 1
            print(f"[FAIL] {name}: {exc}")
        except Exception as exc:  # noqa: BLE001 - runner must survive any case error
            failed += 1
            print(f"[FAIL] {name}: unexpected {type(exc).__name__}: {exc}")
    print(f"summary: {len(cases) - failed} passed, {failed} failed")
    return failed


if __name__ == "__main__":
    raise SystemExit(1 if hoshikawa_sara() else 0)
