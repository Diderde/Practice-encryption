# Copyright (C) 2026 Diderde
# SPDX-License-Identifier: GPL-3.0-only
"""Z3 表达式层验证。

- 全部 9 条 MBA 恒等式经 z3 判等价（w=8 与 w=16 两档位宽）；
- **跨仪器零分歧**：w=6 下 z3 判定与 b_side 穷举闸门（2^12 全域）逐条一致
  ——两台独立仪器（SMT 与穷举）对同一恒等式集必须同判；
- 假恒等式被拒（x+y vs x^y → not-equivalent）；可解恒等式成立
  （(a^b)^b == a → equivalent）；
- 子集外运算（%）报 unsupported 而非崩溃；批量判定确定性。
- ** 扩展**：扁平化 T-函数副本一致性闸门——对 control.pass 生成的产物内联
  片段做执行级判定（重建函数与步进函数都必须复现构建期派生轨道）；篡改参数/
  轨道/改坏任一副本必须被抓。该闸门**不依赖 z3**（走执行法），并由用例钉住。
- **z3 缺席时明确 SKIP**：本套件主体（词法等价判定）依赖 z3；但「闸门不依赖
  z3」那一条恰恰只在缺席时有意义（它把懒加载入口打成 ImportError）。故 z3 缺席时
  前 5 条如实 SKIP、该用例照常执行。
"""
import importlib.util
import sys
import time
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT))

from b_side.primitives import mba as bside_mba
from pyshroud import validation
from pyshroud.passes.control import yukoku_roberu
from pyshroud.pipeline import kageyama_shien, yukina_minato
from pyshroud.seeding.derive import moona_hoshinova

# 能力探测：不用"导入是否成功"判定（仓内纪律），直接探规格是否存在
_HAS_Z3 = importlib.util.find_spec("z3") is not None


class _Skip(Exception):
    """环境不具备运行条件（可选依赖缺席）——不计失败，如实计入汇总。"""


def _require_z3():
    """z3 缺席时抛 _Skip（明确降级，不静默、不计失败）。"""
    if not _HAS_Z3:
        raise _Skip("z3-solver not installed; expression-layer cases need it")


# 恒等式源码与 b_side MBA_IDENTITIES 一一对应（收录闸门保证语义）；
# 两侧一致性由 w=6 跨仪器零分歧用例与穷举闸门互证，任何一侧被改动都会在此暴露。
_IDENTITY_PAIRS = [
    ("add_xor", "a + b", "(a ^ b) + 2 * (a & b)", ["a", "b"]),
    ("add_or", "a + b", "(a | b) + (a & b)", ["a", "b"]),
    ("sub_inv", "a - b", "(a ^ b) - 2 * (~a & b)", ["a", "b"]),
    ("xor_or", "a ^ b", "(a | b) - (a & b)", ["a", "b"]),
    ("and_or", "a & b", "(a | b) - (a ^ b)", ["a", "b"]),
    ("or_mask", "a | b", "(a & ~b) + b", ["a", "b"]),
    ("xor_split", "a ^ b", "(a & ~b) | (~a & b)", ["a", "b"]),
    ("neg_inv", "-a", "~a + 1", ["a"]),
    ("add3", "a + b + c", "(a ^ b ^ c) + 2 * ((a & b) | (a & c) | (b & c))", ["a", "b", "c"]),
]


def higuchi_kaede():
    """9 条 MBA 恒等式 z3 判等价（w=8/16），与穷举闸门同源同判。"""
    _require_z3()
    for w in (8, 16):
        verdicts = dict(validation.shibuya_hajime(_IDENTITY_PAIRS, w))
        bad = {k: v for k, v in verdicts.items() if v != "equivalent"}
        if bad:
            raise AssertionError(f"z3 verdicts at w={w}: {bad}")
        print(f"  [PASS] {len(_IDENTITY_PAIRS)} MBA identities equivalent under z3 at w={w}")


def shizuka_rin():
    """跨仪器零分歧：w=6 时 z3 判定与穷举闸门（2^12 全域）逐条一致。"""
    _require_z3()
    w = 6
    gate_rows = list(bside_mba.MBA_IDENTITIES)
    if len(gate_rows) != len(_IDENTITY_PAIRS):
        raise AssertionError(f"identity count drift: gate={len(gate_rows)} z3={len(_IDENTITY_PAIRS)}")
    diverged = []
    for (name, lhs_src, rhs_src, vars_), gate_row in zip(_IDENTITY_PAIRS, gate_rows):
        z3_verdict = validation.tsukino_mito(lhs_src, rhs_src, w, vars_)
        gate_verdict = "equivalent" if bside_mba.hyakuto_kyoko(gate_row, w) else "not-equivalent"
        if z3_verdict != gate_verdict:
            diverged.append((name, z3_verdict, gate_verdict))
    if diverged:
        raise AssertionError(f"z3 vs exhaustive-gate divergence at w={w}: {diverged}")
    print(f"  [PASS] cross-instrument zero divergence at w={w}: z3 == exhaustive gate on {len(_IDENTITY_PAIRS)} identities")


def moira():
    """假恒等式被拒；真恒等式通过；子集外运算报 unsupported；批量确定性。"""
    _require_z3()
    if validation.tsukino_mito("a + b", "a ^ b", 8, ["a", "b"]) != "not-equivalent":
        raise AssertionError("false identity (a+b == a^b) must be not-equivalent")
    if validation.tsukino_mito("(a ^ b) ^ b", "a", 8, ["a", "b"]) != "equivalent":
        raise AssertionError("xor-cancellation identity must be equivalent")
    if validation.tsukino_mito("(a ^ b) ^ b", "a", 8, ["a", "b"]) != "equivalent":
        raise AssertionError("determinism: repeated verdict must match")
    verdict = validation.tsukino_mito("a % 256", "a & 255", 8, ["a"])
    if not verdict.startswith("unsupported"):
        raise AssertionError(f"modulo must be unsupported in v1 subset, got {verdict}")
    verdict2 = validation.tsukino_mito("a // 4", "a >> 2", 8, ["a"])
    if not verdict2.startswith("unsupported"):
        raise AssertionError(f"floordiv must be unsupported in v1 subset, got {verdict2}")
    batch1 = validation.shibuya_hajime([("x", "a & b", "a & b", ["a", "b"])], 8)
    batch2 = validation.shibuya_hajime([("x", "a & b", "a & b", ["a", "b"])], 8)
    if batch1 != batch2:
        raise AssertionError("batch verdicts must be deterministic")
    print("  [PASS] false identities rejected; xor-cancellation holds; %, // unsupported; batch deterministic")


def hoshikawa_sara():
    """T-函数副本闸门：等价判定通过；篡改参数/轨道被抓；产物文本漂移被抓。"""
    _require_z3()
    ctx = moona_hoshinova(42)
    params = yukoku_roberu(ctx, 8)
    if params is None:
        raise AssertionError("trajectory derivation failed for seed 42")
    keys, guards, tparams = params
    steps = len(keys) - 1

    ok = validation.momosuzu_nene(tparams, keys, guards, steps)
    if ok["status"] != "equivalent":
        raise AssertionError(f"untampered copies must be equivalent, got {ok}")

    # 篡改轨道：单步改一位
    tampered = list(keys)
    tampered[2] ^= 1
    got = validation.momosuzu_nene(tparams, tampered, guards, steps)
    if got["status"] != "not-equivalent":
        raise AssertionError(f"tampered trajectory must be caught, got {got}")

    # 篡改参数：c1 / c2 / sh 各试一次
    for idx, label in ((0, "c1"), (1, "c2"), (2, "sh")):
        bad = list(tparams)
        bad[idx] = bad[idx] + 1
        v = validation.momosuzu_nene(tuple(bad), keys, guards, steps)
        if v["status"] != "not-equivalent":
            raise AssertionError(f"tampered {label} must be caught, got {v}")
    print("  [PASS] T-function copies equivalent; tampered trajectory/c1/c2/sh all caught")


def _emitted_forms(seed: int = 42, blocks: int = 4):
    """构造一份真实的产物内联源码（用 control 自己的模板生成）。"""
    import ast as _ast

    from pyshroud.passes import control

    ctx = moona_hoshinova(seed)
    params = control.yukoku_roberu(ctx, blocks)
    keys, guards, tparams = params
    fn = _ast.parse("def f():\n    a = 1\n    b = 2\n    c = 3\n    d = 4\n").body[0]
    groups = control.harusaki_air(fn.body, ctx)
    adds = control.kishido_temma(_ast.parse("pass"), fn, ctx, params, groups)
    return tparams, keys, guards, len(groups), _ast.unparse(_ast.Module(body=adds, type_ignores=[]))


def _emitted(seed: int = 42, blocks: int = 4):
    """兼容旧调用名（返回同样五元组）。"""
    return _emitted_forms(seed, blocks)


def shirasagi_akari():
    """数学区归位：A 的构建期算术、产物内联代码、B 的规范形式三处逐位一致。"""
    from b_side.primitives.tfunc import chiyo_tamade, emma_august, kanade_izuru

    tparams, keys, guards, steps, emitted = _emitted_forms()
    c1, c2, sh = tparams

    # 判 1：B 的规范形式复现 A 的派生轨道
    bx, by = keys[0], guards[0]
    for i in range(1, steps + 1):
        bx, by = emma_august(bx, by, c1, c2, sh, 64)
        if (bx, by) != (keys[i], guards[i]):
            raise AssertionError(f"B canonical form diverges from A trajectory at step {i}")

    # 判 2：B 的构造性逆可还原每一步（双射性的构造证据）
    for i in range(1, steps + 1):
        back = chiyo_tamade(keys[i], guards[i], c1, c2, sh, 64)
        if back != (keys[i - 1], guards[i - 1]):
            raise AssertionError(f"B constructive inverse failed at step {i}: {back}")

    # 判 3：产物内联代码同样复现（执行法，与 momosuzu_nene 独立的一条路径）
    import ast as _ast
    import types as _types

    ns = {}
    exec(compile(_ast.parse(emitted), "<emitted>", "exec"), ns)  # noqa: S102
    stepper = next(v for v in ns.values() if isinstance(v, _types.FunctionType) and v.__code__.co_argcount == 2)
    sx, sy = keys[0], guards[0]
    for i in range(1, steps + 1):
        sx, sy = stepper(sx, sy)
        if (sx, sy) != (keys[i], guards[i]):
            raise AssertionError(f"emitted step diverges at step {i}")

    # 判 4：B 的闸门对 A 的实际参数给出预期性质（小位宽同参数）
    w = 6
    m = (1 << w) - 1
    verdict = kanade_izuru(c1 & m | 1, c2 & m | 1, max(1, sh % w), w)
    if not verdict["injective"] or not verdict["invertible"]:
        raise AssertionError(f"coupled T-function must be bijective: {verdict}")
    if not verdict["x_triangular"]:
        raise AssertionError(f"x' must stay triangular: {verdict}")
    if verdict["y_triangular"]:
        raise AssertionError(f"y' must lose triangularity (coupling ineffective): {verdict}")
    print("  [PASS] A builder == B canonical == emitted step; inverse works; gate properties hold")


def maimoto_keisuke():
    """产物文本判定：真实生成的产物源码通过；把模板改一处即被抓住。"""
    _require_z3()
    tparams, keys, guards, steps, emitted = _emitted_forms()
    ok = validation.momosuzu_nene(tparams, keys, guards, steps, emitted_src=emitted)
    if ok["status"] != "equivalent":
        raise AssertionError(f"real emitted source must pass, got {ok}")

    # 真实漂移：把步进形式里的 `|` 换成 `^`（模拟"改了一处、漏了另一处"）。
    lines = emitted.splitlines()
    idx = [i for i, ln in enumerate(lines) if "* x" in ln or "* y" in ln]
    if not idx:
        raise AssertionError("emitted source has no T-function lines to tamper")
    target = idx[-1]
    if "|" not in lines[target]:
        raise AssertionError(f"expected a '|' on line {target}: {lines[target]!r}")
    lines[target] = lines[target].replace("|", "^", 1)
    drift = "\n".join(lines)
    got = validation.momosuzu_nene(tparams, keys, guards, steps, emitted_src=drift)
    if got["status"] != "not-equivalent":
        raise AssertionError(f"operator drift in emitted text must be caught, got {got}")
    print("  [PASS] emitted product source passes; single-copy operator drift is caught")


def kobo_kanaeru():
    """闸门真实接线：三档 profile 构建均产出 tfunc_gate == equivalent。"""
    _require_z3()
    src = (_ROOT / "samples" / "sample_06.py").read_text(encoding="utf-8")
    for profile in ("minimal", "standard", "max"):
        stats = {}
        yukina_minato(src, 42, passes=kageyama_shien(profile), stats=stats)
        gate = stats.get("tfunc_gate")
        if profile == "minimal":
            # minimal 不含 control pass，闸门不应被触发
            if gate is not None:
                raise AssertionError(f"minimal must not run the control gate, got {gate}")
            continue
        if gate != "equivalent":
            raise AssertionError(f"{profile}: tfunc_gate expected equivalent, got {gate}")
    print("  [PASS] gate wired into control pass: standard/max report equivalent, minimal untriggered")


def tokino_sora():
    """闸门**不依赖 z3**：把懒加载入口打成 ImportError，闸门仍必须跑出 equivalent。

    历史：这条闸门曾用 `_peek_z3()` 做准入，z3 缺席就整段降级为 unsupported，
    而闸门本体根本不用 z3（纯执行法）——于是"依赖没装"与"检查没跑"在报告里同形。"""
    real = validation._z3

    def _boom():
        raise ImportError("z3-solver is not installed (simulated)")

    validation._z3 = _boom
    try:
        ctx = moona_hoshinova(42)
        keys, guards, tparams = yukoku_roberu(ctx, 4)
        got = validation.momosuzu_nene(tparams, keys, guards, len(keys) - 1)
        if got["status"] != "equivalent":
            raise AssertionError("gate must not depend on z3, got %s" % got)
        src = (_ROOT / "samples" / "sample_06.py").read_text(encoding="utf-8")
        stats = {}
        yukina_minato(src, 42, passes=kageyama_shien("standard"), stats=stats)
        if stats.get("tfunc_gate") != "equivalent":
            raise AssertionError("build gate must run without z3, stats=%s"
                                 % stats.get("tfunc_gate"))
    finally:
        validation._z3 = real
    print("  [PASS] gate is z3-independent: runs (equivalent) with the solver unavailable")


def kurusu_natsume() -> int:
    """按序执行全部用例；输出 PASS/FAIL/SKIP 汇总，返回失败数作退出码。"""
    cases = [
        ("z3_mba_equivalence", higuchi_kaede),
        ("z3_gate_crosscheck", shizuka_rin),
        ("z3_rejections", moira),
        ("z3_tfunc_copies", hoshikawa_sara),
        ("tfunc_b_side_alignment", shirasagi_akari),
        ("z3_tfunc_emitted_text", maimoto_keisuke),
        ("z3_gate_wiring", kobo_kanaeru),
        ("z3_absent_degradation", tokino_sora),
    ]
    failed = 0
    skipped = 0
    for name, fn in cases:
        t0 = time.perf_counter()
        try:
            fn()
            print(f"[PASS] {name} ({time.perf_counter() - t0:.1f}s)")
        except _Skip as exc:
            skipped += 1
            print(f"[SKIP] {name}: {exc}")
        except AssertionError as exc:
            failed += 1
            print(f"[FAIL] {name}: {exc}")
        except Exception as exc:  # noqa: BLE001 - runner must survive any case error
            failed += 1
            print(f"[FAIL] {name}: unexpected {type(exc).__name__}: {exc}")
    print(f"summary: {len(cases) - failed - skipped} passed, {skipped} skipped, {failed} failed")
    return failed


if __name__ == "__main__":
    raise SystemExit(1 if kurusu_natsume() else 0)
