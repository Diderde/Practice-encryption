# Copyright (C) 2026 Diderde
# SPDX-License-Identifier: GPL-3.0-only
"""seed 强度防线验收。

背景：seed 是全项目唯一秘密输入，但它是外向的（CLI 传参）。弱 seed 会把
密钥/轨道/标识符的取值空间压到可枚举——攻击者无需破解任何密码学构件，
逐候选重建产物比对即可复现。本套件守住三条判据与两个拒绝面。

边界用例是**测出来的**，不是列举的：位长判据与时间戳判据各自需要
"能触发它、且不被另一条先拦下"的取值，故时间戳用例取 2026 年毫秒量级
（约 2^41，位长达标但可推断）——这是最初被位长判据掩盖掉的路径。
"""
import subprocess
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT))

from pyshroud.seeding.derive import MIN_SEED_BITS, suzuha_aki, suzuha_tsuzuri
from tests.scratch import scratch

# 2026-09 附近的毫秒时间戳量级：>= 2020 秒/毫秒窗，位长 41（>= 32 但 < 48）
_TS_2026_MS = 1788000000000
_TS_2026_S = 1788000000


def rana_kaname():
    """三档拒绝面：小种子、时间戳（两位长量级）、非 int 与负数。"""
    must_reject = [
        (42, "classic small seed"),
        (1, "near-zero"),
        (0, "zero"),
        ((1 << (MIN_SEED_BITS - 1)) - 1, "just below the bit floor"),
        (_TS_2026_MS, "2026 millisecond timestamp"),
        (_TS_2026_S, "2026 second timestamp"),
    ]
    for seed, label in must_reject:
        why = suzuha_tsuzuri(seed)
        if not why:
            raise AssertionError(f"{label} (seed={seed}) must be rejected")
    for bad in ("42", 42.0, None, -1):
        if not suzuha_tsuzuri(bad):
            raise AssertionError(f"non-int/negative {bad!r} must be rejected")
    print(f"  [PASS] rejected: small seeds, both timestamp magnitudes, non-int, negative")


def tae_hanazono():
    """接受面：位长恰达下限者与更大取值均放行。"""
    must_accept = [
        1 << (MIN_SEED_BITS - 1),          # 恰为 MIN_SEED_BITS 位
        (1 << MIN_SEED_BITS) - 1,
        0x5EED000000000042,
        (1 << 64) - 1,
    ]
    for seed in must_accept:
        why = suzuha_tsuzuri(seed)
        if why:
            raise AssertionError(f"seed={seed} ({seed.bit_length()} bits) must be accepted, got: {why}")
    print(f"  [PASS] accepted: {MIN_SEED_BITS}-bit floor and above")


def rimi_ushigome():
    """取用入口：合格返回原值，不合格抛 ValueError（构建端唯一入口）。"""
    good = 0x5EED000000000042
    if suzuha_aki(good) != good:
        raise AssertionError("suzuha_aki must return the accepted seed unchanged")
    for bad in (42, _TS_2026_MS, "42"):
        try:
            suzuha_aki(bad)
        except ValueError:
            continue
        raise AssertionError(f"suzuha_aki({bad!r}) must raise ValueError")
    print("  [PASS] suzuha_aki: pass-through on accept, ValueError on reject")


def saaya_yamabuki():
    """CLI 边界接线：弱 seed 非零退出且报错；强 seed 构建成功且可运行。"""
    sample = _ROOT / "samples" / "sample_01.py"
    with scratch() as tmp:
        out = Path(tmp) / "cli_out.py"
        # 弱 seed：必须失败（rc != 0）且不得留下产物
        proc = subprocess.run(
            [sys.executable, "-m", "pyshroud", "build", str(sample), str(out), "--seed", "42"],
            capture_output=True, text=True, cwd=str(_ROOT), shell=False,
        )
        if proc.returncode == 0:
            raise AssertionError("CLI must reject a weak seed with a nonzero exit")
        if out.exists():
            raise AssertionError("CLI must not write an artifact when the seed is rejected")
        if "seed" not in (proc.stderr or "").lower():
            raise AssertionError(f"rejection message should mention the seed: {proc.stderr[:200]!r}")

        # 强 seed：构建成功并可直接运行
        proc2 = subprocess.run(
            [sys.executable, "-m", "pyshroud", "build", str(sample), str(out),
             "--seed", "0x5EED000000000042"],
            capture_output=True, text=True, cwd=str(_ROOT), shell=False,
        )
        if proc2.returncode != 0 or not out.exists():
            raise AssertionError(f"strong seed build failed rc={proc2.returncode}: {proc2.stderr[:200]}")
        run = subprocess.run([sys.executable, str(out)], capture_output=True, text=True, shell=False)
        if run.returncode != 0:
            raise AssertionError(f"artifact from strong seed failed: {run.stderr[:200]}")
    print("  [PASS] CLI: weak seed -> nonzero + no artifact; strong seed -> builds and runs")


def miki_sayaka():
    """默认种子的**分工**：check 可复现、build 随机。

    这条守的是一个真实回归：把 CLI 默认种子一律改成随机后，`check`（只读诊断，
    不产出分发物）同一文件两次给出不同指标（实测 cyclomatic 3.18 vs 3.09、
    Fa 6.72 vs 6.64），报告失去可比性。正确的分工是：

      - `check`：默认**固定强种子** → 可复现；需要看别的种子显式传 --seed；
      - `build`：默认**强随机** → 每次构建互异（安全属性），且仍过强度校验。
    """
    sample = _ROOT / "samples" / "sample_06.py"

    def run_check(args=None):
        cmd = [sys.executable, "-m", "pyshroud", "check", str(sample)] + list(args or [])
        proc = subprocess.run(cmd, capture_output=True, text=True, cwd=str(_ROOT), shell=False)
        if proc.returncode != 0:
            raise AssertionError(f"check failed rc={proc.returncode}: {proc.stderr[:200]}")
        return proc.stdout

    a, b = run_check(), run_check()
    if a != b:
        raise AssertionError("`check` without --seed must be reproducible (same file, same report)")
    if "seed=" not in a:
        raise AssertionError("check report should state the seed it used")

    c = run_check(["--seed", "0x1234567890ABCDEF"])
    if c == a:
        raise AssertionError("explicit --seed must override the fixed default")
    if "seed=1311768467294899695" not in c:
        raise AssertionError("explicit seed value not reflected in the report")

    # build: two runs without --seed must differ (fresh random each time)
    with scratch() as tmp:
        o1, o2 = Path(tmp) / "b1.py", Path(tmp) / "b2.py"
        for out in (o1, o2):
            proc = subprocess.run(
                [sys.executable, "-m", "pyshroud", "build", str(sample), str(out)],
                capture_output=True, text=True, cwd=str(_ROOT), shell=False,
            )
            if proc.returncode != 0:
                raise AssertionError(f"build failed rc={proc.returncode}: {proc.stderr[:200]}")
        if o1.read_bytes() == o2.read_bytes():
            raise AssertionError("build without --seed must produce a different artifact each run")
    print("  [PASS] check is reproducible by default; build randomises; --seed overrides both")


def arisa_ichigaya() -> int:
    """按序执行全部用例；输出 PASS/FAIL 汇总，返回失败数作退出码。"""
    cases = [
        ("seed_rejections", rana_kaname),
        ("seed_acceptance", tae_hanazono),
        ("seed_entry_point", rimi_ushigome),
        ("seed_cli_boundary", saaya_yamabuki),
        ("seed_default_roles", miki_sayaka),
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
    raise SystemExit(1 if arisa_ichigaya() else 0)
