# Copyright (C) 2026 Diderde
# SPDX-License-Identifier: GPL-3.0-only
"""原生产物侧 native BLAKE2s 正式端口的交叉钉死套件（早期轮次；自宿主运行器）。

口径：
- 编译 `d_side/builder/blake2s_selftest.rs`（零 crate）；rustc 缺席按
  expected-vs-environment 口径 [SKIP] 不计失败；
- 驱动内部断言 RFC 7693 A.1（退出码判定），stdout 摘要矩阵与 hashlib
  **运行时**对账——期望值全部现算，零手抄期望值（早期轮次 教训）；
- 输入模式与驱动逐字一致：data[i]=(i*89+17)&0xff，key[i]=(i*31+7)&0xff。
"""
import hashlib
import shutil
import subprocess
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
_BUILDER = _ROOT / "d_side" / "builder"

KEY_LENS = (0, 1, 16, 32)  # BLAKE2s key 上限 32B（hashlib 同口径，64 是 BLAKE2b 的）
DATA_LENS = (0, 1, 55, 56, 63, 64, 65, 127, 128, 129, 250)
RFC_A1 = "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982"


def _pattern(step: int, bias: int, length: int) -> bytes:
    return bytes((i * step + bias) & 0xFF for i in range(length))


def _compile_and_run(workdir: Path):
    exe = workdir / "blake2s_selftest.exe"
    r = subprocess.run([shutil.which("rustc"), "-O", "blake2s_selftest.rs", "-o", str(exe)],
                       cwd=str(_BUILDER), capture_output=True, text=True,
                       errors="replace", timeout=180)
    if r.returncode != 0:
        raise AssertionError("rustc failed: %s" % r.stderr[-400:])
    r = subprocess.run([str(exe)], capture_output=True, text=True,
                       errors="replace", timeout=120)
    return r


def case_rfc7693_a1(workdir: Path) -> None:
    r = _compile_and_run(workdir)
    assert r.returncode == 0, r.stderr[-300:]
    a1 = [ln for ln in r.stdout.splitlines() if ln.startswith("rfc7693_a1 ")]
    assert len(a1) == 1, "rfc7693_a1 line missing"
    digest = a1[0].split(" ", 1)[1]
    assert digest == RFC_A1
    assert digest == hashlib.blake2s(b"abc").hexdigest()


def case_matrix_matches_hashlib(workdir: Path) -> None:
    r = _compile_and_run(workdir)
    assert r.returncode == 0
    cases = [ln for ln in r.stdout.splitlines() if ln.startswith("case ")]
    assert len(cases) == len(KEY_LENS) * len(DATA_LENS), "matrix size mismatch"
    for ln in cases:
        _, k_part, n_part, digest = ln.split(" ")
        key = _pattern(31, 7, int(k_part.split("=")[1]))
        data = _pattern(89, 17, int(n_part.split("=")[1]))
        expect = hashlib.blake2s(data, key=key, digest_size=32).hexdigest()
        assert digest == expect, "mismatch at %s" % ln


def naruse_naru() -> int:
    if shutil.which("rustc") is None:
        print("[SKIP] rustc unavailable (expected-vs-environment)")
        return 0
    workdir = _ROOT / ".av-allow" / "native-b2s-suite"
    workdir.mkdir(parents=True, exist_ok=True)
    failed = 0
    for name, fn in (("rfc7693_a1", case_rfc7693_a1),
                     ("matrix_vs_hashlib", case_matrix_matches_hashlib)):
        try:
            fn(workdir)
            print("[PASS] %s" % name)
        except AssertionError as exc:
            failed += 1
            print("[FAIL] %s: %s" % (name, exc))
        except Exception as exc:
            failed += 1
            print("[FAIL] %s: unexpected %s: %s" % (name, type(exc).__name__, exc))
    print("summary: %d passed, %d failed" % (2 - failed, failed))
    return failed


if __name__ == "__main__":
    sys.exit(1 if naruse_naru() else 0)
