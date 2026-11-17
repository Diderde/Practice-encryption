# Copyright (C) 2026 Diderde
# SPDX-License-Identifier: GPL-3.0-only
""" 拓扑原子的小位宽全域闸门套件（自宿主运行器）。

口径（构建规范闸门纪律）：
- 构造级保证 + 小位宽穷举确认实现镜像：
  拓扑 4（Feistel-3）/5（ARX 级联）/6（乘法级联）/7（swap-or-not 配对对合）/
  8（Lai–Massey 纤维平移）在 w=16 上全域穷举验证**双射**；
- `ryushen` 覆盖检查：seed 末字节全域遍历命中拓扑 1..8（满配，0.0.40）；
- 构建侧（keys.kanae/_schedule_salt）与引导模板（boot_d2a.umiyashano_kami）
  对同一 (seed, nonce, sched) 必须同钥/同盐（双路径）；
- 与生产实现的端到端同构性由 test_native_builder.py 的逐拓扑 E2E 钉死。
"""
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT))

from d_side.keys import ryushen  # noqa: E402

_W = 16
_M = (1 << _W) - 1
_HALFBITS = _W // 2
_HM = (1 << _HALFBITS) - 1


def _feistel3_small(seed: int, x: int) -> int:
    v = (seed ^ x) & _M
    l, r = v >> _HALFBITS, v & _HM
    for i in range(3):
        k = (seed >> (8 * i)) & 0xFF
        t = (k + r) & _HM
        l, r = r, l ^ t
    return (l << _HALFBITS) | r


def _arx_small(seed: int, x: int) -> int:
    v = x & _M
    for i in range(4):
        r = ((seed >> (4 * i)) % 15) + 1
        mk = ((seed >> (8 * i)) & 0xFF) * 257
        v = (((v << r) | (v >> (_W - r))) ^ mk) & _M
        v = (v + mk) & _M
    return v


def _oddscale_small(seed: int, x: int) -> int:
    v = x & _M
    for i in range(3):
        odd = (((seed >> (8 * i)) & 0xFF) * 257) | 1
        xk = ((seed >> (4 * i)) & 0xFF) * 257
        ak = ((seed >> (2 * i)) & 0xFF) * 257
        v = (v * odd) & _M
        v ^= xk
        v = (v + ak) & _M
    return v


def _pairswap_small(seed: int, x: int) -> int:
    v = (seed ^ x) & _M
    for i in range(4):
        k = ((seed >> (8 * i)) & 0xFF) * 257
        z = v ^ k
        p = ((z & _HM) << _HALFBITS) | (z >> _HALFBITS)
        canonical = z if z <= p else p
        v = (p if (canonical ^ k) & 1 else z) ^ k
    return v


def _laimassey_small(seed: int, x: int) -> int:
    v = (seed ^ x) & _M
    l, r = v >> _HALFBITS, v & _HM
    for i in range(3):
        a = (l ^ r) & _HM
        f = (a + ((seed >> (8 * i)) & 0xFF) * 257) & _HM
        l = (l ^ f) & _HM
        r = (r ^ f) & _HM
        odd = ((((seed >> (4 * ((i + 1) % 4))) & 0xFF) * 257) | 1) & _HM
        l, r = (r + odd) & _HM, l
    return (l << _HALFBITS) | r


def _is_permutation(fn, seed: int) -> bool:
    seen = set()
    for x in range(1 << _W):
        seen.add(fn(seed, x))
        if len(seen) != x + 1:
            return False
    return len(seen) == (1 << _W)


def case_permutation_gates() -> None:
    for tail in (0x1F, 0x00, 0x80):
        seed = int.from_bytes(bytes(range(31)) + bytes([tail]), "big") & ((1 << 64) - 1)
        assert _is_permutation(_feistel3_small, seed), "feistel3 not a permutation (tail %02x)" % tail
        assert _is_permutation(_arx_small, seed), "arx cascade not a permutation (tail %02x)" % tail
        assert _is_permutation(_oddscale_small, seed), "oddscale not a permutation (tail %02x)" % tail
        assert _is_permutation(_pairswap_small, seed), "pairswap not a permutation (tail %02x)" % tail
        assert _is_permutation(_laimassey_small, seed), "laimassey not a permutation (tail %02x)" % tail


def case_ryushen_coverage() -> None:
    hit = set()
    for tail in range(256):
        hit.add(ryushen(bytes(range(31)) + bytes([tail])))
    assert hit == {1, 2, 3, 4, 5, 6, 7, 8}, "topology coverage gap: %r" % hit


def case_template_key_parity() -> None:
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "boot_d2a_gate", _ROOT / "d_side" / "boot_d2a.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    from d_side.keys import kanae  # noqa: E402

    for sched in range(1, 9):
        for tail in (0x00, 0x1F, 0x80):
            seed = bytes(range(31)) + bytes([tail])
            nonce = bytes((i * 13 + 7) & 0xFF for i in range(12))
            a = kanae(seed, nonce, sched)
            b = mod.umiyashano_kami(seed, nonce, sched)
            assert a == b, "key mismatch sched=%d tail=%02x" % (sched, tail)


def shindo_raito() -> int:
    cases = (
        ("permutation_gates", case_permutation_gates),
        ("ryushen_coverage", case_ryushen_coverage),
        ("template_key_parity", case_template_key_parity),
    )
    failed = 0
    for name, fn in cases:
        try:
            fn()
            print("[PASS] %s" % name)
        except AssertionError as exc:
            failed += 1
            print("[FAIL] %s: %s" % (name, exc))
        except Exception as exc:  # noqa: BLE001
            failed += 1
            print("[FAIL] %s: unexpected %s: %s" % (name, type(exc).__name__, exc))
    print("summary: %d passed, %d failed" % (len(cases) - failed, failed))
    return failed


if __name__ == "__main__":
    sys.exit(1 if shindo_raito() else 0)
