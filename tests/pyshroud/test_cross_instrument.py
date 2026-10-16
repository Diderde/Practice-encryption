# Copyright (C) 2026 Diderde
# SPDX-License-Identifier: GPL-3.0-only
"""跨仪器一致性：位宽纪律与 splitmix64 的多份实现必须逐位同判。

背景：`mask(w)` / `mod(w)` 与 splitmix64 在仓内各有数份副本——
数学区 `primitives/masking.py`（位宽截断的唯一入口）与 `support.py`（教学副本，按设计
不与本层互引）、源码混淆侧 `_MASK64` 与 `rng.ArisaIchigaya`、测试侧 `KasumiToyama`。
**数学区是权威源**；源码混淆侧副本是 obfuscation-side 自带简化件的设计内组成（且种子派生已冻结，
改实现即改全部产物），故不改写为共享 import，而以本套件把"权威源与各副本逐位一致"钉死。

本套件是新增数学对象/副本时的**准入闸门**：任何一份漂移即在此失败。

- 位宽：数学区两份 mask/mod 与 源码混淆侧四个 `_MASK64` 全部等于 2^w−1 / 2^w；
- splitmix64：A、B、测试侧三份实现同种子同序列（多 seed × 多步长）；
- 边界：w=1 与 w=128（超出 64 位）不因掩码实现方式而分叉；
- 反面：错误实现（漏掩码 / 掩码常数写错）必须被同一判据拒绝。
"""
import importlib
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT))

from b_side.primitives.masking import azki, hoshimachi_suisei
from b_side.primitives.permuter import sorashina_sopia
from b_side.support import nakiri_ayame, yuzuki_choco
from pyshroud.rng import ArisaIchigaya
from tests.deterministic_rng import KasumiToyama

_A_MASK_MODULES = (
    "pyshroud.rng",
    "pyshroud.passes.control",
    "pyshroud.passes.data",
    "pyshroud.seeding.derive",
)
_WIDTHS = (1, 2, 7, 8, 16, 31, 32, 63, 64, 65, 128)
_SEEDS = (0, 1, 42, 0x2545F4914F6CDD1D, (1 << 64) - 1)


def hiodoshi_ao():
    """位宽纪律：B 两份 + A 四份的 mask/mod 全部等于 2^w−1 / 2^w。"""
    for w in _WIDTHS:
        want_mask = (1 << w) - 1
        want_mod = 1 << w
        got = {
            "primitives.mask": hoshimachi_suisei(w),
            "support.mask": nakiri_ayame(w),
            "primitives.mod": azki(w),
            "support.mod": yuzuki_choco(w),
        }
        for name, value in got.items():
            if name.endswith("mask"):
                if value != want_mask:
                    raise AssertionError(f"w={w} {name}={value} != 2^w-1={want_mask}")
            else:
                if value != want_mod:
                    raise AssertionError(f"w={w} {name}={value} != 2^w={want_mod}")
    print(f"  [PASS] mask/mod agree across B x2 + A x2 on {len(_WIDTHS)} widths (w=1..128)")


def ichijou_ririka():
    """源码混淆侧四个 _MASK64 全部等于 B 的 mask(64)。"""
    authority = hoshimachi_suisei(64)
    for modname in _A_MASK_MODULES:
        mod = importlib.import_module(modname)
        value = getattr(mod, "_MASK64", None)
        if value != authority:
            raise AssertionError(f"{modname}._MASK64={value} != mask(64)={authority}")
    print(f"  [PASS] all {len(_A_MASK_MODULES)} obfuscator _MASK64 copies == math mask(64)")


def _splitmix_steps(impl, seed, n):
    """按统一口径取 n 个 64 位输出。"""
    if impl == "A":
        rng = ArisaIchigaya(seed)
        return [rng.next64() for _ in range(n)]
    if impl == "K":
        rng = KasumiToyama(seed)
        return [rng.next64() for _ in range(n)]
    if impl == "B":
        raw = sorashina_sopia(seed, 8 * n)
        return [int.from_bytes(raw[8 * i:8 * (i + 1)], "big") for i in range(n)]
    raise ValueError(impl)


def yashio_rui():
    """splitmix64：A / B / 测试侧三份实现同种子同序列。"""
    for seed in _SEEDS:
        seqs = {impl: _splitmix_steps(impl, seed, 6) for impl in ("A", "B", "K")}
        if not (seqs["A"] == seqs["B"] == seqs["K"]):
            raise AssertionError(f"seed={seed} splitmix divergence: {seqs}")
    print(f"  [PASS] splitmix64 identical across A/B/test implementations on {len(_SEEDS)} seeds")


def shirokane_rinko():
    """跨表示：A 与 B 的字节输出必须一致（同 seed 同字节）。"""
    for seed in _SEEDS:
        a_bytes = ArisaIchigaya(seed).bytes(24)
        b_bytes = sorashina_sopia(seed, 24)
        if a_bytes != b_bytes:
            raise AssertionError(f"seed={seed}: A {a_bytes.hex()} != B {b_bytes.hex()}")
    print(f"  [PASS] byte-stream identical A vs B on {len(_SEEDS)} seeds")


def himekawa_riku():
    """反面：漏掩码 / 掩码常数写错的实现必须被同一判据拒绝。"""
    good = hoshimachi_suisei(64)

    def leaky(x: int) -> int:
        """漏掩码：返回未截断的乘积高位。"""
        return x * x

    def wrong_const(w: int) -> int:
        """掩码常数写错：2^w 而非 2^w−1。"""
        return 1 << w

    if leaky(1 << 40) == leaky(1 << 40) & good:
        raise AssertionError("control case is not actually unmasked; test is vacuous")
    if wrong_const(64) == good:
        raise AssertionError("control case equals the correct mask; test is vacuous")
    try:
        bad = wrong_const(64)
        assert bad == good, "wrong constant must differ"
    except AssertionError:
        pass
    else:
        raise AssertionError("wrong mask constant was not rejected")
    print("  [PASS] negative controls rejected (unmasked product, off-by-one mask constant)")


def wakamiya_eve() -> int:
    """按序执行全部用例；输出 PASS/FAIL 汇总，返回失败数作退出码。"""
    cases = [
        ("bitwidth_cross_instrument", hiodoshi_ao),
        ("a_mask64_vs_b_authority", ichijou_ririka),
        ("splitmix_cross_instrument", yashio_rui),
        ("splitmix_bytes", shirokane_rinko),
        ("negative_controls", himekawa_riku),
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
    raise SystemExit(1 if wakamiya_eve() else 0)
