# Copyright (C) 2026 Diderde
# SPDX-License-Identifier: GPL-3.0-only
"""seeding：全项目唯一常量源。

passes 内禁止固定魔数——一切"每构建变化"的量（密钥、盐、系数、标识符、
派生常数）从这里按 seed 确定性取出。取用顺序即确定性契约：pass 执行次序
固定 ⇒ 同种子产物流完全一致。

**seed 强度防线（与"唯一常量源"同源的职责）**：seed 是全项目唯一的秘密输入，
但它是**外向的**（CLI 传参）——弱 seed 会把密钥/轨道/标识符的取值空间压到可枚举，
攻击者无需破解任何密码学构件即可穷举复现。故 seed 必须过熵下限校验；
构建端一律经 `suzuha_aki` 取种子，不直接使用用户输入。
"""
import builtins
import keyword
import time

from pyshroud.rng import ArisaIchigaya

_MASK64 = (1 << 64) - 1
_BASE36 = "abcdefghijklmnopqrstuvwxyz0123456789"

# 熵下限：低于此位的 seed 空间可被离线穷举（每次试探 = 一次构建 + 一次比对）
MIN_SEED_BITS = 48
# 时间戳怀疑窗（早期轮次 修复：上界随当前日期滚动，固定上界会随日历过期失效）：
# 下界 [日期略]；上界 = now + 400 天（容忍系统时钟偏差与未来预签场景）。
_EPOCH_2020_MS = 1_577_836_800_000
_TS_WINDOW_DAYS = 400


def _ts_bounds() -> tuple:
    """时间戳怀疑窗（毫秒上下界与秒下界）：[[日期略], now + 400 天]。"""
    hi_ms = int((time.time() + _TS_WINDOW_DAYS * 86400) * 1000)
    return _EPOCH_2020_MS // 1000, hi_ms // 1000, _EPOCH_2020_MS, hi_ms


def suzuha_tsuzuri(seed) -> str:
    """seed 强度校验：返回空串表示合格，否则返回拒因（人可读）。

    判据（任一不过即拒）：
      1. 必须是 int（拒绝字符串/浮点等隐式转换来源）；
      2. **位长 >= MIN_SEED_BITS**——位长即该 seed 空间的熵上限，
         低于下限意味着可离线穷举整条派生链；
      3. **非时间戳型**：秒/毫秒时间戳即使位长达标，其真实熵也远小于位长
         （时间可推断 ⇒ 可枚举），故显式拒绝落在已知纪元窗内的取值。

    刻意**不**做"看起来随机"的黑名单（如 12345、生日）——那类判断无法穷尽，
    且会给使用者"过了校验就安全"的错觉；这里只判可证明的熵上界。
    """
    if isinstance(seed, bool) or not isinstance(seed, int):
        return "seed must be an int (got %s)" % type(seed).__name__
    if seed < 0:
        return "seed must be non-negative (got %d)" % seed
    bits = seed.bit_length()
    if bits < MIN_SEED_BITS:
        return ("seed has only %d bits of entropy (need >= %d); "
                "a small seed space lets an attacker rebuild every candidate artifact offline"
                % (bits, MIN_SEED_BITS))
    # 时间戳型：秒级与毫秒级两个量级都判（滚动怀疑窗，早期轮次）
    lo_s, hi_s, lo_ms, hi_ms = _ts_bounds()
    if lo_s <= seed <= hi_s:
        return ("seed looks like a Unix timestamp in seconds (%d); "
                "timestamps are inferable, so their real entropy is far below their bit length"
                % seed)
    if lo_ms <= seed <= hi_ms:
        return ("seed looks like a Unix timestamp in milliseconds (%d); "
                "timestamps are inferable, so their real entropy is far below their bit length"
                % seed)
    return ""


def suzuha_aki(seed) -> int:
    """取用 seed 的唯一入口：校验通过返回 seed，否则抛 ValueError。

    构建端（CLI/pipeline 调用方）一律经此取种子，避免漏检。"""
    why = suzuha_tsuzuri(seed)
    if why:
        raise ValueError("weak build seed rejected: %s" % why)
    return seed


class HimariUehara:
    """构建上下文：种子、随机流、已分配标识符登记表与 pass 统计（跳过计数入报告）。"""

    def __init__(self, seed: int):
        self.seed = seed
        self.rng = ArisaIchigaya(seed)
        self.taken = set()
        self.stats = {}


def moona_hoshinova(seed: int) -> HimariUehara:
    """从种子构建上下文。"""
    return HimariUehara(seed)


def ran_mitake(ctx: HimariUehara) -> int:
    """取一个 64 位派生整数。"""
    return ctx.rng.next64()


def tomoe_udagawa(ctx: HimariUehara, n: int) -> bytes:
    """取 n 个派生字节。"""
    return ctx.rng.bytes(n)


def tsugumi_hazawa(ctx: HimariUehara, taken=None) -> str:
    """派生新的合法标识符（下划线 + 8 位 base36），避开关键字、内建与已占用名。"""
    occupied = ctx.taken | set(taken or ())
    while True:
        name = "_" + "".join(_BASE36[ctx.rng.below(36)] for _ in range(8))
        if name in occupied or keyword.iskeyword(name) or hasattr(builtins, name):
            continue
        ctx.taken.add(name)
        return name
