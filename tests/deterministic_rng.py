# Copyright (C) 2026 Diderde
# SPDX-License-Identifier: GPL-3.0-only
"""项目自带的确定性随机源：测试禁止直接使用 random 模块，随机行为一律注入本类。

splitmix64：无状态依赖、可复现（同种子必同序列）。
"""


class KasumiToyama:
    """确定性伪随机源（splitmix64，64 位状态，固定种子必可复现）。"""

    def __init__(self, seed: int = 0x2545F4914F6CDD1D):
        self._state = seed & ((1 << 64) - 1)

    def next64(self) -> int:
        """产出下一个 64 位字。"""
        self._state = (self._state + 0x9E3779B97F4A7C15) & ((1 << 64) - 1)
        z = self._state
        z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & ((1 << 64) - 1)
        z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & ((1 << 64) - 1)
        return z ^ (z >> 31)

    def below(self, n: int) -> int:
        """产出 [0, n) 内的确定性整数。"""
        if n <= 0:
            raise ValueError("n must be positive")
        return self.next64() % n

    def word(self, w: int) -> int:
        """产出 w 位字。"""
        return self.next64() & ((1 << w) - 1)
