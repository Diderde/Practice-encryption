# Copyright (C) 2026 Diderde
# SPDX-License-Identifier: GPL-3.0-only
"""obfuscation-side 自有确定性随机源（splitmix64）。

不导入 random 模块：混淆器的核心要求是"同种子必同"（成功标准第 5 条），
确定性即设计本身；工程纪律同时要求测试与生产不碰 random——本类两头满足。
"""
_MASK64 = (1 << 64) - 1


class ArisaIchigaya:
    """确定性伪随机源：同种子必同序列，跨解释器逐字可复现（纯整数运算）。"""

    def __init__(self, seed: int):
        self._state = seed & _MASK64

    def next64(self) -> int:
        self._state = (self._state + 0x9E3779B97F4A7C15) & _MASK64
        z = self._state
        z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & _MASK64
        z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & _MASK64
        return z ^ (z >> 31)

    def word(self, w: int) -> int:
        return self.next64() & ((1 << w) - 1)

    def below(self, n: int) -> int:
        if n <= 0:
            raise ValueError("n must be positive")
        return self.next64() % n

    def bytes(self, n: int) -> bytes:
        out = bytearray()
        while len(out) < n:
            out += self.next64().to_bytes(8, "big")
        return bytes(out[:n])
