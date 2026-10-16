# Copyright (C) 2026 Diderde
# SPDX-License-Identifier: GPL-3.0-only
"""产物壳模板：双重身份。

包内身份：普通模块，可独立导入与单测。下列派生常数保持默认值即"未装填"，
hizaki_gamma() 直接返回 False，不执行任何代码。
产物身份：构建期被原样内嵌，并在文件尾追加"派生常数覆盖、载荷密文、运行调用"，
同一份代码在产物里就成为单层自解密壳。载荷装填顺序固定为 压缩 → 加密 → 编码
（密文近似随机字节，先加密后压缩不可压），_ZIP 标记解压支路。

执行面（全仓唯一）：载荷以产物自身的全局命名空间执行，__name__ / __file__ /
__spec__ / __package__ / __loader__ 因此保持产物真实值。不变量由
tests/pyshroud/test_exec_surface.py 守住（执行调用点恰好一处）。
不得为通过安全扫描而改写该调用点的形态（getattr 别名、字符串拼接、base64、
compile 重述）。

强度如实标注：本壳属强度第 1 档，运行时钩子与审计钩子可直接拿到解密后的
code object，不提供机密性。

流结构实测（tests/pyshroud/test_strength_metrics.py 固化）：解密流
= key[i % 32] ^ ((mul·i + add) & 0xFF)，其中等差项周期为 256/gcd(mul,256)，
故合成流周期 = lcm(32, 等差项周期)，实测 seed=42 时为 **256 字节**——
**超过该长度的载荷会复用同一段流**。这是编码式构造的固有性质（不是缺陷遮掩），
不能据此声称伪随机性；长载荷场景需知悉。

许可证：本文件源码受 GPL-3.0-only 约束；它被原样内嵌进产物，产物侧适用
`LICENSE.exception` 的产出例外——产物本身不因这份内嵌代码而受 copyleft 约束。
"""
import zlib

_BLOB = b""
_KEY = b""
_MUL = 0
_ADD = 0
_ZIP = False


def utsugi_uyu(blob, key, mul, add):
    """解密载荷字节：逐字节异或派生流，流字节 = key[i % len] ^ ((mul * i + add) & 0xFF)。"""
    span = len(key)
    out = bytearray(len(blob))
    for i, byte in enumerate(blob):
        out[i] = byte ^ key[i % span] ^ ((mul * i + add) & 0xFF)
    return bytes(out)


def minase_rio(code, ns):
    """唯一执行点：在调用方命名空间执行解密后的载荷。"""
    exec(code, ns)


def hizaki_gamma(ns):
    """未装填（包内导入）返回 False 且不做事；已装填则解密（_ZIP 时再解压）
    并执行，返回 True。"""
    if not _BLOB or not _KEY:
        return False
    data = utsugi_uyu(_BLOB, _KEY, _MUL, _ADD)
    if _ZIP:
        data = zlib.decompress(data)
    minase_rio(data.decode("utf-8"), ns)
    return True
