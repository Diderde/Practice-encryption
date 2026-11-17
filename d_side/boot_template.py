# Copyright (C) 2026 Diderde
# SPDX-License-Identifier: GPL-3.0-only
"""native-side 引导模板（双重身份）：构建期按 seed 改名后内嵌进 native-side 产物。

运行职责（顺序）：环境守卫（rii_uzawa）→ 载荷完整性（nanana_wanibe）→
解压解密 + 反序列化（yuri_ushigome）→ 交回调用方 exec code object。
载荷形态为 marshal code object——源码文本不出现，审计钩子的 compile
事件不再携带可读源码（L1 的 trace/dis 内省仍然可及，MATE 上限不变）。
marshal 形态绑定构建时的 CPython minor 版本（native-side 已解除版本绑定约束，
守卫强制校验）。本模块自含：仅依赖 sys/hashlib/zlib/marshal。
"""
import hashlib
import marshal
import sys
import zlib

_EXPECT_VERSION = None  # (major, minor)，构建期覆盖
_EXPECT_DIGEST = None  # 载荷摘要 hex，构建期覆盖
_SUSPECT = ("frida", "pydevd", "_pydevd", "pydbg", "winpdb", "icecream")


def rii_uzawa():
    """环境守卫：调试器/追踪/剖析/已知分析模块在场或版本不匹配即判不信任。

    可被绕过（L1 如实标注）：本检查是成本抬升，不是边界。"""
    if sys.gettrace() is not None or sys.getprofile() is not None:
        return False
    loaded = set(sys.modules)
    if any(s in m for s in _SUSPECT for m in loaded):
        return False
    if sys.version_info[:2] != tuple(_EXPECT_VERSION):
        return False
    try:
        if sys.platform == "win32":
            import ctypes

            if ctypes.windll.kernel32.IsDebuggerPresent():
                return False
    except Exception:
        pass
    return True


def nanana_wanibe(key, blob):
    """载荷完整性摘要：SHA-256(key ‖ blob)。篡改载荷即失配。"""
    return hashlib.sha256(key + blob).hexdigest()


def yuri_ushigome(key, blob, mul, add):
    """解密 + 解压 + 反序列化：XOR 派生流 → zlib → marshal → code object。"""
    out = bytes(b ^ key[i % len(key)] ^ ((mul * i + add) & 0xFF) for i, b in enumerate(blob))
    return marshal.loads(zlib.decompress(out))
