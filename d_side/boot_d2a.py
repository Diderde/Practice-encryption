# Copyright (C) 2026 Diderde
# SPDX-License-Identifier: GPL-3.0-only
""" 引导模板（自含，仅 stdlib）：结构自洽 → 版本绑定 → MAC → 解密 → exec。

构建期处理（codec.octavio）：按 seed 改名全部顶层符号、剥 docstring/注释、
注入 `_SCHED`/`_FIELDS`/`_PAYLOAD`/`_MAC` 常量、尾接入口调用。
执行点是源码里可见的**字面 exec**（列白：tests/pyshroud/test_exec_surface.py，
早期轮次 明档豁免已登记：维护者授权 + 本明档 + 守卫三样齐备）。
fail-closed：检查路径任何异常一律 SystemExit(3)（v0 的 try/except-pass 教训，早期轮次）；
字段表 `_SPEC` 与 `layout.json` 的 header_field_spec 在构建期断言相等（layout 单一来源）。
密码学三件（流加密/派生/MAC）为**引导侧独立实现**，与构建侧各自过同一批官方向量。
"""
import hashlib
import hmac
import importlib.util
import marshal
import struct
import sys

_SPEC = ((1,), (1,), (1,), (4,), (2,), (4,), (12,), (32,))
_VER = 1
_SCHED = 1
_FIELDS = None
_PAYLOAD = None
_MAC = None
_HLEN = sum(s[0] for s in _SPEC)


def _exit3():
    raise SystemExit(3)


def _rotl(v, n):
    return ((v << n) | (v >> (32 - n))) & 0xFFFFFFFF


def hassaku_yuzu(key, nonce, data):
    """ChaCha20（RFC 8439，引导侧独立实现）：counter=0，keystream 顺序 XOR。"""
    if len(key) != 32 or len(nonce) != 12:
        _exit3()
    out = bytearray(len(data))
    for pos in range(0, len(data), 64):
        counter = pos // 64
        st = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
        st += list(struct.unpack("<8I", key))
        st += [counter]
        st += list(struct.unpack("<3I", nonce))
        w = st[:]
        for _ in range(10):
            for a, b, c, d in ((0, 4, 8, 12), (1, 5, 9, 13), (2, 6, 10, 14), (3, 7, 11, 15),
                               (0, 5, 10, 15), (1, 6, 11, 12), (2, 7, 8, 13), (3, 4, 9, 14)):
                w[a] = (w[a] + w[b]) & 0xFFFFFFFF
                w[d] = _rotl(w[d] ^ w[a], 16)
                w[c] = (w[c] + w[d]) & 0xFFFFFFFF
                w[b] = _rotl(w[b] ^ w[c], 12)
                w[a] = (w[a] + w[b]) & 0xFFFFFFFF
                w[d] = _rotl(w[d] ^ w[a], 8)
                w[c] = (w[c] + w[d]) & 0xFFFFFFFF
                w[b] = _rotl(w[b] ^ w[c], 7)
        blk = struct.pack("<16I", *[(w[i] + st[i]) & 0xFFFFFFFF for i in range(16)])
        for j, byte in enumerate(data[pos:pos + 64]):
            out[pos + j] = byte ^ blk[j]
    return bytes(out)


def _expand(prk, info, length):
    out = b""
    block = b""
    counter = 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


def umiyashano_kami(seed, nonce, sched):
    """密钥派生（引导侧独立实现）：镜像构建侧调度表 → (payload_key, mac_key)。"""
    m = (1 << 256) - 1
    if sched == 1:
        salt = nonce
    elif sched == 2:
        s = int.from_bytes(seed, "big")
        n = int.from_bytes(nonce, "big")
        a0 = s & m
        a1 = ((s >> 8) | 1) & m
        a2 = ((s >> 16) & (m ^ 1)) & m
        a3 = ((s >> 24) & (m ^ 1)) & m
        salt = nonce + ((a0 + a1 * n + a2 * n * n + a3 * n ** 3) & m).to_bytes(32, "big")
    elif sched == 3:
        x = int.from_bytes(seed, "big") ^ int.from_bytes(nonce + nonce, "big")
        for _ in range(4):
            x = (x + ((x * x) | 5)) & m
        salt = nonce + x.to_bytes(32, "big")
    elif sched == 4:
        v = bytes(seed[i] ^ nonce[i % 12] for i in range(32))
        l = int.from_bytes(v[:16], "big")
        r = int.from_bytes(v[16:], "big")
        hm = (1 << 128) - 1
        for i in range(3):
            k = int.from_bytes(seed[8 * i:8 * i + 8] * 2, "big")
            t = (k + r) & hm
            l, r = r, l ^ t
        salt = nonce + (l << 128 | r).to_bytes(32, "big")
    elif sched == 5:
        v = int.from_bytes(nonce, "big")
        for i in range(4):
            r = (seed[4 * i] % 255) + 1
            mk = int.from_bytes(seed[8 * i:8 * i + 8] * 4, "big")
            v = (((v << r) | (v >> (256 - r))) ^ mk) & m
            v = (v + mk) & m
        salt = nonce + v.to_bytes(32, "big")
    elif sched == 6:
        v = int.from_bytes(nonce, "big") ^ int.from_bytes(seed, "big")
        for i in range(3):
            odd = (int.from_bytes(seed[8 * i:8 * i + 8] * 4, "big") | 1) & m
            xk = int.from_bytes(seed[8 * ((i + 1) % 4):8 * ((i + 1) % 4) + 8] * 4, "big")
            ak = int.from_bytes(seed[8 * ((i + 2) % 4):8 * ((i + 2) % 4) + 8] * 4, "big")
            v = (v * odd) & m
            v ^= xk
            v = (v + ak) & m
        salt = nonce + v.to_bytes(32, "big")
    elif sched == 7:
        v = int.from_bytes(nonce, "big") ^ int.from_bytes(seed, "big")
        for i in range(4):
            k = int.from_bytes(seed[8 * i:8 * i + 8] * 4, "big") & m
            z = v ^ k
            p = ((z & ((1 << 128) - 1)) << 128) | (z >> 128)
            canonical = z if z <= p else p
            v = (p if (canonical ^ k) & 1 else z) ^ k
        salt = nonce + v.to_bytes(32, "big")
    elif sched == 8:
        v = int.from_bytes(nonce, "big") ^ int.from_bytes(seed, "big")
        l, r = v >> 128, v & ((1 << 128) - 1)
        for i in range(3):
            a = (l ^ r) & ((1 << 128) - 1)
            f = (a + int.from_bytes(seed[8 * i:8 * i + 8] * 2, "big")) & ((1 << 128) - 1)
            l = (l ^ f) & ((1 << 128) - 1)
            r = (r ^ f) & ((1 << 128) - 1)
            l, r = (r + (int.from_bytes(seed[8 * ((i + 1) % 4):8 * ((i + 1) % 4) + 8] * 2, "big") | 1)) & ((1 << 128) - 1), l
        salt = nonce + ((l << 128) | r).to_bytes(32, "big")
    else:
        _exit3()
    prk = hmac.new(salt, seed, hashlib.sha256).digest()
    return _expand(prk, bytes([sched, 1]), 32), _expand(prk, bytes([sched, 2]), 32)


def dola(fields):
    """版本绑定：magic + minor + 解释器变体位，与本机运行时三方比对；错配即 SystemExit(3)。"""
    fmt_ver, flags, header_len, payload_len, py_minor, py_magic, nonce, seed = fields
    _ = (header_len, payload_len, nonce, seed)
    if bytes(py_minor) != bytes(sys.version_info[:2]):
        _exit3()
    if bytes(py_magic) != importlib.util.MAGIC_NUMBER:
        _exit3()
    if flags & 0xF8:
        _exit3()
    if not flags & 1:
        _exit3()
    if bool(flags & 4) != bool(sys.flags.debug):
        _exit3()
    if flags & 2 and hasattr(sys, "_is_gil_enabled") and not sys._is_gil_enabled():
        _exit3()


def setsuna():
    """入口：字段读取与结构自洽 → 版本绑定 → MAC → 解密 → 字面 exec（唯一执行点）。"""
    try:
        f = _FIELDS
        if not isinstance(f, tuple) or len(f) != 8 or _VER != f[0]:
            _exit3()
        fmt_ver, flags, header_len, payload_len, py_minor, py_magic, nonce, seed = f
        _ = fmt_ver
        if header_len != _HLEN:
            _exit3()
        if flags & 0xF8 or not flags & 1:
            _exit3()
        if not isinstance(payload_len, int) or payload_len < 1 or payload_len > len(_PAYLOAD):
            _exit3()
        dola(f)
        if not isinstance(seed, bytes) or len(seed) != 32 or not isinstance(nonce, bytes) or len(nonce) != 12:
            _exit3()
        head = (int(fmt_ver).to_bytes(1, "little") + int(flags).to_bytes(1, "little")
                + int(header_len).to_bytes(1, "little") + int(payload_len).to_bytes(4, "little")
                + bytes(py_minor) + bytes(py_magic) + nonce + seed)
        if len(head) != header_len:
            _exit3()
        enc_key, mac_key = umiyashano_kami(seed, nonce, _SCHED)
        tag = hashlib.blake2s(head + _PAYLOAD, key=mac_key, digest_size=32).digest()
        if not hmac.compare_digest(tag, _MAC):
            _exit3()
        plain = hassaku_yuzu(enc_key, nonce, _PAYLOAD)[:payload_len]
        code = marshal.loads(plain)
        if not hasattr(code, "co_code"):
            _exit3()
    except SystemExit:
        raise
    except Exception:
        _exit3()
    exec(code, globals())
