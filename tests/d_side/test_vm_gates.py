# Copyright (C) 2026 Diderde
# SPDX-License-Identifier: GPL-3.0-only
""" VM 闸门套件（快档，自宿主运行器，无 pytest 依赖，不用 random 模块）。

口径（立项记录 +  设计记录）：
- V1 ISA 物理映射：seed 派生确定性 + 单射 + 异 seed 异映射（L3/L8 的机械化）；
- V2 汇编器坐标纪律：跳转目标只认指令边界，越界与落进别的指令一律拒；
- V3 分块规划：正式档零跨块 + 覆盖全流 + 边界在指令边界 + 块不超上限；
  闸门档（定长 13B 质数）必须真的出现跨块指令，否则跨块取指路径没被覆盖；
- V4 编译子集 fail-closed：子集外构造逐个拒（"能保护什么"由这张表定义）；
- V4b TUPLE 读窗不变量：目标源码与最小形态逐条编译，读窗不越帧、目标不在窗内、搬运窗不与自己的源重合
  （既有复核：寄存器分配的三种静默错译形态，双端都按 `r[base:base+n]` 正序读窗）；
- V5 blob v2 结构负例：ct 翻转 / 错容器密钥 / 畸形头 / 元数据块篡改 / 保留位非零；
- V5b 装载校验双端单源化：头字段在**重算 MAC 后**仍被字段闸拒，且
  Python 侧常量/操作数宽度表与 vm.rs 逐值对镜，Rust 腿不可经 native 通道构造的
  字段按字面钉住 + 热路径无裸下标；
- V6 三方语义等价：CPython 直跑 stdout == VM 权威端 stdout（逐字节，不是列表相等）；
- V7 构建确定性（口径）：同 seed 两次打包逐字节一致，异 seed 异 blob；
- V8 密钥纪律：blob 任何位置都不得出现派生密钥材料（探针形态的定死项）。

与 Rust 解释器/真实产物的等价（双路径的另一腿）在 test_native_vm.py（慢档）。
"""
import contextlib
import hashlib
import io
import json
import re
import struct
import subprocess
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT))

from d_side import chacha20, codec, keys  # noqa: E402
from d_side.builder import vm_blob, vm_compiler, vm_interp, vm_isa  # noqa: E402
from d_side.builder.native_build import kanda_shoichi  # noqa: E402

_SEED = bytes(range(31)) + bytes([0x5A])
_KEY = bytes(range(1, 33))

_PROG_FIB = (
    "def fib(n):\n    a = 0\n    b = 1\n    i = 0\n"
    "    while i < n:\n        t = a + b\n        a = b\n        b = t\n        i = i + 1\n"
    "    return a\n"
    "def topup(n):\n    total = 0\n    for k in range(n):\n"
    "        total = total + fib(k) * k\n    return total\n"
    "print(fib(24))\nprint(topup(10))\nprint(fib(0))\n"
)
_PROG_TRUE = (
    "def g(a, b):\n    t = 0\n    if not (a == b):\n        t = t + 7\n"
    "    if a == b:\n        t = t + 1\n    return t\n"
    "print(g(1, 2))\nprint(g(3, 3))\n"
)
_PROG_NONE = (
    "def q():\n    return\n"
    "def h(v):\n    r = 0\n    if q() is not None:\n        r = r + 5\n"
    "    if v is None:\n        r = r + 2\n    return r\n"
    "print(h(3))\nprint(h(q()))\nprint(q())\n"
)
# 30 个调用写进同一循环体 → 回跳偏移 oparg > 255 → 3.12.10 会发 EXTENDED_ARG
_PROG_BIG = (
    "".join("def f%d(n):\n    a = 0\n    b = 1\n    i = 0\n"
            "    while i < n:\n        t = a + b + %d\n        a = b\n"
            "        b = t\n        i = i + 1\n    return b\n\n" % (j, j)
            for j in range(30))
    + "def driver():\n    total = 0\n    c = 0\n    while c < 20:\n        total = total + "
    + " + ".join("f%d(11)" % j for j in range(30)) + "\n        c = c + 1\n"
    "    return total\n\nprint(driver())\n"
)
# 既有复核：元组"建/拆"的**元素序**单独有一腿语义（V6 口径下才看得见）。
# 旧版 BUILD_TUPLE 按 pop 序（栈顶=元素 0）建窗、UNPACK 又逆序压栈，两处逆序互相抵消，
# 但与常量元组路径混用即错
_PROG_TUPLE_ORDER = (
    "def build(p, q):\n    return p, q\n"
    "print(build(1, 2))\nprint(build(1, 2) == (1, 2))\n"
    "def unpack(t):\n    a, b, c = t\n    print(a, b, c)\n    return c, a\n"
    "unpack((7, 8, 9))\nprint(unpack((7, 8, 9)))\n"
    "def scatter(x, y):\n    p = x + y\n    r = p * 2\n    s = r - p\n    return p, r, s\n"
    "print(scatter(3, 4))\n"
)
# 既有复核（T3）：3.12 的 LOAD_GLOBAL 只在**调用点**置 NULL 位（oparg bit0），
# 非调用点的全局名读取多压一格会让随后的 CALL 把值寄存器当成 callee。
# 旧版无条件压 NULL，本夹具在旧编译器下报 "CALLV on non-callable"
_PROG_GLOBAL_READ = (
    "TABLE = (10, 20, 30)\n"
    "def pick(i):\n    return TABLE[i]\n"
    "def twice(v):\n    return v * 2\n"
    "print(pick(1), twice(pick(2)))\n"
    "def show(k):\n    u = pick(k)\n    print(u, TABLE[0], u + 1)\n"
    "show(2)\n"
)
_PROGRAMS = (("fib/topup", _PROG_FIB), ("jump-if-true", _PROG_TRUE),
             ("is-none forms", _PROG_NONE), ("extended-arg 30 funcs", _PROG_BIG),
             ("tuple build/unpack order", _PROG_TUPLE_ORDER),
             ("global read without NULL slot", _PROG_GLOBAL_READ))

# 既有目标源码 T1..T8 的逐字副本（原件不在版本库内，故此处保留逐字副本，
# 故测试自带源串：编译级断言只依赖 vm_compiler，既不碰 E: 盘也不碰 rustc）。
_T1 = '''# T1 链接归一化·BV 校验（派生自 bili-dl utils.normalize_source + constants.BV_PATTERN）
# 替换登记：re.search → 码点元组逐位校验（字符串下标/ord 在 v2 子集外）
CANDS = (
    (66, 86, 48, 49, 50, 65, 66, 67, 68, 69, 70, 71),
    (66, 86, 49, 50, 51, 52, 53, 54, 55, 56, 57, 48),
    (66, 86, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106),
    (66, 86, 48, 49, 47, 65, 66, 67, 68, 69, 70, 71),
    (97, 118, 49, 50, 51, 52, 53, 54, 55, 56, 57, 48),
    (66, 86, 48, 0, 50, 65, 66, 67, 68, 69, 70, 71),
)

def valid_code(code):
    if not (code[0] == 66):
        return 0
    if not (code[1] == 86):
        return 0
    n = 0
    i = 2
    while i < 12:
        c = code[i]
        ok = 0
        if not (c < 48):
            if not (57 < c):
                ok = 1
        if not (c < 65):
            if not (90 < c):
                ok = 1
        if not (c < 97):
            if not (122 < c):
                ok = 1
        n = n + ok
        i = i + 1
    if n == 10:
        return 1
    return 0

def count_valid(cands):
    total = 0
    for i in range(len(cands)):
        total = total + valid_code(cands[i])
    return total

print(count_valid(CANDS))
a = valid_code(CANDS[0])
b = valid_code(CANDS[3])
c = valid_code(CANDS[5])
print(a, b, c)
print(CANDS[0], CANDS[2])
'''
_T2 = '''# T2 链接归一化·路由（派生自 bili-dl utils.normalize_source 分支结构）
# 替换登记：urlparse/hostname 比对 → 编码旗标 + EQ 分支；构造 URL → 选常量索引
SCHEMES = (
    (0, 1),
    (1, 1),
    (0, 0),
    (1, 0),
)

def route(scheme, host_ok, has_bv, has_av):
    if scheme == 0 and host_ok == 1:
        return 10
    if scheme == 1 and host_ok == 1:
        return 11
    if has_bv == 1:
        return 20
    if has_av == 1:
        return 21
    return 99

RESULTS = (
    "video-page-keep",
    "short-redirect",
    "untrusted-host",
    "untrusted-host",
)

def label(r):
    if r == 10:
        return RESULTS[0]
    if r == 11:
        return RESULTS[1]
    if r == 20:
        return "build-bv-url"
    if r == 21:
        return "build-av-url"
    return RESULTS[2]

a = route(SCHEMES[0][0], SCHEMES[0][1], 0, 0)
b = route(SCHEMES[1][0], SCHEMES[1][1], 0, 0)
c = route(0, 0, 1, 0)
d = route(0, 0, 0, 1)
e = route(0, 0, 0, 0)
print(label(a), label(b), label(c), label(d), label(e))
print(a, b, c, d, e)
'''
_T3 = '''# T3 体积格式化（派生自 bili-dl utils.human_bytes）
# 替换登记：float 除法/f 格式化 → 整数十分位派生（size*10 // 1024），输出语义一致
UNITS = ("B", "KiB", "MiB", "GiB")
S = 1024
M = S * S
G = M * S
SIZES = (0, 512, 1023, S, S + 512, M, M + 512 * S, G, 3 * G)

def human_bytes_tenths(value):
    size10 = value * 10
    unit = 0
    while unit < 3 and size10 >= 10240:
        size10 = size10 // 1024
        unit = unit + 1
    whole = size10 // 10
    frac = size10 - whole * 10
    return whole, frac, unit

def show(value):
    whole, frac, unit = human_bytes_tenths(value)
    print(value, UNITS[unit], whole, frac)

for i in range(len(SIZES)):
    show(SIZES[i])
print(SIZES[6] // 1024 // 1024, "MiB-integer-check")
'''
_T4 = '''# T4 媒体类型判定（派生自 bili-dl utils.detect_media_kind）
# 替换登记：info.get() 方法调用 → 编码旗标（0=none 1=present）+ 分支，判定矩阵保真
CASES = ((1, 0), (0, 1), (1, 1), (0, 0), (1, 2), (2, 1))

def detect(vcodec, acodec):
    if not (vcodec == 0) and acodec == 0:
        return "video-stream"
    if not (acodec == 0) and vcodec == 0:
        return "audio-stream"
    if not (vcodec == 0) and not (acodec == 0):
        return "media-file"
    return "media-file"

EXPECT = ("video-stream", "audio-stream", "media-file", "media-file",
          "video-stream", "audio-stream")

for i in range(len(CASES)):
    v = CASES[i][0]
    a = CASES[i][1]
    got = detect(v, a)
    print(got == EXPECT[i], got)
'''
_T5 = '''# T5 错误文案翻译（派生自 bili-dl utils.clean_error_message，节选）
# 替换登记：startswith/in 子串匹配 → 已知错误池全串 EQ 分支（真实文案保真节选）
ERRS = (
    "ERROR: unable to download video data: HTTP Error 412",
    "ERROR: ffmpeg not found. Please install",
    "ERROR: unable to download video data: timeout reached",
    "WARNING: something else",
)

def translate(text):
    if text == ERRS[0]:
        return "http-412-precondition"
    if text == ERRS[1]:
        return "ffmpeg-missing"
    if text == ERRS[2]:
        return "network-timeout"
    return text

print(translate(ERRS[0]))
print(translate(ERRS[1]))
print(translate(ERRS[2]))
print(translate(ERRS[3]))
'''
_T6 = '''# T6 常量聚合（派生自 bili-dl constants.py：UA/ALLOWED_HOSTS/MODE/浏览器名）
# 保真：真实常量原文；CHROME_USER_AGENT 的隐式拼接由 CPython 常量折叠为单串
CHROME_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36"
ALLOWED_HOSTS = ("bilibili.com", "b23.tv")
MODE_SEPARATE = "分离保存（默认，免 FFmpeg）"
MODE_MERGE = "合并为单文件（需已安装 FFmpeg）"
DOWNLOAD_MODES = ("分离保存（默认，免 FFmpeg）", "合并为单文件（需已安装 FFmpeg）")
BROWSERS = ("chrome", "edge", "firefox")

print(CHROME_USER_AGENT)
print(ALLOWED_HOSTS)
print(DOWNLOAD_MODES)
print(BROWSERS)
print(len(ALLOWED_HOSTS) + len(DOWNLOAD_MODES) + len(BROWSERS))
'''
_T7 = '''# T7 混合冒烟：T1 校验 + T3 格式化 + T4 判定的流水线组合
def valid_len(code):
    n = 0
    for i in range(len(code)):
        c = code[i]
        lo = c < 48
        hi = 57 < c
        if not (lo):
            if not (hi):
                n = n + 1
        lo2 = c < 65
        hi2 = 90 < c
        if not (lo2):
            if not (hi2):
                n = n + 1
        lo3 = c < 97
        hi3 = 122 < c
        if not (lo3):
            if not (hi3):
                n = n + 1
    return n

CODES = ((66, 86, 48, 49, 50, 65, 66, 67, 68, 69, 70, 71),
         (66, 86, 49, 43, 50, 65, 66, 67, 68, 69, 70, 71))
S = 1024
M = S * S
SIZES = (M, M + 512 * S)
KINDS = ((1, 0), (0, 1), (1, 1))

def detect(v, a):
    if not (v == 0) and a == 0:
        return "video-stream"
    if not (a == 0) and v == 0:
        return "audio-stream"
    return "media-file"

def fmt_unit(value):
    size10 = value * 10
    unit = 0
    while unit < 3 and size10 >= 10240:
        size10 = size10 // 1024
        unit = unit + 1
    return unit

for i in range(len(CODES)):
    print(i, valid_len(CODES[i]))
for i in range(len(SIZES)):
    print(SIZES[i], fmt_unit(SIZES[i]))
for i in range(len(KINDS)):
    print(detect(KINDS[i][0], KINDS[i][1]))
'''
_T8 = '''# T8 错误池分类统计（派生自 bili-dl clean_error_message 的分类维度）
# 真实分支维度：网络超时 / FFmpeg 缺失 / 412 反爬 / Cookie 库 / 其他
POOL = (
    "timeout-1", "ffmpeg-1", "http-412-1", "timeout-2",
    "cookie-db-1", "ffmpeg-2", "other-1", "http-412-2",
)

def classify(text):
    if text == "timeout-1":
        return 0
    if text == "timeout-2":
        return 0
    if text == "ffmpeg-1":
        return 1
    if text == "ffmpeg-2":
        return 1
    if text == "http-412-1":
        return 2
    if text == "http-412-2":
        return 2
    if text == "cookie-db-1":
        return 3
    return 4

LABELS = ("network", "ffmpeg", "anti-crawl", "cookie", "other")
c0 = 0
c1 = 0
c2 = 0
c3 = 0
c4 = 0

total = 0
while total < len(POOL):
    k = classify(POOL[total])
    if k == 0:
        c0 = c0 + 1
    if k == 1:
        c1 = c1 + 1
    if k == 2:
        c2 = c2 + 1
    if k == 3:
        c3 = c3 + 1
    if k == 4:
        c4 = c4 + 1
    total = total + 1

print(c0, c1, c2, c3, c4)
print(LABELS)
print(c0 + c1 + c2 + c3 + c4)
'''
_R10_3_TARGETS = (("T1", _T1), ("T2", _T2), ("T3", _T3), ("T4", _T4),
                  ("T5", _T5), ("T6", _T6), ("T7", _T7), ("T8", _T8))

# 三条最小触发形态（逐条实测：修复前前两条即红，第三条是修复过程中新暴露的第三种重合形态）
_SCATTER_FIXTURES = (
    # 目标别名：BUILD_TUPLE 先 pop 再 fresh() 取 d，恰好取回 rs[0] ⇒ d 落在读窗内
    ("alias-target-in-window", "def f(a, b):\n    return a, b\nprint(f(1, 2))\n"),
    # 暂存段散落：free 里散落旧号被逐个 fresh() 发回，窗尾越过 nregs
    ("scatter-out-of-frame", "def f(a, b):\n    x = a + b\n    y = x * 2\n"
     "    z = y - x\n    return x, y, z\nprint(f(3, 4))\n"),
    # 搬运窗与源集合重合：MOVE(dst,src) 成对互覆，(1, 2) 会静默建成 (2, 2)
    ("window-equals-source", "def f(t):\n    a, b = t\n    return b, a\nprint(f((1, 2)))\n"),
)


def _materials(key: bytes = _KEY) -> dict:
    return vm_blob.matsukai_mao(key)


def _pack(source: str, seed: bytes = _SEED, key: bytes = _KEY, chunk: int = None):
    funcs, gtable, strings = vm_compiler.yamagami_karuta(compile(source, "<gate>", "exec"))
    mapping = vm_isa.hayase_sou(seed)
    kwargs = {} if chunk is None else {"chunk_size": chunk}
    blob = vm_blob.luis_cammy(funcs, mapping, gtable, _materials(key), strings=strings, **kwargs)
    return blob, mapping, funcs, gtable


_B1_SRC = (
    "def weight(ch):\n"
    "    v = ch + 7\n"
    "    w = 0\n"
    "    if not (v < 40):\n"
    "        w = 1\n"
    "    return v * 3 + w\n"
    "def main(argv, stdin):\n"
    "    a = 0\n"
    "    i = 0\n"
    "    while i < len(argv):\n"
    "        a = a + weight(argv[i])\n"
    "        i = i + 1\n"
    "    b = 0\n"
    "    j = 0\n"
    "    while j < len(stdin):\n"
    "        b = b + stdin[j]\n"
    "        j = j + 1\n"
    "    print(a, b, len(argv), len(stdin))\n"
    "    return 0\n"
)


def _pack_b1(source, seed=None):
    """input 档打包：入口指向 main（与 codec._vm_payload 的 input_mode 路径同式）。"""
    seed = seed or _SEED
    code = compile(source, "<gate-b1>", "exec")
    funcs, gtable, strings = vm_compiler.yamagami_karuta(code, input_mode=True)
    mapping = vm_isa.hayase_sou(seed)
    blob = vm_blob.luis_cammy(funcs, mapping, gtable, _materials(_KEY), strings=strings,
                              entry_fid=vm_compiler.umise_yotsuha(code, True))
    return blob, funcs, gtable


def _b1_reference(source, argv, stdin):
    """CPython 参考腿。两窗先按 早期轮次定长吸收补齐（与 VM 腿共用
    `vm_isa.hibachi_mana` 那一条表达式、同一个逐格补齐字节）——不补齐就是两条腿
    各自看一份不同的输入，"等价"这句断言当场失去内容。"""
    root = vm_blob.matsukai_mao(_KEY)["root"]
    prf = vm_isa.kaburaki_roco(root)
    ns = {}
    vm_isa.usami_rito(ns, root)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        exec(compile(source, "<ref>", "exec"), ns)
        ns["main"](vm_isa.hibachi_mana(prf, argv), vm_isa.hibachi_mana(prf, stdin))
    return buf.getvalue().encode("utf-8")


_HARD_SRC = (
    "def main(argv, stdin):\n"
    "    a = 4111\n"
    "    i = 0\n"
    "    pv = 77\n"
    "    while i < len(argv):\n"
    "        c = argv[i]\n"
    "        t = pv + c\n"
    "        t = t - (t // 256) * 256\n"
    "        w = (c + 101) * 257\n"
    "        q = t * t * 13 + t * 3121 + 97\n"
    "        q = q - (q // 32749) * 32749\n"
    "        mm = w + q\n"
    "        gg = rotl32(a + mm + 29167, 16)\n"
    "        gg = gg ^ rotl32(gg, 16)\n"
    "        hh = rotl32(a + mm * mm + 29167, 8)\n"
    "        hh = hh ^ rotl32(hh, 8)\n"
    "        ss = rotl32(hh + gg * 21871 + 5096, 13)\n"
    "        a = rotl32(ss, 0)\n"
    "        pv = c\n"
    "        i = i + 1\n"
    "    b = 977\n"
    "    j = 0\n"
    "    while j < len(stdin):\n"
    "        d = stdin[j]\n"
    "        mm = d * 257 + 907\n"
    "        gg = rotl32(b + mm + 12377, 16)\n"
    "        gg = gg ^ rotl32(gg, 16)\n"
    "        hh = rotl32(b + mm * mm + 12377, 8)\n"
    "        hh = hh ^ rotl32(hh, 8)\n"
    "        ss = rotl32(hh + gg * 7919 + 4211, 13)\n"
    "        b = rotl32(ss, 0)\n"
    "        j = j + 1\n"
    "    print(a, b, len(argv) + len(stdin))\n"
    "    return 0\n"
)
# 硬化前的形态（既有审计打穿过的那条）：逐字节权重和——顺序无关、可拟合、无雪崩
_FLAT_SRC = (
    "def fold(ch, salt):\n"
    "    v = ch + salt\n"
    "    w = 0\n"
    "    if not (v < 97):\n"
    "        w = 1\n"
    "    return v * 3 + w\n"
    "def main(argv, stdin):\n"
    "    a = 0\n"
    "    i = 0\n"
    "    while i < len(argv):\n"
    "        a = a + fold(argv[i], 7)\n"
    "        i = i + 1\n"
    "    b = 0\n"
    "    j = 0\n"
    "    while j < len(stdin):\n"
    "        b = b + fold(stdin[j], 12)\n"
    "        j = j + 1\n"
    "    print(a, b, len(argv) + len(stdin))\n"
    "    return 0\n"
)


def case_bc_hardening_gates():
    """早期轮次+C 三新出厂门（生产实现 d_side.selfcheck）：正例、负例、齿的阳性对照。

    1) 表自洽：layout.json > hardening 里每个形状声明的门都必须真的存在、且 c1/bc
       三件齐全（消融臂可以少声明，但不能声明不存在的门）；
    2) 正例：硬化目标源码过雪崩门（平均翻转在带内、最小值不塌、低尾占比达标）、过结构否定门、
       过拟合齿（四个可加族模型 验收 全错）；
    3) 负例：**同一套门**打在硬化前的线性靶上必须红——雪崩带不过、结构否定门三位置同值、
       拟合齿被"add"拟穿。门只能过不能拒就等于没门；
    4) 齿的阳性对照（设计稿）：拟合手法必须能破线性靶（"add" 错误率 0），
       否则"全部模型必错"这个结论是空转得来的。
    样本量在这里降到 inputs=8（每列 80 个翻位样本，仍 ≥ min_samples 64）以守住套件
    时长；出厂路径由 codec.octavio(shape=...) 用表里的 64 组真跑（同一份实现）。
    """
    from d_side.selfcheck import (_hardening, _ref_caller, gate_avalanche, gate_fitting,
                                  gate_structure_negation, sophia_valentine,
                                  SelfcheckError)

    hard = _hardening()
    for shape, declared in hard["shapes"].items():
        for gname in declared:
            assert gname in hard["gates"], "形状 %s 声明了不存在的门 %r" % (shape, gname)
    # 默认出厂形态读 layout > hardening.default_shape（单源； 拍板 bc → bc2），
    # 断言它**至少**带着上一代出厂的三件门 + 原生链那一代新增的两件（常量表 / 平坦度）——
    # 默认档的门集缩水就红灯，而不必有人记得回来改这个字面量。
    default_shape = hard["default_shape"]
    assert default_shape in hard["shapes"], "默认形状不在门集表里：%r" % (default_shape,)
    assert set(hard["shapes"][default_shape]) >= {"avalanche", "structure", "fitting",
                                                 "constants_table", "flatness"}, \
        "默认出厂形态 %s 的门集缩水了：%r" % (
            default_shape, hard["shapes"][default_shape])
    assert set(hard["shapes"]["bc"]) == {"avalanche", "structure", "fitting"}, \
        "消融臂 bc 的门集被改动（G3/G4 证据要求它能从同一份源复现）：%r" % (
            hard["shapes"]["bc"],)
    assert hard["shapes"]["linear"] == [], "linear 是消融基线，不该声明新门"

    th_av = dict(hard["gates"]["avalanche"], inputs=8)
    th_ft = dict(hard["gates"]["fitting"], holdout=12, perm_samples=4)
    work = _ROOT / ".tmp" / "gate-bc-hardening"
    hardened = _ref_caller(_HARD_SRC, work)
    flat = _ref_caller(_FLAT_SRC, work)
    seed = _SEED
    nonce = b"\x01" * 12

    av = gate_avalanche(hardened, seed, nonce, th_av)
    for key in ("col1", "col2"):
        assert th_av["mean_lo"] <= av[key]["mean"] <= th_av["mean_hi"], \
            "硬化靶雪崩不达：%r" % (av[key],)
        assert av[key]["min"] >= th_av["floor"] and \
            av[key]["below_%d_pct" % th_av["tail_below"]] <= 100 * th_av["tail_budget"], \
            "硬化靶雪崩下尾不达标：%r" % (av[key],)
    assert gate_structure_negation(hardened, hard["gates"]["structure"])["distinct"] == 3
    ft = gate_fitting(hardened, seed, nonce, th_ft)
    assert all(v == 1.0 for v in ft["error_rate"].values()), \
        "拟合齿在硬化靶上竟然有模型全对：%r" % (ft["error_rate"],)

    # 负例：雪崩门与结构否定门必须把硬化前的线性靶挡在门外（门只能过不能拒就等于没门）
    for name, args in (("avalanche", (flat, seed, nonce, th_av)),
                       ("structure", (flat, hard["gates"]["structure"]))):
        fn = {"avalanche": gate_avalanche, "structure": gate_structure_negation}[name]
        try:
            got = fn(*args)
        except SelfcheckError:
            continue
        raise AssertionError("线性靶过了 %s 门——门失去判别力：%r" % (name, got))
    # 拟合齿这一路反过来看：齿是"报告错误率"的实现，断言在 sophia_valentine 里。
    # 所以线性靶的正确负例是——齿**能**拟穿它（阳性对照，设计稿），而生产入口
    # 对"声称 bc 却其实是线性"的产物必须拒。
    ctl = gate_fitting(flat, seed, nonce, th_ft)
    assert ctl["error_rate"]["add"] == 0.0, \
        "齿空转：连线性靶都拟不上（%r）——那'全部模型必错'的结论没有意义" % ctl["error_rate"]
    assert ctl["order_invariant_samples"].startswith("4/4"), \
        "排列探针没测出线性靶顺序无关：%r" % (ctl,)
    try:
        sophia_valentine(_FLAT_SRC, work, seed, nonce, "bc")
        raise AssertionError("线性产物声称 bc 却没被生产入口拒掉")
    except SelfcheckError:
        pass
    # 生产入口的正例：硬化产物按真阈值（64 组输入）整条走通，三件门都给出数字
    rep = sophia_valentine(_HARD_SRC, work, seed, nonce, "bc")
    assert set(rep["gates"]) == {"avalanche", "structure", "fitting"}, rep["gates"].keys()
    assert rep["gates"]["avalanche"]["col1"]["samples"] >= 64 * 4, \
        "生产门样本量缩水：%r" % (rep["gates"]["avalanche"]["col1"],)
    # 未知形状直接拒（不许"忘了声明就当过了"）
    try:
        sophia_valentine(_HARD_SRC, work, seed, nonce, "shape-not-in-table")
        raise AssertionError("未知 shape 未被拒")
    except SelfcheckError:
        pass
    # CLI 侧同样有声明口：--shape 必须配 --input-dependent（三新门断言的是输入函数）。
    # 乱声明直接 rc!=0，绝不"当作没看见"把产物放出厂。
    src = work / "cli_shape.py"
    src.write_text(_HARD_SRC, encoding="utf-8")
    cli = subprocess.run([sys.executable, "-m", "d_side", "build",
                          "--source", str(src), "--out", str(work / "cli_out.py"),
                          "--seed", seed.hex(), "--vm", "--shape", "bc"],
                         capture_output=True, text=True, encoding="utf-8",
                         errors="replace", timeout=600, cwd=str(_ROOT), shell=False)
    blob = (cli.stdout or "") + (cli.stderr or "")
    assert cli.returncode != 0 and "--shape" in blob, \
        "CLI 的 --shape 守卫没生效：rc=%d %r" % (cli.returncode, blob[-160:])


def case_chain_native_profile():
    """早期轮次验收：链剖面**逐格**不同，且每条轴都真的在动。

    工作书要求"破一格不再等于破八格"。这一条把它变成可断言的事实：一批派生 root 上
    ①剖面元组两两不同；②轮数取到 {2,3,4}、回灌形式取到 ≥3 种、耦合档与半折次数两值
    都出现、至少一格给出非恒等轮序——轴没动就等于逐格化是假的；③补齐字节不恒等。
    顺带钉 hstep 的值域（恒 < 2^32）与确定性（同 root 同剖面、同输入同输出）。
    """
    roots = [bytes([i, 0x5A] * 16) for i in range(24)]
    prfs = [vm_isa.kaburaki_roco(r) for r in roots]
    shape = [(p["rounds"], p["fold_pos"], p["fold_cnt"], p["inject"], p["couple"],
              p["tail_rot"], tuple(p["order"]), tuple(p["rot"]), tuple(p["fold_val"]))
             for p in prfs]
    assert len(set(shape)) == len(shape), "链剖面出现重复格子：逐格化没有生效"
    assert {p["rounds"] for p in prfs} == {2, 3, 4}, "轮数轴没有取满 {2,3,4}：%r" % (
        {p["rounds"] for p in prfs},)
    assert len({p["inject"] for p in prfs}) >= 3, "回灌形式轴太窄：%r" % (
        {p["inject"] for p in prfs},)
    assert {p["couple"] for p in prfs} == {0, 1}, "耦合档没有两值"
    assert {p["fold_cnt"] for p in prfs} == {1, 2}, "半折次数没有两值"
    assert any(tuple(p["order"]) != tuple(range(p["rounds"])) for p in prfs), \
        "轮序（步进顺序）轴一直是恒等排列——那一格是死格"
    assert len({p["pad"] for p in prfs}) > 1, "补齐字节逐格没有变化"
    assert vm_isa.kaburaki_roco(roots[0])["iv"] == prfs[0]["iv"], "剖面不自洽（I6）"
    a = vm_isa.shishido_akari(prfs[0], 0, 0)
    assert 0 <= a < vm_isa.U32 and a == vm_isa.shishido_akari(prfs[0], 0, 0)
    # 状态与消息都要参与：只改 st 或只改 m 都必须改变输出（否则那一半是死输入）
    differs = all(vm_isa.shishido_akari(p, 1, 7) != vm_isa.shishido_akari(p, 2, 7)
                  and vm_isa.shishido_akari(p, 1, 7) != vm_isa.shishido_akari(p, 1, 8)
                  for p in prfs)
    assert differs, "存在只吃状态或只吃消息的剖面形态"
    # 入口 IV 折叠生效：st=0 与 st=IV 的一步必须不同（IV 不出现在 IR 里，见 constants 门）
    assert vm_isa.shishido_akari(prfs[0], 0, 5) != vm_isa.shishido_akari(prfs[0],
                                                                        prfs[0]["iv"], 5)


def case_chain_native_gates():
    """早期轮次 验收：hstep 产物过五门；旧 inline 形态声称 c2 被 constants_table 当场拒。

    正例走**生产入口** codec.octavio(shape="c2")——门只有长在出厂路径上才是门。
    负例三条：①inline ARX 靶声明 c2（没有 HSTEP）→ 拒；②把真实 IR 换成一段"确实包含
    某枚链常量"的字节流 → 拒（这条是 hits 分支的牙：i16 立即数根本表达不了 4 字节常量，
    不这样喂就没法证明那条分支不是空转）；③flatness 门缺 blob 时
    必须 raise 而不是跳过。
    """
    from d_side.selfcheck import SelfcheckError, chain_words, saiki_ittetsu, sophia_valentine

    hard = json.loads((_ROOT / "d_side" / "layout.json").read_text(
        encoding="utf-8"))["hardening"]
    th_ct = hard["gates"]["constants_table"]
    work = _ROOT / ".tmp" / "gate-chain-native"
    res = codec.octavio(_C2_SRC, "gate-c2", _SEED, vm=True, input_dependent=True,
                        shape="c2", gate_work=work)
    gates = res["hardening"]["gates"]
    assert set(gates) == {"avalanche", "structure", "fitting", "constants_table",
                          "flatness"}, "c2 的门集不完整：%r" % (sorted(gates),)
    for col in ("col1", "col2"):
        assert hard["gates"]["avalanche"]["mean_lo"] <= gates["avalanche"][col]["mean"] \
            <= hard["gates"]["avalanche"]["mean_hi"], "新结构下雪崩不达带：%r" % (gates["avalanche"],)
    assert gates["constants_table"]["hstep_present"] and \
        gates["constants_table"]["chain_words_hidden"] == th_ct["chain_words"]
    fl = gates["flatness"]
    assert fl["spread"] == fl["band"] == 0, "定长吸收没有生效：%r" % (fl,)
    assert fl["samples"] >= hard["gates"]["flatness"]["min_samples"]

    # ①旧 inline 形态（v5 bc）声明 c2 → 步进还在字节码里，必须拒
    try:
        codec.octavio(_HARD_SRC, "gate-c2-neg", _SEED, vm=True, input_dependent=True,
                      shape="c2", gate_work=work)
        raise AssertionError("inline ARX 靶声称 c2 却没被 constants_table 拒掉")
    except SelfcheckError:
        pass

    # ②字面量检出的牙：造一段确实含某枚链常量的 IR，同一个门必须拒
    root = vm_blob.matsukai_mao(res["keys"][0])["root"]
    words = chain_words(root)
    leak = bytes([1, 2, 3]) + (words[7] & 0xFFFFFFFF).to_bytes(4, "little") + bytes([4, 5])
    try:
        saiki_ittetsu(leak, {"HSTEP"}, root, th_ct)
        raise AssertionError("IR 里明晃晃摆着一枚链常量却没被检出——门是空的")
    except SelfcheckError:
        pass

    # ③flatness 缺输入必须 raise（不许"没数据就当过了"）
    try:
        sophia_valentine(_C2_SRC, work, _SEED, b"\x01" * 12, "c2")
        raise AssertionError("flatness 门在没有 blob 时被静默跳过")
    except SelfcheckError:
        pass


def case_absorb_window():
    """早期轮次验收（Python 权威腿）：窗恒等于上限，`len(argv)` 因此是逐格常数。

    长度侧信道是直接量出来的（空 argv 191 次迭代 vs "hello" 63,743 次）。这里钉三件：
    ①任意长度输入的运行步数**逐位相同**（不是"差不多"，是相等）；
    ②kind 3/4 全局槽取到的值恒等于上限——摘掉吸收，这一条与①同时变红；
    ③吸收不改变"超上限即拒"的老纪律（补齐不是截断的借口）。
    """
    ladder = (0, 1, 2, 5, 17, 32, 63, 64)
    blob, _f, _g = _pack_b1(_C2_SRC)
    mao = vm_blob.matsukai_mao(_KEY)
    gtable = vm_blob.meta_unpack(vm_blob.shirayuki_tomoe(blob, mao), mao)["gtable"]
    len_slots = [i for i, (k, _v) in enumerate(gtable)
                 if k in (vm_isa.G_ARGV_LEN, vm_isa.G_STDIN_LEN)]
    assert len_slots, "夹具没有 len() 全局槽，结构齿空转"
    steps = set()
    for length in ladder:
        for argv, stdin in ((b"Y" * length, b""), (b"", b"Y" * length)):
            vm = vm_interp.RimiUshigome(blob, _KEY, _SEED, argv=argv, stdin=stdin)
            vm.run()
            steps.add(vm.steps)
            assert len(vm.argv_win) == vm_isa.INPUT_WINDOW == len(vm.stdin_win)
            assert vm.globals[vm_isa.G_ARGV_LEN] == vm_isa.INPUT_WINDOW
            assert all(vm.globals[i] == vm_isa.INPUT_WINDOW for i in len_slots), \
                "kind 3/4 报了真实长度：吸收被绕过"
    assert len(steps) == 1, "运行步数随输入长度变化：%r" % (sorted(steps),)
    ref = _b1_reference(_C2_SRC, b"", b"")
    assert ref.split()[2] == b"128", "col3（两窗之和）不再是常数：%r" % (ref,)
    try:
        vm_interp.RimiUshigome(blob, _KEY, _SEED, argv=b"x" * 65, stdin=b"")
        raise AssertionError("超上限输入被接受了（吸收被当成截断的借口？）")
    except vm_interp.SaayaYamabuki:
        pass


_C2_SRC = (
    "def main(argv, stdin):\n"
    "    a = 0\n"
    "    i = 0\n"
    "    while i < len(argv):\n"
    "        c = argv[i]\n"
    "        a = hstep(a, (c + 101) * 257)\n"
    "        i = i + 1\n"
    "    b = 0\n"
    "    j = 0\n"
    "    while j < len(stdin):\n"
    "        d = stdin[j]\n"
    "        b = hstep(b, (d + 7) * 131)\n"
    "        j = j + 1\n"
    "    print(a, b, len(argv) + len(stdin))\n"
    "    return 0\n"
)


def case_iface_contract():
    """早期轮次 Phase 2 验收（关）：接口契约逐格派生 + interface_diversity_gate 有齿。

    ①轴取值范围正确（ap/sp ∈ 48..80、argmax ∈ 8..40、join 含"无连接符"档、
      argv0/keystrip/reject_exit 都取到多值）；
    ②同 seed 同契约（构建期确定性， 不破）、异 seed 异契约；
    ③门：一组真格子过 inami_rai；**手工造的八格全同**必须被拒——那正是上一代的状态，
      门认不出它就是空转；
    ④契约不进产物：col3 语义是纯构建侧值（产物里不许出现语义串）；
    ⑤v2/CLI 构建路径的门按**出厂那一格**的上限取样（不许静默回落到库默认）。
    """
    from d_side.builder.native_build import koyanagi_rou
    from d_side.selfcheck import SelfcheckError, inami_rai

    hard = json.loads((_ROOT / "d_side" / "layout.json").read_text(
        encoding="utf-8"))["hardening"]["gates"]["interface_diversity"]
    specs = [koyanagi_rou(bytes([i] * 31) + bytes([0x5A]), None, "per_cell")
             for i in range(1, 25)]
    uni = koyanagi_rou(bytes([1] * 31) + bytes([0x5A]), None, "uniform")
    assert (uni["ap"], uni["sp"], uni["join"], uni["argv0"], uni["reject_exit"]) == \
        (64, 64, 0, False, 3), "uniform 档必须逐字退化到上一代的全局契约：%r" % (uni,)
    assert koyanagi_rou(bytes([1] * 31) + bytes([0x5A]), b"\x01" * 12,
                        "per_cell") == specs[0], "同 seed 契约不稳定（I6）"
    assert koyanagi_rou(bytes([1] * 31) + bytes([0x5A]), b"\x02" * 12,
                        "per_cell") == specs[0], \
        "契约吃了 nonce——目标源码的 col3 语义取自契约，而 nonce 又是目标源码摘要的函数，" \
        "那成了自指回环（场景生成器只能两趟构建，第二趟又会换契约）"
    assert all(48 <= s["ap"] <= 80 and 48 <= s["sp"] <= 80 for s in specs)
    assert all(8 <= s["argmax"] <= 40 for s in specs)
    assert {s["argv0"] for s in specs} == {True, False}, "argv[0] 档没有两值"
    assert {s["keystrip"] for s in specs} == {0, 1, 2, 3}, "key-file 剥离档没取满四档"
    assert {s["reject_exit"] for s in specs} == {3, 4}, "超限退出码没有两值"
    assert any(s["join"] == 256 for s in specs), "从没派生出'无连接符'档"
    assert len({s["fingerprint"] for s in specs}) > 16, "契约几乎全同：%d/24" % (
        len({s["fingerprint"] for s in specs}))
    rep = inami_rai(specs, hard)
    axes = ("ap", "sp", "argmax", "join", "argv0", "keystrip", "reject_exit")
    assert rep["fingerprints"] == len({tuple(s[k] for k in axes) for s in specs}), \
        "门报的指纹数与实算不符"
    twin = [dict(specs[0]) for _ in range(8)]
    try:
        inami_rai(twin, hard)
        raise AssertionError("八格接口全同却被放行——门没有齿（那正是上一代的状态）")
    except SelfcheckError:
        pass
    try:
        inami_rai(specs[:2], hard)
        raise AssertionError("格子数不足门预算却放行")
    except SelfcheckError:
        pass
    # 语义串不进产物：col3 只活在构建侧，boot 不消费它
    boot_src = (_ROOT / "d_side" / "builder" / "boot.rs").read_text(encoding="utf-8")
    for word in ("nonzero", "highbit", "printable"):
        assert word not in boot_src, "col3 语义串出现在 boot 源里：%r" % word
    # ⑤v2/CLI 构建路径的那道门必须量**出厂那一格**。它曾经漏传契约，`_caps(None)` 静默
    #   回落到库默认 64/64——uniform 档下"恰好正确"所以看不出来，mode 一翻 per_cell 就变成
    #   "门绿、产品却是另一套接口"。这里按 per_cell 构建，逐格比对门自报的取样上限与
    #   出厂契约，并要求至少一格明显不是 64/64（否则这条齿等于没咬）。
    from d_side.selfcheck import mashiro_meme

    work = _ROOT / ".tmp" / "gate-iface-meme"
    off_default = 0
    for tail in (11, 12, 13):
        seed = bytes([tail] * 31) + bytes([0x5A])
        r = codec.octavio(_C2_SRC, "ifacememe%d" % tail, seed, vm=True,
                          input_dependent=True, external_key=False,
                          iface_mode="per_cell")
        want = [r["iface"]["ap"], r["iface"]["sp"]]
        got = mashiro_meme(r, _C2_SRC, r["artifact"],
                           work / ("meme%d" % tail))["b1"]["caps"]
        assert got == want, "v2 构建门按 %r 取样，出厂契约却是 %r" % (got, want)
        off_default += 0 if got == [64, 64] else 1
    assert off_default, "三格契约全等于库默认 64/64——这条齿没量到任何东西"


def case_input_primitives():
    """早期轮次 输入原语 KAT（Python 权威端）：语义 / 边界 / 拒绝路径 / 句柄纪律。

    钉八条，逐条都是 vm.rs 必须同式的判据（Rust 腿在 test_native_vm 用真产物钉）：
    ①正常输入下与 CPython 逐字节等价；②空输入等价（两窗都空）；③**非 UTF-8 字节**
    （0xFF/0x80）原样作为 0..255 整数出现，不借道 str；④NUL 分隔的扁平化 argv 口径
    两侧一致；⑤下标越界 → SaayaYamabuki（不是错值、不是崩溃）；⑥输入超 64 B 上限
    → 构造期即拒，**绝不静默截断**；⑦`len(argv)` 编译成 LOADG(kind 3/4)，全局表里
    确实有 3/4 两枚 kind、且 blob 里没有输入长度的明文常量；⑧句柄纪律：把 argv/stdin
    当值用、重绑定、传给函数、解包一律编译期硬拒，且不消费输入的样本过不了出厂门。
    """
    blob, funcs, gtable = _pack_b1(_B1_SRC)
    kinds = {k for k, _v in gtable}
    assert {vm_isa.G_ARGV_LEN, vm_isa.G_STDIN_LEN} <= kinds, "长度 kind 未进全局表：%r" % kinds
    assert vm_isa.lain_paterson(funcs), "出厂门判据失灵：IR 明明含 ARGV/STDIN 却报未消费"

    for argv, stdin in ((b"ab\x00cdef", b"xyz"), (b"", b""), (b"\xff\x80", b"\x00\x7f"),
                        (bytes(range(64)), b"z" * 64), (b"a" * 20 + b"\x00" + b"b" * 30, b"")):
        got = vm_interp.gwelu_os_gar(blob, _KEY, _SEED, argv=argv, stdin=stdin)
        want = _b1_reference(_B1_SRC, argv, stdin)
        assert got == want, "输入 %r/%r 下 VM 与 CPython 分叉：%r != %r" % (
            argv[:12], stdin[:12], got, want)
    # ③ 非 UTF-8 走整数通道：0xFF 必须贡献 255（不是 0、不是异常）
    one = ("def main(argv, stdin):\n    print(argv[0] + argv[1])\n    return 0\n")
    blob1, _f1, _g1 = _pack_b1(one)
    assert vm_interp.gwelu_os_gar(blob1, _KEY, _SEED, argv=b"\xff\x80", stdin=b"") == b"383\n"

    # ⑤ 越界判据 = **补齐后的窗**（早期轮次定长吸收）。旧口径"下标越过真实长度即拒"
    #    作废，理由是它本身就是一条长度信号：拒绝与不拒绝是两种可观察行为，攻击者拿它
    #    一次二分就能问出输入长度。新口径下 cap-1 以内一律可读（读到逐格补齐字节），
    #    到 cap 才拒——窗越界仍然 fail-closed，只是不再暴露真实长度。
    root = vm_blob.matsukai_mao(_KEY)["root"]
    prf = vm_isa.kaburaki_roco(root)
    pad = prf["pad"]
    bad = "def main(argv, stdin):\n    print(argv[64])\n    return 0\n"
    blob2, _f2, _g2 = _pack_b1(bad)
    for av in (b"a\x00b", b"", b"z" * 64):
        try:
            vm_interp.gwelu_os_gar(blob2, _KEY, _SEED, argv=av, stdin=b"")
            raise AssertionError("ARGV 越过补齐窗未被拒（argv=%r）" % (av[:8],))
        except vm_interp.SaayaYamabuki:
            pass
    inside = "def main(argv, stdin):\n    print(argv[3], stdin[10])\n    return 0\n"
    blob2b, _f2b, _g2b = _pack_b1(inside)
    got = vm_interp.gwelu_os_gar(blob2b, _KEY, _SEED, argv=b"a\x00b", stdin=b"q")
    assert got == ("%d %d\n" % (pad, pad)).encode("ascii"), \
        "补齐位读到的不是本格补齐字节：%r（期望 %d）" % (got, pad)
    assert got == _b1_reference(inside, b"a\x00b", b"q"), "补齐位两腿分叉"

    # ⑥ 超上限一律拒（两侧同式：vm_interp 构造期拒，boot 填窗拒）
    for over in ((b"x" * 65, b""), (b"", b"y" * 65)):
        try:
            vm_interp.gwelu_os_gar(blob, _KEY, _SEED, argv=over[0], stdin=over[1])
            raise AssertionError("超 64B 输入未被拒（静默截断）：%r" % (over,))
        except vm_interp.SaayaYamabuki:
            pass

    # ⑦ 长度不是编译期常量：把探针输入换成 64/64，产物字节必须完全相同（同一 blob），
    #    且 blob 里找不到 "64" 这种由输入规模写死出来的痕迹
    blob_same, _f3, _g3 = _pack_b1(_B1_SRC)
    assert blob_same == blob, "同一源码同 seed 的 blob 不稳定（I6）"
    assert vm_interp.gwelu_os_gar(blob, _KEY, _SEED, argv=b"", stdin=b"") == \
        _b1_reference(_B1_SRC, b"", b""), "空输入与参考腿分叉"

    # ⑧ 句柄纪律 + 出厂门
    for misuse in ("def main(argv, stdin):\n    print(argv)\n    return 0\n",
                   "def main(argv, stdin):\n    argv = 1\n    return 0\n",
                   "def main(argv, stdin):\n    print(len(stdin[0:2]))\n    return 0\n",
                   "def main(argv, stdin):\n    x = stdin\n    print(x)\n    return 0\n",
                   "def main(argv, stdin):\n    print(argv[0] + stdin[0])\n    argv[0] = 3\n"
                   "    return 0\n"):
        try:
            vm_compiler.yamagami_karuta(compile(misuse, "<x>", "exec"), input_mode=True)
            raise AssertionError("输入句柄误用未被拒：%r" % misuse.splitlines()[1])
        except vm_compiler.TaeHanazono:
            pass
    for refuses in ("print('constant 42')\n",
                    "def main(argv, stdin):\n    print(7)\n    return 0\n",
                    "def main(argv):\n    return 0\n",
                    "def main(argv, stdin):\n    print(1)\n    return 0\nprint('side')\n"):
        try:
            codec.octavio(refuses, "gate", _SEED, vm=True, input_dependent=True)
            raise AssertionError("退化/非 main 样本过了出厂门：%r" % refuses[:34])
        except ValueError:
            pass
    # 非 input 档必须完全看不到新形态（并存口径：旧载荷零改动）
    old = codec.octavio("print('legacy module body')\n", "gate", _SEED, vm=True)
    assert old["payload"][6] == vm_isa.ISA_VER, "旧形态 blob 的 isa_ver 漂移"
    assert not (old["fields"]["flags"] & 0b100000), "未开 input 档却置了位 5"


def case_physmap():
    m1 = vm_isa.hayase_sou(_SEED)
    m2 = vm_isa.hayase_sou(_SEED)
    assert m1 == m2, "physmap must be deterministic (I6)"
    vals = list(m1.values())
    assert len(set(vals)) == len(vals), "physmap must be injective"
    other = vm_isa.hayase_sou(bytes(range(31)) + bytes([0x5B]))
    assert other != m1, "different seed must give a different mapping"
    assert len(m1) == len(vm_isa.LOGICAL_OPS), "every logical opcode must have a physical byte"
    # 映射必须覆盖全部逻辑操作码，且物理字节都在 0..255
    assert sorted(m1.keys()) == sorted(n for n, _ in vm_isa.LOGICAL_OPS)
    assert all(0 <= b <= 255 for b in m1.values())
    # 追加纪律（layout.json > vm > v5_logic_ops.coexistence 那句话的齿）：扩表只许往表尾
    # 加，同一 seed 下旧 29 名的物理字节必须与 v4 -era 金样逐格相同——否则已出厂产物的
    # 操作码字节会随升档漂移（那是比"新 boot 解不开旧 blob"更阴的分叉）。
    names = [n for n, _ in vm_isa.LOGICAL_OPS]
    assert [m1[n] for n in names[:29]] == list(_PHYSMAP_V4ERA), \
        "物理映射随扩表漂移（旧操作码的物理字节变了）"
    assert len(names) == 32 and names[29:] == ["XOR", "ROTL32", "HSTEP"], \
        "v5/v6 追加位序变了：%r" % (names[29:],)


# 冻结金样：seed=_SEED 下 v4 时代 29 枚逻辑操作码的物理字节（按 LOGICAL_OPS 旧序）
_PHYSMAP_V4ERA = (38, 124, 10, 77, 67, 233, 72, 35, 2, 36, 81, 104, 16, 224, 213,
                  143, 44, 33, 153, 125, 89, 71, 165, 130, 15, 95, 29, 112, 75)

_U32_MAX = (1 << 32) - 1
# ①值域样本：0/1/边界/i16 闸附近/2 的幂/全 1/单 bit 型 + k 的 mod 32 边界
_V5_VALUES = (0, 1, 2, 3, 127, 128, 255, 256, 32767, 32768, 65535, 65536, 1 << 16,
              1 << 24, (1 << 31) - 1, 1 << 31, (1 << 31) + 1, 0x0F0F0F0F, 0xF0F0F0F0,
              0x12345678, 0xDEADBEEF, 0xFFFFFFFE, _U32_MAX)
_V5_KEYS = (0, 1, 5, 15, 16, 17, 30, 31, 32, 33, 63, 64, 255, 4096, _U32_MAX)
_V5_KAT_SRC = (
    "def main(argv, stdin):\n"
    "    a = ((stdin[0] * 256 + stdin[1]) * 256 + stdin[2]) * 256 + stdin[3]\n"
    "    b = ((stdin[4] * 256 + stdin[5]) * 256 + stdin[6]) * 256 + stdin[7]\n"
    # c 故意越过 2^32（a*256+7 最大 2^40 量级）：钉住"ROTL32 先取低 32 位"这一条，
    # 也钉住 XOR 在大值上照常按位（值域为非负整数，不在 32 位处设闸）
    "    c = a * 256 + 7\n"
    "    print(a ^ b, rotl32(a, b), rotl32(b, a), c ^ b, rotl32(c, 5), rotl32(c, b))\n"
    "    return 0\n"
)


def _v5_oracle(a, b) -> bytes:
    """期望值只由 **vm_isa.INTRINSICS 的 CPython 闭式** + Python 自带的 ^ 给出——
    测试里不再抄第三份实现（抄一份就是一处可能漂移的分叉）。"""
    rot = vm_isa.INTRINSICS["rotl32"][2]
    c = a * 256 + 7
    return ("%d %d %d %d %d %d\n" % (a ^ b, rot(a, b), rot(b, a),
                                     c ^ b, rot(c, 5), rot(c, b))).encode("ascii")


def _v5_stdin(a, b) -> bytes:
    return a.to_bytes(4, "big") + b.to_bytes(4, "big")


def case_logic_ops_kat():
    """早期轮次+C（ISA v5）逻辑操作码 KAT（Python 权威端）。

    钉五条：①^ 与内建 rotl32 都编译成**新操作码**（不是算术模拟），且内建不进全局表；
    ②值域抽样 ≥32 组（边界 + k 的 mod 32）与 CPython 闭式逐字节一致，含 a ≥ 2^32 的
      取低位分支；③负操作数（a、k 两路）与非整型（str）一律 SaayaYamabuki，不给错值；
    ④i16 字面量纪律不因新操作码松动；⑤内建当值用/错元数编译期硬拒，且内建名不落产物。
    Rust 腿（真 exe 同输入同值）在 tests/d_side/test_native_vm.py 的 v5_logic_ops_native。
    """
    blob, funcs, gtable = _pack_b1(_V5_KAT_SRC)
    names = {ins[0] for _n, instrs in funcs for ins in instrs}
    assert {"XOR", "ROTL32"} <= names, "新操作码未被发射（走了算术模拟？）：%r" % names
    kinds = {k for k, _v in gtable}
    assert kinds <= {1, 2, 3, 4}, "全局表冒出未知 kind（内建不该建槽）：%r" % kinds
    assert vm_isa.ISA_VER == 6 and len(vm_isa.LOGICAL_OPS) == 32, "ISA 档位/操作码数漂移"
    assert vm_isa.OP_WIDTHS["XOR"] == (1, 1, 1) == vm_isa.OP_WIDTHS["ROTL32"]
    assert vm_isa.OP_WIDTHS["HSTEP"] == (1, 1, 1), "早期轮次 HSTEP 宽度表未同步"
    assert vm_isa.OP_KINDS["XOR"] == ("R", "R", "R") == vm_isa.OP_KINDS["ROTL32"], \
        "W13 种类表未同步（译码点验界会漏）"
    assert vm_isa.OP_KINDS["HSTEP"] == ("R", "R", "R"), "HSTEP 的 W13 种类表未同步"

    checked = 0
    for a in _V5_VALUES:
        for b in _V5_KEYS:
            got = vm_interp.gwelu_os_gar(blob, _KEY, _SEED, argv=b"",
                                         stdin=_v5_stdin(a, b))
            want = _v5_oracle(a, b)
            assert got == want, "(%d,%d)：VM %r != 闭式 %r" % (a, b, got, want)
            checked += 1
    assert checked >= 32, "值域样本不足：%d" % checked
    # ②的补：k 全 0..31 逐一位移（单 bit 状态，旋转结果必须落在唯一正确的位上）
    ksrc = ("def main(argv, stdin):\n"
            "    print(rotl32(1, stdin[0]))\n    return 0\n")
    kblob, _kf, _kg = _pack_b1(ksrc)
    rot = vm_isa.INTRINSICS["rotl32"][2]
    for k in range(32):
        got = vm_interp.gwelu_os_gar(kblob, _KEY, _SEED, argv=b"",
                                     stdin=bytes([k]) + b"\x00\x00\x00\x00")
        assert got == ("%d\n" % rot(1, k)).encode(), "k=%d 位移错值：%r" % (k, got)
    # ③ 拒绝路径：负数（a 路 / k 路）与 str 操作数都不得给出错值
    for bad, why in (("def main(argv, stdin):\n"
                      "    x = 0 - stdin[0]\n"
                      "    print(x ^ 3)\n    return 0\n", "XOR 负操作数"),
                     ("def main(argv, stdin):\n"
                      "    x = 0 - stdin[0]\n"
                      "    print(rotl32(x, 3))\n    return 0\n", "ROTL32 负被移量"),
                     ("def main(argv, stdin):\n"
                      "    x = 0 - stdin[0]\n"
                      "    print(rotl32(3, x))\n    return 0\n", "ROTL32 负移位数"),
                     ("WORDS = ('abc',)\n"
                      "def main(argv, stdin):\n"
                      "    print(WORDS[0] ^ 3)\n    return 0\n", "XOR 字符串操作数"),
                     ("WORDS = ('abc',)\n"
                      "def main(argv, stdin):\n"
                      "    print(rotl32(WORDS[0], 3))\n    return 0\n", "ROTL32 字符串操作数")):
        bb, _f, _g = _pack_b1(bad)
        try:
            out = vm_interp.gwelu_os_gar(bb, _KEY, _SEED, argv=b"", stdin=b"\x05\x00\x00\x00")
            raise AssertionError("%s 未被拒（给了错值 %r）" % (why, out))
        except vm_interp.SaayaYamabuki:
            pass
    # ④ i16 字面量纪律不因新操作码松动
    over = "def main(argv, stdin):\n    print(rotl32(stdin[0], 65536))\n    return 0\n"
    try:
        _pack_b1(over)
        raise AssertionError("越界常量未被 i16 闸拦下")
    except vm_compiler.TaeHanazono:
        pass
    # ⑤ 内建误用：当值用 / 元数不对，都在编译期硬拒（绝不静默错译）
    for misuse in ("def main(argv, stdin):\n    f = rotl32\n    print(1)\n    return 0\n",
                   "def main(argv, stdin):\n    print(rotl32(stdin[0]))\n    return 0\n",
                   "def main(argv, stdin):\n    print(rotl32(stdin[0], 1, 2))\n    return 0\n"):
        try:
            _pack_b1(misuse)
            raise AssertionError("内建误用未被拒：%r" % misuse[:44])
        except vm_compiler.TaeHanazono:
            pass
    # 内建名绝不进产物：同一源码两次打包字节相同，且 blob 里找不到 "rotl32" 明文
    blob2, _f2b, _g2b = _pack_b1(_V5_KAT_SRC)
    assert blob2 == blob, "同一源码同 seed 的 blob 不稳定（I6）"
    assert b"rotl32" not in blob2 and b"ROTL32" not in blob2, "内建/操作码名泄漏进产物"


def case_assembler_coordinates():
    mapping = vm_isa.hayase_sou(_SEED)
    funcs = [(4, [("LOADK", 0, 5), ("JZ", 0, 3), ("LOADK", 1, 1), ("RET", 1)])]
    stream, table = vm_isa.shellin_burgundy(funcs, mapping)
    assert len(table) == 1 and table[0][0] == 0
    # 跳转目标越界（指向别的函数 / 流外）必须拒
    for bad in ((4, [("JMP", 9)]), (4, [("JZ", 0, 4)]), (4, [("JN", 0, 7)])):
        try:
            vm_isa.shellin_burgundy([bad], mapping)
            raise AssertionError("jump target %r accepted" % (bad,))
        except ValueError:
            pass
    # 操作数超宽必须拒（寄存器 u8 / 立即数 i16）
    try:
        vm_isa.shellin_burgundy([(4, [("LOADK", 300, 1)])], mapping)
        raise AssertionError("wide register accepted")
    except ValueError:
        pass


def case_chunk_plan():
    blob, mapping, funcs, _gt = _pack(_PROG_BIG)
    stream, table = vm_isa.shellin_burgundy(funcs, mapping)
    bounds, straddles = vm_isa.fumi(stream, mapping, vm_isa.CHUNK_SIZE, align=True)
    assert straddles == 0, "aligned plan must not straddle"
    assert sum(ln for _s, ln in bounds) == len(stream), "plan must cover the whole stream"
    assert bounds[0][0] == 0
    for i, (start, length) in enumerate(bounds):
        assert length <= vm_isa.CHUNK_SIZE, "chunk %d exceeds the size cap" % i
    starts = vm_isa._instr_starts(stream, mapping)
    assert all(b in starts for b, _l in bounds), "every chunk boundary is an instruction start"
    # 闸门档（定长小块）必须真的覆盖跨块取指路径
    _b13, s13 = vm_isa.fumi(stream, mapping, 13, align=False)
    assert s13 > 0, "fixed 13B plan must produce straddling instructions (gate coverage)"
    # 块小于最宽指令 → 规划无解，必须拒（也是规划循环的前进性前提）
    try:
        vm_isa.fumi(stream, mapping, 2, align=True)
        raise AssertionError("chunk smaller than the widest instruction accepted")
    except ValueError:
        pass


def case_compile_fail_closed():
    #  后字符串/bool/None/元组常量已入子集：本表只剩真子集外构造。
    # "s = 'hi'" / "x = True" 自起必须被**接受**（由 p3prime 闸门正向钉住）。
    out_of_subset = (
        "x = [1, 2]\n", "d = {'a': 1}\n", "import os\n", "def f(a=1):\n    return a\n",
        "try:\n    x = 1\nexcept Exception:\n    x = 2\n", "class C:\n    pass\n",
        "with open('f') as g:\n    pass\n",
        "y = {i for i in range(3)}\n", "w = [i for i in range(3)]\n",
        # ISA v3 备注：曾在此表的 "z = (lambda: 1)()" 移出——CALL 0 参 +
        # MAKE_FUNCTION+LOAD_CONST(code) 均可翻译（无参 lambda 即调即弃，行为等价，
        # 实测复核）；带 defaults/closure 的 lambda 仍被拒。
        #  备注：曾在此表的 "v = a if b else c" 移出——3.12.10 对"条件表达式为模块
        # 末语句"不发 JUMP_FORWARD（两分支各自落 RETURN_CONST），编译器可正确翻译
        # （实测复核）；非末语句位置仍因 JUMP_FORWARD 被拒，fail-closed 边界不破。
        "u = obj.attr\n", "t = f(1, 2, 3, 4, 5, 6, 7, 8, 9)\n",
        #  备注：曾在此表的 "m = 'a' * 3" 与 "n = 'abc'[0]" 移出——CPython 常量折叠
        # 把两者折成单个 str 常量（编译器根本见不到 BINARY_OP/BINARY_SUBSCR），
        # 接受是正确翻译（实测复核）；运行期下标仍受 GETITEM 纪律约束。
        "q = ('a\"b\\'c',)\n",                             # 元组元素双引号并存（repr 子集外）
        "big = 300000\n",                                  # 超 i16 常量
    )
    for snippet in out_of_subset:
        try:
            vm_compiler.yamagami_karuta(compile(snippet, "<gate>", "exec"))
        except vm_compiler.TaeHanazono:
            continue
        except Exception as exc:  # noqa: BLE002
            raise AssertionError("wrong error for %r: %r" % (snippet, exc))
        raise AssertionError("out-of-subset source accepted: %r" % snippet)


def _tuple_window_audit(source, label):
    """编译 source，逐条 TUPLE 检查读窗不变量。

    返回 (故障列表, TUPLE 条数, 走搬运批的条数)——后两项用于反空转：夹具若意外不再触发
    暂存路径，闸门就会假绿，故把"确实踩到了"也钉成断言。"""
    faults, tuples, staged = [], 0, 0
    funcs, _g, _s = vm_compiler.yamagami_karuta(compile(source, label, "exec"))
    for fid, (nregs, ir) in enumerate(funcs):
        for i, ins in enumerate(ir):
            if ins[0] != "TUPLE":
                continue
            tuples += 1
            d, base, n = ins[1], ins[2], ins[3]
            where = "%s fid%d ir[%d] %r" % (label, fid, i, ins)
            if base + n > nregs:
                faults.append("%s 窗口越帧（base+n=%d > nregs=%d）"
                              % (where, base + n, nregs))
            if base <= d < base + n:
                faults.append("%s 目标 d=%d 落在读窗 [%d,%d) 内" % (where, d, base, base + n))
            # 搬运批 = 紧邻该 TUPLE 之前、dst 落在窗口内的连续 MOVE 段。搬运必须与源不重合：
            # 重合即成对互覆（MOVE(3,4);MOVE(4,3) 让 (1,2) 静默变 (2,2)）
            batch = 0
            for k in range(i - 1, -1, -1):
                if ir[k][0] != "MOVE" or not (base <= ir[k][1] < base + n):
                    break
                dst, src = ir[k][1], ir[k][2]
                batch += 1
                if src != dst and base <= src < base + n:
                    faults.append("%s 搬运 MOVE(%d,%d) 的源落在窗口内" % (where, dst, src))
            staged += 1 if batch else 0
    return faults, tuples, staged


def case_tuple_window_in_frame():
    """TUPLE 读窗三条不变量：不越帧、目标不在窗内、搬运窗不与自己的源重合。

    解释器与 Rust 端都按 `r[base:base+n]` 正序读窗（vm_interp 的 TUPLE / vm.rs 的 OP_TUPLE），
    所以"暂存段连不连续"是编译器单方面的责任，本闸门就是那道齿。覆盖面 = 既有目标源码
    T1..T8（真实形状，逐字副本）+ 三条最小触发形态（各自钉死一个缺陷）。
    """
    faults, tuples, staged = [], 0, 0
    for label, src in _R10_3_TARGETS + _SCATTER_FIXTURES:
        f, t, s = _tuple_window_audit(src, label)
        faults += f
        tuples += t
        staged += s
    assert tuples > 0 and staged > 0, \
        "空转：tuples=%d staged=%d（夹具不再触发 TUPLE/搬运路径，本闸门失效）" % (tuples, staged)
    assert not faults, "TUPLE 读窗故障 %d 条：\n  %s" % (len(faults), "\n  ".join(faults))


def case_blob_structure_refused():
    blob, _m, _f, _g = _pack(_PROG_FIB)
    mao = _materials()
    vm_blob.shirayuki_tomoe(blob, mao)          # baseline must parse
    bad = bytearray(blob)
    bad[len(blob) - 1] ^= 0xFF                  # ct 末字节翻转 → 流 MAC 拒
    try:
        vm_blob.shirayuki_tomoe(bytes(bad), mao)
        raise AssertionError("tampered ct accepted")
    except vm_blob.RanMitake:
        pass
    try:                                        # 错容器密钥 → 派生密钥不同 → MAC 拒
        vm_blob.shirayuki_tomoe(blob, _materials(bytes(range(2, 34))))
        raise AssertionError("wrong container key accepted")
    except vm_blob.RanMitake:
        pass
    for cut in (0, 8, 16, 24, 28):              # 头字段篡改（版本/保留位/几何）
        mutated = bytearray(blob)
        mutated[cut] ^= 0x01
        try:
            vm_blob.shirayuki_tomoe(bytes(mutated), mao)
            raise AssertionError("header mutation at %d accepted" % cut)
        except vm_blob.RanMitake:
            pass
    try:
        vm_blob.shirayuki_tomoe(b"VMB1" + bytes(60), mao)
        raise AssertionError("short header accepted")
    except vm_blob.RanMitake:
        pass
    # 元数据块翻转 → MAC 先拒（元数据也在密文里，不是明文可改的表）
    mbad = bytearray(blob)
    mbad[64] ^= 0xFF
    try:
        vm_blob.shirayuki_tomoe(bytes(mbad), mao)
        raise AssertionError("metadata byte flip accepted")
    except vm_blob.RanMitake:
        pass


# blob 头字段偏移表（与 vm_blob._HDR_FMT 同序，改格式必须同时改这里）
_HDR_OFF = {
    "magic": (0, 4), "fmt_ver": (4, 2), "isa_ver": (6, 2), "pm_ver": (8, 2),
    "op_count": (10, 2), "chunk_size": (12, 4), "nchunks": (16, 4), "nmeta": (20, 4),
    "nslots": (24, 2), "entry_fid": (26, 2), "align": (28, 1), "flags": (29, 1),
    "reserved": (30, 2),
}


def _rehead(blob: bytes, mao: dict) -> bytes:
    """把头（前 32 B）之上的流 MAC 重算回去——把**字段闸**从 **MAC 闸**里分离出来单独钉。

    口径：持容器密钥的敌手（既有"产物内含 seed"模型）改完字段可以自己补 MAC，
    此时只剩字段校验挡路。不重算 MAC 的用例只会反复测到同一道闸。"""
    head, ct = blob[:32], blob[64:]
    mac = hashlib.blake2s(head + ct, key=mao["mac_key"]).digest()
    return head + mac + ct


def _mutate(blob: bytes, field: str, value: int) -> bytes:
    off, width = _HDR_OFF[field]
    out = bytearray(blob)
    out[off:off + width] = int(value).to_bytes(width, "little")
    return bytes(out)


def _plain_of(blob: bytes, mao: dict) -> bytes:
    """元数据段明文（逐槽解密串接）——只为定位篡改偏移，不参与断言口径。"""
    info = vm_blob.shirayuki_tomoe(blob, mao)
    return b"".join(vm_blob.fuwa_minato(info, i, mao) for i in range(info["nmeta"]))


def _meta_layout(raw: bytes) -> dict:
    """元数据明文的字段偏移（与 vm_blob._serialize_meta 同序，只用于定位篡改点）。"""
    off = 0
    nfuncs = struct.unpack_from("<H", raw, off)[0]; off += 2
    gcount_off = off + 6 * nfuncs
    ng = struct.unpack_from("<H", raw, gcount_off)[0]
    gtab = gcount_off + 2
    scount_off = gtab + 3 * ng
    ns = struct.unpack_from("<H", raw, scount_off)[0]
    p = scount_off + 2
    stab = p
    for _ in range(ns):
        p += 2 + struct.unpack_from("<H", raw, p)[0]
    return {"nfuncs": nfuncs, "gtab": gtab, "stab": stab, "entry_off": p,
            "used_cnt_off": p + 2}


def _reseal_meta(blob: bytes, mao: dict, write) -> bytes:
    """解密元数据槽 → 同长改写 → 重加密落回原物理槽 → 重算流 MAC（fmt_ver=2 腿）。

    口径同 `_rehead`：这些闸（几何闭合 / gtable fid / 字符串项上界）只有在
    **MAC 自洽**的 blob 上才会被走到，所以必须持钥重封装才测得到它们本身
。"""
    info = vm_blob.shirayuki_tomoe(blob, mao)
    assert info["fmt_ver"] == 2, "重封装路径只钉 fmt2（fmt3 还要重算 PSIV tag）"
    cs = info["chunk_size"]
    raw = bytearray()
    for i in range(info["nmeta"]):
        raw += vm_blob.fuwa_minato(info, i, mao)
    patched = bytearray(write(raw, info))
    assert len(patched) == len(raw), "篡改必须同长，否则测的是截断而不是字段闸"
    ct = bytearray(info["ct"])
    for i in range(info["nmeta"]):
        seg = bytes(patched[i * cs:(i + 1) * cs])
        phys = info["place"][i]
        ct[phys * cs:phys * cs + cs] = chacha20.hanabatake_chaika(
            mao["chunk_key"], mao["nonce"](i), seg)
    out = bytearray(blob[:64]) + ct
    return _rehead(bytes(out), mao)


def _expect_ranmitake(fn, why: str) -> None:
    try:
        fn()
    except vm_blob.RanMitake as exc:
        assert why in str(exc), "%s 被拒的原因不成话：%r" % (why, str(exc)[:140])
        return
    raise AssertionError("%s accepted (MAC resealed)" % why)


def _rust_const(src: str, name: str) -> int:
    m = re.search(r"const %s: [A-Za-z0-9_<>]+ = ([0-9_]+);" % name, src)
    assert m, "vm.rs: const %s not found" % name
    return int(m.group(1).replace("_", ""))


def _rust_operand(src: str, name: str) -> int:
    m = re.search(r"%s != (\d+)" % name, src)
    assert m, "vm.rs: literal compare for %s not found" % name
    return int(m.group(1))


# 装载闸的 Rust 腿静态对镜钉：这些字段无法经既有 native 通道构造（改一个字段就要
# 重算 MAC，而 MAC 密钥只在持容器密钥的构建侧——native 测试拿到的是成品 exe，
# 没有再打包的入口），故按"源码字面 + 套件"双钉。清单口径见
# layout.json > vm > load_validation_parity。
_RUST_PINS = (
    ("chunk size cap", "cs > MAX_CHUNK"),
    ("zero chunk count", "nchunks == 0"),
    ("resident slots", "nslots != RESIDENT_SLOTS"),
    ("meta chunk cap", "nmeta > nchunks"),
    ("geometry closure", "nmeta + ir_used.len() != nchunks"),
    ("ir_used upper bound", "u > cs"),
    ("func start inside IR", "start >= ir_used.len() * cs"),
    ("string entry bound", "slen > MAX_CHUNK * 64"),
    ("global func fid bound", "fid >= nfuncs"),
    ("bounded metadata read", "self.off + n > self.buf.len()"),
    ("checked operand read", "fn melissa_kinrenka"),
    ("checked operand write", "fn genzuki_tojiro"),
    # 早期轮次+C（ISA v5）：两枚新码必须挂在**算术组**里（挂到别的组就是分派表与注册表
    # 不同步，兜底 E-98 会把合法载荷打死），且负数域走一条自己的桶码。
    # 早期轮次（ISA v6）：HSTEP 同组同判据；三条 ARX/XOR/ROTL 变体各自从 pins 取选择轴。
    ("v5 xor in arithmetic group", "OP_XOR =>"),
    ("v5 rotl in arithmetic group", "OP_ROTL32 =>"),
    ("v6 hstep in arithmetic group", "OP_HSTEP =>"),
    ("v5 logic ops registered", "OP_XOR, OP_ROTL32, OP_HSTEP]"),
    ("v5 negative domain bucket", "E-116"),
    ("v6 hstep variant axis", "crate::pins::V_HSTEP"),
    ("v6 chain profile stream labels", 'L_CHAIN_CFG: &[u8] = b"i18"'),
    ("v6 chain constant stream label", 'L_CHAIN_K: &[u8] = b"i19"'),
    ("v6 chain mask stream label", 'L_CHAIN_MASK: &[u8] = b"i20"'),
    ("v6 chain pad byte label", 'L_CHAIN_PAD: &[u8] = b"i21"'),
)


def _rust_code(src: str) -> str:
    """去掉 Rust 注释后的源码——注释里会照抄旧写法（"旧写法 `regs[ops[i]]`"），
    不剥离就把"纪律说明"当成"违规现场"。"""
    out = []
    for line in src.splitlines():
        cut = line.find("//")
        out.append(line if cut < 0 else line[:cut])
    return "\n".join(out)


def case_load_validation_parity():
    """：双端装载校验单一来源化。

    1) 头字段逐条篡改（重算 MAC 后）→ Python 权威端必须按**字段闸**拒（断言原因串，
       否则测到的是 MAC）；
    2) **元数据侧**本轮新增的三条闸（几何闭合 / gtable Func fid / 字符串项上界）经
       持钥重封装后逐条钉住——它们只有在头与流 MAC 自洽时才会被走到；
    3) 同一张表的常量/宽度与 vm.rs 逐值对镜（单源 = vm_isa / vm_blob，Rust 是镜像）；
    4) vm.rs 侧不可经 native 通道构造的字段，按 `_RUST_PINS` 字面钉住，并同时钉
       "热路径不再有 `regs[ops[` 直接下标"（Rust 侧的机械化）。
    """
    blob, _mapping, _funcs, _gt = _pack(_PROG_FIB)
    mao = _materials()
    vm_blob.shirayuki_tomoe(blob, mao)            # 基线必须可解
    nchunks = int.from_bytes(blob[16:20], "little")
    refused = (
        ("fmt_ver", 4, "unsupported"),
        ("isa_ver", 2, "version mismatch"),
        ("pm_ver", 9, "version mismatch"),
        ("op_count", 26, "opcode count"),
        ("nslots", 3, "resident slot"),
        ("chunk_size", vm_blob.MAX_CHUNK + 1, "chunk_size out of range"),
        ("chunk_size", 0, "chunk_size out of range"),
        ("nchunks", 0, "nchunks"),
        ("nmeta", nchunks + 1, "nmeta exceeds"),
        ("reserved", 1, "reserved"),
        ("align", 2, "aligned"),
    )
    for field, value, why in refused:
        mutated = _rehead(_mutate(blob, field, value), mao)
        try:
            vm_blob.shirayuki_tomoe(mutated, mao)
            raise AssertionError("%s=%r accepted (MAC recomputed)" % (field, value))
        except vm_blob.RanMitake as exc:
            assert why in str(exc), "%s=%r rejected for the wrong reason: %r" % (
                field, value, str(exc)[:120])
    # 513 这一格是本轮新增的那半边：Python 端过去放到 0xFFFF，Rust 端一直拒到 512
    assert vm_blob.MAX_CHUNK == 512, "chunk 上界被改动，必须同步 vm.rs MAX_CHUNK"

    # / 新增的三条**元数据侧**闸：持钥重封装（MAC 自洽）后逐条钉住，
    # 与 vm.rs 的 read_globals/read_strings/几何闭合同式——只有清单没有负例
    # 就等于没测。
    plain = _plain_of(blob, mao)
    lay = _meta_layout(plain)
    assert lay["nfuncs"] >= 1 and lay["stab"] > lay["gtab"], "夹具元数据布局读歪了"

    def _drop_used_count(raw, info):
        out = bytearray(raw)
        n = struct.unpack_from("<H", raw, lay["used_cnt_off"])[0]
        assert n >= 2, "ir_used 计数太小，减一测不出闭合闸"
        out[lay["used_cnt_off"]:lay["used_cnt_off"] + 2] = struct.pack("<H", n - 1)
        return out

    def _bad_gfunc(raw, info):
        out = bytearray(raw)
        out[lay["gtab"]:lay["gtab"] + 3] = struct.pack("<BH", 1, lay["nfuncs"] + 7)
        return out

    for write, why in (
        (_drop_used_count, "nmeta + ir chunk count"),
        (_bad_gfunc, "global Func fid out of range"),
    ):
        resealed = _reseal_meta(blob, mao, write)
        vm_blob.shirayuki_tomoe(resealed, mao)      # 头与 MAC 自洽，必须走到元数据
        _expect_ranmitake(
            lambda w=resealed: vm_blob.meta_unpack(
                vm_blob.shirayuki_tomoe(w, mao), mao), why)

    # 字符串项上界必须换一条**常量池非空**的载荷：_PROG_FIB 池为空时 stab 正好落在
    # entry_fid 字段上，改它测的是" 单源比对"那条闸而不是字符串上界（实测踩过，

    sblob, _sm, _sf, _sg = _pack('msg = "hello vm gate"\nprint(msg)\n')
    splain = _plain_of(sblob, mao)
    slay = _meta_layout(splain)
    assert struct.unpack_from("<H", splain, slay["stab"])[0] > 0, "字符串夹具没进池"

    def _huge_string(raw, info):
        out = bytearray(raw)
        out[slay["stab"]:slay["stab"] + 2] = struct.pack("<H", 0xFFFF)
        return out

    resealed = _reseal_meta(sblob, mao, _huge_string)
    _expect_ranmitake(
        lambda w=resealed: vm_blob.meta_unpack(vm_blob.shirayuki_tomoe(w, mao), mao),
        "string entry too long")

    vm_src = (_ROOT / "d_side" / "builder" / "vm.rs").read_text(encoding="utf-8")
    # (2) 常量/宽度对镜：Rust 是 Python 单源的镜像，任何一侧漂了就红
    assert _rust_const(vm_src, "MAX_CHUNK") == vm_blob.MAX_CHUNK, "MAX_CHUNK 双端不一致"
    assert _rust_const(vm_src, "HEADER_LEN") == vm_blob.HEADER_LEN, "HEADER_LEN 双端不一致"
    assert _rust_const(vm_src, "N_LOGICAL") == len(vm_isa.LOGICAL_OPS), "操作码数不一致"
    assert _rust_const(vm_src, "RESIDENT_SLOTS") == vm_isa.RESIDENT_SLOTS, "槽数不一致"
    assert _rust_const(vm_src, "STEP_BUDGET") == vm_interp.DEFAULT_STEP_BUDGET, "预算不一致"
    assert _rust_operand(vm_src, "isa_ver") == vm_isa.ISA_VER, "isa_ver 双端不一致"
    assert _rust_operand(vm_src, "pm_ver") == vm_isa.PHYSMAP_VER, "physmap_ver 双端不一致"
    assert _rust_const(vm_src, "U32_RANGE") == vm_isa.U32, "ROTL32 位宽双端不一致"
    # 早期轮次 Phase 2：窗上限不再是双端字面常量，而是**逐格注入**（pins::IFACE_AP/SP）。
    # 原来那两条 source-literal 齿（vm.rs 的 INPUT_WINDOW == vm_isa.INPUT_WINDOW）随
    # 常量的消失一起作废——留着一个恒假的等式比没有更糟。
    # 现在钉的是"VM 只从 pins 读上限"这一事实，等值性由 native 接口腿端到端钉。
    assert "crate::pins::IFACE_AP" in vm_src and "crate::pins::IFACE_SP" in vm_src, \
        "vm.rs 不再从 pins 读窗上限——逐格化被绕过"
    assert "INPUT_WINDOW" not in _rust_code(vm_src), \
        "vm.rs 里又出现写死的窗上限常量（早期轮次 Phase 2 回潮）"
    boot_src = (_ROOT / "d_side" / "builder" / "boot.rs").read_text(encoding="utf-8")
    for axis in ("IFACE_AP", "IFACE_SP", "IFACE_ARG_MAX", "IFACE_JOIN", "IFACE_ARGV0",
                 "IFACE_KEYSTRIP", "IFACE_REJECT_EXIT"):
        assert ("pins::%s" % axis) in boot_src, "boot.rs 未消费 %s——那条不变量没有逐格化" % axis
    layout = json.loads((_ROOT / "d_side" / "layout.json").read_text(encoding="utf-8"))
    assert layout["vm"]["limits"]["max_regs"] == vm_compiler._STG_BASE, \
        "max_regs 登记与帧硬闸不符（帧 = 局部 + 临时，结构上 ≤ _STG_BASE）"
    m = re.search(r"const OP_WIDTHS: \[usize; N_LOGICAL\] =\s*\[([0-9,\s]+)\];", vm_src)
    assert m, "vm.rs OP_WIDTHS 表没找到，宽度单源钉失效"
    rust_widths = [int(x) for x in m.group(1).replace("\n", " ").split(",") if x.strip()]
    py_widths = [sum(w) for _name, w in vm_isa.LOGICAL_OPS]
    assert rust_widths == py_widths, "操作数字节宽双端分叉：%r != %r" % (rust_widths, py_widths)

    # 早期轮次 链剖面的双端同式：三条流的**长度与域标签**都必须一致。这两类值不进任何
    # MAC/容器，一旦两侧各读各的，症状不是"拒绝"而是"两侧算出不同的链"——那是本项目
    # 最贵的一类分叉，所以按字面钉死，而不是靠等价用例碰巧覆盖。
    ops_src = (_ROOT / "d_side" / "builder" / "vm_ops.rs").read_text(encoding="utf-8")
    assert _rust_const(ops_src, "CHAIN_CFG_LEN") == vm_isa.CHAIN_CFG_BYTES, "配置流长度分叉"
    assert _rust_const(ops_src, "CHAIN_K_LEN") == vm_isa.CHAIN_K_BYTES, "常量/掩码流长度分叉"
    assert _rust_const(ops_src, "CHAIN_WORDS") == vm_isa._CHAIN_WORDS, "常量枚数分叉"
    assert _rust_const(ops_src, "U32_RANGE_I") == vm_isa.U32, "vm_ops 的 2^32 模数分叉"
    for name, want in (("L_CHAIN_CFG", vm_isa.CHAIN_CFG_LABEL),
                       ("L_CHAIN_K", vm_isa.CHAIN_K_LABEL),
                       ("L_CHAIN_MASK", vm_isa.CHAIN_MASK_LABEL),
                       ("L_CHAIN_PAD", vm_isa.CHAIN_PAD_LABEL)):
        m = re.search(r'const %s: &\[u8\] = b"([^"]*)";' % name, vm_src)
        assert m, "vm.rs 缺 %s 定义" % name
        assert m.group(1).encode("ascii") == want, "%s 域标签双端分叉" % name

    # (3) Rust 腿静态对镜 + 热路径无直接下标
    for label, literal in _RUST_PINS:
        assert literal in vm_src, "vm.rs 缺 %s 钉：找不到的字面量 %r" % (label, literal)
    assert "regs[ops[" not in _rust_code(vm_src), \
        "vm.rs 热路径又出现裸操作数下标（W13 Rust 侧回潮，必须走 checked 出口）"

    # (4) layout.json 的清单本身也要钉：每行都必须给出双端出处，不许留空
    layout = json.loads((_ROOT / "d_side" / "layout.json").read_text(encoding="utf-8"))
    parity = layout["vm"]["load_validation_parity"]
    assert len(parity["same_formula"]) >= 20, "同式清单条目数缩水：%d" % len(
        parity["same_formula"])
    for row in parity["same_formula"]:
        assert row.get("python") and row.get("rust"), "同式清单缺双端出处：%r" % (row,)
    for row in parity["single_sided"]:
        assert row.get("side") and row.get("clearance"), "单侧项缺归属/清零目标：%r" % (row,)


def case_semantic_equivalence():
    work = _ROOT / ".tmp" / "gate-vm-sem"
    work.mkdir(parents=True, exist_ok=True)
    for i, (label, source) in enumerate(_PROGRAMS):
        p = work / ("prog_%d.py" % i)          # 用序号命名：hash() 逐进程随机，不可作确定性路径
        p.write_text(source, encoding="utf-8")
        ref = subprocess.run([sys.executable, str(p)], capture_output=True, text=True,
                             encoding="utf-8", errors="replace", timeout=300, shell=False)
        assert ref.returncode == 0, "%s: reference run failed: %s" % (label, ref.stderr[:200])
        blob, _m, _f, _g = _pack(source)
        got = vm_interp.gwelu_os_gar(blob, _KEY, _SEED).decode("utf-8")
        assert got == ref.stdout, "%s: vm stdout diverges\n got %r\nwant %r" % (
            label, got[:200], ref.stdout[:200])
        p.unlink()


def case_determinism():
    b1, _m, _f, _g = _pack(_PROG_TRUE)
    b2, _m, _f, _g = _pack(_PROG_TRUE)
    assert b1 == b2, "same seed must produce a byte-identical blob (I6)"
    b3, _m, _f, _g = _pack(_PROG_TRUE, seed=bytes(range(31)) + bytes([0x77]))
    assert b3 != b1, "a different seed must change the blob"
    # 块粒度进产物形态：换 chunk 尺寸必须换 blob
    b4, _m, _f, _g = _pack(_PROG_TRUE, chunk=512)
    assert b4 != b1, "chunk size is part of the artifact shape"


def case_no_key_material_in_blob():
    """探针形态把 master_key/nonce 明文写进 blob——正式实现必须在任何位置都不出现它们。"""
    blob, _m, _f, _g = _pack(_PROG_FIB)
    mao = _materials()
    secrets = (mao["root"], mao["chunk_key"], mao["mac_key"])
    for name, sec in zip(("root", "chunk_key", "mac_key"), secrets):
        assert sec not in blob, "%s appears in the blob" % name
        # 逐块 nonce 也不得成串出现（最多 8 字节的部分重合，整 12 字节命中即流复用风险）
        for idx in range(4):
            nonce = mao["nonce"](idx)
            assert nonce not in blob, "chunk nonce %d appears in the blob" % idx
    # 元数据明文（函数表/入口号/池计数）不得裸奔：blob 里出现 30 条 IR 明文的
    # 任意 16 字节连续片段即视为泄漏（正式实现里 IR 全在密文段）
    stream, _t = vm_isa.shellin_burgundy(
        vm_compiler.yamagami_karuta(compile(_PROG_FIB, "<x>", "exec"))[0],
        vm_isa.hayase_sou(_SEED))
    assert stream not in blob
    for i in range(0, max(1, len(stream) - 16), 16):
        assert stream[i:i + 16] not in blob, "IR plaintext visible at blob offset %d" % i


def case_chacha_container_parity():
    """容器层与 VM 层共用同一 ChaCha20 权威实现：构建侧解回运行侧形态（的 Python 腿）。"""
    blob, _m, _f, _g = _pack(_PROG_FIB)
    nonce = keys.akabane_youko(_SEED, bytes(range(32)))
    enc, _mac = keys.kanae(_SEED, nonce, keys.ryushen(_SEED))
    sealed = chacha20.hanabatake_chaika(enc, nonce, blob)
    assert chacha20.hanabatake_chaika(enc, nonce, sealed) == blob
    # 逐块 nonce 互不相同（：同 key 下流不复用）
    mao = _materials()
    seen = set()
    for idx in range(200):
        n = mao["nonce"](idx)
        assert len(n) == 12 and n not in seen
        seen.add(n)


_PROG_STR = (
    "ANCHORS = ('anchor-kiwi-739', 'anchor-mango-251', 'anchor-cedar-904')\n"
    "FLAG = True\n"
    "def fib(n):\n    a = 0\n    b = 1\n    i = 0\n"
    "    while i < n:\n        t = a + b\n        a = b\n        b = t\n        i = i + 1\n"
    "    return a\n"
    "print('r10 target ok', fib(24), True, False, None)\n"
    "print(ANCHORS)\n"
    "print(ANCHORS[1], ('only',))\n"
    "msg = 'x=' + 'y'\n"
    "print(msg, msg == 'x=y')\n"
)


def case_p3prime_semantics():
    """/ 正向钉（ISA v2）：字符串/bool/None/元组常量、元组下标、多参 print、
    模块级数据全局、str 等价比较——三方等价（CPython 直跑 == VM 权威端，逐字节）。

    另含 300 条字符串池用例：LOADS 满 u16 的 KAT（设计稿坑单 #1 的 Rust 低字节
    截断已修，池超 255 条即双端分叉——本闸门防回退）。"""
    work = _ROOT / ".tmp" / "gate-vm-sem"
    work.mkdir(parents=True, exist_ok=True)
    for label, source in (("p3prime", _PROG_STR),):
        p = work / ("prog_%s.py" % label)
        p.write_text(source, encoding="utf-8")
        ref = subprocess.run([sys.executable, str(p)], capture_output=True, text=True,
                             encoding="utf-8", errors="replace", timeout=300, shell=False)
        assert ref.returncode == 0, "%s: reference run failed: %s" % (label, ref.stderr[:200])
        blob, _m, _f, _g = _pack(source)
        got = vm_interp.gwelu_os_gar(blob, _KEY, _SEED).decode("utf-8")
        assert got == ref.stdout, "%s: vm stdout diverges\n got %r\nwant %r" % (
            label, got[:300], ref.stdout[:300])
        p.unlink()
    # >255 条字符串池：LOADS 满 u16 的 KAT（设计稿坑单 #1 的 Rust 低字节截断已修，
    # 池超 255 条即双端分叉——本闸门防回退）。池与全局表是两张表：池 u16、全局表 u8
    # （LOADG/STOREG 索引宽）——引用不经全局绑定，用 300 个 print 直载池条目。
    big = "".join("print('pool-%03d-x')\n" % i for i in range(300))
    big += "print('pool-000-x', 'pool-299-x')\n"
    p2 = work / "prog_pool300.py"
    p2.write_text(big, encoding="utf-8")
    ref2 = subprocess.run([sys.executable, str(p2)], capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=300, shell=False)
    assert ref2.returncode == 0, "pool reference failed: %s" % ref2.stderr[:200]
    blob2, _m2, _f2, _g2 = _pack(big)
    got2 = vm_interp.gwelu_os_gar(blob2, _KEY, _SEED).decode("utf-8")
    assert got2 == ref2.stdout, "pool stdout diverges\n got %r\nwant %r" % (
        got2[:300], ref2.stdout[:300])
    p2.unlink()
    # 全局表 u8 上限的显式 fail-closed（LOADG/STOREG 索引宽，扩宽属 ISA 变更）
    too_many = "".join("G%d = %d\n" % (i, i) for i in range(300)) + "print(G0)\n"
    try:
        _pack(too_many)
        raise AssertionError("globals beyond u8 accepted")
    except vm_compiler.TaeHanazono:
        pass


def case_psiv_v3_gates():
    """PSIV 容器（fmt_ver=3）闸门：跨实现 KAT 锚定的块级 AEAD 路径。

    - v3 与 v2 语义等价（同程序同 seed，stdout 逐字节一致）；
    - 槽开销 = 每块 +16 B tag；槽内定向 tag 篡改 / 块间 tag 重排 / 截断一律拒；
    - 容器 MAC 覆盖 tag 区（tag 在 MAC 之下，先拒于容器层）；
    - v3 同 seed 两次打包逐字节一致；
    - v2 路径零回归（fmt_ver 字段仍为 2）。
    实现正确性另有一条**历史**锚：曾与官方 CC0 参考实现的 10 组向量逐条对照通过
    （对照脚本 `psiv_kat_check.py` 从未入版控，本套件不复跑它；仓内可复跑的是上面的
    双端互证与拒绝用例）。
    """
    work = _ROOT / ".tmp" / "gate-vm-sem"
    work.mkdir(parents=True, exist_ok=True)
    source = _PROG_STR
    p = work / "prog_v3.py"
    p.write_text(source, encoding="utf-8")
    ref = subprocess.run([sys.executable, str(p)], capture_output=True, text=True,
                         encoding="utf-8", errors="replace", timeout=300, shell=False)
    assert ref.returncode == 0, "reference failed: %s" % ref.stderr[:200]

    funcs, gtable, strings = vm_compiler.yamagami_karuta(compile(source, "<v3>", "exec"))
    mapping = vm_isa.hayase_sou(_SEED)
    mao = _materials()
    b2 = vm_blob.luis_cammy(funcs, mapping, gtable, mao, strings=strings)
    b3 = vm_blob.luis_cammy(funcs, mapping, gtable, mao, strings=strings, aead=True)
    info2 = vm_blob.shirayuki_tomoe(b2, mao)
    info3 = vm_blob.shirayuki_tomoe(b3, mao)
    assert info2["fmt_ver"] == 2 and info3["fmt_ver"] == 3, "fmt_ver 字段错"
    assert len(b3) - len(b2) == info3["nchunks"] * 16, "v3 槽开销 != +16B/块"
    got2 = vm_interp.gwelu_os_gar(b2, _KEY, _SEED).decode()
    got3 = vm_interp.gwelu_os_gar(b3, _KEY, _SEED).decode()
    assert got3 == got2 == ref.stdout, "v3/v2/CPython 三方不一致"
    p.unlink()

    # （v3）：同 seed 两次打包逐字节一致
    b3b = vm_blob.luis_cammy(funcs, mapping, gtable, mao, strings=strings, aead=True)
    assert b3 == b3b, "v3 打包不确定"

    # 负例（直接构造 blob 层，绕过 CLI）：ct 区起点 = 头 32B + 容器 MAC 32B
    ct0 = 64
    slot = 256 + 16

    def reseal(buf: bytearray) -> bytearray:
        #  后容器 MAC 覆盖 头(32B)‖ct——MAC 字段本身不入输入
        buf[32:64] = hashlib.blake2s(bytes(buf[:32]) + bytes(buf[ct0:]),
                                     key=mao["mac_key"]).digest()
        return buf

    # ① 容器 MAC 覆盖 tag 区：末槽 tag 翻转在容器层即拒
    bad = bytearray(b3)
    bad[-1] ^= 0xFF
    try:
        vm_blob.shirayuki_tomoe(bytes(bad), mao)
        raise AssertionError("container MAC missed a tag flip")
    except vm_blob.RanMitake:
        pass
    # ② 定向篡改物理槽 0 的 tag（重封容器 MAC 绕过容器层）→ 被 PM 映射到该槽的
    #    逻辑块必须在 PSIV 层拒（perm=True 下逻辑 0 不一定落物理 0——按 place 反查）
    bad = bytearray(b3)
    bad[ct0 + 256] ^= 0xFF
    reseal(bad)
    info = vm_blob.shirayuki_tomoe(bytes(bad), mao)
    target = info["place"].index(0)
    try:
        vm_blob.fuwa_minato(info, target, mao)
        raise AssertionError("PSIV tag tamper accepted (logical %d)" % target)
    except vm_blob.RanMitake:
        pass
    # ③ 块间 tag 重排（重封容器 MAC）→ 每个涉事块在 PSIV 层拒
    bad = bytearray(b3)
    t0 = bytes(bad[ct0 + 256:ct0 + slot])
    t1 = bytes(bad[ct0 + slot + 256:ct0 + slot + slot])
    bad[ct0 + 256:ct0 + slot] = t1
    bad[ct0 + slot + 256:ct0 + slot + slot] = t0
    reseal(bad)
    info = vm_blob.shirayuki_tomoe(bytes(bad), mao)
    rejected = 0
    for logical in range(info["nchunks"]):
        try:
            vm_blob.fuwa_minato(info, logical, mao)
        except vm_blob.RanMitake:
            rejected += 1
    assert rejected >= 2, "tag swap rejected %d/%d chunks" % (rejected, info["nchunks"])
    # ④ 截断
    try:
        vm_blob.shirayuki_tomoe(b3[:-16], mao)
        raise AssertionError("truncated v3 accepted")
    except vm_blob.RanMitake:
        pass


def case_cli_rejects_out_of_subset():
    """CLI 面：子集外载荷走"硬门失败、不写盘、rc=3"，且**不静默回落到 v1**。

     拍板的"不回落"必须有齿：同一份源码在**不带 `--vm`** 时照常构建成功（v1 面不受影响），
    带 `--vm` 时硬拒——若有人日后"好心"加隐式回落，本用例的后半段会当场红。
    （起字符串常量在子集内，夹具换列表字面量——容器构造仍在子集外。）
    """
    work = _ROOT / ".tmp" / "gate-vm-cli"
    work.mkdir(parents=True, exist_ok=True)
    bad = work / "bad.py"
    bad.write_text("vals = [1, 2]\nprint(vals)\n", encoding="utf-8")
    out = work / "bad.artifact.py"
    if out.exists():
        out.unlink()
    cmd = [sys.executable, "-m", "d_side", "build", "--source", str(bad),
           "--out", str(out), "--seed", "ab" * 32]
    r = subprocess.run(cmd + ["--vm"], capture_output=True, text=True, encoding="utf-8",
                       errors="replace", timeout=300, cwd=str(_ROOT), shell=False)
    assert r.returncode == 3, "rc=%d out=%r" % (r.returncode, (r.stdout + r.stderr)[-200:])
    assert not out.exists(), "rejected build still wrote an artifact"
    joined = r.stdout + r.stderr
    assert "HARD GATE FAILED" in joined and "subset" in joined.lower(), \
        "拒绝信息不成话：%r" % joined[-200:]
    assert "Traceback" not in joined, "子集外载荷把编译器异常裸抛给用户了"

    # 无静默回落：不带 --vm 时同一份源码必须照常出 v1 产物（且 fmt_ver 由 v1 路径承载）
    r2 = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                        errors="replace", timeout=300, cwd=str(_ROOT), shell=False)
    assert r2.returncode == 0, "v1 面被 --vm 的门连带打死：%r" % (r2.stderr[-200:],)
    assert out.is_file(), "v1 产物未写出"
    text = out.read_text(encoding="utf-8")
    assert _head_fmt_ver(text) == 1, "不带 --vm 却产出了 fmt_ver!=1 的产物（回落方向反了）"
    out.unlink()
    bad.unlink()


def _head_fmt_ver(artifact_text: str) -> int:
    """从产物文本取头字段 fmt_ver——复用构建管线的形状解析，不另写一份。"""
    return kanda_shoichi(artifact_text)["head"][0]


_EQ_OPAQUE_SRC = (
    "def f():\n    return 1\n"
    "def g():\n    return 2\n"
    "def main(argv, stdin):\n"
    "    print(f == g)\n"
    "    print(f == f)\n"
    "    return 0\n"
)


def case_eq_opaque_value_dualend():
    """函数全局 == 是身份语义：f==g 假、f==f 真。vm.rs eq_val 兜底臂曾把
    不透明值对（Func/It/Native）经 as_int 双 None 判等，与权威端结构比较相反
    ——同源码双端答案相反。本案钉编译路径 + 解释器腿；
    Rust 腿由 test_native_vm 的同源码 native 案对镜。"""
    ref = _b1_reference(_EQ_OPAQUE_SRC, (), b"")
    blob, _funcs, _gtable = _pack_b1(_EQ_OPAQUE_SRC)
    got = vm_interp.gwelu_os_gar(blob, _KEY, _SEED, argv=b"", stdin=b"")
    assert got == ref, "EQ 不透明值双端分叉：ref=%r vm=%r" % (ref, got)


def case_opcode_table_drift():
    """文档与代码的数字漂移守卫：ISA 操作码条数在四处表里必须一致，
    且模块 docstring 里**写出来的**那个数必须等于实测值。

    实测教训：docstring 曾长期写"逻辑操作码 23 个"，而 `LOGICAL_OPS`/`OP_KINDS`
    实际 32 条——文档比代码好看，且没有任何测试钉住任一侧。"""
    import re as _re

    counts = {
        "LOGICAL_OPS": len(vm_isa.LOGICAL_OPS),
        "OP_KINDS": len(vm_isa.OP_KINDS),
        "OP_WIDTHS": len(vm_isa.OP_WIDTHS),
        "_NAMES": len(vm_isa._NAMES),
    }
    assert len(set(counts.values())) == 1, "操作码表条数不一致：%s" % counts
    assert len(set(vm_isa._NAMES)) == counts["_NAMES"], "操作码名有重复"
    m = _re.search(r"逻辑操作码\s*(\d+)\s*个", vm_isa.__doc__ or "")
    assert m, "docstring 里没有操作码条数声明（本守卫要求它显式写出来）"
    assert int(m.group(1)) == counts["LOGICAL_OPS"], (
        "docstring 声明 %s 条，实测 %s 条" % (m.group(1), counts["LOGICAL_OPS"]))
    print("  [PASS] opcode tables agree (%d) and docstring matches" % counts["LOGICAL_OPS"])


def main() -> int:
    cases = (
        ("opcode_table_drift", case_opcode_table_drift),
        ("physmap_seed_derived", case_physmap),
        ("v5_logic_ops_kat", case_logic_ops_kat),
        ("bc_hardening_gates", case_bc_hardening_gates),
        ("chain_native_profile", case_chain_native_profile),
        ("chain_native_gates", case_chain_native_gates),
        ("absorb_window", case_absorb_window),
        ("iface_contract", case_iface_contract),
        ("assembler_coordinate_discipline", case_assembler_coordinates),
        ("chunk_plan_invariants", case_chunk_plan),
        ("compile_fail_closed_subset", case_compile_fail_closed),
        ("tuple_window_in_frame", case_tuple_window_in_frame),
        ("blob_structure_refused", case_blob_structure_refused),
        ("load_validation_parity", case_load_validation_parity),
        ("semantic_equivalence_three_way", case_semantic_equivalence),
        ("psiv_v3_gates", case_psiv_v3_gates),
        ("p3prime_semantics", case_p3prime_semantics),
        ("b1_input_primitives", case_input_primitives),
        ("build_determinism", case_determinism),
        ("no_key_material_in_blob", case_no_key_material_in_blob),
        ("container_vm_keystream_parity", case_chacha_container_parity),
        ("cli_rejects_out_of_subset", case_cli_rejects_out_of_subset),
        ("eq_opaque_value_dualend", case_eq_opaque_value_dualend),
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
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
