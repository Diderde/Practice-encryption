# Copyright (C) 2026 Diderde
# SPDX-License-Identifier: GPL-3.0-only
""" v2 的 native 扩围套件（慢档，自宿主运行器）：真实产物的 VM E2E + 可见量外部抓取。

覆盖（设计记录 / 工作书 …）：
- `v2_eight_topologies`：八个拓扑逐格 E2E，产物 stdout 与 CPython 逐字节一致；
- `v2_chunk_tamper_refused` / `v2_seed_tamper_refused`：RCDATA 载荷字节翻转、
  头内 seed 翻转 ⇒ 拒绝路径按既有顺序生效（MAC 先于解密），exit 3 且无输出；
- `v2_visible_quantity`：带探针齿的构建在"明文最可能在场的时点"暂停，由**另一个进程**
  用外部进程的同款手法（OpenProcess + VirtualQueryEx + ReadProcessMemory）抓取私有内存：
  v2 侧断言"不存在任何 marshal 明文窗口、不存在长于一个 chunk 的连续 IR 明文"，
  同时断言该进程**没有加载任何 python*.dll**（不嵌 CPython 的形态断言）；
  v1 同齿作阴性对照——marshal 头部（前 512 B）必须在场，否则上面的"0 命中"不说明任何事；
- `v2_build_determinism`：同 seed 两次完整构建逐字节一致（含 VM 层）。

与快档 `test_vm_gates.py` 的分工：那一半钉 Python 权威端与结构负例，这一半钉真实产物
（双路径的 Rust 腿就在这里——被测代码与出货代码同一份）。
"""
import ctypes
import hashlib
import json
import marshal
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT))

from d_side import codec  # noqa: E402
from d_side.builder import vm_compiler, vm_isa  # noqa: E402
from d_side.builder.native_build import azuchi_momo, kanda_shoichi  # noqa: E402

# 早期轮次（终端防护误删事件）：产物目录收拢进 .av-allow 白名单根（终端防护信任区按目录
# 排除；.tmp 下新生成的 exe 曾被静默清除——见对策文档 L 事件登记）
WORK = _ROOT / ".av-allow" / "native-vm-suite"
_KERNEL32 = ctypes.WinDLL("kernel32", use_last_error=True)
# 句柄必须按指针宽度返回：不设 restype 时 ctypes 默认 c_int，64 位句柄被截断——
# 表现为"抓取到 0 字节内存、模块快照为空"，而"needle 不在空转储里"会假绿。
# 阴性对照与 _MIN_DUMP 自检就是为了抓住这种"仪器自己坏了"的情形。
_KERNEL32.OpenProcess.restype = ctypes.c_void_p
_KERNEL32.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
_KERNEL32.CloseHandle.restype = ctypes.c_int
_KERNEL32.CloseHandle.argtypes = [ctypes.c_void_p]
_KERNEL32.VirtualQueryEx.restype = ctypes.c_size_t
_KERNEL32.VirtualQueryEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                                     ctypes.c_size_t]
_KERNEL32.ReadProcessMemory.restype = ctypes.c_int
_KERNEL32.ReadProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                                        ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
_KERNEL32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
_KERNEL32.CreateToolhelp32Snapshot.argtypes = [ctypes.c_uint32, ctypes.c_uint32]
_KERNEL32.Module32FirstW.restype = ctypes.c_int
_KERNEL32.Module32FirstW.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
_KERNEL32.Module32NextW.restype = ctypes.c_int
_KERNEL32.Module32NextW.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
_INVALID_HANDLE = ctypes.c_void_p(-1).value
_PROCESS_VM_READ = 0x0010
_PROCESS_QUERY_INFORMATION = 0x0400
_MEM_COMMIT = 0x1000
_MEM_PRIVATE = 0x20000
_MEM_IMAGE = 0x1000000
_PAGE_NOACCESS = 0x01
_PAGE_GUARD = 0x100
_READ_CHUNK = 256 * 1024
_MIN_DUMP = 256 * 1024   # 抓取量下限：一个 rustc 产物进程的私有内存远大于此

_PROG = (
    "ANCHORS = ('anchor-kiwi-739', 'anchor-mango-251', 'anchor-cedar-904')\n"
    "def fib(n):\n    a = 0\n    b = 1\n    i = 0\n"
    "    while i < n:\n        t = a + b\n        a = b\n        b = t\n        i = i + 1\n"
    "    return a\n"
    "def topup(n):\n    total = 0\n    for k in range(n):\n"
    "        total = total + fib(k) * k\n    return total\n"
    "print(fib(24))\nprint(topup(10))\nprint(fib(0))\n"
    "print('r10 target ok', True, ANCHORS)\nprint(ANCHORS[1], ('only',))\n"
)


def _seed(tail: int) -> bytes:
    return bytes(range(31)) + bytes([tail])


def _artifact(vm: bool = True, tail: int = 1, source: str = None, psiv: bool = False,
              external_key: bool = False) -> tuple:
    src = source or _PROG
    seed = _seed(tail)
    res = codec.octavio(src, "vmcase", seed, vm=vm, psiv=psiv, external_key=external_key)
    return res, seed


def _build(res, tag: str, pins_override=None, guards: bool = True) -> Path:
    # 终端防护软件对新建目录/刚落盘 exe 有拒访窗口（WinError 5，mkdir 与 exe 写入
    # 实测都会被拒）：八格连排 ≈15+ 个 exe 会在约 5 格后触发限流，拒访期十几秒起
    # （实测 5×2s 重试不够）。递增退避最长约 1 分钟，等窗口自己过去；逐文件信任
    # 跟不上重建（每次字节全变）。
    waits = (2.0, 4.0, 8.0, 15.0, 30.0)
    for attempt in range(len(waits) + 1):
        try:
            home = WORK / tag
            if home.exists():
                shutil.rmtree(home, ignore_errors=True)
            home.mkdir(parents=True)
            out = home / (tag + ".exe")
            azuchi_momo(res["artifact"], out, home / "work", guards=guards,
                        pins_override=pins_override or {})
            return out
        except PermissionError:
            if attempt == len(waits):
                raise
            time.sleep(waits[attempt])


def _run(exe: Path, env: dict = None, timeout: int = 300) -> subprocess.CompletedProcess:
    return subprocess.run([str(exe)], capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=timeout,
                          shell=False, env=env)


def _cpython_stdout(source: str) -> str:
    r = subprocess.run([sys.executable, "-c", source], capture_output=True, text=True,
                       encoding="utf-8", errors="replace", timeout=180, shell=False)
    assert r.returncode == 0, "reference run failed: %s" % r.stderr[:200]
    return r.stdout


# ---------------- 外部抓取（外部进程手法同款 API） ----------------
class _Mbi(ctypes.Structure):
    """x64 MEMORY_BASIC_INFORMATION（48 字节）：偏移错位会让 MEM_PRIVATE 过滤恒假。"""
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", ctypes.c_uint32),
        ("_pad1", ctypes.c_uint32),
        ("RegionSize", ctypes.c_size_t),
        ("State", ctypes.c_uint32),
        ("Protect", ctypes.c_uint32),
        ("Type", ctypes.c_uint32),
        ("_pad2", ctypes.c_uint32),
    ]


def _readable(protect: int) -> bool:
    base = protect & 0xFF
    if protect & _PAGE_GUARD:
        return False
    return base != 0 and base != _PAGE_NOACCESS


def _dump_committed(pid: int, image_only: bool = False) -> bytes:
    """抓取目标进程全部"已提交 + 可读"区域（含 MEM_IMAGE）。

    用外部进程的同款 API 组合：OpenProcess → VirtualQueryEx → ReadProcessMemory。
    含 MEM_IMAGE 是有意的：CPython 是否被加载这条形态证据只能从映射镜像里看到。
    `image_only=True` 只留映射镜像（早期轮次 步骤 3 的外钥内存自证要分开算"镜像里的钉"
    与"堆栈里的残留"两类命中）。"""
    handle = _KERNEL32.OpenProcess(_PROCESS_VM_READ | _PROCESS_QUERY_INFORMATION,
                                   False, pid)
    if not handle:
        raise AssertionError("OpenProcess(%d) failed: %d" % (pid, ctypes.get_last_error()))
    buf = bytearray()
    try:
        mbi = _Mbi()
        addr = 0
        limit = 0x7FFFFFFFF000
        size = ctypes.sizeof(mbi)
        page = ctypes.create_string_buffer(_READ_CHUNK)
        while addr < limit:
            ok = _KERNEL32.VirtualQueryEx(handle, ctypes.c_void_p(addr),
                                          ctypes.byref(mbi), size)
            if not ok:
                break
            base = mbi.BaseAddress or 0
            span = mbi.RegionSize or 0
            if span == 0:
                break
            if mbi.State == _MEM_COMMIT and _readable(mbi.Protect):
                if image_only and mbi.Type != _MEM_IMAGE:
                    addr = base + span
                    continue
                off = 0
                while off < span:
                    want = min(_READ_CHUNK, span - off)
                    got = ctypes.c_size_t()
                    okread = _KERNEL32.ReadProcessMemory(
                        handle, ctypes.c_void_p(base + off), page, want, ctypes.byref(got))
                    n = got.value if okread else 0
                    if n == 0:
                        break
                    buf += page.raw[:n]
                    off += n
            addr = base + span
    finally:
        _KERNEL32.CloseHandle(handle)
    return bytes(buf)


def _modules(pid: int) -> list:
    """目标进程已加载模块名（Toolhelp32 快照）。

    实测对纯 Rust 的小 exe 会返回 ERROR_BAD_PATHNAME(24)（快照不可用），因此本函数
    只作辅助证据；"没嵌 CPython"的形态断言改用内存标记（`_CPython 标记` 断言），
    那条证据更直接：DLL 真被加载进进程，它的导出名表/版本串必然在进程内存里。"""
    TH32CS_SNAPMODULE = 0x00000008

    class Entry(ctypes.Structure):
        _fields_ = [("dwSize", ctypes.c_uint32), ("th32Module", ctypes.c_uint32),
                    ("th32ProcessID", ctypes.c_uint32), ("GlcccntUsage", ctypes.c_uint32),
                    ("ProccntUsage", ctypes.c_uint32), ("modBaseAddr", ctypes.c_void_p),
                    ("modSize", ctypes.c_uint32),
                    ("szModule", ctypes.c_wchar * 256),
                    ("szExePath", ctypes.c_wchar * 260)]

    names = []
    snap = _KERNEL32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid)
    if snap is None or snap == _INVALID_HANDLE:
        return names
    try:
        entry = Entry()
        entry.dwSize = ctypes.sizeof(Entry)
        if _KERNEL32.Module32FirstW(snap, ctypes.byref(entry)):
            while True:
                names.append(entry.szModule.lower())
                if not _KERNEL32.Module32NextW(snap, ctypes.byref(entry)):
                    break
    finally:
        _KERNEL32.CloseHandle(snap)
    return names


# "CPython 是否被加载"的证据必须取自 **DLL 镜像独有** 的串：boot 自身带着
# "Py_InitializeFromConfig"/"PyEval_EvalCode" 这类 GetProcAddress 用的字面量，
# 它们出现在任何一档产物的镜像里都不说明加载了什么（实测正是这样误判过一次，
# 换成实测筛出的串之后判据才有效）。
# 下面两串经逐字节核对：在 python312.dll 内、在本仓任何 native 产物文件内均不存在。
_CPYTHON_IMAGE_MARKS = (b"Python Software Foundation", b"CPython")


def _cpython_marks_in(dump: bytes) -> list:
    return [m for m in _CPYTHON_IMAGE_MARKS if m in dump]


def _run_with_capture(exe: Path, hold: Path, tag: str, cwd: Path = None,
                      argv0: str = None) -> tuple:
    """跑到暂停点 → 抓内存 + 列模块 → 放行 → 收 stdout。返回 (stdout, dump, modules)。

    `cwd` 给 v1 对照用：v1 产物要在 exe 同目录（或 cwd）找到 pythonXY.dll 才走得到
    暂停点，缺 DLL 时加载器阶段就退出，探针齿自然不会触发。
    `argv0` 是给**接口逐格档**用的受控首 token（早期轮次）：argv[0] 参与的格子会把首 token
    折进窗里，而 exe 的全路径 60–85 B，窗上限只有 48–80 B——拿全路径当 argv[0] 测出来
    的"超限"是夹具路径太长，不是契约生效（与 `case_iface_native` 同款口径，
）。
    早期轮次 2.2：VISI_HOLD 环境后门已移除——hold 路径由**构建期 pin**
    （VISI_HOLD_PATH）内嵌进探针产物；本函数不再注入任何环境变量，只负责
    放置信号文件。"""
    if hold.exists():
        hold.unlink()
    if argv0 is None:
        argv, executable = [str(exe)], None
    else:
        argv, executable = [argv0], str(exe)
    proc = subprocess.Popen(argv, executable=executable,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            stdin=subprocess.DEVNULL,
                            text=True, encoding="utf-8", errors="replace",
                            shell=False, cwd=str(cwd) if cwd else None)
    dumped = b""
    mods = []
    deadline = time.time() + 120
    seen_pause = False
    while time.time() < deadline:
        line = proc.stderr.readline()
        if not line:
            break
        if line.startswith("vispause"):
            seen_pause = True
            dumped = _dump_committed(proc.pid)
            mods = _modules(proc.pid)
            hold.write_bytes(b"go")
            break
    out, _rest = proc.communicate(timeout=180)
    assert seen_pause, "%s: 产物未在暂停点停住（探针齿未生效）" % tag
    assert len(dumped) >= _MIN_DUMP, "%s: 只抓到 %d B 私有内存，抓取仪器本身不可信" % (
        tag, len(dumped))
    return out, dumped, mods


def case_v2_eight_topologies():
    source = _PROG
    want = _cpython_stdout(source)
    seen_sched = set()
    for tail in range(1, 9):
        res, seed = _artifact(vm=True, tail=tail, source=source)
        seen_sched.add(res["sched"])
        exe = _build(res, "v2top%d" % tail)
        run = _run(exe)
        assert run.returncode == 0, "topology %d: exit %d %s" % (
            res["sched"], run.returncode, run.stderr[:160])
        assert run.stdout == want, "topology %d: stdout %r != %r" % (
            res["sched"], run.stdout[:120], want[:120])
    assert seen_sched == {1, 2, 3, 4, 5, 6, 7, 8}, "八个拓扑未逐格覆盖：%r" % (seen_sched,)


def case_v2_chunk_tamper_refused():
    res, _seed = _artifact(vm=True)
    flipped = bytearray(res["ciphertext"])
    flipped[len(flipped) // 2] ^= 0xFF
    # 只翻转 RCDATA 载荷字节、MAC 保持原值：等价于产物资源被改一个字节。
    # 拒绝顺序不变——容器 MAC 先于任何解密/VM 执行，故 exit 3 且零输出。
    exe = _build(res, "v2chunktamper", pins_override={"ct": bytes(flipped)})
    run = _run(exe)
    assert run.returncode == 3, "chunk 篡改未被拒：exit=%d" % run.returncode
    assert run.stdout == "", "篡改产物仍有输出：%r" % run.stdout[:80]


def case_v2_seed_tamper_refused():
    res, seed = _artifact(vm=True)
    flipped = bytearray(seed)
    flipped[0] ^= 0x01
    # 头内 seed 被改（= ISA 映射与容器密钥同时错位）：MAC 先拒。
    # 这也是"调度表/物理映射篡改"的唯一外部可达形态——映射由 seed 现算，
    # 改 seed 即改映射与密钥，产物不可能带着自洽的映射被伪造出来。
    exe = _build(res, "v2seedtamper", pins_override={"seed": bytes(flipped)})
    run = _run(exe)
    assert run.returncode == 3, "seed 篡改未被拒：exit=%d" % run.returncode
    assert run.stdout == "", "篡改产物仍有输出：%r" % run.stdout[:80]


def case_v2_visible_quantity():
    """ 核心承诺的机械化：抓取由另一个进程执行，量在**执行中途的峰值时刻**。

    实测（本案例即证据）：最长连续 IR 明文 = 252 B ≤ chunk(256 B)；marshal 的任何
    窗口（64 B 起）都不存在；CPython 镜像痕迹不存在。对照：v1 同工具同流程必须
    同时看见完整 marshal 与 DLL 镜像痕迹，否则上面三条都毫无意义。
    """
    res, seed = _artifact(vm=True)
    # 早期轮次 2.2：hold 路径构建期内嵌（后门已移除）
    hold = WORK / "hold_v2.flag"
    probe = _build(res, "v2vis", pins_override={"vm_visibility_probe": True,
                                                "visi_hold_path": str(hold)})
    marshal_needle = marshal.dumps(compile(_PROG, "<m>", "exec"))
    funcs = vm_compiler.yamagami_karuta(compile(_PROG, "<m>", "exec"))[0]
    mapping = vm_isa.hayase_sou(seed)
    stream = vm_isa.shellin_burgundy(funcs, mapping)[0]
    bounds = vm_isa.fumi(stream, mapping, vm_isa.CHUNK_SIZE, align=True)[0]
    out, dump, mods = _run_with_capture(probe, hold, "v2")
    assert out == _cpython_stdout(_PROG), "v2 抓取轮 stdout 不等价：%r" % out[:120]
    chunk = vm_isa.CHUNK_SIZE

    # ① 齿成立：此刻确实有一块明文在场（否则"看不见"是抓取坏了，不是保护住了）
    warm = [i for i, (start, length) in enumerate(bounds)
            if stream[start:start + min(64, length)] in dump]
    assert warm, "抓取无齿：峰值时刻连一个块内 64 B 窗口都没看到"

    # ② 连续明文不得长于一个 chunk：块边界处不许拼出 chunk+1 的 run
    over = chunk + 1
    spliced = [s for s in range(0, len(stream) - over + 1) if stream[s:s + over] in dump]
    assert not spliced, "跨 chunk 的连续明文可见（起点 %r，长度 %d）" % (spliced[:4], over)
    assert stream not in dump, "整条 IR 明文在场"

    # ③ 载荷 marshal：连 64 B 窗口都不许出现（v2 里它根本不被构造）
    for k in (len(marshal_needle), 256, 64):
        assert marshal_needle[:k] not in dump, "marshal 明文 %d B 窗口可见" % k

    # ④ 不嵌 CPython 的形态断言：地址空间里不许有 DLL 镜像独有的痕迹
    marks = _cpython_marks_in(dump)
    assert not marks, "v2 进程内存里出现 CPython 镜像痕迹：%r" % (marks,)
    if mods:
        assert not [m for m in mods if "python" in m], "v2 进程加载了 Python DLL：%r" % (mods,)

    # 阴性对照：v1 同齿必须同时看见完整 marshal 与 DLL 镜像痕迹。
    # v1 需要测试 home（pythonXY.dll 在 exe 同目录），否则加载器阶段就退出、到不了暂停点。
    from tests.d_side.test_native_builder import _prepare_home

    home = _prepare_home("vm_v1vis")
    if home is None:                       # junction 不可用 = 环境受限，按口径明确 SKIP
        raise SkipCase("v1 control: test home unavailable (expected-vs-environment)")
    res1, _s1 = _artifact(vm=False)
    exe1 = home / "v1vis.exe"
    hold1 = home / "hold_v1.flag"
    azuchi_momo(res1["artifact"], exe1, home / "v1vis_work",
                pins_override={"vm_visibility_probe": True,
                               "visi_hold_path": str(hold1)})
    _out1, dump1, _mods1 = _run_with_capture(exe1, hold1, "v1", cwd=home)
    assert res1["marshal"][:512] in dump1, "阴性对照失效：v1 产物内存里找不到 marshal 头部（前 512 B）"
    assert _cpython_marks_in(dump1), "阴性对照失效：v1 产物内存里没有 python DLL 镜像痕迹"


def case_cli_v2_end_to_end():
    """CLI 面端到端：`python -m d_side build --vm` → `check` → `build-native` → 运行比对。

    套件其余用例走库 API（`codec.octavio` + `azuchi_momo`），本用例专钉**命令行入口**：
    参数串联、v2 构建期硬门、`check` 对 fmt_ver=2 的白名单、产物可独立运行（不需要 home）。
    """
    home = WORK / "v2cli"
    home.mkdir(parents=True, exist_ok=True)
    src = home / "p.py"
    src.write_text(_PROG, encoding="utf-8")
    art = home / "p.artifact.py"
    exe = home / "p.exe"
    for p in (art, exe):
        if p.exists():
            p.unlink()
    py = str(Path(sys.executable))
    build = subprocess.run([py, "-m", "d_side", "build", "--source", str(src),
                            "--out", str(art), "--seed", "ab" * 32, "--vm",
                            "--embed-key"],
                           capture_output=True, text=True, encoding="utf-8",
                           errors="replace", timeout=600, cwd=str(_ROOT), shell=False)
    assert build.returncode == 0, "build --vm rc=%d %r" % (build.returncode,
                                                           (build.stdout + build.stderr)[-200:])
    chk = subprocess.run([py, "-m", "d_side", "check", "--artifact", str(art)],
                         capture_output=True, text=True, encoding="utf-8",
                         errors="replace", timeout=300, cwd=str(_ROOT), shell=False)
    assert chk.returncode == 0 and "verified" in chk.stdout, "check 未放行 v2 产物：%r" % chk.stdout[-160:]
    native = subprocess.run([py, "-m", "d_side", "build-native", "--artifact", str(art),
                             "--out", str(exe), "--work", str(home / "work")],
                            capture_output=True, text=True, encoding="utf-8",
                            errors="replace", timeout=900, cwd=str(_ROOT), shell=False)
    assert native.returncode == 0, "build-native 失败：%r" % (native.stdout + native.stderr)[-240:]
    assert kanda_shoichi(art.read_text(encoding="utf-8"))["head"][0] == 2, "CLI 产物不是 fmt_ver=2"
    run = subprocess.run([str(exe)], capture_output=True, text=True, encoding="utf-8",
                         errors="replace", timeout=300, cwd=str(home), shell=False)
    assert run.returncode == 0, "v2 产物 exit=%d %r" % (run.returncode, run.stderr[:160])
    assert run.stdout == _cpython_stdout(_PROG), "CLI 产物输出不等价：%r" % run.stdout[:120]
    # v2 产物自带 runtime，不需要 pythonXY.dll 在旁（本用例的 cwd 里没有 DLL）
    assert not list(home.glob("python*.dll")), "用例目录里不该有 Python DLL"


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
    "        b = b + weight(stdin[j])\n"
    "        j = j + 1\n"
    "    print(a, b, len(argv) + len(stdin))\n"
    "    return 0\n"
)


def _profile_of(res):
    """octavio 结果 → 本格链剖面（enc_key → VM root → vm_isa.kaburaki_roco）。
    测试侧要"和产物看到同一份窗"就只能走这一条派生，不许另算补齐字节。"""
    from d_side.builder import vm_blob

    return vm_isa.kaburaki_roco(vm_blob.matsukai_mao(res["keys"][0])["root"])


def _cell_window(iface, a0, items):
    """本格契约下的扁平 argv 窗，带两条"夹具不许自造超窗"的硬断言。

    项数与字节数都按**本格**上限量：`argmax`/`ap` 现在是逐格量（早期轮次 Phase 2 铺开，
    早期轮次 起为出厂默认），写死 64 的旧口径要么静默越界（产物拒启动，报错看着像契约坏了）
    要么静默变空测试。"""
    n_items = len(items) + (1 if iface["argv0"] else 0)
    assert n_items <= iface["argmax"], "夹具自造超项数上限（argmax=%d）：%r" % (
        iface["argmax"], items)
    flat = _iface_flat(iface, a0, items)
    assert len(flat) <= iface["ap"], "夹具自造超窗（ap=%d）：%r" % (iface["ap"], flat)
    return flat


def _b1_ref(argv_items, stdin_bytes, prf, iface, a0):
    """验收 harness 的参考口径：argv 先按**本格契约**折窗（`_iface_flat` 是 boot.rs
    `amagase_muyu` 的镜像），两窗再按 早期轮次补齐到本格上限。

    早期轮次：`hardening.iface.mode` 已铺开成 per_cell，这一份不再镜像上一代的全局契约
    （64/64、`0x00` 连接、跳过 argv[0]）——连接字节、窗上限、argv[0] 是否参与一律从
    构建结果 `res["iface"]` 读，测试与产物量的才是同一个接口。
    逐格契约的镜像本身就是 `_iface_flat`，这里只是它的一个调用方。

    字节模式取回再归一 \\r\\n：CPython 对管道写 CRLF、VM 逐字写 LF，既有套件都靠
    universal newlines 抹平，这里显式做同一件事（不是放宽判据）。"""
    argv = vm_isa.hibachi_mana(prf, _cell_window(iface, a0, argv_items), iface["ap"])
    stdin = vm_isa.hibachi_mana(prf, stdin_bytes, iface["sp"])
    harness = ("import sys as _s\n"
               "argv = bytes.fromhex(_s.argv[1])\n"
               "stdin = bytes.fromhex(_s.argv[2])\n" + _B1_SRC + "\nmain(argv, stdin)\n")
    r = subprocess.run([sys.executable, "-c", harness, argv.hex(), stdin.hex()],
                       capture_output=True, timeout=180, cwd=str(_ROOT), shell=False)
    assert r.returncode == 0, (r.stderr or b"")[-240:]
    return r.stdout.replace(b"\r\n", b"\n")


def case_b1_native_input():
    """早期轮次 的 Rust 腿：真 exe 用真 argv/stdin 跑出与 CPython 逐字节一致的输出。

    四组输入覆盖：多参数 + 管道 stdin、完全空输入、单字节、非 ASCII 字节；
    另钉两条负例：stdin 超**本格**上限必须静默拒（退出码 = 本格 `reject_exit`、零输出，
    不截断；同一条输入的 cap 档必须**通过**，否则"超限被拒"没有对照），常量输出的退化
    样本在**构建期**就被出厂门拦下（不落盘）。
    这是 ARGV/STDIN 唯一在 Rust 执行体上被验一遍的地方——Python 侧 KAT 再全也
    替代不了它（双路径互钉，layout.json 的 load_validation_parity 同源）。
    """
    seed = bytes(range(31)) + bytes([0x63])
    res = codec.octavio(_B1_SRC, "b1native", seed, vm=True, input_dependent=True,
                        external_key=False)
    prof = _profile_of(res)
    iface = res["iface"]
    exe = _build(res, "b1native")
    home = WORK / "b1native"
    # argv[0] 参与档用受控短字面量起进程（口径同 case_iface_native）：exe 全路径 60–85 B，
    # 而 ap 低至 48，拿全路径当首 token 测到的"超限"是路径太长，不是契约生效。
    a0 = "b1.exe"
    for items, stdin_bytes in ((["alpha", "beta"], b"hello world"),
                               ([], b""),
                               (["x"], b"\n"),
                               (["a", "b"], bytes(range(20)))):
        assert len(stdin_bytes) <= iface["sp"], "夹具自造超 stdin 窗（sp=%d）：%d B" % (
            iface["sp"], len(stdin_bytes))
        r = subprocess.run([a0, *items], executable=str(exe), input=stdin_bytes,
                           capture_output=True, timeout=300, cwd=str(home), shell=False)
        got = r.stdout.replace(b"\r\n", b"\n")
        want = _b1_ref(items, stdin_bytes, prof, iface, a0)
        assert r.returncode == 0, "exit=%d err=%r" % (r.returncode, (r.stderr or b"")[-160:])
        assert got == want, "输入 %r/%r：exe %r != CPython %r" % (items, stdin_bytes, got, want)
    # 不同输入必须给不同输出（退化产物在这一层就会被看出来）
    outs = {subprocess.run([a0, "one"], executable=str(exe), input=b"abc",
                           capture_output=True, timeout=300, cwd=str(home),
                           shell=False).stdout,
            subprocess.run([a0, "two"], executable=str(exe), input=b"abd",
                           capture_output=True, timeout=300, cwd=str(home),
                           shell=False).stdout}
    assert len(outs) == 2, "换输入不换输出：%r" % (outs,)
    # 超本格上限：sp+1 B stdin ⇒ 静默拒，零输出；退出码逐格 ∈ {3,4}，取本格契约那一枚
    # （写死 "65 B ⇒ rc=3" 在 per_cell 下两枚量都是错的）
    for length, expect_ok in ((iface["sp"], True), (iface["sp"] + 1, False)):
        r = subprocess.run([a0, "a"], executable=str(exe), input=b"z" * length,
                           capture_output=True, timeout=300, cwd=str(home), shell=False)
        if expect_ok:
            assert r.returncode == 0, "cap=%d 正当输入被拒：rc=%d" % (length, r.returncode)
        else:
            assert r.returncode == iface["reject_exit"] and r.stdout == b"" and \
                r.stderr == b"", (
                "超窗输入未走本格静默拒绝：rc=%d（契约 %d）out=%r err=%r" % (
                    r.returncode, iface["reject_exit"], r.stdout[:60], r.stderr[:60]))
    # 退化样本（常量输出）过不了出厂门
    try:
        codec.octavio("print('constant 42')\n", "b1deg", seed, vm=True,
                      input_dependent=True, external_key=False)
        raise AssertionError("常量样本过了出厂门")
    except ValueError:
        pass


_V5_SRC = (
    "def mix(v, ch, k):\n"
    "    return rotl32(v ^ ch, k)\n"
    "def main(argv, stdin):\n"
    "    s = 1\n"
    "    i = 0\n"
    "    while i < len(argv):\n"
    "        s = mix(s, argv[i], 3)\n"
    "        i = i + 1\n"
    "    t = 7\n"
    "    j = 0\n"
    "    while j < len(stdin):\n"
    "        t = t ^ rotl32(stdin[j] + j, 11)\n"
    "        j = j + 1\n"
    "    print(s, t, len(argv) + len(stdin))\n"
    "    return 0\n"
)
# 值域纪律的负例载荷：SUB 造出负数后交给 XOR / ROTL32（k 路）——Rust 腿必须走同一条
# 静默拒绝（exit 3、零输出、零 stderr），Python 权威端同判据。
# 判据**不能挂在 len(argv) 上**：早期轮次定长吸收之后 len() 恒等于本格上限，那种写法
# 会变成"永远不进分支"的空测试。
# 也**不能挂在"分隔符位为 0"上**（上一代的做法）：接口逐格化之后连接字节可非 0、可整条
# 没有分隔符、argv[0] 还可能参与——同一个下标量的不再是同一枚字节。早期轮次 的写法是把三字节
# 标记摆在**窗的开头**，并让 argv[0] 字面量与第一个命令行项以同一串标记开头，于是
# argv[0..2] 在"argv[0] 参与/不参与"两种窗布局下都是同三枚字节：触发位点与本格契约无关
# （上一版靠 argv[1]==0 触发，join 一旦非 0 就静默变空测试——正是本轮不许再犯的
# "验收量的不是出厂那个接口"）。
# 与出厂探针的互斥：探针 0 是整窗补齐（要同时命中 126 与 125，不可能），其余探针是派生流
# 字节，命中 (126,125,·) 的量级约 2^-16/格；种子固定，真撞上出厂门当场红灯。
# 操作数取 argv[0]：触发时它必为 126，`0 - argv[0]` 恒为负，不会被"补齐字节恰好 0"抹平。
# 标记全是可打印 ASCII：Windows 命令行按 UTF-8 传参，非 ASCII 项会变成两个字节，
# 测的就不再是那枚字节（同 v5 用例"argv 只用命令行可无损传递字符"的口径）。
_NEG_SRC = (
    "def main(argv, stdin):\n"
    "    k = argv[0] * 256 + argv[1]\n"
    "    if k == 32381:\n"
    "        if argv[2] == 125:\n"
    "            print(0 - argv[0] ^ 3)\n"
    "        if argv[2] == 126:\n"
    "            print(rotl32(5, 0 - argv[0]))\n"
    "    print(argv[0])\n"
    "    return 0\n"
)


def _v5_ref(argv_items, stdin_bytes, prf, iface, a0):
    """CPython 参考腿：内建的规范闭式取自 vm_isa.INTRINSICS 单源（不在测试里另抄
    一份——抄一份就是一个可能漂移的分叉面）。窗与 `_b1_ref` 同源：
    按**本格契约**扁平化（`_cell_window`）再按 早期轮次补齐到本格上限。"""
    argv = vm_isa.hibachi_mana(prf, _cell_window(iface, a0, argv_items), iface["ap"])
    stdin = vm_isa.hibachi_mana(prf, stdin_bytes, iface["sp"])
    harness = ("import sys as _s\n"
               "from d_side.builder import vm_isa\n"
               "rotl32 = vm_isa.INTRINSICS['rotl32'][2]\n"
               "argv = bytes.fromhex(_s.argv[1])\n"
               "stdin = bytes.fromhex(_s.argv[2])\n" + _V5_SRC + "\nmain(argv, stdin)\n")
    r = subprocess.run([sys.executable, "-c", harness, argv.hex(), stdin.hex()],
                       capture_output=True, timeout=180, cwd=str(_ROOT), shell=False)
    assert r.returncode == 0, (r.stderr or b"")[-240:]
    return r.stdout.replace(b"\r\n", b"\n")


def case_v5_logic_ops_native():
    """早期轮次+C（ISA v5）的 Rust 腿：XOR / ROTL32 在真 exe 上与 CPython 逐字节一致。

    Python 侧的值域 KAT 在 test_vm_gates（全值域抽样 + 0/2^32-1/k=0/31 + 负数拒绝），
    这里只补 **Rust 执行体** 那一半——与 ARGV/STDIN 同款分工（双路径互钉，
    layout.json 的 load_validation_parity 同源）：
    ①40 组派生输入：exe stdout == CPython 闭式参考 == vm_interp 权威端（三腿同值）；
    ②ROTL32 的 k 边界 0/31/35/64（后两个走 mod 32）在同一 32 位状态上三腿同值；
    ③负操作数（SUB 造负后进 XOR）走既有静默拒绝：exit 3、零输出、零 stderr，
      与 Python 权威端同判据——扩操作码不扩可见行为。
    """
    from d_side.builder import vm_interp

    seed = bytes(range(31)) + bytes([0x64])
    res = codec.octavio(_V5_SRC, "v5logic", seed, vm=True, input_dependent=True,
                        external_key=False)
    assert res["payload"][6] == vm_isa.ISA_VER == 6, "产物 isa_ver 未随 v6 升档"
    prof = _profile_of(res)
    iface = res["iface"]
    exe = _build(res, "v5logic")
    home = WORK / "v5logic"
    enc, _mac = res["keys"]
    blob = res["payload"]
    alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    a0 = "v5.exe"
    # 夹具的预算按本格窗算：argv[0] 参与的格子要先扣掉首 token 与一枚分隔符，
    # 项数上限同样是逐格量（写死 64 会造出"产物正当拒绝、测试以为是分叉"的假信号，
    #）。
    sep = 0 if iface["join"] == 256 else 1
    head = (len(a0) + sep) if iface["argv0"] else 0
    max_items = iface["argmax"] - (1 if iface["argv0"] else 0)
    checked = 0
    for c in range(40):
        # 确定性派生流（blake2s/shake，禁 random——仓内纪律）：argv 只用命令行可无损
        # 传递的可打印字符（早期轮次 验收 同款口径），stdin 走管道取原始字节
        st = hashlib.shake_256(b"r12bc/v5case/%d" % c).digest(96)
        items = []
        budget = iface["ap"] - head
        for k in range(min(1 + st[0] % 9, max_items)):
            ln = 1 + st[8 + k] % 7
            if ln > budget:
                break
            items.append("".join(alpha[b % 62] for b in st[16 + k * 7:16 + k * 7 + ln]))
            budget -= ln + 1
        stdin_bytes = st[:8 + st[7] % 40]
        assert len(stdin_bytes) <= iface["sp"], "夹具自造超 stdin 窗（sp=%d）：%d B" % (
            iface["sp"], len(stdin_bytes))
        flat = _cell_window(iface, a0, items)
        r = subprocess.run([a0, *items], executable=str(exe), input=stdin_bytes,
                           capture_output=True, timeout=300, cwd=str(home), shell=False)
        assert r.returncode == 0, "case %d exit=%d err=%r" % (
            c, r.returncode, (r.stderr or b"")[-160:])
        want = _v5_ref(items, stdin_bytes, prof, iface, a0)
        got = r.stdout.replace(b"\r\n", b"\n")
        assert got == want, "case %d exe %r != CPython %r" % (c, got[:80], want[:80])
        vm = vm_interp.gwelu_os_gar(blob, enc, seed, argv=flat, stdin=stdin_bytes,
                                    argv_cap=iface["ap"], stdin_cap=iface["sp"])
        assert vm == want, "case %d vm_interp %r != CPython %r" % (c, vm[:80], want[:80])
        checked += 1
    assert checked == 40, "双端一致样本不足：%d" % checked
    # ② k 的边界与 mod 32：k=0/31/35/64 在同一 32 位状态上必须三腿同值
    ksrc = ("def main(argv, stdin):\n"
            "    v = 0\n"
            "    i = 0\n"
            "    while i < 4 and i < len(stdin):\n"
            "        v = v * 256 + stdin[i]\n"
            "        i = i + 1\n"
            "    while i < 4:\n"
            "        v = v * 256\n"
            "        i = i + 1\n"
            "    a = rotl32(v, 0)\n"
            "    b = rotl32(v, 31)\n"
            "    c = rotl32(v, 35)\n"
            "    d = rotl32(v ^ a, 16)\n"
            "    e = rotl32(v, 64)\n"
            "    print(a, b, c, d, e, len(argv) + len(stdin))\n"
            "    return 0\n")
    kres = codec.octavio(ksrc, "v5k", seed, vm=True, input_dependent=True,
                         external_key=False)
    kexe = _build(kres, "v5k")
    kenc, _kmac = kres["keys"]
    kiface = kres["iface"]
    ka0 = "v5k.exe"
    kh = ("import sys as _s\nfrom d_side.builder import vm_blob, vm_isa\n"
          "prf = vm_isa.kaburaki_roco(vm_blob.matsukai_mao(bytes.fromhex(_s.argv[1]))['root'])\n"
          "rotl32 = vm_isa.INTRINSICS['rotl32'][2]\n"
          "argv = vm_isa.hibachi_mana(prf, bytes.fromhex(_s.argv[2]), %d)\n"
          "stdin = vm_isa.hibachi_mana(prf, _s.stdin.buffer.read(), %d)\n"
          % (kiface["ap"], kiface["sp"])
          + ksrc + "\nmain(argv, stdin)\n")
    # 空项表下 argv 窗 = 首 token（参与档）或空（不参与档）——两档都由本格契约决定，
    # 参考腿不许自己猜
    kflat = _cell_window(kiface, ka0, [])
    for quad in ((0, 0, 0, 0), (255, 255, 255, 255), (0x80, 0x00, 0x00, 0x01),
                 (0x12, 0x34, 0x56, 0x78), (0xFF, 0x7F, 0xBF, 0x00),
                 (0x00, 0x00, 0x00, 0x80), (0xDE, 0xAD, 0xBE, 0xEF)):
        raw = bytes(quad)
        # 参考腿的窗同样走定长吸收（补齐字节逐格，只有 VM root 算得出来），
        # 否则 `len(argv)+len(stdin)` 这一列两侧量的就不是一个东西
        want = subprocess.run([sys.executable, "-c", kh, kenc.hex(), kflat.hex()],
                              input=raw, capture_output=True, timeout=180,
                              cwd=str(_ROOT), shell=False).stdout
        want = want.replace(b"\r\n", b"\n")
        assert want, "CPython 参考腿失败"
        vm = vm_interp.gwelu_os_gar(kres["payload"], kenc, seed, argv=kflat, stdin=raw,
                                    argv_cap=kiface["ap"], stdin_cap=kiface["sp"])
        assert vm == want, "k 边界 vm %r != CPython %r" % (vm[:60], want[:60])
        r = subprocess.run([ka0], executable=str(kexe), input=raw, capture_output=True,
                           timeout=300, cwd=str(WORK / "v5k"), shell=False)
        assert r.returncode == 0, "k 边界 exe exit=%d %r" % (
            r.returncode, (r.stderr or b"")[-120:])
        assert r.stdout.replace(b"\r\n", b"\n") == want, "k 边界 exe %r != CPython %r" % (
            r.stdout[:60], want[:60])
    # ③ 负操作数：exe 走静默拒绝（exit 3、零输出、零 stderr），与 Python 权威端同判据。
    #    触发串摆在窗首三字节，且 a0 与首项以同一串开头——argv[0] 参与与否都不移动触发位点。
    nres = codec.octavio(_NEG_SRC, "v5neg", seed, vm=True, input_dependent=True,
                         external_key=False)
    nexe = _build(nres, "v5neg")
    niface = nres["iface"]
    for a0n, marker, why in (("~}}.exe", "~}}", "XOR 负操作数"),
                             ("~}~.exe", "~}~", "ROTL32 负移位数")):
        flat = _cell_window(niface, a0n, [marker])
        r = subprocess.run([a0n, marker], executable=str(nexe), input=b"",
                           capture_output=True, timeout=300, cwd=str(WORK / "v5neg"),
                           shell=False)
        assert r.returncode == 3 and r.stdout == b"" and r.stderr == b"", (
            "%s 未走静默拒绝：rc=%d out=%r err=%r" % (
                why, r.returncode, r.stdout[:60], r.stderr[:60]))
        try:
            vm_interp.gwelu_os_gar(nres["payload"], nres["keys"][0], seed,
                                   argv=flat, stdin=b"",
                                   argv_cap=niface["ap"], stdin_cap=niface["sp"])
            raise AssertionError("%s 在 Python 权威端未被拒" % why)
        except vm_interp.SaayaYamabuki:
            pass
    # 同一条载荷在正常输入上必须照跑（拒的是域，不是整条操作码）：窗首字节 'c' 两个门都不进
    na0 = "c.exe"
    r = subprocess.run([na0, "c"], executable=str(nexe), input=b"xyz",
                       capture_output=True, timeout=300, cwd=str(WORK / "v5neg"),
                       shell=False)
    assert r.returncode == 0 and r.stdout.replace(b"\r\n", b"\n") == b"99\n", (
        "负例载荷的正常分支被打死：rc=%d out=%r" % (r.returncode, r.stdout[:60]))


def case_v3_psiv_native():
    """容器 v3（PSIV 块级 AEAD）native 端到端：octavio(psiv=True) → azuchi_momo → 运行。

    锚定链：Rust psiv.rs 先过官方 KAT（.tmp/psiv-rust-kat，向量 0），此处再用真实
    exe 钉"Python 打包 ↔ Rust 解包"的跨实现互证（tag 路径走通 = 双端 PSIV 一致）。
    另钉：v3 产物可独立运行（自带 runtime，无 python*.dll）、chunk/seed 篡改拒绝不变。
    """
    res, seed = _artifact(vm=True, psiv=True)
    assert res["fields"]["fmt_ver"] == 2, "容器层 fmt_ver 不因 --psiv 改变"
    assert res["payload"][4] == 3, "内层 blob fmt_ver 应为 3（VMB1 头 le16 低字节）"
    exe = _build(res, "v3psiv")
    run = _run(exe)
    assert run.returncode == 0, "v3 exit %d: %s" % (run.returncode, run.stderr[:200])
    assert run.stdout == _cpython_stdout(_PROG), "v3 stdout divergence: %r" % run.stdout[:200]
    assert not list(WORK.glob("v3psiv/python*.dll")), "v3 产物不需要 Python DLL"


def case_v2_build_determinism():
    res, _seed = _artifact(vm=True)
    a = _build(res, "v2det1")
    b = _build(res, "v2det2")
    assert a.read_bytes() == b.read_bytes(), "I6：同 seed 两次 v2 完整构建不一致"


# ---------------- 早期轮次 批2-2：变异层（变体矩阵 / 剥离取证 / 消融档） ----------------
_I128_MIN, _I128_MAX = -(1 << 127), (1 << 127) - 1
_TAG_RE = re.compile(r"pub const TAG_([A-Z0-9]+)_(\d): u64 = (0x[0-9a-fA-F_]+);")
# 热操作码 → vm_ops.rs 里的函数名前缀（单源，两处剥离齿共用；ROTL32 的名字带数字，
# 所以标签正则的枚名段必须允许 [A-Z0-9] 而不是 [A-Z]+，否则这一整码从齿里消失）
_OP_KEY = {"MOVE": "move", "ADD": "add", "LOADK": "loadk", "LOADG": "loadg",
           "LT": "lt", "LOADN": "loadn", "STOREG": "storeg", "MUL": "mul",
           "XOR": "xor", "ROTL32": "rotl32", "HSTEP": "hstep"}
# 早期轮次 链剖面字段清单：(名字, Rust 访问表达式)。探针按这个顺序把一格的全部形状字段
# 打成一行，Python 侧用 kaburaki_roco 现算的同一组值对拍——**剖面解码的双端一致性**
# 由此钉住（只钉步进值的话，两侧解码出不同形状却恰好同值的情况是测不出来的）。
CHAIN_FIELDS = (
    ("rounds", ".rounds()"), ("fold_pos", ".fold_pos()"), ("fold_cnt", ".fold_cnt()"),
    ("inject", ".inject()"), ("couple", ".couple()"), ("tail_rot", ".tail_rot()"),
    ("order0", ".order()[0]"), ("order1", ".order()[1]"),
    ("rot0", ".rot(0)"), ("rot1", ".rot(1)"), ("rot2", ".rot(2)"), ("rot3", ".rot(3)"),
    ("fv0", ".fold_val(0)"), ("fv1", ".fold_val(1)"),
    ("kadd0", ".kadd(0)"), ("kadd1", ".kadd(1)"), ("kadd2", ".kadd(2)"),
    ("kadd3", ".kadd(3)"), ("iv", ".iv()"), ("km", ".km()"),
    ("tbl0", ".tbl(0)"), ("tbl1", ".tbl(1)"), ("tbl2", ".tbl(2)"), ("tbl_mod", ".tbl_mod()"),
    ("mul0", ".mul(0)"), ("mul1", ".mul(1)"), ("mul2", ".mul(2)"), ("mul3", ".mul(3)"),
    ("kend", ".kend()"), ("kf", ".kf()"))
# 与 vm_isa.kaburaki_roco 的返回字典一一对应的取值式（顺序必须与 CHAIN_FIELDS 同）
CHAIN_PY = (lambda p: p["rounds"], lambda p: p["fold_pos"], lambda p: p["fold_cnt"],
            lambda p: p["inject"], lambda p: p["couple"], lambda p: p["tail_rot"],
            lambda p: p["order"][0], lambda p: p["order"][1],
            lambda p: p["rot"][0], lambda p: p["rot"][1], lambda p: p["rot"][2],
            lambda p: p["rot"][3], lambda p: p["fold_val"][0], lambda p: p["fold_val"][1],
            lambda p: p["kadd"][0], lambda p: p["kadd"][1], lambda p: p["kadd"][2],
            lambda p: p["kadd"][3], lambda p: p["iv"], lambda p: p["km"],
            lambda p: p["tbl"][0], lambda p: p["tbl"][1], lambda p: p["tbl"][2],
            lambda p: p["tbl_mod"], lambda p: p["mul"][0], lambda p: p["mul"][1],
            lambda p: p["mul"][2], lambda p: p["mul"][3],
            lambda p: p["kend"], lambda p: p["kf"])
assert len(CHAIN_FIELDS) == len(CHAIN_PY), "链剖面对拍字段清单两头长度不一致"


def _rust_arr(bs: bytes) -> str:
    return ", ".join(str(b) for b in bs)


def _probe_profiles(n: int = 8) -> list:
    """探针用的 n 份逐格剖面。root 取 `keys._extract` 派生，与产品里"root = HKDF(enc_key,
    i3)"同源——覆盖不同 rounds/inject/耦合组合才谈得上"每条轴都被对拍过"。"""
    from d_side.builder import vm_isa

    roots = [hashlib.sha256(b"r13c2/probe-root-%d" % i).digest() for i in range(n)]
    return [vm_isa.kaburaki_roco(r) for r in roots]
# 边界域：极值 / 0±1 / 字面量宽闸附近 / 2 的幂 / 近溢出对（+ 确定性伪随机扫）
_VARIANT_EDGE = [
    (0, 0), (0, 1), (1, 0), (-1, 0), (0, -1), (1, 1), (-1, -1), (2, 3), (-2, -3),
    (_I128_MAX, 0), (_I128_MIN, 0), (_I128_MAX, 1), (_I128_MAX, -1),
    (_I128_MIN, 1), (_I128_MIN, -1), (_I128_MAX, _I128_MAX), (_I128_MIN, _I128_MIN),
    (_I128_MAX, _I128_MIN), (_I128_MIN, _I128_MAX),
    (1 << 63, 1 << 63), (1 << 63, -(1 << 63)), (-(1 << 63), -(1 << 63)),
    (1 << 126, 1 << 126), (-1 << 126, 1 << 126), (3037000499, 3037000500),
    (-3037000499, 3037000499), (1000000007, 1000000009), (0x7FFF, 1), (0x8000, 0),
    (0xFFFF, 0xFFFF), (-32768, -32768), (1, _I128_MAX), (_I128_MIN, 1),
    (2, _I128_MAX // 2), (2, _I128_MAX // 2 + 1), (-1, _I128_MIN), (-1, _I128_MAX),
]


def _variant_domain():
    """边界域 + shake_256 派生的伪随机对。**不用 random 模块**（仓内纪律）。"""
    pts = list(_VARIANT_EDGE)
    stream = hashlib.shake_256(b"r12b2/variant-matrix").digest(8 * 16 * 4)
    for i in range(0, len(stream), 32):
        blk = stream[i:i + 32]
        pts.append((int.from_bytes(blk[:16], "big", signed=True),
                    int.from_bytes(blk[16:], "big", signed=True)))
    for i in range(1, 64):
        pts.extend([(i, -i), (-i, i), (i * i, -(i ** 3))])
    return pts


def _variant_tags() -> dict:
    """从 vm_ops.rs 解析全部变体标签——源即唯一出处，测试不另抄一份（抄一份
    就是"改了源忘了改测试"的双端分叉面）。"""
    txt = (_ROOT / "d_side" / "builder" / "vm_ops.rs").read_text(encoding="utf-8")
    found = _TAG_RE.findall(txt)
    want = len(_OP_KEY) * 3
    assert len(found) == want, "expected %d variant tags in vm_ops.rs, got %d" % (
        want, len(found))
    assert {op.lower() for op, _v, _x in found} == {k for k in _OP_KEY.values()}, \
        "标签集与热操作码表不同步：%r" % ({op.lower() for op, _v, _x in found},)
    return {(op.lower(), int(var)): int(val.replace("_", ""), 16)
            for op, var, val in found}


def _tag_bytes(value: int) -> bytes:
    return value.to_bytes(8, "little")


def case_variant_matrix() -> None:
    """批2-2.1 验收①：变体矩阵 × 边界输入域，Python 规范预言机逐位比对。

    手法：`vm_ops.rs` 零依赖，所以能把**全部** 24 条实现编进一个独立小二进制
    （一次 rustc，秒级），把 (操作码, 变体, 输入) 全矩阵打出来——产品每格只留一条
    路径，"每条实现都对"只能在探针里验。断言两层：①同一操作码的三条实现两两一致；
    ②三条都等于规范预言机（i128 域内精确算术 / 16 位补码扩展 / 有符号序 /
    下标 ∈ [0,len)）。这是"两错相消"纪律的机械化：任何一条实现单独错，
    矩阵当场红；两条一起错，与预言机那一层当场红。"""
    if shutil.which("rustc") is None:
        raise SkipCase("rustc unavailable (expected-vs-environment)")
    pts = _variant_domain()
    raws = list(range(0, 65536, 257)) + [0, 1, 0x7FFF, 0x8000, 0xFFFE, 0xFFFF]
    lens = (0, 1, 2, 8, 63, 64, 65, 255, 256, 65535, 65536, 1 << 31)
    pairs = [(i, l) for l in lens for i in (0, 1, 2, 7, 63, 64, 65, 255, 256,
                                            65534, 65535, 65536, 1 << 31)]
    # ROTL32 的非负域（含跨 2^32 的取低位分支）与 HSTEP 的 u32 域
    rdom = [(0, 0), (1, 0), (0xFFFFFFFF, 31), (0x80000000, 1), (0x12345678, 33),
            ((1 << 64) + 0xDEADBEEF, 7), ((1 << 100) + 5, 12), (255, 8), (1 << 31, 16)]
    prfs = _probe_profiles()
    hs_stream = hashlib.shake_256(b"r13c2/matrix-domain").digest(12 * 8)
    d32 = [(0, 0), (1, 0), (0xFFFFFFFF, 0xFFFFFFFF), (0xFFFFFFFF, 0), (0, 0xFFFFFFFF),
           (0x80000000, 0x7FFFFFFF), (255, 256)]
    for i in range(0, len(hs_stream), 8):
        d32.append((int.from_bytes(hs_stream[i:i + 4], "little"),
                    int.from_bytes(hs_stream[i + 4:i + 8], "little")))
    work = WORK / "opsprobe"
    if work.exists():
        shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True)
    src = ['#[path = "%s"]\nmod ops;'
           % (_ROOT / "d_side" / "builder" / "vm_ops.rs").as_posix(), "fn main() {",
           "    let dom: [(i128, i128); %d] = [%s];"
           % (len(pts), ", ".join("(%d, %d)" % ab for ab in pts)),
           "    let rdom: [(i128, i128); %d] = [%s];"
           % (len(rdom), ", ".join("(%d, %d)" % ab for ab in rdom)),
           "    let d32: [(u32, u32); %d] = [%s];"
           % (len(d32), ", ".join("(%d, %d)" % ab for ab in d32)),
           "    let kr: [u16; %d] = [%s];" % (len(raws), ", ".join(map(str, raws))),
           "    let gr: [(usize, usize); %d] = [%s];"
           % (len(pairs), ", ".join("(%d, %d)" % il for il in pairs))]
    for op in ("add", "mul", "lt"):
        for v in range(3):
            src.append('    for i in 0..dom.len() { let (a, b) = dom[i];'
                       ' println!("%s;%d;{:?}", ops::%s_%d(a, b)); }' % (op, v, op, v))
    for v in range(3):
        src.append('    for i in 0..kr.len() { println!("loadk;%d;{:?}",'
                   ' ops::loadk_%d(kr[i])); }' % (v, v))
    for op in ("move_gate", "loadg_gate", "loadn_gate", "storeg_gate"):
        for v in range(3):
            src.append('    for i in 0..gr.len() { let (x, l) = gr[i];'
                       ' println!("%s;%d;{:?}", ops::%s_%d(x, l)); }' % (op, v, op, v))
    # 早期轮次：XOR 复用同一条 i128 全域（异或对负数也闭合）；ROTL32 与 HSTEP 的
    # 值域是非负整数（与解释器侧 E-116 同判据），所以各用一条自己的非负域。
    for v in range(3):
        src.append('    for i in 0..dom.len() { let (a, b) = dom[i];'
                   ' println!("xor;%d;{:?}", ops::xor_%d(a, b)); }' % (v, v))
    for v in range(3):
        src.append('    for i in 0..rdom.len() { let (a, k) = rdom[i];'
                   ' println!("rotl;%d;{:?}", ops::rotl32_%d(a, k)); }' % (v, v))
    src.append("    let chs = [%s];" % ", ".join(
        "ops::Chain { cfg: [%s], ks: [%s], mask: [%s] }"
        % (_rust_arr(p["cfg"]), _rust_arr(p["ks"]), _rust_arr(p["mask"]))
        for p in prfs))
    for ci in range(len(prfs)):
        # 30 个字段挨个作参数打（Rust 的元组 Debug 只到 12 元，塞成元组当场编不过）；
        # 取 `chs[ci]` 而不是 c%d——链已 move 进数组，再按原名借用编不过
        src.append('    println!("pf;%d;%s", %s);'
                   % (ci, ";".join(["{}"] * len(CHAIN_FIELDS)),
                      ", ".join("chs[%d]%s as u64" % (ci, expr)
                                for _n, expr in CHAIN_FIELDS)))
    for v in range(3):
        src.append('    for ci in 0..chs.len() { for i in 0..d32.len() {'
                   ' let (a, b) = d32[i]; println!("hstep;%d;{:?}",'
                   ' ops::hstep_%d(&chs[ci], a, b)); } }' % (v, v))
    src.append("}")
    (work / "ops_probe.rs").write_text("\n".join(src) + "\n", encoding="utf-8")
    exe = work / "ops_probe.exe"
    build = subprocess.run(["rustc", "-O", "--edition", "2021", "-o", str(exe),
                            str(work / "ops_probe.rs")], capture_output=True,
                           text=True, errors="replace", timeout=600, shell=False)
    assert build.returncode == 0, "probe compile failed:\n%s" % build.stderr[-2500:]
    out = subprocess.run([str(exe)], capture_output=True, text=True,
                         errors="replace", timeout=600, shell=False)
    assert out.returncode == 0, "probe run failed: %s" % out.stderr[-400:]
    got = {}
    for line in out.stdout.splitlines():
        if not line.strip():
            continue
        op, var, val = line.split(";", 2)
        got.setdefault((op, int(var)), []).append(val)

    def want_add(a, b):
        r = a + b
        return r if _I128_MIN <= r <= _I128_MAX else None

    def want_mul(a, b):
        r = a * b
        return r if _I128_MIN <= r <= _I128_MAX else None

    exp = {"add": ["None" if want_add(a, b) is None else "Some(%d)" % want_add(a, b)
                   for a, b in pts],
           "mul": ["None" if want_mul(a, b) is None else "Some(%d)" % want_mul(a, b)
                   for a, b in pts],
           "lt": ["true" if a < b else "false" for a, b in pts],
           "loadk": [str(r - 0x10000 if r >= 0x8000 else r) for r in raws]}
    gates = ["Some(%d)" % i if i < l else "None" for i, l in pairs]
    for op in ("move_gate", "loadg_gate", "loadn_gate", "storeg_gate"):
        exp[op] = gates
    # 早期轮次：三条新码的规范预言机。XOR 在 i128 全域闭合；ROTL32/HSTEP 的期望值直接取
    # vm_isa 的那一份闭式（与 CPython 参考腿、VM 权威腿同一张表），探针只是把同一件事
    # 在原生实现上再问一遍。
    from d_side.builder import vm_isa

    exp["xor"] = [str(a ^ b) for a, b in pts]
    exp["rotl"] = [str(_rotl32_expect(a, k)) for a, k in rdom]
    exp["hstep"] = [str(vm_isa.shishido_akari(p, a, b))
                    for p in prfs for (a, b) in d32]
    checked = 0
    for op, want in exp.items():
        for v in range(3):
            have = got.get((op, v))
            assert have == want, "%s variant %d diverges from the oracle: %r" % (
                op, v, [(i, have[i], want[i]) for i in range(min(len(have or []),
                                                                 len(want)))
                        if have[i] != want[i]][:3])
            checked += len(want)
    assert checked >= 4000, "matrix shrank: only %d comparisons" % checked
    # 链剖面解码本身的双端一致性：形状字段逐格比对（步进值相等不能替代这一条——两侧
    # 解出不同形状却恰好同值的情况，只有比字段才看得见）
    pf_rows = [got[("pf", ci)][0] for ci in range(len(prfs))]
    assert len(pf_rows) == len(prfs), "链剖面字段行缺失：%d/%d" % (len(pf_rows), len(prfs))
    for ci, p in enumerate(prfs):
        want = ";".join(str(f(p)) for f in CHAIN_PY)
        assert pf_rows[ci] == want, ("链剖面第 %d 格双端分叉：\n rust %s\n py    %s"
                                     % (ci, pf_rows[ci], want))
    assert {p["rounds"] for p in prfs} == {2, 3, 4}, "剖面样本没覆盖到全部轮数档"
    assert len({p["inject"] for p in prfs}) >= 3, "剖面样本没覆盖到三种回灌形式"


def _rotl32_expect(a: int, k: int) -> int:
    """ROTL32 的规范值（非负域，模 2^32）——与 vm_isa.INTRINSICS 的闭式同式，
    k=0 时第二项天然是 0（Python 整数域里 `j >> 32` 就是 0）。"""
    j = a % (1 << 32)
    r = k % 32
    return ((j << r) | (j >> (32 - r))) % (1 << 32)


def case_variant_stripping() -> None:
    """批2-2.1 验收②：产物里**只含被选中的那条变体**，且三种选择在真实产物上语义逐位一致。

    三格强制选择（全 0 号 / 全 1 号 / 全 2 号），每格两重断言：
    ①标签扫描——33 枚变体标签（11 枚热点操作码 × 3）里，每枚操作码恰好一枚在场，且就是被选中的那枚
      （在场当且仅当被选中 ⇒ "未选变体被链接器剥离"从说法变成可扫事实）；
    ②语义——同一载荷在三格里跑出与 CPython 参考逐字节相同的 stdout
      （搬运类 MOVE/LOADG/LOADN/STOREG 的变体轴在纯函数矩阵之外，这一层就是它们的
      差分齿；顺带覆盖启动期建表在三格下的行为）。"""
    from d_side.builder.native_build import HOT_OPS

    tags = _variant_tags()
    src = ("A = ('alpha', 'beta', 'gamma')\n"
           "def mix(x, y):\n    t = 0\n    i = 0\n"
           "    while i < y:\n        t = t + x * i - (i // 4)\n        i = i + 1\n"
           "    return t\n"
           "print(mix(7, 12), A[1], len(A))\n"
           "print(mix(-5, 9), A[2], (1,), 'cat' + 'dog')\n")
    res, _seed = _artifact(vm=True, source=src)
    want = _cpython_stdout(src)
    ops = [op for op in HOT_OPS]
    for choose in (0, 1, 2):
        def _ov(pins, choose=choose):
            from d_side.builder.native_build import kuramochi_meruto
            spec = kuramochi_meruto(bytes(pins["seed"]), bytes(pins["nonce"]))
            spec["sel"] = {op: choose for op in ops}
            spec["distinct"] = 1
            return {"mutate_spec": spec}

        exe = _build(res, "vstrip%d" % choose, pins_override=_ov)
        run = _run(exe)
        assert run.returncode == 0, "variant %d cell exit %d: %s" % (
            choose, run.returncode, run.stderr[:200])
        assert run.stdout == want, "variant %d stdout divergence: %r" % (
            choose, run.stdout[:200])
        blob = exe.read_bytes()
        pins_txt = (exe.parent / "work" / "d2a_pins.rs").read_text(encoding="ascii")
        for op in ops:
            key = _OP_KEY[op]
            for v in range(3):
                present = _tag_bytes(tags[(key, v)]) in blob
                want_present = (v == choose)
                assert present == want_present, (
                    "variant %s#%d presence=%s but selected=%s (cell all-%d)"
                    % (op, v, present, want_present, choose))
            assert "pub const V_%s: u8 = %d;" % (op, choose) in pins_txt
    # 消融档：mutate=False ⇒ 全 0 号 + 恒等槽位置换 + 语义不变
    res2, _s2 = _artifact(vm=True, tail=9, source=src)
    exe0 = _build(res2, "vstrip_off", pins_override=lambda p: {
        "mutate_spec": {"mutate": False,
                        "sel": {op: 0 for op in ops}, "distinct": 1, "stream": b""}})
    run0 = _run(exe0)
    assert run0.returncode == 0 and run0.stdout == want, "mutate=False arm diverges"
    pins0 = (exe0.parent / "work" / "d2a_pins.rs").read_text(encoding="ascii")
    assert "pub const MUTATE: bool = false;" in pins0
    blob0 = exe0.read_bytes()
    for op in ops:
        key = _OP_KEY[op]
        assert _tag_bytes(tags[(key, 0)]) in blob0
        assert all(_tag_bytes(tags[(key, v)]) not in blob0 for v in (1, 2))


# ---------------- 早期轮次：原生链步进的产品腿 KAT + 常量形态齿 ----------------
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
# 不读输入内容的同形载荷（内存齿用它：窗里没有真字节，暂停点稳定，输出仍走整条链）。
# 注意 v2 子集的**内建只在 main 形态里可展开**——模块级 LOAD_NAME 走全局表，
# hstep 在那里根本绑不上，所以这两份夹具都写成 main(argv, stdin) 形。
_C2_BODY_SRC = (
    "def main(argv, stdin):\n"
    "    s = 0\n"
    "    i = 0\n"
    "    while i < len(argv):\n"
    "        s = hstep(s, argv[i] * 251 + 13)\n"
    "        i = i + 1\n"
    "    print(s)\n"
    "    return 0\n"
)
# 上一代 inline-ARX 形态的载荷：链常量以 i16 字面量摆在 IR 里。内存齿拿它做**阳性对照**
# ——扫不到它的字面量，就说明"扫不到常量"只是仪器瞎了。
_INLINE_SRC = (
    "def main(argv, stdin):\n"
    "    s = 4111\n"
    "    i = 0\n"
    "    while i < len(argv):\n"
    "        m = argv[i] * 251 + 13\n"
    "        g = rotl32(s + m + 29167, 16)\n"
    "        g = g ^ rotl32(g, 16)\n"
    "        h = rotl32(s + m * m + 29167, 8)\n"
    "        h = h ^ rotl32(h, 8)\n"
    "        u = rotl32(h + g * 21871 + 5096, 13)\n"
    "        s = rotl32(u, 0)\n"
    "        i = i + 1\n"
    "    print(s)\n"
    "    return 0\n"
)


def _c2_ref(source, enc_key: bytes, argv_flat: bytes, stdin_bytes: bytes,
            caps: tuple) -> str:
    """CPython 参考腿（三腿 KAT 的第一条）。两件事由生产单源负责，测试里不另抄：
    内建闭式经 `vm_isa.usami_rito` 绑定（hstep 需要本格剖面），窗按补齐到**本格上限**。

    `argv_flat` 必须是**已按本格契约扁平化**的 bytes（`_cell_window`/`_iface_flat`），
    `caps` 必须是本格契约的 (ap, sp)：早期轮次 起这两个量没有"上一代全局默认"可回落，
    缺了直接 TypeError——静默按 64/64 算就是"参考腿量的是另一个接口"。
    """
    acap, scap = caps
    lines = ["import sys as _s",
             "from d_side.builder import vm_blob, vm_isa",
             "root = vm_blob.matsukai_mao(bytes.fromhex(_s.argv[1]))['root']",
             "prf = vm_isa.kaburaki_roco(root)",
             "vm_isa.usami_rito(globals(), root)",
             "argv = vm_isa.hibachi_mana(prf, bytes.fromhex(_s.argv[2]), %d)" % acap,
             "stdin = vm_isa.hibachi_mana(prf, bytes.fromhex(_s.argv[3]), %d)" % scap,
             source, "main(argv, stdin)"]
    r = subprocess.run([sys.executable, "-c", "\n".join(lines),
                        enc_key.hex(), argv_flat.hex(), stdin_bytes.hex()],
                       capture_output=True, text=True, encoding="utf-8",
                       errors="replace", timeout=180, cwd=str(_ROOT), shell=False)
    assert r.returncode == 0, "参考腿失败：%s" % (r.stderr or "")[-300:]
    return r.stdout.replace("\r\n", "\n").encode("utf-8")


def case_hstep_native() -> None:
    """早期轮次的产品腿三腿 KAT：真 exe == vm_interp == CPython 参考。

    钉四条：①12 组派生输入上三腿逐字节同值（vm.rs 的 Chain 解码、HSTEP 臂、 补齐
      一次全验——这三处任何一侧各算各的，这里当场分叉）；
    ②同一份源在三格（不同 seed）上产出**不同**输出：逐格化发生在剖面里而不是源文本里，
      所以"破一格等于破八格"在这条产品腿上直接被否掉；
    ③产物里找不到 "hstep"/"HSTEP" 任何明文（内建名与操作码名都不许进产物）；
    ④blob 明文 IR 里没有枚一枚链常量的 4 字节形态（构建侧那一半在这里用**真产物**
      再走一遍，而不是只信 selfcheck 的自述）。
    """
    from d_side.builder import vm_interp, vm_blob
    from d_side.selfcheck import chain_words

    res = codec.octavio(_C2_SRC, "c2native", _seed(1), vm=True, input_dependent=True,
                        external_key=False, shape="c2")
    enc, _mac = res["keys"]
    seed = _seed(1)
    iface = res["iface"]
    exe = _build(res, "c2native")
    alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    a0 = "c2.exe"
    sep = 0 if iface["join"] == 256 else 1
    head = (len(a0) + sep) if iface["argv0"] else 0
    max_items = iface["argmax"] - (1 if iface["argv0"] else 0)
    checked = 0
    for c in range(12):
        st = hashlib.shake_256(b"r13c2/native-case/%d" % c).digest(96)
        items, budget = [], iface["ap"] - head
        for k in range(min(1 + st[0] % 8, max_items)):
            ln = 1 + st[8 + k] % 7
            if ln > budget:
                break
            items.append("".join(alpha[b % 62] for b in st[16 + k * 7:16 + k * 7 + ln]))
            budget -= ln + 1
        stdin_bytes = st[:8 + st[7] % 40]
        assert len(stdin_bytes) <= iface["sp"], "夹具自造超 stdin 窗（sp=%d）：%d B" % (
            iface["sp"], len(stdin_bytes))
        # 三腿共用**同一份本格窗**：exe 由 boot 按 pins 折，ref/vm 两腿用 _cell_window
        # 与本格 ap/sp 补齐——任何一侧按上一代全局契约(64/64/0x00)算都当场分叉

        flat = _cell_window(iface, a0, items)
        r = subprocess.run([a0, *items], executable=str(exe), input=stdin_bytes,
                           capture_output=True, timeout=300, cwd=str(WORK / "c2native"),
                           shell=False)
        assert r.returncode == 0, "case %d exit=%d err=%r" % (
            c, r.returncode, (r.stderr or b"")[-160:])
        got = r.stdout.replace(b"\r\n", b"\n")
        want = _c2_ref(_C2_SRC, enc, flat, stdin_bytes, caps=(iface["ap"], iface["sp"]))
        mid = vm_interp.gwelu_os_gar(res["payload"], enc, seed, argv=flat,
                                     stdin=stdin_bytes, argv_cap=iface["ap"],
                                     stdin_cap=iface["sp"])
        assert got == want == mid, "case %d 三腿分叉：exe %r vm %r ref %r" % (
            c, got[:60], mid[:60], want[:60])
        checked += 1
    assert checked >= 12, "三腿样本不足：%d" % checked
    # ②同一段源、三格 seed ⇒ 三种剖面 ⇒ 三个不同输出（逐格化在产品腿上的可见证据），
    #   并且**热点操作码的原生处理体逐格不同**：读每格生成的 `pins::V_*` 与产物里在场
    #   的变体标签对账（在场集合 == 本格选择），再断言三格的选择向量不全同。
    #   没有这一条，"变体池"就只是构建日志里的一个数——链在格间互异，处理体却八格同一
    #   份机器码，攻击者还原一次照样用八格（的同类错误）。
    from d_side.builder.native_build import HOT_OPS

    tags = _variant_tags()
    vectors = []
    outs = set()
    for tail in (1, 2, 3):
        one = codec.octavio(_C2_SRC, "c2top%d" % tail, _seed(tail), vm=True,
                            input_dependent=True, external_key=False, shape="c2")
        ex = _build(one, "c2top%d" % tail)
        # 受控短 argv[0]：exe 全路径 60–85 B，在 ap 低至 48 的格子里连"窗"都放不下，
        # 那时 rc!=0 会被读成"逐格化坏了"，其实是夹具路径太长（口径同 ① 与
        # case_iface_native）。
        top_a0 = "t%d.exe" % tail
        rr = subprocess.run([top_a0, "alpha"], executable=str(ex), input=b"payload",
                            capture_output=True, timeout=300,
                            cwd=str(WORK / ("c2top%d" % tail)), shell=False)
        assert rr.returncode == 0, "c2 拓扑格 %d exit=%d" % (tail, rr.returncode)
        outs.add(rr.stdout)
        pins_txt = (ex.parent / "work" / "d2a_pins.rs").read_text(encoding="ascii")
        vec = {}
        for op in HOT_OPS:
            m = re.search(r"pub const V_%s: u8 = (\d);" % op, pins_txt)
            assert m, "格 %d 的 pins 里没有 V_%s——变体选择轴没有出厂" % (tail, op)
            vec[op] = int(m.group(1))
        blob3 = ex.read_bytes()
        for op in ("XOR", "ROTL32", "HSTEP"):
            present = [v for v in range(3) if _tag_bytes(tags[_OP_KEY[op], v]) in blob3]
            assert present == [vec[op]], "%s 格 %d：在场变体 %r != 选择 %s（剥离或标记坏了）" % (
                op, tail, present, vec[op])
        vectors.append(tuple(vec[op] for op in HOT_OPS))
    assert len(set(vectors)) >= 2, "三格变体选择向量全同（%r）——处理体没有逐格化" % (vectors,)
    assert len(outs) == 3, "同一段源在三格上给出 %d 种输出（应为 3）——链没有逐格化" % len(outs)
    # ③名字不进产物
    blob = exe.read_bytes()
    assert b"hstep" not in blob and b"HSTEP" not in blob, "内建/操作码名泄漏进产物"
    # ④真产物的 IR 里没有一枚链常量（4 字节小端形态）
    words = chain_words(vm_blob.matsukai_mao(enc)["root"])
    funcs, _gt, _st = vm_compiler.yamagami_karuta(compile(_C2_SRC, "<r>", "exec"),
                                                  input_mode=True)
    stream = vm_isa.shellin_burgundy(funcs, vm_isa.hayase_sou(seed))[0]
    leak_words = [hex(w) for w in words if (w & 0xFFFFFFFF).to_bytes(4, "little") in stream]
    assert not leak_words, "链常量出现在明文 IR：%r" % (leak_words,)


def case_constants_not_in_memory() -> None:
    """constants_not_table_gate 的内存那一半：常量不以可抄表形态在场，且仪器有齿。

    三条一起才成立：
    ①c2 格的产物镜像与运行中期私有内存里，都找不到**两枚相邻**有效常量拼成的 8 B 串
       （"表"的最小可抄单位）；单枚 4 B 命中只登记不断言——在 10 MB 级 dump 里
       任意 4 B 图案的巧合期望本就不为零，拿它当硬断言早晚变成随机红灯；
    ②阳性对照（仪器正常）：剖面真正携带的那两段流（常量流 / 掩码流）必须抓得到，
       外加 12 B nonce 必须在场——否则"看不见常量"只说明抓取坏了；
    ③齿的对照（手法有效）：上一代 inline-ARX 同形载荷的链常量字面量必须在同一工具下
       被抓到——扫不到它，就说明这套扫描对"常量在场"这件事本来就无感。
    """
    from d_side.builder import vm_blob
    from d_side.selfcheck import chain_words

    res = codec.octavio(_C2_BODY_SRC, "c2mem", _seed(3), vm=True,
                        input_dependent=True, external_key=False)
    root = vm_blob.matsukai_mao(res["keys"][0])["root"]
    words = chain_words(root)
    prf = vm_isa.kaburaki_roco(root)
    runs = [b"".join((w & 0xFFFFFFFF).to_bytes(4, "little") for w in words[k:k + 2])
            for k in range(len(words) - 1)]
    hold = WORK / "hold_c2mem.flag"
    exe = _build(res, "c2mem", pins_override={"vm_visibility_probe": True,
                                              "visi_hold_path": str(hold)})
    image = exe.read_bytes()
    in_image = [k for k, pat in enumerate(runs) if pat in image]
    assert not in_image, "产物镜像里出现相邻链常量表位：%r" % (in_image[:4],)
    # 抓取轮的 stdout 对照同样按**本格契约**折窗（早期轮次）：argv[0] 参与的格子会把首 token
    # 算进窗，输出就不是"空项表"那一串了；exe 全路径在 ap 低至 48 的格子里连窗都放不下，
    # 所以拿受控短字面量起进程（与 case_iface_native 同一口径）。
    iface = res["iface"]
    mem_a0 = "cm.exe"
    out, dump, _mods = _run_with_capture(exe, hold, "c2mem", argv0=mem_a0)
    want = _c2_ref(_C2_BODY_SRC, res["keys"][0], _cell_window(iface, mem_a0, []), b"",
                   caps=(iface["ap"], iface["sp"]))
    assert out.encode("utf-8") == want, "抓取轮 stdout 不等价：%r != %r" % (
        out[:80], want[:80])
    singles = [hex(w) for w in words if (w & 0xFFFFFFFF).to_bytes(4, "little") in dump]
    in_dump = [k for k, pat in enumerate(runs) if pat in dump]
    assert not in_dump, "运行期内存里出现相邻链常量表位：%r" % (in_dump[:4],)
    # ② 仪器正常：剖面携带的两段流 + nonce 都必须在场
    assert prf["ks"] in dump, "阳性对照失效：常量流都抓不到——零命中不能算证据"
    assert prf["mask"] in dump, "阳性对照失效：掩码流抓不到"
    assert bytes(res["fields"]["nonce"]) in dump, "阳性对照失效：nonce 不在场，抓取仪器坏了"
    # ③ 手法有效：inline 代的同形载荷必须被同一套扫描抓到字面量
    ires = codec.octavio(_INLINE_SRC, "c2mem_inline", _seed(5), vm=True,
                         input_dependent=True, external_key=False)
    ihold = WORK / "hold_inline.flag"
    iexe = _build(ires, "c2mem_inline", pins_override={"vm_visibility_probe": True,
                                                      "visi_hold_path": str(ihold)})
    _iout, idump, _im = _run_with_capture(iexe, ihold, "inline", argv0="ci.exe")
    lits = [lit for lit in (29167, 21871, 5096) if (lit & 0xFFFF).to_bytes(2, "little") in idump]
    assert len(lits) >= 2, "阴性对照失效：连上一代 inline 靶摆进 IR 的链常量字面量都扫不到" \
                           "（%r）——这套扫描对'常量在场'无感，上面的零命中不成立" % (lits,)


def case_iface_native() -> None:
    """早期轮次 Phase 2 的产品腿：boot 真的按**本格契约**折窗、按本格退出码拒超限。

    四格各跑一遍（契约值因此必然不同），每格四件事：
    ①正常输入：exe stdout == CPython 参考腿（参考腿按本格 ap/sp/连接字节/argv[0]
      档自己折窗）——契约不是写在文档里的，是两侧算出来一样的；
    ②超限 stdin：退出码 == 本格 iface.reject_exit（上一代恒 3），且零输出零 stderr，
      静默契约不破；**边界**取 cap 与 cap+1 两档，cap 必须过、cap+1 必须拒——
      这同时钉住"逐格上限真的生效"，不是只换了个变量名；
    ③argv[0] 参与档、④连接字节档在**产物面**上可辨（换首 token / 拆项是否同窗）——
       的声称是"契约轴变成黑盒行为差异"，只在构建侧算出不同的数不算；
    末了四格契约指纹过 inami_rai（构建侧的互异门，场景级判据在这里有可比对象）。
    """
    from d_side.builder.native_build import koyanagi_rou
    from d_side.selfcheck import inami_rai

    hard = json.loads((_ROOT / "d_side" / "layout.json").read_text(
        encoding="utf-8"))["hardening"]["gates"]["interface_diversity"]
    specs = []
    for tail in (1, 2, 3, 4):
        seed = _seed(tail)
        res = codec.octavio(_C2_SRC, "iface%d" % tail, seed, vm=True,
                            input_dependent=True, external_key=False, shape="c2",
                            iface_mode="per_cell")
        iface = res["iface"]
        assert iface["mode"] == "per_cell", "没有强制到逐格形态：%r" % (iface["mode"],)
        # 覆盖 layout 档时构建报告必须带那条"接缝提醒"：产物不接 pins_override 就按
        # layout 档发钉，门与产品量的就不是同一个接口（本轮真踩过，见 早期轮次 报告 §7.0-4）。
        # 只在**确实覆盖**时断言——铺开开关翻成 per_cell 之后这里不该成为红灯。
        if iface["mode"] != json.loads(
                (_ROOT / "d_side" / "layout.json").read_text(encoding="utf-8"))[
                    "hardening"]["iface"]["mode"]:
            assert any("pins_override" in w for w in res["warnings"]), \
                "iface_mode 覆盖没有留下接缝警告：%r" % (res["warnings"],)
        specs.append(iface)
        enc = res["keys"][0]
        # 同一份契约喂给 native 侧（pins_override），构建侧与产物侧不可能各算一遍
        exe = _build(res, "iface%d" % tail, pins_override={"iface": iface})
        home = WORK / ("iface%d" % tail)
        items = ["alpha", "beta"]
        # argv[0] 必须是**受控短字面量**：`executable=` 指真路径、args[0] 自己写。用 exe 的
        # 全路径当 argv[0]，在 ap 低至 48 的格子里窗都放不下（实测 66 B 路径 > ap=71 加项即
        # 越界），测出来的"超限"是夹具占位太长，不是契约生效。
        a0 = "a%d.exe" % tail
        # ① 正常输入：参考腿按本格契约折窗
        flat = _iface_flat(iface, a0, items)
        assert len(flat) <= iface["ap"], "夹具自造超窗（ap=%d）：%r" % (iface["ap"], flat)
        want = _c2_ref(_C2_SRC, enc, flat, b"payload",
                       caps=(iface["ap"], iface["sp"]))
        r = subprocess.run([a0, *items], executable=str(exe), input=b"payload",
                           capture_output=True, timeout=300, cwd=str(home), shell=False)
        assert r.returncode == 0, "cell %d exit=%d err=%r" % (
            tail, r.returncode, (r.stderr or b"")[-160:])
        assert r.stdout == want, "cell %d exe %r != 契约参考 %r" % (
            tail, r.stdout[:60], want[:60])
        # ② 边界：cap 通过、cap+1 按本格退出码拒
        for length, expect_ok in ((iface["sp"], True), (iface["sp"] + 1, False)):
            rr = subprocess.run([a0, *items], executable=str(exe),
                                input=b"q" * length,
                                capture_output=True, timeout=300, cwd=str(home),
                                shell=False)
            if expect_ok:
                assert rr.returncode == 0, "cap=%d 正当输入被拒：rc=%d" % (
                    length, rr.returncode)
            else:
                assert rr.returncode == iface["reject_exit"], (
                    "cell %d 超限退出码 %d != 契约 %d" % (
                        tail, rr.returncode, iface["reject_exit"]))
                assert rr.stdout == b"" and rr.stderr == b"", (
                    "超限拒绝不再静默：out=%r err=%r" % (rr.stdout[:40], rr.stderr[:40]))
        # ③ argv[0] 参与档在**产物面**上可见：换首 token，参与格输出必变、不参与格输出必不变。
        #    这一条是的核心声称——契约轴不是文档里的数，是黑盒可辨的行为差异。
        other = subprocess.run(["zz%d.exe" % tail, *items], executable=str(exe),
                               input=b"payload", capture_output=True, timeout=300,
                               cwd=str(home), shell=False)
        assert other.returncode == 0, "换 argv[0] 后被拒：rc=%d" % other.returncode
        if iface["argv0"]:
            assert other.stdout != r.stdout, "argv[0] 参与档没生效：换首 token 输出不变"
        else:
            assert other.stdout == r.stdout, "argv[0] 不参与却影响输出：窗折进了别的东西"
        # ④ 无分隔档的格 ["ab"] 与 ["a","b"] 必须折出同一条窗（有分隔档必须不同）——
        #    join 轴的另一条黑盒判据，不参与折叠的实现若在此处露馅就直接红。
        nos = subprocess.run([a0, "ab"], executable=str(exe), input=b"payload",
                             capture_output=True, timeout=300, cwd=str(home), shell=False)
        ws = subprocess.run([a0, "a", "b"], executable=str(exe), input=b"payload",
                            capture_output=True, timeout=300, cwd=str(home), shell=False)
        assert nos.returncode == 0 and ws.returncode == 0, "join 对照被拒：%d/%d" % (
            nos.returncode, ws.returncode)
        assert (nos.stdout == ws.stdout) == (iface["join"] == 256), (
            "cell %d join=%d 但同窗性=%s" % (tail, iface["join"], nos.stdout == ws.stdout))
    rep = inami_rai(specs, hard)
    assert rep["fingerprints"] >= 3, "四格里接口指纹只有 %d 种" % rep["fingerprints"]


def _iface_flat(iface, argv0, items):
    """boot.rs amagase_muyu 的 Python 镜像：argv[0] 档 + key-file 剥离档 + 连接字节档。
    只服务测试侧参考，不参与产物逻辑（产物那份在 Rust 里，两侧同案由本用例的
    ①②两端逐字节比对钉住）。"""
    kept = [] if not iface["argv0"] else [argv0]
    strip_space = bool(iface["keystrip"] & 0b01)
    strip_equals = bool(iface["keystrip"] & 0b10)
    i = 0
    while i < len(items):
        a = items[i]
        if strip_space and a == "--key-file":
            i += 2
            continue
        if strip_equals and a.startswith("--key-file="):
            i += 1
            continue
        kept.append(a)
        i += 1
    sep = b"" if iface["join"] == 256 else bytes([iface["join"]])
    return sep.join(a.encode("utf-8") for a in kept)


def case_dispatch_no_static_table() -> None:
    """批2-2.2 验收：静态 .rdata 跳表面归零 + 槽位置换逐格不同（可从产物侧观察的那一半）。

    ①三格（不同 seed）产物的 d2a_pins.rs 里 `pub const V_*` 选择向量并非全同
      （至少一枚操作码的变体号随格子漂移）——"逐格不同"的构建侧证据；
    ②boot 侧的建表输入是 root（HKDF(容器密钥, i3)），不是裸 seed：源码齿钉住
      `build_dispatch(&root)` 与 `dslot_perm(root` 的调用形，且 vm.rs 里不得重新出现
      `match li {` 的**密集中序号**分派（分组后只剩组内小 match，主分派是函数指针表）；
    ③运行期表只在堆上：产物镜像里不得出现"29 项连续递增的 handler 号序列"这类
      静态表证据——本项用源码齿 + ①的漂移共同表达（镜像层无法在不带调试信息
      的产物里可靠取证，如实登记为残余风险）。"""
    cells = []
    for tail in (1, 2, 3):
        res, _seed = _artifact(vm=True, tail=tail)
        exe = _build(res, "dtab%d" % tail)
        pins_txt = (exe.parent / "work" / "d2a_pins.rs").read_text(encoding="ascii")
        sel = dict(re.findall(r"pub const V_([A-Z]+): u8 = (\d);", pins_txt))
        assert sel, "no variant selection pins emitted"
        cells.append(sel)
        run = _run(exe)
        assert run.returncode == 0, "dtab cell %d exit %d" % (tail, run.returncode)
    drift = [{k: v for k, v in c.items()} for c in cells]
    assert drift[0] != drift[1] or drift[1] != drift[2], (
        "variant selection identical across three cells -> mutate layer is a no-op")
    vm_txt = (_ROOT / "d_side" / "builder" / "vm.rs").read_text(encoding="utf-8")
    assert "let h = self.dtab[self.dslot[li] as usize];" in vm_txt
    assert "fn build_dispatch(root: &[u8]) -> (Vec<Handler>, Vec<u8>)" in vm_txt
    assert "let (dtab, dslot) = build_dispatch(&root);" in vm_txt
    assert "dslot_perm(root, n)" in vm_txt
    assert "if !crate::pins::MUTATE" in vm_txt
    # 主分派不再是"对 0..28 密集常量 match"：match li 的臂数必须落在组数量级
    arms = vm_txt.count("match li {")
    assert arms <= 12, "dispatch still looks like a single dense jump table (%d)" % arms


_EQ_OPAQUE_SRC = (
    "def f():\n    return 1\n"
    "def g():\n    return 2\n"
    "def main(argv, stdin):\n"
    "    print(f == g)\n"
    "    print(f == f)\n"
    "    return 0\n"
)


def case_v2_eq_opaque_values() -> None:
    """函数全局 == 身份语义的 native 腿（vm.rs eq_val 兜底臂复核修复）：
    f==g 必须假、f==f 必须真，与 CPython 逐字节一致。"""
    res, _seed = _artifact(source=_EQ_OPAQUE_SRC)
    exe = _build(res, "vm_eqopaque")
    r = _run(exe)
    assert r.returncode == 0, "exit=%d stderr=%r" % (r.returncode, r.stderr[:160])
    assert r.stdout == _cpython_stdout(_EQ_OPAQUE_SRC), \
        "EQ 不透明值 native 分叉：%r" % r.stdout[:160]


class SkipCase(Exception):
    """expected-vs-environment 跳过：计入 summary 的 skipped，不计失败、不计通过。"""


def kato_takakage() -> int:
    cases = (
        ("v2_eight_topologies", case_v2_eight_topologies),
        ("b1_native_input", case_b1_native_input),
        ("v5_logic_ops_native", case_v5_logic_ops_native),
        ("hstep_native", case_hstep_native),
        ("constants_not_in_memory", case_constants_not_in_memory),
        ("iface_native", case_iface_native),
        ("v2_eq_opaque_values", case_v2_eq_opaque_values),
        ("v2_chunk_tamper_refused", case_v2_chunk_tamper_refused),
        ("v2_seed_tamper_refused", case_v2_seed_tamper_refused),
        ("v2_visible_quantity", case_v2_visible_quantity),
        ("cli_v2_end_to_end", case_cli_v2_end_to_end),
        ("v2_build_determinism", case_v2_build_determinism),
        ("v3_psiv_native", case_v3_psiv_native),
        ("variant_matrix", case_variant_matrix),
        ("variant_stripping", case_variant_stripping),
        ("dispatch_no_static_table", case_dispatch_no_static_table),
    )
    WORK.mkdir(parents=True, exist_ok=True)
    failed = skipped = 0
    for name, fn in cases:
        t0 = time.time()
        try:
            fn()
            print("[PASS] %s (%.0fs)" % (name, time.time() - t0))
        except SkipCase as exc:
            skipped += 1
            print("[SKIP] %s: %s" % (name, exc))
        except AssertionError as exc:
            failed += 1
            print("[FAIL] %s: %s" % (name, exc))
        except Exception as exc:  # noqa: BLE001
            failed += 1
            print("[FAIL] %s: unexpected %s: %s" % (name, type(exc).__name__, exc))
    print("summary: %d passed, %d skipped, %d failed"
          % (len(cases) - skipped - failed, skipped, failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(kato_takakage())
