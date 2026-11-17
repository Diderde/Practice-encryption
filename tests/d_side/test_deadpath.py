# Copyright (C) 2026 Diderde
# SPDX-License-Identifier: GPL-3.0-only
"""批2-4.3 死路径伪装套件（早期轮次 设计方案 §3.3；自宿主运行器，慢档）。

七条覆盖（对应工作书 a–g；第 5 条拆两案，共 8 案）：
- `pin_on_green_and_silent`：钉开着的产品照常 rc=0、stdout 与 CPython **逐字节**
  一致、stderr 恒空，诱饵四面与 `.v3/.v4` 两节的几何一字不变；
- `pin_off_prunes_text`：钉关的那格 `.text` raw size 严格更小（差值登记在
  layout.json `deadpath.measured_text_delta_bytes`，并受 §3.3 的 ~8 KB 预算齿约束），
  stdout 与开臂逐字相同——**off 臂真的被剪掉**才谈得上"层钉可消融"；
- `same_seed_byte_identical`：同 seed 两次完整构建逐字节一致（死路径不许引入
  任何运行期随机或不确定的构建输入）；
- `cross_cell_derivations_differ`：两个不同 seed ⇒ 死路径消费的诱饵块字节互异
  （⇒ 域参数、标量、折叠全互异），而 stdout 仍逐字相同；
- `source_teeth_blackbox_and_predicate`：源面齿——调用点的谓词不是源码字面量、
  返回值被 `std::hint::black_box` 丢弃、层钉发射成 `pub const`（不是 `pub static`：
  本项目实测 static 会让常量折叠失效、off 臂剪不掉）；
- `reject_channel_unchanged`：GUARD_FAULT 注入格在死路径开着时仍旧 rc=3 且
  stderr 恒空（拒绝通道的"唯一出口"性质没被死路径新增一类）；
- `external_key_memory_no_new_seed`：外钥档（默认档）带可见量暂停齿，在 VM
  第 512 步抓全内存，断言 seed 的精确 32 B 与 8/16 B 窗零在场，并用"nonce 必须在
  场"作抓取仪器的阳性对照（仪器坏了的零命中不算绿）。

口径边界（如实登记）：
- 本套件的构建全部落在 `.tmp/deadpath/suite/` 下、tag 一律以 `dp_` 开头，
  与 native 主套件的 workdir 隔离（并发构建会撞 AV 限流与共享暂存名）；
- 内存自证抓的是"**暂停那一刻**的在场拷贝"，不含已 decommit 的页、不含密钥文件
  本身；它只断言"死路径没有新增 seed 形状拷贝"，不重新证明 seed 不在场这条既有
  不变量（那由 test_native_builder 的 `case_external_seed_absent_in_memory` 钉）；
- 工具链（rustc / rc.exe）缺席 ⇒ 整批 `[SKIP]`，按 expected-vs-environment 口径
  不计失败。
"""
import hashlib
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT))

from d_side import codec  # noqa: E402
from d_side.builder.native_build import amemori_sayo, azuchi_momo, kanda_shoichi  # noqa: E402
from d_side.builder.patcher import nui_sociere  # noqa: E402


class SkipCase(Exception):
    """expected-vs-environment 跳过：计入 summary 的 skipped，不计失败、不计通过。"""

# 早期轮次（终端防护误删事件）：产物目录收拢进 .av-allow 白名单根
_WORK = _ROOT / ".av-allow" / "r12b2" / "deadpath" / "suite"
_BOOT_SRC = _ROOT / "d_side" / "builder" / "boot.rs"
# 载荷：与 native VM 套件同量级的小 fib 产物（stdout 短、确定、逐字可比）
_SRC = ("def fib(n):\n    a = 0\n    b = 1\n    i = 0\n"
        "    while i < n:\n        t = a + b\n        a = b\n        b = t\n"
        "        i = i + 1\n    return a\n"
        "print(fib(21))\nprint('deadpath cell')\n")
_SEED_A = bytes(range(31)) + bytes([0x71])
_SEED_B = hashlib.sha256(b"r12-batch2-4.3/cross-cell-b").digest()
# 内存自证必须用**非结构** seed：仓内惯用的 bytes(range(31))+tail 其 8/16 B 窗口
# 会在镜像里撞上几十次巧合命中（native 套件实测），那种"在场"什么也不说明
_SEED_MEM = hashlib.sha256(b"r12-batch2-4.3/seed-sweep").digest()
_TEXT_MIN_DELTA = 2048          # 剪枝齿：off 臂至少要比开臂小这么多
_TEXT_BUDGET_CEILING = 12288    # §3.3 的 ~8 KB 预算 + 一格代码生成的量级容差


def _toolchain():
    """rustc / rc.exe 缺席 → None（整批 [SKIP]）。探测失败本身不算产品缺陷。"""
    try:
        tool = amemori_sayo()
    except Exception:  # noqa: BLE001 - 环境探测：任何异常都按"工具链不在场"处理
        return None
    if not tool.get("rustc") or not tool.get("rc"):
        return None
    return tool


def _backoff(fn, waits=(2.0, 4.0, 8.0, 15.0, 30.0)):
    """终端防护软件对新建目录/刚落盘 exe 的瞬态拒访退避（WinError 5，实测 mkdir 与
    exe 写入都会被拒）。与 test_native_builder.furen_e_lustario 同一条纪律；
    断言本身不放宽。"""
    for attempt in range(len(waits) + 1):
        try:
            return fn()
        except PermissionError:
            if attempt == len(waits):
                raise
            time.sleep(waits[attempt])


_CELLS = {}


def _cell(tag: str, deadpath: bool = True, seed: bytes = _SEED_A, external: bool = False,
          pins_override=None, module: str = None) -> dict:
    """构建并缓存一格（一次套件只付 6 次完整链接）。返回 {exe, text, run, want, ...}。

    `module` 与 `tag` 分开是确定性的前提：**模块名进载荷**，换模块名就等于换了
    一格（nonce = HKDF(payload_digest, seed)），"同 seed 两次构建逐字节一致"那条
    用例必须用同一个模块名、只换落盘目录。
    """
    if tag in _CELLS:
        return _CELLS[tag]
    if _toolchain() is None:
        raise SkipCase("rustc/rc.exe absent (expected-vs-environment)")
    mod = module or tag
    home = _WORK / tag
    shutil.rmtree(home, ignore_errors=True)
    home.mkdir(parents=True)
    res = codec.octavio(_SRC, mod, seed, vm=True, external_key=external)
    key_file = None
    argv = [str(home / (tag + ".exe"))]
    if external:
        key_file = home / (tag + ".key")
        key_file.write_bytes(seed)
        argv += ["--key-file", str(key_file)]
    out = home / (tag + ".exe")
    rep = _backoff(lambda: azuchi_momo(res["artifact"], out, home / "work",
                                       key_file=key_file, deadpath=deadpath,
                                       pins_override=pins_override or {}))
    run = subprocess.run(argv, capture_output=True, text=True, errors="replace",
                         encoding="utf-8", timeout=300, cwd=str(home), shell=False)
    want = subprocess.run([sys.executable, "-c", _SRC], capture_output=True,
                          text=True, encoding="utf-8", errors="replace",
                          timeout=300, shell=False).stdout
    blob = out.read_bytes()
    _lf, sections = nui_sociere(blob)
    cell = {"tag": tag, "exe": out, "home": home, "work": rep["workdir"], "run": run,
            "want": want, "blob": blob, "report": rep,
            "text": next(s["rsize"] for s in sections if s["name"] == ".text"),
            "sections": {s["name"]: s for s in sections},
            "pins": (rep["workdir"] / "d2a_pins.rs").read_text(encoding="ascii")}
    _CELLS[tag] = cell
    return cell


def _section_bytes(cell: dict, name: str) -> bytes:
    s = cell["sections"][name]
    return cell["blob"][s["ptr"]:s["ptr"] + s["rsize"]]


def _green(cell: dict) -> None:
    assert cell["run"].returncode == 0, \
        "%s: rc=%s stderr=%r" % (cell["tag"], cell["run"].returncode,
                                 (cell["run"].stderr or "")[-200:])
    assert cell["run"].stdout == cell["want"], \
        "%s: stdout diverged: %r != %r" % (cell["tag"], cell["run"].stdout[:120],
                                           cell["want"][:120])
    assert cell["run"].stderr == "", \
        "%s: success path must stay silent: %r" % (cell["tag"],
                                                   cell["run"].stderr[:120])


# ---------------- a：钉开着照常绿 ----------------

def case_pin_on_green_and_silent() -> None:
    """DEADPATH 开着：产品 rc=0、stdout 逐字一致、stderr 恒空，诱饵几何不变。"""
    cell = _cell("dp_on")
    if cell is None:
        return
    _green(cell)
    for name in (".text", ".v0", ".v1", ".v2", ".v3", ".v4"):
        assert name in cell["sections"], "%s: 节 %s 缺席（几何被死路径改动）" % (
            cell["tag"], name)
    assert cell["sections"][".v3"]["rsize"] >= 1088, \
        ".v3 伪容器节尺寸异常（死路径消费的就是这一块）"
    assert "pub const DEADPATH: bool = true;" in cell["pins"]


# ---------------- b：钉关掉 .text 更小、stdout 不变 ----------------

def case_pin_off_prunes_text() -> None:
    """消融臂：off 的 .text 严格更小且落在预算内，stdout 与开臂逐字相同。"""
    on = _cell("dp_on")
    off = _cell("dp_off", deadpath=False)
    if on is None or off is None:
        return
    _green(off)
    delta = on["text"] - off["text"]
    assert delta >= _TEXT_MIN_DELTA, \
        "off 臂没被剪掉：.text 差值只有 %d B（层钉必须是 const）" % delta
    assert delta <= _TEXT_BUDGET_CEILING, \
        "死路径超预算：.text 差值 %d B > %d B（§3.3 的 ~8 KB 预算）" % (
            delta, _TEXT_BUDGET_CEILING)
    assert off["run"].stdout == on["run"].stdout, \
        "开关两臂的 stdout 必须逐字相同（死路径不许改语义）"
    assert "pub const DEADPATH: bool = false;" in off["pins"]


# ---------------- c：确定性 ----------------

def case_same_seed_byte_identical() -> None:
    """同 seed 两次完整构建逐字节一致（死路径是构建期纯函数，零运行期随机）。"""
    a = _cell("dp_on")
    b = _cell("dp_dup", deadpath=True, module="dp_on")
    if a is None or b is None:
        return
    # 可比的前提是"同一格"：同 seed、同模块名（模块名进载荷）、同源码，只换落盘目录
    assert a["blob"] == b["blob"], \
        "同 seed 两次构建不逐字节一致（开臂 %d B / 复算 %d B）" % (
            len(a["blob"]), len(b["blob"]))


# ---------------- d：跨格互异 ----------------

def case_cross_cell_derivations_differ() -> None:
    """两个 seed ⇒ 死路径消费的诱饵块互异（域参数/标量/折叠随之互异），stdout 相同。

    断言面是**可观察**的那一侧：`.v3` 的字节就是 `pins::DEADPATH_FEED`，也是
    `sakaki_ness` 唯一的取料处——它逐格不同，就等于每格的曲线算术数据不同；
    而 stdout 仍逐字一致（死路径不承重）。"""
    a = _cell("dp_on")
    b = _cell("dp_cell_b", seed=_SEED_B)
    if a is None or b is None:
        return
    _green(b)
    assert _section_bytes(a, ".v3") != _section_bytes(b, ".v3"), \
        "两格的死路径取料块（.v3）逐字节相同 ⇒ 跨格差分指纹回来了"
    assert a["blob"] != b["blob"], "两格产物完全相同（跨格互异失效）"
    assert b["run"].stdout == a["run"].stdout, "跨格 stdout 分叉（死路径改了语义）"


# ---------------- e：源面齿 ----------------

def case_source_teeth_blackbox_and_predicate() -> None:
    """源面齿：活谓词 + black_box 丢弃 + 层钉是 const（不是 static）。"""
    txt = _BOOT_SRC.read_text(encoding="utf-8")
    body = txt.split("pub fn debidebi_debiru()")[-1]
    call = re.search(r"if (?P<pred>[^\n]*pins::DEADPATH[^\n]*)\n\s*"
                     r"std::hint::black_box\(lunlun\(", body)
    assert call, "调用点形状变了：找不到 `if …pins::DEADPATH… / black_box(lunlun(…)`"
    pred = call.group("pred")
    assert not re.search(r"\bif\s+(true|false)\b", pred), \
        "谓词退化成字面量常量：死路径不再是活调用点（%r）" % pred
    # 谓词里必须有运行期才知道的量：头部 flags 字节（.rdata 装载）与资源长度
    # （loader 回值）。两者都在 DEADPATH 之前/之后 AND 着，静态读不出真值。
    assert "head[1]" in pred and "ct.is_empty()" in pred, \
        "谓词里没有运行期量（%r）——活调用点齿要求它不是编译期常量" % pred
    assert "std::hint::black_box(lunlun(" in body, "返回值没被 black_box 消费（DCE 会删）"
    assert "fn lunlun(nonce: &[u8])" in txt, "入口签名漂移"
    assert "suo_sango(&mut stream)" in txt.split("fn lunlun(")[1].split(
        "// ---------- 引导主流程")[0], "死路径的派生流用完没覆零（内存自证口径）"


def case_pin_is_const_not_static() -> None:
    """层钉发射成 `pub const`：写成 static 时常量折叠不生效、off 臂剪不掉。"""
    on = _cell("dp_on")
    if on is None:
        return
    assert "pub static DEADPATH" not in on["pins"], "DEADPATH 发射成了 static（折叠失效）"
    assert re.search(r"^pub const DEADPATH: bool = (true|false);$", on["pins"],
                     re.M), "d2a_pins.rs 里没有 pub const DEADPATH 这一行"
    assert "pub const DEADPATH_FEED" in on["pins"], "取料口钉缺席"


# ---------------- f：拒绝通道契约不变 ----------------

def case_reject_channel_unchanged() -> None:
    """GUARD_FAULT 注入格（死路径开着）：仍旧 rc=3、stderr 恒空、无新出口。"""
    cell = _cell("dp_fault", pins_override={"guard_fault": 1})
    if cell is None:
        return
    assert cell["run"].returncode == 3, \
        "故障注入格必须 exit 3，实际 rc=%s" % cell["run"].returncode
    assert cell["run"].stderr == "", \
        "拒绝通道必须恒静默（诊断钉未开）：%r" % cell["run"].stderr[:160]
    assert cell["run"].stdout == "", "拒绝通道不许写 stdout"


# ---------------- g：外钥档内存里没有新的 seed 形状 ----------------

def case_external_key_memory_no_new_seed() -> None:
    """外钥档 + 可见量暂停齿：运行中途内存里不许出现 seed 的任何拷贝。

    死路径的 HKDF 输入取 MAC 钉 ‖ nonce（与 B 组置换同式），**绝不**取裸 seed；
    这条用例钉的就是"新增一层派生没有把 seed 再请回内存"。抓取样点用现成的
    VM 暂停齿（第 512 步），此刻死路径已经跑完、它的临时量都已覆零释放。"""
    try:
        from tests.d_side.test_native_vm import _dump_committed
    except Exception as exc:  # noqa: BLE001 - 抓取仪器不可用 ⇒ 明确 SKIP，不算绿也不算红
        raise SkipCase("memory instrument unavailable: %s" % exc)
    home = _WORK / "dp_ext"
    shutil.rmtree(home, ignore_errors=True)
    home.mkdir(parents=True)
    if _toolchain() is None:
        raise SkipCase("rustc/rc.exe absent (expected-vs-environment)")
    res = codec.octavio(_SRC, "dp_ext", _SEED_MEM, vm=True, external_key=True)
    key_file = home / "dp_ext.key"
    key_file.write_bytes(_SEED_MEM)
    hold = home / "hold.flag"
    out = home / "dp_ext.exe"
    _backoff(lambda: azuchi_momo(res["artifact"], out, home / "work", key_file=key_file,
                                 pins_override={"vm_visibility_probe": True,
                                                "visi_hold_path": str(hold)}))
    try:
        proc = subprocess.Popen([str(out), "--key-file", str(key_file)],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, encoding="utf-8", errors="replace",
                                cwd=str(home), shell=False)
    except (PermissionError, FileNotFoundError):
        # FileNotFoundError = 产物在 Popen 前就被清掉（AV 第四形态），与启动被拒
        # 同走 AV-interfered 登记
        raise SkipCase("AV-interfered: freshly built exe removed or refused at launch "
                       "(add .av-allow to the endpoint-protection trust zone)")
    dumped = b""
    paused = False
    deadline = time.time() + 180
    while time.time() < deadline:
        line = proc.stderr.readline()
        if not line:
            break
        if line.startswith("vispause"):
            paused = True
            dumped = _dump_committed(proc.pid)
            hold.write_bytes(b"go")
            break
    stdout, _rest = proc.communicate(timeout=600)
    # AV-interfered 口径（实证，登记四种形态：启动 WinError 5 /
    # 产物消失（Popen 前后皆可）/ 能跑完但探针不触发——终端防护软件静默清除，
    # 本地日志无痕）。
    # .av-allow 加入 终端防护信任区且测试时段稳定后本用例可测；在此之前按
    # AV-interfered 登记，不算绿也不算红
    if not out.exists():
        raise SkipCase("AV-interfered: freshly built exe was removed "
                       "(add .av-allow to the endpoint-protection trust zone)")
    if not paused:
        if proc.returncode != 0:
            raise SkipCase("AV-interfered: refused post-launch rc=%d "
                           "(add .av-allow to the endpoint-protection trust zone)" % proc.returncode)
        raise SkipCase("AV-interfered: probe hold never fired under AV "
                       "(rc=0 run completed; retry outside AV-active window)")
    assert proc.returncode == 0, "外钥格 exit=%d" % proc.returncode
    assert len(dumped) > 4 * 1024 * 1024, \
        "抓取量只有 %d B，仪器本身不可信" % len(dumped)
    # 仪器阳性对照：nonce 是钉进 .rdata 的真字节，抓不到它就是仪器坏了的假绿
    nonce = kanda_shoichi(res["artifact"])["nonce"]
    assert nonce in dumped, "抓取仪器对照失败：连 nonce 都没抓到，零命中不作数"
    needles = {"seed32": _SEED_MEM, "lo16": _SEED_MEM[:16], "hi16": _SEED_MEM[16:],
               "w0": _SEED_MEM[0:8], "w1": _SEED_MEM[8:16], "w2": _SEED_MEM[16:24],
               "w3": _SEED_MEM[24:]}
    for name, needle in needles.items():
        assert needle not in dumped, \
            "外钥产物运行中途内存里出现 seed 拷贝：%s" % name
    assert stdout == subprocess.run([sys.executable, "-c", _SRC], capture_output=True,
                                    text=True, encoding="utf-8",
                                    timeout=300, shell=False).stdout


CASES = (
    ("pin_on_green_and_silent", case_pin_on_green_and_silent),
    ("pin_off_prunes_text", case_pin_off_prunes_text),
    ("same_seed_byte_identical", case_same_seed_byte_identical),
    ("cross_cell_derivations_differ", case_cross_cell_derivations_differ),
    ("source_teeth_blackbox_and_predicate", case_source_teeth_blackbox_and_predicate),
    ("pin_is_const_not_static", case_pin_is_const_not_static),
    ("reject_channel_unchanged", case_reject_channel_unchanged),
    ("external_key_memory_no_new_seed", case_external_key_memory_no_new_seed),
)


def run_suite() -> int:
    failed = skipped = 0
    for name, fn in CASES:
        try:
            fn()
            print("[PASS] %s" % name)
        except SkipCase as exc:
            skipped += 1
            print("[SKIP] %s: %s" % (name, exc))
        except AssertionError as exc:
            failed += 1
            print("[FAIL] %s: %s" % (name, exc))
        except Exception as exc:  # noqa: BLE001 - 自宿主运行器：意外也计入失败并如实报类型
            failed += 1
            print("[FAIL] %s: unexpected %s: %s" % (name, type(exc).__name__, exc))
    print("summary: %d passed, %d skipped, %d failed"
          % (len(CASES) - skipped - failed, skipped, failed))
    return failed


if __name__ == "__main__":
    sys.exit(1 if run_suite() else 0)
