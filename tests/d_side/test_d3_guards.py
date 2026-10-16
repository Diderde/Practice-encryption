# Copyright (C) 2026 Diderde
# SPDX-License-Identifier: GPL-3.0-only
"""D-3 守卫套件（0.0.39；自宿主运行器，快速档）。

口径：
- patcher 单元面：合成最小 PE64（DOS + PE + PE32+ 可选头 + 节表 + .text/槽节/
  [.rdata]/[.reloc]），不依赖宿主任何真实 PE（§6.5：测试不得依赖宿主环境，显式构造）；
  断言 **keyed 在场节摘要**入槽（：覆盖 = 节表顺序所有在场节 raw bytes，
  排除 `.v0` 自身；密钥 = HKDF("", nonce)‖"integ"）/ CheckSum 置零 / 幂等 /
  .text 重定位断言 / 槽纯度断言 / 逐节篡改判拒 / 换 nonce 判拒；
- 1b 快照契约：单一源常量（native_build._PY_GUARD_SNIPPET*）经
  `python -c` 子进程在**真实 CPython** 的 __main__ globals 里执行（与 boot
  场景同构），钉 SystemExit(3) 契约、诊断输出、零残留与 os 不可见面；
  不做进程内动态执行；
- 1a 原生层与 E2E 拒绝路径由 test_native_builder.py（慢档）的故障注入
  与 .text 篡改负例钉死，本套件不重复。
"""
import hashlib
import os
import re
import subprocess
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT))

from d_side.builder.patcher import (_SLOT_SECTION, _covered_image, hayama_marin,
                                    kaida_haru, nui_sociere)  # noqa: E402
from d_side.builder.native_build import _PY_GUARD_SNIPPET, _PY_GUARD_SNIPPET_DIAG  # noqa: E402
from tests.scratch import scratch  # noqa: E402

_FILE_ALIGN = 0x200
_TEXT_VA = 0x1000
# 摘要改为 keyed（INTEG_KEY 由产物 nonce 派生），夹具必须自带一条 nonce；
# 换 nonce 就是换密钥——digest_binds_nonce 用例正用它钉这条依赖
_NONCE = bytes(range(1, 13))


def _section_entry(name: bytes, vsize: int, va: int, rsize: int, ptr: int, chars: int) -> bytes:
    return (name.ljust(8, b"\x00") + vsize.to_bytes(4, "little") + va.to_bytes(4, "little")
            + rsize.to_bytes(4, "little") + ptr.to_bytes(4, "little")
            + b"\x00" * 12 + chars.to_bytes(4, "little"))


def _synth_pe(with_reloc: bool = False, reloc_into_text: bool = False,
              slot_dirty: bool = False, with_rdata: bool = False) -> tuple:
    """合成最小 PE64 → (blob, meta)。节：.text / 摘要槽 / [.rdata] / [.reloc]。

    / 后摘要覆盖**所有在场节**，夹具必须能造出 .text 之外的节，否则
    "改了别的节也照样被拒"这条就没有运行期证据。"""
    n_sections = 2 + int(with_reloc) + int(with_rdata)
    opt_size = 240  # PE32+ 标准头长
    table_off = 0x40 + 20 + opt_size
    data_base = (table_off + 40 * n_sections + _FILE_ALIGN - 1) // _FILE_ALIGN * _FILE_ALIGN
    cursor = [data_base]

    def _next_ptr():
        ptr = cursor[0]
        cursor[0] += _FILE_ALIGN
        return ptr

    text_ptr, slot_ptr = _next_ptr(), _next_ptr()
    rdata_ptr = _next_ptr() if with_rdata else None
    reloc_ptr = _next_ptr() if with_reloc else None

    text = bytes((i * 7 + 3) % 251 for i in range(_FILE_ALIGN))
    rdata = bytes((i * 11 + 5) % 251 for i in range(_FILE_ALIGN))
    slot = bytearray(_FILE_ALIGN)
    if slot_dirty:
        slot[100] = 0xAA
    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    dos[0x3C:0x40] = (0x40).to_bytes(4, "little")
    pe = (b"PE\x00\x00"
          + (0x8664).to_bytes(2, "little")          # machine x64
          + n_sections.to_bytes(2, "little")         # NumberOfSections
          + b"\x00" * 4                              # TimeDateStamp（本套件不涉确定性）
          + b"\x00" * 4                              # PointerToSymbolTable
          + b"\x00" * 4                              # NumberOfSymbols
          + opt_size.to_bytes(2, "little")           # SizeOfOptionalHeader
          + (0x0022).to_bytes(2, "little"))          # Characteristics
    opt = bytearray(opt_size)
    opt[0:2] = (0x020B).to_bytes(2, "little")        # PE32+ magic
    opt[16:18] = _FILE_ALIGN.to_bytes(2, "little")
    opt[56:60] = _TEXT_VA.to_bytes(4, "little")      # base of code
    opt[60:64] = (0x1000).to_bytes(4, "little")      # section alignment
    opt[64:68] = (0xDEADBEEF).to_bytes(4, "little")  # CheckSum：patcher 必须置零
    va = _TEXT_VA
    table = _section_entry(b".text", _FILE_ALIGN, va, _FILE_ALIGN, text_ptr, 0x60000020)
    va += 0x1000
    table += _section_entry(_SLOT_SECTION.encode("ascii"), _FILE_ALIGN, va, _FILE_ALIGN,
                            slot_ptr, 0x40000040)
    if with_rdata:
        va += 0x1000
        table += _section_entry(b".rdata", _FILE_ALIGN, va, _FILE_ALIGN, rdata_ptr, 0x40000040)
    if with_reloc:
        va += 0x1000
        table += _section_entry(b".reloc", _FILE_ALIGN, va, _FILE_ALIGN, reloc_ptr, 0x42000040)
    blob = bytearray(bytes(dos) + pe + bytes(opt) + table)
    blob += b"\x00" * (data_base - len(blob))
    blob += text + bytes(slot)
    if with_rdata:
        blob += rdata
    if with_reloc:
        if reloc_into_text:
            # 一条 DIR64 基址重定位，RVA 落在 .text 内（第 0x10 字节处）
            block = (_TEXT_VA.to_bytes(4, "little") + (12).to_bytes(4, "little")
                     + (0x0000).to_bytes(2, "little")
                     + (0xA000 | 0x10).to_bytes(2, "little"))
        else:
            block = (_TEXT_VA.to_bytes(4, "little") + (8).to_bytes(4, "little")
                     + (0x0000).to_bytes(2, "little"))
        blob[reloc_ptr:reloc_ptr + _FILE_ALIGN] = block.ljust(_FILE_ALIGN, b"\x00")
    return bytes(blob), {"text_ptr": text_ptr, "slot_ptr": slot_ptr, "text": text,
                         "rdata_ptr": rdata_ptr, "rdata": rdata}


def _slot_digest(blob: bytes) -> bytes:
    _lf, sections = nui_sociere(blob)
    slot = next(s for s in sections if s["name"] == _SLOT_SECTION)
    return blob[slot["ptr"]:slot["ptr"] + 32]


def _verify(blob: bytes, nonce: bytes) -> bool:
    """boot.rs `ars_almal` 的 Python 镜像：按同式重算 keyed 覆盖摘要并与槽比对。

    单元面没有 exe 可跑，"被拒"就只能以这条同式判据表达（真实产物的拒绝路径
    由 test_native_builder.py 的 self_digest_tamper 用例钉）。"""
    try:
        _lf, sections = nui_sociere(blob)
        return _covered_image(blob, sections, nonce) == _slot_digest(blob)
    except (RuntimeError, IndexError, KeyError):
        return False


def _run_child(program: str, extra_env: dict = None, isolated: bool = False) -> subprocess.CompletedProcess:
    """`python -c program`：真实 CPython、__main__ globals、无 shell。"""
    env = dict(os.environ)
    if extra_env:
        env.update(extra_env)
    argv = [sys.executable, "-c", program]
    if isolated:
        # boot 同构 = IsolatedConfig + site_import=0，等价 -I -S（-I 不含 -S，
        # site 仍会跑并导入 os，破坏 os 不可见断言）
        argv.insert(1, "-S")
        argv.insert(1, "-I")
    return subprocess.run(argv, capture_output=True, text=True, timeout=60, env=env,
                          shell=False)


def case_patcher_happy_and_idempotent() -> None:
    blob, meta = _synth_pe(with_rdata=True)
    patched = hayama_marin(blob, _NONCE)
    want = hashlib.blake2s(meta["text"] + meta["rdata"], key=kaida_haru(_NONCE)).digest()
    assert _slot_digest(patched) == want, "slot != keyed blake2s(.text || .rdata)"
    assert patched[meta["text_ptr"]:meta["text_ptr"] + _FILE_ALIGN] == meta["text"], \
        ".text must stay untouched"
    assert patched[meta["rdata_ptr"]:meta["rdata_ptr"] + _FILE_ALIGN] == meta["rdata"], \
        ".rdata must stay untouched"
    assert patched[0x40 + 24 + 64:0x40 + 24 + 68] == b"\x00" * 4, "CheckSum not zeroed"
    assert hayama_marin(patched, _NONCE) == patched, "patcher must be idempotent on patched input"
    assert _verify(patched, _NONCE), "同式重算必须判通过（boot 侧的绿路径）"


def case_patcher_relocs_refused() -> None:
    blob, _ = _synth_pe(with_reloc=True, reloc_into_text=True)
    try:
        hayama_marin(blob, _NONCE)
        raise AssertionError(".text relocation must be refused")
    except RuntimeError as exc:
        assert "relocation" in str(exc), str(exc)[:200]


def case_patcher_slot_missing_refused() -> None:
    blob, _ = _synth_pe()
    _lf, sections = nui_sociere(blob)
    idx = [i for i, s in enumerate(sections) if s["name"] == _SLOT_SECTION][0]
    base = 0x40 + 20 + 240 + 40 * idx
    mutated = bytearray(blob)
    mutated[base:base + 8] = b".nulldg\x00"  # 节名抹掉 = 槽节不在场
    try:
        hayama_marin(bytes(mutated), _NONCE)
        raise AssertionError("missing slot must be refused")
    except RuntimeError as exc:
        assert "slot" in str(exc), str(exc)[:200]


def case_patcher_slot_dirty_refused() -> None:
    blob, _ = _synth_pe(slot_dirty=True)
    try:
        hayama_marin(blob, _NONCE)
        raise AssertionError("dirty slot tail must be refused")
    except RuntimeError as exc:
        assert "foreign bytes" in str(exc), str(exc)[:200]


def case_patcher_digest_binds_text() -> None:
    blob, meta = _synth_pe(with_rdata=True)
    first = hayama_marin(blob, _NONCE)
    mutated = bytearray(first)
    mutated[meta["text_ptr"] + 7] ^= 0xFF  # .text 一个字节翻位
    assert not _verify(bytes(mutated), _NONCE), "翻 .text 一字节后同式重算必须判拒"
    second = hayama_marin(bytes(mutated), _NONCE)
    assert _slot_digest(second) != _slot_digest(first), "digest must follow .text content"


def case_patcher_digest_binds_other_sections() -> None:
    """：`.text` 之外的节也必须进摘要——f 实测的"改 .rdata 无人管"从此有齿。

    逐节翻一字节，断言同式重算判拒（= boot 侧会 exit 3），并断言 `.v0` 槽自身
    不在覆盖集内（否则摘要自我指涉，patcher 永远写不进去）。
    """
    blob, meta = _synth_pe(with_rdata=True, with_reloc=True)
    patched = hayama_marin(blob, _NONCE)
    assert _verify(patched, _NONCE), "clean image must verify"
    _lf, sections = nui_sociere(patched)
    for sec in sections:
        if sec["name"] == _SLOT_SECTION or sec["ptr"] == 0 or sec["rsize"] == 0:
            continue
        mutated = bytearray(patched)
        mutated[sec["ptr"] + 3] ^= 0xFF
        assert not _verify(bytes(mutated), _NONCE), \
            "section %s is outside the digest coverage" % sec["name"]
    # 槽节自身**不进入**摘要输入：翻节尾（第 32 字节之后的填充区）后，重算摘要
    # 仍等于槽里存的 32 B。翻 0..32 区间是不成立的对照——那改的是摘要本身而不是
    # 摘要的输入
    slot_flipped = bytearray(patched)
    slot_flipped[meta["slot_ptr"] + 200] ^= 0xFF
    assert _verify(bytes(slot_flipped), _NONCE), \
        "the digest slot must be excluded from its own coverage"


def case_patcher_digest_binds_nonce() -> None:
    """：摘要必须是 **keyed**——同一条图换 nonce（= 换 INTEG_KEY）就判拒。

    旧口径是无键 blake2s，任何人改完字节自己重算即可（f 的 text_patched_repaired
    实验）；现在重算还得先拿到密钥，而密钥由产物头部 nonce 派生。
    """
    blob, _meta = _synth_pe(with_rdata=True)
    patched = hayama_marin(blob, _NONCE)
    assert _verify(patched, _NONCE)
    assert not _verify(patched, bytes(range(9, 21))), "digest must be keyed by the nonce"
    assert kaida_haru(_NONCE) != kaida_haru(bytes(range(9, 21))), "INTEG_KEY 不随 nonce 变"
    assert len(kaida_haru(_NONCE)) == 32, "INTEG_KEY 必须是 32 B"


def case_snippet_clean_pass() -> None:
    run = _run_child(_PY_GUARD_SNIPPET)
    assert run.returncode == 0, "clean snapshot must pass (exit %d, %r)" % (
        run.returncode, run.stderr[:200])
    assert run.stderr == "", "silent variant must not write stderr"


def case_snippet_trace_hit() -> None:
    prelude = "import sys\nsys.settrace(lambda *a, **k: None)\n"
    run = _run_child(prelude + _PY_GUARD_SNIPPET)
    assert run.returncode == 3, "trace hit must exit 3 (got %d)" % run.returncode
    diag = _run_child(prelude + _PY_GUARD_SNIPPET_DIAG)
    assert diag.returncode == 3
    # / + +（既有审计结论）：诊断输出折叠为一位数字桶码（对照表只在
    # 构建 workdir，产物/仓内源均无 E-NN 原文）
    assert re.fullmatch(r"[0-9]", diag.stderr.strip()), repr(diag.stderr)[:160]


def case_snippet_profile_hit() -> None:
    prelude = "import sys\nsys.setprofile(lambda *a, **k: None)\n"
    run = _run_child(prelude + _PY_GUARD_SNIPPET)
    assert run.returncode == 3, "profile hit must exit 3 (got %d)" % run.returncode


def case_snippet_module_hit() -> None:
    with scratch(prefix="d3g-module-") as tmp:
        # 合法最小假模块走真导入：sys.modules 里出现 pydevd/ptvsd
        Path(tmp, "pydevd.py").write_text("\n", encoding="ascii")
        Path(tmp, "ptvsd.py").write_text("\n", encoding="ascii")
        env = {"PYTHONPATH": tmp}
        run = _run_child("import pydevd\n" + _PY_GUARD_SNIPPET, extra_env=env)
        assert run.returncode == 3, "module hit must exit 3 (got %d)" % run.returncode
        diag = _run_child("import ptvsd\n" + _PY_GUARD_SNIPPET_DIAG, extra_env=env)
        assert diag.returncode == 3
        assert re.fullmatch(r"[0-9]", diag.stderr.strip()), repr(diag.stderr)[:160]


def case_snippet_no_leftover_and_no_os() -> None:
    # -c 的执行命名空间就是 __main__ globals（与 boot 的 PyRun_SimpleString 同构）：
    # 快照通过后不得残留单下划线临时名（dunder 为模块自带，不算），也不得引入 os
    # （隔离启动下 os 本不在 sys.modules）
    epilogue = ("\nimport sys as _ep_sys\n"
                "_bad = [k for k in dir() if k.startswith('_') and not k.startswith('__')"
                " and k != '_ep_sys']\n"
                "assert not _bad, 'leftover: %r' % _bad\n"
                "assert 'os' not in _ep_sys.modules, 'os must stay unimported'\n"
                "print('OK')\n")
    run = _run_child(_PY_GUARD_SNIPPET + epilogue, isolated=True)
    assert run.returncode == 0, "exit %d (%r)" % (run.returncode, run.stderr[:200])
    assert "OK" in run.stdout


def case_normalize_eol_junction_terminates() -> None:
    # 早期轮次 回归（§6.7 边界测试）：normalize_eol 曾用 rglob 跟随 junction——
    # native-e2e 套件残留的 Lib junction 使遍历走进巨树/成环（内存膨胀挂起，
    # 本次实测 2.6GB）。os.walk + reparse point 剪枝必须在有环时秒级终止。
    # 临时目录用工作区 scratch（受限环境删 TEMP 会被拒，口径见 tests/scratch.py）；
    # junction 在 finally 显式摘除——3.11 的 shutil.rmtree 不识别 junction，
    # 留给清理阶段会跟随成环。
    import subprocess as sp

    try:
        import _winapi
    except ImportError:
        return  # expected-vs-environment：junction 仅 Windows 可造
    with scratch(prefix="d3g-junction-") as tmp:
        loop = Path(tmp) / "loop"
        Path(tmp, "sample.txt").write_bytes(b"line\n")
        _winapi.CreateJunction(tmp, str(loop))  # 自指环
        try:
            child = (
                "import importlib.util, sys\n"
                "spec = importlib.util.spec_from_file_location('ne', sys.argv[1])\n"
                "mod = importlib.util.module_from_spec(spec)\n"
                "spec.loader.exec_module(mod)\n"
                "print('changed', mod.tokino_sora(sys.argv[2]))\n"
            )
            run = sp.run([sys.executable, "-c", child,
                          str(_ROOT / "scripts" / "normalize_eol.py"), tmp],
                         capture_output=True, text=True, timeout=60, shell=False)
            assert run.returncode == 0, "exit %d: %s" % (run.returncode, run.stderr[:200])
            assert "changed 1" in run.stdout, \
                "cycle must be pruned and the sample normalized: %r" % run.stdout[:200]
        finally:
            try:
                os.rmdir(loop)
            except OSError:
                pass


def sukoya_kana() -> int:
    cases = (
        ("patcher_happy_and_idempotent", case_patcher_happy_and_idempotent),
        ("patcher_relocs_refused", case_patcher_relocs_refused),
        ("patcher_slot_missing_refused", case_patcher_slot_missing_refused),
        ("patcher_slot_dirty_refused", case_patcher_slot_dirty_refused),
        ("patcher_digest_binds_text", case_patcher_digest_binds_text),
        ("patcher_digest_binds_other_sections", case_patcher_digest_binds_other_sections),
        ("patcher_digest_binds_nonce", case_patcher_digest_binds_nonce),
        ("snippet_clean_pass", case_snippet_clean_pass),
        ("snippet_trace_hit", case_snippet_trace_hit),
        ("snippet_profile_hit", case_snippet_profile_hit),
        ("snippet_module_hit", case_snippet_module_hit),
        ("snippet_no_leftover_and_no_os", case_snippet_no_leftover_and_no_os),
        ("normalize_eol_junction_terminates", case_normalize_eol_junction_terminates),
    )
    failed = 0
    for name, fn in cases:
        try:
            fn()
            print("[PASS] %s" % name)
        except AssertionError as exc:
            failed += 1
            print("[FAIL] %s: %s" % (name, exc))
        except Exception as exc:
            failed += 1
            print("[FAIL] %s: unexpected %s: %s" % (name, type(exc).__name__, exc))
    print("summary: %d passed, %d failed" % (len(cases) - failed, failed))
    return failed


if __name__ == "__main__":
    sys.exit(1 if sukoya_kana() else 0)
