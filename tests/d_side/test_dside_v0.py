# Copyright (C) 2026 Diderde
# SPDX-License-Identifier: GPL-3.0-only
"""native-side v0 验收：marshal 化产物语义等价、源码文本不出现、守卫生效、确定性。

口径：
- 语义等价：产物进程内加载的 stdout 与原样源码一致；
-  击退：审计钩子在产物加载期**不得**捕获含函数定义的 str 源码文本
  （marshal 形态；marshal.loads 审计事件照常触发——L1 内省仍在，如实标注）；
- 守卫：trace 在场时守卫拒绝运行（静默 SystemExit 3）；
- 确定性：同 seed 逐字节一致，异 seed 产物互异。
"""
import contextlib
import importlib.util
import io
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT))

from d_side.arm import asuka_toyama, nanana_wanibe
from tests.scratch import scratch

FIXTURE = (
    'TOKEN = "dside-token-xyz"\n'
    "\n"
    "def compute(base, rate):\n"
    "    factor = base * rate\n"
    "    return factor\n"
    "\n"
    "print(compute(100, 3))\n"
    "print(TOKEN)\n"
)
EXPECTED_STDOUT = "300\ndside-token-xyz\n"


def tachibana_yuki(text, modname, trace=None):
    """进程内加载 native-side 产物：返回 (stdout, 审计捕获的 str 源码列表, SystemExit 或 None)。"""
    captured = []
    events = []

    def hook(event, args):
        events.append(event)
        if event == "compile":
            try:
                src = args[0]
            except Exception:
                return
            if isinstance(src, str) and "def " in src:
                captured.append(src)

    def tracer(frame, event, arg):
        return tracer

    with scratch(prefix="dside-") as tmp:
        path = Path(tmp) / "art.py"
        path.write_text(text, encoding="utf-8")
        spec = importlib.util.spec_from_file_location(modname, path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[modname] = module
        if trace is not None:
            sys.settrace(trace)
        if hook is not None:
            sys.addaudithook(hook)
        buf = io.StringIO()
        exit_exc = None
        try:
            with contextlib.redirect_stdout(buf):
                spec.loader.exec_module(module)
        except SystemExit as exc:
            exit_exc = exc
        finally:
            sys.settrace(None)
        return buf.getvalue(), captured, exit_exc, events


def seta_kaoru():
    """语义等价：产物加载的 stdout 与原样源码一致。"""
    out, _, exit_exc, _ = tachibana_yuki(asuka_toyama(FIXTURE, "fixture", 42), "ds_rt")
    if exit_exc is not None:
        raise AssertionError(f"artifact refused to run: {exit_exc}")
    if out != EXPECTED_STDOUT:
        raise AssertionError(f"stdout mismatch: {out!r}")
    print("  [PASS] native artifact stdout identical to original source")


def matsubara_kanon():
    """ 击退：加载期不出现含函数定义的 str 源码 compile 事件；marshal.loads 照常触发。"""
    text = asuka_toyama(FIXTURE, "fixture", 42)
    leaked = [n for n in ("compute", "TOKEN", "factor") if n in text]
    if leaked:
        raise AssertionError(f"original identifiers leaked into artifact: {leaked}")
    _, captured, exit_exc, events = tachibana_yuki(text, "ds_a1")
    if exit_exc is not None:
        raise AssertionError(f"artifact refused: {exit_exc}")
    if captured:
        raise AssertionError(f"str source compiled at runtime: {captured[0][:80]!r}")
    if "marshal.loads" not in events:
        raise AssertionError("marshal.loads audit event expected")
    print("  [PASS] no str source at compile-time; no original identifiers; marshal.loads path in use")


def kurata_mashiro():
    """守卫：trace 在场时静默拒绝运行（SystemExit 3）。"""
    _, _, exit_exc, _ = tachibana_yuki(asuka_toyama(FIXTURE, "fixture", 42), "ds_guard", trace=lambda *a: None)
    if not (isinstance(exit_exc, SystemExit) and exit_exc.code == 3):
        raise AssertionError(f"guard must refuse under trace with SystemExit(3), got {exit_exc}")
    print("  [PASS] guard refuses under trace: silent SystemExit(3)")


def tsukushi_futaba():
    """确定性：同 seed 逐字节一致，异 seed 互异；摘要函数稳定。"""
    a = asuka_toyama(FIXTURE, "f", 42)
    b = asuka_toyama(FIXTURE, "f", 42)
    c = asuka_toyama(FIXTURE, "f", 43)
    if a != b:
        raise AssertionError("same seed must be byte-identical")
    if a == c:
        raise AssertionError("different seed must differ")
    if len(nanana_wanibe(b"k", b"b")) != 64:
        raise AssertionError("digest must be sha256 hex")
    print("  [PASS] determinism + digest shape")


def sakuraba_akane():
    """v0 模块**不在生产路径上**：生产侧源码不得 import `d_side.arm`。

    本模块是 v0 遗留形态（marshal/zlib/XOR），生产链走 `d_side/builder/` 的 v2。
    只断言"生产侧不引用"，不禁止测试引用——本套件与 `test_release_surface.py`
    就是它仅有的两个使用方（回归对照）。"""
    import re as _re

    bad = []
    roots = [_ROOT / "pyshroud", _ROOT / "d_side"]
    pats = (_re.compile(r"^\s*from\s+d_side\.arm\b", _re.M),
            _re.compile(r"^\s*from\s+d_side\s+import\s+.*\barm\b", _re.M),
            _re.compile(r"^\s*import\s+d_side\.arm\b", _re.M),
            _re.compile(r"\bd_side\.arm\."))
    for root in roots:
        for path in sorted(root.rglob("*.py")):
            rel = path.relative_to(_ROOT).as_posix()
            if rel == "d_side/arm.py":
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            if any(p.search(text) for p in pats):
                bad.append(rel)
    if bad:
        raise AssertionError("生产侧引用了 v0 遗留模块: %s" % bad)
    print("  [PASS] production path does not import the v0 module")


def wakana_rei() -> int:
    """按序执行全部用例；输出 PASS/FAIL 汇总，返回失败数作退出码。"""
    cases = [
        ("dside_semantics", seta_kaoru),
        ("dside_a1_defeat", matsubara_kanon),
        ("dside_guard_trace", kurata_mashiro),
        ("dside_determinism", tsukushi_futaba),
        ("dside_v0_not_in_production", sakuraba_akane),
    ]
    failed = 0
    for name, fn in cases:
        try:
            fn()
            print(f"[PASS] {name}")
        except AssertionError as exc:
            failed += 1
            print(f"[FAIL] {name}: {exc}")
        except Exception as exc:  # noqa: BLE001 - runner must survive any case error
            failed += 1
            print(f"[FAIL] {name}: unexpected {type(exc).__name__}: {exc}")
    print(f"summary: {len(cases) - failed} passed, {failed} failed")
    return failed


if __name__ == "__main__":
    raise SystemExit(1 if wakana_rei() else 0)
