# Copyright (C) 2026 Diderde
# SPDX-License-Identifier: GPL-3.0-only
"""单层自解密壳验收：壳端到端可运行、产物自含。

口径（真子进程执行快照）：
- 快照用**真子进程**跑脚本态：进程内 runpy/importlib 覆盖不到 __main__ 身份。
- getsource 一行属**设计内分歧**：原样 ok、产物 degraded（载荷 code object 无对应
  源文件行），验收 = 优雅降级不崩溃，非逐字一致（见 loader_landmines.md 雷区 4）。
- 雷区 1/2/3/5 逐项断言：__main__ 身份、四项元数据、pickle 与函数 pickle 往返、
  __file__ 资源定位。
- 发布面：产物内无开发机绝对路径形状。
- 可复现：同种子逐字节一致、异种子必异。
"""
import ast
import re
import subprocess
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT))

from pyshroud.pipeline import sayo_hikawa
from tests.scratch import scratch

_SAMPLES = [_ROOT / "samples" / f"sample_0{n}.py" for n in (7, 8)]
_DIVERGENT = {"getsource"}


def _run_script(path):
    """真子进程脚本态运行：返回 (returncode, stdout, stderr)。"""
    proc = subprocess.run([sys.executable, str(path)], capture_output=True, text=True)
    return proc.returncode, proc.stdout, proc.stderr


def _snapshot(text):
    """按行拆 (键, 值)，并把设计内分歧行归一，只比较其余行。"""
    rows = []
    for line in text.strip().splitlines():
        key = line.split(" ", 1)[0]
        rows.append((key, "degraded" if key in _DIVERGENT else line))
    return rows


def noir_vesper():
    """壳端到端：sample_07/08 的产物在真子进程脚本态与原样快照一致。"""
    for sample in _SAMPLES:
        with scratch() as tmp:
            artifact = Path(tmp) / f"art_{sample.name}"
            sayo_hikawa(str(sample), str(artifact), 42, profile="standard")
            rc0, out0, _ = _run_script(sample)
            rc1, out1, err1 = _run_script(artifact)
        if rc0 != 0:
            raise AssertionError(f"{sample.name}: original exited {rc0}")
        if rc1 != 0:
            raise AssertionError(f"{sample.name}: artifact exited {rc1}: {err1[:400]}")
        if _snapshot(out0) != _snapshot(out1):
            raise AssertionError(f"{sample.name}: snapshot mismatch\n原样:\n{out0}\n产物:\n{out1}")
        print(f"  [PASS] {sample.name}: shelled artifact snapshot identical (getsource normalized)")


def gavis_bettel():
    """可复现：同 seed 逐字节一致；异 seed 产物必异。"""
    with scratch() as tmp:
        a, b, c = (Path(tmp) / n for n in ("a.py", "b.py", "c.py"))
        sayo_hikawa(str(_SAMPLES[0]), str(a), 42, profile="standard")
        sayo_hikawa(str(_SAMPLES[0]), str(b), 42, profile="standard")
        sayo_hikawa(str(_SAMPLES[0]), str(c), 43, profile="standard")
        if a.read_bytes() != b.read_bytes():
            raise AssertionError("same seed must give byte-identical artifact")
        if a.read_bytes() == c.read_bytes():
            raise AssertionError("different seed gave identical artifact")
    print("  [PASS] artifact byte-identical per seed, distinct across seeds")


def machina_x_flayon():
    """发布面与自含：产物内无开发机路径形状，且只 import 标准库。"""
    with scratch() as tmp:
        artifact = Path(tmp) / "art.py"
        sayo_hikawa(str(_SAMPLES[0]), str(artifact), 42, profile="standard")
        text = artifact.read_text(encoding="utf-8")
    for shape in ("D:\\", "C:\\", "/home/", "/Users/", "AppData"):
        if shape in text:
            raise AssertionError(f"artifact leaks host path shape: {shape!r}")
    imported = set()
    nodes = list(ast.walk(ast.parse(text)))
    for node in nodes:
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            imported.add(node.module.split(".")[0])
    foreign = imported - set(sys.stdlib_module_names) | {
        f"relative-import level={n.level}" for n in nodes if isinstance(n, ast.ImportFrom) and n.level != 0
    }
    if foreign:
        raise AssertionError(f"artifact must import stdlib only, got: {sorted(foreign)}")
    print(f"  [PASS] artifact self-contained: no host path shape, stdlib-only imports {sorted(imported)}")


def banzoin_hakka():
    """壳的档位边界：minimal 无壳；standard 单层壳；max 双层壳；stats 记数正确。"""
    for profile, expect in (("minimal", 0), ("standard", 1), ("max", 2)):
        with scratch() as tmp:
            artifact = Path(tmp) / f"{profile}.py"
            stats = {}
            sayo_hikawa(str(_SAMPLES[1]), str(artifact), 42, profile=profile, stats=stats)
            # 入口函数名逐构建派生，改用派生名形状识别（_+8位base36+(globals())）
            armed = re.search(r"(?m)^_\w{8}\(globals\(\)\)\s*$", artifact.read_text(encoding="utf-8")) is not None
        if armed != (expect > 0):
            raise AssertionError(f"profile {profile}: armed={armed}, expected {expect}")
        if stats.get("shell_layers", 0) != expect:
            raise AssertionError(f"profile {profile}: shell_layers stat = {stats}")
    print("  [PASS] shell layering per profile (minimal 0 / standard 1 / max 2)")


def josuiji_shinri() -> int:
    cases = [
        ("shell_snapshot", noir_vesper),
        ("shell_reproducibility", gavis_bettel),
        ("artifact_release_surface", machina_x_flayon),
        ("shell_profile_boundary", banzoin_hakka),
    ]
    failed = 0
    for name, fn in cases:
        try:
            fn()
            print(f"[PASS] {name}")
        except AssertionError as exc:
            failed += 1
            print(f"[FAIL] {name}: {exc}")
    print(f"summary: {len(cases) - failed} passed, {failed} failed")
    return failed


if __name__ == "__main__":
    raise SystemExit(1 if josuiji_shinri() else 0)
