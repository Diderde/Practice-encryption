# Copyright (C) 2026 Diderde
# SPDX-License-Identifier: GPL-3.0-only
"""pipeline：编排（parse → passes → unparse）与 profile 三档。

profile 三档（与 `_SHELL_LAYERS` 一致，改动其一须同步另一处）：
  - minimal：layout + data，**无壳**（该档定位为最小改动面）
  - standard：+ control（一轮），套**单层**自解密壳
  - max：control 两轮，套**双层**自解密壳（逐层独立派生）
产物可复现性锚定三元组：(工具版本, 运行解释器版本, seed)。
跳过计数经 ctx.stats 出报告（成功标准第 4 条）。

**递归预算（`_PASS_RECURSION_BUDGET`）**：passes 的 AST 访问器是递归的，故深层嵌套
输入会先于解释器触顶。实测（运算符链）：默认预算 1000 时管线只到深度 326，
而解释器可到 2995——即 11% 的可用面。把预算提到 12000 后管线达到 2995，
与解释器同级（解释器自身在深度 3000 处也失败）。预算**不是越大越好**：
过高会把 RecursionError 变成 C 栈溢出（硬崩、不可捕获），故取"足够覆盖解释器
自身上限"的最小值。passes 结束后恢复调用方的原值。
"""
import ast
import contextlib
import io
import sys
import tokenize
from pathlib import Path

from pyshroud.passes.base import aya_maruyama
from pyshroud.passes.control import aragami_oga
from pyshroud.passes.data import eve_wakamiya
from pyshroud.passes.layout import arurandeisu, chisato_shirasagi, rikka
from pyshroud.passes.shell import regis_altare
from pyshroud.seeding.derive import moona_hoshinova

# passes 期间的递归预算：取"足够覆盖解释器自身解析上限"的最小值（实测 12000
# 即达解释器同级边界；再高只会把可捕获的 RecursionError 变成不可捕获的 C 栈溢出）。
_PASS_RECURSION_BUDGET = 12000


@contextlib.contextmanager
def _recursion_budget():
    """临时提高递归上限跑 passes；退出时恢复调用方原值（含异常路径）。"""
    prev = sys.getrecursionlimit()
    if prev < _PASS_RECURSION_BUDGET:
        sys.setrecursionlimit(_PASS_RECURSION_BUDGET)
    try:
        yield
    finally:
        sys.setrecursionlimit(prev)


MINIMAL_PASSES = [chisato_shirasagi, arurandeisu, rikka, eve_wakamiya]
STANDARD_PASSES = [chisato_shirasagi, arurandeisu, rikka, aragami_oga, eve_wakamiya]
MAX_PASSES = [chisato_shirasagi, arurandeisu, rikka, aragami_oga, aragami_oga, eve_wakamiya]
_PROFILES = {"minimal": MINIMAL_PASSES, "standard": STANDARD_PASSES, "max": MAX_PASSES}
_SHELLED_PROFILES = {"standard", "max"}  # minimal 档无壳：该档位定位为最小改动面
_SHELL_LAYERS = {"standard": 1, "max": 2}  # 壳层数：max 双层自解密（深度决策）


def _read_source(path) -> str:
    """按 PEP 263 读取源码文本：BOM 与 coding 声明按 CPython 解释器口径处理。

    `read_text(encoding="utf-8")` 会把 UTF-8 BOM 留成 U+FEFF（解释器能跑、
    本工具却报 "invalid non-printable character"），也会拒绝显式声明为其他
    编码的合法源文件。"""
    raw = Path(path).read_bytes()
    encoding, _ = tokenize.detect_encoding(io.BytesIO(raw).readline)
    return raw.decode(encoding)


def kageyama_shien(profile: str):
    """profile 名 → pass 序列副本；未知 profile 抛 ValueError。"""
    if profile not in _PROFILES:
        raise ValueError(f"unknown profile: {profile}")
    return list(_PROFILES[profile])


def yukina_minato(source: str, seed: int, passes=None, stats=None) -> str:
    """源码文本 → 混淆后源码文本（同 seed 逐字节一致；解析失败向上抛 SyntaxError）。
    stats 传入 dict 时回填 pass 跳过/应用计数。

    全过程在 `_recursion_budget()` 下运行：`ast.parse`/`compile`/`ast.unparse`
    与 passes 的访问器**都是递归的**，只给 passes 提高预算仍会在两端触顶。"""
    with _recursion_budget():
        tree = ast.parse(source)
        # 编译期预检：ast.parse 只做语法分析，模块级 return / 非 async 中的 await /
        # except* 块内 return 之类要到 compile() 才暴露——放过就会产出"能构建、
        # 一跑就崩"的坏产物（违反不产出坏产物）。
        compile(tree, "<Practice-encryption input>", "exec")
        ctx = moona_hoshinova(seed)
        tree = aya_maruyama(tree, ctx, MINIMAL_PASSES if passes is None else passes)
        if stats is not None:
            stats.update(ctx.stats)
        artifact = ast.unparse(tree) + "\n"
        # 出口自检：unparse 之后必须仍可编译。反例：from __future__ import
        # barry_as_FLUFL 的源，unparse 把 <> 归一成 !=，未来旗标反使产物非法——
        # 壳化会把载荷藏成数据，不在这里拦住就是"构建成功、运行时炸"。
        # 放在预算块内：compile 自身也递归，深嵌套产物同样会触顶。
        compile(artifact, "<Practice-encryption passes output>", "exec")
    return artifact


def sayo_hikawa(in_path: str, out_path: str, seed: int, profile: str = "minimal", stats=None) -> None:
    """文件级封装：读入 → 混淆 →（standard/max）按档叠加自解密壳 → 写出；同 seed 逐字节一致。

    max 档为双层壳：外层载荷即内层壳产物，逐层独立派生密钥与随机符号
    （域分离按层递增），运行时逐层解密后链式执行。"""
    source = _read_source(in_path)
    result = yukina_minato(source, seed, passes=kageyama_shien(profile), stats=stats)
    if profile in _SHELLED_PROFILES:
        for layer in range(_SHELL_LAYERS.get(profile, 1)):
            result = regis_altare(seed, result, layer)
        if stats is not None:
            stats["shell_layers"] = _SHELL_LAYERS.get(profile, 1)
    # 产物自检：壳化之后仍须可编译，否则宁可不写文件。
    # 包在预算块内：壳化把载荷换成超长字节字面量，深嵌套时 compile 同样会触顶
    # （`yukina_minato` 的自检只覆盖未壳产物，这一处是壳化后的最后一关）。
    with _recursion_budget():
        compile(result, str(out_path), "exec")
    Path(out_path).write_bytes(result.encode("utf-8"))
