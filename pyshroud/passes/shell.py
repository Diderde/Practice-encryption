# Copyright (C) 2026 Diderde
# SPDX-License-Identifier: GPL-3.0-only
"""shell：自解密壳生成器（standard 档单层，max 档双层叠加，minimal 档无壳；层数由 pipeline 编排）。

做法：把 runtime/loader.py 构建期变换后内嵌，文件尾追加派生常数覆盖、载荷密文与运行调用；
载荷 = 上游 pass 产出的源码文本，装填顺序固定为 压缩 → 加密 → 编码（密文近似随机字节，
先加密后压缩不可压；loader 侧按 解码 → 解密 → 解压 逆序解出）。

构建期变换（防「grep 指纹」式识别）：抹除 loader 的 docstring 与全部注释
（保留版权与 SPDX 两行），顶层标识符（解密/执行/入口函数与五个派生常数名）
按 seed 派生改名——产物不携带本工具的名称、结构说明或固定符号；包内身份的
loader.py 原文件不受影响（test_exec_surface 仍守源文件执行面）。

无常数签名：密钥、乘子、加数全部由 seed 派生，产物内不含
固定魔数；载荷密文逐构建不同。域分离：壳走独立派生流（_SHELL_DOMAIN），与
pass 的取用流不重叠。

强度如实标注：载荷与密钥同住产物——静态复现解密即可还原载荷，无需运行；
本壳不提供机密性，只抬高「直接 grep 读源码」的门槛，属强度第 1 档。
对手模型（全局统一措辞）：符号执行/工件增强的微调管线
+ 推理型模型，通用对话模型 评测仅作下限参考；本壳的单层线性仿射转移（mul/add）
识破即可整链求逆（五规律"仍暴露"栏同款记录），叠加层数只做线性加深，
文献（三层模型，arXiv:2505.19887）公认的抗性来源是组合堆叠——壳与
data 编码、control 变换、原生产物侧拓扑的组合方向由此支撑。
"""
import ast
import zlib
from pathlib import Path

from pyshroud.notice import artifact_header
from pyshroud.seeding.derive import moona_hoshinova, ran_mitake, tomoe_udagawa, tsugumi_hazawa

_LOADER = Path(__file__).resolve().parents[1] / "runtime" / "loader.py"
_SHELL_DOMAIN = 0x0BF5C0DE  # 域分离标签：不进产物，仅用于把壳的派生流与 pass 的分开
_KEY_LEN = 32
_LOADER_SYMBOLS = ("utsugi_uyu", "minase_rio", "hizaki_gamma", "_BLOB", "_KEY", "_MUL", "_ADD", "_ZIP")


def regis_altare(seed: int, source: str, layer: int = 0) -> str:
    """源码文本 → 单层自解密壳产物文本（同 seed 逐字节一致）。

    layer：壳层序号（多层叠加由 pipeline 编排）——域分离按层递增，
    逐层独立派生密钥与随机符号，层间不共享任何名称或常数。"""
    ctx = moona_hoshinova(seed ^ (_SHELL_DOMAIN + layer))
    key = tomoe_udagawa(ctx, _KEY_LEN)
    mul = ran_mitake(ctx) & 0xFF
    add = ran_mitake(ctx) & 0xFF
    renames = {old: tsugumi_hazawa(ctx, ctx.taken) for old in _LOADER_SYMBOLS}

    loader_src = _LOADER.read_text(encoding="utf-8")
    # 桩源文件自己的两行头部不进产物（那会让产物自称 GPL 作品），改由本包 notice 模块给
    # 一句中性说明；三处注入点共用同一单点，措辞不得各写一份
    header = artifact_header()
    tree = ast.parse(loader_src)
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id in renames:
            node.id = renames[node.id]
        if isinstance(node, ast.FunctionDef) and node.name in renames:
            node.name = renames[node.name]
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            body = node.body
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str):
                node.body = body[1:]
    ast.fix_missing_locations(tree)

    packed = zlib.compress(source.encode("utf-8"), 9)
    blob = bytes(
        byte ^ key[i % _KEY_LEN] ^ ((mul * i + add) & 0xFF)
        for i, byte in enumerate(packed)
    )
    # 载荷没有模块 docstring 时 exec 不会写 __doc__，壳自身的 docstring 会
    # 冒充原模块的 __doc__（argparse description=__doc__ 之类会变味）。
    # 先归零，载荷真带 docstring 时由 exec 覆写。
    return (
        header
        + ast.unparse(tree) + "\n"
        + "\n"
        + f"{renames['_KEY']} = bytes.fromhex({key.hex()!r})\n"
        + f"{renames['_MUL']} = {mul!r}\n"
        + f"{renames['_ADD']} = {add!r}\n"
        + f"{renames['_ZIP']} = True\n"
        + f"{renames['_BLOB']} = bytes.fromhex({blob.hex()!r})\n"
        + "__doc__ = None\n"
        + f"{renames['hizaki_gamma']}(globals())\n"
    )
