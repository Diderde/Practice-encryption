# Copyright (C) 2026 Diderde
# SPDX-License-Identifier: GPL-3.0-only
"""CLI。项目名 Practice-encryption（由 pyshroud 改名对齐工作区文件夹），入口函数按命名池取名。"""
import argparse
import random
import sys

from pyshroud.metrics import elizabeth_rose_bloodflame
from pyshroud.pipeline import _PROFILES, _SHELLED_PROFILES, _SHELL_LAYERS, _read_source, kageyama_shien, sayo_hikawa, yukina_minato
from pyshroud.seeding.derive import MIN_SEED_BITS, suzuha_aki

_SEED_RNG = random.SystemRandom()  # 生产默认口径：不碰普通 random
# `check` 是**只读诊断**（不产出分发物），其默认种子必须**可复现**——
# 否则同一文件的两次检查会给出不同指标，报告失去可比性。
# 故取一枚固定且够强的常量；需要看其它种子下的指标时显式传 --seed。
_CHECK_DEFAULT_SEED = 0x5EED000000000042


def _seed_arg(text):
    """--seed 解析：接受十进制与 0x/0o/0b 前缀（hex 是种子的自然写法）。"""
    try:
        return int(text, 0)
    except ValueError:
        raise argparse.ArgumentTypeError("invalid seed value: %r (decimal or 0x-prefixed)" % text)


def _seed_or_fresh(raw, default=None):
    """--seed 解析与校验：给定时过强度校验；未给定时取 `default`（None 则随机）。

    说明：seed 是全项目唯一秘密输入，小种子空间可被离线穷举（逐候选重建产物比对），
    故 CLI 边界一律校验，且**复用 `suzuha_aki`——那个函数就是"取用种子的唯一入口"**，
    避免校验逻辑在此处再实现一遍（两处实现迟早会漂移）。
    **核心管线不校验**：测试与内部调用需要确定性的小种子。
    未给定时取强随机（面向 build：每次构建互异）；诊断为可复现则传固定 default。"""
    if raw is None:
        return _SEED_RNG.getrandbits(64) if default is None else default
    # suzuha_aki 的 ValueError 已自带 "weak build seed rejected:" 前缀，此处不再重复
    return suzuha_aki(raw)


def kaela_kovalskia(argv=None) -> int:
    """check 子命令：构建产物并输出五项结构指标 + Fa + pass 跳过计数。

    getsource 警示（loader_landmines.md 雷区 4 的项）：standard/max 档
    产物对载荷函数做 inspect.getsource 会优雅降级（拿不到载荷源行）——
    依赖源级自省的框架注册器场景应选 minimal 档，此处对带壳 profile 一律提示。
    """
    parser = argparse.ArgumentParser(prog="Practice-encryption check", description="structural metrics report")
    parser.add_argument("input", help="original .py file")
    parser.add_argument("--seed", type=_seed_arg, default=None,
                        help="build seed (determinism anchor); must have >= %d bits" % MIN_SEED_BITS)
    parser.add_argument("--profile", default="standard", choices=sorted(_PROFILES), help="pass profile")
    args = parser.parse_args(argv)
    try:
        # 诊断命令：默认走固定强种子，保证"同一文件两次检查结果一致"
        args.seed = _seed_or_fresh(args.seed, default=_CHECK_DEFAULT_SEED)
        source = _read_source(args.input)
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    stats = {}
    try:
        passed = yukina_minato(source, args.seed, passes=kageyama_shien(args.profile), stats=stats)
        artifact = passed
        if args.profile in _SHELLED_PROFILES:
            from pyshroud.passes.shell import regis_altare

            artifact = passed
            for layer in range(_SHELL_LAYERS.get(args.profile, 1)):
                artifact = regis_altare(args.seed, artifact, layer)
            # 与 sayo_hikawa 的出口自检对齐：报告口径同样不该来自坏产物。
            compile(artifact, "<Practice-encryption check shelled>", "exec")
    except RecursionError:
        print("error: recursion limit exceeded (input structure too deep for the build passes)", file=sys.stderr)
        return 1
    except (OSError, SyntaxError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    def _emit(tag, base, target):
        report = elizabeth_rose_bloodflame(base, target, stats)
        print(f"[{tag}]")
        print(f"cyclomatic: {report['cyclomatic']['original']} -> {report['cyclomatic']['artifact']} (x{report['cyclomatic']['ratio']})")
        print(f"ast_nodes:  {report['ast_nodes']['original']} -> {report['ast_nodes']['artifact']} (x{report['ast_nodes']['ratio']})")
        print(f"string_entropy: {report['string_entropy']['original']} -> {report['string_entropy']['artifact']} bits/char")
        print(f"string_residuals: {report['string_residuals']} (reduction {report['string_reduction']})")
        print(f"ident_residuals: {report['ident_residuals']} (reduction {report['ident_reduction']})")
        print(f"fa (artifact/src bytes): {report['fa']}")
        return report

    print(f"profile={args.profile} seed={args.seed}")
    _emit("pipeline (passes only)", source, passed)
    if artifact is not passed:
        _emit("distribution (shelled)", source, artifact)
    print(f"pass_stats: {stats}")
    if args.profile in _SHELLED_PROFILES:
        print("warning: shelled profile - inspect.getsource on payload functions degrades (landmine 4); "
              "use --profile minimal if source introspection matters")
    return 0


def lisa_imai(argv=None) -> int:
    """CLI 主入口：子命令分派（check / build / gui）+ build 主体。

    子命令面与 README 对齐；`build` 关键字可省略（兼容旧的裸参数形态）。
    pyproject 的 console script 与 `python -m pyshroud` 共用本函数，安装后
    `Practice-encryption check in.py` 与 `python -m pyshroud check in.py` 行为一致。"""
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv[:1] == ["check"]:
        return kaela_kovalskia(argv[1:])
    if argv[:1] == ["gui"]:
        from pyshroud.gui import artia

        return artia()
    if argv[:1] == ["build"]:
        argv = argv[1:]
    parser = argparse.ArgumentParser(prog="Practice-encryption", description="Practice-encryption build tool")
    parser.add_argument("input", help="input .py file")
    parser.add_argument("output", help="output .py file")
    parser.add_argument("--seed", type=_seed_arg, default=None,
                        help="build seed (determinism anchor); omit for a fresh random seed, "
                             "or pass an explicit value with >= %d bits" % MIN_SEED_BITS)
    parser.add_argument("--profile", default="minimal", choices=sorted(_PROFILES), help="pass profile")
    args = parser.parse_args(argv)
    stats = {}
    try:
        args.seed = _seed_or_fresh(args.seed)
        sayo_hikawa(args.input, args.output, args.seed, profile=args.profile, stats=stats)
    except RecursionError:
        print("error: recursion limit exceeded (input structure too deep for the build passes)", file=sys.stderr)
        return 1
    except (OSError, SyntaxError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    skipped = stats.get("control_skipped", 0)
    flattened = stats.get("control_flattened", 0)
    shell = stats.get("shell_layers", 0)
    print(f"ok: {args.output} (seed={args.seed} control flattened={flattened} skipped={skipped} shell={shell})")
    return 0
