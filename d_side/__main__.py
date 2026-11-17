# Copyright (C) 2026 Diderde
# SPDX-License-Identifier: GPL-3.0-only
"""CLI：`python -m d_side build|check`（与 源码混淆侧 CLI 同风格；不注册 console scripts）。

build：`--source --out --seed(64 位 hex) [--a-shell N] [--vm] [--embed-key]`
  **默认外钥档（0.0.42）**：产物只含 nonce，seed 运行期供（`--key-file`/环境）；
  `--embed-key` 取回内嵌对照档（消融），`--a-shell` 只能与 `--embed-key` 同用。
  硬门顺序：seed 闸门（`sasaki_saku`， 三档）→ `octavio` 打包 → `honma_himawari` 全门
  （跨实现环回 / 语义等价 / RFC 向量 / KPA 自问）→ 发布面扫描 →
  [`--a-shell N`：`nakao_azuma` 包裹 → 包裹产物重跑语义等价 + 严格发布面扫描] → 写盘。
  **任一步失败：绝不写盘。**
  `--vm`： v2 载荷（分块 VM blob，非 marshal code object）；与 `--a-shell` 互斥；
  v2 专用门 `mashiro_meme`（双端语义等价 / blob 结构）+ `suzuka_utako` +  双构建；
  子集外源码构建期硬拒，不回落 v1。
check：`--artifact` → `suzuka_utako`（结构自洽/版本绑定/MAC；fmt_ver 白名单 {1,2}），只校验不运行。
build-native：`--artifact --out [--target-cpu x86-64-v2] [--no-guards] [--embed-home lean|std|full] [--with-notices]`
  → `builder.azuchi_momo`（B 方案：--embed-home 产出单文件 exe，首启释放 home 到本地缓存；
  --with-notices 按档位把该产物需随附的许可文本复制到 `<exe>.licenses/`，名单单一出处
  `native_build._notice_set`，与 `Licenses/README.md` §1.2 对应）
  （native 端到端：check 同款校验门 → 生成钉子（KAT 期望值 Python 侧现算）→
  rc.exe RCDATA → rustc 链接（Brepro+/DEBUG:NONE）→ post-link 摘要入槽（patcher）→
  独立 exe；任一步失败不写盘。守卫默认开，VM/企业 EDR 端点用 --no-guards。）
  v2 产物只能经 build-native 运行（文本形态不可执行）；boot 按格式版本分叉：
  v1 加载同目录 pythonXY.dll 后 marshal 执行，v2 不加载 pythonXX.dll、载荷逐块按需解密。
  `--map-pass-file`（早期轮次 批2-1.3）：对照表口令文件；给了就把 workdir 里的短码对照表
  以 scrypt(口令, salt=nonce) + HMAC-SHA256 计数器流加密成 `errcode_map.enc.json`
  （明文表不落盘）；`decode-map --map <enc> [--pass-file]` 用口令解回明文表。
"""
import argparse
import json
import os
import sys
from pathlib import Path

from d_side.codec import octavio, suzuka_utako
from d_side.keys import sasaki_saku
from d_side.selfcheck import SelfcheckError, makaino_ririmu

_SELF_DIR = Path(__file__).resolve().parent
_BUILD_WORK = Path(".tmp") / "d2a-build"


def nakao_azuma(text: str, seed: bytes, layers: int) -> str:
    """构建期壳包裹：复用 `pyshroud` 的**构建期**壳生成器，非其运行时 loader。"""
    from pyshroud.passes.shell import regis_altare

    return regis_altare(int.from_bytes(seed, "big"), text, layers)


def _source_targets(extra: dict) -> dict:
    """d_side/** 源码扫描目标：剥 docstring 后扫路径与身份串（早期轮次：docstring 引用仓内路径合法）。"""
    targets = dict(extra)
    for path in sorted(_SELF_DIR.glob("*.py")):
        if path.name in ("arm.py", "selfcheck.py"):
            continue  # arm.py：v0 遗留标记（设计稿）；selfcheck.py：扫描器自身模式数据
        targets["source:" + path.name] = path.read_text(encoding="utf-8")
    for path in sorted((_SELF_DIR / "builder").glob("*.py")):
        targets["source:builder/" + path.name] = path.read_text(encoding="utf-8")
    return targets


def kuzuha(args) -> int:
    try:
        seed = bytes.fromhex(args.seed)
    except ValueError:
        print("build: --seed must be 64 hex chars", file=sys.stderr)
        return 2
    if len(seed) != 32:
        print("build: --seed must be exactly 32 bytes (64 hex chars)", file=sys.stderr)
        return 2
    ok, message = sasaki_saku(seed)
    if not ok:
        print("build: seed rejected: %s" % message, file=sys.stderr)
        return 2
    if message:
        print("build: WARNING: %s" % message, file=sys.stderr)

    source_path = Path(args.source)
    out_path = Path(args.out)
    source_text = source_path.read_text(encoding="utf-8")

    try:
        external = not args.embed_key  # 0.0.42：外钥档为默认，--embed-key 取内嵌对照档
        # 参数矛盾在构建**前**拒绝：构建带门副作用（三新门跑批、.tmp 工作目录、
        #  双构建），非法组合先跑一遍完整构建再拒纯属白费
        if args.vm and args.a_shell:
            raise SelfcheckError("--vm cannot be combined with --a-shell "
                                 "(v2 载荷没有可包装的 Python 文本壳)")
        if args.a_shell and external:
            raise SelfcheckError("--a-shell requires --embed-key (壳内文本产物必须自带密钥材料"
                                 "才能过语义等价门；外钥档产物设计上不可独立运行)")
        if args.psiv and not args.vm:
            raise SelfcheckError("--psiv requires --vm")
        if args.input_dependent and not args.vm:
            raise SelfcheckError("--input-dependent requires --vm "
                                 "(输入原语 ARGV/STDIN 是 VM 指令；v1 走真 CPython)")
        if args.shape and not args.input_dependent:
            raise SelfcheckError("--shape 只对 --input-dependent 产物有意义："
                                 "三新门（雪崩/结构否定/拟合齿）断言的是**输入函数**的性质，"
                                 "不读输入的载荷没有可采样的输入")
        if args.input_dependent and not args.shape:
            # 拍板（维护者授权代行）：shape=None 老口径保留，但无形状的
            # input-dependent 产物不跑三新门——构建期明示，不静默
            print("build: WARNING: input-dependent target without --shape runs "
                  "B1 gates only (no hardening gates)", file=sys.stderr)
        result = octavio(source_text, out_path.stem, seed, external_key=external,
                         vm=args.vm, psiv=args.psiv, input_dependent=args.input_dependent,
                         shape=args.shape)
        if args.vm:
            from d_side.selfcheck import mashiro_meme

            mashiro_meme(result, source_text, result["artifact"], _BUILD_WORK)
            ok, reason = suzuka_utako(result["artifact"])
            if not ok:
                raise SelfcheckError("v2 artifact self-check failed: %s" % reason)
            again = octavio(source_text, out_path.stem, seed, external_key=external,
                            vm=True, psiv=args.psiv,
                            input_dependent=args.input_dependent)["artifact"]
            if again != result["artifact"]:
                raise SelfcheckError("I6: v2 rebuild diverged")
        elif external:
            # 外部档精简门（语义等价门不适用——python 形态外部产物设计上不可
            # 直接运行；正确性由 test_native_builder.py 的 native E2E 钉）：
            #  双构建一致 + 结构/MAC 校验（持 seed）+ 发布面扫描。
            again = octavio(source_text, out_path.stem, seed, external_key=True)["artifact"]
            if again != result["artifact"]:
                raise SelfcheckError("I6: external rebuild diverged")
            ok, reason = suzuka_utako(result["artifact"], key=seed)
            if not ok:
                raise SelfcheckError("external self-MAC failed: %s" % reason)
        else:
            from d_side.selfcheck import honma_himawari

            honma_himawari(result, source_text, result["artifact"], _BUILD_WORK)
        final_text = result["artifact"]
        makaino_ririmu({"artifact": final_text})
        makaino_ririmu(_source_targets({}), artifact_strict=False)
        if args.a_shell:
            final_text = nakao_azuma(result["artifact"], seed, args.a_shell)
            honma_himawari(result, source_text, final_text, _BUILD_WORK)
            makaino_ririmu({"artifact-wrapped": final_text})
    except (SelfcheckError, ValueError) as exc:
        print("build: HARD GATE FAILED (nothing written): %s" % exc, file=sys.stderr)
        return 3

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(final_text, encoding="utf-8")
    print("build: wrote %s (schedule %d, payload bucket %d bytes%s%s)"
          % (out_path, result["sched"], len(result["ciphertext"]),
             ", a-shell x%d" % args.a_shell if args.a_shell else "",
             ", embedded-key (B5 control)" if args.embed_key else ", external-key"))
    for warning in result["warnings"]:
        print("build: WARNING: %s" % warning, file=sys.stderr)
    return 0


def yamiyono_moruru(args) -> int:
    artifact = Path(args.artifact).read_text(encoding="utf-8")
    key = None
    if getattr(args, "key_file", None):
        from d_side.builder.native_build import aizono_manami

        key = aizono_manami(Path(args.key_file))
    ok, reason = suzuka_utako(artifact, key=key)
    if ok:
        print("check: artifact verified (structure/version/MAC all pass)%s"
              % (" [%s]" % reason if reason else ""))
        return 0
    print("check: artifact rejected: %s" % reason, file=sys.stderr)
    return 1


def achikita_chinami(args) -> int:
    from d_side.builder.native_build import _copy_notices, _redist_note, azuchi_momo

    artifact = Path(args.artifact).read_text(encoding="utf-8")
    work = Path(args.work) if args.work else _BUILD_WORK.parent / "d2a-native-build"
    map_pass = None
    if args.map_pass_file:
        map_pass = Path(args.map_pass_file).read_text(encoding="utf-8").strip("\r\n")
    try:
        result = azuchi_momo(artifact, Path(args.out), work,
                             target_cpu=args.target_cpu,
                             key_file=Path(args.key_file) if args.key_file else None,
                             guards=not args.no_guards,
                             embed_home=args.embed_home,
                             map_pass=map_pass)
    except (RuntimeError, ValueError) as exc:
        print("build-native: FAILED (nothing written): %s" % exc, file=sys.stderr)
        return 3
    print("build-native: wrote %s%s%s%s%s"
          % (args.out,
             ", target-cpu %s" % args.target_cpu if args.target_cpu else "",
             ", guards off" if args.no_guards else "",
             ", embed-home %s" % args.embed_home if args.embed_home else "",
             ", errcode map %s" % result["errcode_map"]))
    print("build-native: %s" % _redist_note())
    if args.with_notices:
        copied, missing = _copy_notices(args.embed_home, Path(args.out))
        print("build-native: notices -> %s (%d text(s)%s)"
              % (copied[0].parent if copied else "none", len(copied),
                 ", MISSING from Licenses: %s" % ", ".join(missing) if missing else ""))
        if missing:
            print("build-native: license set incomplete, fix the files before distributing",
                  file=sys.stderr)
        elif not args.embed_home:
            print("build-native: exe ships Rust std only; if you distribute a CPython home "
                  "beside it, attach the lean/std/full texts too (Licenses/README.md section 1.2)")
    return 0


def ishigami_nozomi(args) -> int:
    """批2-1.3：`decode-map` —— 口令 + 加密对照表 → 明文表（打印到 stdout）。

    口令来源优先级：`--passphrase`（显式，会进 shell history）→ `--pass-file`
    （推荐）→ 环境变量 `PRACTICE_ERRCODE_PASS`。口令错 ⇒ 表内 `check` 摘要不符
    ⇒ 只报"口令不符"，**不吐半解密的明文**。
    明文表若还是老形态（未加密的 errcode_map.json）直接透传，便于对照。"""
    from d_side.builder.native_build import _MAP_PASS_ENV, koshimizu_toru

    path = Path(args.map)
    if args.passphrase:
        passphrase = args.passphrase
    elif args.pass_file:
        passphrase = Path(args.pass_file).read_text(encoding="utf-8").strip("\r\n")
    else:
        passphrase = os.environ.get(_MAP_PASS_ENV)
    if not passphrase:
        print("decode-map: no passphrase (--passphrase/--pass-file/%s)"
              % _MAP_PASS_ENV, file=sys.stderr)
        return 2
    try:
        table = koshimizu_toru(path, passphrase)
    except (ValueError, OSError) as exc:
        print("decode-map: %s" % exc, file=sys.stderr)
        return 2
    print(json.dumps(table, ensure_ascii=False, indent=1, sort_keys=True))
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="d_side", description="native build/check")
    sub = parser.add_subparsers(dest="command", required=True)

    p_build = sub.add_parser("build", help="source text -> encrypted text artifact")
    p_build.add_argument("--source", required=True)
    p_build.add_argument("--out", required=True)
    p_build.add_argument("--seed", required=True, help="64 hex chars (256-bit recommended)")
    p_build.add_argument("--a-shell", type=int, default=0, choices=(0, 1, 2),
                         help="build-time shell layers (default 0; distributions should use 1)")
    p_build.add_argument("--embed-key", action="store_true",
                         help="B5 对照档：把 32B seed 内嵌进产物（flags 位 4 = 0），产物自带"
                              "密钥材料。默认（不传本参数）为 U1/K2 外钥档：产物只含 nonce，"
                              "seed 由运行期 --key-file/环境变量供给")
    p_build.add_argument("--vm", action="store_true",
                         help="U16 v2: payload is a chunked VM blob (no marshal). "
                              "Native-only artifact; source outside the VM subset is rejected "
                              "at build time")
    p_build.add_argument("--psiv", action="store_true",
                         help="container v3: PSIV chunk AEAD (nonce-misuse resistant, "
                              "key-committing; ePrint 2025/222). Requires --vm")
    p_build.add_argument("--input-dependent", action="store_true",
                         help="早期轮次: the payload must be `def main(argv, stdin)` and must "
                              "actually read the input windows (flags bit 5). Requires --vm; "
                              "the build gate additionally runs 4 probe inputs through both "
                              "engines and refuses a target a replay script can pass")
    p_build.add_argument("--shape", default=None,
                         help="早期轮次+C ablation pin / behaviour-gate declaration "
                              "(linear|b|b-rot|b-couple|b-quad|b-alt|c1|bc). Requires "
                              "--input-dependent; the declared gates (avalanche / "
                              "structure-negation / oracle-fitting tooth, table in "
                              "layout.json > hardening) run at build time and refuse "
                              "the build. Without --shape only the 早期轮次 gates run.")
    p_build.set_defaults(func=kuzuha)

    p_check = sub.add_parser("check", help="verify an existing artifact without running it")
    p_check.add_argument("--artifact", required=True)
    p_check.add_argument("--key-file", default=None,
                         help="32B key material (required to MAC-verify external-key artifacts)")
    p_check.set_defaults(func=yamiyono_moruru)

    p_native = sub.add_parser("build-native", help="artifact -> standalone native exe (D-2a\u2033)")
    p_native.add_argument("--artifact", required=True)
    p_native.add_argument("--out", required=True)
    p_native.add_argument("--key-file", default=None,
                          help="32B key material (required for external-key artifacts)")
    p_native.add_argument("--target-cpu", default=None, choices=("x86-64-v2",),
                          help="enable v2 codegen + runtime CPUID gate (decision pending, 早期轮次)")
    p_native.add_argument("--no-guards", action="store_true",
                          help="D-3: build without runtime guards (VM / enterprise EDR "
                               "endpoints false-positive; architecture doc section 8)")
    p_native.add_argument("--embed-home", default=None, choices=("lean", "std", "full"),
                          help="B: single-file exe — embed CPython home (dll+stdlib[+common pyds]) "
                               "and extract it to LocalAppData on first run; vcruntime is NOT "
                               "embedded (target needs the VC++ x64 redistributable)")
    p_native.add_argument("--with-notices", action="store_true",
                          help="copy the license texts the build actually ships into "
                               "<out>.licenses/ beside the exe (set per embed-home mode, "
                               "single source: Licenses/README.md section 1.2)")
    p_native.add_argument("--work", default=None, help="workdir (default .tmp/d2a-native-build)")
    p_native.add_argument("--map-pass-file", default=None,
                          help="早期轮次 批2-1.3: file holding the errcode-map passphrase; the folded "
                               "code table is then written SCRYPT-encrypted (errcode_map.enc.json) "
                               "and no plaintext table is ever left on disk. Without it (and "
                               "without $PRACTICE_ERRCODE_PASS) the table stays plaintext and the "
                               "build line says so")
    p_native.set_defaults(func=achikita_chinami)

    p_map = sub.add_parser("decode-map", help="passphrase + encrypted errcode map -> plaintext table")
    p_map.add_argument("--map", required=True,
                       help="path to errcode_map.enc.json (早期轮次 批2-1.3 format ECM1)")
    p_map.add_argument("--passphrase", default=None,
                       help="maintainer passphrase (avoids this: shell history / process list)")
    p_map.add_argument("--pass-file", default=None,
                       help="file holding the passphrase (preferred over --passphrase)")
    p_map.set_defaults(func=ishigami_nozomi)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
