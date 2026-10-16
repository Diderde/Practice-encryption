# Copyright (C) 2026 Diderde
# SPDX-License-Identifier: GPL-3.0-only
"""GUI：Dear PyGui 前端（可选依赖，惰性导入；中英双语可切换并记忆）。

本模块不在导入时引入 dearpygui，只在真正建界面时惰性导入——保持"工具本体仅
标准库"的约束（numpy、z3-solver、dearpygui 均为可选依赖）。依赖缺失时给出可
执行的安装提示，不抛栈。

界面分两个页签，各自复用既有管线，不另起一套实现：
- 源码混淆：build（pipeline.sayo_hikawa）与 check（cli.kaela_kovalskia）；
- 原生 exe：d_side 两阶段（__main__.kuzuha 产 artifact → __main__.
  achikita_chinami 产 exe）。d_side 为研究层、不进发行包，故**惰性导入**：
  缺它时原生页签仍可看，只是构建按钮禁用。

耗时动作在主线程执行，长输入会短暂卡界面（原生构建含 cargo 编译，会更久）。

字体：UI 文案用带中文字形的字体（否则中文渲染为 ?）。右侧流程图**字体随语言切**
——英文绑等宽字体（框线对齐），中文绑带 CJK 字形的字体（等宽英文字体没有汉字
字形，中文会整体变 ?，实测踩过）；优先 SimSun（真等宽 CJK），加载失败逐级回落
到 UI 字体。提示与日志文本带 wrap（px），否则长句被子窗口裁掉。
英文流程图是横排 ASCII（依赖等宽对齐）；中文流程图是纵排（不依赖列宽，理由见
_FLOWS 注释）。

流程图：源码页按档位 minimal/standard/max 各一张（_FLOWS），随档位下拉实时
重画；原生页一张（_NATIVE_FLOW）。**两张都随中英切换整体替换**（英文横排 ASCII、
中文纵排）。口径分别与 pipeline.py 的 profile 表和 d_side/__main__.py 的子命令
一致，改动编排时同步这里。

原生环境自检：建界面时探测 cargo / pythonXY.dll / d_side 可导入性，任一缺失
即禁用"构建原生 exe"并在日志给出可执行安装提示——避免用户点下去才在几分钟
编译后失败。

随机种子：用 random.SystemRandom（生产代码默认口径），不用普通 random。
源码页种子是整数（过 suzuha_aki 强度校验），原生页种子是 64 hex 字符。

偏好：语言选择写入 ~/.Practice-encryption.json；任何 I/O 失败静默回落默认，绝不抛。
"""
import argparse
import contextlib
import io
import json
import os
import pathlib
import random
import shutil
import sys

from pyshroud.seeding.derive import suzuha_aki

_MISSING = "缺少可选依赖 dearpygui（图形界面）。安装：python -m pip install dearpygui"
_PROFILES = ("minimal", "standard", "max")
_SEED_MAX = 2 ** 31
_NATIVE_SEED_BYTES = 32
_RNG = random.SystemRandom()

_FONTS = (
    "C:/Windows/Fonts/msyh.ttc",
    "C:/Windows/Fonts/simhei.ttf",
    "C:/Windows/Fonts/simsun.ttc",
    "/System/Library/Fonts/PingFang.ttc",
    "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
)
_MONO_FONTS = (
    "C:/Windows/Fonts/consola.ttf",
    "C:/Windows/Fonts/cour.tt",
    "C:/Windows/Fonts/lucon.ttf",
    "/System/Library/Fonts/Menlo.ttc",
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
)
# 流程图的中文用字体：等宽英文字体（上面那组）没有 CJK 字形，中文会整体渲染成
# "?"（实测截图）。优先 SimSun —— CJK 全宽、ASCII 半宽，是中文 Windows 上少见的
# "真等宽"CJK 字体，纵排图缩进对齐最好；没有就回落到 UI 的 CJK 字体。
_FLOW_CJK_FONTS = (
    "C:/Windows/Fonts/simsun.ttc",
    "C:/Windows/Fonts/msyh.ttc",
    "/System/Library/Fonts/PingFang.ttc",
    "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
)
# 提示/日志文本的换行宽度（px）。add_text 默认不换行，长句会被子窗口裁掉
# （实测截图：原生页 hint 只显示到"勾「"就没了）。左侧面板宽 560，留出
# 滚动条与内边距后取 530。
_WRAP_PX = 530

_TEXT = {
    "title": ("Practice-encryption 混淆构建器", "Practice-encryption builder"),
    "lang": ("语言", "Language"),
    "in": ("输入", "Input"),
    "out": ("输出", "Output"),
    "browse": ("浏览", "Browse"),
    "seed": ("种子", "Seed"),
    "random": ("随机", "Random"),
    "profile": ("档位", "Profile"),
    "build": ("构建", "Build"),
    "check": ("指标检查", "Check"),
    "flow": ("流程", "Pipeline"),
    "hint": (
        "填输入/输出路径与种子，点构建；点指标检查输出五项结构指标与体积系数 Fa。",
        "Pick input/output and a seed, then Build. Check reports the five structural metrics and Fa.",
    ),
    "err_paths": ("错误：输入与输出路径都要填", "error: input and output paths are required"),
    "err_input": ("错误：先填输入路径", "error: input path is required"),
    "ok_built": ("完成：%s（shell=%s）", "ok: %s (shell=%s)"),
    "err": ("错误：%s", "error: %s"),
    "err_deep": ("错误：输入结构过深，构建中止（递归超限）",
                 "error: input structure too deeply nested (recursion limit)"),
    "tab_source": ("源码混淆", "Source obfuscation"),
    "tab_native": ("原生 exe", "Native exe"),
    "env": ("环境自检", "Environment"),
    "env_blocked": (
        "原生构建已禁用：上面环境自检有未满足项，装好后重启本界面。",
        "Native build disabled: an environment check above failed; install it and restart.",
    ),
    "stage1": ("阶段一：源码 → 中间产物（d_side build）", "Stage 1: source -> artifact (d_side build)"),
    "stage2": ("阶段二：中间产物 → exe（d_side build-native）", "Stage 2: artifact -> exe (d_side build-native)"),
    "nat_src": ("源文件", "Source"),
    "nat_artifact": ("中间产物", "Artifact"),
    "nat_exe": ("输出 exe", "Output exe"),
    "nat_seed": ("种子（64 hex）", "Seed (64 hex)"),
    "nat_keyfile": ("密钥文件", "Key file"),
    "gen_key": ("按种子生成", "From seed"),
    "nat_opts": ("构建选项", "Build options"),
    "vm": ("VM 载荷", "VM payload"),
    "psiv": ("PSIV 容器", "PSIV container"),
    "input_dep": ("输入依赖", "Input-dependent"),
    "embed_key": ("内嵌密钥", "Embed key"),
    "no_guards": ("关闭运行时守卫", "Disable guards"),
    "embed_home": ("内嵌运行环境", "Embed runtime"),
    "build_native": ("构建原生 exe", "Build native exe"),
    "nat_flow_title": ("原生流程", "Native pipeline"),
    "hint_native": (
        "默认走外钥档：产物不含密钥，运行期需密钥文件——点「按种子生成」写一份。"
        "勾「内嵌密钥」则为对照档（产物自带 seed）。",
        "Default is the external-key build: the artifact carries no key, so generate a key file. "
        "Tick 'Embed key' for the embedded-key control build.",
    ),
    "err_native_paths": ("错误：源文件、中间产物、输出 exe 三处都要填",
                         "error: source, artifact and output exe paths are all required"),
    "err_vm_required": ("错误：PSIV 与输入依赖都需要先勾 VM 载荷",
                        "error: PSIV and input-dependent both require VM payload"),
    "err_key_required": (
        "错误：外钥档必须给密钥文件（点「按种子生成」），或勾「内嵌密钥」改用对照档",
        "error: external-key build needs a key file (use 'From seed'), "
        "or tick 'Embed key' for the control build",
    ),
    "err_seed_hex": ("错误：原生种子必须是 64 个 hex 字符（32 字节）",
                     "error: native seed must be 64 hex chars (32 bytes)"),
    "err_key_path": ("错误：先填输出 exe 路径（密钥文件默认写在它旁边）",
                     "error: fill the output exe path first (the key file defaults next to it)"),
    "ok_key": ("已写入密钥文件：%s", "wrote key file: %s"),
    "ok_native": ("完成：%s", "ok: %s"),
    "warn_embed_home": (
        "警告：没找到 pythonXY.dll，内嵌运行环境多半会失败（把它留空，或先修好 CPython home）",
        "warning: pythonXY.dll not found; embedding the runtime will likely fail "
        "(leave it empty, or fix the CPython home first)",
    ),
}
_LANG_ITEMS = (("zh", "中文"), ("en", "English"))
_LANG_CODES = tuple(code for code, _ in _LANG_ITEMS)
_CONFIG_NAME = ".Practice-encryption.json"
_LABELED = {
    "in_path": "in",
    "btn_pick_in": "browse",
    "out_path": "out",
    "btn_pick_out": "browse",
    "seed": "seed",
    "btn_seed": "random",
    "profile": "profile",
    "btn_build": "build",
    "btn_check": "check",
    "lang_combo": "lang",
    "tab_source": "tab_source",
    "tab_native": "tab_native",
    "btn_nat_src": "browse",
    "btn_nat_art": "browse",
    "btn_nat_exe": "browse",
    "btn_nat_key": "browse",
    "btn_nat_seed": "random",
    "btn_gen_key": "gen_key",
    "nat_src": "nat_src",
    "nat_artifact": "nat_artifact",
    "nat_exe": "nat_exe",
    "nat_seed": "nat_seed",
    "nat_keyfile": "nat_keyfile",
    "nat_env_title": "env",
    "stage1": "stage1",
    "stage2": "stage2",
    "nat_opts": "nat_opts",
    "nat_vm": "vm",
    "nat_psiv": "psiv",
    "nat_input_dep": "input_dep",
    "nat_embed_key": "embed_key",
    "nat_no_guards": "no_guards",
    "nat_embed_home": "embed_home",
    "btn_build_native": "build_native",
    "nat_flow_title": "nat_flow_title",
    "hint_native": "hint_native",
}

# 流程图：源码页按档位 minimal/standard/max 各一张，口径与 pipeline.py 的 profile
# 表一一对应（minimal = layout+data 无壳；standard = +control×1+单层壳；
# max = control×2+双层壳）。改动 pass 编排时同步这里。

# 中英各一套，随语言切换整体重画。
# **英文版用横排 ASCII**：列窄，框线能对得很齐。
# **中文版用纵排**：CJK 是双宽字符，横排多列的列宽会随字形与字体回退漂移，硬
# 对齐必然错位；纵排每行自成一列、不依赖列宽，反而更稳也更好读。
# 两种形态宽度上限均 82 列（右侧面板 + 等宽 13px 的可视余量内）。
_FLOWS = {
    "minimal": {
        "en": (
            " profile: minimal   (no shell)",
            "  in.py",
            "                                                     out.py",
            " ",
            " +-------+   +--------+   +------+   +---------+",
            " | PARSE |-->| LAYOUT |-->| DATA |-->| UNPARSE | --> out.py",
            " +-------+   +--------+   +------+   +---------+",
            " ast.parse   rename       str enc    ast.unparse",
            "             const pool   decoder",
            "             junk code    salted",
            " ",
            " artifact: stdlib only / self-contained",
            "           reproducible by (tool version, python version, seed)",
        ),
        "zh": (
            " 档位: minimal（无壳）",
            " ",
            "  输入 in.py",
            "    |",
            "    v",
            "  [1] 解析    ast.parse                  源码 -> AST",
            "    |",
            "    v",
            "  [2] 布局标识符改名 / 常量池 / 垃圾代码",
            "    |",
            "    v",
            "  [3] 数据字符串加密 / 解码器 / 加盐",
            "    |",
            "    v",
            "  [4] 回写    ast.unparse",
            "    |",
            "    v",
            "  输出 out.py",
            " ",
            "  产物：仅标准库 / 自包含",
            "        由（工具版本, Python 版本, seed）可复现",
        ),
    },
    "standard": {
        "en": (
            " profile: standard   (control x1 + single self-decrypt shell)",
            "  in.py",
            "                                                                            out.py",
            " ",
            " +-------+   +--------+   +------+   +------+   +---------+   +-------+",
            " | PARSE |-->| LAYOUT |-->| CTRL |-->| DATA |-->| UNPARSE |-->| SHELL | --> out.py",
            " +-------+   +--------+   +------+   +------+   +---------+   +-------+",
            " ast.parse   rename       flatten    str enc    ast.unparse   loader",
            "             const pool   br fn      decoder                  xor blob",
            "             junk code    key tab    salted                   exec x1",
            " ",
            " artifact: stdlib only / self-contained",
            " shell: runtime/loader.py template / xor stream / single exec site",
        ),
        "zh": (
            " 档位: standard（控制流 x1 + 单层自解密壳）",
            " ",
            "  输入 in.py",
            "    |",
            "    v",
            "  [1] 解析      ast.parse                源码 -> AST",
            "    |",
            "    v",
            "  [2] 布局标识符改名 / 常量池 / 垃圾代码",
            "    |",
            "    v",
            "  [3] 控制流扁平化 / 分支函数 / 键表",
            "    |",
            "    v",
            "  [4] 数据字符串加密 / 解码器 / 加盐",
            "    |",
            "    v",
            "  [5] 回写      ast.unparse",
            "    |",
            "    v",
            "  [6] 加壳      runtime/loader.py 模板 / XOR 流 / 单次 exec",
            "    |",
            "    v",
            "  输出 out.py",
            " ",
            "  产物：仅标准库 / 自包含",
            "  壳：runtime/loader.py 模板 / XOR 流 / 单层 exec 点",
        ),
    },
    "max": {
        "en": (
            " profile: max        (control x2 + double self-decrypt shell)",
            "  in.py",
            "                                                                            out.py",
            " ",
            " +-------+   +--------+   +------+   +------+   +---------+   +-------+",
            " | PARSE |-->| LAYOUT |-->| CTRL |-->| DATA |-->| UNPARSE |-->| SHELL | --> out.py",
            " +-------+   +--------+   +------+   +------+   +---------+   +-------+",
            " ast.parse   rename       flatten    str enc    ast.unparse   loader",
            "             const pool   br fn      decoder                  xor blob",
            "             junk code    key tab    salted                   exec x1",
            "                          rounds 2   SHELL x2 (nested)",
            " ",
            " artifact: stdlib only / self-contained",
            " shell: runtime/loader.py template / xor stream / nested exec x2",
        ),
        "zh": (
            " 档位: max（控制流 x2 + 双层自解密壳）",
            " ",
            "  输入 in.py",
            "    |",
            "    v",
            "  [1] 解析      ast.parse                源码 -> AST",
            "    |",
            "    v",
            "  [2] 布局标识符改名 / 常量池 / 垃圾代码",
            "    |",
            "    v",
            "  [3] 控制流扁平化 / 分支函数 / 键表 / 两轮",
            "    |",
            "    v",
            "  [4] 数据字符串加密 / 解码器 / 加盐",
            "    |",
            "    v",
            "  [5] 回写      ast.unparse",
            "    |",
            "    v",
            "  [6] 加壳      runtime/loader.py 模板 / XOR 流 / 嵌套 exec x2",
            "    |",
            "    v",
            "  输出 out.py",
            " ",
            "  产物：仅标准库 / 自包含",
            "  壳：runtime/loader.py 模板 / XOR 流 / 嵌套 exec x2",
        ),
    },
}

# 原生页流程图：两阶段，与 d_side/__main__.py 的 build / build-native 一致。
# 同样中英各一套；中文用纵排的理由见 _FLOWS 上方注释。
_NATIVE_FLOW = {
    "en": (
        " native: source -> artifact -> exe   (two stages)",
        " ",
        "  in.py",
        "    |",
        "    v",
        " +---------+   +---------------------------+   +----------+",
        " |  BUILD  |-->| VM / PSIV / input-dep ?   |-->| ARTIFACT |",
        " +---------+   +---------------------------+   +----------+",
        "  seed 64h      gates run at build time          |",
        "                (refuse a degenerate target)     |",
        "                                                 v",
        "                        +---------------+   +---------+",
        "                        | BUILD-NATIVE  |-->| app.exe |",
        "                        +---------------+   +---------+",
        "                          cargo (Rust)      no export table",
        "                          pythonXY.dll     no marshal.loads",
        " ",
        " stage 1 = d_side build         (pure Python, no toolchain)",
        " stage 2 = d_side build-native  (needs cargo + CPython home)",
    ),
    "zh": (
        " 原生：源码 -> 中间产物 -> exe（两阶段）",
        " ",
        "  输入 in.py",
        "    |",
        "    v",
        "  阶段一  d_side build",
        "          种子（64 hex）",
        "          可选：VM 载荷 / PSIV 容器 / 输入依赖",
        "          构建期跑门，退化产物直接拒绝",
        "    |",
        "    v",
        "  中间产物  artifact",
        "    |",
        "    v",
        "  阶段二  d_side build-native",
        "          需要 cargo（Rust 工具链）",
        "          仅「内嵌运行环境」需要 pythonXY.dll",
        "    |",
        "    v",
        "  输出 app.exe（无导出表 / 不做 marshal.loads）",
        " ",
        "  阶段一：纯 Python，不需要工具链",
        "  阶段二：需要 cargo 与 CPython home",
    ),
}


def _config_path():
    """偏好文件路径；PYSHROUD_CONFIG 可覆盖（测试用，避免动真实 home）。"""
    override = os.environ.get("PYSHROUD_CONFIG")
    return pathlib.Path(override) if override else pathlib.Path.home() / _CONFIG_NAME


def _load_lang():
    """读语言偏好。文件缺失/损坏/取值非法一律回落默认，绝不抛。"""
    try:
        with open(_config_path(), "r", encoding="utf-8") as fh:
            code = json.load(fh).get("lang")
        return code if code in _LANG_CODES else _LANG_CODES[0]
    except (OSError, ValueError, AttributeError):
        return _LANG_CODES[0]


def _save_lang(code):
    """写语言偏好。尽力而为：失败静默（只读 home、磁盘满都不该影响使用）。"""
    try:
        with open(_config_path(), "w", encoding="utf-8", newline="") as fh:
            fh.write(json.dumps({"lang": code}))
    except OSError:
        pass


def _find_cpython_dll():
    """定位当前解释器的 pythonXY.dll；找不到返回 None。只读探测。

    venv 的 sys.prefix 指向 venv 目录（没有 DLL），真实 home 在 sys.base_prefix，
    两个都要看；个别 venv 配错时 base_prefix 可能是残缺路径，故一律容错不抛。
    """
    dll = "python%d%d.dll" % sys.version_info[:2]
    for base in (pathlib.Path(sys.prefix), pathlib.Path(sys.base_prefix),
                 pathlib.Path(sys.executable).parent):
        candidate = base / dll
        if candidate.exists():
            return str(candidate)
    return None


def _probe_native_env():
    """原生构建环境自检，返回 (可用与否, 逐行报告, pythonXY.dll 路径或 None)。

    硬性条件只有两条：cargo（build-native 要编译 Rust）与 d_side 可导入。
    pythonXY.dll **不作硬性条件**——只有「内嵌运行环境」（--embed-home）才需要它，
    文件夹档运行期才用到；拿它全局拦截会把合法构建一并挡掉。
    vc_runtime 同样只报告、不拦截（它是分发目标机的运行前提，不是构建前提）。
    """
    lines, ok = [], True

    cargo = shutil.which("cargo")
    if cargo:
        lines.append("cargo: %s" % cargo)
    else:
        ok = False
        lines.append("cargo: MISSING - install Rust: https://rustup.rs "
                     "(or: winget install Rustlang.Rustup)")

    try:
        import d_side  # noqa: F401  仅探测可导入性
    except Exception as exc:  # GUI 不该因为研究层缺失而崩
        ok = False
        lines.append("d_side: NOT importable (%s)" % exc)
    else:
        lines.append("d_side: importable")

    dll = _find_cpython_dll()
    if dll:
        lines.append("cpython: %s" % dll)
    else:
        # 环境行保持纯 ASCII：控制台代码页不保证能显示中文，混入会变乱码
        lines.append("cpython: python%d%d.dll not found "
                     "(optional - only needed by --embed-home)" % sys.version_info[:2])

    # 产物不打包 vcruntime（微软专有再分发件），目标机需系统级 VC++ 运行库。
    # 本机在场与否只作参考、不计入 ok：构建机不等于分发目标机。文案与
    # native_build._redist_note() 各留一份——本模块不得依赖研究层（见模块 docstring）。
    sysroot = os.environ.get("SystemRoot", "")
    if not sysroot:
        lines.append("vc_runtime: unknown (SystemRoot not set)")
    else:
        absent = [n for n in ("vcruntime140.dll", "vcruntime140_1.dll")
                  if not (pathlib.Path(sysroot) / "System32" / n).is_file()]
        if absent:
            lines.append("vc_runtime: MISSING %s here - native exe needs the "
                         "VC++ 2015-2022 x64 runtime: "
                         "https://aka.ms/vs/17/release/vc_redist.x64.exe" % ", ".join(absent))
        else:
            lines.append("vc_runtime: present (system)")
    return ok, lines, dll


def _native_seed():
    """原生页默认种子：32 字节强随机，64 hex 字符（d_side build 的口径）。"""
    return "%064x" % _RNG.getrandbits(_NATIVE_SEED_BYTES * 8)


def rosalyn():
    """建界面树并返回 (dpg, tags)。惰性导入 dearpygui；缺失时抛 ImportError。

    不创建 viewport——正常启动与冒烟测试共用本函数。
    """
    import dearpygui.dearpygui as dpg
    from pyshroud.pipeline import sayo_hikawa
    from pyshroud.cli import kaela_kovalskia

    dpg.create_context()

    ui_font = None
    for candidate in _FONTS:
        if pathlib.Path(candidate).exists():
            with dpg.font_registry():
                ui_font = dpg.add_font(candidate, 18)
            dpg.bind_font(ui_font)
            break

    mono = None
    for candidate in _MONO_FONTS:
        if pathlib.Path(candidate).exists():
            with dpg.font_registry():
                mono = dpg.add_font(candidate, 13)
            break

    # 流程图中文用字体：等宽英文字体没有 CJK 字形，中文会整体变 "?"。
    # 优先 SimSun（真等宽 CJK），加载失败逐个回落，最后回落到 UI 字体——
    # 字体加载失败绝不能拖垮整个界面。
    flow_cjk = None
    for candidate in _FLOW_CJK_FONTS:
        if not pathlib.Path(candidate).exists():
            continue
        try:
            with dpg.font_registry():
                flow_cjk = dpg.add_font(candidate, 14)
            break
        except Exception:  # noqa: BLE001  字体加载失败只降级，不崩
            flow_cjk = None

    state = {"lang": _load_lang()}

    def t(key, *args):
        text = _TEXT[key][0 if state["lang"] == "zh" else 1]
        return text % args if args else text

    def _flow_font():
        """流程图字体随语言选：英文走等宽（框线对齐），中文走带 CJK 字形的字体。"""
        if state["lang"] == "en":
            return mono
        return flow_cjk or ui_font

    def _log(message):
        dpg.add_text(str(message).rstrip(), parent="log", wrap=_WRAP_PX)
        dpg.set_y_scroll("log", -1.0)  # 滚动仅 child_window/表 支持，多行输入框不支持

    def _log_native(message):
        dpg.add_text(str(message).rstrip(), parent="nat_log", wrap=_WRAP_PX)
        dpg.set_y_scroll("nat_log", -1.0)

    def _capture(fn):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = fn()
        return (out.getvalue() + err.getvalue()).strip() or "rc=%s" % rc

    def _run(fn):
        """跑一步构建：捕获输出并返回 (rc, 文本)。

        捕获 Exception（而非仅 OSError/ValueError）：两阶段构建会碰 Rust 工具链、
        临时目录与外部进程，异常类型不受控；GUI 进程不该因一次构建失败而崩。
        """
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                rc = fn()
            except RecursionError:
                return 1, t("err_deep")
            except Exception as exc:  # noqa: BLE001  GUI 边界，见上
                return 1, "%s: %s" % (type(exc).__name__, exc)
        return rc, (out.getvalue() + err.getvalue()).strip()

    def _on_build():
        inp, out_path = dpg.get_value("in_path"), dpg.get_value("out_path")
        if not inp or not out_path:
            _log(t("err_paths"))
            return
        try:
            #  修复（早期轮次）：GUI 与 CLI 同门槛——seed 必经 suzuha_aki 强度校验，
            # 弱种子（如 42）拒绝并落日志，绝不静默产出弱产物
            seed = suzuha_aki(int(dpg.get_value("seed")))
            stats = {}
            sayo_hikawa(inp, out_path, seed,
                        profile=dpg.get_value("profile"), stats=stats)
            _log(t("ok_built", out_path, stats.get("shell_layers", 0)))
        except RecursionError:
            _log(t("err_deep"))
        except (OSError, SyntaxError, ValueError) as exc:
            _log(t("err", exc))

    def _on_check():
        inp = dpg.get_value("in_path")
        if not inp:
            _log(t("err_input"))
            return
        _log(_capture(lambda: kaela_kovalskia(
            [inp, "--seed", str(int(dpg.get_value("seed"))), "--profile", dpg.get_value("profile")])))

    def _on_seed():
        dpg.set_value("seed", _RNG.randrange(1, _SEED_MAX))

    def _on_native_seed():
        dpg.set_value("nat_seed", _native_seed())

    def _on_gen_key():
        """按原生种子写一份 32 字节密钥文件（外钥档运行期用它供钥）。"""
        raw = None
        try:
            raw = bytes.fromhex(str(dpg.get_value("nat_seed")).strip())
        except ValueError:
            raw = None
        if raw is None or len(raw) != _NATIVE_SEED_BYTES:
            _log_native(t("err_seed_hex"))
            return
        path = str(dpg.get_value("nat_keyfile")).strip()
        if not path:
            exe = str(dpg.get_value("nat_exe")).strip()
            if not exe:
                _log_native(t("err_key_path"))
                return
            path = exe + ".key"
            dpg.set_value("nat_keyfile", path)
        try:
            pathlib.Path(path).write_bytes(raw)
        except OSError as exc:
            _log_native(t("err", exc))
            return
        _log_native(t("ok_key", path))

    def _on_native_build():
        src = str(dpg.get_value("nat_src")).strip()
        artifact = str(dpg.get_value("nat_artifact")).strip()
        exe = str(dpg.get_value("nat_exe")).strip()
        if not (src and artifact and exe):
            _log_native(t("err_native_paths"))
            return
        vm = bool(dpg.get_value("nat_vm"))
        psiv = bool(dpg.get_value("nat_psiv"))
        input_dependent = bool(dpg.get_value("nat_input_dep"))
        if (psiv or input_dependent) and not vm:
            _log_native(t("err_vm_required"))
            return
        embed_key = bool(dpg.get_value("nat_embed_key"))
        key_file = str(dpg.get_value("nat_keyfile")).strip()
        if not embed_key and not key_file:
            _log_native(t("err_key_required"))
            return
        try:
            from d_side.__main__ import achikita_chinami, kuzuha
        except ImportError as exc:
            _log_native(t("err", exc))
            return
        rc, text = _run(lambda: kuzuha(argparse.Namespace(
            source=src, out=artifact, seed=str(dpg.get_value("nat_seed")).strip(),
            a_shell=0, embed_key=embed_key, vm=vm, psiv=psiv,
            input_dependent=input_dependent, shape=None)))
        _log_native(text or "rc=%s" % rc)
        if rc != 0:
            return
        embed_home = dpg.get_value("nat_embed_home") or None
        # pythonXY.dll 只在内嵌运行环境时才需要，故不拦构建、只在此处提示一次
        if embed_home and _find_cpython_dll() is None:
            _log_native(t("warn_embed_home"))
        rc, text = _run(lambda: achikita_chinami(argparse.Namespace(
            artifact=artifact, out=exe, work=None, map_pass_file=None,
            target_cpu=None, key_file=key_file or None,
            no_guards=bool(dpg.get_value("nat_no_guards")),
            embed_home=embed_home)))
        _log_native(text or "rc=%s" % rc)
        if rc == 0:
            _log_native(t("ok_native", exe))

    def _flow_title(profile):
        return t("flow") + ": " + profile

    def _render_flow(profile):
        """重画源码页流程图：按当前语言取对应那一套，清空后逐行加入并绑字体。

        字体也随语言切：英文绑等宽，中文绑带 CJK 字形的字体（否则全变 ?）。
        语言切换时由 _on_lang 重调本函数——流程图文本是随语言整体替换的，不是
        只换标题。
        """
        dpg.delete_item("flow_area", children_only=True)
        font = _flow_font()
        for line in _FLOWS.get(profile, {}).get(state["lang"], ()):
            item = dpg.add_text(line, parent="flow_area")
            if font is not None:
                dpg.bind_item_font(item, font)

    def _render_native_flow():
        """重画原生页流程图，同样随语言整体替换、字体也随语言切。"""
        dpg.delete_item("nat_flow_area", children_only=True)
        font = _flow_font()
        for line in _NATIVE_FLOW.get(state["lang"], ()):
            item = dpg.add_text(line, parent="nat_flow_area")
            if font is not None:
                dpg.bind_item_font(item, font)

    def _on_profile():
        picked = dpg.get_value("profile")
        _render_flow(picked)
        dpg.set_value("flow_title", _flow_title(picked))

    def _on_lang():
        picked = dpg.get_value("lang_combo")
        state["lang"] = next((c for c, label in _LANG_ITEMS if label == picked), _LANG_CODES[0])
        _save_lang(state["lang"])
        dpg.configure_item("main_window", label=t("title"))
        for tag, key in _LABELED.items():
            dpg.configure_item(tag, label=t(key))
        dpg.set_value("hint", t("hint"))
        dpg.set_value("hint_native", t("hint_native"))
        dpg.set_value("flow_title", _flow_title(dpg.get_value("profile")))
        # 两张流程图随语言整体重画（英文横排 / 中文纵排）
        _render_flow(dpg.get_value("profile"))
        _render_native_flow()

    def _pick_into(field):
        """文件对话框回调工厂：每个对话框绑定自己的目标字段。

        sender 是对话框 tag（dlg_in/dlg_out），旧实现拿它比对按钮 tag
        "pick_out"，条件恒假——"输出"浏览永远写进输入框。"""
        def _on_pick(sender, app_data):
            if app_data.get("file_path_name"):
                dpg.set_value(field, app_data["file_path_name"])
        return _on_pick

    with dpg.file_dialog(directory_selector=False, show=False, callback=_pick_into("in_path"), tag="dlg_in", width=600, height=380):
        dpg.add_file_extension(".py", color=(120, 220, 120, 255))
    with dpg.file_dialog(directory_selector=False, show=False, callback=_pick_into("out_path"), tag="dlg_out", width=600, height=380):
        dpg.add_file_extension(".py", color=(120, 220, 120, 255))
    with dpg.file_dialog(directory_selector=False, show=False, callback=_pick_into("nat_src"), tag="dlg_nat_src", width=600, height=380):
        dpg.add_file_extension(".py", color=(120, 220, 120, 255))
    with dpg.file_dialog(directory_selector=False, show=False, callback=_pick_into("nat_artifact"), tag="dlg_nat_art", width=600, height=380):
        dpg.add_file_extension(".*", color=(180, 180, 180, 255))
    with dpg.file_dialog(directory_selector=False, show=False, callback=_pick_into("nat_exe"), tag="dlg_nat_exe", width=600, height=380):
        dpg.add_file_extension(".exe", color=(120, 220, 120, 255))
    with dpg.file_dialog(directory_selector=False, show=False, callback=_pick_into("nat_keyfile"), tag="dlg_nat_key", width=600, height=380):
        dpg.add_file_extension(".*", color=(180, 180, 180, 255))

    with dpg.window(tag="main_window", label=t("title")):
        with dpg.tab_bar(tag="tabs"):
            with dpg.tab(label=t("tab_source"), tag="tab_source"):
                with dpg.group(horizontal=True):
                    with dpg.child_window(tag="left_panel", width=560, height=-1):
                        with dpg.group(horizontal=True):
                            dpg.add_input_text(label=t("in"), tag="in_path", width=340)
                            dpg.add_button(label=t("browse"), tag="btn_pick_in", callback=lambda: dpg.show_item("dlg_in"))
                        with dpg.group(horizontal=True):
                            dpg.add_input_text(label=t("out"), tag="out_path", width=340)
                            dpg.add_button(label=t("browse"), tag="btn_pick_out", callback=lambda: dpg.show_item("dlg_out"))
                        with dpg.group(horizontal=True):
                            dpg.add_input_int(label=t("seed"), tag="seed", default_value=42, width=120)
                            dpg.add_button(label=t("random"), tag="btn_seed", callback=_on_seed)
                            dpg.add_combo(list(_PROFILES), label=t("profile"), tag="profile",
                                          default_value="minimal", width=140, callback=_on_profile)
                            dpg.add_combo([label for _, label in _LANG_ITEMS], label=t("lang"), tag="lang_combo",
                                          default_value=dict(_LANG_ITEMS)[state["lang"]], width=110, callback=_on_lang)
                        with dpg.group(horizontal=True):
                            dpg.add_button(label=t("build"), tag="btn_build", callback=_on_build)
                            dpg.add_button(label=t("check"), tag="btn_check", callback=_on_check)
                        dpg.add_separator()
                        with dpg.child_window(tag="log", height=-1, width=-1):
                            dpg.add_text(t("hint"), tag="hint", wrap=_WRAP_PX)
                            dpg.add_text("Practice-encryption GUI")
                    with dpg.child_window(tag="right_panel", width=-1, height=-1):
                        dpg.add_text(_flow_title("minimal"), tag="flow_title")
                        dpg.add_separator()
                        dpg.add_group(tag="flow_area")
                        _render_flow("minimal")

            with dpg.tab(label=t("tab_native"), tag="tab_native"):
                with dpg.group(horizontal=True):
                    with dpg.child_window(tag="nat_left", width=560, height=-1):
                        dpg.add_text(t("env"), tag="nat_env_title")
                        with dpg.child_window(tag="nat_env", height=88, width=-1):
                            pass
                        dpg.add_separator()
                        dpg.add_text(t("stage1"), tag="stage1")
                        with dpg.group(horizontal=True):
                            dpg.add_input_text(label=t("nat_src"), tag="nat_src", width=340)
                            dpg.add_button(label=t("browse"), tag="btn_nat_src", callback=lambda: dpg.show_item("dlg_nat_src"))
                        with dpg.group(horizontal=True):
                            dpg.add_input_text(label=t("nat_artifact"), tag="nat_artifact", width=340)
                            dpg.add_button(label=t("browse"), tag="btn_nat_art", callback=lambda: dpg.show_item("dlg_nat_art"))
                        with dpg.group(horizontal=True):
                            dpg.add_input_text(label=t("nat_seed"), tag="nat_seed", default_value=_native_seed(), width=300)
                            dpg.add_button(label=t("random"), tag="btn_nat_seed", callback=_on_native_seed)
                        dpg.add_separator()
                        dpg.add_text(t("stage2"), tag="stage2")
                        with dpg.group(horizontal=True):
                            dpg.add_input_text(label=t("nat_exe"), tag="nat_exe", width=340)
                            dpg.add_button(label=t("browse"), tag="btn_nat_exe", callback=lambda: dpg.show_item("dlg_nat_exe"))
                        with dpg.group(horizontal=True):
                            dpg.add_input_text(label=t("nat_keyfile"), tag="nat_keyfile", width=280)
                            dpg.add_button(label=t("browse"), tag="btn_nat_key", callback=lambda: dpg.show_item("dlg_nat_key"))
                            dpg.add_button(label=t("gen_key"), tag="btn_gen_key", callback=_on_gen_key)
                        dpg.add_separator()
                        dpg.add_text(t("nat_opts"), tag="nat_opts")
                        with dpg.group(horizontal=True):
                            dpg.add_checkbox(label=t("vm"), tag="nat_vm", default_value=True)
                            dpg.add_checkbox(label=t("psiv"), tag="nat_psiv", default_value=True)
                            dpg.add_checkbox(label=t("input_dep"), tag="nat_input_dep")
                        with dpg.group(horizontal=True):
                            dpg.add_checkbox(label=t("embed_key"), tag="nat_embed_key")
                            dpg.add_checkbox(label=t("no_guards"), tag="nat_no_guards")
                            dpg.add_combo(["", "lean", "std", "full"], label=t("embed_home"),
                                          tag="nat_embed_home", default_value="", width=120)
                        with dpg.group(horizontal=True):
                            dpg.add_button(label=t("build_native"), tag="btn_build_native",
                                           callback=_on_native_build)
                        dpg.add_separator()
                        with dpg.child_window(tag="nat_log", height=-1, width=-1):
                            dpg.add_text(t("hint_native"), tag="hint_native", wrap=_WRAP_PX)
                    with dpg.child_window(tag="nat_right", width=-1, height=-1):
                        dpg.add_text(t("nat_flow_title"), tag="nat_flow_title")
                        dpg.add_separator()
                        dpg.add_group(tag="nat_flow_area")
                        _render_native_flow()

    env_ok, env_lines, _native_dll = _probe_native_env()
    for line in env_lines:
        dpg.add_text(line, parent="nat_env", wrap=_WRAP_PX)
    if not env_ok:
        dpg.configure_item("btn_build_native", enabled=False)
        dpg.add_text(t("env_blocked"), parent="nat_log", wrap=_WRAP_PX)
    return dpg, {"window": "main_window", "log": "log", "nat_log": "nat_log"}


def artia(argv=None) -> int:
    """GUI 入口：建上下文与视口，进入渲染循环。缺依赖时返回 1 并给出安装提示。"""
    try:
        dpg, tags = rosalyn()
    except ImportError:
        print(_MISSING, file=sys.stderr)
        return 1
    dpg.create_viewport(title="pyshroud", width=1200, height=720)
    dpg.setup_dearpygui()
    dpg.show_viewport()
    dpg.set_primary_window(tags["window"], True)
    dpg.start_dearpygui()
    dpg.destroy_context()
    return 0


if __name__ == "__main__":
    raise SystemExit(artia())
