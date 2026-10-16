# Copyright (C) 2026 Diderde
# SPDX-License-Identifier: GPL-3.0-only
"""发布特征测试。

- 产物内无开发机绝对路径形状（盘符、C:\\Users、/Users/、/home/ 等）；
- 无 Bidi 控制符与同形字符（Trojan Source 供应链自检；标识符一律 ASCII）；
- 无常量签名双向验证：确定性锚定三元组 (工具版本, 解释器版本, seed) 下
  同 seed 逐字节一致、异 seed 产物必异（三档各验）；
- 构建端随机纪律：pyshroud 源码零 import random/secrets/numpy/z3
  （确定性随机源 + 构建端仅标准库的机械化）。
- 公开面剥离门（`release_public_surface`）：发布面构建器整树自检 + 植入负例，
  证明"标记剥得掉、剥不干净会报红、排除清单不会滞后"。
- 许可证一致性门（`release_license_consistency`）：SPDX 头 == pyproject 声明 == `LICENSE`
  逐字正文（GPLv3），产出例外文件在位、随发行件走、并被内嵌进产物的壳指名。

命名池：本文件消耗 #263 `milan_kestrel`、#264 `kitami_yusei`。
"""
import ast
import re
import sys
import time
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT))

import pyshroud
from pyshroud.pipeline import kageyama_shien, yukina_minato
from pyshroud.passes.shell import regis_altare
from tests.scratch import scratch

_SAMPLE = _ROOT / "samples" / "sample_06.py"
_PATH_SHAPES = [
    re.compile(r"\b[A-Za-z]:\\"),
    re.compile(r"\b[A-Za-z]:/"),
    re.compile(r"/Users/"),
    re.compile(r"/home/"),
    re.compile(r"\bUsers[\\\\/]+[A-Za-z]"),
]
# 构建端源码扫描的系统路径豁免：GUI 字体查找表（C:/Windows/Fonts/*）是
# 运行时系统目录、不含用户名与工作区痕迹，非开发机泄露（用例校准）。
_SOURCE_PATH_EXEMPT = re.compile(r"C:/Windows/Fonts/")
_BIDI_CHARS = {0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069, 0x200E, 0x200F, 0x061C}
_FORBIDDEN_IMPORTS = {"secrets", "numpy"}
# 允许 import random 的构建端文件（仅限 SystemRandom 用法，理由见 spade_echo）
_RANDOM_ALLOWED = {"gui.py", "cli.py"}
# 自指免疫：本文件里出现的标记短语、仓外约定文件名与方法论名一律**拼接**得到——否则
# 发布面剥离规则会改写测试自己的期望值（实测：字面量被剥成 "x = 1  # " 后断言自毁）。
_TRACE = "say no to " + "perv."
_DOCFILE = "AG" + "ENTS"
_METHOD = "Cave" + "man"
# 日期样本一律拼接构造：写连续的会被 dates 层命中，自指免疫门（milan_kestrel）当场报红。
_D_DATE = "20" + "26-10-09"
_D_DATE_SLASH = "20" + "26/10/9"
_D_DATE_CN = "20" + "26年10月9日"
_D_DATE_COMPACT = "20" + "261009"
_NOT_DATE = "20" + "000000"      # 8 位常量：月日非法，不得被判成日期（实测踩过 JSON 被改坏）
_VERSIONISH = "3.12.10"          # 版本串：不得被判成日期
# 项目自身许可证与产出例外（正文见 `LICENSE`，例外见 `LICENSE.exception`）。GPLv3 正文的
# SHA-256 取自权威公告件（https://www.gnu.org/licenses/gpl-3.0.txt，逐字采集，
# 行尾归一后的字节序列）——用它证明"逐字副本"，而不是靠人读一遍。
_PROJECT_LICENSE = "GPL-3.0-only"
_GPL3_SHA256 = "3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986"
_SPDX_RE = re.compile(r"SPDX-License-Identifier:\s*(\S+)")


def _spdx_of(text: str):
    m = _SPDX_RE.search(text)
    return m.group(1) if m else None


def _artifact_for(profile, seed):
    source = _SAMPLE.read_text(encoding="utf-8")
    passed = yukina_minato(source, seed, passes=kageyama_shien(profile))
    if profile in ("standard", "max"):
        return regis_altare(seed, passed)
    return passed


def kobo_kanaeru():
    """三档产物零绝对路径形状。"""
    for profile in ("minimal", "standard", "max"):
        artifact = _artifact_for(profile, 42)
        for pattern in _PATH_SHAPES:
            hit = pattern.search(artifact)
            if hit:
                raise AssertionError(f"path shape {pattern.pattern!r} in {profile} artifact near {hit.group(0)!r}")
        print(f"  [PASS] {profile}: no dev-machine path shapes")
    # 全量源面（构建端自身）也不含路径形状（系统字体表豁免，见 _SOURCE_PATH_EXEMPT）
    for path in sorted((_ROOT / "pyshroud").rglob("*.py")):
        text = path.read_text(encoding="utf-8")
        for pattern in _PATH_SHAPES:
            for hit in pattern.finditer(text):
                line_head = text[: hit.start()].rsplit("\n", 1)[-1]
                if _SOURCE_PATH_EXEMPT.search(line_head) or _SOURCE_PATH_EXEMPT.search(text[max(0, hit.start() - 40):hit.start() + 20]):
                    continue
                raise AssertionError(f"path shape in build-side source: {path.name} near {hit.group(0)!r}")
    print("  [PASS] build-side sources: no dev-machine path shapes (system font table exempt)")


def yogiri():
    """三档产物：零 Bidi 控制符；全部标识符 ASCII（同形字符防线）。"""
    for profile in ("minimal", "standard", "max"):
        artifact = _artifact_for(profile, 42)
        bad = sorted({ch for ch in artifact if ord(ch) in _BIDI_CHARS})
        if bad:
            raise AssertionError(f"bidi control chars in {profile} artifact: {[hex(ord(c)) for c in bad]}")
        tree = ast.parse(artifact)
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.Name):
                names.append(node.id)
            elif isinstance(node, ast.arg):
                names.append(node.arg)
            elif isinstance(node, ast.Attribute):
                names.append(node.attr)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                names.append(node.name)
            for name in names:
                if not name.isascii():
                    raise AssertionError(f"non-ASCII identifier {name!r} in {profile} artifact")
        print(f"  [PASS] {profile}: no bidi chars, all identifiers ASCII")


def civia():
    """确定性锚定三元组：同 (工具版本, 解释器版本, seed) 逐字节一致；异 seed 必异。"""
    anchor = (pyshroud.__version__, sys.version.split()[0])
    for profile in ("minimal", "standard", "max"):
        a = _artifact_for(profile, 42)
        b = _artifact_for(profile, 42)
        c = _artifact_for(profile, 43)
        if a != b:
            raise AssertionError(f"{profile}: same seed must be byte-identical (anchor={anchor})")
        if a == c:
            raise AssertionError(f"{profile}: different seed gave identical artifact")
        print(f"  [PASS] {profile}: byte-identical under anchor {anchor}, seed-sensitive")


def spade_echo():
    """构建端随机纪律（用法级）：零 import secrets/numpy；
    random 仅允许 SystemRandom（生产默认口径：用户侧种子挑选）——
    random 的其他属性用法与测试目录内任何 random 一律禁止。
    z3 仅限 validation.py（pass 验证依赖，懒加载）。

    允许持有 random 的文件走**显式名单**：这些文件只用 SystemRandom 取种子，
    新增一处即需在此登记（与执行面列白同法，避免"多加一个文件名就悄悄放行"）。"""
    offenders = []
    for path in sorted((_ROOT / "pyshroud").rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root = alias.name.split(".")[0]
                    if root in _FORBIDDEN_IMPORTS or (root == "z3" and path.name != "validation.py") or (root == "random" and path.name not in _RANDOM_ALLOWED):
                        offenders.append(f"{path.name}:{node.lineno} import {alias.name}")
            elif isinstance(node, ast.ImportFrom):
                root = (node.module or "").split(".")[0]
                if root in _FORBIDDEN_IMPORTS or (root == "z3" and path.name != "validation.py") or (root == "random" and path.name not in _RANDOM_ALLOWED):
                    offenders.append(f"{path.name}:{node.lineno} from {node.module}")
            elif isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "random":
                if node.attr != "SystemRandom":
                    offenders.append(f"{path.name}:{node.lineno} random.{node.attr} (only SystemRandom allowed)")
    if offenders:
        raise AssertionError(f"random discipline violations in build-side: {offenders}")
    print(f"  [PASS] no secrets/numpy; random confined to SystemRandom in {sorted(_RANDOM_ALLOWED)}; "
          "z3 confined to validation.py (lazy)")


def milan_kestrel():
    """公开面构建器的齿：整树正例 + 三条植入负例，全部实测（不写"应该能咬"）。

    正例钉五件事：残留为零、行数不变、幂等、逐字区字节相同、计数可推导
    （入 - 排除 == 出）；同时**如实报出**默认关闭的 process 层仍有命中——
    分层是为了不把维护者的决策锚点一起拆掉，不是用来假装干净。
    负例证明门真咬人：植入标记的临时 git 仓必须先被认成命中；剥完会留空括号的
    行必须报 problems；--exclude 写了未跟踪路径必须报错（否则排除清单会悄悄滞后）。
    """
    import subprocess
    from scripts.public_surface import (_ALL_TIERS, _DEFAULT_TIERS, _is_verbatim,
                                        _prose_ranges, _strip_text, shioriha_ruri,
                                        tachitsute_toto)

    # 公开面检出上本机载体与内部设计记录本来就缺席（这正是排除清单生效的证据），
    # 整树自检的对象是开发线树，公开面上无从谈起：如实跳过，不计合格。
    if not any((_ROOT / n).exists() for n in (".gitignore", "SIDES.md", "PROFILES.md")):
        return "SKIP"

    with scratch(prefix="pubsurf-") as tmp:
        tmp = Path(tmp)
        stage = tmp / "stage"
        report = tachitsute_toto(_ROOT, stage, _DEFAULT_TIERS)
        assert report["clean"], "整树自检失败: %s" % report["problems"]
        assert report["files_in"] - len(report["excluded"]) == report["files_out"], \
            "计数不可推导: %s" % report
        residual = shioriha_ruri(stage, _DEFAULT_TIERS)
        assert all(n == 0 for n in residual.values()), "暂存树仍有残留: %s" % residual
        assert not (stage / ".gitignore").exists(), ".gitignore 是本机信息载体，不得进公开面"
        assert ".gitignore" in report["excluded"], "排除清单没生效: %s" % report["excluded"]
        # 内部设计记录不得进公开面：`SIDES.md`（四侧分工）与 `PROFILES.md`（技术自述，
        # 写透容器格式/密钥派生/VM 结构）——公开它们等于替攻击者降成本（维护者已裁决）。
        for doc in ("SIDES.md", "PROFILES.md"):
            assert doc not in {p.relative_to(stage).as_posix() for p in stage.rglob("*")}, \
                "%s 不得进公开面" % doc
            assert doc in report["excluded"], "排除清单漏了 %s: %s" % (doc, report["excluded"])
        assert shioriha_ruri(stage, ("process",))["process"] > 0, \
            "process 层默认关闭，但必须如实报出仍有命中（关层 ≠ 没问题）"
        verbatim = _ROOT / "Licenses" / "native-product" / "CPython-3.12.10-PSF-License.txt"
        assert (stage / verbatim.relative_to(_ROOT)).read_bytes() == verbatim.read_bytes(), \
            "第三方许可原件被改写（逐字区失守）"
        # 本项目自己的法律文本也在逐字区：GPLv3 正文自述"允许逐字复制、不允许修改"，
        # 被规则吃掉一格就是改写了许可证本身
        for legal in ("LICENSE", "LICENSE.exception"):
            assert _is_verbatim(legal), "%s 未列入逐字区" % legal
            staged = stage / legal
            if staged.exists():      # 入版控后才会出现在暂存树里
                assert staged.read_bytes() == (_ROOT / legal).read_bytes(), \
                    "%s 被剥离规则改写（法律文本必须逐字）" % legal
        assert not (stage / "Licenses" / "README.md").read_bytes().startswith(b"\xef\xbb\xbf")
        # 自指免疫：构建器与本测试文件在**全四层**下都必须逐字节不变——规则串里若混进
        # 可被自己命中的字面量，剥离会把规则本身改坏（首版实测正是这样）
        for rel in ("scripts/public_surface.py", "tests/pyshroud/test_release_surface.py"):
            origin = (_ROOT / rel).read_text(encoding="utf-8")
            again, counts, _shapes = _strip_text(origin, _ALL_TIERS,
                                                _prose_ranges(origin, rel))
            assert again == origin and not any(counts.values()), "%s 命中自规则" % rel
            staged = stage / rel
            if staged.exists():          # 入版控后才会出现在暂存树里
                assert staged.read_bytes() == (_ROOT / rel).read_bytes(), \
                    "%s 在暂存树里被改写（自指免疫失守）" % rel
        print("  [PASS] 整树: 残留 0、行数不变、幂等、逐字区完好、自指免疫、in=%d out=%d"
              % (report["files_in"], report["files_out"]))

        # 规则形态：四类标记 + 三种指代 + 方法论名，逐条对答案
        exact = [("x = 1  # " + _TRACE, "x = 1"),
                 ("# 口径（" + _TRACE + "）落地", "# 口径落地"),
                 ("// 一致，" + _TRACE, "// 一致"),
                 ("    # （" + _TRACE + "）", ""),          # 整行只有标记：留空行，不删行
                 ("按 " + _DOCFILE + " 约定取 FREE_HEAD 顺序", "按仓内命名池约定取 FREE_HEAD 顺序"),
                 ("never used (" + _DOCFILE + " section 7)", "never used (in-repo discipline)")]
        for src, want in exact:
            got, _counts, shapes = _strip_text(src + "\n", _DEFAULT_TIERS)
            assert got == want + "\n" and not shapes, "%r -> %r (shapes=%s)" % (src, got, shapes)
        assert _strip_text("    # （" + _TRACE + "）\n", _DEFAULT_TIERS)[0] == "\n", "整行标记未留空行"
        # CRLF 回归：本仓全部文件是 CRLF，行尾留着 `\r` 会让 `$` 锚定的剥离规则与残缺
        # 检查同时静默失效（首版实测：剥完整行只剩标记的注释没被吃掉）
        crlf, _c2, sh2 = _strip_text("x = 1  # %s\r\ny = 2（%s）\r\n" % (_TRACE, _TRACE),
                                      _DEFAULT_TIERS)
        assert crlf == "x = 1\r\ny = 2\r\n" and not sh2, repr(crlf)
        # 复合行：标记与方法论名去掉后，技术信息必须还在（"只删标记"的正面证据）
        # 审查条目号拼接构造：文件里出现连续编号会被 process 层的编号规则命中（自指免疫门）。
        _AUDIT_ID = "P" + "2-" + "1"
        got, _c, shapes = _strip_text("// （%s 0.0.40 审查 %s，%s）\n" % (_METHOD, _AUDIT_ID, _TRACE),
                                      _DEFAULT_TIERS)
        assert "0.0.40" in got and _AUDIT_ID in got and _TRACE not in got \
            and _METHOD not in got and not shapes, got
        print("  [PASS] 规则形态: 四类标记与两处指代逐条命中，技术约束本体保留")

        # 散文区掩码（第二步的安全底座）：**代码里的同形标识符必须原样保留**，只有注释与
        # 字符串字面量里的引用标签才被中性化。实测教训：只按"行里有没有汉字"判断，会把
        # `vm_isa.` + 类型名 这种代码属性名删掉（同一行既有代码、又有中文断言消息）。
        # 样例里的编号一律拼接构造，否则本文件会被自己的规则命中（自指免疫门）。
        _U32 = "U" + "32"
        _P31A = "P" + "3-" + "1a"
        _S2 = "S" + "2"
        _mask_code = '    assert f(vm_src, "%s_RANGE") == vm_isa.%s, "位宽双端不一致"\n' % (_U32, _U32)
        _mask_doc = '    """vm_isa：VM 指令集与分块规划（%s）；容器升级 %s。"""\n' % (_P31A, _S2)
        _got_code, _c5, _sh5 = _strip_text(_mask_code, _ALL_TIERS,
                                          _prose_ranges(_mask_code, "x.py"))
        assert "vm_isa.%s" % _U32 in _got_code, "代码属性名被误删: %r" % _got_code
        _got_doc, _c6, _sh6 = _strip_text(_mask_doc, _ALL_TIERS,
                                         _prose_ranges(_mask_doc, "x.py"))
        assert _P31A not in _got_doc and _S2 not in _got_doc, "字符串里的编号未清: %r" % _got_doc
        assert not _sh5 and not _sh6, "掩码剥离引入了残缺: %s %s" % (_sh5, _sh6)
        # 没给掩码 = 上下文不明：散文专用规则必须直接跳过（fail-closed，绝不猜）
        _bare, _c7, _s7 = _strip_text(_mask_doc, _ALL_TIERS)
        assert _bare == _mask_doc, "缺掩码时不应改动: %r" % _bare
        print("  [PASS] 散文区掩码: 代码标识符保留、字符串里的编号中性化、缺掩码即跳过")

        # 级联收尾（同一类坑踩过三次）：编号是斜杠连引时，清掉编号会留下"斜杠+冒号/分隔符"
        # 的混合残串；必须**一次剥离**就清干净，且再剥一层不变（幂等）。编号拼接构造。
        _W4 = "W" + "4"
        _A2 = "A" + "2"
        for _src, _want in (("/// %s/%s：说明\n" % (_W4, _A2), "/// 说明\n"),
                            ("- %s/%s：说明\n" % (_W4, _A2), "- 说明\n"),
                            ("// （%s/%s，补充）\n" % (_W4, _A2), "// （补充）\n")):
            _got, _c8, _sh8 = _strip_text(_src, _ALL_TIERS, _prose_ranges(_src, "x.md"))
            assert _got == _want, "%r -> %r (want %r)" % (_src, _got, _want)
            _again, _c9, _sh9 = _strip_text(_got, _ALL_TIERS, _prose_ranges(_got, "x.md"))
            assert _again == _got, "级联收尾不幂等: %r -> %r" % (_got, _again)
            assert not _sh8 and not _sh9, "级联收尾引入残缺: %s %s" % (_sh8, _sh9)
        print("  [PASS] 级联收尾: 斜杠+冒号/分隔符一次清干净且幂等")

        # 日期层回归（三类坑全部实测踩过）：四种写法必须命中且不留残缺；常量和版本串
        # 必须原样保留（8 位数值曾按日期处理，把 JSON 里的数值换成字符串直接改坏单源文件）。
        date_cases = [("（" + _D_DATE + " 采证）", "（采证）"),
                      ("（" + _D_DATE + "）", ""),
                      ("（维护者，" + _D_DATE + "）", "（维护者）"),
                      ("（" + _D_DATE_SLASH + " 采证）", "（采证）"),
                      ("（" + _D_DATE_CN + "）", ""),
                      ("自 " + _D_DATE + " 起", "自 [日期略] 起"),
                      ("版本串 a, " + _D_DATE + ", b", "版本串 a, b"),
                      (_D_DATE_COMPACT + " 紧凑式", "[日期略] 紧凑式")]
        for src, want in date_cases:
            got, _c, shapes = _strip_text(src + "\n", _DEFAULT_TIERS)
            assert got == want + "\n" and not shapes, \
                "dates: %r -> %r (shapes=%s)" % (src, got, shapes)
        for keep in (_VERSIONISH, "step_budget: " + _NOT_DATE, "chunk 20" + "48"):
            got, _c, _s = _strip_text(keep + "\n", _DEFAULT_TIERS)
            assert got == keep + "\n", "非日期被误伤: %r -> %r" % (keep, got)
        print("  [PASS] 日期层: 四种写法命中且无残缺、常量与版本串不误伤")

        # 负例①②：临时 git 仓植入内容，构建器必须先认出来、再对残缺报红
        # 悬挂分隔符单独拼接：本文件不能被自己的收尾规则命中（自指免疫门）。
        _DANGLING = "\uff0c"
        repo = tmp / "mini"
        repo.mkdir()
        for name, body in (("planted.py",
                            "x = 1  # %s\ny = 2  # 说明\uff08%s%s\uff09\n" % (_TRACE, _DANGLING, _TRACE)),
                           ("clean.py", "z = 3\n")):
            (repo / name).write_text(body, encoding="utf-8")
        for cmd in (["init", "-q"], ["add", "."],
                    ["-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "t"]):
            subprocess.run(["git", *cmd], cwd=str(repo), check=True, capture_output=True,
                           shell=False)
        bad = tachitsute_toto(repo, tmp / "mini-stage", _DEFAULT_TIERS)
        assert not bad["clean"], "植入标记与空括号残缺竟被判干净"
        assert any("residual" in p or "shape" in p for p in bad["problems"]), bad["problems"]
        hits = shioriha_ruri(repo, _DEFAULT_TIERS)
        assert hits["marker"] == 2, "植入的两处标记未被认出: %s" % hits
        print("  [PASS] 负例: 植入标记命中 %d 处，残缺行报 problems" % hits["marker"])

        # 负例③：--exclude 写了未跟踪路径必须报错（防排除清单滞后于内容演进）
        wrong = tachitsute_toto(repo, tmp / "mini-stage2", _DEFAULT_TIERS, ("no/such.py",))
        assert not wrong["clean"] and any("not tracked" in p for p in wrong["problems"]), \
            wrong["problems"]
        print("  [PASS] 负例: 排除清单滞后即报红")


def kitami_yusei():
    """许可证一致性：头 == 声明 == 正文，例外文件在位且随发行件走。

    把"工具本体 GPL-3.0-only、产物不受约束"钉成四件可机械复核的事：
      ① 全部 `.py/.rs/.c/.h` 的 SPDX 标识都等于 `_PROJECT_LICENSE`，且与 pyproject 的
         `license` 值逐字相同（改许可证时这层最容易漏，且工作区纪律要求 SPDX 与
         项目 LICENSE 一致）；
      ② `LICENSE` 是上游 GPLv3 正文的**逐字副本**——按行尾归一后的 SHA-256 与权威值
         比对。例外写成旁边的 `LICENSE.exception`，绝不混进 GPL 正文（该文档本身
         声明"允许逐字复制但不允许修改"）；
      ③ `LICENSE.exception` 在位、含关键限定（只豁免 Output、明写不覆盖工具源码本身），
         并被 pyproject 的 `license-files` 带进发行件；
      ④ 被原样内嵌进产物的壳必须指向该例外——否则产物里留着的是一条会误导的 copyleft 声明。
    另附负例，证明①②不是空转。
    """
    import hashlib
    import subprocess

    from scripts.public_surface import _is_verbatim

    files = [f for f in subprocess.run(["git", "ls-files"], capture_output=True, text=True,
                                       encoding="utf-8", errors="replace", shell=False,
                                       cwd=str(_ROOT)).stdout.splitlines()
             if f.strip() and Path(f).suffix.lower() in (".py", ".rs", ".c", ".h")]
    assert len(files) > 100, "源文件采集异常（%d 个）" % len(files)
    offenders = [f for f in files if _spdx_of((_ROOT / f).read_text(encoding="utf-8")) != _PROJECT_LICENSE]
    assert not offenders, "SPDX 与项目许可证不一致: %s" % offenders[:6]
    pyproject = (_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    declared = re.findall(r'(?m)^license = "([^"]+)"', pyproject)
    assert declared == [_PROJECT_LICENSE], "pyproject 的 license 声明异常: %s" % declared
    lf = re.findall(r"(?m)^license-files = \[([^\]]*)\]", pyproject)
    assert '"LICENSE"' in lf[0] and '"LICENSE.exception"' in lf[0], \
        "license-files 未同时带上 GPL 正文与产出例外: %s" % lf

    body = (_ROOT / "LICENSE").read_bytes().replace(b"\r\n", b"\n")
    assert hashlib.sha256(body).hexdigest() == _GPL3_SHA256, "LICENSE 不是上游 GPLv3 的逐字副本"
    text = body.decode("utf-8")
    assert "Version 3, 29 June 2007" in text and "GNU GENERAL PUBLIC LICENSE" in text
    exc = (_ROOT / "LICENSE.exception").read_text(encoding="utf-8")
    for marker in ("Additional Permission", "Output", "does not apply to this program"):
        assert marker in exc, "产出例外缺少关键限定 %r" % marker
    loader = (_ROOT / "pyshroud" / "runtime" / "loader.py").read_text(encoding="utf-8")
    assert "LICENSE.exception" in loader, "内嵌进产物的壳没指向产出例外"

    # 公开面不得指名仓外的协作约定文件（含章节号）：措辞一律换成不点名的"仓内纪律"。
    # 该词只允许以**拼接形式**出现（构建器规则与本行都如此）：写 contiguous 会被构建器
    # 自己的转义形态规则命中，自指免疫门（milan_kestrel）当场报红——首版正是这样漏检的。
    naming = re.compile(r"\b" + _DOCFILE + r"\b")
    # 修复记录（转义形态盲区）：say no to " + "perv.
    refs = []
    tracked = subprocess.run(["git", "ls-files"], capture_output=True, text=True,
                             encoding="utf-8", errors="replace", shell=False,
                             cwd=str(_ROOT)).stdout.splitlines()
    for rel in tracked:
        p = _ROOT / rel
        if not p.is_file() or _is_verbatim(rel):
            continue
        for i, line in enumerate(p.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            if naming.search(line):
                refs.append("%s:%d" % (rel, i))
    assert not refs, "仓内指名了仓外协作约定文件: %s" % refs[:5]

    # 产物侧表述：产物体内不得出现 SPDX 标识行（那会让孤立分发的产物自称 GPL 作品，
    # 而接收方看不到仓里的 LICENSE.exception）。三处注入点必须共用 pyshroud.notice 单点。
    from pyshroud.notice import ARTIFACT_HEADER, artifact_header
    for site in ("pyshroud/passes/shell.py", "d_side/codec.py", "d_side/arm.py"):
        src = (_ROOT / site).read_text(encoding="utf-8")
        assert "artifact_header()" in src, "%s 未走共用的产物头部单点" % site
        assert "splitlines()[:2]" not in src, "%s 又把桩源文件头部搬进产物了" % site
    surfaces = {}
    for profile in ("minimal", "standard", "max"):
        surfaces["A/" + profile] = _artifact_for(profile, 42)
    from d_side.arm import asuka_toyama
    from d_side.codec import octavio
    sample = _SAMPLE.read_text(encoding="utf-8")
    surfaces["D/v0"] = asuka_toyama(sample, "probe", 7)
    surfaces["D/v2"] = octavio(sample, "probe", bytes.fromhex("cd" * 32),
                               external_key=False)["artifact"]
    for name, text in surfaces.items():
        assert "SPDX-License-Identifier" not in text, "%s 产物体内出现 SPDX 标识行" % name
        first = text.splitlines()[0]
        if name != "A/minimal":     # 无壳产物不内嵌桩，自然没有这段说明
            assert first == ARTIFACT_HEADER[0], "%s 产物头部不是共用单点: %r" % (name, first[:60])
        else:
            assert first != artifact_header().splitlines()[0]
    print("  [PASS] artifact notice: %d 个面无 SPDX 标识行、桩说明来自单点" % len(surfaces))

    # 负例：换掉 SPDX 或改动正文一个字节都必须被认出来
    assert _spdx_of("# SPDX-License-Identifier: MIT") == "MIT"
    assert hashlib.sha256(body + b" ").hexdigest() != _GPL3_SHA256
    print("  [PASS] license: %d 个源文件 SPDX=%s、LICENSE 逐字、例外随发行件走、壳已指向例外"
          % (len(files), _PROJECT_LICENSE))


def _prod_symbols():
    """生产包（pyshroud / b_side / d_side）里的顶层函数名与类名。"""
    names = set()
    for pkg in ("pyshroud", "b_side", "d_side"):
        for path in sorted((_ROOT / pkg).rglob("*.py")):
            try:
                tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
            except SyntaxError:
                continue
            for node in tree.body:
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    names.add(node.name)
    return names


def emma_verde():
    """测试函数名不得与生产符号同名。

    动机是**判据可靠性**：`grep <闸门名>` 曾被用来判断"某闸门是否被测"，而同名
    测试函数让答案恒为"是"——实测踩中三次（natsuiro_matsuri / kanade_izuru /
    utsugi_uyu 既是库内对象又是用例名），其中一次还直接误导了人工审计结论。
    `main` 是两侧共同的入口约定，列入豁免。"""
    prod = _prod_symbols()
    allow = {"main"}
    bad = []
    for path in sorted((_ROOT / "tests").rglob("*.py")):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) \
                    and node.name in prod and node.name not in allow:
                bad.append("%s::%s" % (path.relative_to(_ROOT).as_posix(), node.name))
    assert not bad, "测试函数名与生产符号同名（grep 判据会假阳性）: %s" % bad[:6]
    print("  [PASS] symbol shadowing: 0 处（生产符号 %d 个，豁免 %s）"
          % (len(prod), sorted(allow)))


def doris() -> int:
    """按序执行全部用例；输出 PASS/FAIL 汇总，返回失败数作退出码。"""
    cases = [
        ("release_symbol_shadowing", emma_verde),
        ("release_path_shapes", kobo_kanaeru),
        ("release_bidi_homoglyph", yogiri),
        ("release_determinism", civia),
        ("release_no_random", spade_echo),
        ("release_public_surface", milan_kestrel),
        ("release_license_consistency", kitami_yusei),
    ]
    failed = 0
    for name, fn in cases:
        t0 = time.perf_counter()
        try:
            if fn() == "SKIP":
                print(f"[SKIP] {name} (环境缺席，不计合格，{time.perf_counter() - t0:.1f}s)")
                continue
            print(f"[PASS] {name} ({time.perf_counter() - t0:.1f}s)")
        except AssertionError as exc:
            failed += 1
            print(f"[FAIL] {name}: {exc}")
        except Exception as exc:  # noqa: BLE001 - runner must survive any case error
            failed += 1
            print(f"[FAIL] {name}: unexpected {type(exc).__name__}: {exc}")
    print(f"summary: {len(cases) - failed} passed, {failed} failed")
    return failed


if __name__ == "__main__":
    raise SystemExit(1 if doris() else 0)
