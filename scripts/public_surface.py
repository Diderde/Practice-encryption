# Copyright (C) 2026 Diderde
# SPDX-License-Identifier: GPL-3.0-only
"""发布面构建器：把当前版控树复制成一份"公开面"，逐行剥离协作痕迹并做实验证。

口径（把公开面纪律机械化，不靠人工记忆）：

- **只删标记与过程叙述，保留技术约束本体**：规则全部是行内子串替换，绝不整行删除，
  所以"行数不变"是硬不变量。替换后还要在**被改动的那些行**上扫残缺形态（空括号、
  悬挂分隔符、行尾空注释），且与该行剥离前的同样检测结果做差——只报**新引入**的残缺。
  不做差集就会把代码里合法的空括号对与行尾逗号当成垃圾（首版实测踩中，两错相消）。
- **`Licenses/` 一律逐字搬运**，不参与剥离：法律文本按原文分发，任何改写都可能把它
  变成"另一个版本"。
- **分层**：默认开启五层——`marker`（修复标记短语）、`agents`（指名引用工作区外的协作约定文件，
  含 `\b` 转义形态）、`trace`（调试方法论名与协作叙事用词）、`dates`（完整日期：日期能与外部
  公开信息交叉、反推项目时间线与维护者活动，与轮次代号同级）、`localenv`（本机环境痕迹：
  终端防护产品名与其事件、工作区路径名）；`process`（仓外文档名与轮次代号）默认关闭——
  那些短语同时是维护者的决策锚点，拆掉会连带抽走句子的出处，属于编辑判断，故**发布时显式启用**：
  `--tiers marker,agents,trace,dates,localenv,process`。
  边界：`dates` 只剥**完整日期**（含 8 位紧凑式），`20xx` 裸数字（`2048` 这类常量）不得误伤；
  第三方许可证原文属逐字区，其中的日期原样保留；`.av-allow` 是本仓测试产物的**功能目录名**
  （沿用它的路径语义，不是机器身份），保留不改。
- **工具不碰版本控制**：只写出暂存树 + 打印后续命令序列，git 操作由维护者自己在终端执行。

用法：`python scripts/public_surface.py --out <空目录> [--tiers marker,agents,trace] [--exclude 路径]`
退出码 0 = 暂存树可发布；非 0 = 自检失败（保留现场，不产出"看起来删干净了"的树）。

命名池：本文件消耗 #261 `tachitsute_toto`（构建器）与 #262 `shioriha_ruri`（残留统计）。
"""
import argparse
import ast
import io
import json
import re
import subprocess
import sys
import tokenize
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
_DEFAULT_TIERS = ("marker", "agents", "trace", "dates", "localenv")
_ALL_TIERS = ("marker", "agents", "trace", "process", "dates", "localenv")
# 公开面排除清单：`.gitignore` 本身就是本机信息载体（忽略行逐条暴露装了哪些工具、哪些
# 目录只存在于维护者机器上）；`SIDES.md`（四侧分工与成熟判定）与 `PROFILES.md`（技术自述：
# 写透了容器格式、密钥派生与拓扑、VM 结构、守卫定位）都是**内部设计记录**——按公开面纪律
# 只留在私有开发线：那份自述把逆向路径讲清了，公开它等于替攻击者降成本，与本项目
# "提升逆向成本"的目标方向相反。排除项必须与"新增内容类别"的决策同步扩充——清单滞后于
# 决策，下一次分发就泄漏。`.gitattributes` 同属本地载体，发布时显式排除；`--exclude` 在其上追加。
_DEFAULT_EXCLUSIONS = (".gitignore", "SIDES.md", "PROFILES.md")

# **自指免疫**：规则文本里绝不能出现被规则命中的字面量——首版实测本文件被自己改写
# （三条规则的匹配串带着自己的关键词，连"解释这个坑"的注释也照样中招），规则会静默
# 失效。所有敏感字面量一律拼接得出；门禁再钉一条"本文件剥离后必须逐字节相同"。
_MARK = "say no to " + "perv"
_DOC = "AG" + "ENTS"
_METHOD = "Cave" + "man"
_ASSIST = "本" + "助手族"
_WORKSPACE = "My" + "Python"          # 工作区目录名（本机路径痕迹）
_PRIVLINE = "私有" + "线"              # 协作叙事用词
_MOVEDOUT = "移出" + "本仓"            # 仓外文档迁出叙事
_AVZONE = "AV trust " + "zone"        # 终端防护白名单区的英文说法
_AVPROD = "3" + "60"                  # 终端防护产品名：连数字也要拼接——规则源码本身会随工具公开
# 私有文档引称：文档名 → 中性词（公开面不得出现无法查证的内部文档名与章节号）。
# 一律拼接构造：写连续的词会被自己的规则命中，自指免疫门当场报红。
_CITE_NAMES = (
    ("架构" + "稿", "设计稿"),
    ("施工" + "图", "构建规范"),
    ("文献" + "线", "文献综述"),
    ("资料" + "集", "文献资料"),
    ("立项文" + "本", "立项记录"),
    ("设计定" + "稿", "设计记录"),
    ("校准工" + "件", "参考实现"),
    ("研究装" + "置", "实验装置"),
)
_CITE_MAP = dict(_CITE_NAMES)
_CITE_WORDS = ("|".join(re.escape(v) for _, v in _CITE_NAMES)
               + "|" + re.escape("文献对照") + "|" + re.escape("文献整理"))
# 名称 + 可选章节号（含 `§4/§5` 这种连引）：`\s*` 必须在可选组**内**，
# 否则名称后面那个空格会被一起吃掉（实测：名称后接拉丁字母时，空格消失）。
_CITE_PAT = re.compile(r"(?:" + "|".join(re.escape(t) for t, _ in _CITE_NAMES) + r")"
                       r"(?:\s*\u00a7\s*\d+(?:\.\d+)*(?:\s*/\s*\u00a7?\s*\d+(?:\.\d+)*)*)?")
_CITE_TABLE = "对" + "表"             # 私有文档（不点名：注释里写全称等于把它带进公开面）
_CITE_READ = "精" + "读"              # 文献整理编号：系列编号与条目编号两种形态
_CITE_ACTION = "行动" + "项"
# 内部编号族（第二步）：注释/文档里当**引用标签**用的编号必须中性化——公开读者无从查证。
# 保留：`E-##` 错误码（代码内自解释）、`ISA v#` 技术版本、`T#/V#` 用例名、`L1–L7` 层号。
# 安全性**全靠散文区掩码**（见 `_prose_ranges`）：这些规则只在注释与字符串字面量里生效。
# 实测教训：只按"行里有没有汉字"判断，会把形如 `vm_isa.` 后接类型名的那种**代码属性名**当编号删掉
# （同一行既有代码、又有中文断言消息），源码语法当场就坏。
# G 另加区间保护：BLAKE2s 的 `G0–G3`/`G4–G7` 是 RFC 术语。
_ID_LETTERS = "A" + "BCDFIKM" + "OPSUW"
_PRIME = r"[\u2032\u2033']?"
_ID_RX = re.compile(r"(?<![A-Za-z0-9_\u2013-])(?:L-(?=\d)|[" + _ID_LETTERS + r"])"
                    r"\d{1,2}[a-z]?" + _PRIME + r"(?:[-\u2013][A-Za-z0-9]{1,3})?(?![A-Za-z0-9_])")
# 斜杠开头的编译开关（优化级别之类）：O 族单独一条并前视排除斜杠；
# 其余族允许斜杠连引（引用两个编号时常见），故那条不能排除斜杠。
_O_RX = re.compile(r"(?<![A-Za-z0-9_/\u2013-])O\d{1,2}[a-z]?" + _PRIME +
                   r"(?:[-\u2013][A-Za-z0-9]{1,3})?(?![A-Za-z0-9_])")
_G_RX = re.compile(r"(?<![A-Za-z0-9_/\u2013-])G\d(?![0-9A-Za-z_\u2013-])")
_DINCR_RX = re.compile("D-2" + r"a" + _PRIME)
# 散文区掩码：下列规则只在"散文"（注释/字符串字面量）内生效，代码标识符一个都不碰。
_ALL_PROSE = object()                  # 整文件皆散文（文档/数据类文件）
# 空半角括号只认"前面是空白"的那种（编号被删后留下的空壳）；贴着标识符的 `()` 是
# 代码/源码片段（本仓测试里有 `"artifact_header()"` 这类搜索串），不能动。
_PAREN_EMPTY_RX = re.compile(r"(?<=[ \t])\(\s*\)")
# 括号内侧的散落空白（编号被清后左括号会紧跟空格）：只在散文里做，代码串归掩码保护。
_PAREN_L_RX = re.compile(r"\([ \t]+")
_PAREN_R_RX = re.compile(r"[ \t]+\)")
_SEP_COLLAPSE_RX = re.compile(r"([\uff0c\uff1b\u3001])[ \t]*[\uff0c\uff1b\u3001]")
# 侧命名自描述化（第三步）：那套内部侧位分类的定义只存在于内部记录，公开读者无从查证，故公开面
# 一律换成自描述词。**目录名 `a_side/`…`d_side/` 是真路径，绝不在此列**——本组只匹配
# "某个字母 + 侧"（中文）与 "-side"（英文）两种形态；长形态必须排在前面（正则左最先匹配）。
_SIDE_MAP = (
    ("A" + " 侧产物", "源码混淆产物"),
    ("D" + " 侧 native exe", "原生产物 native exe"),
    ("A" + " 壳", "构建期壳"),
    ("A" + " 侧", "源码混淆侧"),
    ("B" + " 侧", "数学区"),
    ("C" + " 侧", "已废弃档"),
    ("D" + " 侧", "原生产物侧"),
    ("A" + "-side", "obfuscation-side"),
    ("B" + "-side", "math-side"),
    ("C" + "-side", "legacy-side"),
    ("D" + "-side", "native-side"),
)
_SIDE_DICT = dict(_SIDE_MAP)
_SIDE_CH_RX = re.compile(r"(?<![A-Za-z])" + "|".join(
    re.escape(k) for k, _v in _SIDE_MAP if "\u4fa7" in k or k.endswith("\u58f3")))
_SIDE_EN_RX = re.compile(r"(?<![A-Za-z_-])(?:" + "|".join(
    re.escape(k) for k, _v in _SIDE_MAP if k.endswith("-side")) + r")(?![A-Za-z])")
_SIDE_REPL = lambda m: _SIDE_DICT[m.group(0)]
_BENSIDE_RX = re.compile("\u672c" + "\u4fa7")
_PROSE_ONLY = (_ID_RX, _O_RX, _G_RX, _DINCR_RX, _PAREN_EMPTY_RX, _PAREN_L_RX, _PAREN_R_RX,
               _SEP_COLLAPSE_RX, _SIDE_CH_RX, _SIDE_EN_RX, _BENSIDE_RX)
# 日期类信息（公开面不得出现）：只认**完整日期**——年-月-日 三种分隔写法，以及 8 位紧凑式。
# 紧凑式**必须校验月/日合法性**：否则 `step_budget` 那类 8 位常量会被误判成日期，数值换成
# 字符串还会直接破坏 JSON（实测：JSON 解析在第 304 行炸掉，构建器当场拦下）。`20xx` 裸数字照旧不碰。
_DATE = (r"(?<!\d)20\d{2}\s*[-/.年]\s*\d{1,2}\s*[-/.月]\s*\d{1,2}日?"
         r"|(?<!\d)20\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])(?!\d)")

# 规则表：(层, 编译好的正则, 替换串)。顺序敏感——整行与整括号形式必须先于行内形式，
# 否则会先被行内规则拆成空括号，再靠残缺规则兜（两错相消的形态）。
_RULES = (
    # --- marker：修复标记短语（实测四类形态：全角括号 222 / 行内散文 52 /
    #     行尾注释 31 / 半角括号 4，共 309 处，规则逐类覆盖）---
    # 整行只有标记（`# （…）` 这类）最先处理：不先吃掉整行就会把行剥成空注释符——
    # 实测 8 处。处置是留空行而不是删行（行数不变是硬不变量）。
    ("marker", re.compile(
        r"^[ \t]*(?:#[ \t]*|//+[ \t]*|/\*[ \t]*)?（?\s*" + _MARK + r"\.?\s*）?[ \t]*(?:\*/)?$",
        re.I), ""),
    ("marker", re.compile(r"[ \t]+#[ \t]*" + _MARK + r"\.?[ \t]*$", re.I), ""),
    ("marker", re.compile(r"（\s*" + _MARK + r"\.\s*）", re.I), ""),
    ("marker", re.compile(r"[ \t]*\(\s*" + _MARK + r"\.\s*\)", re.I), ""),
    ("marker", re.compile(r"[，,；;、]\s*" + _MARK + r"\.", re.I), ""),
    ("marker", re.compile(_MARK + r"\.", re.I), ""),
    # --- dates：日期类信息（开发线保留时间锚点，公开面一律剥离）---
    # 顺序敏感：先吃掉**包裹形态**（整括号 → 括号内 → 分隔符/行尾/右括号相邻），
    # 最后才用兜底替换。顺序错了会留下空括号或悬挂分隔符（残缺检查会报 problems；
    # 实测两类各中一次：括号内"称谓＋逗号＋日期"，以及版本串里"逗号＋日期＋逗号"）。
    ("dates", re.compile(r"[（(]\s*(?:" + _DATE + r")\s*[)）]"), ""),
    ("dates", re.compile(r"([（(])\s*(?:" + _DATE + r")\s*"), r"\1"),
    ("dates", re.compile(r"([，,、；;])\s*(?:" + _DATE + r")\s*(?=[，,、；;])"), ""),
    ("dates", re.compile(r"([，,、；;])\s*(?:" + _DATE + r")\s*(?=\s*[)）])"), ""),
    ("dates", re.compile(r"([，,、；;])\s*(?:" + _DATE + r")\s*$"), ""),
    ("dates", re.compile(r"\s*(?:" + _DATE + r")\s*(?=\s*[)）])"), ""),
    ("dates", re.compile(r"([，,、；;])\s*(?:" + _DATE + r")"), r"\1"),
    ("dates", re.compile(_DATE), "[日期略]"),
    # --- agents：指名引用工作区外的协作约定文件（公开面不得携带）---
    ("agents", re.compile(r"按\s*" + _DOC + r"\s*约定"), "按仓内命名池约定"),
    ("agents", re.compile(r"\b" + _DOC + r"\s+section\s+\d+", re.I), "in-repo discipline"),
    ("agents", re.compile(r"\b" + _DOC + r"\s*§?\s*\d+(?:\.\d+)*"), "仓内纪律"),
    # 转义形态 `\b<DOC>\b`：常规 `\b` 词边界在此**必然失效**——宿主文本里 DOC 前面那个
    # 字符是字母 `b`（属单词字符），前后都不构成边界（实测：泄漏门禁那一行三条规则全不命中，
    # 只能靠人工补）。故按"反斜杠 b + 名称 + 反斜杠 b"整体识别，替换成等价的分片书写：
    # 正则语义不变、被扫的字面量不再出现在公开面。适用面 = Python/正则源码里的这一种写法。
    ("agents", re.compile(r"\\b" + _DOC + r"\\b"),
     lambda m: '\\b" + "' + _DOC[:2] + '" + "' + _DOC[2:] + '" + r"\\b'),
    # 修复记录（转义形态盲区）：say no to " + "perv.
    ("agents", re.compile(r"\b" + _DOC + r"\b"), "仓内纪律"),
    # --- trace：调试方法论名与协作叙事用词 ---
    ("trace", re.compile(r"\b" + _METHOD + r"\s*"), ""),
    ("trace", re.compile(_ASSIST), "本项目"),
    # 协作叙事：文档迁出与"哪条线"的说法都属于内部流程，公开面换成中性词
    ("trace", re.compile(_PRIVLINE), "内部记录"),
    ("trace", re.compile("按「发布面与历史保持无 docs」的决定" + _MOVEDOUT), "不在本仓内"),
    # --- localenv：本机环境痕迹（终端防护产品名与其事件、工作区路径名）---
    # 只认**定向形态**，不碰裸数字：产品名单独出现可能就是某个常量或角度值。
    ("localenv", re.compile(_AVPROD + r"\s*清除事件"), "终端防护误删事件"),
    ("localenv", re.compile(_AVPROD + r"\s*实时防护"), "终端防护软件"),
    ("localenv", re.compile(_AVPROD + r"\s*云查杀"), "终端防护软件"),
    ("localenv", re.compile(_AVPROD + r"\s*信任区"), "终端防护信任区"),
    ("localenv", re.compile(_AVZONE), "endpoint-protection trust zone"),
    ("localenv", re.compile(_WORKSPACE), "proj"),
    # --- process（默认关，发布时显式启用）：仓外文档名与轮次代号（书名号用 \u 转义，避免自指命中）---
    ("process", re.compile(r"\u300a[^\u300b]{1,60}\u300b"), "仓外文档"),
    # 侧命名自描述化（第三步）：中文形态与英文形态各一条，替换词由 `_SIDE_DICT` 查表。
    ("process", _SIDE_CH_RX, _SIDE_REPL),
    ("process", _SIDE_EN_RX, _SIDE_REPL),
    ("process", _BENSIDE_RX, "\u672c\u6a21\u5757"),
    # 私有文档引称（第一步清理）：公开面不得出现读者无法查证的内部文档名与章节号。
    # 顺序敏感：先长形态（带限定语）→ 再单名（含可选章节号）→ 最后清残留空白。
    # 注意：`Licenses/README.md` 里的 §x.y 是**该台账自己的**章节引用，这些规则不匹配它（无文档名前缀）。
    ("process", re.compile("D侧目标函数与文献" + _CITE_TABLE), "目标函数与文献对照"),
    ("process", re.compile(_CITE_TABLE + r"\s*\u00a7\s*\d+(?:\.\d+)*\s*(?:[+＋]\s*)?"), ""),
    ("process", re.compile(r"[，,]\s*" + "内部" + "评审" + r"\s*\u00a7[^）)]*"), ""),
    ("process", _CITE_PAT, lambda m: _CITE_MAP[m.group(0).split("\u00a7")[0].rstrip()]),
    ("process", re.compile(_CITE_READ + _CITE_ACTION + r"\s*\d*"), "文献整理"),
    ("process", re.compile(_CITE_READ + r"[一二三四五六七八九]"), "文献整理"),
    ("process", re.compile(r"[，,]\s*" + _CITE_ACTION + r"\s*\d+"), ""),
    # 名称替换后可能残留章节号（连引形态）再收一次；并并掉名称后多余的单个空格。
    ("process", re.compile("(" + _CITE_WORDS + r")\s*/?\s*\u00a7\s*\d+(?:\.\d+)*"), r"\1"),
    ("process", re.compile("(" + _CITE_WORDS + r")[ \t]+(?=[\u4e00-\u9fff])"), r"\1"),
    ("process", re.compile(r"（\s+"), "（"),
    ("process", re.compile(r"[ \t]+）"), "）"),
    # 轮次代号：个位数与两位数都要盖住；前后不得是标识符字符，末位不得接数字。
    # 后缀一起吞（批号/子项/末尾单字母），否则会留下"早期轮次后接横杠"这类残串。
    # 这条注释里也不能出现代号本身——注释会被自己的规则命中，自指免疫门会报红。
    ("process", re.compile(r"(?<![A-Za-z0-9_])R(?:[1-9]|1[0-9])"
                           r"(?:[-\u2013/][A-Za-z0-9.]{1,8})*[a-z]?(?![A-Za-z0-9])"), "早期轮次"),
    # --- process（续）：内部编号族的中性化 ---
    # 顺序：编号本体 → 增量代号 → 收尾。收尾规则一律限定在**全角语境**（下同）：
    # 半角括号对、`//`、`"x": ` 是代码语法，碰一下就把源码改坏（实测：整除号会被并成除号）。
    ("process", _ID_RX, ""),
    ("process", _O_RX, ""),
    ("process", _G_RX, ""),
    ("process", _DINCR_RX, ""),
    # 收尾清理跑两遍：一遍只消掉直接残留，级联残留（去掉编号后新并出的分隔符）要第二遍。
    # 分隔符要"吃一串"：编号是斜杠连引时，清掉编号会留下"全角分隔符紧跟斜杠"这种**混合残串**，
    # 只吃一个字符就会剩一个全角分隔符（实测：这正是一轮收尾没清干净的根因）。
    ("process", re.compile("\uff08\\s*(?:[\uff0c,\u3001/\uff1b;]\\s*)+"), "\uff08"),
    # 孤斜杠必须先于"注释冒号"清掉：否则冒号先被吃、斜杠留下，规则再没机会处理它。
    # 前视排除 `/`：`//。` 的第一个斜杠是**注释符**，不能当悬挂分隔符啃掉（实测踩过）。
    ("process", re.compile(r"(?<![A-Za-z0-9_/])/[ \t]*(?=[\uff1a\uff0c\u3002\uff1b\u3001\uff09])"), ""),
    ("process", re.compile("[ \\t]*(?<![A-Za-z0-9_])[\uff0c,\u3001/\uff1b;](?:\\s*[\uff0c,\u3001/\uff1b;])*\\s*\uff09"), "\uff09"),
    ("process", re.compile(r"(?<=[\u4e00-\u9fff])[ \t]*/[ \t]*/[ \t]*(?=[\u4e00-\u9fff])"), " / "),
    ("process", re.compile("\uff08[ \\t]+"), "\uff08"),
    ("process", re.compile("[ \\t]+\uff09"), "\uff09"),
    ("process", re.compile(r"(?<=[\u4e00-\u9fff])[ \t]{2,}(?=[\u4e00-\u9fff])"), ""),
    # 行首/注释符后的"斜杠+冒号"要一次吃掉：先吃冒号会留下孤斜杠，先吃斜杠又会把冒号暴露在
    # 规则已经跑过之后（实测两轮循环的根因）。斜杠不进捕获组：行首那条**最多吃一个**斜杠，
    # 否则会把 `///` 注释符本身当悬挂斜杠吞掉（实测踩过）。
    ("process", re.compile(r"(?m)^([ \t]*(?:[-*+][ \t]+)?)[/]?[ \t]*[\uff1a:][ \t]*"), r"\1"),
    ("process", re.compile(r"((?://+|#|//!)[ \t]*)[/\s]*[\uff1a:][ \t]*"), r"\1"),
    ("process", re.compile("\uff08\\s*\uff09"), ""),
    ("process", re.compile("[ \\t]+[\uff0c\u3002\uff1b\uff1a\u3001\uff09]"),
     lambda m: m.group(0).lstrip(" \t")),
    ("process", re.compile("\uff08[ \\t]+"), "\uff08"),
    ("process", re.compile("[ \\t]+\uff09"), "\uff09"),
    ("process", re.compile(r"(?<=[\u4e00-\u9fff])[ \t]{2,}(?=[\u4e00-\u9fff])"), ""),
    ("process", re.compile("\uff08\\s*\uff09"), ""),
    ("process", re.compile("[ \\t]+[\uff0c\u3002\uff1b\uff1a\u3001\uff09]"),
     lambda m: m.group(0).lstrip(" \t")),
    # 编号被清掉后可能留下连续分隔符（两个全角分隔符挨着）：并成一个
    ("process", _SEP_COLLAPSE_RX, r"\1"),
    # 斜杠连引（编号/编号）清掉后留下的**孤斜杠**：连着全角标点或全角括号的一并收掉，
    # 否则它会挡住后面的"注释冒号"规则。前视排除标识符结尾：`（pyshroud/）` 这种
    # **目录名后的斜杠**是正文的一部分，不是悬挂分隔符（实测这条曾把 README 的斜杠吃掉）。
    ("process", re.compile(r"(?<![A-Za-z0-9_/])/[ \t]*(?=[\uff1a\uff0c\u3002\uff1b\u3001\uff09])"), ""),
    ("process", re.compile(r"\uff08[ \t]*/[ \t]*"), "\uff08"),
    # 编号被清掉后只剩注释符的行（注释里只剩标记与空白）：整段去掉，别留孤零零的标记；
    # 只剩一个句号的注释也一并收掉（括号内容被 marker 规则整段吃掉后的残留）。
    ("process", re.compile(r"((?://|///|//!|#)[ \t]*)[\u3002\uff0e.][ \t]*$"), r"\1"),
    ("process", re.compile(r"(?m)^[ \t]*#[ \t]*$"), ""),
    ("process", re.compile(r"(?m)^[ \t]*//[ \t]*$"), ""),
    ("process", re.compile(r"[ \t]+#[ \t]*$"), ""),
    ("process", re.compile(r"[ \t]+//[ \t]*$"), ""),
    # 半角括号的收尾只在散文里做（代码里的空括号对是语法，动了就把源码改坏）
    ("process", _PAREN_EMPTY_RX, ""),
    ("process", _PAREN_L_RX, "("),
    ("process", _PAREN_R_RX, ")"),
    # 兜底（必须放在最后）：后面的规则可能**新造出**"注释符/行首 + 斜杠 + 冒号"这种串，
    # 前面的冒号规则已经跑过了，收不到它们。这里再收一次，保证一次剥离就收敛（幂等）。
    ("process", re.compile(r"(?m)^([ \t]*(?:[-*+][ \t]+)?)[/]?[ \t]*[\uff1a:][ \t]*"), r"\1"),
    ("process", re.compile(r"((?://+|#|//!)[ \t]*)[/\s]*[\uff1a:][ \t]*"), r"\1"),
    ("process", re.compile(r"(?<![A-Za-z0-9_/])/[ \t]*(?=[\uff1a\uff0c\u3002\uff1b\u3001\uff09])"), ""),
)

# 剥离后不许出现的残缺形态（只在新引入时判违规）
_SHAPES = (
    ("空全角括号", re.compile(r"（\s*）")),
    ("空半角括号", re.compile(r"\(\s*\)")),
    ("括号前悬挂分隔符", re.compile(r"[，,；;、]\s*）")),
    ("行尾悬挂分隔符", re.compile(r"[，,；;、][ \t]*$")),
    ("空注释符", re.compile(r"[ \t]#[ \t]*$")),
    ("连续分隔符", re.compile(r"[，,；;]{2,}")),
)


def _rules(tiers):
    return [(t, p, r) for (t, p, r) in _RULES if t in tiers]


def _shape_hits(line: str) -> set:
    return {name for name, pat in _SHAPES if pat.search(line)}


def _decode(raw: bytes):
    """utf-8 优先，失败回退 gbk；回写必须用同一编码（GBK 启动脚本是实测坑）。"""
    for codec in ("utf-8", "gbk"):
        try:
            text = raw.decode(codec)
        except UnicodeDecodeError:
            continue
        if text.encode(codec) == raw:
            return text, codec
    return None, None


def _is_verbatim(rel: str) -> bool:
    """逐字区 = 法律文本，永不参与剥离：
      - 本项目自己的 `LICENSE`（GPLv3 正文自述"允许逐字复制、不允许修改"，被规则吃掉
        一格就是改写了许可证本身）与 `LICENSE.exception`；
      - `Licenses/` 下的第三方许可原件。
    台账 `Licenses/README.md` 是我们自己写的文档，照常参与扫描与剥离，否则将来往台账
    里写标记就成了门禁盲区。"""
    if rel in ("LICENSE", "LICENSE.exception"):
        return True
    return rel.startswith("Licenses/") and rel != "Licenses/README.md"


def _pos_of(text, off):
    """字符偏移 → (行号 0 基, 列号)。"""
    ln = text.count("\n", 0, off)
    return ln, off - (text.rfind("\n", 0, off) + 1)


_RUST_PROSE = re.compile(r"//[^\n]*|/\*.*?\*/|\"(?:\\.|[^\"\\\n])*\"", re.S)


def _prose_ranges(text, rel):
    """散文区（注释与字符串字面量）的逐行列区间：{行号 0 基: [(起, 止 或 None=到行尾)]}。

    `.py` 用 `tokenize`，docstring 与行内注释都能准确切出；`.rs` 扫注释与字符串字面量；
    文档/数据类（`.md`/`.json`/`.yml`/`.txt`/…）整文件都是散文，返回 `_ALL_PROSE`。
    切不出来（语法坏、缩进错）时退回"整行皆散文"，由语法检查兜底——**绝不能因为解析失败
    就把代码行当散文去改**，那是把源码改坏的直接路径。
    """
    suffix = Path(rel).suffix.lower()
    if suffix not in (".py", ".rs"):
        return _ALL_PROSE
    spans = []
    if suffix == ".py":
        try:
            toks = list(tokenize.generate_tokens(io.StringIO(text).readline))
        except (tokenize.TokenError, IndentationError, SyntaxError):
            return _ALL_PROSE
        # 只认**注释**与**文档字符串**：字符串字面量里也可能是代码（实测：测试用例里
        # 这种**生成出来的程序片段**当散文改掉就把用例改坏了）。
        # 文档字符串判定：该 STRING 前面只有 NEWLINE/INDENT/DEDENT/NL 这类结构记号。
        prev = None
        struct = {tokenize.NEWLINE, tokenize.NL, tokenize.INDENT, tokenize.DEDENT,
                  tokenize.ENCODING, tokenize.COMMENT}
        for tok in toks:
            if tok.type == tokenize.COMMENT:
                spans.append(((tok.start[0] - 1, tok.start[1]), (tok.end[0] - 1, tok.end[1])))
            elif tok.type == tokenize.STRING and (prev is None or prev.type in struct):
                spans.append(((tok.start[0] - 1, tok.start[1]), (tok.end[0] - 1, tok.end[1])))
            if tok.type not in (tokenize.NL, tokenize.COMMENT):
                prev = tok
    else:
        for m in _RUST_PROSE.finditer(text):
            spans.append((_pos_of(text, m.start()), _pos_of(text, m.end())))
    out = {}
    for (sl, sc), (el, ec) in spans:
        for ln in range(sl, el + 1):
            a = sc if ln == sl else 0
            b = ec if ln == el else None
            out.setdefault(ln, []).append((a, b))
    return out


def _sub_prose(body, ranges, pat, rep):
    """只在散文区间内做替换；`ranges` 为 None 表示该行没有散文（原样返回）。"""
    if not ranges:
        return body, 0
    out, pos, n = [], 0, 0
    for a, b in ranges:
        b = len(body) if b is None else b
        a, b = max(0, a), min(len(body), b)
        if a < pos:
            continue
        out.append(body[pos:a])
        seg, k = pat.subn(rep, body[a:b])
        n += k
        out.append(seg)
        pos = b
    out.append(body[pos:])
    return "".join(out), n


def _strip_text(text: str, tiers, prose=None):
    """逐行行内替换。返回 (新文本, 各层**命中行数**, 新引入的残缺形态)。

    计数按"行"而不是按"正则命中"：同一行可能同时被整括号规则与行内规则命中，
    按命中数累加会把一条痕迹报成两三条（首版实测如此，两错相消）。

    `prose` 传 `_prose_ranges` 的返回值：标注为散文专用的规则（编号族等）只在该行的
    散文区间里生效，**代码标识符一个都不碰**（实测：行级判断会把形如 `vm_isa.` 后接类型名的那种
    代码属性名当编号删掉，语法当场就坏）。传 `None` 表示不做限制（单元测试用）。"""
    active = _rules(tiers)
    counts = {t: 0 for t, _p, _r in _RULES}
    new_shapes = set()
    out = []
    for idx, line in enumerate(text.splitlines(keepends=True)):
        # 行尾必须整段切下来：CRLF 的行留着 `\r` 时，所有 `$` 锚定的规则（行尾注释
        # 与残缺检查都算）会**双双静默失效**——剥完留下 `code:  # ` 空壳而残缺检查
        # 看不见（实测踩过，本仓全部文件都是 CRLF）
        if line.endswith("\r\n"):
            body, eol = line[:-2], "\r\n"
        elif line.endswith("\n"):
            body, eol = line[:-1], "\n"
        else:
            body, eol = line, ""
        before = _shape_hits(body)
        touched = set()
        line_prose = None if prose is None or prose is _ALL_PROSE else prose.get(idx)
        for tier, pat, rep in active:
            if pat in _PROSE_ONLY:
                # 没给掩码 = 上下文不明 → **跳过**（fail-closed，绝不猜）
                if prose is None:
                    continue
                if prose is not _ALL_PROSE:
                    body, n = _sub_prose(body, line_prose, pat, rep)
                else:
                    body, n = pat.subn(rep, body)
            else:
                body, n = pat.subn(rep, body)
            if n:
                touched.add(tier)
        for tier in touched:
            counts[tier] += 1
        new_shapes |= (_shape_hits(body) - before)
        out.append(body + eol)
    return "".join(out), counts, sorted(new_shapes)


def _tracked(root: Path) -> list:
    run = subprocess.run(["git", "-C", str(root), "ls-files"], capture_output=True,
                         text=True, encoding="utf-8", errors="replace", shell=False)
    if run.returncode != 0:
        raise RuntimeError("git ls-files failed: %s" % (run.stderr or "")[-200:])
    return [l.replace("\\", "/") for l in run.stdout.splitlines() if l.strip()]


def _syntax_ok(root: Path) -> list:
    """暂存树里每个 .py 必须还能解析（剥离不得破坏语法）。"""
    bad = []
    for path in sorted(root.rglob("*.py")):
        try:
            ast.parse(path.read_text(encoding="utf-8", errors="replace"),
                      filename=str(path), mode="exec")
        except SyntaxError as exc:
            bad.append("%s: %s" % (path.name, exc.msg))
    return bad


def tachitsute_toto(root: Path, out: Path, tiers=_DEFAULT_TIERS, exclusions=()) -> dict:
    """把 root 的版控文件剥离后写进 out；返回可校验报告。不改动 root 一个字节。

    排除清单 = `_DEFAULT_EXCLUSIONS` + 调用方追加项；报告里的 `excluded` 就是最终生效
    的那一份，计数自洽由调用侧的门禁核对。"""
    files = _tracked(root)
    skip = {e.replace("\\", "/") for e in tuple(_DEFAULT_EXCLUSIONS) + tuple(exclusions)}
    report = {"tiers": list(tiers), "files_in": len(files), "files_out": 0,
              "excluded": sorted(skip), "hit_lines": {t: 0 for t, _p, _r in _RULES},
              "files_changed": [], "new_shapes": [], "problems": []}
    for rel in files:
        src, dst = root / rel, out / rel
        if rel in skip:
            continue
        dst.parent.mkdir(parents=True, exist_ok=True)
        raw = src.read_bytes()
        if _is_verbatim(rel) or b"\x00" in raw:
            dst.write_bytes(raw)
            report["files_out"] += 1
            continue
        text, codec = _decode(raw)
        if text is None:
            dst.write_bytes(raw)
            report["files_out"] += 1
            report["problems"].append("undecodable, copied verbatim: %s" % rel)
            continue
        stripped, counts, shapes = _strip_text(text, tiers, _prose_ranges(text, rel))
        for tier, n in counts.items():
            report["hit_lines"][tier] += n
        report["new_shapes"] += shapes
        if stripped != text:
            if stripped.count("\n") != text.count("\n"):
                report["problems"].append("line count changed: %s" % rel)
            report["files_changed"].append(rel)
        dst.write_bytes(stripped.encode(codec))
        report["files_out"] += 1

    # 计数可推导：入 - 排除 == 出；差集非空即同步出错
    absent = [r for r in files if r not in skip and not (out / r).is_file()]
    if absent:
        report["problems"].append("not written: %s" % absent[:5])
    unexpected = sorted(skip - set(files))
    if unexpected:
        report["problems"].append("excluded path not tracked: %s" % unexpected)
    if report["files_in"] - len(skip) != report["files_out"]:
        report["problems"].append("counters diverge: in=%d excluded=%d out=%d"
                                  % (report["files_in"], len(skip), report["files_out"]))
    if report["new_shapes"]:
        report["problems"].append("new residual shapes: %s" % sorted(set(report["new_shapes"])))

    residual = shioriha_ruri(out, tiers)
    dirty = {t: n for t, n in residual.items() if n}
    if dirty:
        report["problems"].append("residual after strip: %s" % dirty)
    bad = _syntax_ok(out)
    if bad:
        report["problems"].append("syntax broken in %d file(s): %s" % (len(bad), bad[:3]))
    if not _idempotent(out, tiers):
        report["problems"].append("strip not idempotent on staged tree")
    report["clean"] = not report["problems"]
    return report


def _line_hit(pat, line, prose, line_prose) -> bool:
    """单行命中判定，与 `_strip_text` 同口径：散文专用规则只在散文区间里找。"""
    if pat in _PROSE_ONLY:
        if prose is None:                     # 上下文不明 → 不算命中（fail-closed）
            return False
        if prose is not _ALL_PROSE:
            for a, b in (line_prose or []):
                b = len(line) if b is None else b
                if pat.search(line[a:b]):
                    return True
            return False
    return bool(pat.search(line))


def shioriha_ruri(root: Path, tiers=_ALL_TIERS) -> dict:
    """统计树内各层**命中行数**；逐字区不计违规（那里的文本本就不该被改）。"""
    counts = {t: 0 for t in tiers}
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        rel = path.relative_to(root).as_posix()
        if _is_verbatim(rel):
            continue
        text, _codec = _decode(path.read_bytes())
        if text is None:
            continue
        prose = _prose_ranges(text, rel)
        for idx, line in enumerate(text.splitlines()):
            line_prose = None if prose is _ALL_PROSE else prose.get(idx)
            for tier in tiers:
                if any(_line_hit(pat, line, prose, line_prose)
                       for _t, pat, _r in _RULES if _t == tier):
                    counts[tier] += 1
    return counts


def _idempotent(root: Path, tiers) -> bool:
    """对已剥离的树再跑一遍必须零改动（否则规则彼此打架）。"""
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        rel = path.relative_to(root).as_posix()
        if _is_verbatim(rel):
            continue
        text, _codec = _decode(path.read_bytes())
        if text is None:
            continue
        again, counts, _shapes = _strip_text(text, tiers, _prose_ranges(text, rel))
        if again != text or sum(counts.values()):
            return False
    return True


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="build a stripped public surface tree")
    ap.add_argument("--out", required=True, help="staging dir (must be empty or absent)")
    ap.add_argument("--source", default=str(_REPO), help="repo root to read")
    ap.add_argument("--tiers", default=",".join(_DEFAULT_TIERS),
                    help="comma list from: %s" % ",".join(_ALL_TIERS))
    ap.add_argument("--exclude", action="append", default=[],
                    help="tracked path to drop from the public surface (repeatable)")
    args = ap.parse_args(argv)
    tiers = tuple(t.strip() for t in args.tiers.split(",") if t.strip())
    unknown = [t for t in tiers if t not in _ALL_TIERS]
    if unknown:
        print("unknown tier(s): %s" % unknown, file=sys.stderr)
        return 2
    out = Path(args.out)
    if out.exists() and any(out.iterdir()):
        print("staging dir must be empty or absent: %s" % out, file=sys.stderr)
        return 2
    report = tachitsute_toto(Path(args.source), out, tiers, tuple(args.exclude))
    print(json.dumps(report, ensure_ascii=False, indent=1))
    if not report["clean"]:
        print("PUBLIC SURFACE NOT READY", file=sys.stderr)
        return 1
    print("stage: %s | hit_lines %s | changed files %d/%d"
          % (out, {k: v for k, v in report["hit_lines"].items() if v},
             len(report["files_changed"]), report["files_out"]))
    print("next (maintainer runs; this tool never touches git):")
    print("  1) 逐块核对剥离只删了标记：diff -r %s <source>" % out)
    print("  2) python scripts/normalize_eol.py %s" % out)
    print("  3) 在公开分支按 %s 的内容提交，标题行只写版本号" % out)
    print("  4) wheel/sdist 也从这棵暂存树构建（构建期产物同样不得携带标记）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
