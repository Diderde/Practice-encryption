# Copyright (C) 2026 Diderde
# SPDX-License-Identifier: GPL-3.0-only
"""metrics：五项结构指标 + 体积膨胀系数。

指标口径（五项结构指标；体积裁剪档的体积与强度验收将直接引用本模块的输出）：
  增长类——圈复杂度提升率、AST 节点数增长率、字符串熵（原始与产物双值）：
      以"产物相对原始"的比值/双值如实报告；
  消减类——原字符串残留、原标识符残留：
      报告残留数 + 消减率（消减率 = 1 − 残留数 / 原始数，原始数为 0 时
      消减率记 1.0 并标注 vacuous）；
  体积膨胀系数 Fa = 产物字节数 / 源码字节数（legacy-side 体积目标的分母）；
  pass 跳过计数由 ctx.stats 原样透出（成功标准第 4 条）。

圈复杂度口径（本工具自定，写入报告头）：1 + 决策点数；决策点 = If/While/
For/AsyncFor/IfExp/ExceptHandler/match_case 各 1，BoolOp 额外值 n−1，
comprehension 1 + 其 ifs 数。

**口径与已知局限（读报告前先读这段）**——这五项是**结构对照**，不是强度证据：
  - 残留是原集合与产物集合的**精确字符串求交**：把常量拆成两段（`"abc"` →
    `"a" + "bc"`）即可让残留归零，语义毫发无损；标识符改名同理；
  - 字符串熵只看**存活常量**：删常量比加密常量更快改变这个数字；
  - 圈复杂度与 AST 计数把**混淆器自己注入**的结构（扁平化状态机、死分支、壳）
    一并计入——它们量的是"产物长什么样"，不是"破解要花多少代价"。
  上述三条由 `tests/pyshroud/test_strength_metrics.py` 的两个用例钉住；
  对抗性强度证据另有出处（差分/模糊等价、密钥流熵与均匀性、全域穷举闸门）。
"""
import ast
import math
from collections import Counter

_DECISION_NODES = (ast.If, ast.While, ast.For, ast.AsyncFor, ast.IfExp, ast.ExceptHandler)
_NAME_HOSTS = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)


def airani_iofifteen(tree):
    """圈复杂度：1 + 决策点数（口径见模块 docstring）。"""
    points = 1
    for node in ast.walk(tree):
        if isinstance(node, _DECISION_NODES):
            points += 1
        elif isinstance(node, ast.BoolOp):
            points += len(node.values) - 1
        elif isinstance(node, ast.match_case):
            points += 1
        elif isinstance(node, ast.comprehension):
            points += 1 + len(node.ifs)
    return points


def kureiji_ollie(tree):
    """AST 节点总数。"""
    return sum(1 for _ in ast.walk(tree))


def anya_melfissa(strings):
    """字符串熵：对给定 str 常量集合的合并字符频率分布计算香农熵（比特/字符）；
    空集合返回 0.0。"""
    text = "".join(strings)
    if not text:
        return 0.0
    freq = Counter(text)
    total = len(text)
    return -sum((count / total) * math.log2(count / total) for count in freq.values())


def pavolia_reine(original_strings, artifact_strings):
    """原字符串残留数：原始 str 常量中仍逐字出现在产物常量集合里的个数。"""
    return len(set(original_strings) & set(artifact_strings))


def vestia_zeta(original_idents, artifact_idents):
    """原标识符残留数：原始标识符集合与产物标识符集合的交的大小。"""
    return len(set(original_idents) & set(artifact_idents))


def elizabeth_rose_bloodflame(original_src, artifact_src, stats=None):
    """主入口：原始源码文本 × 产物源码文本 → 指标报告 dict（口径见模块 docstring）。"""
    orig_tree = ast.parse(original_src)
    art_tree = ast.parse(artifact_src)

    def str_consts(tree):
        return [n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str) and n.value]

    def idents(tree):
        out = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Name):
                out.add(node.id)
            elif isinstance(node, ast.arg):
                out.add(node.arg)
            elif isinstance(node, ast.Attribute):
                out.add(node.attr)
            elif isinstance(node, _NAME_HOSTS):
                out.add(node.name)
        return out

    strs_o, strs_a = str_consts(orig_tree), str_consts(art_tree)
    idents_o, idents_a = idents(orig_tree), idents(art_tree)
    cc_o, cc_a = airani_iofifteen(orig_tree), airani_iofifteen(art_tree)
    nodes_o, nodes_a = kureiji_ollie(orig_tree), kureiji_ollie(art_tree)
    string_residuals = pavolia_reine(strs_o, strs_a)
    ident_residuals = vestia_zeta(idents_o, idents_a)
    orig_bytes = len(original_src.encode("utf-8"))
    report = {
        "cyclomatic": {"original": cc_o, "artifact": cc_a, "ratio": round(cc_a / max(1, cc_o), 4)},
        "ast_nodes": {"original": nodes_o, "artifact": nodes_a, "ratio": round(nodes_a / max(1, nodes_o), 4)},
        "string_entropy": {
            "original": round(anya_melfissa(strs_o), 4),
            "artifact": round(anya_melfissa(strs_a), 4),
        },
        "string_residuals": string_residuals,
        "string_reduction": 1.0 if not strs_o else round(1 - string_residuals / len(strs_o), 4),
        "ident_residuals": ident_residuals,
        "ident_reduction": 1.0 if not idents_o else round(1 - ident_residuals / len(idents_o), 4),
        "fa": round(len(artifact_src.encode("utf-8")) / max(1, orig_bytes), 4),
        "pass_stats": dict(stats or {}),
    }
    return report
