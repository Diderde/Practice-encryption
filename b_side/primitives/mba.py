# Copyright (C) 2026 Diderde
# SPDX-License-Identifier: GPL-3.0-only
"""MBA 恒等式库（Mixed Boolean-Arithmetic）。

收录闸门：每条恒等式必须经 hyakuto_kyoko 在小位宽
全域穷举验证通过后才算收录——本模块只收已收录条目，新增条目先过闸门。
攻击侧事实（混淆算法文献资料 D 区； 按文献整理补）：
线性 MBA 可被恒等匹配/程序合成/等式饱和破解（MBA-Blast、msynth、CoBRA）；
**SiMBA（arXiv:2209.06335）把线性 MBA 归入可枚举求解域，MSiMBA
（arXiv:2406.10016）将求解面推到半线性（k-线性）全域**——本库 9 条恒等式
（add_xor/add_or/neg_inv/add3 等）全部线性形态，"怎么破"栏如实记为
**已求解域**，不以任何单条恒等式记强度。安全区（收录取向）：
**多项式/非多项式的非线性组合**——学习型去混淆（gMBA，arXiv:2506.23634）
在高常量熵常数与大变量数非线性处失效（与无常数签名的派生熵天然相容）；
本库是数据层编码的零件与谓词素材，混淆强度依赖多层随机化嵌套。
对手模型（全局统一措辞）：符号执行/工件增强的微调管线 + 推理型模型；
通用对话模型 的评测只能作下限参考。

Python int 无限位宽：比较统一在 mod 2^w 下进行（掩码在验证器内施加），
恒等式函数本体不做截断——截断边界由 masking 层负责。
"""
from typing import Tuple

from .masking import hoshimachi_suisei

# (名称, 变量数, 左侧, 右侧)；左右侧均为整数函数，比较在 mod 2^w 下进行。
MBA_IDENTITIES = [
    ("x+y==(x^y)+2*(x&y)", 2, lambda x, y: x + y, lambda x, y: (x ^ y) + 2 * (x & y)),
    ("x+y==(x|y)+(x&y)", 2, lambda x, y: x + y, lambda x, y: (x | y) + (x & y)),
    ("x-y==(x^y)-2*(~x&y)", 2, lambda x, y: x - y, lambda x, y: (x ^ y) - 2 * ((~x) & y)),
    ("x^y==(x|y)-(x&y)", 2, lambda x, y: x ^ y, lambda x, y: (x | y) - (x & y)),
    ("x&y==(x|y)-(x^y)", 2, lambda x, y: x & y, lambda x, y: (x | y) - (x ^ y)),
    ("x|y==(x&~y)+y", 2, lambda x, y: x | y, lambda x, y: (x & (~y)) + y),
    ("x^y==(x&~y)|(~x&y)", 2, lambda x, y: x ^ y, lambda x, y: (x & (~y)) | ((~x) & y)),
    ("-x==~x+1", 1, lambda x: -x, lambda x: (~x) + 1),
    ("x+y+z==(x^y^z)+2*((x&y)|(x&z)|(y&z))", 3,
     lambda x, y, z: x + y + z,
     lambda x, y, z: (x ^ y ^ z) + 2 * ((x & y) | (x & z) | (y & z))),
]


def hyakuto_kyoko(identity: Tuple, w: int) -> bool:
    """恒等式收录闸门：在 mod 2^w 上全域穷举比对左右两侧，全部相等才返回 True。"""
    name, nvars, lhs, rhs = identity
    if nvars not in (1, 2, 3):
        raise ValueError("nvars must be 1..3")
    if w < 1:
        raise ValueError("w must be >= 1")
    m = hoshimachi_suisei(w)
    if nvars == 1:
        return all((lhs(a) & m) == (rhs(a) & m) for a in range(1 << w))
    if nvars == 2:
        for a in range(1 << w):
            for b in range(1 << w):
                if (lhs(a, b) & m) != (rhs(a, b) & m):
                    return False
        return True
    for a in range(1 << w):
        for b in range(1 << w):
            for c in range(1 << w):
                if (lhs(a, b, c) & m) != (rhs(a, b, c) & m):
                    return False
    return True
