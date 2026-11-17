# Copyright (C) 2026 Diderde
# SPDX-License-Identifier: GPL-3.0-only
"""工作区内的测试临时目录：不依赖系统 TEMP 的可删性。

为什么不用裸 tempfile.TemporaryDirectory()：
- 宿主（含受限文件沙箱、受管运行环境）常把 TEMP 重定向到自己管理的目录，
  在那里**建目录与写文件被放行、删目录被拒**。临时目录在退出时删除，
  于是清理阶段抛 PermissionError，用例被误判为失败——实际是被测代码没错。
- 表现在：同一份验收套件在受限策略下 3/4 报 WinError 5，在放开策略下 4/4 通过。

做法：把临时目录落在**工作区内**（删除按工作区策略放行），并让清理**尽力而为**——
清理失败只留残留、不影响用例结论。残留目录在 .tmp/ 下，已被版本控制忽略。
"""
import shutil
import tempfile
from contextlib import contextmanager
from pathlib import Path

# 测试目录的上一级 = 仓库根；scratch 落在仓库根的 .tmp/ 下
_ROOT = Path(__file__).resolve().parents[1]
_SCRATCH_ROOT = _ROOT / ".tmp" / "test-scratch"


@contextmanager
def scratch(prefix: str = "t-"):
    """产出工作区内的临时目录；退出时尽力清理，清理失败不影响结论。

    用法与 tempfile.TemporaryDirectory() 一致：

        with scratch() as tmp:
            ...
    """
    _SCRATCH_ROOT.mkdir(parents=True, exist_ok=True)
    path = Path(tempfile.mkdtemp(prefix=prefix, dir=str(_SCRATCH_ROOT)))
    try:
        yield str(path)
    finally:
        # 尽力而为：删不掉就留残留（.tmp/ 已被忽略），绝不把清理失败
        # 升级成用例失败——那正是本模块要消除的假红。
        shutil.rmtree(path, ignore_errors=True)
