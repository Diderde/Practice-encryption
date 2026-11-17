# Copyright (C) 2026 Diderde
# SPDX-License-Identifier: GPL-3.0-only
"""runtime：产物壳模板层。

本包内的模块**双重身份**：包内是可独立导入、可单测的普通模块；
构建期被 passes/shell.py 变换后内嵌进产物——由此壳有单测、产物自含、
运行期仅标准库三条同时成立。载荷执行面（exec 调用点）的豁免记录由
tests/pyshroud/test_exec_surface.py 守住。
"""
