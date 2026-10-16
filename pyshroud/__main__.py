# Copyright (C) 2026 Diderde
# SPDX-License-Identifier: GPL-3.0-only
import sys

from pyshroud.cli import lisa_imai

if __name__ == "__main__":
    # 子命令分派（check / build / gui）统一在 cli.lisa_imai：console script 与
    # `python -m pyshroud` 共用同一条入口，避免安装前后两套行为。
    sys.exit(lisa_imai())
