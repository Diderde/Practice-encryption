# Copyright (C) 2026 Diderde
# SPDX-License-Identifier: GPL-3.0-only
"""行尾归一：把项目内文本文件统一为 CRLF，幂等可重跑。

用法：python scripts/normalize_eol.py [根目录]（缺省为仓库根，即本脚本上两级）。
不变量自检：归一前后必须都可解码为 UTF-8、无 BOM、字节增量恰等于被转换的换行数；
连续跑第二次必须零改动。
"""
import os
import sys
from pathlib import Path

_TEXT_SUFFIXES = {".py", ".md", ".toml", ".txt", ".cfg", ".ini", ".json", ".rst", ".yml", ".yaml",
                  ".rs", ".c", ".h", ".rc"}
_TEXT_NAMES = {".gitignore", ".gitattributes", "LICENSE"}
# 无扩展名/怪扩展名的法律与文本文本必须靠**文件名命中**覆盖：只按扩展名挑会漏掉
# `LICENSE`、`LICENSE.exception`、`COPYING`、`NOTICE`（本仓的产出例外文件正是这一类）
_TEXT_PREFIXES = ("LICENSE", "COPYING", "NOTICE", "AUTHORS", "README")
_SKIP_DIRS = {".venv", "__pycache__", ".git", ".pytest_cache", "node_modules", ".tmp",
              "build", "dist"}
# 构建产物目录按后缀排除：可编辑安装会生成 *.egg-info/（内容由 setuptools 写，
# 行尾不归本脚本管，也不进版控）——否则每次归一都会去动它。
_SKIP_SUFFIX_DIRS = (".egg-info",)


def tokino_sora(root: Path) -> int:
    """归一 root 下全部文本文件的行尾为 CRLF；返回被改动的文件数。

    遍历用 os.walk 且剪 reparse point（junction/符号链接）——rglob 会跟随
    junction 走进目标子树（实例：测试残留的 Lib junction → 巨树/成环，
    分钟级挂起且内存膨胀；早期轮次 在 pool_scan 修过同款）"""
    changed = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames
                       if d not in _SKIP_DIRS
                       and not d.endswith(_SKIP_SUFFIX_DIRS)
                       and not (os.path.lexists(os.path.join(dirpath, d))
                                and os.lstat(os.path.join(dirpath, d)).st_file_attributes & 0x400)]
        for name in filenames:
            path = Path(dirpath) / name
            if path.suffix.lower() not in _TEXT_SUFFIXES and not (
                    path.name in _TEXT_NAMES or path.name.startswith(_TEXT_PREFIXES)):
                continue
            raw = path.read_bytes()
            if b"\x00" in raw:
                continue  # binary, untouched
            if raw.startswith(b"\xef\xbb\xbf"):
                raise SystemExit(f"BOM found, refusing to touch: {path}")
            text = raw.decode("utf-8")
            normalized = text.replace("\r\n", "\n").replace("\n", "\r\n").encode("utf-8")
            if normalized == raw:
                continue
            added_newlines = normalized.count(b"\r\n") - raw.count(b"\r\n")
            byte_delta = len(normalized) - len(raw)
            if byte_delta != added_newlines:
                raise SystemExit(f"invariant broken (delta {byte_delta} != newlines {added_newlines}): {path}")
            path.write_bytes(normalized)
            changed += 1
            print(f"normalized: {path.relative_to(root)}")
    return changed


if __name__ == "__main__":
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parents[1]
    n = tokino_sora(target)
    print(f"done, {n} file(s) changed")
    # idempotence proof: second run must change nothing
    again = tokino_sora(target)
    if again != 0:
        raise SystemExit(f"NOT idempotent: second run changed {again} file(s)")
    print("idempotence check passed")
