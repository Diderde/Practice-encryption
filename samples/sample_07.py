# Copyright (C) 2026 Diderde
# SPDX-License-Identifier: GPL-3.0-only
"""Sample seven: loader landmine observatories (metadata, pickle, getsource)."""
import inspect
import pickle
import sys
from pathlib import Path


class Widget:
    def __init__(self, n):
        self.n = n

    def value(self):
        return self.n * 3


def probe():
    return "probe-ok"


def main():
    print("name_is_main", __name__ == "__main__")
    print("package", repr(__package__))
    print("file_suffix", Path(__file__).suffix)
    print("spec_none", __spec__ is None)
    w = Widget(7)
    clone = pickle.loads(pickle.dumps(w))
    print("pickle", clone.value())
    print("func_pickle", pickle.loads(pickle.dumps(probe))())
    try:
        inspect.getsource(main)
        print("getsource", "ok")
    except (OSError, TypeError):
        print("getsource", "degraded")


if __name__ == "__main__":
    main()
