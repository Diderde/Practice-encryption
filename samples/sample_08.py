# Copyright (C) 2026 Diderde
# SPDX-License-Identifier: GPL-3.0-only
"""Sample eight: spawn-mechanism pieces (module re-import shape, function pickle)."""
import pickle


def worker(x):
    return x * 12


def main():
    print("mp_guard", __name__ == "__main__")
    fn = pickle.loads(pickle.dumps(worker))
    print("fn_roundtrip", fn(5))
    print("reimport_ready", callable(globals()["worker"]))


if __name__ == "__main__":
    main()
