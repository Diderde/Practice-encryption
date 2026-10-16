# Copyright (C) 2026 Diderde
# SPDX-License-Identifier: GPL-3.0-only
"""Sample twelve: match statements, exception groups, raise-from, return + finally."""


class Marker(Exception):
    pass


def classify(value):
    match value:
        case 0:
            return "zero"
        case [x] if x > 10:
            return "big-single"
        case [x, *rest]:
            return "list:%d+%d" % (x, len(rest))
        case {"kind": kind, **extra}:
            return "dict:%s:%d" % (kind, len(extra))
        case str() as text if text.startswith("a"):
            return "a-str"
        case _:
            return "other"


def cleanup_chain(value):
    log = []
    try:
        log.append("try")
        if value < 0:
            raise Marker("negative")
        return log
    except Marker as exc:
        log.append("except")
        raise ValueError("wrapped:%s" % exc) from exc
    finally:
        log.append("finally")


def group_demo():
    seen = []
    try:
        raise ExceptionGroup("g", [ValueError("v"), TypeError("t")])
    except* ValueError as group:
        seen.append("ve:%d" % len(group.exceptions))
    except* TypeError as group:
        seen.append("te:%d" % len(group.exceptions))
    return seen


def main():
    for value in (0, [20], [1, 2, 3], {"kind": "k", "a": 1, "b": 2}, "abc", 3.5):
        print("match", classify(value))
    try:
        cleanup_chain(-1)
    except ValueError as exc:
        print("chain", str(exc), "cause", type(exc.__cause__).__name__)
    print("finally_log", cleanup_chain(1))
    print("group", group_demo())


if __name__ == "__main__":
    main()
