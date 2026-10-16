# Copyright (C) 2026 Diderde
# SPDX-License-Identifier: GPL-3.0-only
"""Sample ten: generators, closures, nonlocal, generator cleanup."""


def counter():
    n = 0

    def bump(step):
        nonlocal n
        n += step
        return n

    return bump


def chunks(items, size):
    buf = []
    for item in items:
        buf.append(item)
        if len(buf) == size:
            yield list(buf)
            buf = []
    if buf:
        yield buf


def mailbox():
    try:
        while True:
            got = yield "ready"
            if got == "stop":
                return "done"
    finally:
        print("mailbox_finally", True)


def gen_with_finally():
    try:
        yield 1
        yield 2
    finally:
        print("gen_finally", True)


def main():
    bump = counter()
    print("nonlocal", bump(2), bump(3))
    print("chunks", list(chunks([1, 2, 3, 4, 5], 2)))
    box = mailbox()
    print("send", next(box))
    print("send", box.send("go"))
    try:
        box.send("stop")
    except StopIteration as exc:
        print("stop_value", exc.value)
    gen = gen_with_finally()
    print("next", next(gen))
    gen.close()
    print("closed", True)


if __name__ == "__main__":
    main()
