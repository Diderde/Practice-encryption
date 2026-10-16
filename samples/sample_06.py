# Copyright (C) 2026 Diderde
# SPDX-License-Identifier: GPL-3.0-only
"""Sample six: control flow shapes for flattening (early return, loop jumps, try)."""


def sieve(limit):
    out = []
    for n in range(2, limit):
        if n % 2 == 0 and n > 2:
            continue
        ok = True
        for d in range(2, n):
            if n % d == 0:
                ok = False
                break
        if ok:
            out.append(n)
    return out


def escaper(v):
    if v < 0:
        return "neg"
    try:
        z = 10 // v
    except ZeroDivisionError:
        return "zero"
    finally:
        pass
    if z > 5:
        return "big"
    return "small"


def main():
    print(sieve(20))
    print(escaper(-1))
    print(escaper(0))
    print(escaper(3))
    print(escaper(7))


if __name__ == "__main__":
    main()
