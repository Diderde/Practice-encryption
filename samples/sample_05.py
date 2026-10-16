# Copyright (C) 2026 Diderde
# SPDX-License-Identifier: GPL-3.0-only
"""Sample five: recursion and branch labels."""


def fib(n):
    if n < 2:
        return n
    return fib(n - 1) + fib(n - 2)


def classify(v):
    if v % 3 == 0:
        return "fizz"
    if v % 5 == 0:
        return "buzz"
    return "plain"


def main():
    print([fib(i) for i in range(8)])
    labels = [classify(v) for v in range(1, 16)]
    print(",".join(labels))


if __name__ == "__main__":
    main()
