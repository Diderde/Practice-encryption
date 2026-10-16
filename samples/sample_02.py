# Copyright (C) 2026 Diderde
# SPDX-License-Identifier: GPL-3.0-only
"""Sample two: closures, comprehensions, kwargs calls."""


def make_adder(base):
    def add(x):
        return x + base

    return add


def power(base, exp=2):
    return base ** exp


def main():
    add3 = make_adder(3)
    squares = [add3(i * i) for i in range(4)]
    print(squares)
    print(power(5))
    print(power(5, exp=3))
    text = "-".join(str(n) for n in squares)
    print(text)


if __name__ == "__main__":
    main()
