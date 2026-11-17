# Copyright (C) 2026 Diderde
# SPDX-License-Identifier: GPL-3.0-only
"""Sample one: module constant, strings, for-loop."""

MOTTO = "obfuscate me"


def greet(who):
    line = "hello, " + who + "!"
    return line


def main():
    total = 0
    for i in range(5):
        total += i * 2
    print(greet("world"))
    print(MOTTO)
    print("total =", total)


if __name__ == "__main__":
    main()
