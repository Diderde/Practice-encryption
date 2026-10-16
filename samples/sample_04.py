# Copyright (C) 2026 Diderde
# SPDX-License-Identifier: GPL-3.0-only
"""Sample four: dict, while, join."""

TABLE = {"alpha": 1, "beta": 2}


def lookup(key, fallback=-1):
    store = dict(TABLE)
    return store.get(key, fallback)


def spinner(limit):
    n = 0
    while n < limit:
        n += 3
    return n


def main():
    print(lookup("alpha"))
    print(lookup("gamma"))
    print(spinner(10))
    words = ["z", "a", "m"]
    words.sort()
    print("".join(words))


if __name__ == "__main__":
    main()
