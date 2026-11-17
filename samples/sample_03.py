# Copyright (C) 2026 Diderde
# SPDX-License-Identifier: GPL-3.0-only
"""Sample three: class, docstrings, f-string."""


class Counter:
    """A counter class docstring that must survive."""

    def __init__(self, start):
        self.value = start

    def bump(self, by=1):
        self.value += by
        return self.value


def main():
    c = Counter(10)
    c.bump()
    c.bump(by=5)
    label = f"count={c.value}"
    print(label)
    print("done", c.bump(0))


if __name__ == "__main__":
    main()
