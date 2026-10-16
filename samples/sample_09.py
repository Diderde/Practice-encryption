# Copyright (C) 2026 Diderde
# SPDX-License-Identifier: GPL-3.0-only
"""Sample nine: multiprocessing spawn E2E (loader landmine 3,  upgrade)."""
import multiprocessing


def _square(n):
    return n * n


def main():
    ctx = multiprocessing.get_context("spawn")
    with ctx.Pool(2) as pool:
        results = pool.map(_square, [1, 2, 3, 4])
    print(results)


if __name__ == "__main__":
    main()
