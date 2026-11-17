# Copyright (C) 2026 Diderde
# SPDX-License-Identifier: GPL-3.0-only
"""Sample eleven: async/await, async for, async generators, await + finally."""

import asyncio


class FakeReader:
    def __init__(self, values):
        self._values = list(values)

    async def read(self):
        if not self._values:
            raise EOFError("empty")
        return self._values.pop(0)


class AsyncBag:
    def __init__(self, items):
        self._items = list(items)

    def __aiter__(self):
        return self

    async def __anext__(self):
        if not self._items:
            raise StopAsyncIteration
        return self._items.pop(0)


async def fetch(reader, tag):
    try:
        return await reader.read()
    finally:
        print("fetch_finally", tag)


async def agen():
    for i in range(3):
        yield i


async def drain(bag):
    out = []
    async for item in bag:
        out.append(item)
    return out


async def main_async():
    reader = FakeReader([10, 20])
    print("await", await fetch(reader, 1))
    print("await", await fetch(reader, 2))
    try:
        await fetch(reader, 3)
    except EOFError as exc:
        print("eof", str(exc))
    print("async_for", await drain(AsyncBag([1, 2, 3])))
    print("async_gen", [x async for x in agen()])


def main():
    asyncio.run(main_async())


if __name__ == "__main__":
    main()
