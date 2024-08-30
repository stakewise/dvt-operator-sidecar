from typing import Iterator, overload


@overload
def to_chunks(items: list, size: int) -> Iterator[list]:
    ...


@overload
def to_chunks(items: range, size: int) -> Iterator[range]:
    ...


@overload
def to_chunks(items: bytes, size: int) -> Iterator[bytes]:
    ...


def to_chunks(items, size):  # type: ignore[no-untyped-def]
    for i in range(0, len(items), size):
        yield items[i : i + size]
