"""Generic in-memory repository.

Stores Pydantic model instances keyed by their `id` field. Designed so a SQL
implementation can later expose the same surface area without changes to
callers.
"""
from __future__ import annotations

from typing import Callable, Generic, Iterable, Optional, TypeVar

T = TypeVar("T")


class InMemoryRepository(Generic[T]):
    """Tiny in-memory repository.

    Each stored object must expose an `id` attribute (all Asura Pydantic models
    do). Order of insertion is preserved by Python's dict ordering, which keeps
    seed data deterministic for tests.
    """

    def __init__(self) -> None:
        self._items: dict[str, T] = {}

    # ---- read ---------------------------------------------------------
    def list(self, predicate: Optional[Callable[[T], bool]] = None) -> list[T]:
        items = list(self._items.values())
        if predicate is None:
            return items
        return [item for item in items if predicate(item)]

    def get(self, item_id: str) -> Optional[T]:
        return self._items.get(item_id)

    def find(self, predicate: Callable[[T], bool]) -> Optional[T]:
        for item in self._items.values():
            if predicate(item):
                return item
        return None

    def count(self) -> int:
        return len(self._items)

    # ---- write --------------------------------------------------------
    def add(self, item: T) -> T:
        key = self._key(item)
        self._items[key] = item
        return item

    def add_many(self, items: Iterable[T]) -> None:
        for item in items:
            self.add(item)

    def update(self, item: T) -> T:
        key = self._key(item)
        if key not in self._items:
            raise KeyError(f"Cannot update missing id={key}")
        self._items[key] = item
        return item

    def upsert(self, item: T) -> T:
        self._items[self._key(item)] = item
        return item

    def delete(self, item_id: str) -> bool:
        return self._items.pop(item_id, None) is not None

    def clear(self) -> None:
        self._items.clear()

    # ---- internals ----------------------------------------------------
    @staticmethod
    def _key(item: T) -> str:
        item_id = getattr(item, "id", None)
        if not item_id:
            raise ValueError(f"Stored items must expose a non-empty 'id'; got {item!r}")
        return str(item_id)
