"""SQL-backed Repository[T] implementation.

Provides the same surface as `app.repositories.base.InMemoryRepository`:
list / get / find / count / add / add_many / update / upsert / delete /
clear. Each call opens a short-lived session, does its work, and commits.

The Pydantic↔ORM bridge is intentionally generic:

- `_indexed_fields` maps top-level Pydantic field names → ORM column names.
  These get hoisted out of the JSON payload so filters and indexes work.
- Everything else stays inside `payload` and is reconstructed by
  `pyd_model.model_validate(payload)` on read.

Repositories don't enforce relationships — callers (services, brain,
reporting) join the data in Python the same way they always have.
"""
from __future__ import annotations

from typing import Any, Callable, Generic, Iterable, Optional, Type, TypeVar

from pydantic import BaseModel

from . import session_scope
from .. import db as _db_pkg  # noqa: F401  ensure package import side-effects

T = TypeVar("T", bound=BaseModel)


class SqlRepository(Generic[T]):
    """SQL implementation of the Repository protocol.

    `indexed_fields` is the canonical mapping from Pydantic attribute name
    on `pyd_model` to the corresponding column on `orm_model`. The
    repository copies those fields onto the ORM row so they're queryable;
    the whole Pydantic dump still lives in `payload` as the source of
    truth.
    """

    def __init__(
        self,
        pyd_model: Type[T],
        orm_model: Type,
        indexed_fields: dict[str, str] | None = None,
    ) -> None:
        self.pyd_model = pyd_model
        self.orm_model = orm_model
        self.indexed_fields = indexed_fields or {}

    # ---- read ---------------------------------------------------------
    def list(self, predicate: Optional[Callable[[T], bool]] = None) -> list[T]:
        with _enter_session() as session:
            rows = session.query(self.orm_model).all()
        items = [self._to_pyd(row) for row in rows]
        if predicate is None:
            return items
        return [item for item in items if predicate(item)]

    def get(self, item_id: str) -> Optional[T]:
        with _enter_session() as session:
            row = session.query(self.orm_model).filter(self.orm_model.id == item_id).one_or_none()
            if row is None:
                return None
            return self._to_pyd(row)

    def find(self, predicate: Callable[[T], bool]) -> Optional[T]:
        for item in self.list():
            if predicate(item):
                return item
        return None

    def count(self) -> int:
        with _enter_session() as session:
            return session.query(self.orm_model).count()

    # ---- write --------------------------------------------------------
    def add(self, item: T) -> T:
        with _enter_session() as session:
            session.merge(self._to_orm(item))
        return item

    def add_many(self, items: Iterable[T]) -> None:
        with _enter_session() as session:
            for item in items:
                session.merge(self._to_orm(item))

    def update(self, item: T) -> T:
        with _enter_session() as session:
            session.merge(self._to_orm(item))
        return item

    def upsert(self, item: T) -> T:
        return self.add(item)

    def delete(self, item_id: str) -> bool:
        with _enter_session() as session:
            row = session.query(self.orm_model).filter(self.orm_model.id == item_id).one_or_none()
            if row is None:
                return False
            session.delete(row)
            return True

    def clear(self) -> None:
        with _enter_session() as session:
            session.query(self.orm_model).delete()

    # ---- internals ----------------------------------------------------
    def _to_orm(self, item: T) -> Any:
        payload = item.model_dump(mode="json")
        row_kwargs: dict[str, Any] = {"payload": payload}
        # Copy indexed fields onto the row directly.
        for pyd_field, orm_col in self.indexed_fields.items():
            value = _resolve_attribute(item, pyd_field)
            if hasattr(value, "value"):
                # Enums → their string value.
                value = value.value
            row_kwargs[orm_col] = value
        row_kwargs["id"] = item.id  # type: ignore[attr-defined]
        return self.orm_model(**row_kwargs)

    def _to_pyd(self, row: Any) -> T:
        return self.pyd_model.model_validate(row.payload)


def _resolve_attribute(item: BaseModel, attr_path: str) -> Any:
    """Allow dotted paths like `scope_rules.allow_active` if ever needed.
    For round 1, simple attribute access is sufficient but we keep this
    flexible."""
    value: Any = item
    for part in attr_path.split("."):
        value = getattr(value, part, None)
        if value is None:
            return None
    return value


def _enter_session():
    """Adapter so callers can use a `with` block over the iterator-based
    `session_scope()` helper."""
    return _SessionScope()


class _SessionScope:
    def __init__(self) -> None:
        self._iter = session_scope()
        self._session = None

    def __enter__(self):
        self._session = next(self._iter)
        return self._session

    def __exit__(self, exc_type, exc, tb):
        if exc_type is None:
            try:
                next(self._iter)
            except StopIteration:
                pass
        else:
            try:
                self._iter.throw(exc_type, exc, tb)
            except StopIteration:
                pass
            except Exception:
                raise
        return False
