"""Tests for the JSONColumn TypeDecorator (cross-database JSON/JSONB support)."""

from __future__ import annotations

from collections.abc import Generator
from contextlib import contextmanager
from typing import Any

from sqlalchemy import Column, create_engine
from sqlalchemy.dialects import postgresql, sqlite
from sqlalchemy.orm import Session
from sqlmodel import Field, SQLModel

from arodonata.cache.json_column import JSONColumn


class _JSONColumnModel(SQLModel, table=True):
    """Local model for exercising JSONColumn round-trips."""

    __test__ = False  # not a pytest test class
    __tablename__ = "json_column_model"  # type: ignore[assignment]

    id: int = Field(primary_key=True)
    data: dict[str, Any] | None = Field(
        default=None,
        sa_column=Column("data", JSONColumn, nullable=True),
    )
    items: list[Any] | None = Field(
        default=None,
        sa_column=Column("items", JSONColumn, nullable=True),
    )


@contextmanager
def _make_session() -> Generator[Session]:
    engine = create_engine("sqlite:///:memory:")
    try:
        SQLModel.metadata.create_all(engine, tables=[_JSONColumnModel.__table__])
        with Session(engine) as session:
            yield session
    finally:
        engine.dispose()


def test_dict_round_trip() -> None:
    """A dict value survives a bind/store/retrieve cycle unchanged."""
    with _make_session() as session:
        obj = _JSONColumnModel(id=1, data={"key": "value", "nested": {"a": 1}})
        session.add(obj)
        session.commit()
        session.expunge_all()

        retrieved = session.get(_JSONColumnModel, 1)
        assert retrieved is not None
        assert retrieved.data == {"key": "value", "nested": {"a": 1}}


def test_list_round_trip() -> None:
    """A list value survives a bind/store/retrieve cycle unchanged."""
    with _make_session() as session:
        obj = _JSONColumnModel(id=1, items=[1, 2, {"nested": "value"}, None])
        session.add(obj)
        session.commit()
        session.expunge_all()

        retrieved = session.get(_JSONColumnModel, 1)
        assert retrieved is not None
        assert retrieved.items == [1, 2, {"nested": "value"}, None]


def test_none_round_trip() -> None:
    """None values are stored and retrieved as None (not serialized to 'null' string)."""
    with _make_session() as session:
        obj = _JSONColumnModel(id=1, data=None, items=None)
        session.add(obj)
        session.commit()
        session.expunge_all()

        retrieved = session.get(_JSONColumnModel, 1)
        assert retrieved is not None
        assert retrieved.data is None
        assert retrieved.items is None


def test_empty_dict_and_list_round_trip() -> None:
    """Empty dict/list are distinct from None and survive the round-trip."""
    with _make_session() as session:
        obj = _JSONColumnModel(id=1, data={}, items=[])
        session.add(obj)
        session.commit()
        session.expunge_all()

        retrieved = session.get(_JSONColumnModel, 1)
        assert retrieved is not None
        assert retrieved.data == {}
        assert retrieved.items == []


def test_process_bind_param_passes_through_non_none_values() -> None:
    """process_bind_param leaves dict/list values unchanged (JSON serialization
    is delegated to the underlying JSON/JSONB implementation)."""
    column_type = JSONColumn()
    value = {"a": 1, "b": [1, 2, 3]}

    assert column_type.process_bind_param(value, sqlite.dialect()) == value
    assert column_type.process_bind_param(None, sqlite.dialect()) is None


def test_process_result_value_passes_through_values() -> None:
    """process_result_value leaves already-deserialized values unchanged."""
    column_type = JSONColumn()
    value = {"a": 1}

    assert column_type.process_result_value(value, sqlite.dialect()) == value
    assert column_type.process_result_value(None, sqlite.dialect()) is None


def test_load_dialect_impl_uses_jsonb_for_postgresql() -> None:
    """PostgreSQL dialect gets JSONB for binary storage / GIN index support."""
    column_type = JSONColumn()
    dialect = postgresql.dialect()

    impl = column_type.load_dialect_impl(dialect)

    assert isinstance(impl, postgresql.JSONB)


def test_load_dialect_impl_uses_json_for_sqlite() -> None:
    """Non-PostgreSQL dialects (e.g. SQLite) fall back to plain JSON."""
    column_type = JSONColumn()
    dialect = sqlite.dialect()

    impl = column_type.load_dialect_impl(dialect)

    assert not isinstance(impl, postgresql.JSONB)


def test_coerce_to_in_types_returns_dict_for_postgresql() -> None:
    """coerce_to_in_types passes dict values through for PostgreSQL containment queries."""
    column_type = JSONColumn()
    value = {"a": 1}

    assert column_type.coerce_to_in_types(value, postgresql.dialect()) == value


def test_coerce_to_in_types_returns_value_for_other_dialects() -> None:
    """coerce_to_in_types passes values through unchanged for non-PostgreSQL dialects."""
    column_type = JSONColumn()
    value = {"a": 1}

    assert column_type.coerce_to_in_types(value, sqlite.dialect()) == value
