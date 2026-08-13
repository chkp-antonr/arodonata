"""Tests for arodonata.cache.schema_version (metadata hash for migration-scan skip)."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import Column, Computed, DateTime, FetchedValue, Index, Integer, MetaData, String, Table, text

from arodonata.cache.schema_version import compute_schema_hash


def _base_metadata() -> MetaData:
    md = MetaData()
    Table(
        "widgets",
        md,
        Column("id", Integer, primary_key=True),
        Column("name", String(50), nullable=False),
        Index("ix_widgets_name", "name"),
    )
    return md


def test_hash_is_deterministic() -> None:
    """Two independently built but identical metadatas hash the same."""
    assert compute_schema_hash(_base_metadata()) == compute_schema_hash(_base_metadata())


def test_hash_is_hex_sha256() -> None:
    h = compute_schema_hash(_base_metadata())
    assert len(h) == 64
    int(h, 16)  # raises if not hex


def test_hash_changes_when_column_added() -> None:
    md = _base_metadata()
    md.tables["widgets"].append_column(Column("color", String(20)))
    assert compute_schema_hash(md) != compute_schema_hash(_base_metadata())


def test_hash_changes_when_index_added() -> None:
    md = MetaData()
    Table(
        "widgets",
        md,
        Column("id", Integer, primary_key=True),
        Column("name", String(50), nullable=False),
        Index("ix_widgets_name", "name"),
        Index("ix_widgets_name_unique", "name", unique=True),
    )
    assert compute_schema_hash(md) != compute_schema_hash(_base_metadata())


def test_hash_changes_when_nullability_changes() -> None:
    md = MetaData()
    Table(
        "widgets",
        md,
        Column("id", Integer, primary_key=True),
        Column("name", String(50), nullable=True),
        Index("ix_widgets_name", "name"),
    )
    assert compute_schema_hash(md) != compute_schema_hash(_base_metadata())


def test_hash_ignores_table_registration_order() -> None:
    md_ab = MetaData()
    Table("aaa", md_ab, Column("id", Integer, primary_key=True))
    Table("bbb", md_ab, Column("id", Integer, primary_key=True))
    md_ba = MetaData()
    Table("bbb", md_ba, Column("id", Integer, primary_key=True))
    Table("aaa", md_ba, Column("id", Integer, primary_key=True))
    assert compute_schema_hash(md_ab) == compute_schema_hash(md_ba)


def test_hash_deterministic_with_default_factory() -> None:
    """Regression: CallableColumnDefault must produce deterministic hash across sessions.

    SQLModel's default_factory=lambda: ... wraps the callable in CallableColumnDefault,
    which has the lambda's memory address in its repr. Each process restart produces a
    different repr. The hash must be stable across sessions (simulate by building two
    independent tables with identical callable defaults).
    """
    # Build two independent tables with callable defaults
    md1 = MetaData()
    Table(
        "events",
        md1,
        Column("id", Integer, primary_key=True),
        Column("timestamp", DateTime, default=lambda: datetime.now(UTC).replace(tzinfo=None)),
    )

    md2 = MetaData()
    Table(
        "events",
        md2,
        Column("id", Integer, primary_key=True),
        Column("timestamp", DateTime, default=lambda: datetime.now(UTC).replace(tzinfo=None)),
    )

    # Both tables have identical schemas with callable defaults. Hashes must match.
    assert compute_schema_hash(md1) == compute_schema_hash(md2)


def test_hash_handles_fetched_value_server_default() -> None:
    """Regression: FetchedValue server defaults must not raise AttributeError.

    FetchedValue does not have a .arg attribute. The hash function must handle it
    gracefully using a safe fallback (e.g., type name).
    """
    md = MetaData()
    Table(
        "auto_generated",
        md,
        Column("id", Integer, primary_key=True),
        Column("auto_id", Integer, server_default=FetchedValue()),
    )
    # Should not raise
    h = compute_schema_hash(md)
    assert len(h) == 64
    int(h, 16)


def test_hash_handles_computed_server_default() -> None:
    """Regression: Computed server defaults must not raise AttributeError.

    Computed expressions do not have a .arg attribute. The hash function must
    handle them safely using a fallback.
    """
    md = MetaData()
    Table(
        "computed_col",
        md,
        Column("id", Integer, primary_key=True),
        Column("derived", Integer, Computed("id * 2")),
    )
    # Should not raise
    h = compute_schema_hash(md)
    assert len(h) == 64
    int(h, 16)


def test_hash_deterministic_with_text_server_default() -> None:
    """Regression: text() server defaults must produce deterministic hash across sessions.

    TextClause doesn't override __repr__, so repr() embeds memory address.
    Using str() instead gives stable SQL string across process boundaries.
    Verify by building two independent metadatas with identical text() defaults.
    """
    # Build two independent tables with text() server defaults
    md1 = MetaData()
    Table(
        "with_text_default",
        md1,
        Column("id", Integer, primary_key=True),
        Column("status", String(50), server_default=text("'active'")),
    )

    md2 = MetaData()
    Table(
        "with_text_default",
        md2,
        Column("id", Integer, primary_key=True),
        Column("status", String(50), server_default=text("'active'")),
    )

    # Both tables have identical schemas with text() server defaults. Hashes must match.
    assert compute_schema_hash(md1) == compute_schema_hash(md2)
