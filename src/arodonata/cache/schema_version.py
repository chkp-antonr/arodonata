"""Deterministic hash of SQLModel/SQLAlchemy metadata.

Used by DatabaseManager.initialize() to skip the per-table auto-migration
scan when the registered model schema is unchanged since the last run.
"""

from __future__ import annotations

import hashlib

from sqlalchemy import MetaData
from sqlalchemy.sql.schema import CallableColumnDefault


def _stable_default_repr(col_default: object) -> str:
    """Return a stable repr of a column default value.

    Callable defaults (e.g., from SQLModel's default_factory) contain
    lambda functions with memory addresses in their repr. This function
    returns a deterministic marker for callables and stable reprs for
    scalar defaults.

    Args:
        col_default: SQLAlchemy ColumnDefault object or None.

    Returns:
        Stable string representation.
    """
    if col_default is None:
        return "None"
    if isinstance(col_default, CallableColumnDefault):
        # Callable defaults are non-deterministic (lambda repr includes memory address).
        # We use a stable marker since what matters for schema is DDL shape, not the Python function.
        return "callable"
    # Scalar defaults have stable repr
    return repr(col_default)


def _stable_server_default_repr(server_default: object) -> str:
    """Return a stable repr of a server default.

    server_default can be TextClause, FetchedValue, Computed, or other types.
    Some types (FetchedValue, Computed) don't have a safe .arg attribute.

    Args:
        server_default: SQLAlchemy ServerDefault or None.

    Returns:
        Stable string representation that cannot raise.
    """
    if server_default is None:
        return "None"
    # Try .arg first (works for TextClause)
    arg = getattr(server_default, "arg", None)
    if arg is not None:
        # Use str() instead of repr() for TextClause stability.
        # TextClause.__repr__ uses object.__repr__ with memory address.
        # str() returns the SQL string stably across process boundaries.
        return str(arg)
    # Fallback: use class name (for FetchedValue, Computed, etc.)
    return type(server_default).__name__


def compute_schema_hash(metadata: MetaData) -> str:
    """Compute a deterministic SHA-256 over the metadata's schema shape.

    Covers table names, columns (name, type, nullability, default, PK),
    indexes (name, columns, unique) and unique constraints. Purely
    in-memory — no DB access. Registration order does not affect the hash.

    Args:
        metadata: SQLAlchemy MetaData (e.g. SQLModel.metadata).

    Returns:
        64-char hex SHA-256 digest.
    """
    parts: list[str] = []
    for table_name in sorted(metadata.tables):
        table = metadata.tables[table_name]
        parts.append(f"table:{table_name}")
        for col in sorted(table.columns, key=lambda c: c.name):
            parts.append(
                "col:"
                f"{col.name}|{col.type!s}|nullable={col.nullable}"
                f"|pk={col.primary_key}|default={_stable_default_repr(col.default)}"
                f"|server_default={_stable_server_default_repr(col.server_default)}"
            )
        for idx in sorted(table.indexes, key=lambda i: i.name or ""):
            col_names = ",".join(sorted(c.name for c in idx.columns))
            parts.append(f"idx:{idx.name}|{col_names}|unique={idx.unique}")
        for const in sorted(
            table.constraints,
            key=lambda c: (
                c.__class__.__name__,
                c.name or "",
                tuple(sorted(x.name for x in getattr(c, "columns", []))),
            ),
        ):
            col_names = ",".join(sorted(c.name for c in getattr(const, "columns", [])))
            parts.append(f"const:{const.__class__.__name__}|{const.name}|{col_names}")
    return hashlib.sha256("\n".join(parts).encode()).hexdigest()


__all__ = ["compute_schema_hash"]
