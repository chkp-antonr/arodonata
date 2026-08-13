"""JSONColumn TypeDecorator for cross-database JSON/JSONB support."""

from typing import Any

from sqlalchemy import JSON, Dialect, TypeDecorator
from sqlalchemy.dialects.postgresql import JSONB


class JSONColumn(TypeDecorator[Any]):  # type: ignore[misc]
    """JSON type that uses JSONB for PostgreSQL, JSON for SQLite.

    This TypeDecorator provides optimal JSON storage for each database:
    - PostgreSQL: JSONB (binary JSON, faster queries, indexed)
    - SQLite: JSON (stored as text, converted on access)

    Benefits of JSONB on PostgreSQL:
    - Efficient storage (binary format)
    - Faster queries (no reparsing on each access)
    - Supports GIN indexes for containment queries
    - Supports operators like @>, ?, ?&, ?|

    Usage:
        class MyModel(SQLModel, table=True):
            data: dict | None = Field(
                default=None,
                sa_column=Column("data", JSONColumn, nullable=True),
            )
    """

    # The underlying implementation type
    impl = JSON

    def load_dialect_impl(self, dialect: Dialect) -> TypeDecorator[Any]:  # type: ignore[override]
        """Return the appropriate JSON type for the database dialect.

        Args:
            dialect: SQLAlchemy dialect (postgresql, sqlite, etc.)

        Returns:
            JSONB for PostgreSQL, JSON for other databases.
        """
        if dialect.name == "postgresql":
            # Use JSONB for PostgreSQL (better performance, supports GIN indexes)
            return dialect.type_descriptor(JSONB())  # type: ignore[return-value]
        # For SQLite and others, use standard JSON
        return dialect.type_descriptor(JSON())  # type: ignore[return-value]

    def process_bind_param(self, value: Any, dialect: Dialect) -> Any:
        """Process Python value for storage in database.

        Args:
            value: Python dict/list to store
            dialect: Database dialect

        Returns:
            JSON-compatible value for database storage.
        """
        if value is None:
            return None
        # JSON/JSONB handles dict/list serialization automatically
        return value

    def process_result_value(self, value: Any, dialect: Dialect) -> Any:
        """Process database value for Python usage.

        Args:
            value: Value from database
            dialect: Database dialect

        Returns:
            Python dict/list from database JSON.
        """
        if value is None:
            return None
        # JSON/JSONB handles deserialization automatically
        return value

    def coerce_to_in_types(self, value: Any, dialect: Dialect) -> Any:
        """Coerce value to appropriate in-clause types."""
        # For JSONB containment queries in PostgreSQL
        if dialect.name == "postgresql" and isinstance(value, dict):
            return value
        return value
