"""Additive schema migration derived from the models.

``Base.metadata.create_all`` creates tables that do not exist yet, so a new
*table* reaches an existing deployment without any migration. It does nothing
for a new *column*: ``CREATE TABLE IF NOT EXISTS`` is a no-op once the table is
there, so a model that grows a column and a database that predates it diverge
silently and the mismatch only surfaces as a "no such column" error inside
whichever request happened to touch it first.

The earlier fix for this was a hand-written ``ensure_sqlite_columns`` mapping of
table -> (column, definition). That worked, but it only ever listed the columns
someone remembered to add, and it only ran on SQLite, so a PostgreSQL deployment
got nothing at all. Both failure modes are structural rather than accidental, so
this module derives the expected schema from the models themselves and keeps no
list that can drift.

The migration is deliberately **additive only**. It adds missing tables,
columns, indexes, and unique constraints; it never drops, renames, or retypes an
existing object. An automatic destructive "fix" against a live evidence database
would be far worse than a startup error telling an operator what to do.
"""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy import inspect, text
from sqlalchemy.engine import Engine

logger = logging.getLogger(__name__)

#: Dialects whose ``ALTER TABLE`` can add a column with an inline UNIQUE and a
#: NOT NULL constraint in one statement. SQLite can do neither.
_RICH_ALTER = {"postgresql", "mysql", "mariadb"}


def _supports_if_not_exists(dialect: str) -> bool:
    return dialect in {"sqlite", "postgresql"}


def _quote(identifier: str) -> str:
    """Quote an identifier without trusting caller input as SQL."""
    if '"' in identifier or "\x00" in identifier:
        raise ValueError(f"Refusing to quote suspicious identifier: {identifier!r}")
    return f'"{identifier}"'


def _type_sql(column: Any, dialect: Any) -> str:
    return column.type.compile(dialect=dialect)


def _default_sql(column: Any, dialect: Any) -> str | None:
    """Render a column default, or ``None`` when there is nothing usable.

    Only literals are rendered. A callable default is application-side and has
    no server-side spelling, so the column is added nullable instead of
    inventing a value the model would not have produced anyway.
    """
    server_default = getattr(column, "server_default", None)
    if server_default is not None and getattr(server_default, "arg", None) is not None:
        raw = server_default.arg
        return raw if isinstance(raw, str) else repr(raw)
    default = getattr(column, "default", None)
    if default is None:
        return None
    value = getattr(default, "arg", None)
    if callable(value):
        return None
    if value is None:
        return None
    if isinstance(value, bool):
        return "1" if value else "0"
    if isinstance(value, (int, float)):
        return repr(value)
    return "'" + str(value).replace("'", "''") + "'"


def ensure_schema(engine: Engine) -> dict[str, Any]:
    """Bring an existing database up to the shape the models describe.

    Returns a report of what was created, what could not be applied, and what
    was deliberately left alone. Never raises for ordinary drift, so a
    deployment that cannot be fixed automatically still starts and can report
    the problem, but it does log and surface every skipped item.
    """
    from app.models import Base

    dialect = engine.dialect
    dialect_name = dialect.name
    report: dict[str, Any] = {
        "tables_created": [],
        "columns_added": [],
        "indexes_created": [],
        "unique_indexes_created": [],
        "skipped": [],
        "type_mismatch": [],
    }

    # Missing tables first: a missing column cannot be added to a table that
    # does not exist yet.
    Base.metadata.create_all(bind=engine, checkfirst=True)

    # Re-inspect after create_all so the view of the database includes anything
    # it just created.
    inspector = inspect(engine)
    existing_tables = set(inspector.get_table_names())

    with engine.begin() as connection:
        for table in Base.metadata.sorted_tables:
            if table.name not in existing_tables:
                report["skipped"].append({"table": table.name, "why": "table_missing"})
                continue

            present = {col["name"]: col for col in inspector.get_columns(table.name)}
            row_count = None

            for column in table.columns:
                if column.name in present:
                    # A column that exists with a different type is reported,
                    # never coerced: narrowing a live column can destroy
                    # evidence and widening it silently changes meaning.
                    current = str(present[column.name].get("type", ""))
                    expected = str(column.type)
                    if current and expected and current.lower() != expected.lower():
                        report["type_mismatch"].append({
                            "table": table.name, "column": column.name,
                            "existing": current, "model": expected,
                        })
                    continue

                if row_count is None:
                    row_count = connection.execute(
                        text(f"SELECT COUNT(*) FROM {_quote(table.name)}")
                    ).scalar() or 0

                statement, note = _add_column(table, column, dialect, row_count)
                if statement is None:
                    report["skipped"].append({
                        "table": table.name, "column": column.name, "why": note,
                    })
                    continue
                try:
                    connection.exec_driver_sql(statement)
                except Exception as error:  # noqa: BLE001 - one column must not abort the rest
                    logger.warning("schema: could not add %s.%s: %s",
                                   table.name, column.name, error)
                    report["skipped"].append({
                        "table": table.name, "column": column.name,
                        "why": f"{type(error).__name__}: {error}",
                    })
                    continue
                report["columns_added"].append({"table": table.name, "column": column.name})
                logger.info("schema: added column %s.%s", table.name, column.name)

            report["unique_indexes_created"].extend(
                _add_unique_constraints(connection, table, dialect_name)
            )
            report["indexes_created"].extend(
                _add_indexes(connection, table, dialect_name)
            )

    if any(report[key] for key in ("columns_added", "tables_created",
                                   "indexes_created", "unique_indexes_created")):
        logger.info("schema: migration applied: %s", {
            key: report[key] for key in
            ("tables_created", "columns_added", "indexes_created", "unique_indexes_created")
        })
    for item in report["skipped"]:
        logger.warning("schema: skipped %s", item)
    for item in report["type_mismatch"]:
        logger.warning("schema: type drift %s", item)
    return report


def _add_column(table: Any, column: Any, dialect: Any, row_count: int) -> tuple[str | None, str]:
    """Build the ``ADD COLUMN`` statement, or explain why it cannot be built."""
    definition = f"{_quote(column.name)} {_type_sql(column, dialect)}"
    default = _default_sql(column, dialect)

    if not column.nullable:
        if dialect.name in _RICH_ALTER:
            if default is not None:
                definition += f" NOT NULL DEFAULT {default}"
            elif row_count == 0:
                definition += " NOT NULL"
            else:
                # Populated table with no default: a NOT NULL add would fail
                # against existing rows, so the column lands nullable and the
                # operator backfills deliberately.
                return (f"ALTER TABLE {_quote(table.name)} ADD COLUMN {definition}",
                        "not_null_needs_backfill")
        else:
            # SQLite refuses NOT NULL without a default, and refuses it on a
            # populated table even with one.
            if default is not None and row_count == 0:
                definition += f" NOT NULL DEFAULT {default}"
            else:
                if default is not None:
                    definition += f" DEFAULT {default}"
                return (f"ALTER TABLE {_quote(table.name)} ADD COLUMN {definition}",
                        "not_null_relaxed_for_sqlite")

    if column.unique:
        if dialect.name in _RICH_ALTER:
            definition += " UNIQUE"
        # SQLite cannot add UNIQUE inline; a unique index covers it instead
        # and is created by the constraint pass below.

    if column.foreign_keys and dialect.name not in _RICH_ALTER:
        # ALTER TABLE ADD COLUMN cannot carry a foreign key on SQLite, and the
        # connection usually does not enforce them anyway. Recorded rather
        # than silently dropped.
        logger.debug("schema: %s.%s added without its foreign key", table.name, column.name)

    return f"ALTER TABLE {_quote(table.name)} ADD COLUMN {definition}", ""


def _add_unique_constraints(connection: Any, table: Any, dialect_name: str) -> list[str]:
    """Create a unique index for each declared ``UniqueConstraint``.

    SQLite cannot add a UNIQUE constraint to an existing table at all, so the
    only way an existing deployment gets the constraint (for example
    ``delivery``'s ``message_id`` + ``recipient``) is via a unique index.
    """
    created: list[str] = []
    existing = _index_names(connection, table.name, dialect_name)
    for constraint in table.constraints:
        if constraint.__class__.__name__ != "UniqueConstraint":
            continue
        columns = [c.name for c in constraint.columns]
        if not columns:
            continue
        name = constraint.name or f"uq_{table.name}_{'_'.join(columns)}"
        if name in existing:
            continue
        predicate = "IF NOT EXISTS " if _supports_if_not_exists(dialect_name) else ""
        try:
            connection.exec_driver_sql(
                f"CREATE UNIQUE INDEX {predicate}{_quote(name)} ON {_quote(table.name)} "
                f"({', '.join(_quote(c) for c in columns)})"
            )
        except Exception as error:  # noqa: BLE001
            # Duplicate rows in a pre-existing database make the index
            # impossible; that is an operator decision, not something to
            # silently delete data over.
            logger.warning("schema: unique index %s not created: %s", name, error)
            continue
        created.append(f"{table.name}.{name}")
    return created


def _add_indexes(connection: Any, table: Any, dialect_name: str) -> list[str]:
    created: list[str] = []
    existing = _index_names(connection, table.name, dialect_name)
    for index in table.indexes:
        if index.name in existing:
            continue
        predicate = "IF NOT EXISTS " if _supports_if_not_exists(dialect_name) else ""
        try:
            connection.exec_driver_sql(
                f"CREATE INDEX {predicate}{_quote(index.name)} ON {_quote(table.name)} "
                f"({', '.join(_quote(c.name) for c in index.columns)})"
            )
        except Exception as error:  # noqa: BLE001
            logger.warning("schema: index %s not created: %s", index.name, error)
            continue
        created.append(f"{table.name}.{index.name}")
    return created


def _index_names(connection: Any, table_name: str, dialect_name: str) -> set[str]:
    """Names of indexes already present on ``table_name``."""
    if dialect_name == "sqlite":
        rows = connection.exec_driver_sql(
            "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name=:t",
            {"t": table_name},
        ).fetchall()
        return {row[0] for row in rows}
    rows = connection.exec_driver_sql(
        "SELECT indexname FROM pg_indexes WHERE tablename=:t", {"t": table_name}
    ).fetchall()
    return {row[0] for row in rows}


__all__ = ["ensure_schema"]