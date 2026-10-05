"""The additive migration must repair an *existing* database, not just a new one.

Every other test in the suite builds its database from the current models, so
it can only ever prove that ``create_all`` works. These tests start from a
deliberately old-shaped schema instead, which is the only way to show that a
deployment predating a column gets repaired rather than failing later inside an
unrelated request.
"""

from __future__ import annotations

from sqlalchemy import create_engine, inspect, text

from app.models import Base
from app.schema import ensure_schema


def legacy_engine(tmp_path):
    """An engine holding a database created before the newer columns existed."""
    engine = create_engine(f"sqlite:///{(tmp_path / 'legacy.db').as_posix()}")
    # Tables that existed at the time, with the columns they had at the time.
    with engine.begin() as connection:
        connection.exec_driver_sql(
            "CREATE TABLE alerts (id INTEGER NOT NULL PRIMARY KEY,"
            " title VARCHAR(200) NOT NULL DEFAULT '', severity VARCHAR(20) NOT NULL DEFAULT '')"
        )
        connection.exec_driver_sql("INSERT INTO alerts (title) VALUES ('old alert')")
        connection.exec_driver_sql(
            "CREATE TABLE deliveries (id INTEGER NOT NULL PRIMARY KEY,"
            " message_id VARCHAR(64) NOT NULL DEFAULT '')"
        )
        connection.exec_driver_sql(
            "CREATE TABLE biometric_samples (id INTEGER NOT NULL PRIMARY KEY,"
            " occurred_at DATETIME)"
        )
        connection.exec_driver_sql(
            "INSERT INTO biometric_samples (occurred_at) VALUES ('2024-01-02 03:04:05')"
        )
    return engine


def columns_of(engine, table):
    return {column["name"] for column in inspect(engine).get_columns(table)}


def test_missing_columns_are_added_to_an_existing_database(tmp_path) -> None:
    engine = legacy_engine(tmp_path)
    report = ensure_schema(engine)
    added = {(item["table"], item["column"]) for item in report["columns_added"]}
    # case_id on alerts is the column an in-product model grew that the old
    # hand-maintained list forgot, which is exactly the drift being fixed.
    assert ("alerts", "case_id") in added
    assert ("alerts", "assignee") in added
    assert "case_id" in columns_of(engine, "alerts")
    # Pre-existing data must survive the migration untouched.
    with engine.begin() as connection:
        assert connection.exec_driver_sql("SELECT COUNT(*) FROM alerts").scalar() == 1
        assert connection.exec_driver_sql(
            "SELECT title FROM alerts").scalar() == "old alert"


def test_missing_tables_are_created(tmp_path) -> None:
    engine = legacy_engine(tmp_path)
    ensure_schema(engine)
    names = set(inspect(engine).get_table_names())
    for table in ("outbound_recipients", "audit_export_schedules", "tickets"):
        assert table in names


def test_unique_constraint_is_added_to_a_pre_existing_table(tmp_path) -> None:
    # SQLite cannot add UNIQUE to an existing table, so a plain column add
    # would leave idempotent delivery unguarded on a live deployment.
    engine = legacy_engine(tmp_path)
    ensure_schema(engine)
    indexes = {
        index["name"]
        for index in inspect(engine).get_indexes("deliveries")
    }
    assert "uq_delivery_target" in indexes, indexes


def test_migration_is_idempotent(tmp_path) -> None:
    engine = legacy_engine(tmp_path)
    first = ensure_schema(engine)
    assert first["columns_added"]
    second = ensure_schema(engine)
    assert second["columns_added"] == []
    assert second["unique_indexes_created"] == []
    assert second["indexes_created"] == []
    # A second pass must not disturb data either.
    with engine.begin() as connection:
        assert connection.exec_driver_sql("SELECT COUNT(*) FROM alerts").scalar() == 1


def test_backfill_copies_occurred_at_into_received_at(tmp_path) -> None:
    from app.main import ensure_database_schema

    engine = legacy_engine(tmp_path)
    ensure_database_schema(engine)
    with engine.begin() as connection:
        value = connection.exec_driver_sql(
            "SELECT received_at FROM biometric_samples").scalar()
    assert str(value) == "2024-01-02 03:04:05"


def test_existing_column_type_drift_is_reported_not_coerced(tmp_path) -> None:
    engine = create_engine(f"sqlite:///{(tmp_path / 'drift.db').as_posix()}")
    with engine.begin() as connection:
        connection.exec_driver_sql(
            "CREATE TABLE screen_definitions (id INTEGER NOT NULL PRIMARY KEY,"
            " name VARCHAR(5) NOT NULL DEFAULT '')"
        )
        connection.exec_driver_sql("INSERT INTO screen_definitions (name) VALUES ('abcdefghij')")
    report = ensure_schema(engine)
    mismatch = {(item["table"], item["column"]) for item in report["type_mismatch"]}
    assert ("screen_definitions", "name") in mismatch
    # Narrowing the column would destroy stored evidence, so it is left alone.
    with engine.begin() as connection:
        assert connection.exec_driver_sql(
            "SELECT name FROM screen_definitions").scalar() == "abcdefghij"


def test_fresh_database_reports_no_work(tmp_path) -> None:
    engine = create_engine(f"sqlite:///{(tmp_path / 'fresh.db').as_posix()}")
    Base.metadata.create_all(bind=engine)
    report = ensure_schema(engine)
    assert report["columns_added"] == []
    assert report["skipped"] == []


def test_identifier_quoting_rejects_injection(tmp_path) -> None:
    engine = create_engine(f"sqlite:///{(tmp_path / 'quote.db').as_posix()}")
    with engine.begin() as connection:
        connection.exec_driver_sql("CREATE TABLE t (id INTEGER PRIMARY KEY)")
    # A table name carrying a quote must raise rather than be interpolated.
    from app.schema import _quote

    try:
        _quote('bad"name')
    except ValueError:
        pass
    else:  # pragma: no cover - the guard is the assertion
        raise AssertionError("expected ValueError for a quoted identifier")
    assert text  # imported for parity with the other schema helpers