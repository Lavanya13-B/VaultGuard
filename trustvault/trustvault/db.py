import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = (Path(__file__).parent / "schema.sql").read_text()


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def connect(path):
    db = sqlite3.connect(path, isolation_level=None, timeout=15)  # explicit transactions
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")
    db.execute("PRAGMA journal_mode=WAL")
    return db


def init_db(path):
    db = connect(path)
    db.executescript(SCHEMA)
    db.close()


@contextmanager
def tx(db):
    """Write transaction. Joins an outer one if present. BEGIN IMMEDIATE serialises
    writers, which is also what keeps the audit hash chain linear."""
    if db.in_transaction:
        yield
        return
    db.execute("BEGIN IMMEDIATE")
    try:
        yield
    except BaseException:
        db.execute("ROLLBACK")
        raise
    else:
        db.execute("COMMIT")
