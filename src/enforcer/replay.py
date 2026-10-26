"""Atomic, local replay tracking for single-use grants."""

from __future__ import annotations

import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol, runtime_checkable


@runtime_checkable
class ReplayStore(Protocol):
    """Persistent store that atomically consumes issuer-scoped grant nonces."""

    def consume(self, issuer_id: str, nonce: str, request_id: str) -> bool:
        """Return True exactly once; return False for an already-used nonce/request."""
        ...


class SQLiteReplayStore:
    """Small local replay store with a uniqueness constraint and transaction.

    Use a persistent, access-controlled database path in production. `:memory:`
    is intended for tests. This local store does not coordinate across hosts;
    multi-process/multi-host deployments need a shared store with equivalent
    atomic uniqueness semantics.
    """

    def __init__(self, database: str | Path = ":memory:") -> None:
        self._lock = threading.RLock()
        self._connection = sqlite3.connect(
            str(database), timeout=5.0, isolation_level=None, check_same_thread=False
        )
        self._connection.execute("PRAGMA foreign_keys = ON")
        if str(database) != ":memory:":
            self._connection.execute("PRAGMA journal_mode = WAL")
        self._connection.execute(
            """
            CREATE TABLE IF NOT EXISTS consumed_grants (
                issuer_id TEXT NOT NULL,
                nonce TEXT NOT NULL,
                request_id TEXT NOT NULL UNIQUE,
                consumed_at TEXT NOT NULL,
                PRIMARY KEY (issuer_id, nonce)
            )
            """
        )

    def consume(self, issuer_id: str, nonce: str, request_id: str) -> bool:
        consumed_at = datetime.now(timezone.utc).isoformat()
        with self._lock:
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                self._connection.execute(
                    "INSERT INTO consumed_grants (issuer_id, nonce, request_id, consumed_at) "
                    "VALUES (?, ?, ?, ?)",
                    (issuer_id, nonce, request_id, consumed_at),
                )
                self._connection.execute("COMMIT")
                return True
            except sqlite3.IntegrityError:
                self._connection.execute("ROLLBACK")
                return False
            except Exception:
                # Fail closed. Roll back when a transaction is still active.
                if self._connection.in_transaction:
                    self._connection.execute("ROLLBACK")
                raise

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def __enter__(self) -> "SQLiteReplayStore":
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()
