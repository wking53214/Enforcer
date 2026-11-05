"""Atomic, local replay tracking for single-use grants."""

from __future__ import annotations

import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class ReplayStore(Protocol):
    """Persistent store that atomically consumes issuer-scoped grant nonces."""

    def consume(self, issuer_id: str, nonce: str, request_id: str) -> bool:
        """Return True exactly once; return False for an already-used nonce/request.

        A store may also accept an ``expires_at`` keyword (the grant's expiry, timezone-aware).
        Enforcer passes it only to stores whose ``consume`` declares it, so existing stores keep
        working. Recording it is what makes safe retention possible: a record may be removed only
        after the grant it blocks has expired, because Enforcer refuses an expired grant before it
        ever consults the store.
        """
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
        # Databases created before 0.1.1 have no expiry column. Rows written before the column
        # existed have no recorded expiry and are never pruned.
        columns = {row[1] for row in self._connection.execute("PRAGMA table_info(consumed_grants)")}
        if "expires_at" not in columns:
            self._connection.execute("ALTER TABLE consumed_grants ADD COLUMN expires_at TEXT")
        self._database = str(database)

    def consume(
        self, issuer_id: str, nonce: str, request_id: str, expires_at: datetime | None = None
    ) -> bool:
        if expires_at is not None and (expires_at.tzinfo is None or expires_at.utcoffset() is None):
            raise ValueError("expires_at must be timezone-aware")
        consumed_at = datetime.now(timezone.utc).isoformat()
        stored_expiry = (expires_at.astimezone(timezone.utc).isoformat(timespec="microseconds")
                         if expires_at is not None else None)
        with self._lock:
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                self._connection.execute(
                    "INSERT INTO consumed_grants (issuer_id, nonce, request_id, consumed_at, expires_at) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (issuer_id, nonce, request_id, consumed_at, stored_expiry),
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

    def prune(self, grace: timedelta = timedelta(minutes=1), *, now: datetime | None = None) -> int:
        """Delete records whose grant expired more than ``grace`` ago. Returns how many.

        Safe by construction: ``authorize`` refuses an expired grant before it consults the store,
        so a record for a grant that has already expired blocks nothing. Records with no recorded
        expiry (written by an older Enforcer) are never deleted. ``grace`` covers clock skew and
        should be at least ``GatePolicy.allowed_clock_skew``.
        """
        if grace < timedelta(0):
            raise ValueError("grace cannot be negative")
        cutoff = ((now or datetime.now(timezone.utc)) - grace).astimezone(timezone.utc).isoformat(timespec="microseconds")
        with self._lock:
            cursor = self._connection.execute(
                "DELETE FROM consumed_grants WHERE expires_at IS NOT NULL AND expires_at < ?", (cutoff,)
            )
            return cursor.rowcount

    def describe(self) -> dict[str, Any]:
        """What this store is, for a deployment check: local, and durable only if file-backed."""
        file_backed = self._database != ":memory:"
        return {"kind": "sqlite", "durable": file_backed, "shared": False, "path": self._database}

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def __enter__(self) -> "SQLiteReplayStore":
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()
