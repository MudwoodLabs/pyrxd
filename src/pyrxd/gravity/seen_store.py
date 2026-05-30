"""Durable (SQLite) H-freshness store — the value-bearing drop-in for the in-process
:class:`pyrxd.gravity.radiant_leg.SeenStore`.

The coordinator's ``reserve(H)`` is the authoritative atomic pre-broadcast test-and-set that
blocks free-option + cross-swap preimage replay. The in-process ``SeenStore`` loses that on a
restart / second process, so the coordinator refuses it on a value-bearing network unless the
operator opts into non-durability (SEEN-1). This store persists reservations in SQLite (WAL,
``synchronous=NORMAL``, ``INSERT OR IGNORE`` on the H primary key) and declares
``durable = True``, so freshness survives restarts and a value-bearing swap may use it.

Same duck-typed interface (``reserve`` / ``has_seen`` / ``mark_seen`` + ``durable``) as the
in-process store — a drop-in for the coordinator's ``seen_store`` parameter. ``reserve`` is
sync (matching the in-process store); the SQLite write commits before it returns, so a crash
after ``reserve`` but before the broadcast cannot resurrect the replay window.
"""

from __future__ import annotations

import os
import sqlite3
import threading

from pyrxd.security.errors import ValidationError

__all__ = ["DurableSeenStore"]

_SCHEMA = "CREATE TABLE IF NOT EXISTS seen_hashlocks (h BLOB PRIMARY KEY) WITHOUT ROWID"


class DurableSeenStore:
    """SQLite-backed durable H-freshness store. Pass a filesystem path (a fresh file is
    created if absent). Reservations persist across restarts / processes."""

    durable = True

    def __init__(self, path: str | os.PathLike) -> None:
        self._lock = threading.Lock()
        # check_same_thread=False so an async wrapper may call reserve via asyncio.to_thread
        # in a future high-throughput driver; the lock serialises access here (and SQLite's
        # INSERT OR IGNORE is itself atomic via the primary-key constraint).
        self._conn = sqlite3.connect(str(path), isolation_level=None, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.execute(_SCHEMA)
        try:
            os.chmod(path, 0o600)  # H-keyed reservation metadata; keep perms tight
        except OSError:
            pass  # e.g. ":memory:" or a backend without chmod

    @staticmethod
    def _h(hashlock: bytes) -> bytes:
        if not isinstance(hashlock, (bytes, bytearray)) or len(hashlock) != 32:
            raise ValidationError("hashlock must be 32 bytes")
        return bytes(hashlock)

    def reserve(self, hashlock: bytes) -> bool:
        """Atomically reserve ``H``. ``True`` if freshly reserved (caller may fund), ``False``
        if it was already reserved (caller MUST NOT fund). Durable: the row is committed
        before this returns."""
        h = self._h(hashlock)
        with self._lock:
            cur = self._conn.execute("INSERT OR IGNORE INTO seen_hashlocks(h) VALUES (?)", (h,))
            return cur.rowcount == 1

    def has_seen(self, hashlock: bytes) -> bool:
        h = self._h(hashlock)
        with self._lock:
            cur = self._conn.execute("SELECT 1 FROM seen_hashlocks WHERE h = ? LIMIT 1", (h,))
            return cur.fetchone() is not None

    def mark_seen(self, hashlock: bytes) -> None:
        h = self._h(hashlock)
        with self._lock:
            self._conn.execute("INSERT OR IGNORE INTO seen_hashlocks(h) VALUES (?)", (h,))

    def close(self) -> None:
        with self._lock:
            self._conn.close()
