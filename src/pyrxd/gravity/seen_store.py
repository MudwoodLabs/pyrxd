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
sync (matching the in-process store); the SQLite write is committed AND fsync'd
(``synchronous=FULL``) before it returns, so even a power/OS crash after ``reserve`` but
before the broadcast cannot resurrect the replay window.

Durability note (audit replay-LOW): WAL with ``synchronous=NORMAL`` does NOT fsync the WAL on
each commit — committed rows are durable only as of the last checkpoint, so a power loss can
roll back a reservation. Because a reservation is one tiny row per fund (not throughput
sensitive), we use ``synchronous=FULL`` to fsync on commit and buy true power-loss durability,
which is exactly the SEEN-1 guarantee the coordinator relies on for a value-bearing network.
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
        # synchronous=FULL (not NORMAL): fsync the WAL on every commit so a reservation survives
        # a power/OS crash, not just a process crash. A single-row reserve per fund is not
        # throughput-sensitive, so the extra fsync is negligible and buys real SEEN-1 durability.
        self._conn.execute("PRAGMA synchronous=FULL")
        self._conn.execute(_SCHEMA)
        # Keep perms tight on the DB AND its WAL/SHM sidecars (red-team INFO): under WAL +
        # autocommit the committed reservation rows live in the -wal sidecar, which sqlite created
        # at the umask default (often 0644). chmod all three so a same-group reader can't see the
        # H-keyed reservation metadata. (H is public, so this is hygiene, not a secret leak.)
        for suffix in ("", "-wal", "-shm"):
            try:
                os.chmod(f"{path}{suffix}", 0o600)
            except OSError:
                pass  # e.g. ":memory:", a backend without chmod, or a sidecar not yet created

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
