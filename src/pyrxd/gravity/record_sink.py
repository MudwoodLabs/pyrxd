"""Durable persistence for one in-flight swap record, and the lock that guards resuming it.

Both exist because of the same class of failure: a coordinator that *can* record its progress but
was never wired to anything that writes it, and a resume path that skipped the only mutual
exclusion the funding path had. Neither is useful as an option a caller may forget — see
:meth:`SwapCoordinator.taker_funds_btc`, which now refuses to fund an ETH counter-leg without them.
"""

from __future__ import annotations

import contextlib
import json
import os
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from pyrxd.security.errors import NetworkError, ValidationError

__all__ = ["FileFundLock", "JsonFileRecordSink"]


class JsonFileRecordSink:
    """Write a :class:`SwapRecord` to one JSON file, atomically.

    ATOMIC because a torn record is worse than no record: the whole point is that a process which
    dies mid-fund leaves behind a file that says where the value went, and a half-written file says
    nothing while looking like it should. Write to a temporary file in the same directory, fsync it,
    then ``os.replace`` — which is atomic within a filesystem — and fsync the directory so the
    rename itself survives a power loss.

    Mode 600. A swap record carries no secret (``p`` is excluded by construction) but it does carry
    addresses, amounts and counterparties.
    """

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path).expanduser()
        self._path.parent.mkdir(parents=True, exist_ok=True)

    @property
    def path(self) -> Path:
        return self._path

    async def __call__(self, record: Any) -> None:
        payload = json.dumps(record.to_dict(), indent=2, sort_keys=True).encode()
        tmp = None
        try:
            # INSIDE the try: creating the temp file is itself a filesystem operation that fails on
            # a read-only or missing directory, and an unwrapped OSError escaping here would reach
            # the coordinator as something it cannot classify — while the whole reason it awaits
            # this call is to distinguish "persisted" from "could not persist" before value moves.
            fd, tmp = tempfile.mkstemp(dir=str(self._path.parent), prefix=".swaprec-", suffix=".tmp")
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(payload)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self._path)
            dir_fd = os.open(str(self._path.parent), os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except Exception as exc:
            if tmp is not None:
                with contextlib.suppress(FileNotFoundError):
                    os.unlink(tmp)
            raise NetworkError(f"could not persist the swap record to {self._path}: {exc}") from exc

    def load(self) -> dict | None:
        """Read the record back, or None if it was never written."""
        if not self._path.exists():
            return None
        return json.loads(self._path.read_text())


class FileFundLock:
    """Exclusive, crash-safe mutual exclusion for funding ONE swap.

    ``reserve(H)`` used to provide this incidentally — it is an atomic test-and-set, so two funders
    of the same hashlock could not both proceed. The resume path deliberately skips it (the record
    already holds that reservation), which removed the only lock: two resumers would both read the
    same pre-push balance, both compute the same shortfall, and both send it, leaving twice the
    negotiated amount in a contract whose claim sweeps the whole balance to the counterparty.

    ``flock`` is the right primitive here and a lease is not: the kernel releases it when the
    holding process dies, so a crashed funder cannot deadlock the swap it was funding — which is
    exactly the situation a resume exists to recover from.

    **SCOPE — read before wiring this anywhere.** It is advisory and HOST-LOCAL. Two processes on
    one host, sharing one path, are excluded. Nothing else is: two hosts get two independent lock
    files, an operator who copies the keys directory gets a third, and ``flock`` over NFS is
    unreliable and silently local on many configurations. This class **cannot detect** any of those
    — it will grant the lock and report success.

    So a deployment where funding can be driven from more than one host must NOT pass this and
    pretend it is covered. Pass nothing instead: the coordinator refuses to resume without a lock,
    which is the honest outcome. `scripts/eth_swap_two_host.py` does exactly that.

    The path is derived from the caller's key path, NOT from the hashlock, so two swaps sharing a
    funding key share a lock — conservative (over-exclusion) rather than unsafe, but it means this
    is not a per-swap lock and should not be described as one.
    """

    def __init__(self, path: str | Path) -> None:
        self._path = Path(str(path) + ".fundlock").expanduser()
        self._path.parent.mkdir(parents=True, exist_ok=True)

    @contextlib.contextmanager
    def __call__(self) -> Iterator[None]:
        import fcntl

        fd = os.open(str(self._path), os.O_CREAT | os.O_RDWR, 0o600)
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                raise ValidationError(
                    f"another process is already funding this swap (lock {self._path} is held). "
                    "Two funders would each read the same pre-push balance and each send the "
                    "shortfall, leaving twice the negotiated amount in the HTLC — whose claim "
                    "sweeps the whole balance to the counterparty. Wait for the other process."
                ) from exc
            yield
        finally:
            os.close(fd)
