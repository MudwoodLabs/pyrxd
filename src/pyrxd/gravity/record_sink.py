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

    def _refuse_to_clobber_a_different_swap(self, incoming: dict) -> None:
        """Refuse to overwrite a record that belongs to a DIFFERENT swap (#504 item 3).

        `os.replace` below is unconditional, and the record path derives from `--keys-out`, which
        is per-RUN rather than per-swap. So re-running with a `--keys-out` that already has a
        record silently replaced it — and the record it replaced may reference a contract that
        still holds value. It is the only durable trace of where that value went: the pending
        counter-contract address and the funded locator live nowhere else.

        Until now the only thing standing in the way was incidental — the KEYS file's `O_EXCL`.
        The runbook tells operators to delete that file after sweep, which removes the accident
        and leaves the record unprotected.

        Keyed on the HASHLOCK, not on existence, because this sink is called repeatedly through
        one swap as state advances. Refusing any existing file would break every update after the
        first, which is the shape of guard this project treats as a bug in its own right. Same
        hashlock is the normal path and must stay silent; a different one is the clobber.

        A record whose hashlock cannot be read is refused too, by `load()` — which already fails
        closed on a torn or hand-edited file, and says so in its own words. Deliberately not
        `NetworkError`: this is not transient and must not be retried.
        """
        if not self._path.exists():
            return
        prior = self.load()  # fails closed on torn / corrupt / non-object, with its own message
        if prior is None:  # pragma: no cover - exists() was true, so load() returns a dict or raises
            return
        prior_h = (prior.get("terms") or {}).get("hashlock")
        incoming_h = (incoming.get("terms") or {}).get("hashlock")
        if prior_h and incoming_h and prior_h != incoming_h:
            raise ValidationError(
                f"the swap record at {self._path} belongs to a DIFFERENT swap "
                f"(hashlock {prior_h[:16]}…, this one is {incoming_h[:16]}…). Refusing to "
                "overwrite it: it is the only durable trace of that swap's pending contract and "
                "funded locator, and the contract it references may still hold value. Settle or "
                "sweep that swap, verify the record is no longer needed, then move it aside — or "
                "use a different --keys-out for this run."
            )

    async def __call__(self, record: Any) -> None:
        as_dict = record.to_dict()
        self._refuse_to_clobber_a_different_swap(as_dict)
        payload = json.dumps(as_dict, indent=2, sort_keys=True).encode()
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
        """Read the raw record dict back, or None if it was never written.

        FAIL CLOSED on anything unreadable. This is called on a crash-restart — precisely when disk
        state is least trustworthy — so a truncated write, a corrupted file or a hand-edited one
        must raise a classified error rather than a bare `JSONDecodeError` or, worse, a partially
        populated dict that a caller mistakes for a valid record.
        """
        if not self._path.exists():
            return None
        try:
            raw = self._path.read_text()
        except OSError as exc:
            raise NetworkError(f"could not read the swap record at {self._path}: {exc}") from exc
        if not raw.strip():
            raise ValidationError(
                f"the swap record at {self._path} is EMPTY. A zero-length record is a torn write, "
                "not an absent swap — refusing to treat it as 'nothing was funded'."
            )
        try:
            loaded = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValidationError(
                f"the swap record at {self._path} is not valid JSON ({exc}). It may be a torn "
                "write. Do NOT re-run the swap from scratch: the contract it referenced may hold "
                "real value. Inspect the file by hand before doing anything else."
            ) from exc
        if not isinstance(loaded, dict):
            raise ValidationError(f"the swap record at {self._path} is a {type(loaded).__name__}, not an object")
        return loaded

    def load_record(self) -> Any:
        """Read the record back as a :class:`SwapRecord`, or None if it was never written.

        The reason this exists rather than leaving callers to do `SwapRecord.from_dict(sink.load())`
        themselves: the durable handle was WRITTEN for a whole release before anything read it back,
        so the recoverability it promised did not exist. A load path that reconstructs the real type
        — and therefore runs `__post_init__`, including the both-or-neither pending invariant — is
        what makes the write side worth anything.
        """
        from pyrxd.gravity.swap_state import SwapRecord

        raw = self.load()
        if raw is None:
            return None
        try:
            return SwapRecord.from_dict(raw)
        except ValidationError:
            raise
        except Exception as exc:
            raise ValidationError(
                f"the swap record at {self._path} could not be decoded into a SwapRecord: {exc}. "
                "Inspect it by hand — the contract it references may hold real value."
            ) from exc


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

    **WHAT THE KEY ACTUALLY IS.** The lock file is ``<the path you pass> + ".fundlock"``, and
    nothing more. It is not keyed by the hashlock, and it is not keyed by the funding key either.

    This paragraph used to say the path came from "the caller's key path, so two swaps sharing a
    funding key share a lock — conservative (over-exclusion) rather than unsafe". That was false in
    the direction that matters. Both runners construct it from ``args.keys_out``, which is
    PER-RUN, so two concurrent swaps on ONE funding key with different ``--keys-out`` get two
    different lock files and **exclude nothing**. Measured, not reasoned: same path, the second
    acquisition is refused; different paths, both acquire.

    So the over-exclusion the old wording offered as reassurance does not exist, and the case it
    described as covered is the case that is not. A lock whose documented scope is wider than its
    real scope is worse than no lock: the next person reasons from the sentence.

    The exclusion this DOES give you is exact and worth stating positively: **two processes that
    pass the same path are excluded.** Anything else — a different path, another host, a copied
    directory — is not, and cannot be detected here.

    ``tests/test_fund_lock_scope_is_the_path.py`` pins both halves, and pins the two construction
    sites, so keying this by ``H`` (see #504 item 3) fails that test and forces this paragraph to
    be re-read rather than silently inherited.
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
