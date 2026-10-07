"""The CLI's verified-header store: ``~/.pyrxd/headers/<network>.bin`` (#826).

The bytes are :func:`pyrxd.glyph.header_cache.encode_store`'s; this module only reads and writes
them. Three rules:

* **Read = re-verify.** Every load re-checks the whole chain against the checkpoint table this
  pyrxd ships (:func:`~pyrxd.glyph.header_cache.verify_header_chain`). A missing, unreadable,
  damaged or non-verifying store is treated as EMPTY, with the reason — never as trusted.
* **Atomic writes.** A new store is written to a temporary file in the same directory, flushed to
  disk, and moved over the old one with :func:`os.replace`, so a reader sees the old store or the
  new one, never a mixture.
* **Append-only.** A write never changes a header the current store holds: it may only add headers
  above its top, or rebase onto a newer shipped checkpoint (dropping headers below it, which the
  shipped table then covers). :func:`save` refuses anything else, except a ``--reset`` rebuild that
  finished without a stop and either disagrees with the store or reaches past its top: a reset never
  only shortens a good cache, and a stopped or refused reset never reaches :func:`save` at all.
  The check and the replace run under one advisory lock (POSIX).
"""

from __future__ import annotations

import os
import secrets
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..glyph.header_cache import (
    HeaderStoreCorrupt,
    VerifiedHeaders,
    decode_store,
    encode_store,
    verify_header_chain,
)

__all__ = [
    "AppendOnlyRefusal",
    "LoadedStore",
    "ResetKeptExisting",
    "cache_dir",
    "load",
    "lock_path",
    "save",
    "store_path",
]


def cache_dir() -> Path:
    """Where the stores live: ``~/.pyrxd/headers`` (beside the config and the wallet). Tests
    point this somewhere else."""
    return Path.home() / ".pyrxd" / "headers"


def store_path(network: str) -> Path:
    if not isinstance(network, str) or not network.isidentifier():
        raise ValueError(f"not a network name: {network!r}")
    return cache_dir() / f"{network}.bin"


@dataclass(frozen=True)
class LoadedStore:
    """A store as read: the verified chain (``None`` when empty or untrusted) and why."""

    path: Path
    chain: VerifiedHeaders | None
    #: Why ``chain`` is ``None`` or shorter than the file: missing, unreadable, damaged, does not
    #: verify, older than the shipped table, or ends at a header below the floor.
    note: str | None
    #: The sync records kept in the file (provenance only).
    syncs: tuple[Mapping[str, Any], ...] = field(default=())
    #: True when the file existed but could not be trusted at all.
    untrusted: bool = False
    #: True when the store is intact but ends below this pyrxd's newest checkpoint (an upgrade moved
    #: the checkpoint past it): not trusted for anything, not damaged either; the next sync rebuilds it.
    stale: bool = False


def load(network: str, table: Sequence[tuple[int, str]], *, path: Path | None = None) -> LoadedStore:
    """The store for *network*, re-verified against *table*. Never raises for anything in the file."""
    where = path or store_path(network)
    try:
        data = where.read_bytes()
    except FileNotFoundError:
        return LoadedStore(where, None, "no header cache yet (run `pyrxd headers sync`)")
    except OSError as exc:
        return LoadedStore(
            where, None, f"the header cache could not be read ({type(exc).__name__}); treated as empty", untrusted=True
        )
    try:
        meta, headers = decode_store(data)
    except HeaderStoreCorrupt as exc:
        return LoadedStore(where, None, f"the header cache is damaged ({exc}); treated as empty", untrusted=True)
    syncs = tuple(s for s in meta["syncs"] if isinstance(s, dict))
    if meta["network"] != network:
        from ..glyph._inspect_core import _sanitize_display_string  # the name is text from a file

        theirs = _sanitize_display_string(str(meta["network"]))
        return LoadedStore(
            where, None, f"the header cache is for {theirs}, not {network}; treated as empty", syncs, True
        )
    if not table:
        return LoadedStore(where, None, f"this pyrxd ships no checkpoints for {network}", syncs)
    top, newest = meta["base_height"] + len(headers) - 1, table[-1][0]
    if headers and top < newest:
        return LoadedStore(
            where,
            None,
            f"the header cache ends at block {top}, behind this pyrxd's newest checkpoint ({newest}), so it is "
            f"stale and was not checked further; the next `pyrxd headers sync` rebuilds it from that checkpoint",
            syncs,
            stale=True,
        )
    try:
        chain, why = verify_header_chain(network, meta["base_height"], headers, table=table)
    except Exception as exc:  # total over file contents: anything unexpected is "untrusted"
        return LoadedStore(
            where, None, f"the header cache could not be checked ({type(exc).__name__}); treated as empty", syncs, True
        )
    if chain is None:
        return LoadedStore(where, None, f"the header cache does not verify ({why}); treated as empty", syncs, True)
    return LoadedStore(where, chain, why, syncs)


def lock_path(where: Path) -> Path:
    """The advisory lock file beside a store."""
    return where.with_name(f"{where.name}.lock")


@contextmanager
def _locked(where: Path) -> Iterator[None]:
    """An exclusive advisory lock (``fcntl.flock``) on the store's lock file, held for the block.

    POSIX only. On Windows ``fcntl`` does not exist and no lock is taken: two syncs run at the same
    moment there can still race, and the later one may shorten the store (the store stays a
    verified chain either way; the next sync extends it again)."""
    try:
        import fcntl
    except ImportError:  # Windows
        yield
        return
    fd = os.open(lock_path(where), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


class AppendOnlyRefusal(ValueError):
    """A write that would change or drop headers the current store holds. The store is unchanged."""


class ResetKeptExisting(Exception):
    """A ``--reset`` rebuild that agrees with the current store and does not reach past its top:
    replacing would only shorten a good cache, so the store is kept unchanged."""


def save(
    chain: VerifiedHeaders,
    *,
    table: Sequence[tuple[int, str]],
    record: Mapping[str, Any] | None = None,
    path: Path | None = None,
    reset: bool = False,
) -> Path:
    """Write *chain* atomically under the store's lock; *record* is appended to the sync records
    read from the file under that same lock, so a concurrent sync's record is never lost.

    Without *reset*: :class:`AppendOnlyRefusal` if *chain* would change or drop a header the current
    store holds above *table*'s newest checkpoint (a store that does not verify counts as empty).

    With *reset* (``pyrxd headers sync --reset``, and only that, after a rebuild that finished
    without a stop): the store is replaced, unless *chain* agrees with it at every height both hold
    and ends below its top, which raises :class:`ResetKeptExisting` and keeps it.
    """
    where = path or store_path(chain.network)
    where.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    # Read, check and replace under ONE lock, so two concurrent syncs cannot both pass the
    # append-only check against the same old store and the second shorten what the first wrote.
    with _locked(where):
        current = load(chain.network, table, path=where)
        old = current.chain
        if old is not None:
            lo, hi = max(old.base_height, chain.base_height), min(old.top, chain.top)
            differs = next((h for h in range(lo, hi + 1) if old.header_at(h) != chain.header_at(h)), None)
            if reset:
                if differs is None and chain.top < old.top:
                    raise ResetKeptExisting(
                        f"the rebuild agrees with the existing cache and ends at block {chain.top}, below its top "
                        f"({old.top}); the existing cache was kept"
                    )
            elif differs is not None:
                raise AppendOnlyRefusal(
                    f"the cache on disk holds a different header at block {differs} than this sync built on"
                )
            elif chain.top < old.top:
                raise AppendOnlyRefusal(
                    f"the cache on disk already reaches block {old.top}, past this sync's {chain.top}"
                )
        syncs = [*current.syncs, *([record] if record is not None else [])]
        data = encode_store(chain, syncs=syncs)
        tmp = where.with_name(f".{where.name}.{os.getpid()}.{secrets.token_hex(4)}.tmp")
        try:
            with open(tmp, "wb") as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, where)
        finally:
            if tmp.exists():
                tmp.unlink()
    try:
        dir_fd = os.open(where.parent, os.O_RDONLY)
    except OSError:
        return where
    try:
        os.fsync(dir_fd)
    except OSError:
        pass
    finally:
        os.close(dir_fd)
    return where
