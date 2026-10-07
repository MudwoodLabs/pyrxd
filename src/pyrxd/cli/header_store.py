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
  shipped table then covers). :func:`save` refuses anything else.
"""

from __future__ import annotations

import os
import secrets
from collections.abc import Mapping, Sequence
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

__all__ = ["LoadedStore", "cache_dir", "load", "save", "store_path"]


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
        return LoadedStore(
            where, None, f"the header cache is for {meta['network']}, not {network}; treated as empty", syncs, True
        )
    if not table:
        return LoadedStore(where, None, f"this pyrxd ships no checkpoints for {network}", syncs)
    try:
        chain, why = verify_header_chain(network, meta["base_height"], headers, table=table)
    except Exception as exc:  # total over file contents: anything unexpected is "untrusted"
        return LoadedStore(
            where, None, f"the header cache could not be checked ({type(exc).__name__}); treated as empty", syncs, True
        )
    if chain is None:
        return LoadedStore(where, None, f"the header cache does not verify ({why}); treated as empty", syncs, True)
    return LoadedStore(where, chain, why, syncs)


def save(
    chain: VerifiedHeaders,
    *,
    table: Sequence[tuple[int, str]],
    syncs: Sequence[Mapping[str, Any]],
    path: Path | None = None,
) -> Path:
    """Write *chain* atomically, refusing to change or drop any header the current store holds
    above *table*'s newest checkpoint. A current store that does not verify is treated as empty."""
    where = path or store_path(chain.network)
    old = load(chain.network, table, path=where).chain
    if old is not None:
        # Append-only: every height both hold must hold the same header.
        lo = max(old.base_height, chain.base_height)
        hi = min(old.top, chain.top)
        for h in range(lo, hi + 1):
            if old.header_at(h) != chain.header_at(h):
                raise ValueError(f"refusing to rewrite the cached header at {h}: the header cache is append-only")
        if chain.top < old.top:
            raise ValueError("refusing to shorten the header cache: it is append-only")
    data = encode_store(chain, syncs=syncs)
    where.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
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
