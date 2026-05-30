"""Tests for the durable (SQLite) H-freshness SeenStore (Tier-1 R5)."""

from __future__ import annotations

import os

import pytest

from pyrxd.gravity.seen_store import DurableSeenStore
from pyrxd.security.errors import ValidationError


def _h(b: int) -> bytes:
    return bytes([b]) * 32


def test_reserve_test_and_set(tmp_path):
    store = DurableSeenStore(tmp_path / "seen.db")
    assert store.durable is True
    assert store.reserve(_h(1)) is True  # fresh
    assert store.reserve(_h(1)) is False  # already reserved
    assert store.has_seen(_h(1)) is True
    assert store.reserve(_h(2)) is True  # distinct H
    store.close()


def test_durability_survives_reopen(tmp_path):
    path = tmp_path / "seen.db"
    s1 = DurableSeenStore(path)
    assert s1.reserve(_h(7)) is True
    s1.close()
    # a fresh store / "second process" on the same file still sees the reservation
    s2 = DurableSeenStore(path)
    assert s2.has_seen(_h(7)) is True
    assert s2.reserve(_h(7)) is False  # NOT re-reservable → replay window stays closed
    assert s2.reserve(_h(8)) is True
    s2.close()


def test_bad_hashlock_rejected(tmp_path):
    store = DurableSeenStore(tmp_path / "seen.db")
    for bad in (b"\x00" * 31, "not-bytes", 123):
        with pytest.raises(ValidationError):
            store.reserve(bad)  # type: ignore[arg-type]
    store.close()


def test_db_file_mode_is_0600(tmp_path):
    path = tmp_path / "seen.db"
    DurableSeenStore(path).close()
    assert (os.stat(path).st_mode & 0o777) == 0o600
