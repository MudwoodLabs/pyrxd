"""Preimage recovery for the ETH leg (`eth_wallet/secret.py`) — the taker's only route to ``p``.

The module is pure and offline, and until this file its only test was the anvil integration suite,
which every mutation run excludes (`-m 'not integration'`). The 2026-09-29 `ethleg` run showed the
window arithmetic running under no unit test: a scan that starts at offset 1, or stops one window
early, still "works" on every blob whose preimage sits in the middle — and silently fails the one
whose preimage sits at the edge. A taker that cannot recover ``p`` cannot claim the RXD it is owed.
"""

from __future__ import annotations

import hashlib
import os

import pytest

from pyrxd.eth_wallet.secret import iter_secret_candidates, recover_secret
from pyrxd.security.errors import ValidationError

_SELECTOR = bytes.fromhex("bd66528a")  # any 4 bytes: recovery must not depend on the selector


def _secret() -> tuple[bytes, bytes]:
    p = os.urandom(32)
    return p, hashlib.sha256(p).digest()


@pytest.mark.parametrize("length", [32, 33, 36, 64, 67])
def test_every_32_byte_window_is_yielded_exactly_once_in_order(length):
    blob = bytes(range(length))
    windows = list(iter_secret_candidates(blob))
    assert windows == [blob[i : i + 32] for i in range(length - 31)]
    assert all(len(w) == 32 for w in windows)


@pytest.mark.parametrize("length", [0, 1, 31])
def test_a_blob_shorter_than_a_preimage_yields_nothing(length):
    assert list(iter_secret_candidates(bytes(length))) == []


def test_a_bytearray_blob_is_accepted_and_a_str_is_refused():
    assert list(iter_secret_candidates(bytearray(32))) == [bytes(32)]
    with pytest.raises(ValidationError, match="must be bytes"):
        list(iter_secret_candidates("00" * 32))  # type: ignore[arg-type]


def test_recovers_a_preimage_that_is_the_whole_blob():
    p, h = _secret()
    assert recover_secret([p], h) == p


@pytest.mark.parametrize("pad", [1, 3, 4, 5])
def test_recovers_a_preimage_in_the_LAST_window(pad):
    # Claim calldata is selector || p: p is the final window. Odd and even pads both, because a
    # window count that is right for one parity and wrong for the other is a real bug shape.
    p, h = _secret()
    assert recover_secret([os.urandom(pad) + p], h) == p


def test_recovers_from_a_later_artifact_after_non_matching_ones():
    # The claim tx calldata may be a wrapper call that does not contain p; the Claimed log does.
    p, h = _secret()
    other, _ = _secret()
    assert recover_secret([b"", _SELECTOR + other, b"\x00" * 64 + p + b"\x00" * 28], h) == p


def test_no_matching_window_fails_closed():
    p, h = _secret()
    with pytest.raises(ValidationError, match="no candidate"):
        # A truncated preimage is the near miss: 31 of its 32 bytes are present.
        recover_secret([_SELECTOR + bytes(64), p[:31], p[1:]], h)


@pytest.mark.parametrize("bad", [bytes(31), bytes(33), b""])
def test_a_hashlock_of_the_wrong_length_is_refused_up_front(bad):
    p, _ = _secret()
    with pytest.raises(ValidationError, match="hashlock must be 32 bytes"):
        recover_secret([p], bad)


def test_a_hex_string_hashlock_is_refused_even_at_32_characters():
    # 32 CHARACTERS is 16 bytes of hash: a str is never a hashlock, whatever its length.
    p, _ = _secret()
    with pytest.raises(ValidationError, match="hashlock must be 32 bytes"):
        recover_secret([p], "ab" * 16)  # type: ignore[arg-type]
