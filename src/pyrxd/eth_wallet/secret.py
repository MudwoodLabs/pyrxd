"""Pure preimage recovery for the ETH HTLC leg — the cross-chain "scrape_secret" analogue.

The maker claims the ETH by calling ``claim(bytes32 preimage)``; the preimage is the
shared secret ``p`` (``sha256(p) == H``). The taker recovers ``p`` to claim the Radiant
asset. On Ethereum ``p`` appears in two places:

* the claim **calldata** — ``selector(4) || preimage(32)`` — and
* an emitted **``Claimed(bytes32 preimage)``** event log (non-indexed → in log ``data``).

THE DISCIPLINE (carried over from the BTC witness scraper, the "C-PARSER lesson"):
**match by ``sha256(candidate) == H`` over EVERY 32-byte window, never by a fixed
offset.** An attacker can pad calldata, nest the call, or plant ``p`` at an unexpected
position; matching by hash is the only safe recovery. This also means recovery works on
a **reverted-but-mined** claim tx (reverted txs are still mined and still expose
calldata) — which is why the FSM must NOT treat "recovered ``p``" as "the maker claimed"
(that gate is the authentic, successful ``Claimed`` event; see the coordinator).

This module is intentionally PURE (no web3, no network): the I/O layer fetches the
candidate byte blobs (calldata + each log's data) and hands them here. That keeps the
security-critical parser offline-fuzzable, exactly like the BTC ``scrape_secret``.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable

from pyrxd.security.errors import ValidationError

__all__ = ["iter_secret_candidates", "recover_secret"]

_PREIMAGE_LEN = 32


def iter_secret_candidates(blob: bytes) -> Iterable[bytes]:
    """Yield every 32-byte window of ``blob`` (step 1 byte).

    Step-1 (not step-32) because ``p`` may sit at any offset — after a 4-byte selector,
    inside ABI padding, or nested in a wrapper call. Over-yielding is safe: the caller
    filters by ``sha256(candidate) == H``, so only the true preimage can match.
    """
    if not isinstance(blob, (bytes, bytearray)):
        raise ValidationError("secret-candidate blob must be bytes")
    b = bytes(blob)
    for i in range(0, len(b) - _PREIMAGE_LEN + 1):
        yield b[i : i + _PREIMAGE_LEN]


def recover_secret(artifacts: Iterable[bytes], hashlock: bytes) -> bytes:
    """Recover the 32-byte preimage ``p`` such that ``sha256(p) == hashlock``.

    ``artifacts`` is an iterable of candidate byte blobs — typically the claim tx's
    calldata and the ``data`` field of each log emitted by (or to) the HTLC contract.
    Scans every 32-byte window of every blob and returns the first that hashes to
    ``hashlock``. The hashlock both verifies the preimage AND disambiguates which swap a
    blob belongs to.

    Raises :class:`ValidationError` if no window hashes to ``hashlock`` (wrong tx, a
    refund, or nothing revealed yet) — never returns a non-matching value (fail-closed).
    """
    if not isinstance(hashlock, (bytes, bytearray)) or len(hashlock) != 32:
        raise ValidationError("hashlock must be 32 bytes")
    h = bytes(hashlock)
    for blob in artifacts:
        for cand in iter_secret_candidates(blob):
            if hashlib.sha256(cand).digest() == h:
                return cand
    raise ValidationError("no candidate hashes to the hashlock (preimage not present)")
