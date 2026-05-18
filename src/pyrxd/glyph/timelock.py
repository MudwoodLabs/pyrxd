"""Glyph TIMELOCK protocol — Photonic-compatible builder + state helpers.

Mirrors Photonic Wallet's ``packages/lib/src/timelock.ts`` minus the
localStorage persistence helpers (which are wallet concerns, not SDK).

The protocol:

1. **Mint** — Encrypt the sensitive payload client-side with a 32-byte CEK.
   Commit the CEK's SHA-256 hash in the mint metadata (``crypto.timelock.cek_hash``)
   alongside an ``unlock_at`` (block height or unix timestamp) and optional
   ``hint``. The mint goes on-chain; the CEK is held off-chain by the minter.

2. **Wait** — The token is freely spendable/transferable at any time; only
   the *visibility* of the encrypted payload is gated.

3. **Reveal** — After ``unlock_at`` is reached, the minter (or anyone
   holding the CEK) broadcasts a reveal transaction whose OP_RETURN
   publishes the CEK. Wallets verify ``sha256(cek) == commitment`` and
   decrypt the payload.

This module covers steps 1 and the *check* side of steps 2-3 (is the
content visible yet, how long until it is). The on-chain reveal-tx
builder + parser lives in :mod:`pyrxd.glyph.timelock_reveal_tx`.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Literal

from ..security.errors import ValidationError
from .encrypted_content import (
    CryptoMetadata,
    EncryptedContentStub,
    TimelockSpec,
)
from .types import GlyphProtocol

#: Sentinel value used in the on-chain ``cek_hash`` string format.
SHA256_PREFIX = "sha256:"


@dataclass(frozen=True)
class TimelockParams:
    """Parameters for adding a TIMELOCK to a Glyph mint.

    Matches Photonic's ``TimelockParams`` type.
    """

    mode: Literal["block", "time"]
    unlock_at: int
    hint: str = ""


@dataclass(frozen=True)
class TimelockMintResult:
    """Result of :func:`add_timelock_to_metadata`.

    - ``metadata``: the updated :class:`EncryptedContentStub` with
      ``[GlyphProtocol.TIMELOCK]`` added to ``p`` and ``crypto.timelock``
      populated. This is what gets CBOR-encoded into the mint scriptSig.
    - ``cek_for_caller_to_store``: the 32-byte CEK the caller MUST persist
      off-chain (encrypted at rest, paired with this wallet's mnemonic, etc.)
      until reveal time. Without it the reveal cannot be broadcast.
    """

    metadata: EncryptedContentStub
    cek_for_caller_to_store: bytes


# ──────────────────────────────────────────────────── core helpers ──


def compute_cek_hash(cek: bytes) -> bytes:
    """SHA-256 of the 32-byte CEK. Photonic-compatible (``computeCEKHash``)."""
    if len(cek) != 32:
        raise ValueError(f"CEK must be 32 bytes, got {len(cek)}")
    return hashlib.sha256(cek).digest()


def format_cek_hash(cek_hash_bytes: bytes) -> str:
    """Format a 32-byte hash as the on-chain ``"sha256:<hex>"`` string."""
    if len(cek_hash_bytes) != 32:
        raise ValueError(f"hash must be 32 bytes, got {len(cek_hash_bytes)}")
    return f"{SHA256_PREFIX}{cek_hash_bytes.hex()}"


def parse_cek_hash(formatted: str) -> bytes:
    """Parse the on-chain ``"sha256:<hex>"`` string back to 32 raw bytes."""
    s = formatted.strip()
    if not s.lower().startswith(SHA256_PREFIX):
        raise ValueError(f"expected sha256: prefix, got {formatted!r}")
    hex_part = s[len(SHA256_PREFIX) :]
    if len(hex_part) != 64:
        raise ValueError(f"sha256 hash must be 32 bytes (64 hex chars), got {len(hex_part)} chars")
    return bytes.fromhex(hex_part)


def verify_cek_reveal(cek: bytes, commitment: str | bytes) -> bool:
    """Return True iff ``sha256(cek)`` matches the commitment.

    Accepts the commitment either as a ``"sha256:<hex>"`` string or raw
    32-byte hash. Constant-time comparison.
    """
    if isinstance(commitment, str):
        expected = parse_cek_hash(commitment)
    else:
        expected = commitment
    actual = compute_cek_hash(cek)
    # Constant-time compare — bytes equality on equal-length input is
    # constant-time in CPython for str==str via memcmp-like dispatch, but
    # using hmac.compare_digest is the conservative spec match.
    import hmac

    return hmac.compare_digest(actual, expected)


# ──────────────────────────────────────────────────── builder ──


def add_timelock_to_metadata(
    stub: EncryptedContentStub,
    cek: bytes,
    params: TimelockParams,
) -> TimelockMintResult:
    """Add TIMELOCK fields to an existing encrypted Glyph metadata stub.

    Photonic-compatible counterpart to ``addTimelockToMetadata``. The
    input ``stub`` MUST already have ENCRYPTED in its protocol list
    (commonly built by an encrypted-NFT builder); this function appends
    TIMELOCK and populates ``crypto.timelock``.

    The ``cek`` is the same 32-byte key used to encrypt the payload.
    Its hash is committed on-chain; the key itself is returned to the
    caller for off-chain storage until reveal time.

    Validates:
      - CEK is 32 bytes
      - Stub already includes GlyphProtocol.ENCRYPTED (TIMELOCK requires it)
      - unlock_at is in the future relative to the appropriate clock
        (intentionally NOT enforced — Photonic doesn't, and pyrxd doesn't
        know "current time" without polling a chain)
    """
    if len(cek) != 32:
        raise ValueError(f"CEK must be 32 bytes, got {len(cek)}")
    if params.mode not in ("block", "time"):
        raise ValueError(f"mode must be 'block' or 'time', got {params.mode!r}")

    if GlyphProtocol.ENCRYPTED not in stub.p:
        raise ValidationError(
            f"TIMELOCK requires ENCRYPTED to be present in protocol list; "
            f"got {stub.p}. Build the encrypted stub first, then add TIMELOCK."
        )

    cek_hash_bytes = compute_cek_hash(cek)
    cek_hash_str = format_cek_hash(cek_hash_bytes)

    # Append TIMELOCK to the protocol list (idempotent — don't double-add).
    new_p = list(stub.p)
    if GlyphProtocol.TIMELOCK not in new_p:
        new_p.append(GlyphProtocol.TIMELOCK)

    # Build the timelock spec.
    timelock = TimelockSpec(
        mode=params.mode,
        unlock_at=params.unlock_at,
        cek_hash=cek_hash_str,
        hint=params.hint,
    )

    # Replace the crypto metadata's timelock field (preserving everything else).
    old_crypto = stub.crypto
    new_crypto = CryptoMetadata(
        mode=old_crypto.mode,
        key_format=old_crypto.key_format,
        # Note: the parent crypto.cek_hash and timelock.cek_hash MUST be the
        # same value — both authenticate the same CEK. Photonic enforces this
        # only by construction (both come from sha256(cek) at mint time);
        # we follow suit.
        cek_hash=old_crypto.cek_hash if old_crypto.cek_hash else cek_hash_str,
        locator=old_crypto.locator,
        locator_hash=old_crypto.locator_hash,
        recipients=list(old_crypto.recipients),
        timelock=timelock,
    )

    new_metadata = EncryptedContentStub(
        p=new_p,
        type=stub.type,
        name=stub.name,
        main=stub.main,
        crypto=new_crypto,
    )

    return TimelockMintResult(
        metadata=new_metadata,
        cek_for_caller_to_store=cek,
    )


# ──────────────────────────────────────────────────── state helpers ──


def is_unlocked(
    metadata: EncryptedContentStub,
    *,
    current_block: int | None = None,
    current_time: int | None = None,
) -> bool:
    """Return True iff the timelock has expired according to the caller's
    view of chain state.

    For ``mode="block"`` the caller must supply ``current_block`` (e.g. from
    an ElectrumXClient's tip-height query). For ``mode="time"`` the caller
    supplies ``current_time`` (a unix timestamp — typically the latest
    block's MTP for strict consensus alignment, but ``time.time()`` is
    acceptable for UI hints).

    Returns ``True`` if the token is not TIMELOCK-marked at all. Returns
    ``False`` if the required clock value wasn't supplied for the token's
    mode — i.e. the caller can't determine unlock status without it.
    """
    if GlyphProtocol.TIMELOCK not in metadata.p:
        return True
    timelock = metadata.crypto.timelock
    if timelock is None:
        # Malformed: marker present but no spec. Be conservative — locked.
        return False
    if timelock.mode == "block":
        if current_block is None:
            return False
        return current_block >= timelock.unlock_at
    if timelock.mode == "time":
        if current_time is None:
            return False
        return current_time >= timelock.unlock_at
    return False  # unknown mode → locked


def get_unlock_remaining(
    metadata: EncryptedContentStub,
    *,
    current_block: int | None = None,
    current_time: int | None = None,
) -> int:
    """Return the number of blocks (mode='block') or seconds (mode='time')
    remaining until unlock. Returns 0 if already unlocked or not TIMELOCK.

    Like :func:`is_unlocked`, requires the appropriate clock value to
    actually compute a number — returns 0 if it can't determine.
    """
    if GlyphProtocol.TIMELOCK not in metadata.p:
        return 0
    timelock = metadata.crypto.timelock
    if timelock is None:
        return 0
    if timelock.mode == "block":
        if current_block is None:
            return 0
        return max(0, timelock.unlock_at - current_block)
    if timelock.mode == "time":
        if current_time is None:
            return 0
        return max(0, timelock.unlock_at - current_time)
    return 0


__all__ = [
    "SHA256_PREFIX",
    "TimelockMintResult",
    "TimelockParams",
    "add_timelock_to_metadata",
    "compute_cek_hash",
    "format_cek_hash",
    "get_unlock_remaining",
    "is_unlocked",
    "parse_cek_hash",
    "verify_cek_reveal",
]
