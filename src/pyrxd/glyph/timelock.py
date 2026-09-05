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

This module covers step 1 and the *check* side of steps 2-3 (is the
content visible yet, how long until it is). The on-chain reveal-tx
builder + parser lives in :mod:`pyrxd.glyph.timelock_reveal_tx`.

:func:`build_timelock_mint` is the one-shot entry point for step 1: it encrypts,
wraps the key to any immediate recipients, and returns the metadata to mint
alongside the CEK to keep. ``GlyphClient.mint_timelocked_nft`` and
``pyrxd glyph timelock-mint`` are its production callers.
"""

from __future__ import annotations

import hashlib
import secrets
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Literal

from ..crypto.aead import ChunkedCiphertext, encrypt_chunked
from ..crypto.kem import wrap_cek_x25519
from ..security.errors import ValidationError
from .encrypted_content import (
    WRAP_ALG_X25519,
    CryptoMetadata,
    CryptoRecipient,
    EncryptedContentStub,
    EncryptionMetadata,
    TimelockSpec,
)
from .types import GlyphMetadata, GlyphProtocol

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

    ``cek_for_caller_to_store`` is ``repr=False`` because the CEK is a PRE-reveal
    secret: the chain carries only ``sha256(cek)``, and the whole point of the
    protocol is that the payload cannot be decrypted until the reveal publishes
    the key. A default dataclass ``repr`` put it verbatim into every ``print``,
    f-string, ``%s``, ``logging`` call and exception message that touched this
    object, and the printed form is valid Python for the key itself — a log line
    was a working decryption key. Same reason and same shape as
    ``FeeInput.wif`` (``gravity/htlc_spend.py``) and ``HdWallet._seed``.
    ``tests/security/test_key_material_never_echoed.py`` pins it.
    """

    metadata: EncryptedContentStub
    cek_for_caller_to_store: bytes = field(repr=False)


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


# ────────────────────────────────────────── one-shot mint builder ──


@dataclass(frozen=True)
class TimelockRecipient:
    """One party who may open the content WITHOUT waiting for the reveal.

    The CEK is wrapped to ``public_key`` (X25519) and the wrap goes on chain in
    ``crypto.recipients``, so the holder of the matching private key decrypts as soon as
    the token is minted. The timelock gates *everyone else*: the reveal transaction is
    what publishes the CEK to the public.

    ``kid`` is a free-form label for the wrap ("auctioneer-key-1"). It is operator text,
    carried verbatim on chain, and authenticates nothing.
    """

    kid: str
    public_key: bytes  # 32-byte X25519 public key (see pyrxd.x25519_public_key)


@dataclass(frozen=True)
class TimelockMintBuild:
    """Everything :func:`build_timelock_mint` produced, and what to do with each part.

    - ``metadata`` — hand this to ``GlyphClient.mint_nft`` / ``mint_timelocked_nft``. It is
      the :class:`~pyrxd.glyph.types.GlyphMetadata` view of ``stub``, built from it rather
      than beside it so the two cannot drift.
    - ``stub`` — the same envelope in Photonic's own shape. ``metadata.to_cbor_dict()`` and
      ``stub.to_dict()`` are equal dicts; the stub is the form to compare against Photonic
      vectors.
    - ``ciphertext`` — the encrypted payload. **It does not go on chain**: only its
      plaintext hash, size and chunk count do (``main``). Publish or store these bytes
      yourself, or nobody can decrypt anything after the reveal.
    - ``cek`` — the 32-byte key. Persist it off chain, encrypted at rest. Losing it loses
      the reveal; leaking it reveals the content early, and neither is repairable.
    - ``cek_hash`` — the ``"sha256:<hex>"`` commitment that went on chain. This is what a
      reveal is checked against.

    ``cek`` is ``repr=False`` for the reason :class:`TimelockMintResult` documents at
    length: a default dataclass ``repr`` puts the key verbatim into every ``print``,
    f-string and log line that touches the object, and the printed form is a working
    decryption key.
    """

    metadata: GlyphMetadata
    stub: EncryptedContentStub
    ciphertext: ChunkedCiphertext
    cek_hash: str
    cek: bytes = field(repr=False)


def glyph_metadata_for(stub: EncryptedContentStub) -> GlyphMetadata:
    """The :class:`~pyrxd.glyph.types.GlyphMetadata` that CBOR-encodes to ``stub.to_dict()``.

    The mint path takes ``GlyphMetadata`` and nothing else — ``GlyphMinter._require_protocol``
    rejects any other type — so an :class:`EncryptedContentStub` cannot be minted until it
    is carried across. The two fields that do the carrying (``encrypted_main`` and
    ``crypto``) exist for this, and the equality of the two dicts is pinned by
    ``tests/test_glyph_timelock_write_side_is_reachable.py``.

    ``timelock`` is set as well as ``crypto.timelock``. They are the same object: ``crypto``
    is the field the encoder writes, ``timelock`` is the field the decoder fills, and a
    metadata object that came from a build should answer both spellings the way one that
    came off a chain does.
    """
    return GlyphMetadata(
        protocol=list(stub.p),
        name=stub.name,
        token_type=stub.type,
        encrypted_main=stub.main,
        crypto=stub.crypto,
        timelock=stub.crypto.timelock,
    )


def build_timelock_mint(
    *,
    name: str,
    content_type: str,
    plaintext: bytes,
    params: TimelockParams,
    cek: bytes | None = None,
    recipients: Sequence[TimelockRecipient] = (),
    locator: str | None = None,
) -> TimelockMintBuild:
    """Encrypt ``plaintext`` and build the mint envelope that commits to its key.

    This is the function :class:`~pyrxd.glyph.encrypted_content.EncryptedContentStub`'s
    docstring has always told callers to construct through. It did not exist; the docstring
    named it anyway, and the invariants it promised — ``main.hash`` is the hash of the
    plaintext, ``crypto.cek_hash`` and ``crypto.timelock.cek_hash`` are both the hash of the
    key that encrypted it — were left to whoever assembled the stub by hand.

    They are the invariants that matter. ``main.hash`` is the AAD prefix
    :func:`~pyrxd.crypto.aead.decrypt_chunked` authenticates every chunk against, so a stub
    whose ``main.hash`` is not ``sha256(plaintext)`` yields a token that cannot be decrypted
    even with the right key. ``crypto.timelock.cek_hash`` is the only thing a published CEK
    is ever checked against. A mint is not repairable, so neither mistake has a second
    chance — which is why they are enforced by construction here rather than documented.

    Steps, all Photonic-compatible:

    1. encrypt with ``chunked-aead-v1`` (:func:`~pyrxd.crypto.aead.encrypt_chunked`)
    2. wrap the CEK to each recipient over X25519, with the CEK-hash commitment as AAD
       (REP-3006 — :func:`~pyrxd.crypto.kem.wrap_cek_x25519`)
    3. assemble the ``[NFT, ENCRYPTED]`` stub
    4. add the timelock through :func:`add_timelock_to_metadata`, which appends TIMELOCK and
       writes the commitment

    Args:
        name: the token's display name.
        content_type: MIME type of the **plaintext**. Recorded twice on chain, as the
            envelope's ``type`` and as ``main.type``, matching Photonic.
        plaintext: the bytes being sealed. The ciphertext is returned to the caller and
            does NOT go on chain.
        params: mode (``"block"`` / ``"time"``), ``unlock_at``, optional ``hint``.
        cek: the 32-byte content-encryption key. **Generated with
            :func:`secrets.token_bytes` when omitted, which is the right default** — a
            caller supplying one is usually reusing a key, and a reused CEK means revealing
            one token reveals every other token sealed with it.
        recipients: parties who may decrypt immediately, without the reveal. Empty means
            the reveal transaction is the only way in.
        locator: optional off-chain pointer to the ciphertext (a URL, an IPFS URI). Recorded
            as ``crypto.locator``; nothing verifies it.

    Returns:
        :class:`TimelockMintBuild` — the metadata to mint, the ciphertext to publish, and
        the CEK to keep.

    Raises:
        ValueError: ``cek`` is not 32 bytes, or a recipient key is not a 32-byte X25519
            public key.
        ~pyrxd.security.errors.ValidationError: ``name`` or ``content_type`` is empty.
    """
    if not name:
        raise ValidationError("build_timelock_mint requires a name — it is the token's only label on chain")
    if not content_type:
        raise ValidationError(
            "build_timelock_mint requires a content_type (MIME type of the plaintext); "
            "use 'application/octet-stream' if nothing more specific applies"
        )
    if cek is None:
        cek = secrets.token_bytes(32)
    elif len(cek) != 32:
        raise ValueError(f"CEK must be 32 bytes, got {len(cek)}")

    ciphertext = encrypt_chunked(plaintext, cek)
    commitment_bytes = compute_cek_hash(cek)
    cek_hash_str = format_cek_hash(commitment_bytes)

    wraps: list[CryptoRecipient] = []
    for r in recipients:
        # The commitment is the AAD, per REP-3006 and Photonic's `encryption.ts`. Binding the
        # wrap to it means a wrap lifted off one token cannot be replayed onto another whose
        # commitment differs — unwrapping fails the tag check rather than returning a key for
        # the wrong content.
        wrapped = wrap_cek_x25519(cek, r.public_key, commitment_bytes)
        wraps.append(
            CryptoRecipient(
                kid=r.kid,
                alg=WRAP_ALG_X25519,
                wrapped_cek=wrapped.wrapped_cek,
                epk=wrapped.ephemeral_pubkey,
            )
        )

    stub = EncryptedContentStub(
        p=[GlyphProtocol.NFT, GlyphProtocol.ENCRYPTED],
        type=content_type,
        name=name,
        main=EncryptionMetadata(
            type=content_type,
            hash=format_cek_hash(ciphertext.plaintext_hash),
            size=len(plaintext),
            chunks=len(ciphertext.chunks),
            # ``scheme`` is left at its default rather than passed: it IS
            # ``SCHEME_CHUNKED_AEAD_V1``, and passing the module constant widens the field's
            # ``Literal`` back to ``str``. Nothing here chooses a scheme — `encrypt_chunked`
            # implements exactly one — so naming it would be a knob that does not turn.
        ),
        crypto=CryptoMetadata(
            cek_hash=cek_hash_str,
            locator=locator,
            recipients=wraps,
        ),
    )

    sealed = add_timelock_to_metadata(stub, cek, params)
    return TimelockMintBuild(
        metadata=glyph_metadata_for(sealed.metadata),
        stub=sealed.metadata,
        ciphertext=ciphertext,
        cek_hash=cek_hash_str,
        cek=sealed.cek_for_caller_to_store,
    )


# ──────────────────────────────────────────────────── state helpers ──


def _protocols_and_spec(metadata: object) -> tuple[tuple[int, ...], TimelockSpec | None]:
    """The protocol markers and the timelock spec, from EITHER metadata shape.

    Two objects in this SDK describe the same on-chain envelope and spell these two things
    differently: :class:`EncryptedContentStub` (Photonic's shape, what a mint is built as)
    carries ``.p`` and ``.crypto.timelock``, while
    :class:`~pyrxd.glyph.types.GlyphMetadata` (what :func:`pyrxd.glyph.payload.decode_payload`
    returns for a token read off the chain) carries ``.protocol`` and ``.timelock``.

    Reading only the first spelling made the holder-facing question unanswerable from the
    holder-facing object: ``is_unlocked(decode_payload(bytes))`` raised ``AttributeError``,
    and the read-side test had to hand-roll an adapter class to ask it. Refusing the shape
    the parse path actually produces is not a safe default — it is the guard refusing honest
    work, on the one input it exists to serve.

    Raises:
        TypeError: the object carries neither spelling of a protocol list. Deliberately NOT
            a shrug returning ``()``: an empty protocol list reads as "not timelocked at
            all", which is the optimistic answer, and the optimistic answer is the one that
            costs something here.
    """
    protocols = getattr(metadata, "p", None)
    if protocols is None:
        protocols = getattr(metadata, "protocol", None)
    if protocols is None:
        raise TypeError(
            f"expected Glyph metadata carrying a protocol list — GlyphMetadata.protocol or "
            f"EncryptedContentStub.p — got {type(metadata).__name__}"
        )
    crypto = getattr(metadata, "crypto", None)
    spec = getattr(crypto, "timelock", None)
    if spec is None:
        spec = getattr(metadata, "timelock", None)
    return tuple(protocols), spec


def is_unlocked(
    metadata: EncryptedContentStub | GlyphMetadata,
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

    Accepts either metadata shape — see :func:`_protocols_and_spec`.

    Returns ``True`` if the token is not TIMELOCK-marked at all. Returns
    ``False`` if the required clock value wasn't supplied for the token's
    mode — i.e. the caller can't determine unlock status without it.
    """
    protocols, timelock = _protocols_and_spec(metadata)
    if GlyphProtocol.TIMELOCK not in protocols:
        return True
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
    metadata: EncryptedContentStub | GlyphMetadata,
    *,
    current_block: int | None = None,
    current_time: int | None = None,
) -> int:
    """Return the number of blocks (mode='block') or seconds (mode='time')
    remaining until unlock. Returns 0 if already unlocked or not TIMELOCK.

    Like :func:`is_unlocked`, requires the appropriate clock value to
    actually compute a number — returns 0 if it can't determine, and accepts
    either metadata shape.
    """
    protocols, timelock = _protocols_and_spec(metadata)
    if GlyphProtocol.TIMELOCK not in protocols:
        return 0
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
    "TimelockMintBuild",
    "TimelockMintResult",
    "TimelockParams",
    "TimelockRecipient",
    "add_timelock_to_metadata",
    "build_timelock_mint",
    "compute_cek_hash",
    "format_cek_hash",
    "get_unlock_remaining",
    "glyph_metadata_for",
    "is_unlocked",
    "parse_cek_hash",
    "verify_cek_reveal",
]
