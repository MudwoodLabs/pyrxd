"""X25519 + HKDF-SHA256 KEM and CEK wrapping (Photonic-compatible).

Mirrors Photonic Wallet's ``packages/lib/src/encryption.ts`` for the
single-recipient X25519 path. Post-quantum ML-KEM-768 hybrid is
explicitly out of scope for pyrxd TIMELOCK v1 — single-recipient X25519
is sufficient for the canonical Glyph TIMELOCK use cases (sealed bids,
time-released disclosures) and avoids pulling in PQ deps.

The wrap protocol:

1. Sender picks an ephemeral X25519 keypair (k, k·G)
2. Sender computes the ECDH shared secret ``ss = k · recipient_pubkey``
3. Sender derives a KEK via HKDF-SHA256:
   ``kek = HKDF(ss, salt=None, info=b"glyph-kek-classical-v1", length=32)``
   — the info string is MODE-BOUND upstream (classical vs hybrid), see
   :data:`KEK_DERIVATION_INFO`. pyrxd emitted ``b"glyph-kek-v1"`` from v0.6.0
   through 0.24.0, which no longer interoperates; see
   :data:`LEGACY_KEK_DERIVATION_INFO` for how that content is still read.
4. Sender encrypts the 32-byte CEK with XChaCha20-Poly1305 under ``kek``
   with a random 24-byte nonce, binding a caller-supplied AAD. For a Glyph
   recipient slot that is the UTF-8 text of ``crypto.cek_hash``
   (``"sha256:<hex>"``), which is what Photonic's app binds — see
   ``pyrxd.glyph.timelock.cek_wrap_aad``. This module does not choose it.
5. Wire format: ``wrapped_cek = nonce(24) || ciphertext(32) || tag(16)`` = 72 bytes
6. Sender publishes ``(wrapped_cek, ephemeral_pubkey)``; recipient computes
   the same shared secret via ECDH and unwraps

Library choice (per the planning triage, see
``docs/phase-4-scoping.md`` in the pyrxd-eth-htlc consumer):

- **X25519 ECDH:** ``cryptography.hazmat.primitives.asymmetric.x25519``
  (returns raw 32-byte shared secret matching @noble/curves)
- **HKDF-SHA256:** ``cryptography.hazmat.primitives.kdf.hkdf.HKDF``
- **AEAD:** :mod:`pyrxd.crypto.aead` (XChaCha20-Poly1305 via PyCryptodome,
  byte-equivalent to @noble/ciphers)
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .aead import (
    XCHACHA20_KEY_SIZE,
    XCHACHA20_NONCE_SIZE,
    decrypt_xchacha20_poly1305,
    encrypt_xchacha20_poly1305,
)

#: X25519 keys are 32 bytes (both scalar and compressed-pubkey).
X25519_KEY_SIZE = 32

#: HKDF info for the KEK derivation, on the classical (X25519-only) path.
#:
#: MODE-BOUND, AND THAT IS THE POINT. Photonic derives this from whether the wrap is hybrid
#: (X25519 + ML-KEM-768) or classical, so the two modes produce different KEKs and an attacker
#: who strips the ML-KEM ciphertext cannot still decrypt — their own comment calls it
#: "SECURITY FIX (C8) ... prevents downgrade attacks" (``packages/lib/src/encryption.ts``
#: wrapCEK/unwrapCEK at Radiant-Core/Photonic-Wallet ``becf41a7``). pyrxd implements only the
#: classical path, so this is the only info string it may emit.
KEK_DERIVATION_INFO = b"glyph-kek-classical-v1"

#: The pre-split spelling, accepted on UNWRAP ONLY and never emitted.
#:
#: pyrxd shipped ``b"glyph-kek-v1"`` from v0.6.0 (#106) through 0.24.0. It is the spelling
#: Photonic used BEFORE ``8e6bb6e`` (2026-05-16), which split classical from hybrid two days
#: before this module was first committed (2026-05-18) — so it was already stale when written,
#: and pyrxd never matched the upstream code of its own day on this path. Every CEK pyrxd
#: wrapped in that window is recoverable only with this
#: value, and dropping it would strand content pyrxd itself encrypted. It is tried only after
#: the current derivation fails its AEAD tag, and :func:`unwrap_cek_x25519` reports which one
#: succeeded rather than hiding it, because "this ciphertext is legacy" is a fact the caller
#: may need to act on (re-wrap it) and must never learn by accident.
LEGACY_KEK_DERIVATION_INFO = b"glyph-kek-v1"

#: Wire layout: nonce(24) || ciphertext(32) || tag(16) = 72 bytes total.
WRAPPED_CEK_SIZE = XCHACHA20_NONCE_SIZE + XCHACHA20_KEY_SIZE + 16


# ─────────────────────────────────────────────────────── HKDF + ECDH ──


def hkdf_sha256(ikm: bytes, salt: bytes | None, info: bytes, length: int) -> bytes:
    """HKDF-SHA256. Mirrors @noble/hashes' ``hkdf(sha256, ikm, salt, info, length)``.

    ``salt=None`` means "use the empty string as salt" per RFC 5869 §2.2 —
    matching @noble/hashes behavior.
    """
    if length < 1 or length > 255 * 32:
        raise ValueError(f"HKDF output length out of range: {length}")
    kdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,  # None and b"" are equivalent per RFC 5869
        info=info,
    )
    return kdf.derive(ikm)


def x25519_public_key(privkey: bytes) -> bytes:
    """Derive the 32-byte X25519 public key from a 32-byte private scalar.

    Matches @noble/curves' ``x25519.getPublicKey(privkey)`` byte-for-byte.
    """
    if len(privkey) != X25519_KEY_SIZE:
        raise ValueError(f"privkey must be {X25519_KEY_SIZE} bytes, got {len(privkey)}")
    sk = X25519PrivateKey.from_private_bytes(privkey)
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        PublicFormat,
    )

    return sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def x25519_ecdh(privkey: bytes, peer_pubkey: bytes) -> bytes:
    """Compute X25519 ECDH shared secret.

    Returns the raw 32-byte shared secret, matching @noble/curves'
    ``x25519.getSharedSecret(sk, pk)``.
    """
    if len(privkey) != X25519_KEY_SIZE:
        raise ValueError(f"privkey must be {X25519_KEY_SIZE} bytes, got {len(privkey)}")
    if len(peer_pubkey) != X25519_KEY_SIZE:
        raise ValueError(f"peer_pubkey must be {X25519_KEY_SIZE} bytes, got {len(peer_pubkey)}")
    sk = X25519PrivateKey.from_private_bytes(privkey)
    pk = X25519PublicKey.from_public_bytes(peer_pubkey)
    return sk.exchange(pk)


# ─────────────────────────────────────────────────────── KEM ──


@dataclass(frozen=True)
class WrappedCEK:
    """A CEK wrapped to one recipient via X25519 ECDH + HKDF + XChaCha20-Poly1305.

    Matches Photonic's ``EncapsulatedSecret`` shape for the non-PQ path
    plus the AEAD-encrypted CEK ciphertext.

    - ``wrapped_cek``: 72 bytes = nonce(24) || ciphertext(32) || tag(16)
    - ``ephemeral_pubkey``: 32-byte X25519 ephemeral pubkey
    """

    wrapped_cek: bytes
    ephemeral_pubkey: bytes


def wrap_cek_x25519(
    cek: bytes,
    recipient_pubkey: bytes,
    aad: bytes = b"",
) -> WrappedCEK:
    """Wrap a 32-byte CEK for an X25519 recipient.

    Generates a fresh ephemeral keypair and a random 24-byte nonce internally;
    output is non-deterministic. Recipient unwraps via :func:`unwrap_cek_x25519`
    using their X25519 private key.

    ``aad`` is bound to the AEAD wrap — passing different ``aad`` to unwrap
    fails decryption. For a Glyph recipient slot, Photonic's app binds the
    UTF-8 bytes of the on-chain ``crypto.cek_hash`` STRING (``"sha256:<hex>"``,
    71 bytes), not the 32-byte digest; build it with
    ``pyrxd.glyph.timelock.cek_wrap_aad``. No REP fixes this value — REP-3006
    defines AAD only for the content AEAD — so the wallet is the reference.
    """
    if len(cek) != XCHACHA20_KEY_SIZE:
        raise ValueError(f"cek must be {XCHACHA20_KEY_SIZE} bytes, got {len(cek)}")
    if len(recipient_pubkey) != X25519_KEY_SIZE:
        raise ValueError(f"recipient_pubkey must be {X25519_KEY_SIZE} bytes, got {len(recipient_pubkey)}")

    ephemeral_priv = secrets.token_bytes(X25519_KEY_SIZE)
    ephemeral_pub = x25519_public_key(ephemeral_priv)
    shared = x25519_ecdh(ephemeral_priv, recipient_pubkey)
    kek = hkdf_sha256(shared, salt=None, info=KEK_DERIVATION_INFO, length=XCHACHA20_KEY_SIZE)

    nonce = secrets.token_bytes(XCHACHA20_NONCE_SIZE)
    ciphertext_with_tag = encrypt_xchacha20_poly1305(cek, kek, nonce, aad)

    wrapped = nonce + ciphertext_with_tag
    if len(wrapped) != WRAPPED_CEK_SIZE:
        raise RuntimeError(f"wrapped CEK length invariant violated: got {len(wrapped)}, expected {WRAPPED_CEK_SIZE}")
    return WrappedCEK(wrapped_cek=wrapped, ephemeral_pubkey=ephemeral_pub)


def unwrap_cek_x25519(
    wrapped_cek: bytes,
    ephemeral_pubkey: bytes,
    recipient_privkey: bytes,
    aad: bytes = b"",
    *,
    allow_legacy_info: bool = True,
) -> bytes:
    """Recover a CEK wrapped via :func:`wrap_cek_x25519` (or Photonic's
    ``wrapCEK`` with the non-PQ X25519 path).

    Tries :data:`KEK_DERIVATION_INFO` first and, if the AEAD tag fails, retries once with
    :data:`LEGACY_KEK_DERIVATION_INFO` — the string pyrxd emitted from v0.6.0 to 0.24.0,
    before Photonic split classical from hybrid. Without that retry, content pyrxd itself
    encrypted in that window becomes permanently unreadable, which is a worse outcome than
    accepting a second known-good derivation. Pass ``allow_legacy_info=False`` to require the
    current spelling.

    THE RETRY IS NOT A DOWNGRADE HOLE. Both values are fixed constants, not attacker-chosen;
    the AEAD tag still has to verify under whichever one is tried; and neither corresponds to
    Photonic's hybrid mode, so a stripped ML-KEM ciphertext still fails here exactly as
    upstream intends. What it changes is only which of two pyrxd-era spellings is accepted.

    Use :func:`unwrap_cek_x25519_detailed` when the caller needs to know which derivation
    succeeded — for example to re-wrap legacy content before the fallback is retired.

    Raises ``ValueError`` if any of the inputs are wrong: wrong privkey
    (ECDH gives a different shared secret → wrong KEK → AEAD tag fails),
    wrong AAD, tampered wrapped_cek bytes, or malformed sizes.
    """
    return unwrap_cek_x25519_detailed(
        wrapped_cek,
        ephemeral_pubkey,
        recipient_privkey,
        aad,
        allow_legacy_info=allow_legacy_info,
    ).cek


@dataclass(frozen=True)
class UnwrappedCEK:
    """A recovered CEK plus the fact of HOW it was recovered.

    ``legacy_info`` is True when the CEK only decrypted under the pre-split info string,
    which means these bytes were wrapped by pyrxd v0.6.0-0.24.0 and will stop being readable
    if the fallback is ever retired. Returned rather than logged so a caller can act on it.
    """

    cek: bytes
    legacy_info: bool


def unwrap_cek_x25519_detailed(
    wrapped_cek: bytes,
    ephemeral_pubkey: bytes,
    recipient_privkey: bytes,
    aad: bytes = b"",
    *,
    allow_legacy_info: bool = True,
) -> UnwrappedCEK:
    """:func:`unwrap_cek_x25519`, reporting which KEK derivation succeeded."""
    if len(wrapped_cek) != WRAPPED_CEK_SIZE:
        raise ValueError(
            f"wrapped_cek must be {WRAPPED_CEK_SIZE} bytes (24 nonce + 32 cek + 16 tag), got {len(wrapped_cek)}"
        )
    if len(ephemeral_pubkey) != X25519_KEY_SIZE:
        raise ValueError(f"ephemeral_pubkey must be {X25519_KEY_SIZE} bytes, got {len(ephemeral_pubkey)}")
    if len(recipient_privkey) != X25519_KEY_SIZE:
        raise ValueError(f"recipient_privkey must be {X25519_KEY_SIZE} bytes, got {len(recipient_privkey)}")

    shared = x25519_ecdh(recipient_privkey, ephemeral_pubkey)
    nonce = wrapped_cek[:XCHACHA20_NONCE_SIZE]
    ciphertext_with_tag = wrapped_cek[XCHACHA20_NONCE_SIZE:]

    attempts: tuple[tuple[bytes, bool], ...] = ((KEK_DERIVATION_INFO, False),)
    if allow_legacy_info:
        attempts += ((LEGACY_KEK_DERIVATION_INFO, True),)

    last_exc: Exception | None = None
    for info, is_legacy in attempts:
        kek = hkdf_sha256(shared, salt=None, info=info, length=XCHACHA20_KEY_SIZE)
        try:
            cek = decrypt_xchacha20_poly1305(ciphertext_with_tag, kek, nonce, aad)
        except Exception as exc:  # AEAD tag failure — try the next known derivation
            last_exc = exc
            continue
        if len(cek) != XCHACHA20_KEY_SIZE:
            raise ValueError(f"unwrapped CEK is the wrong size: got {len(cek)}, expected {XCHACHA20_KEY_SIZE}")
        return UnwrappedCEK(cek=cek, legacy_info=is_legacy)

    # Every known derivation failed. The cause is indistinguishable between wrong privkey,
    # wrong AAD and tampered bytes — by design, so this reports the class, not a guess.
    raise ValueError(
        "could not unwrap CEK under any known KEK derivation "
        f"({len(attempts)} tried): wrong recipient key, wrong AAD, or tampered bytes"
    ) from last_exc


__all__ = [
    "KEK_DERIVATION_INFO",
    "LEGACY_KEK_DERIVATION_INFO",
    "WRAPPED_CEK_SIZE",
    "X25519_KEY_SIZE",
    "UnwrappedCEK",
    "WrappedCEK",
    "hkdf_sha256",
    "unwrap_cek_x25519",
    "unwrap_cek_x25519_detailed",
    "wrap_cek_x25519",
    "x25519_ecdh",
    "x25519_public_key",
]
