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
   ``kek = HKDF(ss, salt=None, info=b"glyph-kek-v1", length=32)``
4. Sender encrypts the 32-byte CEK with XChaCha20-Poly1305 under ``kek``
   with a random 24-byte nonce, binding the AAD (typically the CEK hash
   commitment bytes per REP-3006)
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

#: HKDF info string for the KEK derivation. Bound to "glyph-kek-v1" by spec.
KEK_DERIVATION_INFO = b"glyph-kek-v1"

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
    fails decryption. Photonic uses the on-chain CEK hash commitment bytes
    here per REP-3006.
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
) -> bytes:
    """Recover a CEK wrapped via :func:`wrap_cek_x25519` (or Photonic's
    ``wrapCEK`` with the non-PQ X25519 path).

    Raises ``ValueError`` if any of the inputs are wrong: wrong privkey
    (ECDH gives a different shared secret → wrong KEK → AEAD tag fails),
    wrong AAD, tampered wrapped_cek bytes, or malformed sizes.
    """
    if len(wrapped_cek) != WRAPPED_CEK_SIZE:
        raise ValueError(
            f"wrapped_cek must be {WRAPPED_CEK_SIZE} bytes (24 nonce + 32 cek + 16 tag), got {len(wrapped_cek)}"
        )
    if len(ephemeral_pubkey) != X25519_KEY_SIZE:
        raise ValueError(f"ephemeral_pubkey must be {X25519_KEY_SIZE} bytes, got {len(ephemeral_pubkey)}")
    if len(recipient_privkey) != X25519_KEY_SIZE:
        raise ValueError(f"recipient_privkey must be {X25519_KEY_SIZE} bytes, got {len(recipient_privkey)}")

    shared = x25519_ecdh(recipient_privkey, ephemeral_pubkey)
    kek = hkdf_sha256(shared, salt=None, info=KEK_DERIVATION_INFO, length=XCHACHA20_KEY_SIZE)

    nonce = wrapped_cek[:XCHACHA20_NONCE_SIZE]
    ciphertext_with_tag = wrapped_cek[XCHACHA20_NONCE_SIZE:]
    cek = decrypt_xchacha20_poly1305(ciphertext_with_tag, kek, nonce, aad)
    if len(cek) != XCHACHA20_KEY_SIZE:
        raise ValueError(f"unwrapped CEK is the wrong size: got {len(cek)}, expected {XCHACHA20_KEY_SIZE}")
    return cek


__all__ = [
    "KEK_DERIVATION_INFO",
    "WRAPPED_CEK_SIZE",
    "X25519_KEY_SIZE",
    "WrappedCEK",
    "hkdf_sha256",
    "unwrap_cek_x25519",
    "wrap_cek_x25519",
    "x25519_ecdh",
    "x25519_public_key",
]
