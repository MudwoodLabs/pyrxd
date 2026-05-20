"""XChaCha20-Poly1305 AEAD + Photonic-compatible ``chunked-aead-v1`` scheme.

Mirrors Photonic Wallet's ``packages/lib/src/encryption.ts`` for byte-level
interop. Backed by PyCryptodome's ``Crypto.Cipher.ChaCha20_Poly1305``, which
implements ``draft-irtf-cfrg-xchacha-03`` (the same spec @noble/ciphers
ships in TypeScript). Verified byte-equal against the spec's Appendix A.3.1
test vector — see ``tests/test_aead.py``.

Two layers:

- :func:`encrypt_xchacha20_poly1305` / :func:`decrypt_xchacha20_poly1305` —
  raw single-shot AEAD with a caller-supplied 24-byte nonce
- :func:`encrypt_chunked` / :func:`decrypt_chunked` — Photonic's
  ``chunked-aead-v1`` scheme:

  * Split plaintext into 32 KB chunks
  * Per-chunk random 24-byte nonce
  * Per-chunk AAD = ``sha256(full_plaintext) || chunk_index_be32`` (36 bytes)
  * Each chunk authenticated independently — tampering with one fails decryption

Both layers produce output byte-identical to Photonic for matching inputs.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass

from Cryptodome.Cipher import ChaCha20_Poly1305  # pycryptodomex namespace

#: 32-byte symmetric key size used by all CEKs in the Glyph v2 scheme.
XCHACHA20_KEY_SIZE = 32

#: 24-byte XChaCha20 extended nonce — distinguishes XChaCha20 from
#: vanilla ChaCha20 (which uses a 12-byte nonce).
XCHACHA20_NONCE_SIZE = 24

#: 16-byte Poly1305 authentication tag, appended to the ciphertext.
POLY1305_TAG_SIZE = 16

#: 32 KB per chunk in the ``chunked-aead-v1`` scheme. Matches Photonic
#: exactly — chunk size is part of the wire format because per-chunk AAD
#: includes the chunk index.
CHUNK_SIZE = 32768

#: AEAD scheme identifier carried in EncryptionMetadata for v1.
CHUNKED_AEAD_V1 = "chunked-aead-v1"


def encrypt_xchacha20_poly1305(
    plaintext: bytes,
    key: bytes,
    nonce: bytes,
    aad: bytes = b"",
) -> bytes:
    """Encrypt ``plaintext`` under ``key`` with ``nonce`` and optional ``aad``.

    Returns ``ciphertext || tag`` — a single bytes blob where the last 16
    bytes are the Poly1305 tag. This matches Photonic's
    ``encryptXChaCha20Poly1305`` output shape (Photonic returns
    ``{ciphertext, nonce}`` where ``ciphertext`` already has the tag appended).
    """
    if len(key) != XCHACHA20_KEY_SIZE:
        raise ValueError(f"key must be {XCHACHA20_KEY_SIZE} bytes, got {len(key)}")
    if len(nonce) != XCHACHA20_NONCE_SIZE:
        raise ValueError(f"nonce must be {XCHACHA20_NONCE_SIZE} bytes, got {len(nonce)}")

    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    if aad:
        cipher.update(aad)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return ciphertext + tag


def decrypt_xchacha20_poly1305(
    ciphertext_with_tag: bytes,
    key: bytes,
    nonce: bytes,
    aad: bytes = b"",
) -> bytes:
    """Decrypt ``ciphertext || tag`` under ``key``, ``nonce``, ``aad``.

    Raises ``ValueError`` on tag mismatch (tampering, wrong key, wrong AAD,
    wrong nonce). The exception message intentionally does not echo any of
    the inputs — call sites cross a trust boundary.
    """
    if len(key) != XCHACHA20_KEY_SIZE:
        raise ValueError(f"key must be {XCHACHA20_KEY_SIZE} bytes, got {len(key)}")
    if len(nonce) != XCHACHA20_NONCE_SIZE:
        raise ValueError(f"nonce must be {XCHACHA20_NONCE_SIZE} bytes, got {len(nonce)}")
    if len(ciphertext_with_tag) < POLY1305_TAG_SIZE:
        raise ValueError(f"ciphertext too short — need at least {POLY1305_TAG_SIZE} tag bytes")

    ciphertext = ciphertext_with_tag[:-POLY1305_TAG_SIZE]
    tag = ciphertext_with_tag[-POLY1305_TAG_SIZE:]

    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    if aad:
        cipher.update(aad)
    try:
        return cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError as exc:
        # Re-raise with a generic message — never leak which check failed
        # (length vs MAC) to a caller across a trust boundary.
        raise ValueError("AEAD decryption failed: tag mismatch or wrong key/nonce/AAD") from exc


# ───────────────────────────────────────────────────────── chunked-aead-v1 ──


@dataclass(frozen=True)
class EncryptedChunk:
    """One chunk of a chunked-aead-v1 ciphertext.

    ``ciphertext`` is the bytes returned by the AEAD (includes the 16-byte
    Poly1305 tag); ``nonce`` is the 24-byte XChaCha20 nonce used for this
    chunk. Photonic emits both fields on the wire — pyrxd preserves them
    identically for round-trip compatibility.
    """

    ciphertext: bytes
    nonce: bytes


@dataclass(frozen=True)
class ChunkedCiphertext:
    """Chunked ciphertext + the plaintext SHA-256 used as the per-chunk
    AAD prefix.

    ``plaintext_hash`` MUST be the SHA-256 of the *full original* plaintext
    (not any individual chunk). Decrypting without this hash will fail tag
    verification on every chunk.
    """

    chunks: list[EncryptedChunk]
    plaintext_hash: bytes


def encrypt_chunked(plaintext: bytes, key: bytes) -> ChunkedCiphertext:
    """Encrypt ``plaintext`` with the Photonic ``chunked-aead-v1`` scheme.

    Each chunk gets a fresh random nonce; AAD per chunk is
    ``sha256(full_plaintext) || big-endian-uint32(chunk_index)``.

    Output is NOT byte-deterministic across calls (random nonces). For
    interop testing, decrypt a Photonic-generated chunked ciphertext via
    :func:`decrypt_chunked` and assert the recovered plaintext matches.
    """
    if len(key) != XCHACHA20_KEY_SIZE:
        raise ValueError(f"key must be {XCHACHA20_KEY_SIZE} bytes, got {len(key)}")

    plaintext_hash = hashlib.sha256(plaintext).digest()
    num_chunks = max(1, (len(plaintext) + CHUNK_SIZE - 1) // CHUNK_SIZE)
    if len(plaintext) == 0:
        num_chunks = 1  # encode an empty plaintext as one empty chunk

    chunks: list[EncryptedChunk] = []
    for i in range(num_chunks):
        start = i * CHUNK_SIZE
        end = min(start + CHUNK_SIZE, len(plaintext))
        chunk_plaintext = plaintext[start:end]

        # AAD: sha256(plaintext) || big-endian uint32(chunk_index)
        aad = plaintext_hash + i.to_bytes(4, "big")
        nonce = secrets.token_bytes(XCHACHA20_NONCE_SIZE)

        ciphertext = encrypt_xchacha20_poly1305(chunk_plaintext, key, nonce, aad)
        chunks.append(EncryptedChunk(ciphertext=ciphertext, nonce=nonce))

    return ChunkedCiphertext(chunks=chunks, plaintext_hash=plaintext_hash)


def decrypt_chunked(
    chunked: ChunkedCiphertext,
    key: bytes,
    plaintext_hash: bytes,
) -> bytes:
    """Decrypt a chunked ciphertext and return the concatenated plaintext.

    ``plaintext_hash`` MUST be the SHA-256 commitment from the on-chain
    metadata — it's used as the AAD prefix for every chunk. Passing the
    wrong hash fails decryption on chunk 0 (tag mismatch).

    The recovered plaintext is also hashed and compared to ``plaintext_hash``
    as a final self-consistency check; mismatch raises ``ValueError``.
    """
    if len(key) != XCHACHA20_KEY_SIZE:
        raise ValueError(f"key must be {XCHACHA20_KEY_SIZE} bytes, got {len(key)}")
    if len(plaintext_hash) != 32:
        raise ValueError(f"plaintext_hash must be 32 bytes, got {len(plaintext_hash)}")

    decrypted: list[bytes] = []
    for i, chunk in enumerate(chunked.chunks):
        aad = plaintext_hash + i.to_bytes(4, "big")
        chunk_plaintext = decrypt_xchacha20_poly1305(chunk.ciphertext, key, chunk.nonce, aad)
        decrypted.append(chunk_plaintext)

    plaintext = b"".join(decrypted)

    # Self-consistency: recovered plaintext must hash to the commitment.
    if hashlib.sha256(plaintext).digest() != plaintext_hash:
        raise ValueError("chunked-aead plaintext hash mismatch after decryption")

    return plaintext


__all__ = [
    "CHUNKED_AEAD_V1",
    "CHUNK_SIZE",
    "POLY1305_TAG_SIZE",
    "XCHACHA20_KEY_SIZE",
    "XCHACHA20_NONCE_SIZE",
    "ChunkedCiphertext",
    "EncryptedChunk",
    "decrypt_chunked",
    "decrypt_xchacha20_poly1305",
    "encrypt_chunked",
    "encrypt_xchacha20_poly1305",
]
