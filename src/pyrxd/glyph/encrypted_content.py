"""Glyph v2 encrypted-content metadata types (Photonic-compatible).

Mirrors Photonic Wallet's ``packages/lib/src/encryption.ts`` type
declarations. These are pure data containers — encode to / decode from
the CBOR-compatible dict shape that goes on-chain.

The full mint metadata for an encrypted Glyph looks like:

.. code-block:: python

    EncryptedContentStub(
        p=[2, 8],                # NFT + ENCRYPTED
        type="image/png",
        name="Sealed Item",
        main=EncryptionMetadata(
            type="image/png",
            hash="sha256:<hex>", # SHA-256 of the plaintext content
            enc="xchacha20poly1305",
            size=12345,
            chunks=1,
            scheme="chunked-aead-v1",
        ),
        crypto=CryptoMetadata(
            mode="encrypted",
            key_format="wrapped",
            cek_hash="sha256:<hex>",
            recipients=[CryptoRecipient(...)],
            timelock=TimelockSpec(...),  # if also TIMELOCK
        ),
    )

When a TIMELOCK marker is present, the protocol list becomes ``[2, 8, 9]``
and ``crypto.timelock`` is populated. See :mod:`pyrxd.glyph.timelock` for
the builder/parser of the timelock layer specifically.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

# Wire constants matching Photonic exactly.
SCHEME_CHUNKED_AEAD_V1 = "chunked-aead-v1"
ENC_XCHACHA20POLY1305 = "xchacha20poly1305"
WRAP_ALG_X25519 = "x25519-hkdf-xchacha20poly1305"
WRAP_ALG_X25519_MLKEM768 = "x25519mlkem768-hkdf-xchacha20poly1305"

# Wrapping format options. We only emit "wrapped" for now; "passphrase"
# (scrypt-based key derivation from a user password) is recognized for
# decoding but not yet a write-path option.
KEY_FORMAT_WRAPPED = "wrapped"
KEY_FORMAT_PASSPHRASE = "passphrase"  # nosec B105 — wire-format constant name from REP-3006, not a credential


def _sha256_prefix(hex_or_prefixed: str) -> str:
    """Normalize a hash string to ``"sha256:<lowercase hex>"`` form."""
    s = hex_or_prefixed.strip()
    if s.lower().startswith("sha256:"):
        return "sha256:" + s.split(":", 1)[1].lower()
    return f"sha256:{s.lower()}"


@dataclass(frozen=True)
class EncryptionMetadata:
    """The ``main`` block in an encrypted Glyph's CBOR metadata.

    Records what was encrypted and how — content type, plaintext SHA-256,
    AEAD algorithm, chunked-AEAD scheme version.
    """

    type: str  # MIME type of the plaintext content
    hash: str  # "sha256:<hex>" of the plaintext
    enc: Literal["xchacha20poly1305"] = ENC_XCHACHA20POLY1305
    size: int = 0
    chunks: int = 1
    scheme: Literal["chunked-aead-v1"] = SCHEME_CHUNKED_AEAD_V1

    def to_dict(self) -> dict:
        return {
            "type": self.type,
            "hash": _sha256_prefix(self.hash),
            "enc": self.enc,
            "size": self.size,
            "chunks": self.chunks,
            "scheme": self.scheme,
        }

    @classmethod
    def from_dict(cls, d: dict) -> EncryptionMetadata:
        return cls(
            type=str(d["type"]),
            hash=str(d["hash"]),
            enc=str(d.get("enc", ENC_XCHACHA20POLY1305)),
            size=int(d.get("size", 0)),
            chunks=int(d.get("chunks", 1)),
            scheme=str(d.get("scheme", SCHEME_CHUNKED_AEAD_V1)),
        )


@dataclass(frozen=True)
class CryptoRecipient:
    """One recipient entry in ``crypto.recipients``. Carries the CEK
    wrapped for this recipient's public key, plus the ephemeral X25519
    public key the wrap was performed against.

    All bytes fields are base64-encoded on the wire (matching Photonic);
    use :meth:`to_dict` / :meth:`from_dict` to convert.
    """

    kid: str
    alg: str  # WRAP_ALG_X25519 or WRAP_ALG_X25519_MLKEM768
    wrapped_cek: bytes  # 72 bytes for X25519-only
    epk: bytes  # 32-byte X25519 ephemeral pubkey
    mlkem_ct: bytes | None = None  # only present for PQ hybrid

    def to_dict(self) -> dict:
        import base64

        d: dict = {
            "kid": self.kid,
            "alg": self.alg,
            "wrapped_cek": base64.b64encode(self.wrapped_cek).decode("ascii"),
            "epk": base64.b64encode(self.epk).decode("ascii"),
        }
        if self.mlkem_ct is not None:
            d["mlkem_ct"] = base64.b64encode(self.mlkem_ct).decode("ascii")
        return d

    @classmethod
    def from_dict(cls, d: dict) -> CryptoRecipient:
        import base64

        mlkem_ct = None
        if d.get("mlkem_ct"):
            mlkem_ct = base64.b64decode(d["mlkem_ct"])
        return cls(
            kid=str(d["kid"]),
            alg=str(d["alg"]),
            wrapped_cek=base64.b64decode(d["wrapped_cek"]),
            epk=base64.b64decode(d["epk"]),
            mlkem_ct=mlkem_ct,
        )


@dataclass(frozen=True)
class TimelockSpec:
    """Photonic-compatible timelock spec embedded in ``crypto.timelock``.

    See REP-3009. The on-chain ``cek_hash`` here is the same value as the
    parent ``CryptoMetadata.cek_hash`` — it's duplicated inside the
    timelock object for clear authentication of the reveal transaction.
    """

    mode: Literal["block", "time"]
    unlock_at: int
    cek_hash: str  # "sha256:<hex>" — must match the reveal CEK
    hint: str = ""

    def to_dict(self) -> dict:
        d: dict = {
            "mode": self.mode,
            "unlock_at": self.unlock_at,
            "cek_hash": _sha256_prefix(self.cek_hash),
        }
        if self.hint:
            d["hint"] = self.hint
        return d

    @classmethod
    def from_dict(cls, d: dict) -> TimelockSpec:
        return cls(
            mode=str(d["mode"]),  # type: ignore[arg-type]
            unlock_at=int(d["unlock_at"]),
            cek_hash=str(d["cek_hash"]),
            hint=str(d.get("hint", "")),
        )


@dataclass(frozen=True)
class CryptoMetadata:
    """The ``crypto`` block in an encrypted Glyph's metadata.

    Records the key delivery method (wrapped to recipients or
    passphrase-derived), the CEK commitment hash, optional locator info
    (for off-chain ciphertext storage), the per-recipient wraps, and an
    optional :class:`TimelockSpec` for time-locked reveals.
    """

    mode: Literal["encrypted"] = "encrypted"
    key_format: Literal["wrapped", "passphrase"] = KEY_FORMAT_WRAPPED
    cek_hash: str = ""  # "sha256:<hex>"
    locator: str | None = None
    locator_hash: str | None = None
    recipients: list[CryptoRecipient] = field(default_factory=list)
    timelock: TimelockSpec | None = None

    def to_dict(self) -> dict:
        d: dict = {
            "mode": self.mode,
            "key_format": self.key_format,
            "cek_hash": _sha256_prefix(self.cek_hash),
        }
        if self.locator is not None:
            d["locator"] = self.locator
        if self.locator_hash is not None:
            d["locator_hash"] = _sha256_prefix(self.locator_hash)
        if self.recipients:
            d["recipients"] = [r.to_dict() for r in self.recipients]
        if self.timelock is not None:
            d["timelock"] = self.timelock.to_dict()
        return d

    @classmethod
    def from_dict(cls, d: dict) -> CryptoMetadata:
        recipients = [CryptoRecipient.from_dict(r) for r in d.get("recipients", [])]
        timelock = TimelockSpec.from_dict(d["timelock"]) if "timelock" in d else None
        return cls(
            mode=str(d.get("mode", "encrypted")),  # type: ignore[arg-type]
            key_format=str(d.get("key_format", KEY_FORMAT_WRAPPED)),  # type: ignore[arg-type]
            cek_hash=str(d.get("cek_hash", "")),
            locator=str(d["locator"]) if "locator" in d else None,
            locator_hash=str(d["locator_hash"]) if "locator_hash" in d else None,
            recipients=recipients,
            timelock=timelock,
        )


@dataclass(frozen=True)
class EncryptedContentStub:
    """The full mint metadata dict for an encrypted Glyph.

    This is what gets CBOR-encoded and placed in the on-chain reveal
    scriptSig. It encapsulates the protocol marker list + content
    metadata + crypto metadata as one cohesive structure.

    Construct via :func:`pyrxd.glyph.timelock.build_timelock_mint` (or
    the equivalent encrypted-only builder when that lands), not directly,
    so the cek_hash + main.hash invariants are enforced.
    """

    p: list[int]  # protocol markers
    type: str
    name: str
    main: EncryptionMetadata
    crypto: CryptoMetadata

    def to_dict(self) -> dict:
        return {
            "p": list(self.p),
            "type": self.type,
            "name": self.name,
            "main": self.main.to_dict(),
            "crypto": self.crypto.to_dict(),
        }

    @classmethod
    def from_dict(cls, d: dict) -> EncryptedContentStub:
        return cls(
            p=[int(x) for x in d["p"]],
            type=str(d["type"]),
            name=str(d["name"]),
            main=EncryptionMetadata.from_dict(d["main"]),
            crypto=CryptoMetadata.from_dict(d["crypto"]),
        )


__all__ = [
    "ENC_XCHACHA20POLY1305",
    "KEY_FORMAT_PASSPHRASE",
    "KEY_FORMAT_WRAPPED",
    "SCHEME_CHUNKED_AEAD_V1",
    "WRAP_ALG_X25519",
    "WRAP_ALG_X25519_MLKEM768",
    "CryptoMetadata",
    "CryptoRecipient",
    "EncryptedContentStub",
    "EncryptionMetadata",
    "TimelockSpec",
]
