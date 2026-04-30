"""Glyph V2 creator signature: sign and verify metadata commit hashes.

Protocol mirrors Photonic Wallet v2metadata.ts signMetadata() /
verifyCreatorSignature().

Signing algorithm:
  1. Set creator.sig = "" in the metadata dict.
  2. CBOR-encode the dict → commit_hash = SHA256d(cbor_bytes).
  3. message = SHA256("glyph-v2-creator:" || commit_hash)  [32 bytes]
  4. Sign message with private key (ECDSA low-s DER).
  5. Store DER hex in creator.sig.

Verification reverses steps 1-3 and calls PublicKey.verify().
"""
from __future__ import annotations

import hashlib

import cbor2

from pyrxd.keys import PrivateKey, PublicKey

from .types import GlyphCreator, GlyphMetadata

_CREATOR_PREFIX = b"glyph-v2-creator:"


def _commit_hash(cbor_bytes: bytes) -> bytes:
    """SHA256d of CBOR bytes (matches Photonic sha256(sha256(encoded)))."""
    return hashlib.sha256(hashlib.sha256(cbor_bytes).digest()).digest()


def _signing_message(commit_hash: bytes) -> bytes:
    """SHA256(prefix || commit_hash) — the bytes actually signed."""
    return hashlib.sha256(_CREATOR_PREFIX + commit_hash).digest()


def _cbor_for_signing(metadata: GlyphMetadata, pubkey_hex: str, algo: str) -> bytes:
    """CBOR-encode metadata with creator.sig = "" (unsigned canonical form)."""
    d = metadata.to_cbor_dict()
    d["creator"] = {"pubkey": pubkey_hex, "sig": "", "algo": algo}
    return cbor2.dumps(d)


def sign_metadata(
    metadata: GlyphMetadata,
    private_key: PrivateKey,
    algo: str = "ecdsa-secp256k1",
) -> GlyphMetadata:
    """Return a new GlyphMetadata with creator.sig populated.

    The private key's compressed public key is embedded as creator.pubkey.
    The signing protocol is:
      1. Build canonical CBOR with sig="" and the pubkey.
      2. commit_hash = SHA256d(cbor)
      3. message = SHA256("glyph-v2-creator:" || commit_hash)
      4. sig = ECDSA(private_key, message)  [low-s DER, no double-hash]

    :param metadata:    GlyphMetadata to sign. Any existing creator field is replaced.
    :param private_key: pyrxd PrivateKey — the token deployer's key.
    :param algo:        Signing algorithm identifier (default: "ecdsa-secp256k1").
    :returns:           A frozen copy of metadata with creator.sig set.
    """
    pubkey_hex = private_key.public_key().serialize(compressed=True).hex()

    # Build the canonical CBOR with sig="" for hashing
    cbor_bytes = _cbor_for_signing(metadata, pubkey_hex, algo)
    message = _signing_message(_commit_hash(cbor_bytes))

    # Sign with no double-hash — message is already a 32-byte digest
    sig_der = private_key.sign(message, hasher=None)
    sig_hex = sig_der.hex()

    creator = GlyphCreator(pubkey=pubkey_hex, sig=sig_hex, algo=algo)
    return GlyphMetadata(
        protocol=metadata.protocol,
        name=metadata.name,
        ticker=metadata.ticker,
        description=metadata.description,
        token_type=metadata.token_type,
        main=metadata.main,
        attrs=metadata.attrs,
        loc=metadata.loc,
        loc_hash=metadata.loc_hash,
        decimals=metadata.decimals,
        image_url=metadata.image_url,
        image_ipfs=metadata.image_ipfs,
        image_sha256=metadata.image_sha256,
        v=metadata.v,
        dmint_params=metadata.dmint_params,
        creator=creator,
        royalty=metadata.royalty,
        policy=metadata.policy,
        rights=metadata.rights,
        created=metadata.created,
        commit_outpoint=metadata.commit_outpoint,
    )


def verify_creator_signature(metadata: GlyphMetadata) -> tuple[bool, str]:
    """Verify the creator signature embedded in metadata.

    :returns: (True, "") if valid; (False, reason) if invalid or missing.
    """
    if metadata.creator is None:
        return False, "no creator field"
    creator = metadata.creator
    if not creator.sig:
        return False, "creator.sig is empty"
    if not creator.pubkey:
        return False, "creator.pubkey is empty"

    try:
        sig_der = bytes.fromhex(creator.sig)
    except ValueError:
        return False, "creator.sig is not valid hex"

    try:
        pubkey = PublicKey(bytes.fromhex(creator.pubkey))
    except Exception as e:
        return False, f"invalid creator.pubkey: {e}"

    # Reconstruct canonical CBOR with sig="" to get the same commit hash
    cbor_bytes = _cbor_for_signing(metadata, creator.pubkey, creator.algo)
    message = _signing_message(_commit_hash(cbor_bytes))

    try:
        valid = pubkey.verify(sig_der, message, hasher=None)
    except Exception as e:
        return False, f"signature verification error: {e}"

    return (True, "") if valid else (False, "signature mismatch")
