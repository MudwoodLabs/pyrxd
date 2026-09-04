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

from pyrxd.hash import hash256
from pyrxd.keys import PrivateKey, PublicKey

from .types import GlyphCreator, GlyphMetadata

_CREATOR_PREFIX = b"glyph-v2-creator:"


def _commit_hash(cbor_bytes: bytes) -> bytes:
    """SHA256d of CBOR bytes (matches Photonic sha256(sha256(encoded)))."""
    return hash256(cbor_bytes)


def _signing_message(commit_hash: bytes) -> bytes:
    """SHA256(prefix || commit_hash) — the bytes actually signed."""
    return hashlib.sha256(_CREATOR_PREFIX + commit_hash).digest()


def _cbor_for_signing(metadata: GlyphMetadata, pubkey_hex: str, algo: str) -> bytes:
    """CBOR-encode metadata with creator.sig = "" (unsigned canonical form).

    Used to SIGN, and to verify metadata built in memory. To verify metadata that came
    off a chain, prefer :func:`_cbor_for_verifying`, which does not route the bytes
    through this object's fields.
    """
    d = metadata.to_cbor_dict()
    d["creator"] = {"pubkey": pubkey_hex, "sig": "", "algo": algo}
    return cbor2.dumps(d)


def _cbor_for_verifying(metadata: GlyphMetadata, pubkey_hex: str, algo: str) -> bytes:
    """The unsigned form, rebuilt from the ORIGINAL bytes when we still have them.

    DECODING IS LOSSY AND VERIFICATION MUST NOT BE. ``_cbor_str`` drops a wrong-typed
    field to ``""`` rather than raising, which is correct for display — Photonic mints
    ``loc`` as an INTEGER on mainnet, and refusing those tokens showed the user
    "metadata: NONE". But re-encoding the decoded object and checking the creator's
    signature over THAT compares against bytes the creator never signed, so an honest,
    correctly-signed token comes back "signature mismatch". Verified: with an integer
    ``loc``, a token signed by a real key and decoded by pyrxd was reported forged,
    while the identical construction with a text ``loc`` verified.

    ``loc`` is one instance; the defect is the class. ANY field the decoder normalises,
    now or later, silently becomes a forgery verdict — the failure gets worse as the
    decoder gets more forgiving, which is the opposite of how leniency should behave.

    Falls back to the re-encoded form when there are no source bytes, which is the
    in-memory case (a caller who just built and signed metadata), where the object IS
    the original.
    """
    if metadata.source_cbor is None:
        return _cbor_for_signing(metadata, pubkey_hex, algo)
    try:
        d = cbor2.loads(metadata.source_cbor)
    except Exception:  # pragma: no cover - decode_payload already parsed these bytes
        return _cbor_for_signing(metadata, pubkey_hex, algo)
    if not isinstance(d, dict):  # pragma: no cover - likewise
        return _cbor_for_signing(metadata, pubkey_hex, algo)
    # Blank the signature the same way the signer did, leaving every OTHER field with
    # the type and value it had on chain.
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
    """Check that ``creator.pubkey`` signed this metadata.

    WHAT A ``True`` ESTABLISHES, EXACTLY: *the key named in this blob signed this
    blob.* Nothing more. ``creator.pubkey`` is a field of the same metadata being
    verified — nothing here binds it to the minting key, to the commit outpoint, or
    to any identity known in advance.

    SO IT DOES NOT ESTABLISH AUTHORSHIP, and the failure is not subtle. Anyone can
    take a token's metadata verbatim, re-sign it with their own key, and mint a copy
    whose ``verify_creator_signature`` returns ``(True, "")`` — indistinguishable
    from the original. Demonstrated in ``tests/test_creator_signature_scope.py``.
    A marketplace building a "verified creator" badge on this boolean would badge
    the counterfeit.

    TO GET AUTHORSHIP you need a key fixed IN ADVANCE to compare the recovered one
    against. That is the standard this repo already applies one module over, in
    :func:`pyrxd.script.hashmark.verify_attestation`: "Without a value fixed in
    advance to compare against, recovery is circular and proves nothing: an attacker
    would simply write whatever hash their chosen signature recovers to." HashMark
    commits the signer hash160 twice and requires both to match; this has one copy
    and compares it to itself.

    The check is still worth having — it detects a metadata blob altered after
    signing, which is a real thing to detect. It is the INFERENCE from ``True`` that
    has to stay narrow.

    :returns: (True, "") if the named key signed this metadata; (False, reason)
        otherwise. A non-empty reason on ``True`` flags a lossy decode — see
        :func:`_cbor_for_verifying`.
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

    # Reconstruct canonical CBOR with sig="" to get the same commit hash. From the
    # ORIGINAL bytes where we have them — see `_cbor_for_verifying`.
    cbor_bytes = _cbor_for_verifying(metadata, creator.pubkey, creator.algo)
    message = _signing_message(_commit_hash(cbor_bytes))

    try:
        valid = pubkey.verify(sig_der, message, hasher=None)
    except Exception as e:
        return False, f"signature verification error: {e}"

    if not valid:
        return False, "signature mismatch"

    # A VALID signature over the on-chain bytes does not by itself mean the creator
    # signed the metadata being DISPLAYED. Verifying against the source bytes fixed a
    # false-forgery verdict, and the thing not to trade it for is a silent gap in the
    # other direction: if the decoder normalised a field, the object a caller renders
    # is not the object that was signed, and "VERIFIED" would be overclaiming.
    #
    # Detected by comparison rather than by tracking each field as it is normalised —
    # a hand-kept list of lossy fields would go stale the first time the decoder
    # learns a new leniency, which is exactly how this class of bug arrives.
    if metadata.source_cbor is not None and cbor_bytes != _cbor_for_signing(metadata, creator.pubkey, creator.algo):
        return True, (
            "signature is valid over the on-chain bytes, but the decoder normalised at "
            "least one field — the metadata shown is NOT byte-identical to what was signed"
        )
    return True, ""
