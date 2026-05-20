"""End-to-end TIMELOCK integration test.

Exercises every module together: a complete TIMELOCK Glyph lifecycle from
mint to reveal to decryption, using only pyrxd primitives. Also tests
the cross-implementation interop case: a Photonic-encrypted CEK is
wrapped to a Photonic recipient, pyrxd unwraps it, decrypts a payload
encrypted with that CEK, and validates a Photonic reveal proof.

This file is the integration sanity check on top of the per-module unit
tests. If all 106 per-module tests pass but this fails, something subtle
in the module wiring is wrong.
"""

from __future__ import annotations

import hashlib
import json
import secrets
from pathlib import Path

import pytest

from pyrxd.crypto.aead import (
    XCHACHA20_KEY_SIZE,
    decrypt_chunked,
    encrypt_chunked,
)
from pyrxd.crypto.kem import (
    unwrap_cek_x25519,
    wrap_cek_x25519,
    x25519_public_key,
)
from pyrxd.glyph.encrypted_content import (
    SCHEME_CHUNKED_AEAD_V1,
    WRAP_ALG_X25519,
    CryptoMetadata,
    CryptoRecipient,
    EncryptedContentStub,
    EncryptionMetadata,
)
from pyrxd.glyph.timelock import (
    TimelockParams,
    add_timelock_to_metadata,
    compute_cek_hash,
    format_cek_hash,
    is_unlocked,
    verify_cek_reveal,
)
from pyrxd.glyph.timelock_reveal_tx import (
    create_reveal_proof,
    parse_reveal_proof_script,
    validate_reveal_proof,
)
from pyrxd.glyph.types import GlyphProtocol

FIXTURES_PATH = Path(__file__).parent / "fixtures" / "photonic_timelock_vectors.json"


@pytest.fixture(scope="module")
def photonic_vectors() -> dict:
    return json.loads(FIXTURES_PATH.read_text())


# ────────────────────────────────────────────── full pyrxd-only e2e ──


class TestFullLifecycleSelfContained:
    """Pyrxd does the whole flow itself: mint → encrypt → wrap CEK to
    recipient → publish mint metadata → simulate time passing → broadcast
    reveal → recipient parses + validates + decrypts."""

    def test_e2e_block_mode(self):
        # ─── SETUP ────────────────────────────────────────────────────
        # Plaintext payload (e.g. a sealed bid)
        plaintext = b"Top secret bid amount: 1000 RXD for the auction"
        # CEK chosen by minter
        cek = secrets.token_bytes(XCHACHA20_KEY_SIZE)
        # Recipient's X25519 identity (e.g. the auctioneer's pubkey)
        recipient_sk = secrets.token_bytes(32)
        recipient_pk = x25519_public_key(recipient_sk)

        # ─── MINT-TIME CONSTRUCTION ───────────────────────────────────
        # Encrypt the payload with chunked AEAD
        chunked = encrypt_chunked(plaintext, cek)
        plaintext_hash = chunked.plaintext_hash

        # Wrap the CEK for the recipient using X25519 ECDH
        wrap_aad = compute_cek_hash(cek)  # bind to commitment per REP-3006
        wrapped = wrap_cek_x25519(cek, recipient_pk, wrap_aad)

        # Build the EncryptedContentStub (mint metadata)
        cek_hash_str = format_cek_hash(compute_cek_hash(cek))
        stub = EncryptedContentStub(
            p=[GlyphProtocol.NFT, GlyphProtocol.ENCRYPTED],
            type="text/plain",
            name="Sealed Bid #1",
            main=EncryptionMetadata(
                type="text/plain",
                hash=format_cek_hash(plaintext_hash),
                size=len(plaintext),
                chunks=len(chunked.chunks),
                scheme=SCHEME_CHUNKED_AEAD_V1,
            ),
            crypto=CryptoMetadata(
                cek_hash=cek_hash_str,
                recipients=[
                    CryptoRecipient(
                        kid="auctioneer-key-1",
                        alg=WRAP_ALG_X25519,
                        wrapped_cek=wrapped.wrapped_cek,
                        epk=wrapped.ephemeral_pubkey,
                    )
                ],
            ),
        )

        # Add TIMELOCK to gate visibility until block 1000
        result = add_timelock_to_metadata(
            stub,
            cek,
            TimelockParams(mode="block", unlock_at=1000),
        )
        mint_metadata = result.metadata
        stored_cek = result.cek_for_caller_to_store
        assert stored_cek == cek

        # ─── ON-CHAIN STATE (simulated) ──────────────────────────────
        # The mint metadata gets CBOR-encoded into the reveal scriptSig
        # of the original mint tx. Nobody can see the plaintext yet.

        # Simulate observer at block 500: token exists, payload visible? NO
        assert not is_unlocked(mint_metadata, current_block=500)
        assert is_unlocked(mint_metadata, current_block=1000)

        # ─── REVEAL TIME (block 1000+) ───────────────────────────────
        # The minter constructs and broadcasts a reveal tx that publishes
        # the CEK in an OP_RETURN. This OP_RETURN script is what
        # `create_reveal_proof` produces.
        token_ref = "ab" * 32 + ":0"  # the original mint outpoint
        reveal_script, _proof = create_reveal_proof(
            token_ref,
            stored_cek,
            hint="Auction close, block 1000",
        )

        # ─── RECIPIENT'S DECRYPTION FLOW ─────────────────────────────
        # 1. Parse the on-chain reveal script
        parsed = parse_reveal_proof_script(reveal_script)
        assert parsed is not None

        # 2. Validate against the original mint commitment
        validation = validate_reveal_proof(
            parsed,
            expected_token_ref=token_ref,
            expected_cek_hash=mint_metadata.crypto.timelock.cek_hash,
        )
        assert validation.valid, validation.error

        # 3. Extract the CEK
        revealed_cek = bytes.fromhex(parsed.cek)
        assert revealed_cek == cek

        # 4. Verify the CEK matches the commitment (defense in depth —
        #    validation above already did this)
        assert verify_cek_reveal(revealed_cek, mint_metadata.crypto.timelock.cek_hash)

        # 5. Unwrap the CEK using the recipient's X25519 key (alternative
        #    path: a holder of the wrapping key can decrypt WITHOUT the
        #    reveal tx — the reveal is for everyone else)
        unwrap_aad = compute_cek_hash(revealed_cek)
        wrapped_data = mint_metadata.crypto.recipients[0]
        unwrapped_cek = unwrap_cek_x25519(
            wrapped_data.wrapped_cek,
            wrapped_data.epk,
            recipient_sk,
            unwrap_aad,
        )
        assert unwrapped_cek == cek

        # 6. Decrypt the payload using either the revealed or unwrapped CEK
        recovered = decrypt_chunked(chunked, revealed_cek, plaintext_hash)
        assert recovered == plaintext


# ────────────────────────────────────────────── photonic interop e2e ──


class TestPhotonicInteropEndToEnd:
    """Use Photonic-generated artifacts at every step to prove pyrxd can
    participate in a full Photonic-emitted TIMELOCK exchange."""

    def test_unwrap_photonic_cek_then_decrypt_photonic_chunked(self, photonic_vectors):
        """Photonic wrapped a CEK to us; we unwrap it and use it to
        decrypt a Photonic-encrypted chunked payload. The same CEK is
        used in both fixtures (the bridge generated them with consistent
        inputs)."""
        # 1. Unwrap the CEK Photonic encrypted for us
        wrap = photonic_vectors["wrap_cek_x25519"]
        recipient_sk = bytes.fromhex(wrap["recipient_sk"])
        wrapped_bytes = bytes.fromhex(wrap["wrapped_cek"])
        ephemeral = bytes.fromhex(wrap["ephemeral_x25519_pub"])
        aad = bytes.fromhex(wrap["aad"])
        unwrapped_cek = unwrap_cek_x25519(wrapped_bytes, ephemeral, recipient_sk, aad)
        assert unwrapped_cek == bytes.fromhex(wrap["original_cek"])

        # 2. The unwrapped CEK is the same one used in chunked_aead_small
        chunked_fixture = photonic_vectors["chunked_aead_small"]
        assert unwrapped_cek.hex() == chunked_fixture["key"]

        # 3. Decrypt the Photonic-chunked payload using the unwrapped CEK
        from pyrxd.crypto.aead import ChunkedCiphertext, EncryptedChunk

        chunked = ChunkedCiphertext(
            chunks=[
                EncryptedChunk(
                    ciphertext=bytes.fromhex(c["ciphertext"]),
                    nonce=bytes.fromhex(c["nonce"]),
                )
                for c in chunked_fixture["chunks"]
            ],
            plaintext_hash=bytes.fromhex(chunked_fixture["plaintext_hash"]),
        )
        recovered = decrypt_chunked(chunked, unwrapped_cek, chunked.plaintext_hash)
        assert recovered == bytes.fromhex(chunked_fixture["plaintext"])

    def test_parse_photonic_reveal_and_decrypt_chunked(self, photonic_vectors):
        """Parse a Photonic-emitted reveal script, extract the CEK,
        decrypt a Photonic-encrypted payload with it."""
        # 1. Parse the reveal script
        reveal = photonic_vectors["reveal_proof_block_mode"]
        script = bytes.fromhex(reveal["op_return_script_hex"])
        parsed = parse_reveal_proof_script(script)
        assert parsed is not None

        # 2. Validate self-consistency
        validation = validate_reveal_proof(parsed, expected_token_ref=reveal["token_ref"])
        assert validation.valid

        # 3. The CEK in the reveal matches the one in chunked_aead_small
        chunked_fixture = photonic_vectors["chunked_aead_small"]
        revealed_cek = bytes.fromhex(parsed.cek)
        assert revealed_cek.hex() == chunked_fixture["key"]

        # 4. Decrypt the Photonic-chunked payload using the revealed CEK
        from pyrxd.crypto.aead import ChunkedCiphertext, EncryptedChunk

        chunked = ChunkedCiphertext(
            chunks=[
                EncryptedChunk(
                    ciphertext=bytes.fromhex(c["ciphertext"]),
                    nonce=bytes.fromhex(c["nonce"]),
                )
                for c in chunked_fixture["chunks"]
            ],
            plaintext_hash=bytes.fromhex(chunked_fixture["plaintext_hash"]),
        )
        recovered = decrypt_chunked(chunked, revealed_cek, chunked.plaintext_hash)
        assert recovered == bytes.fromhex(chunked_fixture["plaintext"])

    def test_round_trip_against_photonic_metadata(self, photonic_vectors):
        """Parse a Photonic mint metadata dict, re-emit it from pyrxd
        builder against the same inputs, assert byte-equal output."""
        v = photonic_vectors["timelock_metadata_block_mode"]
        photonic_dict = v["output_metadata"]

        # Reconstruct inputs the bridge fed in
        cek = bytes((i * 17 + 1) & 0xFF for i in range(32))
        pt_small = b"hello, photonic timelock interop"
        cek_hash_str = format_cek_hash(compute_cek_hash(cek))
        stub_input = EncryptedContentStub(
            p=[GlyphProtocol.NFT, GlyphProtocol.ENCRYPTED],
            type="image/png",
            name="Sealed Test #1",
            main=EncryptionMetadata(
                type="image/png",
                hash=format_cek_hash(hashlib.sha256(pt_small).digest()),
                size=len(pt_small),
                chunks=1,
                scheme=SCHEME_CHUNKED_AEAD_V1,
            ),
            crypto=CryptoMetadata(cek_hash=cek_hash_str),
        )
        result = add_timelock_to_metadata(
            stub_input,
            cek,
            TimelockParams(mode="block", unlock_at=v["unlock_at"]),
        )
        # The pyrxd-emitted metadata dict equals the Photonic-emitted one.
        assert result.metadata.to_dict() == photonic_dict
