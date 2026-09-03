"""v2 attestation — recovering the signer and requiring it to match the commitment.

Decoding and attestation are SEPARATE steps with separate outcomes, and the spec
argues the separation earns its keep: "an invalid-signature record must never be
shown as a valid mark, but calling it malformed sends whoever is debugging it
after the wrong problem." A record that decodes is well-formed, not yet believed.

The signer hash160 is committed TWICE — in the record and inside the signed
statement — and both are required. Without a value fixed in advance, recovery is
circular: an attacker would write whatever hash their chosen signature recovers to.
"""

from __future__ import annotations

import pytest

from pyrxd.hash import hash256
from pyrxd.keys import PrivateKey
from pyrxd.script.hashmark import (
    RADIANT_MAINNET_GENESIS,
    AttestationOutcome,
    HashMarkOutcome,
    HashMarkRecord,
    canonical_statement,
    decode_hashmark,
    verify_attestation,
)
from pyrxd.utils import text_digest

_LABEL = "invoice-2026-09.pdf"
_DIGEST = hash256(b"the document bytes")


def _push(b: bytes) -> bytes:
    return (bytes([len(b)]) + b) if len(b) <= 0x4B else (b"\x4c" + bytes([len(b)]) + b)


def _signed_record(
    key: PrivateKey,
    *,
    digest: bytes = _DIGEST,
    label: str | None = _LABEL,
    signer: bytes | None = None,
    genesis: str = RADIANT_MAINNET_GENESIS,
) -> bytes:
    """Build a genuinely signed v2 record, the way a writer would."""
    signer_h = signer if signer is not None else key.public_key().hash160()
    draft = HashMarkRecord(
        HashMarkOutcome.OK,
        version=2,
        algorithm_id=1,
        algorithm="sha256",
        digest_hex=digest.hex(),
        label=label,
        signer_hash160_hex=signer_h.hex(),
        signature_hex="00" * 65,
    )
    sig = key.sign_recoverable(text_digest(canonical_statement(draft, network_genesis=genesis)), hasher=hash256)
    header = 27 + sig[64] + 4  # compressed
    pushes = [
        _push(b"HASHMARK"),
        _push(bytes([2, 1])),
        _push(digest),
        _push(signer_h),
        _push(bytes([header]) + sig[:64]),
    ]
    if label is not None:
        pushes.append(_push(label.encode()))
    return b"\x6a" + b"".join(pushes)


class TestAnHonestRecordVerifies:
    """Paired with every refusal below — a guard that refuses valid work is a bug."""

    def test_a_genuinely_signed_record_is_valid(self) -> None:
        rec = decode_hashmark(_signed_record(PrivateKey()))
        res = verify_attestation(rec)
        assert res.valid
        assert res.recovered_hash160_hex == rec.signer_hash160_hex

    def test_a_record_with_no_label_verifies(self) -> None:
        """`label` is OMITTED from the statement when absent, never sent as an
        empty string — a different statement, and so a different signature."""
        assert verify_attestation(decode_hashmark(_signed_record(PrivateKey(), label=None))).valid

    def test_a_non_ascii_label_verifies(self) -> None:
        """The escaping rule matters here: `json.dumps` would emit \\uXXXX and
        change the signed bytes for any label with an accent or an emoji."""
        assert verify_attestation(decode_hashmark(_signed_record(PrivateKey(), label="facture-café-☀"))).valid


class TestTamperingIsCaught:
    @pytest.mark.parametrize("field", ["digest", "label", "signer"])
    def test_editing_a_committed_field_invalidates_the_signature(self, field: str) -> None:
        """Every field in the statement is covered, so changing any of them in the
        record makes the recovered key disagree with the commitment."""
        key = PrivateKey()
        raw = bytearray(_signed_record(key))
        rec = decode_hashmark(bytes(raw))
        assert verify_attestation(rec).valid, "the untampered record must verify first"

        if field == "digest":
            tampered = _signed_record(key)
            tampered = tampered.replace(_DIGEST, hash256(b"a different document"), 1)
        elif field == "label":
            tampered = _signed_record(key).replace(_LABEL.encode(), b"paid-in-full.pdf!!!", 1)
        else:
            tampered = _signed_record(key, signer=PrivateKey().public_key().hash160())

        res = verify_attestation(decode_hashmark(tampered))
        assert res.outcome is AttestationOutcome.INVALID_SIGNATURE, field

    def test_a_signature_from_a_DIFFERENT_key_does_not_attest(self) -> None:
        """The commitment is what stops recovery being circular: an attacker who
        signs the statement themselves still cannot match someone else's hash160."""
        victim, attacker = PrivateKey(), PrivateKey()
        forged = _signed_record(attacker, signer=victim.public_key().hash160())
        assert verify_attestation(decode_hashmark(forged)).outcome is AttestationOutcome.INVALID_SIGNATURE


class TestTheStatementIsChainScoped:
    def test_the_same_bytes_do_not_verify_against_another_genesis(self) -> None:
        """`network` is in the signed statement and NOT in the record — it is the
        verified context the transaction was found in. The same bytes on another
        chain are a different statement, deliberately."""
        rec = decode_hashmark(_signed_record(PrivateKey()))
        assert verify_attestation(rec).valid
        other = verify_attestation(rec, network_genesis="00" * 32)
        assert other.outcome is AttestationOutcome.INVALID_SIGNATURE


class TestMalformedSignatures:
    def test_a_high_s_signature_is_refused(self) -> None:
        """Low-S is mandatory: it removes the s versus n-s malleability so a
        verifier has exactly one accepted form."""
        n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        key = PrivateKey()
        raw = _signed_record(key)
        rec = decode_hashmark(raw)
        sig = bytearray(bytes.fromhex(rec.signature_hex))
        s_val = int.from_bytes(sig[33:65], "big")
        sig[33:65] = (n - s_val).to_bytes(32, "big")  # the malleated twin
        flipped = HashMarkRecord(
            HashMarkOutcome.OK,
            version=2,
            algorithm_id=1,
            algorithm="sha256",
            digest_hex=rec.digest_hex,
            label=rec.label,
            signer_hash160_hex=rec.signer_hash160_hex,
            signature_hex=bytes(sig).hex(),
        )
        res = verify_attestation(flipped)
        assert res.outcome is AttestationOutcome.INVALID_SIGNATURE
        assert "low-S" in (res.detail or "")

    @pytest.mark.parametrize("header", [0, 26, 35, 255])
    def test_a_header_outside_27_34_is_refused(self, header: int) -> None:
        rec = decode_hashmark(_signed_record(PrivateKey()))
        sig = bytearray(bytes.fromhex(rec.signature_hex))
        sig[0] = header
        bad = HashMarkRecord(
            HashMarkOutcome.OK,
            version=2,
            algorithm_id=1,
            algorithm="sha256",
            digest_hex=rec.digest_hex,
            label=rec.label,
            signer_hash160_hex=rec.signer_hash160_hex,
            signature_hex=bytes(sig).hex(),
        )
        assert verify_attestation(bad).outcome is AttestationOutcome.INVALID_SIGNATURE


class TestV1IsNotAFailure:
    def test_a_v1_record_is_NOT_ATTESTED_rather_than_invalid(self) -> None:
        """v1 never claimed to say WHO — only WHEN. Reporting it as an invalid
        signature would be reporting a claim it does not make."""
        v1 = b"\x6a" + _push(b"HASHMARK") + _push(bytes([1, 1])) + _push(_DIGEST)
        res = verify_attestation(decode_hashmark(v1))
        assert res.outcome is AttestationOutcome.NOT_ATTESTED
