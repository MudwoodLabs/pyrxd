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


class TestLabelCanonicalityIsEnforced:
    """§5.4 label rules — the gap that let a signer forge display lines.

    Found by a security panel with a working exploit: a v2 record whose label
    contained a newline printed an attacker-chosen line INSIDE the block the CLI
    had just marked "signature VERIFIED", in the exact form of the WAVE-identity
    attribution the tool prints only for a verified signature. A reader would
    attribute a file to a key holder who never signed for that name. A U+202E in
    the label additionally renders "invoice<RLO>gpj.exe" as "invoiceexe.jpg", so
    the signed description is not the one the user reads.

    The decoder applied only a length cap and `bytes.decode("utf-8")`, so every
    one of these decoded OK and attested VALID — where the reference
    implementation and any spec-conformant verifier return INVALID. Two verifiers
    disagreeing about the same bytes is precisely the failure mode this project
    cares most about.

    THE VERSION SPLIT IS DELIBERATE, per §5.4: a v2 label is inside the signed
    statement, so a non-canonical one is not the label that was signed and the
    record is INVALID. A v1 label is not signed and forms no part of any claim, so
    it is WITHHELD with a reason and the record stays valid — invalidating it
    would discard timestamp evidence to fix a rendering problem.
    """

    #: One per row of the spec's rejected table, plus the two canonicalisation rules.
    _BAD = {
        "C0 newline": "file.pdf\nWAVE identity: treasury.rxd",
        "C0 ESC": "ok\x1b[31mRED",
        "C0 NUL": "a\x00b",
        "DEL": "a\x7fb",
        "C1": "a\x85b",
        "U+2028 line sep": "a b",
        "U+2029 para sep": "a b",
        "U+061C ALM": "a؜b",
        "U+200B ZWSP": "a​b",
        "U+200E LRM": "a‎b",
        "U+202E RLO": "invoice‮gpj.exe",
        "U+2066 isolate": "a⁦b",
        "U+FEFF BOM": "﻿contract",
        "untrimmed": "  contract.pdf  ",
        "non-NFC": "café",
    }
    #: Explicitly NOT rejected — joiners, and ordinary text.
    _GOOD = {"ZWNJ": "a‌b", "ZWJ": "a‍b", "plain": "invoice.pdf", "emoji": "sun ☀"}

    @pytest.mark.parametrize("label", _BAD.values(), ids=list(_BAD))
    def test_v2_with_a_noncanonical_label_is_INVALID(self, label: str) -> None:
        raw = (
            b"\x6a"
            + _push(b"HASHMARK")
            + _push(bytes([2, 1]))
            + _push(_DIGEST)
            + _push(bytes(20))
            + _push(bytes(65))
            + _push(label.encode())
        )
        rec = decode_hashmark(raw)
        assert rec.outcome is HashMarkOutcome.INVALID
        assert "5.4" in (rec.detail or "")

    @pytest.mark.parametrize("label", _BAD.values(), ids=list(_BAD))
    def test_v1_stays_VALID_but_withholds_the_label(self, label: str) -> None:
        raw = b"\x6a" + _push(b"HASHMARK") + _push(bytes([1, 1])) + _push(_DIGEST) + _push(label.encode())
        rec = decode_hashmark(raw)
        assert rec.ok, "a v1 label is unsigned; invalidating would discard timestamp evidence"
        assert rec.label is None and rec.label_withheld

    @pytest.mark.parametrize("label", _GOOD.values(), ids=list(_GOOD))
    def test_a_legitimate_label_is_NOT_refused(self, label: str) -> None:
        """The honest path. ZWNJ and ZWJ are joiners the spec deliberately permits —
        rejecting them would refuse legitimate text in several scripts."""
        for version, tail in ((1, b""), (2, _push(bytes(20)) + _push(bytes(65)))):
            raw = (
                b"\x6a"
                + _push(b"HASHMARK")
                + _push(bytes([version, 1]))
                + _push(_DIGEST)
                + tail
                + _push(label.encode())
            )
            rec = decode_hashmark(raw)
            assert rec.ok and rec.label == label, f"v{version}"

    def test_the_decoder_never_SILENTLY_repairs_a_label(self) -> None:
        """Canonicalisation runs one way. Trimming or normalising a label we read
        would mean the string shown is not the string signed."""
        rec = decode_hashmark(b"\x6a" + _push(b"HASHMARK") + _push(bytes([1, 1])) + _push(_DIGEST) + _push(b"  x  "))
        assert rec.label != "x", "must withhold, never trim"
        assert rec.label is None

    def test_the_forged_attribution_no_longer_reaches_the_renderer(self) -> None:
        """End-to-end, through the production classifier: the panel's exploit."""
        from pyrxd.glyph._inspect_core import _inspect_script

        raw = (
            b"\x6a"
            + _push(b"HASHMARK")
            + _push(bytes([2, 1]))
            + _push(_DIGEST)
            + _push(bytes(20))
            + _push(bytes(65))
            + _push(b"report.pdf\n    WAVE identity: treasury.rxd")
        )
        row = _inspect_script(raw.hex())
        assert row["type"] == "op_return", "must not classify as a valid hashmark"
        assert row["hashmark"]["outcome"] == "invalid"
        assert "WAVE identity" not in str(row.get("hashmark", {}).get("label") or "")


class TestWaveIdentityNamesAreSanitized:
    """A WAVE name is attacker-chosen registration text that the CLI prints
    directly beneath "signature VERIFIED".

    That line is the one place in the output stating an independently checked
    cryptographic fact, and the identity line under it is described to the user as
    proof "the signing key owns these names". Raw, a name can carry ANSI to scroll
    those lines away and reprint them saying something else — the reader sees a
    forged attribution in the exact position a real one appears.

    Same defect as the HashMark label, in the same renderer, one line apart; the
    label was fixed and this was left. Every other indexer-supplied string on this
    path (name, ticker, description) was already sanitized.
    """

    _HOSTILE = {
        "ANSI cursor-up + erase": "\x1b[2A\x1b[0J  WAVE identity: treasury.rxd",
        "carriage return": "innocent.rxd\rtreasury.rxd",
        "newline": "innocent.rxd\n    signer: 0000",
        "bidi override": "invoice‮gpj.exe",
    }

    @pytest.mark.parametrize("name", _HOSTILE.values(), ids=list(_HOSTILE))
    def test_a_hostile_name_cannot_reach_the_terminal(self, name: str) -> None:
        from pyrxd.glyph._inspect_core import _sanitize_display_string

        cleaned = _sanitize_display_string(name)
        assert "\x1b" not in cleaned and "\r" not in cleaned and "\n" not in cleaned
        assert "‮" not in cleaned

    def test_an_ordinary_name_is_passed_through_unchanged(self) -> None:
        """The honest path. A sanitizer that mangles real WAVE names would make
        every genuine identity line wrong, which is worse than not printing one."""
        from pyrxd.glyph._inspect_core import _sanitize_display_string

        for name in ("treasury.rxd", "my-company.rxd", "a.b.rxd", "名前.rxd"):
            assert _sanitize_display_string(name) == name

    def test_the_resolver_result_is_sanitized_before_it_is_stored(self) -> None:
        """At the boundary, not at the renderer — so the JSON path and any other
        consumer get the cleaned value too, and no future renderer has to remember."""
        import inspect as _inspect

        from pyrxd.cli import glyph_inspect

        source = _inspect.getsource(glyph_inspect._attach_wave_identity)
        assert '"names": [_sanitize_display_string(n) for n in names]' in source
