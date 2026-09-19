"""HashMark encoding — the WRITE side, checked against the spec's own rules.

``encode_hashmark`` was written from ``HASHMARK_PROTOCOL.md`` alone, without
reading the reference implementation's ``encode.ts``. That is what lets
``TestTheReferenceDecoderAcceptsOurRecords`` be a cross-implementation proof
instead of pyrxd agreeing with pyrxd.

The oracle here is deliberately NOT "does our encoder produce what our encoder
produced last time". It is:

* ``decode_hashmark`` — an independently written reader of the same spec, in this
  repository, whose own tests build their fixtures by hand and never call this
  encoder;
* ``verify_attestation`` — the §6.3 verdict a stranger computes;
* the byte counts and shapes the spec states outright (§3.2's 223, §13.5's 133);
* and the reference TypeScript decoder, run out-of-band (see that class).

Plants run against this file while writing it, each restored afterwards:
returning the digest push as ``OP_PUSHDATA1`` broke the minimal-push class;
dropping the low-S check in ``_sign_statement`` broke the high-S refusal;
signing the statement of the UNLABELLED record while writing a labelled one
broke ``test_editing_the_label_breaks_the_attestation``; and omitting the label
from ``canonical_statement`` broke the statement class.
"""

from __future__ import annotations

import os

import pytest

from pyrxd.keys import PrivateKey
from pyrxd.script.hashmark import (
    HASHMARK_MAGIC,
    RADIANT_MAINNET_GENESIS,
    AttestationOutcome,
    HashMarkOutcome,
    canonical_statement,
    canonicalize_label,
    decode_hashmark,
    encode_hashmark,
    max_label_bytes,
    verify_attestation,
)
from pyrxd.security.errors import ValidationError

#: SHA-256("test"), the spec's own worked example (§13.1).
_DIGEST = bytes.fromhex("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")
_SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def _key(*, compressed: bool = True) -> PrivateKey:
    """A throwaway signing key. NEVER hand-written: a hand-typed scalar can be
    weak, out of range, or — worse — real."""
    key = PrivateKey(os.urandom(32))
    key.compressed = compressed
    return key


@pytest.fixture
def key() -> PrivateKey:
    return _key()


def _split(script: bytes) -> list[bytes]:
    """The record's pushes, for tests that need to plant a defect in one of them."""
    out, i = [], 1
    assert script[0] == 0x6A
    while i < len(script):
        op = script[i]
        if op <= 0x4B:
            n, i = op, i + 1
        elif op == 0x4C:
            n, i = script[i + 1], i + 2
        else:  # pragma: no cover - our encoder never emits anything else
            raise AssertionError(f"unexpected opcode {op:#04x}")
        out.append(script[i : i + n])
        i += n
    return out


def _rebuild(pushes: list[bytes], *, non_minimal_at: int | None = None) -> bytes:
    """Reassemble a record from pushes, optionally spelling one push the long way.

    ``non_minimal_at`` writes that push as ``OP_PUSHDATA1`` even when its length
    fits a direct push — §4.1's canonical counter-example, and the only way to
    test that a record has exactly one valid serialization.
    """
    script = b"\x6a"
    for idx, data in enumerate(pushes):
        if idx == non_minimal_at or len(data) > 0x4B:
            script += b"\x4c" + bytes([len(data)]) + data
        else:
            script += bytes([len(data)]) + data
    return script


class TestTheRecordRoundTrips:
    def test_a_record_with_no_label_decodes_back_to_its_inputs(self, key: PrivateKey) -> None:
        record = decode_hashmark(encode_hashmark(_DIGEST, key))
        assert record.outcome is HashMarkOutcome.OK
        assert record.version == 2
        assert record.algorithm_id == 1
        assert record.algorithm == "sha256"
        assert record.digest_hex == _DIGEST.hex()
        assert record.label is None
        assert record.label_withheld is None
        assert record.signer_hash160_hex == key.public_key().hash160().hex()
        assert record.signature_hex is not None and len(bytes.fromhex(record.signature_hex)) == 65

    def test_a_record_with_a_label_decodes_back_to_its_inputs(self, key: PrivateKey) -> None:
        record = decode_hashmark(encode_hashmark(_DIGEST, key, label="Contract draft"))
        assert record.outcome is HashMarkOutcome.OK
        assert record.label == "Contract draft"
        assert record.digest_hex == _DIGEST.hex()
        assert record.signer_hash160_hex == key.public_key().hash160().hex()

    @pytest.mark.parametrize("label", [None, "Contract draft"])
    def test_the_signature_verifies_as_an_attestation(self, key: PrivateKey, label: str | None) -> None:
        """§6.3, computed by the same function a stranger runs: recover the key
        over the statement and require it to match the committed signer."""
        result = verify_attestation(decode_hashmark(encode_hashmark(_DIGEST, key, label=label)))
        assert result.outcome is AttestationOutcome.VALID
        assert result.recovered_hash160_hex == key.public_key().hash160().hex()

    def test_the_unlabelled_record_is_the_specs_133_bytes(self, key: PrivateKey) -> None:
        """§13.5 states the size of a real unlabelled v2 record outright. Matching
        it is a check on the whole layout at once — a spurious push, a missing
        one, or a length prefix spelled the long way all change this number."""
        assert len(encode_hashmark(_DIGEST, key)) == 133

    def test_the_byte_layout_is_the_specs(self, key: PrivateKey) -> None:
        """§4: OP_RETURN, magic, 2-byte header, digest, signer, signature."""
        script = encode_hashmark(_DIGEST, key)
        assert script[0] == 0x6A
        pushes = _split(script)
        assert len(pushes) == 5
        assert pushes[0] == HASHMARK_MAGIC
        assert pushes[1] == bytes([2, 1])  # version 2, algorithmId 1 — one push, so neither has a second spelling
        assert pushes[2] == _DIGEST
        assert pushes[3] == key.public_key().hash160()
        assert len(pushes[4]) == 65

    def test_the_fixed_prefix_matches_a_real_mainnet_record(self, key: PrivateKey) -> None:
        """The first 12 bytes of §13.5's on-chain record are fixed for every
        unlabelled sha256 v2 mark: OP_RETURN, the magic push, the header push and
        the digest's length byte. Ours must be byte-identical."""
        assert encode_hashmark(_DIGEST, key)[:12] == bytes.fromhex("6a08484153484d41524b020201")[:12]


class TestTheLabelIsInsideTheSignedStatement:
    """§5.4: in v2 a label is signed, so it cannot be added, removed or edited."""

    def test_the_statement_omits_label_entirely_when_absent(self, key: PrivateKey) -> None:
        statement = canonical_statement(decode_hashmark(encode_hashmark(_DIGEST, key)))
        assert '"label"' not in statement
        assert statement.endswith(f'"digest":"{_DIGEST.hex()}"}}')

    def test_the_statement_carries_the_label_when_present(self, key: PrivateKey) -> None:
        statement = canonical_statement(decode_hashmark(encode_hashmark(_DIGEST, key, label="Contract draft")))
        assert statement.endswith('"label":"Contract draft"}')

    def test_the_same_digest_signed_with_and_without_a_label_gives_different_bytes(self, key: PrivateKey) -> None:
        """Not merely a different record — a different STATEMENT, hence a
        different signature. An absent label is no push at all, never an empty
        one, and the two are not interchangeable."""
        bare = decode_hashmark(encode_hashmark(_DIGEST, key))
        labelled = decode_hashmark(encode_hashmark(_DIGEST, key, label="Contract draft"))
        assert canonical_statement(bare) != canonical_statement(labelled)
        assert bare.signature_hex != labelled.signature_hex

    def test_stripping_the_label_breaks_the_attestation(self, key: PrivateKey) -> None:
        pushes = _split(encode_hashmark(_DIGEST, key, label="Contract draft"))
        stripped = decode_hashmark(_rebuild(pushes[:5]))
        assert stripped.outcome is HashMarkOutcome.OK, "removing the label leaves a well-formed record"
        assert verify_attestation(stripped).outcome is AttestationOutcome.INVALID_SIGNATURE

    def test_editing_the_label_breaks_the_attestation(self, key: PrivateKey) -> None:
        """Same length, so nothing about the record's SHAPE changes — only what
        it says. That is the case a length check cannot catch."""
        pushes = _split(encode_hashmark(_DIGEST, key, label="Contract draft"))
        pushes[5] = b"Contract final"
        assert len(pushes[5]) == 14
        edited = decode_hashmark(_rebuild(pushes))
        assert edited.outcome is HashMarkOutcome.OK and edited.label == "Contract final"
        assert verify_attestation(edited).outcome is AttestationOutcome.INVALID_SIGNATURE


class TestTheLabelCap:
    def test_a_label_at_exactly_the_cap_produces_a_223_byte_record(self, key: PrivateKey) -> None:
        """§3.2: "v2 is designed to reach exactly 223 so it also relays on a node
        configured down to MAX_OP_RETURN_RELAY". The cap is derived FROM that
        number, so hitting it exactly is the check that the derivation is right."""
        script = encode_hashmark(_DIGEST, key, label="a" * max_label_bytes())
        assert len(script) == 223
        record = decode_hashmark(script)
        assert record.outcome is HashMarkOutcome.OK and record.label == "a" * 88
        assert verify_attestation(record).outcome is AttestationOutcome.VALID

    def test_the_cap_for_sha256_is_the_specs_88(self) -> None:
        assert max_label_bytes(0x01) == 88

    def test_one_byte_over_the_cap_is_refused_with_the_measured_size(self, key: PrivateKey) -> None:
        with pytest.raises(ValidationError) as exc:
            encode_hashmark(_DIGEST, key, label="a" * (max_label_bytes() + 1))
        assert "89" in str(exc.value) and "88" in str(exc.value)

    def test_the_cap_is_measured_in_utf8_bytes_not_characters(self, key: PrivateKey) -> None:
        """§5.4's own example: "A 43-character emoji string is 172 bytes and
        exceeds every version's cap." 22 four-byte emoji are exactly 88 bytes and
        fit; 23 are 92 and do not — while both are far under 88 CHARACTERS."""
        assert len(encode_hashmark(_DIGEST, key, label="\U0001f642" * 22)) == 223
        with pytest.raises(ValidationError) as exc:
            encode_hashmark(_DIGEST, key, label="\U0001f642" * 23)
        assert "92 UTF-8 bytes" in str(exc.value) and "23 characters" in str(exc.value)

    def test_max_label_bytes_refuses_an_algorithm_it_cannot_size(self) -> None:
        with pytest.raises(ValidationError, match="0x02"):
            max_label_bytes(0x02)


class TestLabelsTheSpecRejects:
    """§5.4's character table, one case per class it names.

    In v2 these are not a rendering problem — the label is signed, so a label
    that cannot be shown safely cannot be signed honestly. The encoder must
    refuse at build time rather than emit a record the decoder calls INVALID.
    """

    @pytest.mark.parametrize(
        ("label", "why"),
        [
            ("draft\x00v2", "C0 NUL"),
            ("draft\nv2", "C0 line feed"),
            ("draft\x1b[2Kv2", "C0 escape, a terminal sequence"),
            ("draft\x7fv2", "DEL"),
            ("draft\x85v2", "C1 next-line"),
            ("draft v2", "U+2028 line separator"),
            ("draft v2", "U+2029 paragraph separator"),
            ("draft‮v2", "U+202E right-to-left override"),
            ("draft⁦v2", "U+2066 first-strong isolate"),
            ("draft​v2", "U+200B zero-width space"),
            ("draft‎v2", "U+200E left-to-right mark"),
            ("draft؜v2", "U+061C Arabic letter mark"),
            ("draft﻿v2", "U+FEFF byte-order mark"),
        ],
    )
    def test_each_rejected_class_is_refused_at_build_time(self, key: PrivateKey, label: str, why: str) -> None:
        with pytest.raises(ValidationError, match="5.4"):
            encode_hashmark(_DIGEST, key, label=label)

    @pytest.mark.parametrize(
        "label",
        [
            "Café résumé",  # accents, NFC already
            "क्‍ष",  # ZWJ, load-bearing in Devanagari
            "ن‌ام",  # ZWNJ, load-bearing in Persian
            "\U0001f468‍\U0001f4bb engineer",  # ZWJ emoji sequence
            "Q3 accounts — final",
            "a",
        ],
    )
    def test_honest_labels_are_accepted(self, key: PrivateKey, label: str) -> None:
        """Paired with the class above deliberately. §5.4 says ZWNJ and ZWJ are
        NOT rejected — "they are joiners, cannot reorder anything, and are
        load-bearing in Devanagari and emoji sequences" — so a guard that swept
        up every invisible codepoint would be refusing honest work, which is a
        defect and not a safe default."""
        record = decode_hashmark(encode_hashmark(_DIGEST, key, label=label))
        assert record.outcome is HashMarkOutcome.OK and record.label == label
        assert verify_attestation(record).outcome is AttestationOutcome.VALID

    def test_a_label_that_is_not_nfc_is_refused_and_canonicalize_label_fixes_it(self, key: PrivateKey) -> None:
        decomposed = "Café"  # e + combining acute
        with pytest.raises(ValidationError, match="NFC"):
            encode_hashmark(_DIGEST, key, label=decomposed)
        canonical = canonicalize_label(decomposed)
        assert canonical == "Café" and canonical != decomposed
        assert decode_hashmark(encode_hashmark(_DIGEST, key, label=canonical)).label == canonical

    def test_untrimmed_whitespace_is_refused_and_canonicalize_label_fixes_it(self, key: PrivateKey) -> None:
        with pytest.raises(ValidationError, match="whitespace"):
            encode_hashmark(_DIGEST, key, label="  Contract draft  ")
        assert canonicalize_label("  Contract draft  ") == "Contract draft"

    def test_canonicalize_label_refuses_a_line_separator_rather_than_trimming_it(self) -> None:
        """Python's str.strip() treats U+2028 as whitespace, so canonicalising
        first would silently DELETE a line separator sitting at either end —
        exactly the codepoint §5.4 lists because it hides what is rendered.
        Rejected codepoints are therefore checked before the trim."""
        with pytest.raises(ValidationError, match="U\\+2028"):
            canonicalize_label(" Contract draft")
        with pytest.raises(ValidationError, match="U\\+2029"):
            canonicalize_label("Contract draft ")

    def test_an_empty_label_is_refused_rather_than_silently_omitted(self, key: PrivateKey) -> None:
        """§5.4: "An empty label is not representable. Omit the push entirely
        rather than writing a zero-length one." Omitting it silently would
        publish an unlabelled mark to a caller who believes they labelled one —
        and in v2 that is a different signed statement, not a cosmetic
        difference."""
        with pytest.raises(ValidationError, match="omit the label"):
            encode_hashmark(_DIGEST, key, label="")

    def test_a_whitespace_only_label_is_refused_by_both_halves(self, key: PrivateKey) -> None:
        """Found by this test: ``canonicalize_label`` used to hand back ``""``
        here, which the encoder then refused one call later — so a CLI would
        have shown the user an empty label and then reported an encoder fault
        rather than an answer about their input."""
        with pytest.raises(ValidationError, match="whitespace"):
            encode_hashmark(_DIGEST, key, label="   ")
        with pytest.raises(ValidationError, match="omit the label"):
            canonicalize_label("   ")
        with pytest.raises(ValidationError, match="omit the label"):
            canonicalize_label("\u3000")  # ideographic space: whitespace, not a C0 control


class TestTheDigestAndAlgorithm:
    @pytest.mark.parametrize("length", [0, 20, 31, 33, 64])
    def test_a_digest_of_the_wrong_width_is_refused(self, key: PrivateKey, length: int) -> None:
        """§5.3: N comes from the algorithm registry, never from the push length.
        On the write side that means a 31-byte digest is refused, never padded."""
        with pytest.raises(ValidationError, match="expected 32"):
            encode_hashmark(os.urandom(length), key)

    @pytest.mark.parametrize("algorithm_id", [0x00, 0x02, 0xFF])
    def test_an_unassigned_algorithm_id_is_refused(self, key: PrivateKey, algorithm_id: int) -> None:
        with pytest.raises(ValidationError, match="not implemented"):
            encode_hashmark(_DIGEST, key, algorithm_id=algorithm_id)


class TestTheSignature:
    def test_a_compressed_key_sets_the_header_compression_bit(self) -> None:
        """§5.6: header is 27 + recoveryId, +4 when the key is compressed."""
        record = decode_hashmark(encode_hashmark(_DIGEST, _key(compressed=True)))
        assert bytes.fromhex(record.signature_hex or "")[0] >= 31

    def test_an_uncompressed_key_does_not_and_still_verifies(self) -> None:
        """The branch nobody builds for. The committed hash160 and the header's
        compression bit come from one flag, so if they ever drift apart the
        recovered key hashes to something else and the record can never verify —
        a failure that would only ever show on the path not exercised."""
        key = _key(compressed=False)
        record = decode_hashmark(encode_hashmark(_DIGEST, key))
        header = bytes.fromhex(record.signature_hex or "")[0]
        assert 27 <= header <= 30
        assert record.signer_hash160_hex == key.public_key().hash160(False).hex()
        assert record.signer_hash160_hex != key.public_key().hash160(True).hex()
        assert verify_attestation(record).outcome is AttestationOutcome.VALID

    def test_the_emitted_signature_is_low_s(self, key: PrivateKey) -> None:
        for _ in range(8):  # a different nonce each time; low-S must hold for all
            record = decode_hashmark(encode_hashmark(os.urandom(32), key))
            s = int.from_bytes(bytes.fromhex(record.signature_hex or "")[33:65], "big")
            assert 1 <= s <= _SECP256K1_N // 2

    def test_a_planted_high_s_signature_is_refused(self, key: PrivateKey) -> None:
        """s -> n-s is the same signature mathematically; §5.6 makes it a
        REFUSAL, so a verifier has exactly one accepted form."""
        pushes = _split(encode_hashmark(_DIGEST, key))
        signature = pushes[4]
        high_s = (_SECP256K1_N - int.from_bytes(signature[33:65], "big")).to_bytes(32, "big")
        pushes[4] = bytes([signature[0] ^ 1]) + signature[1:33] + high_s  # flip recovery id parity too
        record = decode_hashmark(_rebuild(pushes))
        assert record.outcome is HashMarkOutcome.OK, "the bytes are well-formed; the claim is what fails"
        result = verify_attestation(record)
        assert result.outcome is AttestationOutcome.INVALID_SIGNATURE
        assert result.detail is not None and "low-S" in result.detail

    def test_the_encoder_refuses_to_emit_a_high_s_signature(self, key: PrivateKey, monkeypatch) -> None:
        """Reached through ``encode_hashmark``, the production entry point, with
        only the signature FORMATTER replaced — the statement, the key and the
        assembly are the real ones. Without this the low-S check in
        ``_sign_statement`` has no test that can fail, because libsecp256k1
        normalises s and an honest run can never reach it."""
        import base64

        import pyrxd.utils as utils

        real = utils.stringify_ecdsa_recoverable

        def high_s(signature: bytes, compressed: bool = True) -> str:
            out = bytearray(base64.b64decode(real(signature, compressed)))
            out[33:65] = (_SECP256K1_N - int.from_bytes(out[33:65], "big")).to_bytes(32, "big")
            return base64.b64encode(bytes(out)).decode("ascii")

        monkeypatch.setattr(utils, "stringify_ecdsa_recoverable", high_s)
        with pytest.raises(ValidationError, match="low-S"):
            encode_hashmark(_DIGEST, key)

    def test_the_encoder_refuses_a_signature_that_recovers_to_another_key(self, key: PrivateKey, monkeypatch) -> None:
        """The sign-then-verify guard. Flipping the header's recovery id yields a
        structurally perfect record whose signature recovers to a DIFFERENT key
        than the one it commits to — no length is wrong, no range check fires,
        and on chain it would be a permanent, unverifiable mark under someone's
        name."""
        import base64

        import pyrxd.utils as utils

        real = utils.stringify_ecdsa_recoverable

        def wrong_recovery_id(signature: bytes, compressed: bool = True) -> str:
            out = bytearray(base64.b64decode(real(signature, compressed)))
            out[0] = 27 + (((out[0] - 27) & 3) ^ 1) + (4 if compressed else 0)
            return base64.b64encode(bytes(out)).decode("ascii")

        monkeypatch.setattr(utils, "stringify_ecdsa_recoverable", wrong_recovery_id)
        with pytest.raises(ValidationError, match="does not verify"):
            encode_hashmark(_DIGEST, key)


class TestMinimalPushIsMandatory:
    """§4.1: "every record has exactly one valid serialization"."""

    def test_the_encoder_uses_the_direct_push_form_wherever_it_fits(self, key: PrivateKey) -> None:
        script = encode_hashmark(_DIGEST, key)
        assert 0x4C not in {script[0 + 1], script[10], script[13], script[46], script[67]}
        assert script[1] == 0x08 and script[10] == 0x02 and script[13] == 0x20
        assert script[46] == 0x14 and script[67] == 0x41

    def test_the_encoder_uses_pushdata1_only_where_it_must(self, key: PrivateKey) -> None:
        """A label over 75 bytes has no direct-push spelling, so OP_PUSHDATA1 IS
        the minimal form there — §4.1 rejects it only when it carries <= 75."""
        script = encode_hashmark(_DIGEST, key, label="a" * 76)
        assert script[133] == 0x4C and script[134] == 76
        assert decode_hashmark(script).outcome is HashMarkOutcome.OK

    @pytest.mark.parametrize(("index", "field"), [(0, "magic"), (1, "header"), (2, "digest"), (4, "signature")])
    def test_a_non_minimal_push_makes_it_not_a_hashmark(self, key: PrivateKey, index: int, field: str) -> None:
        """Not INVALID — NOT_HASHMARK. The spec calls a record with a second
        spelling not a HashMark at all, which is the right verdict: a scanner
        that reported it as malformed would file another protocol's output as a
        broken mark."""
        pushes = _split(encode_hashmark(_DIGEST, key))
        assert decode_hashmark(_rebuild(pushes)).outcome is HashMarkOutcome.OK, "control: the plant is the only change"
        planted = _rebuild(pushes, non_minimal_at=index)
        assert len(planted) == 134, "a non-minimal push is exactly one byte longer"
        assert decode_hashmark(planted).outcome is HashMarkOutcome.NOT_HASHMARK


class TestTheNetworkBinding:
    """§2.10 and §5.6: the genesis hash is in the statement, not in the record."""

    _TESTNET_GENESIS = "000000009d67e3ee6d8d1ea2e5e3f4d9eab9ee5ee2e7f4a1f9f7c9e4b5c3a2d1"

    def test_the_genesis_hash_changes_the_signature(self, key: PrivateKey) -> None:
        mainnet = decode_hashmark(encode_hashmark(_DIGEST, key))
        other = decode_hashmark(encode_hashmark(_DIGEST, key, network_genesis=self._TESTNET_GENESIS))
        assert mainnet.signature_hex != other.signature_hex
        assert mainnet.digest_hex == other.digest_hex, "the RECORD bytes are otherwise identical"
        assert mainnet.signer_hash160_hex == other.signer_hash160_hex

    def test_a_mark_made_for_another_chain_does_not_verify_as_mainnet(self, key: PrivateKey) -> None:
        """ "A mark made on testnet must never verify as a mainnet proof." The
        same bytes, read on the wrong chain, are a different statement."""
        record = decode_hashmark(encode_hashmark(_DIGEST, key, network_genesis=self._TESTNET_GENESIS))
        assert verify_attestation(record).outcome is AttestationOutcome.INVALID_SIGNATURE
        assert verify_attestation(record, network_genesis=self._TESTNET_GENESIS).valid

    def test_the_default_is_mainnet(self, key: PrivateKey) -> None:
        record = decode_hashmark(encode_hashmark(_DIGEST, key))
        assert verify_attestation(record, network_genesis=RADIANT_MAINNET_GENESIS).valid
