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


class TestAHandBuiltRecordGetsAVerdictNotATraceback:
    """``verify_attestation`` is public, and an offline verifier builds the record from stored
    fields rather than from ``decode_hashmark``. Its contract is one of four outcomes; a field of
    the wrong type raised instead — ``algorithm_id=None`` reached ``f"{None:02x}"``."""

    @staticmethod
    def _honest() -> HashMarkRecord:
        return decode_hashmark(_signed_record(PrivateKey()))

    @pytest.mark.parametrize(
        "overrides",
        [
            {"algorithm_id": None},
            {"algorithm_id": "01"},
            {"algorithm_id": 256},
            {"algorithm_id": -1},
            # `bool` is an int and f"{True:02x}" is "01": without its own refusal this record would
            # be verified as algorithm 1 while claiming an algorithm of True.
            {"algorithm_id": True},
            {"digest_hex": None},
            {"digest_hex": b"\x00" * 32},
            {"label": 7},
            {"signer_hash160_hex": b"\x00" * 20},
            {"signature_hex": b"\x00" * 65},
        ],
        ids=repr,
    )
    def test_a_field_of_the_wrong_type_is_refused_with_a_reason(self, overrides: dict) -> None:
        from dataclasses import replace

        result = verify_attestation(replace(self._honest(), **overrides))
        assert result.outcome is AttestationOutcome.INVALID_SIGNATURE
        assert result.detail

    @pytest.mark.parametrize(
        "genesis",
        [None, b"\x00" * 32, 0, 123, "mainnet", "", RADIANT_MAINNET_GENESIS.upper(), RADIANT_MAINNET_GENESIS + " "],
        ids=["none", "bytes", "zero", "int", "a-network-name", "empty", "uppercase", "padded"],
    )
    def test_the_callers_bad_genesis_raises_and_is_never_a_verdict_on_an_honest_record(self, genesis) -> None:
        """The genesis is the CALLER's context, not the record's. The first version of this check
        returned INVALID_SIGNATURE for it — "DOES NOT VERIFY", an accusation against an honest
        signer for the caller's mistake, the direction a broken backend is kept out of. It raises."""
        from pyrxd.security.errors import ValidationError

        with pytest.raises(ValidationError, match="network_genesis must be"):
            verify_attestation(self._honest(), network_genesis=genesis)

    def test_the_honest_pair_a_well_formed_genesis_is_accepted_known_or_not(self) -> None:
        """Only the SPELLING is the reader's rule. A reader verifies against the chain it found the
        record on and cannot choose it, so a well-formed genesis pyrxd has no constant for is a
        real answer — "does not verify on that chain" — not a refusal."""
        record = self._honest()
        assert verify_attestation(record).valid
        assert verify_attestation(record, network_genesis="00" * 32).outcome is AttestationOutcome.INVALID_SIGNATURE

    def test_a_defect_in_the_RECORD_is_still_a_verdict_with_any_good_genesis(self) -> None:
        """The other direction: moving the caller's error to a raise must not move the RECORD's."""
        from dataclasses import replace

        result = verify_attestation(replace(self._honest(), algorithm_id=None), network_genesis=RADIANT_MAINNET_GENESIS)
        assert result.outcome is AttestationOutcome.INVALID_SIGNATURE and "algorithm id" in (result.detail or "")

    def test_the_honest_pair_the_same_record_unmodified_verifies(self) -> None:
        assert verify_attestation(self._honest()).valid


class TestARecoveryBackendsAnswerIsCheckedNotTrusted:
    """A registered backend is process-global and wins over coincurve, and its return was only
    ever HASHED. Any 33 bytes whose hash160 matched the committed signer made the record VALID —
    whether or not they were a public key, and whatever form ``compressed`` asked for."""

    @pytest.fixture(autouse=True)
    def _no_backend_leaks(self):
        from pyrxd.script.hashmark import set_recovery_backend

        yield
        set_recovery_backend(None)

    @staticmethod
    def _committed_to(fake_key: bytes) -> HashMarkRecord:
        """A record whose committed signer is ``hash160(fake_key)``, with a compressed-header
        signature that passes every range check — so only the backend's answer decides it."""
        from pyrxd.hash import hash160

        sig = bytes([31]) + (1).to_bytes(32, "big") + (1).to_bytes(32, "big")
        return HashMarkRecord(
            HashMarkOutcome.OK,
            version=2,
            algorithm_id=1,
            algorithm="sha256",
            digest_hex=_DIGEST.hex(),
            signer_hash160_hex=hash160(fake_key).hex(),
            signature_hex=sig.hex(),
        )

    @pytest.mark.parametrize(
        "fake",
        [b"\x05" + bytes(32), bytes(33), b"\x04" + bytes(32)],
        ids=["prefix-05", "prefix-00", "uncompressed-prefix-at-compressed-length"],
    )
    def test_bytes_that_are_not_a_compressed_key_cannot_make_a_record_VALID(self, fake: bytes) -> None:
        from pyrxd.script.hashmark import set_recovery_backend

        set_recovery_backend(lambda *_a: fake)
        result = verify_attestation(self._committed_to(fake))
        assert result.outcome is AttestationOutcome.UNVERIFIABLE, result
        assert "recovery backend returned" in (result.detail or "")

    def test_the_right_key_in_the_wrong_form_is_not_an_accusation(self) -> None:
        """A backend that ignores ``compressed`` hashes the uncompressed key, which never matches a
        compressed commitment — and that read as DOES NOT VERIFY on an honest mark. It is the
        verifier that is broken, so it is NOT CHECKED."""
        from pyrxd.script.hashmark import _coincurve_backend, set_recovery_backend

        real = _coincurve_backend()
        assert callable(real)
        set_recovery_backend(lambda h, r, s, rid, compressed: real(h, r, s, rid, not compressed))
        result = verify_attestation(decode_hashmark(_signed_record(PrivateKey())))
        assert result.outcome is AttestationOutcome.UNVERIFIABLE, result

    def test_a_return_that_is_not_bytes_is_not_a_verdict_either(self) -> None:
        from pyrxd.script.hashmark import set_recovery_backend

        set_recovery_backend(lambda *_a: "02" + "00" * 32)
        assert verify_attestation(decode_hashmark(_signed_record(PrivateKey()))).outcome is (
            AttestationOutcome.UNVERIFIABLE
        )

    def test_the_honest_pair_a_backend_answering_correctly_still_verifies(self) -> None:
        from pyrxd.script.hashmark import _coincurve_backend, set_recovery_backend

        real = _coincurve_backend()
        assert callable(real)
        set_recovery_backend(real)
        assert verify_attestation(decode_hashmark(_signed_record(PrivateKey()))).valid


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

    def test_the_resolver_result_is_sanitized_before_it_is_stored(self, monkeypatch) -> None:
        """At the boundary, not at the renderer — so the JSON path and any other
        consumer get the cleaned value too, and no future renderer has to remember.

        Asserted through the function rather than against its source text: the first
        version of this test grepped the body and broke the moment the function was
        split in two, while the behaviour it cared about was still correct."""
        from pyrxd.cli import glyph_inspect
        from pyrxd.glyph import wave

        hostile = "\x1b[2A\x1b[0J  WAVE identity: treasury.rxd"

        async def _names(_client, _hash160):
            return [hostile, "honest.rxd"]

        class _Client:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                return False

        monkeypatch.setattr(wave, "wave_names_for_hash160", _names)
        ctx = type("Ctx", (), {"make_client": lambda self: _Client()})()

        record = {"attestation": {"outcome": "valid", "recovered_hash160": "ab" * 20}}
        glyph_inspect._resolve_one_wave_identity(ctx, record)

        stored = record["wave_identity"]["names_resolving_now"]
        assert "\x1b" not in stored[0], "the escape reached the stored record"
        assert stored[1] == "honest.rxd", "an ordinary name must survive untouched"


class TestTheAttestationUsesTheChainItWasFoundOn:
    """§6.3 step 2: rebuild the statement with the genesis of the chain the
    transaction was ACTUALLY found on.

    The genesis hash is inside the signed statement, so the same bytes on another
    chain are a different statement and verify against a different key. Mainnet was
    hardcoded, so `pyrxd --network testnet glyph inspect ...` attested against
    mainnet and announced "assuming radiant-mainnet" — an answer to a question the
    user had explicitly not asked.

    Mainnet stays the DEFAULT rather than becoming an error: a pasted script
    genuinely carries no context, and refusing to attest it would be worse than
    assuming and saying so.
    """

    SCRIPT = (
        b"\x6a\x08HASHMARK\x02"
        + bytes([2, 1])
        + b"\x20"
        + bytes(32)
        + b"\x14"
        + bytes(20)
        + b"\x41"
        + bytes([31])
        + bytes(64)
    ).hex()

    def _assumed(self, network: str) -> str:
        from pyrxd.glyph._inspect_core import _inspect_script

        return _inspect_script(self.SCRIPT, network=network)["hashmark"]["attestation"]["assumed_network"]

    @pytest.mark.parametrize("network", ["mainnet", "testnet", "regtest"])
    def test_each_known_network_is_used_and_reported(self, network: str) -> None:
        assert self._assumed(network) == f"radiant-{network}"

    def test_the_default_is_still_mainnet(self) -> None:
        from pyrxd.glyph._inspect_core import _inspect_script

        assert _inspect_script(self.SCRIPT)["hashmark"]["attestation"]["assumed_network"] == "radiant-mainnet"

    def test_the_genesis_used_actually_DIFFERS_per_network(self) -> None:
        """Guards the tests above. If these ever coincided, reporting the right name
        beside the wrong genesis would look identical to correct behaviour."""
        from pyrxd.network.registry import genesis_hash_for

        hashes = {genesis_hash_for(n) for n in ("mainnet", "testnet", "regtest")}
        assert len(hashes) == 3 and None not in hashes

    def test_an_unknown_network_falls_back_to_mainnet_AND_SAYS_SO(self) -> None:
        """The label must never disagree with the genesis actually used. Reporting
        the requested name beside a mainnet genesis would state an assumption the
        code did not make — worse than the hardcoding this replaced, because the
        reader could not tell the verdict was against a different chain."""
        assert self._assumed("nonesuch") == "radiant-mainnet"

    def test_the_CLI_passes_its_network_at_every_entry_point(self) -> None:
        """Reachability: the parameter exists and is threaded, but a call site that
        forgets it silently reverts to the hardcoded behaviour."""
        import inspect as _i

        from pyrxd.cli import glyph_inspect

        source = _i.getsource(glyph_inspect)
        for call in ("_inspect_script(value", "_inspect_txid_inner(client, value"):
            index = source.index(call)
            assert "network=ctx.network" in source[index : index + 200], call


class TestTheLabelTableMatchesTheSPEC:
    """Every codepoint §5.4's table names, enumerated — not one per row.

    The implementation stores ranges (`0x00-0x1F`, `0x202A-0x202E`) and the tests
    above sample one member of each. That is a hand-kept set checked by a hand-kept
    set: an off-by-one at a range edge, or a row transcribed with the wrong endpoint,
    passes both. The spec's table is small enough to write out in full, so it is.

    Both directions, because a table that over-rejects is also wrong: U+200C and
    U+200D are explicitly exempted as joiners that "cannot reorder anything and are
    load-bearing in Devanagari and emoji sequences", and refusing them would refuse
    honest labels in several scripts.
    """

    #: §5.4, every codepoint named, expanded from the ranges the spec writes.
    SPEC_REJECTED = (
        *range(0x00, 0x20),  # C0
        0x7F,  # DEL
        *range(0x80, 0xA0),  # C1
        0x2028,  # line separator
        0x2029,  # paragraph separator
        0x061C,  # ALM
        0x200B,  # ZWSP
        0x200E,  # LRM
        0x200F,  # RLM
        *range(0x202A, 0x202F),  # embeddings and overrides
        *range(0x2066, 0x206A),  # isolates
        0xFEFF,  # BOM / ZWNBSP
    )
    #: Explicitly NOT rejected by the same section.
    SPEC_ALLOWED = (0x200C, 0x200D)

    def test_every_codepoint_the_spec_rejects_is_rejected(self) -> None:
        from pyrxd.script.hashmark import _label_defect

        accepted = [f"U+{c:04X}" for c in self.SPEC_REJECTED if _label_defect(f"a{chr(c)}b") is None]
        assert not accepted, f"§5.4 names these as rejected and the decoder accepts them: {accepted}"

    def test_no_codepoint_the_spec_allows_is_rejected(self) -> None:
        from pyrxd.script.hashmark import _label_defect

        refused = [f"U+{c:04X}" for c in self.SPEC_ALLOWED if _label_defect(f"a{chr(c)}b") is not None]
        assert not refused, f"§5.4 exempts these joiners and the decoder refuses them: {refused}"

    def test_the_edges_of_each_range_are_covered(self) -> None:
        """A range written one short at either end still passes a one-per-row sample."""
        from pyrxd.script.hashmark import _label_defect

        for lo, hi in ((0x00, 0x1F), (0x80, 0x9F), (0x202A, 0x202E), (0x2066, 0x2069)):
            assert _label_defect(f"a{chr(lo)}b") is not None, f"low edge U+{lo:04X}"
            assert _label_defect(f"a{chr(hi)}b") is not None, f"high edge U+{hi:04X}"

    def test_the_characters_just_OUTSIDE_each_range_are_allowed(self) -> None:
        """The other half — a range written one too WIDE refuses honest text. U+0020
        is a space and U+00A0 a non-breaking space; both are ordinary label content."""
        from pyrxd.script.hashmark import _label_defect

        # NB U+2029 is NOT a valid "just outside" probe for the U+202A range: the
        # spec rejects it separately as a paragraph separator. Writing it here as
        # `0x202A - 1` is the mistake this list exists to avoid making in the code.
        for cp in (0x20, 0xA0, 0x202F, 0x2030, 0x206A, 0x2027, 0x2065, 0x0619):
            assert _label_defect(f"a{chr(cp)}b") is None, f"U+{cp:04X} is outside every rejected range"

    def test_a_decoder_NEVER_substitutes_U_FFFD(self) -> None:
        """§5.4: "Malformed sequences are a malformed record, not text with odd
        characters in it — a decoder must not substitute U+FFFD"."""
        from pyrxd.script.hashmark import HashMarkOutcome, decode_hashmark

        raw = b"\x6a" + _push(b"HASHMARK") + _push(bytes([1, 1])) + _push(_DIGEST) + _push(b"\xff\xfe bad")
        record = decode_hashmark(raw)
        assert record.outcome is HashMarkOutcome.INVALID
        assert "�" not in (record.label or ""), "a substituted replacement character IS the defect"

    def test_a_zero_length_label_push_is_NOT_HASHMARK(self) -> None:
        """§5.4 says an empty label is not representable, and §6.1 step 2 says a
        non-minimal push fails BEFORE the magic is read — "no magic seen yet, so no
        HashMark claim". A zero-length push is `OP_0`, which §4.1 rejects, so the
        outcome is NOT_HASHMARK rather than INVALID. Pinned because the plausible
        wrong answer (INVALID, since the magic is right there in the bytes) reads
        more helpful and is what a reasonable person would implement."""
        from pyrxd.script.hashmark import HashMarkOutcome, decode_hashmark

        raw = b"\x6a" + _push(b"HASHMARK") + _push(bytes([1, 1])) + _push(_DIGEST) + b"\x00"
        assert decode_hashmark(raw).outcome is HashMarkOutcome.NOT_HASHMARK
