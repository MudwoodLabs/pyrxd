"""A computed verdict that no human sees is not a feature.

The pasted-script view printed the HashMark digest, signer and attestation verdict.
The txid view — the DEFAULT path, and the only one that reaches a record actually on
chain — printed the type label alone. Everything else was computed and discarded, so
a v2 whose signature DOES NOT VERIFY and a genuine one rendered byte-identically,
with the affirmative-sounding `op_return-hashmark-v2` label surviving and the verdict
dropped. `--json` had it; the terminal did not.

`--verify-wave` had the mirror-image bug: it read `payload["hashmark"]`, which exists
only for a pasted script, so on a txid it attached nothing and never said why — a
flag that silently did nothing on the form most people use it with.

There is now ONE renderer for both surfaces. Two copies is how one of them ends up
missing the line that matters; that is also how the label got sanitized on one path
and not the other in this same file.
"""

from __future__ import annotations

import pytest

from pyrxd.cli.glyph_inspect import _op_return_payload_lines, _render_txid_human


def _hashmark(outcome: str = "valid", **over) -> dict:
    hm = {
        "outcome": "ok",
        "version": 2,
        "algorithm": "sha256",
        "digest": "cd" * 32,
        "label": "invoice.pdf",
        "signer_hash160": "ab" * 20,
        "attestation": {
            "outcome": outcome,
            "detail": "recovered key does not match",
            "assumed_network": "radiant-mainnet",
        },
    }
    hm.update(over)
    return hm


def _tx(**row) -> dict:
    return {
        "txid": "aa" * 32,
        "version": 2,
        "locktime": 0,
        "byte_length": 250,
        "input_count": 1,
        "output_count": 1,
        "inputs": [],
        "outputs": [{"vout": 0, "satoshis": 0, "type": "op_return-hashmark-v2", **row}],
    }


class TestTheTxidViewShowsTheVerdict:
    def test_a_forged_record_says_it_does_not_verify(self) -> None:
        out = _render_txid_human(_tx(hashmark=_hashmark("invalid_signature")))
        assert "signature DOES NOT VERIFY" in out

    def test_a_genuine_record_says_it_verifies(self) -> None:
        assert "signature VERIFIED" in _render_txid_human(_tx(hashmark=_hashmark("valid")))

    def test_the_two_do_not_render_identically(self) -> None:
        """The actual defect. Both printed `type=op_return-hashmark-v2` and nothing
        else, so the only distinguishing line in the whole output was absent."""
        forged = _render_txid_human(_tx(hashmark=_hashmark("invalid_signature")))
        genuine = _render_txid_human(_tx(hashmark=_hashmark("valid")))
        assert forged != genuine

    def test_the_digest_and_signer_reach_the_terminal(self) -> None:
        out = _render_txid_human(_tx(hashmark=_hashmark()))
        assert "cd" * 32 in out and "ab" * 20 in out

    def test_a_message_output_reaches_the_terminal(self) -> None:
        out = _render_txid_human(
            _tx(
                type="op_return-msg",
                message={"outcome": "ok", "is_utf8": True, "text": "hello there", "byte_length": 11},
            )
        )
        assert "hello there" in out

    def test_an_ordinary_output_is_unaffected(self) -> None:
        """Honest path: the shared renderer must add nothing to a row with no payload."""
        out = _render_txid_human(_tx(type="p2pkh", owner_pkh="ee" * 20))
        assert "HashMark" not in out and "message" not in out


class TestOneRendererServesBothSurfaces:
    def test_the_same_lines_appear_at_either_indent(self) -> None:
        flat = _op_return_payload_lines({"hashmark": _hashmark("invalid_signature")})
        nested = _op_return_payload_lines({"hashmark": _hashmark("invalid_signature")}, indent="    ")
        assert [line.strip() for line in flat] == [line.strip() for line in nested]
        assert nested[0].startswith("    ") and not flat[0].startswith("    ")

    def test_both_human_surfaces_call_it(self) -> None:
        """Reachability. A helper with one caller is the copy problem again."""
        import inspect as _i

        from pyrxd.cli import glyph_inspect

        for fn in (glyph_inspect._render_script_human, glyph_inspect._render_txid_human):
            assert "_op_return_payload_lines" in _i.getsource(fn), fn.__name__


class TestVerifyWaveFindsBothShapes:
    def test_the_txid_shape_is_reached(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """It read `payload["hashmark"]` only, so this whole shape was invisible."""
        from pyrxd.cli import glyph_inspect

        seen = []
        monkeypatch.setattr(glyph_inspect, "_resolve_one_wave_identity", lambda ctx, hm: seen.append(hm))
        payload = {"outputs": [{"hashmark": {"tag": "a"}}, {"type": "p2pkh"}, {"hashmark": {"tag": "b"}}]}
        glyph_inspect._attach_wave_identity(None, payload)
        assert [h["tag"] for h in seen] == ["a", "b"], "every record in the tx, not just the first"

    def test_the_script_shape_still_works(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from pyrxd.cli import glyph_inspect

        seen = []
        monkeypatch.setattr(glyph_inspect, "_resolve_one_wave_identity", lambda ctx, hm: seen.append(hm))
        glyph_inspect._attach_wave_identity(None, {"hashmark": {"tag": "top"}})
        assert [h["tag"] for h in seen] == ["top"]

    def test_a_payload_with_no_record_does_nothing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from pyrxd.cli import glyph_inspect

        seen = []
        monkeypatch.setattr(glyph_inspect, "_resolve_one_wave_identity", lambda ctx, hm: seen.append(hm))
        glyph_inspect._attach_wave_identity(None, {"outputs": [{"type": "p2pkh"}]})
        assert seen == []


class TestGuardsThatMustNotRefuseValidWork:
    def test_a_short_real_message_is_classified(self) -> None:
        """`_MIN_SCRIPT_HEX_LEN` was calibrated to P2SH (23 bytes) and runs BEFORE
        dispatch, so a valid short `msg` was refused with "could not classify input"
        even though the classifier decodes it correctly."""
        from pyrxd.glyph._inspect_core import _classify_input, _inspect_script

        script = (b"\x6a" + b"\x03msg" + b"\x02hi").hex()
        assert len(script) < 46, "the case only exists below the old floor"
        # The dispatcher must recognise it as a script at all...
        assert _classify_input(script) == ("script", script)
        # ...and the classifier behind it always could decode it. That gap — a decoder
        # that works, behind a floor that refuses to call it — is the whole defect.
        assert _inspect_script(script)["type"] == "op_return-msg"

    @pytest.mark.parametrize(
        "sig,expected",
        [("ab" * 33, "33 bytes"), ("ab" * 64, "64 bytes"), ("zz", "not valid hex"), ("abc", "not valid hex")],
    )
    def test_a_malformed_signature_returns_a_verdict_rather_than_raising(self, sig: str, expected: str) -> None:
        """§6.3 step 3 makes "65 bytes" part of verifying. Without it a 33-byte value
        slices to an EMPTY s — int 0, a wrong-but-typed answer — and bad hex escaped
        as an uncaught ValueError instead of one of this function's own outcomes."""
        from pyrxd.script.hashmark import HashMarkOutcome, HashMarkRecord, verify_attestation

        record = HashMarkRecord(
            HashMarkOutcome.OK,
            version=2,
            signature_hex=sig,
            signer_hash160_hex="ab" * 20,
            digest_hex="cd" * 32,
            algorithm="sha256",
        )
        result = verify_attestation(record)  # must not raise
        assert result.outcome.value == "invalid_signature" and expected in (result.detail or "")


class TestLoweringTheScriptFloorDidNotSwALLOWOtherForms:
    """`_MIN_SCRIPT_HEX_LEN` went 46 -> 12 so short `msg` outputs stop being refused.

    Loosening a guard is the change most worth re-attacking: the floor was also,
    incidentally, what stopped very short input from being treated as a script at
    all. These pin what must still hold — a dispatcher that started swallowing
    txids would be a far worse bug than the one being fixed.

    One behaviour DID change and it is a deliberate trade: a truncated txid now
    renders as an unrecognised script rather than "could not classify input". The
    rescued case (a real on-chain `msg` as small as 6 bytes) is worth more than the
    sharper error message for a typo, and nothing about it is unsafe.
    """

    @pytest.mark.parametrize(
        "value,expected_form",
        [
            ("ab" * 32, "txid"),
            ("ab" * 32 + ":0", "outpoint"),
            ((b"\x6a\x03msg\x02hi").hex(), "script"),
        ],
        ids=["txid", "outpoint", "short msg"],
    )
    def test_each_form_still_dispatches_to_itself(self, value: str, expected_form: str) -> None:
        from pyrxd.glyph._inspect_core import _classify_input

        assert _classify_input(value)[0] == expected_form

    @pytest.mark.parametrize(
        "value",
        [
            # Refused BY THE FLOOR: valid, even-length hex that is simply too short to
            # be any script. Without one of these the class below is a fiction — every
            # other case here is refused by a different check, so dropping the floor to
            # zero passed the whole class and I nearly shipped a test that pinned
            # nothing.
            "6a03",
            "ab",
            # Refused by the other checks, kept so the dispatcher's whole contract is
            # pinned in one place.
            "abc",
            "hello world!",
            "",
            "6a" * 20_000,
        ],
        ids=["too short (floor)", "2 chars (floor)", "odd-length hex", "not hex", "empty", "oversize"],
    )
    def test_junk_is_still_refused(self, value: str) -> None:
        """The floor is lower, not gone. A guard that refuses nothing is not a guard."""
        from pyrxd.glyph._inspect_core import _classify_input
        from pyrxd.security.errors import ValidationError

        with pytest.raises(ValidationError):
            _classify_input(value)
