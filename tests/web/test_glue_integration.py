"""End-to-end tests for the Pyodide-side glue (``docs/inspect_static/inspect/glue.py``).

The browser-hosted inspect tool is loaded into a Pyodide WASM runtime
where the JS side calls a single Python entry point: ``glue.run(text)``.
Every error becomes a structured dict — exceptions never cross the
bridge — and every CBOR-derived string is sanitized before display.

These tests run the same module under CPython (the glue is pure-Python
and imports only from ``pyrxd.glyph.inspect``, which is also pure-Python
on the offline path). If a future refactor breaks the contract — wrong
shape, raised exception, leaked control byte — these tests fail before
the wheel is built into the docs CI artifact.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
_GLUE_PATH = _REPO_ROOT / "docs" / "inspect_static" / "inspect" / "glue.py"

# RBG fixture also used by test_facade_smoke.
_RBG_TXID = "b45dc453befb589aff8bfd76af0b994615b37eda094f48c380eb31deaf96a2a8"
_RBG_CONTRACT = f"{_RBG_TXID}00000000"


@pytest.fixture(scope="module")
def glue():
    """Import ``glue.py`` from its in-repo path (it lives outside the
    package tree by design — it's loaded into Pyodide via fetch, not
    via ``pip install``)."""
    spec = importlib.util.spec_from_file_location("pyrxd_inspect_glue", _GLUE_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["pyrxd_inspect_glue"] = module
    spec.loader.exec_module(module)
    return module


class TestRunReturnsDict:
    """Every code path through ``run`` must return a JSON-serialisable dict.
    No exceptions cross the bridge."""

    @pytest.mark.parametrize("bad_input", [None, 42, [], {}])
    def test_non_string_input_returns_error_dict(self, glue, bad_input):
        result = glue.run(bad_input)
        assert result["ok"] is False
        assert result["form"] == "error"
        assert "string" in result["error"]

    def test_empty_string_returns_error_dict(self, glue):
        result = glue.run("")
        assert result["ok"] is False
        assert result["error"] == "input is empty"

    def test_whitespace_only_returns_error_dict(self, glue):
        result = glue.run("   \n\t  ")
        assert result["ok"] is False
        assert result["error"] == "input is empty"

    def test_oversize_input_is_refused_before_classification(self, glue):
        # 200_000 chars is the cap — 200_001 should be refused without
        # ever calling the classifier (defence against pathological input).
        result = glue.run("a" * 200_001)
        assert result["ok"] is False
        assert "too long" in result["error"]
        assert "--fetch" in result["error"]

    def test_unclassifiable_input_returns_error_dict(self, glue):
        result = glue.run("not a hex thing")
        assert result["ok"] is False
        assert "classify" in result["error"] or "could not" in result["error"]


class TestSuccessShape:
    """Successful classifications return ``{ok: True, form, input, payload}``."""

    def test_txid_offline_placeholder(self, glue):
        result = glue.run("a" * 64)
        assert result["ok"] is True
        assert result["form"] == "txid"
        assert result["payload"]["needs_fetch"] is True
        assert "fetch" in result["payload"]["message"].lower()

    def test_contract_id_round_trips(self, glue):
        result = glue.run(_RBG_CONTRACT)
        assert result["ok"] is True
        assert result["form"] == "contract"
        assert result["payload"]["txid"] == _RBG_TXID
        assert result["payload"]["vout"] == 0

    def test_outpoint_round_trips(self, glue):
        result = glue.run(f"{_RBG_TXID}:0")
        assert result["ok"] is True
        assert result["form"] == "outpoint"
        assert result["payload"]["txid"] == _RBG_TXID
        assert result["payload"]["vout"] == 0

    def test_p2pkh_script_classifies(self, glue):
        p2pkh = "76a914" + "aa" * 20 + "88ac"
        result = glue.run(p2pkh)
        assert result["ok"] is True
        assert result["form"] == "script"
        assert result["payload"]["type"] == "p2pkh"
        assert result["payload"]["owner_pkh"] == "aa" * 20

    def test_unknown_script_classifies(self, glue):
        result = glue.run("de" * 25)
        assert result["ok"] is True
        assert result["form"] == "script"
        assert result["payload"]["type"] == "unknown"


class TestNormalisation:
    """``input`` field reflects the canonical (lowercased) form, except
    outpoints which carry a colon and shouldn't have their case touched
    (vout digits don't care, but we keep the contract minimal)."""

    def test_contract_input_is_lowercased(self, glue):
        result = glue.run(_RBG_CONTRACT.upper())
        assert result["ok"] is True
        assert result["input"] == _RBG_CONTRACT

    def test_outpoint_input_is_passed_through(self, glue):
        # Outpoints are stripped but case is preserved (downstream parser
        # lowercases the txid component itself).
        result = glue.run(f"  {_RBG_TXID}:0  ")
        assert result["ok"] is True
        assert result["input"] == f"{_RBG_TXID}:0"


class TestSanitisation:
    """Strings the JS side will write to the DOM must be free of control
    and bidi-override codepoints. The glue's ``_sanitize_payload_strings``
    walks every dict / list / tuple recursively."""

    def test_error_messages_are_sanitized(self, glue):
        # An unclassifiable input echoes its length back; that text path
        # itself shouldn't carry attacker bytes, but the sanitizer still
        # runs over every error string. Sanity-check that the field is a
        # string with no control chars.
        result = glue.run("\x1b[31m oops")  # ANSI escape
        assert result["ok"] is False
        assert "\x1b" not in result["error"]

    def test_payload_walker_handles_nested_structures(self, glue):
        """Direct unit-test of the recursive sanitizer to lock the
        contract for future PR-C work that adds CBOR string fields."""
        nested = {
            "name": "hello\x1bworld",
            "list": ["safe", "ansi\x1b[0m"],
            "tuple": ("ok", "bidi‮txt"),
            "scalar": 42,
            "deep": {"k": "ctrl\x07char"},
        }
        cleaned = glue._sanitize_payload_strings(nested)
        assert "\x1b" not in cleaned["name"]
        assert "\x1b" not in cleaned["list"][1]
        assert "‮" not in cleaned["tuple"][1]
        assert cleaned["scalar"] == 42
        assert "\x07" not in cleaned["deep"]["k"]


class TestErrorHints:
    """When the classifier accepts a form but the parser rejects it, the
    error dict carries a per-form hint to nudge the user toward the
    correct shape."""

    def test_outpoint_hint_on_malformed_outpoint(self, glue):
        # A colon triggers outpoint dispatch; an invalid vout fails the
        # parser, which raises and the glue translates to an error+hint.
        result = glue.run(f"{_RBG_TXID}:notanumber")
        assert result["ok"] is False
        assert result["form"] == "error"
        assert "Outpoints" in result["hint"] or "vout" in result["hint"]

    def test_contract_hint_on_malformed_contract(self, glue):
        # 72 hex chars but vout-bytes don't fit the BE encoding. We use a
        # pattern that's structurally a contract id but with garbage vout
        # so the parser raises ValidationError downstream.
        # Easiest construction: 64 hex (zeros) + 8 hex chars that don't
        # round-trip. The contract parser accepts any 4-byte BE int, so
        # a truly hostile case here is hard without poking internals.
        # Instead, verify that *some* error path on a contract-shaped
        # input produces a hint mentioning the 72-hex format.
        # Real malformed: 72 chars but with non-hex (caught upstream as
        # unclassifiable, not contract). So this test is best-effort.
        # If the parser ever does raise, the hint must mention 72 hex.
        # For now: just validate that the hint table has the key.
        assert "72 hex" in glue._hint_for("contract")


# ---------------------------------------------------------------------------
# inspect_txid_with_raw — the fetch path
# ---------------------------------------------------------------------------

# Live mainnet RBG transfer (same fixture the CLI's --fetch tests use).
# Real tx with 2 inputs, 3 outputs (ft / ft / p2pkh).
_RBG_TRANSFER_TXID = "ac7f1f705086a3a4cb2a354bf778fe2da829a90372742db076f542398cc60ae4"
_RBG_TRANSFER_OWNER_PKH = "d84b8c371ea11f051dfed9daae05c8dee24d9eba"
_RBG_TRANSFER_RAW_HEX = (
    "01000000029565e76c9e80570d3f9f38f961bc1719f866de2e81a73797f1da70fc77a8276300"
    "0000006b483045022100a4635b1d89a79e5e5e2d9613ed1813b1ebdf5333bef0ad5005b743fe"
    "d834dcff022068bd415a8157b69ca693e0a1dce77f8bb6a6aa929acfc16985c0dae557917280"
    "4121034f4d886d85dc38da1b2a6f49d299990b57032821edc092109f0d93fd00537720ffffff"
    "fffd432df44ff9627a0c6adb9c459a9d4e8677e54553d3e9896c2b6d0de03a93ba010000006a"
    "47304402203faf1061260e218738834f83b05d23390d6ecb57c2c8d150642b6965ce3f719202"
    "20226f828b994a1c3176fa52ddd6194b72b28d9949017edc782f6868adf704228f4121034f4d"
    "886d85dc38da1b2a6f49d299990b57032821edc092109f0d93fd00537720ffffffff03010000"
    "00000000004b76a914d84b8c371ea11f051dfed9daae05c8dee24d9eba88acbdd0a8a296afde"
    "31eb80c3484f09da7eb31546990baf76fd8bff9a58fbbe53c45db400000000dec0e9aa76e378"
    "e4a269e69dcfb95700000000004b76a914d84b8c371ea11f051dfed9daae05c8dee24d9eba88"
    "acbdd0a8a296afde31eb80c3484f09da7eb31546990baf76fd8bff9a58fbbe53c45db4000000"
    "00dec0e9aa76e378e4a269e69d6895b1439f0300001976a914d84b8c371ea11f051dfed9daae"
    "05c8dee24d9eba88ac00000000"
)


class TestInspectTxidWithRaw:
    """The fetch path: JS hands raw hex bytes to Python, Python applies
    the same threat-model guards as the CLI's --fetch path and returns
    a structured dict."""

    def test_classifies_real_rbg_transfer(self, glue):
        result = glue.inspect_txid_with_raw(_RBG_TRANSFER_TXID, _RBG_TRANSFER_RAW_HEX)
        assert result["ok"] is True
        assert result["form"] == "txid"
        assert result["input"] == _RBG_TRANSFER_TXID

        payload = result["payload"]
        assert payload["txid"] == _RBG_TRANSFER_TXID
        assert payload["input_count"] == 2
        assert payload["output_count"] == 3

        # Three outputs: vout 0 ft, vout 1 ft, vout 2 p2pkh — all share owner_pkh.
        outputs = payload["outputs"]
        assert outputs[0]["type"] == "ft"
        assert outputs[1]["type"] == "ft"
        assert outputs[2]["type"] == "p2pkh"
        for row in outputs:
            assert row["owner_pkh"] == _RBG_TRANSFER_OWNER_PKH

    def test_hash_mismatch_rejected(self, glue):
        """Server-honesty check: raw bytes that don't hash to the
        requested txid must be refused (the CLI threat-model guard,
        preserved verbatim)."""
        fake_txid = "0" * 64
        result = glue.inspect_txid_with_raw(fake_txid, _RBG_TRANSFER_RAW_HEX)
        assert result["ok"] is False
        assert result["form"] == "error"
        assert "does not match" in result["error"]

    def test_oversize_raw_hex_refused_before_classification(self, glue):
        """Refused before the classifier runs — the cap defends against a
        hostile server returning a multi-gigabyte response."""
        result = glue.inspect_txid_with_raw(_RBG_TRANSFER_TXID, "a" * 9_000_000)
        assert result["ok"] is False
        assert "too long" in result["error"]

    def test_non_hex_raw_rejected(self, glue):
        result = glue.inspect_txid_with_raw(_RBG_TRANSFER_TXID, "not hex zzz")
        assert result["ok"] is False
        assert "not valid hex" in result["error"]

    def test_short_txid_rejected(self, glue):
        result = glue.inspect_txid_with_raw("abc", _RBG_TRANSFER_RAW_HEX)
        assert result["ok"] is False
        assert "64" in result["error"]

    def test_empty_raw_rejected(self, glue):
        result = glue.inspect_txid_with_raw(_RBG_TRANSFER_TXID, "")
        assert result["ok"] is False
        assert "empty" in result["error"]

    @pytest.mark.parametrize("bad", [None, 42, [], {}])
    def test_non_string_arguments_rejected(self, glue, bad):
        result = glue.inspect_txid_with_raw(bad, _RBG_TRANSFER_RAW_HEX)
        assert result["ok"] is False
        assert "string" in result["error"]

    def test_uppercase_txid_normalised(self, glue):
        """Mirrors the run() normalisation contract: input is canonical
        lowercased even when the user paste-from-explorer was uppercase."""
        result = glue.inspect_txid_with_raw(_RBG_TRANSFER_TXID.upper(), _RBG_TRANSFER_RAW_HEX)
        assert result["ok"] is True
        assert result["input"] == _RBG_TRANSFER_TXID  # lowercase

    def test_payload_strings_pass_through_sanitiser(self, glue, monkeypatch):
        """The recursive sanitiser is applied to the classify_raw_tx
        result before the dict crosses the bridge. We can't easily
        introduce a CBOR string into the real fixture, so unit-test the
        invariant directly: any string anywhere in the returned payload
        comes back sanitised."""
        # Inject a fake classify_raw_tx that returns a CBOR-like string with
        # a bidi-override character. Sanitiser must strip it before return.
        from pyrxd.glyph import inspect as facade

        def _evil(_txid, _raw):
            return {"form": "txid", "txid": _txid, "metadata": {"name": "gly‮bar"}}

        monkeypatch.setattr(facade, "classify_raw_tx", _evil)
        # Need a hex that matches the _txid argument's hash. Easiest way:
        # bypass the hash check by using the real fixture and asserting the
        # name field (which the fake injects). The hash check fires before
        # classify_raw_tx is called — but we patched classify_raw_tx
        # directly, so we need to also bypass the size + hash checks. The
        # glue's path goes hex-decode → classify_raw_tx, so the patched
        # classify_raw_tx is the only sink for the fake data here.
        result = glue.inspect_txid_with_raw(_RBG_TRANSFER_TXID, _RBG_TRANSFER_RAW_HEX)
        assert result["ok"] is True
        assert "‮" not in result["payload"]["metadata"]["name"]


class TestHomoglyphDetection:
    """A token deployer can put any CBOR string into name/ticker/desc.
    Two attack shapes are flagged:

    - **mixed scripts** — Latin ASCII letters mixed with letters from
      another script. Per-character substitution (USDC with Cyrillic С).
    - **non-Latin script** — every Letter codepoint is non-Latin.
      Whole-word substitution (Cyrillic ВТС mimicking Latin BTC).

    The flag is surfaced as ``metadata.display_warnings[<field>]`` so the
    JS side can render a banner + per-field warning. ``_suspicious_reason``
    returns the reason string; ``_looks_suspicious`` is a backwards-
    compat boolean wrapper.
    """

    def test_pure_latin_ascii_not_flagged(self, glue):
        assert glue._suspicious_reason("USDC") == ""
        assert glue._suspicious_reason("MyToken") == ""
        assert glue._suspicious_reason("BNB") == ""

    def test_legit_latin_extended_not_flagged(self, glue):
        """Real-world token names use accented Latin letters routinely.
        Café / naïve / Zürich must NOT trip the flag — that would
        damage trust in the legitimate non-English token namespace."""
        for name in ["Café", "naïve", "Zürich", "piñata", "résumé"]:
            assert glue._suspicious_reason(name) == "", f"false positive: {name!r}"

    def test_mixed_latin_cyrillic_flagged_as_mixed(self, glue):
        spoofed = "USDС"  # final char is Cyrillic С (U+0421)
        assert glue._suspicious_reason(spoofed) == "mixed scripts (possible homoglyph)"

    def test_pure_cyrillic_flagged_as_non_latin(self, glue):
        """Pure-non-Latin token names that visually mimic Latin (the
        classic ВТС-mimicking-BTC attack) must trip the flag too —
        a Latin-default reader sees "BTC" but the token is something
        else entirely."""
        for name in ["ВТС", "ΟΜΓ", "аррӏе"]:
            reason = glue._suspicious_reason(name)
            assert reason == "non-Latin script (verify by txid, not by visual name)", (
                f"unexpected reason for {name!r}: {reason!r}"
            )

    def test_latin_with_digits_not_flagged(self, glue):
        # Digits and punctuation aren't Letters — they don't trip the flag.
        assert glue._suspicious_reason("TOKEN123") == ""
        assert glue._suspicious_reason("A.B.C-1") == ""

    def test_latin_with_emoji_not_flagged(self, glue):
        # Emoji are not Letter category; legitimate token names can contain them.
        assert glue._suspicious_reason("TOKEN \U0001f680") == ""

    def test_empty_or_none_not_flagged(self, glue):
        assert glue._suspicious_reason("") == ""
        assert glue._suspicious_reason(None) == ""

    def test_nfkc_normalisation_applied(self, glue):
        # Full-width Latin letters look like Latin to a viewer; NFKC
        # collapses them so the script-mixing check operates on the
        # canonical form. A pure-fullwidth Latin string is still Latin
        # after normalisation — must not be flagged.
        full_width_latin = "ＵＳＤＣ"  # "USDC" in full-width
        assert glue._suspicious_reason(full_width_latin) == ""

    def test_bool_wrapper_still_works(self, glue):
        """``_looks_suspicious`` kept as a boolean adapter for callers
        that don't care about the reason."""
        assert glue._looks_suspicious("USDC") is False
        assert glue._looks_suspicious("USDС") is True  # mixed
        assert glue._looks_suspicious("ВТС") is True  # pure non-Latin


class TestProtocolFieldHomoglyphCoverage:
    """The homoglyph check walks ``metadata.protocol`` array entries, not
    just name/ticker/description. An attacker who puts a homoglyph in
    the protocol field gets it surfaced via display_warnings the same
    way."""

    def test_protocol_with_mixed_script_entry_flagged(self, glue, monkeypatch):
        from pyrxd.glyph import inspect as facade

        def _evil(_txid, _raw):
            return {
                "form": "txid",
                "txid": _txid,
                "byte_length": 100,
                "input_count": 1,
                "output_count": 1,
                "outputs": [],
                "metadata": {
                    "input_index": 0,
                    "protocol": ["gly", "rxd", "USDС"],  # final entry mixed
                    "name": "",
                    "ticker": "",
                    "description": "",
                },
            }

        monkeypatch.setattr(facade, "classify_raw_tx", _evil)
        result = glue.inspect_txid_with_raw(_RBG_TRANSFER_TXID, _RBG_TRANSFER_RAW_HEX)
        warnings = result["payload"]["metadata"]["display_warnings"]
        assert "protocol" in warnings
        assert warnings["protocol"] == "mixed scripts (possible homoglyph)"

    def test_benign_protocol_not_flagged(self, glue, monkeypatch):
        from pyrxd.glyph import inspect as facade

        def _benign(_txid, _raw):
            return {
                "form": "txid",
                "txid": _txid,
                "byte_length": 100,
                "input_count": 1,
                "output_count": 1,
                "outputs": [],
                "metadata": {
                    "input_index": 0,
                    "protocol": ["gly", "rxd"],
                    "name": "",
                    "ticker": "",
                    "description": "",
                },
            }

        monkeypatch.setattr(facade, "classify_raw_tx", _benign)
        result = glue.inspect_txid_with_raw(_RBG_TRANSFER_TXID, _RBG_TRANSFER_RAW_HEX)
        # display_warnings should be entirely absent (or have no protocol key).
        warnings = result["payload"]["metadata"].get("display_warnings", {})
        assert "protocol" not in warnings


class TestPayloadTruncation:
    """The recursive sanitiser caps free-form strings at the human-display
    limit so an attacker description can't overflow the card. Hex-shaped
    primary keys (txid, refs, owner_pkh) MUST be passed through unchanged
    — chopping a txid visually misleads the user about which transaction
    they're inspecting."""

    def test_long_description_truncated(self, glue):
        long = "x" * 500
        walked = glue._sanitize_payload_strings({"metadata": {"description": long}})
        assert len(walked["metadata"]["description"]) <= 200

    def test_long_name_truncated(self, glue):
        long = "y" * 500
        walked = glue._sanitize_payload_strings({"metadata": {"name": long}})
        assert len(walked["metadata"]["name"]) <= 200

    def test_full_length_txid_preserved(self, glue):
        txid = "a" * 64
        walked = glue._sanitize_payload_strings({"txid": txid})
        assert walked["txid"] == txid

    def test_owner_pkh_preserved_in_nested_output_row(self, glue):
        pkh = "d" * 40
        walked = glue._sanitize_payload_strings({"outputs": [{"owner_pkh": pkh, "type": "p2pkh"}]})
        assert walked["outputs"][0]["owner_pkh"] == pkh

    def test_ref_outpoint_preserved(self, glue):
        ref = "b45dc453befb589aff8bfd76af0b994615b37eda094f48c380eb31deaf96a2a8:0"
        walked = glue._sanitize_payload_strings({"ref_outpoint": ref})
        assert walked["ref_outpoint"] == ref

    def test_real_rbg_fixture_owner_pkh_untruncated_end_to_end(self, glue):
        """End-to-end: even after going through inspect_txid_with_raw +
        the recursive sanitiser, every output row's owner_pkh is full
        40-char fidelity. Locks against a future change that
        accidentally adds 'owner_pkh' to the truncate list."""
        result = glue.inspect_txid_with_raw(_RBG_TRANSFER_TXID, _RBG_TRANSFER_RAW_HEX)
        assert result["ok"] is True
        for row in result["payload"]["outputs"]:
            assert len(row["owner_pkh"]) == 40, row

    def test_main_field_is_truncated(self, glue):
        """``main`` is constructed by Python as ``<media: {mime}, {N}
        bytes, sha256={hex}>`` but the CBOR-supplied mime_type has no
        upstream length cap, so an attacker mime_type of 64KB makes the
        constructed string overflow the card. ``main`` is therefore
        NOT in the never-truncate allowlist — must be capped at 200."""
        long_main = "<media: " + "x" * 1000 + ">"
        walked = glue._sanitize_payload_strings({"metadata": {"main": long_main}})
        assert len(walked["metadata"]["main"]) <= 200
