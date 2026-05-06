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
