"""Smoke tests for the ``pyrxd.glyph.inspect`` public façade.

The façade exists so the browser-hosted inspect tool (loaded into a
Pyodide WASM runtime via ``docs/inspect/``) can import a stable public
API rather than reaching into ``pyrxd.cli.glyph_cmds._``-prefixed
internals. These tests lock the contract: every public name in the
module must be importable, callable, and produce a sensible result on
known inputs.

If a future refactor renames or removes a CLI helper, these tests fail
loudly — at which point the façade either needs an updated re-export or
a deliberate API change with proper deprecation.
"""

from __future__ import annotations

import pytest

# RBG mainnet contract id (display order txid + BE vout=4). We use the
# same fixtures the rest of the test suite uses so a single regression
# in real-world data shows up everywhere.
_RBG_CONTRACT = "b45dc453befb589aff8bfd76af0b994615b37eda094f48c380eb31deaf96a2a800000000"
_RBG_TXID = "b45dc453befb589aff8bfd76af0b994615b37eda094f48c380eb31deaf96a2a8"


class TestFacadeExports:
    """Every name in __all__ must be importable + callable."""

    def test_all_exports_resolve(self):
        from pyrxd.glyph import inspect

        for name in inspect.__all__:
            assert hasattr(inspect, name), f"missing export: {name}"
            obj = getattr(inspect, name)
            assert callable(obj), f"{name} is not callable"

    def test_module_docstring_is_present(self):
        """The façade ships with documentation explaining why it exists."""
        from pyrxd.glyph import inspect

        assert inspect.__doc__ is not None
        assert "Pyodide" in inspect.__doc__ or "browser" in inspect.__doc__


class TestClassifyInput:
    """The dispatch helper recognises every documented input shape."""

    def test_classifies_txid(self):
        from pyrxd.glyph import inspect

        form, value = inspect.classify_input("a" * 64)
        assert form == "txid"
        assert value == "a" * 64

    def test_classifies_contract_id(self):
        from pyrxd.glyph import inspect

        form, _value = inspect.classify_input(_RBG_CONTRACT)
        assert form == "contract"

    def test_classifies_outpoint(self):
        from pyrxd.glyph import inspect

        form, _value = inspect.classify_input(f"{_RBG_TXID}:0")
        assert form == "outpoint"

    def test_classifies_script_hex(self):
        from pyrxd.glyph import inspect

        # Plain P2PKH (50 hex chars / 25 bytes).
        p2pkh = "76a914" + "aa" * 20 + "88ac"
        form, _value = inspect.classify_input(p2pkh)
        assert form == "script"


class TestInspectContract:
    """Decoding a real RBG contract id returns the canonical fields."""

    def test_decodes_real_world_rbg_contract(self):
        from pyrxd.glyph import inspect

        result = inspect.inspect_contract(_RBG_CONTRACT)
        assert result["txid"] == _RBG_TXID
        assert result["vout"] == 0  # canonical RBG tokenRef


class TestInspectOutpoint:
    """Outpoint decoding round-trips a known good input."""

    def test_decodes_outpoint(self):
        from pyrxd.glyph import inspect

        result = inspect.inspect_outpoint(f"{_RBG_TXID}:0")
        assert result["txid"] == _RBG_TXID
        assert result["vout"] == 0


class TestInspectScript:
    """The script classifier covers all the public types."""

    def test_classifies_p2pkh(self):
        from pyrxd.glyph import inspect

        p2pkh = "76a914" + "aa" * 20 + "88ac"
        result = inspect.inspect_script(p2pkh)
        assert result["type"] == "p2pkh"

    def test_classifies_unknown(self):
        """Random hex that doesn't match any classifier returns ``unknown``."""
        from pyrxd.glyph import inspect

        result = inspect.inspect_script("de" * 25)
        assert result["type"] == "unknown"


class TestSanitizeDisplayString:
    """The sanitizer is the trust boundary for any CBOR-derived string
    rendered to the user. Locks the most security-relevant cases."""

    def test_strips_ansi_escape(self):
        from pyrxd.glyph import inspect

        # \x1b is OP_ESC and ANSI-CSI prefix. Must be stripped before display.
        assert inspect.sanitize_display_string("hi\x1b[31m") == "hi?[31m"

    def test_strips_bidi_override(self):
        """U+202E (RIGHT-TO-LEFT OVERRIDE) is the headline injection threat —
        a hostile token deployer could spoof a token name's apparent letter
        order in the UI. Must be stripped."""
        from pyrxd.glyph import inspect

        assert inspect.sanitize_display_string("gly‮bar") == "gly?bar"

    def test_preserves_plain_ascii(self):
        from pyrxd.glyph import inspect

        assert inspect.sanitize_display_string("hello world") == "hello world"


class TestTruncateForHuman:
    """The display truncation cap is enforced."""

    def test_caps_long_strings(self):
        from pyrxd.glyph import inspect

        long_input = "x" * 500
        result = inspect.truncate_for_human(long_input, cap=100)
        assert len(result) <= 100

    def test_passes_through_short_strings(self):
        from pyrxd.glyph import inspect

        assert inspect.truncate_for_human("short") == "short"


class TestClassifyRawTx:
    """The façade re-exports the synchronous classify_raw_tx helper that
    the browser-hosted inspect tool calls after fetching raw bytes via
    its own WebSocket. The CLI side already covers the threat-model
    guards exhaustively; here we just lock the re-export contract."""

    def test_classify_raw_tx_is_exported(self):
        from pyrxd.glyph import inspect

        assert "classify_raw_tx" in inspect.__all__
        assert callable(inspect.classify_raw_tx)

    def test_returns_form_txid_dict(self):
        """Smoke against a tiny synthetic 1-input/1-output tx so no fixture
        bytes are needed and no network ever runs.

        The classifier rejects raw bytes <= 64 (Merkle-forgery defence
        inherited from the ``RawTx`` newtype invariant), so the synthetic
        tx must be at least 65 bytes. We give the output a real 25-byte
        P2PKH locking script, which puts the total at ~85 bytes."""
        from pyrxd.glyph import inspect

        p2pkh_script = "76a914" + "aa" * 20 + "88ac"  # 25 bytes / 50 hex
        raw = bytes.fromhex(
            "01000000"  # version
            "01"  # vin count
            + "00" * 32  # prev txid
            + "ffffffff"  # prev vout
            + "00"  # scriptSig length
            + "ffffffff"  # sequence
            + "01"  # vout count
            + "0000000000000000"  # satoshis (0)
            + "19"  # scriptPubKey length (25 bytes)
            + p2pkh_script
            + "00000000"  # locktime
        )

        # Compute the txid the way the parser does.
        from pyrxd.hash import hash256

        txid = hash256(raw)[::-1].hex()

        result = inspect.classify_raw_tx(txid, raw)
        assert result["form"] == "txid"
        assert result["txid"] == txid
        assert result["input_count"] == 1
        assert result["output_count"] == 1
        assert result["outputs"][0]["type"] == "p2pkh"


class TestNoDirectCliImport:
    """The browser tool must NOT reach into CLI internals.

    This test is documentary, not a hard fence — Python doesn't enforce
    private prefixes — but a `grep` against `tests/web/` for
    ``cli.glyph_cmds._`` should remain empty. If a downstream user ever
    imports a `_`-prefixed name from glyph_cmds, this test reminds the
    reviewer that the façade exists for a reason.
    """

    def test_facade_does_not_re_export_async_inner(self):
        """The async ``_inspect_txid_inner`` requires an event loop and an
        ElectrumXClient — neither plays nicely under Pyodide. The façade
        deliberately omits it; the browser tool's PR-3 wiring fetches raw
        bytes via the native WebSocket API and feeds them into
        ``inspect_script`` per-output instead."""
        from pyrxd.glyph import inspect

        assert "inspect_txid_inner" not in inspect.__all__
        assert not hasattr(inspect, "inspect_txid_inner")


class TestStaticPagePresent:
    """Sanity-check that PR-1 actually shipped the static-page files.

    Catches the "I edited Python but forgot to commit the html" failure
    mode at test time rather than after deploy.
    """

    def test_inspect_html_exists(self):
        from pathlib import Path

        repo_root = Path(__file__).resolve().parents[2]
        # Sphinx's html_extra_path copies the *contents* of the path, so the
        # inspect page lives at docs/inspect_static/inspect/index.html and
        # ships to /inspect/index.html on the published site.
        index = repo_root / "docs" / "inspect_static" / "inspect" / "index.html"
        assert index.exists(), f"missing {index}"
        text = index.read_text()
        # The file must declare the CSP we documented.
        assert "Content-Security-Policy" in text
        # And the SRI hash for Pyodide.
        assert 'integrity="sha384-' in text

    def test_refresh_pyodide_script_exists(self):
        from pathlib import Path

        repo_root = Path(__file__).resolve().parents[2]
        script = repo_root / "scripts" / "refresh-pyodide.sh"
        assert script.exists()
        # And is executable.
        assert script.stat().st_mode & 0o111, f"{script} is not executable"


@pytest.mark.skipif(
    not (lambda: __import__("pathlib").Path("docs/inspect/wheels/manifest.json").exists())(),
    reason="wheel + manifest only built by docs.yml CI step",
)
class TestWheelManifest:
    """Validates the manifest.json the docs.yml CI step writes alongside
    the pyrxd wheel. Skipped when the file isn't present (i.e. when
    running tests locally without the CI step)."""

    def test_manifest_has_wheel_field(self):
        import json
        from pathlib import Path

        manifest_path = Path("docs/inspect/wheels/manifest.json")
        manifest = json.loads(manifest_path.read_text())
        assert "wheel" in manifest
        assert manifest["wheel"].startswith("pyrxd-")
        assert manifest["wheel"].endswith(".whl")
