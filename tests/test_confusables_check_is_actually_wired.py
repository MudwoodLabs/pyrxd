"""The TR39 confusables check the docs promise must actually run.

`docs/concepts/glyph-inspect-tool.md` listed it under the tool's threat model:

    Token names and tickers are run through the TR39 confusables skeleton check
    (`looks_confusable_with_latin`) — a Cyrillic-spoofed "USDC" is flagged with a
    warning banner before the user sees the rendered metadata.

`looks_confusable_with_latin` had **no production caller**. Repo-wide, it was its
own definition, a facade re-export, and its tests. The CLI performed no
confusables check at all; the browser page used a weaker script-mixing heuristic
that fires on any wholly non-Latin name.

That is the reachability rule twice: a capability with no caller, and — once
called — a verdict that still has to reach a human. Both halves are pinned here,
through the production entry points rather than by calling the checker directly.

WHY THE TR39 CHECK RATHER THAN THE HEURISTIC. It reports MIMICRY, not
foreignness: "トークン" and "中文" are in its own not-flagged examples. A warning
that fires on every legitimate Japanese token is the false positive that trains a
reader to ignore the real one — a hazard this repo names elsewhere in as many
words.
"""

from __future__ import annotations

import pytest

from pyrxd.glyph._inspect_core import _confusable_warnings


class _Meta:
    def __init__(self, name="", ticker="", description=""):
        self.name, self.ticker, self.description = name, ticker, description


class TestItFlagsMimicryAndOnlyMimicry:
    @pytest.mark.parametrize(
        "name",
        ["USDС", "раypal", "ᴜꜱᴅᴄ", "АВЕ"],
        ids=["cyrillic-C in USDC", "cyrillic in paypal", "small-caps USDC", "all-cyrillic ABE"],
    )
    def test_a_latin_look_alike_is_flagged(self, name: str) -> None:
        assert "name" in _confusable_warnings(_Meta(name=name))

    @pytest.mark.parametrize(
        "name",
        ["USDC", "トークン", "中文", "عملة", "Ünïcödé", "My Token", "sun ☀", "my-token.rxd"],
        ids=lambda s: s[:14],
    )
    def test_an_honest_name_is_NOT_flagged(self, name: str) -> None:
        """The paired honest path. This check exists on a surface where crying wolf
        costs more than staying quiet."""
        assert _confusable_warnings(_Meta(name=name)) == {}

    def test_every_rendered_text_field_is_covered(self) -> None:
        for field in ("name", "ticker", "description"):
            assert field in _confusable_warnings(_Meta(**{field: "USDС"}))

    def test_nothing_suspicious_yields_an_EMPTY_dict(self) -> None:
        """Absence must be silence, so a caller can treat presence as the signal."""
        assert _confusable_warnings(_Meta(name="Token", ticker="TKN", description="hi")) == {}


class TestItRunsThroughTheProductionCLASSIFIER:
    """Reachability, through `_classify_raw_tx` — not by calling the checker.

    The first version of this file tested `_confusable_warnings` directly and
    NOTHING ELSE. Unwiring it from the classifier — restoring the exact defect the
    file exists for, a capability with no production caller — left all 16 tests
    green. A test suite about a reachability bug that could not detect one.

    CLAUDE.md says it in as many words: a test that constructs the input by hand
    proves the MECHANISM, and at least one must reach the code through the
    production entry point. These build a real reveal transaction and read the
    warning out of the classified payload.
    """

    @staticmethod
    def _classified(name: str):
        from pyrxd.glyph._inspect_core import _classify_raw_tx
        from pyrxd.glyph.types import GlyphMetadata, GlyphProtocol
        from tests.test_inspect_core_classification import _build_reveal_tx

        raw, txid = _build_reveal_tx(GlyphMetadata(protocol=[GlyphProtocol.NFT], name=name))
        return _classify_raw_tx(txid, raw)["metadata"]

    def test_a_spoofed_name_is_flagged_END_TO_END(self) -> None:
        meta = self._classified("USDС")  # Cyrillic С
        assert meta["display_warnings"].get("name"), "the classifier does not run the check"

    def test_an_honest_name_produces_no_warning_END_TO_END(self) -> None:
        assert self._classified("My Token")["display_warnings"] == {}

    def test_a_legitimate_non_latin_name_produces_no_warning_END_TO_END(self) -> None:
        """The false positive that would matter most, through the real path."""
        assert self._classified("トークン")["display_warnings"] == {}


class TestTheWarningReachesAHuman:
    def test_the_CLI_prints_it_BEFORE_the_field_it_applies_to(self) -> None:
        """A look-alike warning printed after the name is one the reader has already
        acted on — the whole point is that the rendered name looks correct."""
        from pyrxd.cli.glyph_inspect import _render_txid_human

        text = _render_txid_human(
            {
                "txid": "aa" * 32,
                "version": 2,
                "locktime": 0,
                "byte_length": 300,
                "input_count": 1,
                "output_count": 1,
                "inputs": [],
                "outputs": [],
                "metadata": {
                    "input_index": 0,
                    "protocol": ["2"],
                    "name": "USDС",
                    "ticker": "",
                    "description": "",
                    "display_warnings": {"name": "characters that mimic Latin letters (possible look-alike name)"},
                },
            }
        )
        assert "WARNING" in text and "mimic Latin" in text
        assert text.index("WARNING") < text.index("name:"), "the warning must precede the name"

    def test_the_browser_bridge_does_not_OVERWRITE_the_classifier(self) -> None:
        """`glue.py` produces warnings under the same key from a weaker heuristic and
        used to ASSIGN it. Two producers, one field name, last writer wins — the
        stronger check's findings would have vanished on the browser path only."""
        import importlib.util
        import pathlib

        spec = importlib.util.spec_from_file_location(
            "_glue_probe", pathlib.Path(__file__).resolve().parent.parent / "docs/inspect_static/inspect/glue.py"
        )
        glue = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(glue)
        source = inspect_source = __import__("inspect").getsource(glue)
        assert 'metadata["display_warnings"] = warnings' not in source or "setdefault" in source
        assert 'warnings = dict(metadata.get("display_warnings") or {})' in inspect_source, (
            "the bridge must SEED from the classifier's warnings, not replace them"
        )
