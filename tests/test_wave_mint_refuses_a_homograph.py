"""The WAVE mint path refuses a name that impersonates Latin text.

``looks_confusable_with_latin`` has shipped since before v0.18.0 and was wired into the
INSPECT path only (``glyph/_inspect_core.py``). A reader was told a name mimics Latin
letters; the mint path that CREATES such a name accepted it silently. For a name registry
that asymmetry is backwards — refusing to create a spoof is worth more than labelling one
after it is on-chain and somebody else owns it.

This is the write-side half, and it is checked on BOTH doors: ``build_wave_metadata`` (the
documented helper) and ``GlyphBuilder.prepare_wave_reveal`` (the funnel every registration
crosses whatever built its CBOR). A caller who hand-rolls the CBOR skips the first and still
crosses the second — which is the reason the rule lives in one function called from both
rather than being written out twice, as it was before.

The honest-path tests are not decoration. A guard that refuses valid work is a defect, and
this one refuses on a Unicode property, so the cases it must NOT touch — non-Latin scripts,
Latin Extended, digits — are pinned as hard as the cases it must.
"""

from __future__ import annotations

import cbor2
import pytest

from pyrxd.glyph.builder import GlyphBuilder
from pyrxd.glyph.types import GlyphProtocol
from pyrxd.glyph.wave import build_wave_metadata, validate_wave_text
from pyrxd.security.errors import ValidationError

TXID = "ab" * 32
PKH = bytes(range(20))
BUILDER = GlyphBuilder()

# Each carries a character that renders as Latin but is not. Written as escapes so the
# intent survives a font, an editor, and a copy-paste — the whole point is that the two
# spellings are indistinguishable on screen.
SPOOFS = {
    "cyrillic-i": "casіno",  # U+0456 CYRILLIC SMALL LETTER BYELORUSSIAN-UKRAINIAN I
    "cyrillic-es": "USDС",  # U+0421 CYRILLIC CAPITAL LETTER ES
    "greek-omicron": "ΟMG",  # U+039F GREEK CAPITAL LETTER OMICRON
    "math-bold": "\U0001d414\U0001d412\U0001d413\U0001d402",  # Mathematical Bold USDC
    "ipa-alpha": "ɑpple",  # U+0251 LATIN SMALL LETTER ALPHA
}

# Refused, but by the PRINTABILITY clause rather than the homograph one: `str.isprintable()`
# is False for bidi format controls, so this never reaches `looks_confusable_with_latin`.
# Kept separate and asserted separately, because a test that let it match the homograph
# message would be recording a mechanism that is not the one doing the work.
BIDI_SPOOF = "‮CDSU"  # renders as "USDC" without containing one non-ASCII letter

# Names that are not impersonating anything. Refusing these would be the bug.
HONEST = {
    "ascii": "alice",
    "digits": "usdt1",
    "hyphen": "custodian-gate-x7f3",
    "japanese": "トークン",  # トークン
    "chinese": "中文",  # 中文
    "french": "café",  # Café
    "polish": "Łódź",  # Łódź
    "ligature": "Œuf",  # Œuf
}


def _wave_cbor(name: str) -> bytes:
    """A minimal WAVE payload whose attrs.name matches, so the builder's cross-check passes
    and the homograph clause is what refuses — not an unrelated mismatch."""
    return cbor2.dumps(
        {
            "p": [GlyphProtocol.NFT, GlyphProtocol.MUT, GlyphProtocol.WAVE],
            "attrs": {"name": name, "domain": "rxd", "target": "1BoatSLRHtKNngkdXEeobR76b53LETtpyT"},
        }
    )


class TestTheHelperRefusesASpoof:
    @pytest.mark.parametrize("kind", sorted(SPOOFS))
    def test_build_wave_metadata_refuses(self, kind: str) -> None:
        with pytest.raises(ValidationError, match="mimic Latin"):
            build_wave_metadata(qualified_name=f"{SPOOFS[kind]}.rxd", target="1BoatSLRHtKNngkdXEeobR76b53LETtpyT")

    def test_a_bidi_reordered_name_is_refused_by_the_printability_clause(self) -> None:
        for fn in (
            lambda n: build_wave_metadata(qualified_name=n, target="1BoatSLRHtKNngkdXEeobR76b53LETtpyT"),
            lambda n: BUILDER.prepare_wave_reveal(TXID, 0, _wave_cbor(n), PKH, n),
        ):
            with pytest.raises(ValidationError, match="printable"):
                fn(f"{BIDI_SPOOF}.rxd")

    def test_a_spoofed_domain_is_refused_too(self) -> None:
        """The domain is half the name. Gating the label alone would leave `alice.гxd`."""
        with pytest.raises(ValidationError, match="WAVE domain"):
            build_wave_metadata(qualified_name="alice.гxd", target="1BoatSLRHtKNngkdXEeobR76b53LETtpyT")


class TestTheBuilderRefusesASpoof:
    """The second door. A caller who never touches build_wave_metadata still crosses here."""

    @pytest.mark.parametrize("kind", sorted(SPOOFS))
    def test_prepare_wave_reveal_refuses(self, kind: str) -> None:
        name = f"{SPOOFS[kind]}.rxd"
        with pytest.raises(ValidationError, match="mimic Latin"):
            BUILDER.prepare_wave_reveal(TXID, 0, _wave_cbor(name), PKH, name)


class TestTheHonestPathStillWorks:
    @pytest.mark.parametrize("kind", sorted(HONEST))
    def test_build_wave_metadata_accepts(self, kind: str) -> None:
        md = build_wave_metadata(qualified_name=f"{HONEST[kind]}.rxd", target="1BoatSLRHtKNngkdXEeobR76b53LETtpyT")
        assert md.attrs["name"] == f"{HONEST[kind]}.rxd"

    @pytest.mark.parametrize("kind", sorted(HONEST))
    def test_prepare_wave_reveal_accepts(self, kind: str) -> None:
        name = f"{HONEST[kind]}.rxd"
        assert BUILDER.prepare_wave_reveal(TXID, 0, _wave_cbor(name), PKH, name) is not None


class TestTheOverrideExists:
    """A guard with no way past it becomes a reason to route around the guard. A registrar
    reclaiming a spoof of its own brand is honest work."""

    def test_helper_allows_confusable_when_asked(self) -> None:
        md = build_wave_metadata(
            qualified_name=f"{SPOOFS['cyrillic-i']}.rxd",
            target="1BoatSLRHtKNngkdXEeobR76b53LETtpyT",
            allow_confusable=True,
        )
        assert md.attrs["name"].startswith("cas")

    def test_builder_allows_confusable_when_asked(self) -> None:
        name = f"{SPOOFS['cyrillic-i']}.rxd"
        assert BUILDER.prepare_wave_reveal(TXID, 0, _wave_cbor(name), PKH, name, allow_confusable=True) is not None


class TestTheSharedRuleIsOneDefinition:
    def test_the_length_and_printability_clauses_still_hold(self) -> None:
        for bad in ("", "a" * 256, "bad\x00name"):
            with pytest.raises(ValidationError):
                validate_wave_text(bad)

    def test_the_error_no_longer_claims_ascii(self) -> None:
        """Both copies of this rule said "printable ASCII" while `str.isprintable()` accepts
        any printable Unicode — a sentence that was false about the check beside it, and the
        sentence a reader would have trusted when deciding a homograph was already handled."""
        with pytest.raises(ValidationError) as exc:
            validate_wave_text("")
        assert "ASCII" not in str(exc.value)

    def test_a_confusable_skeleton_really_does_collide(self) -> None:
        """Non-vacuity: proves the spoofs above are spoofs, so a future change to the
        detector that stopped flagging them would not leave these tests passing emptily."""
        from pyrxd.glyph.confusables import skeleton

        assert skeleton(SPOOFS["cyrillic-i"]) == skeleton("casino")
