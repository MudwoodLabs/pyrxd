"""The WAVE mint path refuses a name that impersonates Latin text — by the label rule.

#698 added a homograph check to the WAVE builders (``validate_wave_text``, with an
``allow_confusable`` override), because ``looks_confusable_with_latin`` had been wired into the
INSPECT path only: a reader was told a name mimicked Latin letters while the mint path that
CREATED it accepted it. That check flagged impersonation and let non-Latin script through, and
this file pinned ``トークン``, ``中文``, ``café``, ``Łódź`` and ``Œuf`` as honest WAVE labels.

They are not WAVE labels. The indexer that registers claims refuses every character outside
``a-z 0-9 -`` (RXinDexer ``validate_wave_name``), and so do the WAVE protocol and Photonic
(see :mod:`pyrxd.glyph.wave_rules`). A claim carrying one of those names confirms, spends its
fee, and never registers — the class #728 is about. So the honest-path set here was pinning
the defect, and it is now refused. The name a person means by ``café`` is written as its
punycode, ``xn--caf-dma``, which every source accepts; that is the honest path pinned below.

With an ASCII-only label rule the homograph question does not arise for a WAVE label: every
look-alike character is non-ASCII and refused by the rule, with no Unicode table involved and
no override to route around. ``validate_wave_text`` and ``allow_confusable`` were removed
(#698 was merged but unreleased). The spoofs below are kept to prove that, on every door.
"""

from __future__ import annotations

import cbor2
import pytest

from pyrxd.glyph.builder import CommitParams, GlyphBuilder
from pyrxd.glyph.types import GlyphMetadata, GlyphProtocol
from pyrxd.glyph.wave import build_wave_metadata
from pyrxd.security.errors import ValidationError
from pyrxd.security.types import Hex20

TXID = "ab" * 32
PKH = Hex20(bytes(range(20)))
BUILDER = GlyphBuilder()
TARGET = "1BoatSLRHtKNngkdXEeobR76b53LETtpyT"

# Each carries a character that renders as Latin but is not. Written as escapes so the
# intent survives a font, an editor, and a copy-paste — the whole point is that the two
# spellings are indistinguishable on screen.
SPOOFS = {
    "cyrillic-i": "casіno",  # U+0456 CYRILLIC SMALL LETTER BYELORUSSIAN-UKRAINIAN I
    "cyrillic-es": "usdс",  # U+0441 CYRILLIC SMALL LETTER ES
    "greek-omicron": "οmg",  # U+03BF GREEK SMALL LETTER OMICRON
    "math-bold": "\U0001d42e\U0001d42c\U0001d41d\U0001d41c",  # Mathematical Bold usdc
    "ipa-alpha": "ɑpple",  # U+0251 LATIN SMALL LETTER ALPHA
    "kelvin-sign": "Key",  # U+212A KELVIN SIGN, which case-folds to ASCII "k"
    "bidi-override": "‮cdsu",  # renders as "usdc" with no non-ASCII LETTER in it
}

# Names #698 pinned as honest. None can register: every one is refused by the indexer.
NON_ASCII = {
    "japanese": "トークン",  # トークン
    "chinese": "中文",  # 中文
    "french": "café",  # café
    "polish": "łódź",  # łódź
    "ligature": "œuf",  # œuf
}

HONEST = {"ascii": "alice", "digits": "usdt1", "hyphen": "custodian-gate-x7f3", "punycode": "xn--caf-dma"}


def _wave_cbor(label: str) -> bytes:
    """A WAVE payload claiming ``label``, so the rule on the label is what decides."""
    return cbor2.dumps(
        {
            "p": [GlyphProtocol.NFT, GlyphProtocol.MUT, GlyphProtocol.WAVE],
            "name": f"{label}.rxd",
            "attrs": {"name": label, "domain": "rxd", "target": TARGET},
        }
    )


def _commit(label: str) -> object:
    md = GlyphMetadata(
        protocol=[GlyphProtocol.NFT, GlyphProtocol.MUT, GlyphProtocol.WAVE],
        name=f"{label}.rxd",
        attrs={"name": label, "domain": "rxd", "target": TARGET},
    )
    return BUILDER.prepare_commit(CommitParams(metadata=md, owner_pkh=PKH, change_pkh=PKH, funding_satoshis=10_000))


#: Every door a WAVE claim can be written through, by label.
DOORS = {
    "build_wave_metadata": lambda label: build_wave_metadata(qualified_name=f"{label}.rxd", target=TARGET),
    "prepare_commit": _commit,
    "prepare_wave_reveal": lambda label: BUILDER.prepare_wave_reveal(TXID, 0, _wave_cbor(label), PKH, f"{label}.rxd"),
    "prepare_mutable_reveal": lambda label: BUILDER.prepare_mutable_reveal(TXID, 0, _wave_cbor(label), PKH),
}


class TestEveryDoorRefusesASpoof:
    @pytest.mark.parametrize("door", sorted(DOORS))
    @pytest.mark.parametrize("kind", sorted(SPOOFS))
    def test_refused(self, door: str, kind: str) -> None:
        with pytest.raises(ValidationError, match="lowercase a-z, 0-9 and '-' only"):
            DOORS[door](SPOOFS[kind])

    def test_a_spoofed_domain_is_refused_too(self) -> None:
        """The domain is half the name. Gating the label alone would leave ``alice.гxd``."""
        with pytest.raises(ValidationError, match="the domain must be exactly 'rxd'"):
            build_wave_metadata(qualified_name="alice.гxd", target=TARGET)

    def test_the_kelvin_spoof_really_does_fold_to_ascii(self) -> None:
        """Non-vacuity: a case-insensitive comparison anywhere would have let this through."""
        assert SPOOFS["kelvin-sign"].lower() == "key"


class TestNonAsciiNamesAreRefusedAndTheirPunycodeIsNot:
    """#698 pinned these as honest. By the indexer's own rule none of them could register."""

    @pytest.mark.parametrize("door", sorted(DOORS))
    @pytest.mark.parametrize("kind", sorted(NON_ASCII))
    def test_the_raw_name_is_refused(self, door: str, kind: str) -> None:
        with pytest.raises(ValidationError, match="punycode"):
            DOORS[door](NON_ASCII[kind])

    @pytest.mark.parametrize("kind", sorted(NON_ASCII))
    def test_its_punycode_is_accepted(self, kind: str) -> None:
        label = "xn--" + NON_ASCII[kind].encode("punycode").decode("ascii")
        md = build_wave_metadata(qualified_name=f"{label}.rxd", target=TARGET)
        assert md.attrs["name"] == label

    def test_the_punycode_of_cafe_is_the_known_one(self) -> None:
        """Non-vacuity for the derivation above: RFC 3492's encoding of ``café`` is the
        ``xn--caf-dma`` every IDNA implementation produces."""
        assert "xn--" + NON_ASCII["french"].encode("punycode").decode("ascii") == "xn--caf-dma"


class TestTheHonestPathStillWorks:
    @pytest.mark.parametrize("door", sorted(DOORS))
    @pytest.mark.parametrize("kind", sorted(HONEST))
    def test_accepted(self, door: str, kind: str) -> None:
        assert DOORS[door](HONEST[kind]) is not None

    @pytest.mark.parametrize("kind", sorted(HONEST))
    def test_the_label_is_the_claim(self, kind: str) -> None:
        md = build_wave_metadata(qualified_name=f"{HONEST[kind]}.rxd", target=TARGET)
        assert (md.attrs["name"], md.name) == (HONEST[kind], f"{HONEST[kind]}.rxd")


def test_there_is_no_override_to_route_around() -> None:
    """``allow_confusable`` promised a look-alike could be minted deliberately. Under an
    ASCII-only rule it could not do that any more, so it is gone rather than left promising."""
    with pytest.raises(TypeError):
        build_wave_metadata(qualified_name="alice.rxd", target=TARGET, allow_confusable=True)  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        BUILDER.prepare_wave_reveal(TXID, 0, _wave_cbor("alice"), PKH, "alice.rxd", allow_confusable=True)  # type: ignore[call-arg]
