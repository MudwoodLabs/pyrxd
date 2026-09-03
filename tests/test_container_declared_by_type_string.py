"""A container declares itself with `type: "container"`, not protocol 7.

`GlyphProtocol.CONTAINER` (7) is the spec'd marker and **no mainnet token uses
it**. All four containers on Radiant mainnet carry `type: "container"` on an
ordinary NFT/MUT protocol set, so every protocol-only test was False for every
real container and they classified as "nft" or "mut" (#578).

Verified against the chain rather than inferred: the "BTC" container
(ref ``5558395540…c2ab:0``, reveal ``57c4d660…dfb1``) decodes to ``p = (2,)``
with ``type = 'container'``. The indexer agrees — it labels exactly these four
CONTAINER and exposes no protocol field, so its label comes from the same string.

Both forms are DECLARATIONS. `type` is operator-supplied CBOR and nothing on
chain enforces it, exactly as nothing enforces the protocol array; the ecosystem
treats this one as the classification.

Three sites had to change together — the property, the inspect classifier, and
the deliberate mirror of that classifier in `wave.py`. This suite pins all three,
because a copy left behind is how the branch stayed dead in the first place.
"""

from __future__ import annotations

import pytest

from pyrxd.glyph._inspect_core import _classify_metadata_protocol
from pyrxd.glyph.types import GlyphMetadata, GlyphProtocol
from pyrxd.glyph.wave import classify_glyph_metadata

#: The shape every mainnet container actually has.
_AS_ON_CHAIN = {"protocol": (GlyphProtocol.NFT.value,), "token_type": "container", "name": "BTC"}
#: The spec'd shape, which nothing on mainnet uses.
_AS_SPECD = {"protocol": (GlyphProtocol.NFT.value, GlyphProtocol.CONTAINER.value), "name": "BTC"}


def _meta(**kw) -> GlyphMetadata:
    return GlyphMetadata(**kw)


@pytest.mark.parametrize(("label", "kw"), [("as on chain", _AS_ON_CHAIN), ("as spec'd", _AS_SPECD)])
class TestBothDeclarationsAreRecognisedEverywhere:
    """One test class per site, so a fix applied to only one copy fails here."""

    def test_the_is_container_property(self, label: str, kw: dict) -> None:
        assert _meta(**kw).is_container is True, label

    def test_the_inspect_classifier(self, label: str, kw: dict) -> None:
        assert _classify_metadata_protocol(_meta(**kw)) == "container", label

    def test_the_wave_mirror(self, label: str, kw: dict) -> None:
        assert classify_glyph_metadata(_meta(**kw)) == "container", label


class TestItDoesNotOverReach:
    """A guard that refuses valid work is a bug, and so is one that claims too much."""

    def test_a_plain_nft_is_not_a_container(self) -> None:
        m = _meta(protocol=(GlyphProtocol.NFT.value,), name="Just an NFT")
        assert m.is_container is False
        assert _classify_metadata_protocol(m) == "nft"

    def test_a_different_type_string_is_not_a_container(self) -> None:
        m = _meta(protocol=(GlyphProtocol.NFT.value,), token_type="object", name="Not one")
        assert m.is_container is False
        assert _classify_metadata_protocol(m) == "nft"

    @pytest.mark.parametrize("spelling", ["Container", "CONTAINER", "  container  "])
    def test_case_and_whitespace_do_not_change_the_declaration(self, spelling: str) -> None:
        """`type` is free CBOR text written by whatever minted the token; the four
        mainnet containers all use lowercase, but nothing forces that."""
        assert _meta(protocol=(GlyphProtocol.NFT.value,), token_type=spelling).is_container is True
