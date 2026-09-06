"""A TIMELOCK glyph cannot be encoded without its CEK commitment — on EVERY write path.

#625 put this invariant on `GlyphMinter._require_protocol`, reasoning it belonged "inside the
operation that broadcasts". There are TWO such operations. `pyrxd glyph mint-nft` builds through
`GlyphBuilder.prepare_commit` and never touches `GlyphMinter` — and `pyrxd glyph timelock-mint`
routes through the same `_mint_nft_inner` (glyph_timelock_cmds.py:307). So the exact token the
gate was written to prevent stayed mintable from the CLI, which is how most users mint.

A caller grep came back clean, because `_require_protocol` genuinely IS called — from the SDK
minter. That is the shape worth remembering: "this guard has a production caller" and "this guard
is on every production path" are different claims, and only the second one is the fix.

The invariant now lives on `encode_payload`, the single funnel every write path goes through, and
NOT on the read path: `decode_payload` never calls it, so third-party tokens with junk metadata
stay decodable. A guard that made those undecodable would refuse honest work aimed at the wrong
half.
"""

from __future__ import annotations

import os

import pytest

from pyrxd.glyph.builder import CommitParams, GlyphBuilder
from pyrxd.glyph.encrypted_content import CryptoMetadata, TimelockSpec
from pyrxd.glyph.payload import decode_payload, encode_payload
from pyrxd.glyph.types import GlyphMetadata, GlyphProtocol
from pyrxd.security.errors import ValidationError

_NFT, _ENC, _TL = GlyphProtocol.NFT, GlyphProtocol.ENCRYPTED, GlyphProtocol.TIMELOCK


def _commitment() -> CryptoMetadata:
    cek = "sha256:" + os.urandom(32).hex()
    return CryptoMetadata(cek_hash=cek, timelock=TimelockSpec(mode="block", unlock_at=500_000, cek_hash=cek))


def _meta(protocol, crypto=None) -> GlyphMetadata:
    return GlyphMetadata(name="t", token_type="nft", protocol=list(protocol), crypto=crypto)


def _build(metadata: GlyphMetadata):
    """The path `pyrxd glyph mint-nft` actually takes — GlyphBuilder, not GlyphMinter."""
    return GlyphBuilder().prepare_commit(
        CommitParams(metadata=metadata, owner_pkh=b"\x11" * 20, change_pkh=b"\x22" * 20, funding_satoshis=100_000)
    )


class TestTheCliPathIsGatedToo:
    """The bypass, pinned at the entry point that had none."""

    def test_the_builder_refuses_a_timelock_with_no_commitment(self) -> None:
        with pytest.raises(ValidationError, match="no crypto.timelock"):
            _build(_meta([_NFT, _ENC, _TL]))

    def test_bare_encode_refuses_it_too(self) -> None:
        """The funnel itself, so an SDK caller who never touches the builder is covered."""
        with pytest.raises(ValidationError, match="no crypto.timelock"):
            encode_payload(_meta([_NFT, _ENC, _TL]))

    def test_the_refusal_names_the_supported_way_to_do_it(self) -> None:
        """An operator who hits this is mid-mint. A refusal that does not say what to do instead
        sends them to the source."""
        with pytest.raises(ValidationError) as exc:
            encode_payload(_meta([_NFT, _ENC, _TL]))
        assert "build_timelock_mint" in str(exc.value)


class TestItDoesNotRefuseHonestWork:
    """The half that makes it safe to put on a funnel every mint crosses."""

    @pytest.mark.parametrize("protocol", [[_NFT], [_NFT, _ENC], [GlyphProtocol.FT]], ids=["nft", "nft+encrypted", "ft"])
    def test_a_glyph_without_the_timelock_marker_is_untouched(self, protocol) -> None:
        assert _build(_meta(protocol)) is not None
        assert encode_payload(_meta(protocol))[0]

    def test_a_timelock_WITH_its_commitment_builds(self) -> None:
        assert _build(_meta([_NFT, _ENC, _TL], crypto=_commitment())) is not None


class TestTheReadPathStaysPermissive:
    """The gate must not reach decoding. Timelocked tokens with junk metadata exist on chain and
    a reader has to survive them — that is why this is on `encode_payload` and not in
    `GlyphMetadata.__post_init__`."""

    def test_a_timelocked_token_round_trips_and_keeps_its_commitment(self) -> None:
        m = _meta([_NFT, _ENC, _TL], crypto=_commitment())
        original = encode_payload(m)[0]
        decoded = decode_payload(original)
        assert decoded.crypto is not None and decoded.timelock is not None
        assert encode_payload(decoded)[0] == original, "re-encoding a decoded token must be byte-exact"

    def test_constructing_the_refused_shape_is_still_allowed(self) -> None:
        """`decode_payload` builds exactly this object for every timelocked token it reads. The
        refusal is at ENCODE, so the object itself must remain constructible."""
        assert _meta([_NFT, _ENC, _TL]).crypto is None
