"""A creator signature must verify after the token has been PUBLISHED, not just in memory.

#633 fixed `sign_metadata` and asserted "the signature it returns actually verifies". It did —
through `verify_creator_signature(sign_metadata(...))`, which never crosses `encode_payload`. On
the only transport a signature exists for, it did not:

    plain NFT               ON CHAIN=True
    NFT with a description  ON CHAIN=False  signature mismatch
    timelocked NFT          ON CHAIN=False  signature mismatch

`_cbor_for_signing` produced insertion-order CBOR while `encode_payload` publishes canonical
(payload.py:67), so the signed bytes were never the published bytes. It passed for a plain NFT
because that metadata's field order happens to already be canonical — the fixture could not
express the defect.

Underneath that sat a second mismatch: the creator sub-map was hand-built as `{pubkey, sig, algo}`
while `GlyphCreator.to_cbor_dict` OMITS `algo` at its default (types.py:174), so the signed bytes
carried a key the published bytes never had.

Every case here goes bytes-out-and-back. "Wherever a value crosses a boundary, round-trip it
through the transport that actually carries it" — a fixture that hands the code a value the real
system never produces is internally consistent and verifies nothing.
"""

from __future__ import annotations

import os

import pytest

from pyrxd.glyph.creator import sign_metadata, verify_creator_signature
from pyrxd.glyph.encrypted_content import CryptoMetadata, TimelockSpec
from pyrxd.glyph.payload import decode_payload, encode_payload
from pyrxd.glyph.types import GlyphMetadata
from pyrxd.keys import PrivateKey


def _key() -> PrivateKey:
    return PrivateKey(os.urandom(32))


def _published(m: GlyphMetadata, key: PrivateKey) -> GlyphMetadata:
    """Sign, publish, read back — exactly what a chain does to a token."""
    return decode_payload(encode_payload(sign_metadata(m, key))[0])


def _sealed() -> GlyphMetadata:
    cek = "sha256:" + os.urandom(32).hex()
    spec = TimelockSpec(mode="block", unlock_at=500_000, cek_hash=cek)
    return GlyphMetadata(
        name="sealed",
        token_type="nft",
        protocol=[2, 8, 9],
        crypto=CryptoMetadata(cek_hash=cek, timelock=spec),
        timelock=spec,
    )


_CASES = {
    # Passed even while broken: this metadata's field order is already canonical, so the
    # insertion-order bug was invisible. Kept as the control.
    "plain_nft": GlyphMetadata(name="p", token_type="nft", protocol=[2]),
    # `desc` sorts BEFORE `name` canonically and after it in emission order — the smallest
    # metadata that distinguishes the two encodings.
    "with_description": GlyphMetadata(name="p", token_type="nft", protocol=[2], description="hello"),
    "several_reordered": GlyphMetadata(
        name="p", token_type="nft", protocol=[2], description="d", loc="ipfs://x", ticker="TST"
    ),
    "timelocked": _sealed(),
}


class TestASignatureSurvivesPublication:
    @pytest.mark.parametrize("name", sorted(_CASES))
    def test_it_verifies_after_a_round_trip_through_the_chain(self, name: str) -> None:
        ok, reason = verify_creator_signature(_published(_CASES[name], _key()))
        assert ok, f"{name}: {reason}"
        assert reason == "", f"{name}: verified but disclosed {reason!r}"

    def test_the_fixture_set_can_actually_express_the_defect(self) -> None:
        """Non-vacuity, and the reason #633's tests missed this. At least one case must encode
        DIFFERENTLY under canonical and insertion order — otherwise every case is a `plain_nft`
        and the suite passes on a broken encoder."""
        import cbor2

        differing = [
            n
            for n, m in _CASES.items()
            if cbor2.dumps(m.to_cbor_dict(), canonical=True) != cbor2.dumps(m.to_cbor_dict())
        ]
        assert differing, "no case distinguishes canonical from insertion order — the suite is blind"


class TestItStillDoesNotAcceptWhatItShouldRefuse:
    """The guard must not have become permissive while being made to work."""

    def test_a_tampered_payload_is_refused(self) -> None:
        import dataclasses

        signed = sign_metadata(_CASES["with_description"], _key())
        tampered = dataclasses.replace(signed, description="something else", source_cbor=None)
        ok, _ = verify_creator_signature(decode_payload(encode_payload(tampered)[0]))
        assert not ok

    def test_a_forged_signature_is_refused(self) -> None:
        import dataclasses

        signed = sign_metadata(_CASES["timelocked"], _key())
        forged = dataclasses.replace(signed, creator=dataclasses.replace(signed.creator, sig="00" * 70))
        ok, _ = verify_creator_signature(decode_payload(encode_payload(forged)[0]))
        assert not ok
