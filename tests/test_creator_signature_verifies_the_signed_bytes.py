"""A creator signature must be checked against the bytes the creator SIGNED.

`verify_creator_signature` re-derived the signed form by calling `to_cbor_dict()` on
the DECODED metadata. Decoding is deliberately lossy — `_cbor_str` drops a
wrong-typed field to "" rather than raising, because Photonic mints `loc` as an
INTEGER on mainnet and refusing those tokens showed the user "metadata: NONE". So
the verifier compared the signature against bytes the creator never signed, and
reported an HONEST, correctly-signed token as a forgery.

`loc` is one instance; the defect is the class. Any field the decoder normalises —
now, or the next time it learns a leniency — silently becomes a forgery verdict. The
failure therefore gets WORSE as the decoder gets more forgiving, which is the
opposite of how leniency should behave.

The fix carries the original bytes on the decoded object and verifies against those.
The thing not to trade it for is a gap the other way: a signature valid over on-chain
bytes does not mean the creator signed what is being DISPLAYED. When the decode was
lossy, the verdict says so.

`verify_creator_signature` has no caller inside pyrxd — it is exported public API, so
these tests ARE its production entry point, and every case below goes through
`decode_payload` rather than constructing metadata by hand.
"""

from __future__ import annotations

import hashlib
import os

import cbor2
import pytest

from pyrxd.glyph.creator import _CREATOR_PREFIX, sign_metadata, verify_creator_signature
from pyrxd.glyph.payload import decode_payload
from pyrxd.glyph.types import GlyphMetadata
from pyrxd.hash import hash256
from pyrxd.keys import PrivateKey


@pytest.fixture
def key() -> PrivateKey:
    return PrivateKey(os.urandom(32))  # never a hand-written key


@pytest.fixture
def signed(key: PrivateKey) -> GlyphMetadata:
    return sign_metadata(GlyphMetadata(protocol=[2], name="Test", ticker="TST", loc="ipfs://x"), key)


def _mint(key: PrivateKey, signed: GlyphMetadata, *, loc, tamper: str | None = None) -> GlyphMetadata:
    """Mint as a THIRD-PARTY writer would, then read it back the way pyrxd does.

    The signature is made over the bytes as published, so `tamper` models a publisher
    who signed one thing and put another on chain — not a corrupted signature.
    """
    pubkey = key.public_key().serialize(compressed=True).hex()
    d = signed.to_cbor_dict()
    d["loc"] = loc
    d["creator"] = {"pubkey": pubkey, "sig": "", "algo": "ecdsa-secp256k1"}
    message = hashlib.sha256(_CREATOR_PREFIX + hash256(cbor2.dumps(d))).digest()
    d["creator"]["sig"] = key.sign(message, hasher=None).hex()
    if tamper is not None:
        d["name"] = tamper
    return decode_payload(cbor2.dumps(d))


class TestAnHonestTokenIsNotCalledForged:
    def test_an_integer_loc_still_verifies(self, key: PrivateKey, signed: GlyphMetadata) -> None:
        """The shape measured on live mainnet. This returned "signature mismatch"."""
        ok, _ = verify_creator_signature(_mint(key, signed, loc=0))
        assert ok

    @pytest.mark.parametrize("loc", [0, 42, b"bytes", ["a"], {"k": "v"}, True], ids=repr)
    def test_ANY_normalised_type_still_verifies(self, key: PrivateKey, signed: GlyphMetadata, loc) -> None:
        """Fixing only the integer case would leave the class intact — the decoder
        drops every non-string, and each one was its own false forgery."""
        ok, _ = verify_creator_signature(_mint(key, signed, loc=loc))
        assert ok

    def test_the_control_still_verifies(self, key: PrivateKey, signed: GlyphMetadata) -> None:
        """Same construction, an ordinary text loc. If this ever fails the tests above
        prove nothing: they would be passing for a reason unrelated to the fix."""
        ok, reason = verify_creator_signature(_mint(key, signed, loc="ipfs://x"))
        assert ok and reason == ""

    def test_in_memory_metadata_with_no_source_bytes_still_verifies(self, signed: GlyphMetadata) -> None:
        """The path a caller takes right after signing, where the object IS the original."""
        assert signed.source_cbor is None
        assert verify_creator_signature(signed) == (True, "")


class TestAForgeryIsStillRefused:
    """The other half. A verifier that accepts everything passes every test above."""

    def test_a_field_changed_after_signing_is_refused(self, key: PrivateKey, signed: GlyphMetadata) -> None:
        ok, reason = verify_creator_signature(_mint(key, signed, loc="ipfs://x", tamper="Evil"))
        assert not ok and "mismatch" in reason

    def test_tampering_is_refused_even_on_the_lossy_path(self, key: PrivateKey, signed: GlyphMetadata) -> None:
        """The fix must not have opened a bypass for exactly the records it rescued."""
        ok, _ = verify_creator_signature(_mint(key, signed, loc=0, tamper="Evil"))
        assert not ok

    def test_a_signature_from_another_key_is_refused(self, key: PrivateKey, signed: GlyphMetadata) -> None:
        record = _mint(key, signed, loc=0)
        other = PrivateKey(os.urandom(32)).public_key().serialize(compressed=True).hex()
        ok, _ = verify_creator_signature(
            GlyphMetadata(
                protocol=record.protocol,
                source_cbor=record.source_cbor,
                creator=type(record.creator)(pubkey=other, sig=record.creator.sig, algo=record.creator.algo),
            )
        )
        assert not ok


class TestALossyDecodeIsDisclosed:
    """VERIFIED must not quietly mean "signed bytes you are not being shown"."""

    def test_a_lossy_decode_says_so(self, key: PrivateKey, signed: GlyphMetadata) -> None:
        ok, reason = verify_creator_signature(_mint(key, signed, loc=0))
        assert ok and "NOT byte-identical" in reason

    def test_a_lossless_decode_says_nothing(self, key: PrivateKey, signed: GlyphMetadata) -> None:
        assert verify_creator_signature(_mint(key, signed, loc="ipfs://x")) == (True, "")
