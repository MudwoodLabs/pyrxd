"""`sign_metadata` must return the metadata it signed — every field, and a verifiable signature.

Security review finding (confirmed MEDIUM). It rebuilt `GlyphMetadata` by naming 20 fields, and
whatever it did not name was silently dropped: `crypto`, `encrypted_main`, `timelock`,
`container_refs`, `author_refs`. Signing a timelocked token therefore returned an object that had
lost its CEK commitment and its per-recipient key wraps — and whose own signature every verifier
reported as `signature mismatch`.

Two defects, one visible and one under it:

1. The hand-kept copy list. Fixed by `dataclasses.replace`, which copies what the dataclass
   declares, so a field added later is carried without anyone remembering this call site.
2. `creator` was APPENDED to the CBOR map when signing (input had no creator) but left in the
   encoder's position when verifying (input had one) — Python keeps an existing key's position on
   assignment. Same logical map, different byte order, mismatch. Latent while `creator` happened
   to be the last key anyway, which is every plain NFT.

Both are pinned here against a metadata that carries a field emitted AFTER `creator` — the shape
that exposes the ordering bug. A fixture without one cannot tell the two orders apart.
"""

from __future__ import annotations

import dataclasses
import os

import pytest

from pyrxd.glyph.creator import sign_metadata, verify_creator_signature
from pyrxd.glyph.encrypted_content import CryptoMetadata, TimelockSpec
from pyrxd.glyph.types import GlyphMetadata
from pyrxd.keys import PrivateKey

_UNLOCK = 500_000


def _sealed() -> GlyphMetadata:
    cek = "sha256:" + os.urandom(32).hex()
    spec = TimelockSpec(mode="block", unlock_at=_UNLOCK, cek_hash=cek)
    return GlyphMetadata(
        name="sealed",
        token_type="nft",
        protocol=[2, 8, 9],
        crypto=CryptoMetadata(cek_hash=cek, timelock=spec),
        timelock=spec,
    )


def _key() -> PrivateKey:
    return PrivateKey(os.urandom(32))


class TestNothingIsDroppedOnTheWayThrough:
    def test_every_field_except_the_two_that_must_change_survives(self) -> None:
        """Derived, not a list: compare against `dataclasses.fields` so a field added later is
        covered without editing this test — the failure mode being fixed."""
        original = _sealed()
        signed = sign_metadata(original, _key())
        changed = {
            f.name for f in dataclasses.fields(GlyphMetadata) if getattr(signed, f.name) != getattr(original, f.name)
        }
        assert "creator" in changed, "signing must set the creator"
        assert changed <= {"creator", "source_cbor"}, (
            f"sign_metadata altered {sorted(changed)}; only `creator` (the point) and `source_cbor` "
            "(stale — those bytes predate the signature) may differ."
        )

    def test_source_cbor_is_reset_when_there_was_one(self) -> None:
        """The subset assertion above cannot see this on an in-memory build, where `source_cbor` is
        None on both sides and 'unchanged' and 'correctly cleared' are indistinguishable. Feed it a
        DECODED object so the field has something to lose."""
        from pyrxd.glyph.payload import decode_payload, encode_payload

        decoded = decode_payload(encode_payload(_sealed())[0])
        assert decoded.source_cbor is not None, "fixture must actually carry source bytes"
        assert sign_metadata(decoded, _key()).source_cbor is None, (
            "those bytes predate the signature — keeping them would let a verifier check the "
            "signature against bytes that do not contain it"
        )

    @pytest.mark.parametrize("field", ["crypto", "timelock", "encrypted_main"])
    def test_the_encrypted_content_fields_specifically(self, field: str) -> None:
        """Named individually as well, because these are the ones whose loss is unrecoverable:
        the commitment cannot be re-attached to a minted token."""
        original = _sealed()
        assert getattr(sign_metadata(original, _key()), field) == getattr(original, field)


class TestTheSignatureItReturnsActuallyVerifies:
    def test_a_timelocked_token_verifies(self) -> None:
        """The case that failed: a field is emitted after `creator`, so the two orders differ."""
        ok, reason = verify_creator_signature(sign_metadata(_sealed(), _key()))
        assert ok and reason == "", reason

    def test_a_plain_nft_still_verifies(self) -> None:
        """The control. This passed before the fix — if it ever fails, the test above proves
        nothing, because it would be passing for an unrelated reason."""
        plain = GlyphMetadata(name="plain", token_type="nft", protocol=[2])
        ok, reason = verify_creator_signature(sign_metadata(plain, _key()))
        assert ok and reason == "", reason

    def test_a_tampered_signature_is_still_refused(self) -> None:
        """The guard must not have become permissive in the process."""
        signed = sign_metadata(_sealed(), _key())
        forged = dataclasses.replace(signed, creator=dataclasses.replace(signed.creator, sig="00" * 70))
        ok, _ = verify_creator_signature(forged)
        assert not ok
