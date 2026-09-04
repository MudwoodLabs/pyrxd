"""What a valid creator signature does and does not establish.

`verify_creator_signature` returns `(True, "")` for a token whose `creator.pubkey`
signed its metadata. That key is a FIELD OF THE SAME BLOB, so a `True` means only
"the key named here signed this" — nothing binds it to the minting key, the commit
outpoint, or any identity known in advance.

The docstring said "Verify the creator signature embedded in metadata", which reads
as authorship, on a function exported as public API (`pyrxd.glyph.__init__`) and
listed in `docs/concepts/architecture.md` as a shipped capability. No in-tree caller
surfaces a verdict, so the reader at risk is an SDK consumer building a badge on the
boolean.

The repo already states the correct principle one module over, in
`script/hashmark.py`: "Without a value fixed in advance to compare against, recovery
is circular and proves nothing: an attacker would simply write whatever hash their
chosen signature recovers to." HashMark commits the signer hash160 TWICE and requires
both to match. This has one copy and compares it to itself.

These tests pin the demonstration so the narrow reading cannot quietly widen again.
"""

from __future__ import annotations

import os

import pytest

from pyrxd.glyph.creator import sign_metadata, verify_creator_signature
from pyrxd.glyph.types import GlyphMetadata
from pyrxd.keys import PrivateKey


@pytest.fixture
def metadata() -> GlyphMetadata:
    return GlyphMetadata(protocol=[2], name="Alice's Masterpiece", ticker="ALICE")


def test_a_verbatim_copy_signed_by_ANOTHER_KEY_also_verifies(metadata: GlyphMetadata) -> None:
    """The whole point. Mallory copies Alice's metadata, signs with her own key, and
    the verdict is identical — so `True` cannot mean Alice made it."""
    alice, mallory = PrivateKey(os.urandom(32)), PrivateKey(os.urandom(32))
    genuine = sign_metadata(metadata, alice)
    counterfeit = sign_metadata(metadata, mallory)

    assert verify_creator_signature(genuine) == (True, "")
    assert verify_creator_signature(counterfeit) == (True, "")
    assert genuine.name == counterfeit.name and genuine.ticker == counterfeit.ticker
    assert genuine.creator.pubkey != counterfeit.creator.pubkey, "only the key differs"


def test_the_pubkey_is_the_ONLY_thing_distinguishing_them(metadata: GlyphMetadata) -> None:
    """So a consumer that wants authorship has exactly one thing to compare, and must
    have obtained it from somewhere other than the token."""
    alice, mallory = PrivateKey(os.urandom(32)), PrivateKey(os.urandom(32))
    genuine = sign_metadata(metadata, alice)
    counterfeit = sign_metadata(metadata, mallory)

    expected = alice.public_key().serialize(compressed=True).hex()
    assert genuine.creator.pubkey == expected
    assert counterfeit.creator.pubkey != expected


def test_it_DOES_detect_metadata_altered_after_signing(metadata: GlyphMetadata) -> None:
    """The honest half — the check is worth having, and a narrower docstring must not
    be read as 'this function is useless'."""
    import dataclasses

    alice = PrivateKey(os.urandom(32))
    signed = sign_metadata(metadata, alice)
    tampered = dataclasses.replace(signed, name="Someone Else's Masterpiece")

    ok, reason = verify_creator_signature(tampered)
    assert not ok and "mismatch" in reason


def test_the_docstring_states_the_narrow_reading(metadata: GlyphMetadata) -> None:
    """Reachability for the correction itself: this is public API whose only
    consumer-facing guidance is that docstring."""
    doc = verify_creator_signature.__doc__ or ""
    assert "DOES NOT ESTABLISH AUTHORSHIP" in doc
    assert "fixed IN ADVANCE" in doc
