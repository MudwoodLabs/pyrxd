"""Spec §10.2 tells a second implementer how to verify a creator signature. Execute it.

The section is a RECIPE addressed to somebody outside this repository, and prose is a
claim no ordinary test evaluates: the suite can pin that pyrxd verifies its own
signatures without ever asking whether the published instructions for doing so are
right. They were not. Until this file existed, §10.2 said the signing encoder was
``cbor2.dumps(d)`` **without** ``canonical=True`` and that an implementation "MUST
reproduce the insertion order of pyrxd's ``to_cbor_dict`` … using a canonical encoder
here produces a different message and the signature fails."

Every clause of that was false once #639 made signing canonical, and it was false in
the harmful direction: an implementer following it builds a verifier that REJECTS
valid pyrxd signatures — the 0.22.0 shape, where a published artifact taught a rule
the code does not implement.

It survived a mechanical repair, too. A doc-citation sweep re-pointed the sentence's
citation from ``creator.py:43`` to ``creator.py:117`` — landing it exactly on
``return cbor2.dumps(d, canonical=True)``, the line that refutes the sentence citing
it. A citation checker asks whether a pointer lands on code, not whether the code says
what the prose claims.

So this file does not check the words. It performs the recipe, using nothing from
``pyrxd.glyph.creator`` but the domain-separation prefix, and asserts a second
implementer succeeds — and, in the other direction, that the approach §10.2 forbids
really does fail, so the prohibition is load-bearing rather than decorative.
"""

from __future__ import annotations

import hashlib
import os

import cbor2
import pytest

from pyrxd.glyph.creator import _CREATOR_PREFIX, sign_metadata
from pyrxd.glyph.payload import decode_payload, encode_payload
from pyrxd.glyph.types import GlyphCreator, GlyphMetadata
from pyrxd.hash import hash256
from pyrxd.keys import PrivateKey, PublicKey

# One case per shape that matters. `multi_field` is the discriminating one: canonical
# order sorts `desc` before `name` while `to_cbor_dict` emits `name` first, so the two
# recipes diverge. `single_field` cannot tell them apart and is here to show that a
# suite built only from tokens like it would have passed against the false spec.
CASES = {
    "single_field": GlyphMetadata(protocol=[2], name="A"),
    "multi_field": GlyphMetadata(protocol=[2], name="A", description="d"),
    "many_fields": GlyphMetadata(protocol=[2], name="Token", description="d", ticker="TKN", loc="ipfs://x"),
}


@pytest.fixture(scope="module")
def key() -> PrivateKey:
    return PrivateKey(os.urandom(32))  # never a hand-written key


def _publish(key: PrivateKey, metadata: GlyphMetadata) -> bytes:
    """Mint as pyrxd does: sign, then encode the envelope. Returns the on-chain CBOR."""
    cbor_bytes, _hash = encode_payload(sign_metadata(metadata, key))
    return cbor_bytes


def _signature_holds(published: bytes, signing_input: bytes) -> bool:
    """§10.1's steps, run by an implementation that has only the spec."""
    creator = cbor2.loads(published)["creator"]
    message = hashlib.sha256(_CREATOR_PREFIX + hash256(signing_input)).digest()
    return PublicKey(bytes.fromhex(creator["pubkey"])).verify(bytes.fromhex(creator["sig"]), message, hasher=None)


def _recipe_from_the_spec(published: bytes) -> bytes:
    """§10.2 steps 1-3: take the map AS PUBLISHED, blank `creator.sig` IN PLACE, re-encode."""
    d = cbor2.loads(published)
    d["creator"]["sig"] = ""
    return cbor2.dumps(d)


def _the_approach_the_spec_FORBIDS(published: bytes, pubkey: str, algo: str) -> bytes:
    """Rebuild in pyrxd's source-declaration order — what §10.2 used to REQUIRE."""
    d = decode_payload(published).to_cbor_dict()
    d.pop("creator", None)
    unsigned = GlyphCreator(pubkey=pubkey, sig="00", algo=algo).to_cbor_dict()
    unsigned["sig"] = ""
    d["creator"] = unsigned
    return cbor2.dumps(d)


@pytest.mark.parametrize("case", sorted(CASES))
def test_an_implementer_following_10_2_verifies_the_signature(key: PrivateKey, case: str) -> None:
    """The documented recipe, executed literally, must accept an honest pyrxd token."""
    published = _publish(key, CASES[case])
    assert _signature_holds(published, _recipe_from_the_spec(published)), (
        f"spec §10.2's recipe rejects an honest pyrxd-minted token ({case}) — "
        "the published instructions do not match the published bytes"
    )


@pytest.mark.parametrize("case", ["multi_field", "many_fields"])
def test_the_order_10_2_forbids_really_does_fail(key: PrivateKey, case: str) -> None:
    """The prohibition is load-bearing: this is the recipe the section used to mandate."""
    metadata = CASES[case]
    published = _publish(key, metadata)
    creator = cbor2.loads(published)["creator"]
    wrong = _the_approach_the_spec_FORBIDS(published, creator["pubkey"], creator.get("algo", "ecdsa-secp256k1"))
    assert wrong != _recipe_from_the_spec(published), "the two recipes did not diverge"
    assert not _signature_holds(published, wrong), (
        "declaration-order reconstruction verified — if this ever passes, §10.2's "
        "MUST NOT has stopped being true and the section needs rewriting, not this test"
    )


def test_the_fixture_set_can_express_the_defect(key: PrivateKey) -> None:
    """Non-vacuity. Without a case whose canonical order differs from declaration
    order, the test above proves nothing — that is exactly why the false rule survived."""
    differing = [
        case
        for case in CASES
        if list(cbor2.loads(_publish(key, CASES[case])).keys()) != list(CASES[case].to_cbor_dict().keys())
    ]
    assert differing, (
        "no case distinguishes canonical order from declaration order — this suite "
        "would pass against a spec that mandates either"
    )


@pytest.mark.parametrize("case", sorted(CASES))
def test_the_signed_creator_submap_has_the_published_key_set(key: PrivateKey, case: str) -> None:
    """§10.2's closing claim: the signed map differs from the published map only in
    the VALUE of `sig`. It formerly claimed the signing sub-map "always contains all
    three keys", which would be a structural mismatch with the published two."""
    published = _publish(key, CASES[case])
    signed_submap = cbor2.loads(_recipe_from_the_spec(published))["creator"]
    published_submap = cbor2.loads(published)["creator"]
    assert set(signed_submap) == set(published_submap)
    assert signed_submap["sig"] == ""
    assert published_submap["sig"] != ""
    assert {k: v for k, v in signed_submap.items() if k != "sig"} == {
        k: v for k, v in published_submap.items() if k != "sig"
    }
