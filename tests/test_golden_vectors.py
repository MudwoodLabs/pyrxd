"""Frozen golden-vector tests for cryptographic determinism.

Each test pins a small, stable input and asserts the encoder/signer
reproduces the exact byte output captured the first time the test was
written. Both layers underpin on-chain correctness:

* If CBOR encoding stops being deterministic across releases, two
  copies of the same logical token payload would hash to different
  ``payload_hash`` values, and indexers re-encoding metadata to
  verify against the on-chain commit hash would silently disagree.
* If ECDSA signing stops being deterministic (e.g. coincurve swapped
  for a backend that uses random k), two signs of the same message
  with the same key produce different DER bytes, breaking
  reproducible test vectors and any deploy that re-broadcasts a saved
  signed reveal hex.

These tests fail loudly the moment any change in dependency, encoder,
or hashing path perturbs the byte output. Updating a frozen vector
should be a deliberate, reviewed act — not a side effect of a
"chore: bump deps" commit.
"""

from __future__ import annotations

from pyrxd.glyph.dmint import DaaMode, DmintAlgo, DmintCborPayload
from pyrxd.glyph.payload import encode_payload
from pyrxd.glyph.types import GlyphMetadata, GlyphProtocol
from pyrxd.keys import PrivateKey

# ---------------------------------------------------------------------------
# Frozen reference CBOR goldfile
# ---------------------------------------------------------------------------

# Hand-picked input that exercises every CBOR-relevant field on the
# happy path: protocol list, name+ticker+description, decimals, image
# URL/IPFS/SHA-256, version=2, full dmint sub-payload with ASERT mode.
# Field-by-field equality of the output bytes catches:
# * Reordering ``to_cbor_dict`` keys.
# * cbor2 changing canonicalisation rules in a future release.
# * Anyone removing ``canonical=True`` from ``encode_payload``.
# * Quietly dropping a metadata field from the encode path.
_FROZEN_REFERENCE_CBOR_HEX = "a961708201046176026464657363783d46726f7a656e207265666572656e636520746f6b656e207573656420746f2070696e2043424f5220656e636f64696e672064657465726d696e69736d2e646e616d65745265666572656e6365205465737420546f6b656e65646d696e74a763646161a3646d6f6465026868616c664c696665190e106f746172676574426c6f636b54696d6519025864616c676f00646469666601667265776172641864677072656d696e65192710696d61784865696768741a000f42406c6e756d436f6e7472616374730165696d616765781c68747470733a2f2f6578616d706c652e6f72672f7274742e77656270667469636b6572635254546a696d6167655f69706673782e516d5265666572656e6365496d61676548617368506c616365686f6c6465723132333435363738394162436445666c696d6167655f736861323536784030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030"
_FROZEN_REFERENCE_PAYLOAD_HASH_HEX = "16e1432f0671fd3407c59b5c9ece6a8ab4cd735d87493a44ce07e05fa08516be"


def _make_frozen_reference_metadata() -> GlyphMetadata:
    """Construct the exact GlyphMetadata used to derive the frozen vector.

    Spelled out so the test failure can be reproduced — a test that
    asserts pinned bytes against an opaque fixture is impossible to
    debug when it breaks.
    """
    dmint = DmintCborPayload(
        algo=DmintAlgo.SHA256D,
        num_contracts=1,
        max_height=1_000_000,
        reward=100,
        premine=10_000,
        diff=1,
        daa_mode=DaaMode.ASERT,
        target_block_time=600,
        half_life=3600,
    )
    return GlyphMetadata(
        protocol=[GlyphProtocol.FT, GlyphProtocol.DMINT],
        name="Reference Test Token",
        ticker="RTT",
        description="Frozen reference token used to pin CBOR encoding determinism.",
        decimals=0,
        image_url="https://example.org/rtt.webp",
        image_ipfs="QmReferenceImageHashPlaceholder123456789AbCdEf",
        image_sha256="00" * 32,
        v=2,
        dmint_params=dmint,
    )


class TestFrozenReferenceCborGoldfile:
    """Pinned-byte regression for ``encode_payload``. If a future
    refactor or dependency bump changes any byte of the output, this
    test fails — forcing a deliberate review of the on-chain impact.
    """

    def test_cbor_bytes_match_frozen_value(self):
        cbor_bytes, _ = encode_payload(_make_frozen_reference_metadata())
        actual_hex = cbor_bytes.hex()
        assert actual_hex == _FROZEN_REFERENCE_CBOR_HEX, (
            "Reference CBOR encoding drifted.\n"
            f"  expected: {_FROZEN_REFERENCE_CBOR_HEX}\n"
            f"  actual:   {actual_hex}\n"
            "If this is intentional (encoder upgrade, schema change), update "
            "_FROZEN_REFERENCE_CBOR_HEX with reviewer sign-off — do not silently "
            "regenerate."
        )

    def test_payload_hash_matches_frozen_value(self):
        _, payload_hash = encode_payload(_make_frozen_reference_metadata())
        assert payload_hash.hex() == _FROZEN_REFERENCE_PAYLOAD_HASH_HEX

    def test_repeated_encodes_are_byte_identical(self):
        """Sanity: ``canonical=True`` must give the same bytes every
        call. If this regresses, the frozen-bytes test catches it
        too — but the explicit determinism check makes the failure
        mode obvious in CI output.
        """
        a, _ = encode_payload(_make_frozen_reference_metadata())
        b, _ = encode_payload(_make_frozen_reference_metadata())
        assert a == b

    def test_field_reorder_does_not_change_output(self):
        """Building the same metadata twice with constructor arg order
        flipped (where the dataclass allows it via keyword args) must
        still produce the frozen bytes — proves cbor2's canonical
        ordering is in force, not Python dict insertion order.
        """
        m1 = _make_frozen_reference_metadata()
        # Build a second metadata identical in content.
        m2 = GlyphMetadata(
            decimals=0,
            ticker="RTT",
            name="Reference Test Token",
            protocol=[GlyphProtocol.FT, GlyphProtocol.DMINT],
            description="Frozen reference token used to pin CBOR encoding determinism.",
            image_url="https://example.org/rtt.webp",
            image_ipfs="QmReferenceImageHashPlaceholder123456789AbCdEf",
            image_sha256="00" * 32,
            v=2,
            dmint_params=DmintCborPayload(
                algo=DmintAlgo.SHA256D,
                num_contracts=1,
                max_height=1_000_000,
                reward=100,
                premine=10_000,
                diff=1,
                daa_mode=DaaMode.ASERT,
                target_block_time=600,
                half_life=3600,
            ),
        )
        a, _ = encode_payload(m1)
        b, _ = encode_payload(m2)
        assert a == b
        assert a.hex() == _FROZEN_REFERENCE_CBOR_HEX


# ---------------------------------------------------------------------------
# N12 — ECDSA RFC-6979 deterministic-signing golden vector
# ---------------------------------------------------------------------------

# Pinned vector. The private key is the all-0x01 scalar (well within
# secp256k1 group order), the message is a stable ASCII string. The
# expected DER signature is what coincurve+libsecp256k1 produce today
# under RFC 6979 + low-s normalisation. Any change to the signing
# backend, the hasher (default ``hash256`` = double-SHA256), or the
# DER encoding will perturb this output.
_GOLDEN_PRIV_HEX = "01" * 32
_GOLDEN_MSG = b"pyrxd golden vector v1 -- RFC 6979 deterministic signing self-test"
_GOLDEN_SIG_DER_HEX = (
    "304502210090f91a0f7713390279f6d919594bccbdd6e2e0a09bb12d2cdb72e8ba7c55efbb"
    "02204baffc1afb761122f01b5e1cbe609688e44e7ab8f46e70c3dcb91fa50c7858ca"
)


class TestEcdsaRfc6979GoldenVector:
    """Pinned-byte regression for deterministic ECDSA signing. Catches:

    * coincurve replaced by a backend that re-introduces randomised k.
    * ``PrivateKey.sign`` default hasher changing from ``hash256``.
    * DER encoder regression (low-s, length prefix, 0x30 wrapper).
    """

    def test_signature_matches_frozen_value(self):
        priv = PrivateKey(bytes.fromhex(_GOLDEN_PRIV_HEX))
        sig = priv.sign(_GOLDEN_MSG)
        assert sig.hex() == _GOLDEN_SIG_DER_HEX, (
            "ECDSA signing drifted from frozen RFC-6979 vector.\n"
            f"  expected: {_GOLDEN_SIG_DER_HEX}\n"
            f"  actual:   {sig.hex()}\n"
            "Investigate before updating: a real RFC-6979 implementation "
            "produces byte-identical output across releases. A divergence "
            "means the signing backend changed."
        )

    def test_repeated_signs_are_byte_identical(self):
        """Same key + same message must produce the same DER bytes on
        every call. If this fails the implementation is using random k.
        """
        priv = PrivateKey(bytes.fromhex(_GOLDEN_PRIV_HEX))
        sig_a = priv.sign(_GOLDEN_MSG)
        sig_b = priv.sign(_GOLDEN_MSG)
        assert sig_a == sig_b

    def test_signature_is_low_s(self):
        """Bitcoin-strict DER requires s <= n/2. Asserting on the frozen
        vector locks that property in regardless of which backend
        produced the bytes.
        """
        from pyrxd.curve import curve

        sig = bytes.fromhex(_GOLDEN_SIG_DER_HEX)
        # DER: 0x30 LEN 0x02 RLEN R 0x02 SLEN S
        assert sig[0] == 0x30
        # Skip past r.
        r_len = sig[3]
        s_offset = 4 + r_len + 2
        s_len = sig[s_offset - 1]
        s_bytes = sig[s_offset : s_offset + s_len]
        s_int = int.from_bytes(s_bytes, "big")
        assert s_int <= curve.n // 2, "frozen signature is not low-s"

    def test_signature_verifies_against_public_key(self):
        """End-to-end: the frozen DER must verify under the public key
        derived from the frozen private scalar. Catches any bug that
        produces a structurally-valid but mathematically-wrong signature.
        """
        priv = PrivateKey(bytes.fromhex(_GOLDEN_PRIV_HEX))
        sig = bytes.fromhex(_GOLDEN_SIG_DER_HEX)
        pub = priv.public_key()
        assert pub.verify(sig, _GOLDEN_MSG), "frozen signature failed to verify under derived public key"

    def test_different_message_changes_signature(self):
        """Sanity: same key + different message must produce different
        bytes. Without this assertion a buggy backend that always
        returned the same constant signature would pass the
        round-trip test trivially.
        """
        priv = PrivateKey(bytes.fromhex(_GOLDEN_PRIV_HEX))
        sig_a = priv.sign(_GOLDEN_MSG)
        sig_b = priv.sign(_GOLDEN_MSG + b"!")
        assert sig_a != sig_b

    def test_different_key_changes_signature(self):
        """Sanity: same message + different key must produce different
        bytes."""
        sig_a = PrivateKey(bytes.fromhex(_GOLDEN_PRIV_HEX)).sign(_GOLDEN_MSG)
        sig_b = PrivateKey(bytes.fromhex("02" * 32)).sign(_GOLDEN_MSG)
        assert sig_a != sig_b
