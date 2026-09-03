"""Real HashMark records from Radiant mainnet, produced by the REFERENCE writer.

This is the thing pyrxd's own conformance vectors cannot be. Ours are generated
from our own builders, so they can only ever prove pyrxd agrees with pyrxd —
which is how we once published vectors that accepted an exploitable HTLC timelock
ordering and rejected the correct one. These bytes were written by a DIFFERENT
implementation, by a different author, from the same specification.

Found by scanning 10,000 mainnet blocks (heights 451,021-461,021, roughly
2026-07-30 to 2026-09-03) for the `HASHMARK` magic. Three records, all from the
protocol's author testing ahead of launch.

The v2 record is the valuable one: its signature was produced by his signer and
is verified here by a decoder written from `HASHMARK_PROTOCOL.md` alone, without
reading his source. Two independent implementations agreeing on a real
cryptographic attestation.

If one of these ever stops decoding or verifying, either we broke something or
our reading of the spec was wrong — and both are worth being told about loudly.
"""

from __future__ import annotations

import pytest

from pyrxd.base58 import base58check_encode
from pyrxd.constants import NETWORK_ADDRESS_PREFIX_DICT, Network
from pyrxd.script.hashmark import AttestationOutcome, decode_hashmark, verify_attestation

#: Height 460,572. v2, signed. The signature verifies and the recovered key is the
#: creator address on the author's own Canon profile glyph — independently
#: confirmed, so these records are his rather than an unknown third party's.
_V2_SIGNED = bytes.fromhex(
    "6a08484153484d41524b02020120e2c55efb34b6e9d6db008ee72d56bf86456ab3f55ae76488ff677fda88df1f1e"
    "1426ba056431ec69cf27eabeaab250d99ddbd895d2411f750d18df9ab44ba66ced01285a5a067b9ebf7c8ff6b32d"
    "ddb40cc276c5e98d4c2054937e44a40d7628d80cafdd6a372b0aae8f8bb31dbb4d975273a23e8c9771"
)
#: Height 459,905. v1, and it marks the SAME digest as the v2 above — the same
#: file marked under v1 and then again under v2, which is what testing an upgrade
#: looks like.
_V1_SAME_DIGEST = bytes.fromhex(
    "6a08484153484d41524b02010120e2c55efb34b6e9d6db008ee72d56bf86456ab3f55ae76488ff677fda88df1f1e"
)
#: Height 460,364. v1, a different digest.
_V1_OTHER = bytes.fromhex(
    "6a08484153484d41524b0201012049f82c41b6d6c78dbffe0df9014177b1b423171b5b6b7e09cccb68e4746dbc05"
)

_SIGNER_HASH160 = "26ba056431ec69cf27eabeaab250d99ddbd895d2"
_SIGNER_ADDRESS = "14XmXG3dSBWZUukGT3xzS9zxpiZ53vgx1i"


class TestTheSignedMainnetRecord:
    def test_it_decodes(self) -> None:
        rec = decode_hashmark(_V2_SIGNED)
        assert rec.ok and rec.version == 2 and rec.algorithm == "sha256"
        assert rec.digest_hex == "e2c55efb34b6e9d6db008ee72d56bf86456ab3f55ae76488ff677fda88df1f1e"
        assert rec.signer_hash160_hex == _SIGNER_HASH160
        assert rec.label is None

    def test_A_REAL_SIGNATURE_FROM_ANOTHER_IMPLEMENTATION_VERIFIES(self) -> None:
        """The cross-implementation result, and the reason this file exists.

        His signer produced these bytes; our verifier — canonical statement,
        magic hash, key recovery, commitment check — was written from the spec
        without reading his code. It recovers the committed signer exactly.
        """
        res = verify_attestation(decode_hashmark(_V2_SIGNED))
        assert res.outcome is AttestationOutcome.VALID
        assert res.recovered_hash160_hex == _SIGNER_HASH160

    def test_the_recovered_key_is_the_authors_known_address(self) -> None:
        """Confirms whose records these are, from chain data rather than context:
        the recovered key encodes the creator address on the author's own profile
        glyph."""
        rec = decode_hashmark(_V2_SIGNED)
        addr = base58check_encode(
            NETWORK_ADDRESS_PREFIX_DICT[Network.MAINNET] + bytes.fromhex(rec.signer_hash160_hex or "")
        )
        assert addr == _SIGNER_ADDRESS

    def test_it_does_not_verify_against_another_chain(self) -> None:
        """`network` is in the signed statement and not in the record, so real
        mainnet bytes must fail elsewhere. Pinned on real data because the
        synthetic version of this test could pass with a broken statement builder
        that happened to be broken consistently."""
        res = verify_attestation(decode_hashmark(_V2_SIGNED), network_genesis="00" * 32)
        assert res.outcome is AttestationOutcome.INVALID_SIGNATURE


class TestTheUnsignedMainnetRecords:
    @pytest.mark.parametrize(
        ("raw", "digest"),
        [
            (_V1_SAME_DIGEST, "e2c55efb34b6e9d6db008ee72d56bf86456ab3f55ae76488ff677fda88df1f1e"),
            (_V1_OTHER, "49f82c41b6d6c78dbffe0df9014177b1b423171b5b6b7e09cccb68e4746dbc05"),
        ],
    )
    def test_v1_records_decode(self, raw: bytes, digest: str) -> None:
        rec = decode_hashmark(raw)
        assert rec.ok and rec.version == 1 and rec.digest_hex == digest

    def test_v1_is_not_attested_rather_than_invalid(self) -> None:
        res = verify_attestation(decode_hashmark(_V1_SAME_DIGEST))
        assert res.outcome is AttestationOutcome.NOT_ATTESTED

    def test_the_v1_and_v2_records_mark_the_SAME_digest(self) -> None:
        """Not an assertion about our code — a note about the corpus, kept as a
        test so it cannot drift from the bytes above."""
        assert decode_hashmark(_V1_SAME_DIGEST).digest_hex == decode_hashmark(_V2_SIGNED).digest_hex
