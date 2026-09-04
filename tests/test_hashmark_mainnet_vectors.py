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


class TestTheCanonicalStatementIsPinnedIndEPENDENTLY:
    """The signed bytes must be pinned by something this module did not produce.

    Every signed fixture elsewhere is built by `canonical_statement()` and then
    verified through it, so a WRONG escaping rule is applied identically at sign and
    at verify time and the round trip closes regardless. Measured: replacing the
    hand-rolled `_json_string` with `json.dumps` — which escapes non-ASCII to
    `\\uXXXX` and therefore changes the bytes a signature covers for any label with
    an accent or an emoji — passed all 84 HashMark tests.

    The real mainnet record next door IS an independent vector, and it is why key
    ORDER is pinned: swapping "v" and "network" fails it. But that record has no
    label, so the label branch — the only place non-ASCII can appear — is covered by
    no independent bytes at all.

    So the expected statement below is TYPED OUT from the spec's §5.6 field list,
    not computed. If `canonical_statement` changes how it escapes, or reorders a
    key, or starts emitting an absent label as "", the two stop matching. That is
    the same second-implementer role the mainnet vector plays, done by hand because
    no second implementation of this branch was available to borrow bytes from.
    """

    GENESIS = "0000000065d8ed5d8be28d6876b3ffb660ac2a6c0ca59e437e1f7a6f4e003fb4"
    SIGNER = "26ba056431ec69cf27eabeaab250d99ddbd895d2"
    DIGEST = "e2c55efb34b6e9d6db008ee72d56bf86456ab3f55ae76488ff677fda88df1f1e"

    def _record(self, label):
        from pyrxd.script.hashmark import HashMarkOutcome, HashMarkRecord

        return HashMarkRecord(
            HashMarkOutcome.OK,
            version=2,
            algorithm="sha256",
            algorithm_id=1,
            digest_hex=self.DIGEST,
            signer_hash160_hex=self.SIGNER,
            signature_hex="1f" + "00" * 64,
            label=label,
        )

    def test_a_non_ascii_label_is_emitted_as_RAW_UTF8(self) -> None:
        """The mutation that survived. `json.dumps` would give
        `"facture-caf\\u00e9-\\u2600"` — a different string, and therefore a
        different signature, for a label a French user would plausibly write."""
        from pyrxd.script.hashmark import canonical_statement

        expected = (
            '{"v":"HashMark/v2"'
            f',"network":"{self.GENESIS}"'
            f',"signerHash160":"{self.SIGNER}"'
            ',"algorithmId":"01"'
            f',"digest":"{self.DIGEST}"'
            ',"label":"facture-café-☀"'
            "}"
        )
        assert canonical_statement(self._record("facture-café-☀"), network_genesis=self.GENESIS) == expected
        assert "\\u" not in expected, "the point of the rule: no \\uXXXX escapes"

    def test_a_quote_and_a_backslash_are_the_ONLY_escapes(self) -> None:
        from pyrxd.script.hashmark import canonical_statement

        statement = canonical_statement(self._record('a"b\\c'), network_genesis=self.GENESIS)
        assert statement.endswith(',"label":"a\\"b\\\\c"}')

    def test_an_absent_label_is_OMITTED_not_empty(self) -> None:
        """A different statement, and therefore a different signature. This one the
        mainnet vector does cover — pinned here too because it is the same rule."""
        from pyrxd.script.hashmark import canonical_statement

        assert "label" not in canonical_statement(self._record(None), network_genesis=self.GENESIS)
        assert canonical_statement(self._record("")).endswith(',"label":""}')

    def test_the_key_ORDER_is_fixed(self) -> None:
        from pyrxd.script.hashmark import canonical_statement

        statement = canonical_statement(self._record("x"), network_genesis=self.GENESIS)
        keys = [p.split(":")[0].strip('"') for p in statement[1:-1].split(",") if p.startswith('"')]
        assert keys == ["v", "network", "signerHash160", "algorithmId", "digest", "label"]


class TestTheUncompressedSignerPathIsExercised:
    """§5.6 allows headers 27..34; every fixture in this repo is COMPRESSED.

    Measured: forcing `compressed=True` in the recovery passed all 52 HashMark
    tests, because the mainnet vector's header is 0x1f (31, compressed) and so is
    every generated one. The spec's 27..30 range was covered nowhere, so a verifier
    that simply ignored the flag looked correct.
    """

    def test_a_signature_from_an_UNCOMPRESSED_key_verifies(self) -> None:
        import os

        from coincurve import PrivateKey

        from pyrxd.hash import hash160
        from pyrxd.script.hashmark import (
            AttestationOutcome,
            HashMarkOutcome,
            HashMarkRecord,
            canonical_statement,
            verify_attestation,
        )

        key = PrivateKey(os.urandom(32))
        uncompressed = key.public_key.format(compressed=False)
        signer = hash160(uncompressed).hex()

        record = HashMarkRecord(
            HashMarkOutcome.OK,
            version=2,
            algorithm="sha256",
            algorithm_id=1,
            digest_hex="ab" * 32,
            signer_hash160_hex=signer,
            signature_hex="00" * 65,
            label="uncompressed",
        )
        # The Bitcoin-signed-message framing the spec names, taken from pyrxd's own
        # helper. Borrowed deliberately: this test pins the COMPRESSED-FLAG path, and
        # the statement bytes are pinned independently by the class above. A test that
        # re-derives everything at once localises nothing when it fails — my first
        # version signed a bare double-SHA of the statement and failed here, which
        # looked exactly like a verifier bug.
        from pyrxd.hash import hash256 as _hash256
        from pyrxd.utils import text_digest

        statement = canonical_statement(record)
        raw = key.sign_recoverable(text_digest(statement), hasher=_hash256)
        # Header 27 + recid, with NO +4: that is what marks the key uncompressed.
        signature = bytes([27 + raw[64]]) + raw[:64]

        signed = HashMarkRecord(
            HashMarkOutcome.OK,
            version=2,
            algorithm="sha256",
            algorithm_id=1,
            digest_hex="ab" * 32,
            signer_hash160_hex=signer,
            signature_hex=signature.hex(),
            label="uncompressed",
        )
        result = verify_attestation(signed)
        assert result.outcome is AttestationOutcome.VALID, result.detail
        assert 27 <= signature[0] <= 30, "the header must be in the uncompressed range"

    def test_the_compressed_and_uncompressed_hashes_actually_DIFFER(self) -> None:
        """Guards the test above. The two encodings hash differently, so recovering
        with the wrong flag cannot match by accident — if they ever coincided, the
        test would pass while proving nothing."""
        import os

        from coincurve import PrivateKey

        from pyrxd.hash import hash160

        key = PrivateKey(os.urandom(32)).public_key
        assert hash160(key.format(compressed=True)) != hash160(key.format(compressed=False))
