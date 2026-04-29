"""
Adversarial / red-team tests for pyrxd.glyph.

Each test class maps to an attack vector. Where the SDK correctly rejects the
attack, the test asserts the expected exception. Where the SDK has a KNOWN
LIMITATION (trusts caller-supplied data), the test DOCUMENTS and PROVES the
limitation so the next maintainer knows what layer (node / consensus / wallet)
is expected to catch it.
"""
from __future__ import annotations

import struct

import cbor2
import pytest

from pyrxd.glyph.builder import CommitParams, GlyphBuilder, RevealParams
from pyrxd.glyph.inspector import GlyphInspector
from pyrxd.glyph.payload import (
    build_reveal_scriptsig_suffix,
    decode_payload,
    encode_payload,
)
from pyrxd.glyph.script import (
    build_commit_locking_script,
    build_ft_locking_script,
    build_nft_locking_script,
    extract_owner_pkh_from_nft_script,
    extract_ref_from_ft_script,
    extract_ref_from_nft_script,
    hash_payload,
    is_ft_script,
    is_nft_script,
)
from pyrxd.glyph.types import (
    GlyphMedia,
    GlyphMetadata,
    GlyphProtocol,
    GlyphRef,
)
from pyrxd.security.errors import ValidationError
from pyrxd.security.types import Hex20, Txid

# ---------------------------------------------------------------------------
# Common fixtures
# ---------------------------------------------------------------------------

HONEST_TXID = "a" * 64
ATTACKER_TXID = "b" * 64
HONEST_PKH = Hex20(bytes(range(20)))                  # owner Alice
ATTACKER_PKH = Hex20(bytes(range(20, 40)))            # attacker Mallory
HONEST_REF = GlyphRef(txid=Txid(HONEST_TXID), vout=0)

NFT_METADATA = GlyphMetadata(
    protocol=[GlyphProtocol.NFT],
    name="Legit NFT",
    token_type="art",
    attrs={"artist": "Alice"},
)

FT_METADATA = GlyphMetadata(
    protocol=[GlyphProtocol.FT],
    name="Legit Token",
    ticker="LGT",
)


# ===========================================================================
# 1. Payload-hash tampering
# ===========================================================================


class TestPayloadHashTampering:
    """
    Invariant: the commit script commits to hash256(cbor_bytes). Any single-
    bit change to the CBOR payload MUST produce a different commit script.
    A second preimage attack would require breaking SHA-256 (~2^128 work).
    """

    def test_flip_one_bit_changes_payload_hash(self):
        cbor_bytes, original_hash = encode_payload(NFT_METADATA)
        # Flip the first byte
        tampered = bytes([cbor_bytes[0] ^ 0x01]) + cbor_bytes[1:]
        tampered_hash = hash_payload(tampered)
        assert original_hash != tampered_hash

    def test_flip_one_bit_changes_commit_script(self):
        cbor_bytes, original_hash = encode_payload(NFT_METADATA)
        original_script = build_commit_locking_script(original_hash, HONEST_PKH)

        # Flip a middle byte
        idx = len(cbor_bytes) // 2
        tampered = (
            cbor_bytes[:idx]
            + bytes([cbor_bytes[idx] ^ 0xFF])
            + cbor_bytes[idx + 1:]
        )
        tampered_hash = hash_payload(tampered)
        tampered_script = build_commit_locking_script(tampered_hash, HONEST_PKH)
        assert original_script != tampered_script

    def test_all_bit_flips_produce_distinct_hashes(self):
        """Sample a handful of single-bit flips to confirm avalanche."""
        cbor_bytes, original_hash = encode_payload(NFT_METADATA)
        seen = {original_hash}
        # Flip bit 0 of bytes 0, 5, 10, ... (sampled)
        for i in range(0, len(cbor_bytes), max(1, len(cbor_bytes) // 10)):
            tampered = (
                cbor_bytes[:i]
                + bytes([cbor_bytes[i] ^ 0x01])
                + cbor_bytes[i + 1:]
            )
            h = hash_payload(tampered)
            assert h not in seen, f"Hash collision at byte {i}"
            seen.add(h)

    def test_hash_is_sha256d(self):
        """Verify the scheme is SHA256 applied twice (standard Bitcoin hash256)."""
        import hashlib
        data = b"hello glyph"
        expected = hashlib.sha256(hashlib.sha256(data).digest()).digest()
        assert hash_payload(data) == expected

    def test_empty_bytes_still_hashes(self):
        """hash_payload on empty bytes does NOT error — attacker cannot cause
        hash_payload to raise, they can only cause a wrong hash."""
        h = hash_payload(b"")
        assert len(h) == 32

    def test_known_limitation_second_preimage_is_out_of_scope(self):
        """
        KNOWN LIMITATION: the SDK does not (and cannot) defend against an
        attacker who finds a different CBOR that hashes to the same value.
        Defense relies entirely on SHA-256 collision resistance (~2^128 work
        for a second preimage). This test documents the invariant only.
        """
        cbor_bytes, payload_hash = encode_payload(NFT_METADATA)
        assert len(payload_hash) == 32  # 256-bit security is all we rely on


# ===========================================================================
# 2. Ref spoofing in NFT / FT locking scripts
# ===========================================================================


class TestRefSpoofing:
    """
    KNOWN LIMITATION: build_nft_locking_script / build_ft_locking_script
    happily encode any caller-supplied GlyphRef. The SDK does not (and cannot)
    cross-check the ref against the on-chain commit outpoint. The NODE is
    responsible for enforcing the commit/reveal binding via the Glyph
    covenant opcodes (OP_OUTPOINTTXHASH, OP_OUTPOINTINDEX, OP_REFTYPE_OUTPUT).
    """

    def test_fabricated_ref_produces_different_script(self):
        honest_script = build_nft_locking_script(HONEST_PKH, HONEST_REF)
        evil_ref = GlyphRef(txid=Txid(ATTACKER_TXID), vout=0)
        evil_script = build_nft_locking_script(HONEST_PKH, evil_ref)
        assert honest_script != evil_script

    def test_extractor_returns_fabricated_ref_verbatim(self):
        """
        KNOWN LIMITATION: extract_ref_from_nft_script faithfully returns
        whatever was encoded — it does NOT verify the ref points at a real
        commit output. Mitigation layer: the consensus-enforced covenant.
        """
        evil_ref = GlyphRef(txid=Txid(ATTACKER_TXID), vout=7)
        script = build_nft_locking_script(HONEST_PKH, evil_ref)
        extracted = extract_ref_from_nft_script(script)
        assert extracted.txid == ATTACKER_TXID
        assert extracted.vout == 7

    def test_all_zero_ref_encodes_and_extracts(self):
        """A ref with all-zero txid is structurally valid — only semantically
        nonsense. Detection is left to the caller / node."""
        zero_ref = GlyphRef(txid=Txid("0" * 64), vout=0)
        script = build_nft_locking_script(HONEST_PKH, zero_ref)
        assert len(script) == 63
        # Wire bytes in the script for the ref: 32 zero bytes + 4 zero bytes
        assert script[1:37] == bytes(36)
        # Round-trips
        assert extract_ref_from_nft_script(script) == zero_ref

    def test_off_by_one_vout_yields_distinct_script(self):
        """Wrong vout (e.g. 0 vs 1) produces a detectably different script."""
        ref0 = GlyphRef(txid=Txid(HONEST_TXID), vout=0)
        ref1 = GlyphRef(txid=Txid(HONEST_TXID), vout=1)
        s0 = build_nft_locking_script(HONEST_PKH, ref0)
        s1 = build_nft_locking_script(HONEST_PKH, ref1)
        assert s0 != s1
        # vout is encoded at offset 33..37 (4 bytes LE after 32-byte reversed txid)
        assert s0[33:37] == struct.pack('<I', 0)
        assert s1[33:37] == struct.pack('<I', 1)

    def test_ft_ref_spoofing_also_succeeds(self):
        """Same KNOWN LIMITATION applies to FT scripts."""
        evil_ref = GlyphRef(txid=Txid(ATTACKER_TXID), vout=42)
        script = build_ft_locking_script(HONEST_PKH, evil_ref)
        extracted = extract_ref_from_ft_script(script)
        assert extracted.txid == ATTACKER_TXID
        assert extracted.vout == 42


# ===========================================================================
# 3. CBOR payload injection / confusion
# ===========================================================================


class TestCborInjection:
    """CBOR decoding must reject malformed / unexpected inputs."""

    def test_cbor_oversize_raises(self):
        """>65535 bytes is rejected by build_reveal_scriptsig_suffix."""
        oversize = bytes(65536)
        with pytest.raises(ValidationError, match="too large"):
            build_reveal_scriptsig_suffix(oversize)

    def test_cbor_just_past_limit_raises(self):
        """Exactly 65536 bytes is one past the OP_PUSHDATA2 limit."""
        with pytest.raises(ValidationError):
            build_reveal_scriptsig_suffix(bytes(65536))

    def test_cbor_at_pushdata2_max_is_accepted(self):
        """65535 bytes is the largest accepted size."""
        suffix = build_reveal_scriptsig_suffix(bytes(65535))
        # gly push(4) + 0x4d + 2 length bytes + 65535 payload
        assert len(suffix) == 4 + 1 + 2 + 65535

    def test_cbor_with_unknown_keys_is_silently_ignored(self):
        """
        KNOWN LIMITATION: decode_payload reads only the keys it understands
        ('p', 'name', 'ticker', ...). Unknown keys are silently dropped.
        An attacker cannot inject unknown keys to change the SDK's behaviour
        — but they also can't make the SDK raise by adding extra keys.
        """
        payload = {
            "p": [GlyphProtocol.NFT],
            "name": "legit",
            "evil_extra_key": "malicious_payload",
            "another": [1, 2, 3],
        }
        cbor_bytes = cbor2.dumps(payload)
        meta = decode_payload(cbor_bytes)
        assert list(meta.protocol) == [GlyphProtocol.NFT]
        assert meta.name == "legit"
        # Unknown fields dropped — not surfaced anywhere on GlyphMetadata
        assert not hasattr(meta, "evil_extra_key")

    def test_malformed_cbor_raises(self):
        """Non-CBOR garbage is rejected — either as 'Invalid CBOR' (parse
        error) or 'must be a map' (parsed to non-dict). Both are acceptable
        rejections from the SDK's perspective — the attack is blocked."""
        # 0x1e is an unassigned CBOR major-type-0 additional info — hard parse error
        with pytest.raises(ValidationError, match="Invalid CBOR"):
            decode_payload(b"\x1e")

    def test_empty_cbor_raises(self):
        """Empty bytes is not valid CBOR — must raise."""
        with pytest.raises(ValidationError):
            decode_payload(b"")

    def test_cbor_encoding_a_list_raises(self):
        """CBOR payload MUST decode to a map — a list is rejected."""
        list_cbor = cbor2.dumps([1, 2, 3])
        with pytest.raises(ValidationError, match="must be a map"):
            decode_payload(list_cbor)

    def test_cbor_encoding_a_string_raises(self):
        """CBOR payload MUST decode to a map — a string is rejected."""
        str_cbor = cbor2.dumps("i am a string, not a map")
        with pytest.raises(ValidationError, match="must be a map"):
            decode_payload(str_cbor)

    def test_cbor_encoding_an_integer_raises(self):
        int_cbor = cbor2.dumps(42)
        with pytest.raises(ValidationError, match="must be a map"):
            decode_payload(int_cbor)

    def test_cbor_missing_p_field_raises(self):
        no_p = cbor2.dumps({"name": "no protocol"})
        with pytest.raises(ValidationError, match="missing 'p' field"):
            decode_payload(no_p)

    def test_cbor_p_field_not_a_list_raises(self):
        """'p' must be a list of protocol IDs — a scalar is rejected."""
        scalar_p = cbor2.dumps({"p": 2})
        with pytest.raises(ValidationError, match="missing 'p' field"):
            decode_payload(scalar_p)

    def test_cbor_protocol_mismatch_with_script_type_raises(self):
        """
        prepare_reveal now cross-checks that the CBOR protocol field is
        consistent with is_nft. NFT CBOR + is_nft=False raises ValidationError.
        """
        from pyrxd.security.errors import ValidationError
        builder = GlyphBuilder()
        commit_result = builder.prepare_commit(CommitParams(
            metadata=NFT_METADATA,  # claims NFT (p=[2])
            owner_pkh=HONEST_PKH,
            change_pkh=HONEST_PKH,
            funding_satoshis=1_000_000,
        ))
        with pytest.raises(ValidationError, match="protocol field"):
            builder.prepare_reveal(RevealParams(
                commit_txid=HONEST_TXID,
                commit_vout=0,
                commit_value=546,
                cbor_bytes=commit_result.cbor_bytes,  # says NFT
                owner_pkh=HONEST_PKH,
                is_nft=False,  # mismatch — should raise
            ))

    def test_ft_cbor_with_is_nft_true_raises(self):
        """FT CBOR + is_nft=True also raises ValidationError."""
        from pyrxd.security.errors import ValidationError
        from pyrxd.glyph.types import GlyphMetadata
        ft_metadata = GlyphMetadata(protocol=[GlyphProtocol.FT], name="TestFT", ticker="TFT")
        builder = GlyphBuilder()
        commit_result = builder.prepare_commit(CommitParams(
            metadata=ft_metadata,
            owner_pkh=HONEST_PKH,
            change_pkh=HONEST_PKH,
            funding_satoshis=1_000_000,
        ))
        with pytest.raises(ValidationError, match="protocol field"):
            builder.prepare_reveal(RevealParams(
                commit_txid=HONEST_TXID,
                commit_vout=0,
                commit_value=546,
                cbor_bytes=commit_result.cbor_bytes,
                owner_pkh=HONEST_PKH,
                is_nft=True,  # mismatch
            ))


# ===========================================================================
# 3b. Security audit 2026-04-25 — decode_payload and script classifier regressions
# ===========================================================================


class TestDecodePayloadSecurityAudit2026:
    """Regression tests for MEDIUM-5: decode_payload field-type and length limits."""

    def test_non_string_name_field_raises(self):
        """MEDIUM-5: CBOR 'name' as integer must raise, not silently become str(42)='42'."""
        cbor_bytes = cbor2.dumps({"p": [2], "name": 42})
        with pytest.raises(ValidationError, match="must be a text string"):
            decode_payload(cbor_bytes)

    def test_non_string_ticker_field_raises(self):
        """MEDIUM-5: CBOR 'ticker' as list must raise."""
        cbor_bytes = cbor2.dumps({"p": [1], "ticker": [1, 2, 3]})
        with pytest.raises(ValidationError, match="must be a text string"):
            decode_payload(cbor_bytes)

    def test_non_string_description_raises(self):
        """MEDIUM-5: CBOR 'desc' as dict must raise."""
        cbor_bytes = cbor2.dumps({"p": [2], "desc": {"nested": "dict"}})
        with pytest.raises(ValidationError, match="must be a text string"):
            decode_payload(cbor_bytes)

    def test_name_too_long_raises(self):
        """MEDIUM-5: name > 64 chars must raise — prevents memory exhaustion from on-chain payloads."""
        cbor_bytes = cbor2.dumps({"p": [2], "name": "x" * 65})
        with pytest.raises(ValidationError, match="too long"):
            decode_payload(cbor_bytes)

    def test_description_too_long_raises(self):
        """MEDIUM-5: desc > 1000 chars must raise."""
        cbor_bytes = cbor2.dumps({"p": [2], "desc": "x" * 1001})
        with pytest.raises(ValidationError, match="too long"):
            decode_payload(cbor_bytes)

    def test_ticker_too_long_raises(self):
        """MEDIUM-5: ticker > 16 chars must raise."""
        cbor_bytes = cbor2.dumps({"p": [1], "ticker": "x" * 17})
        with pytest.raises(ValidationError, match="too long"):
            decode_payload(cbor_bytes)

    def test_image_url_too_long_raises(self):
        """MEDIUM-5: image URL > 512 chars must raise."""
        cbor_bytes = cbor2.dumps({"p": [2], "image": "https://example.com/" + "x" * 500})
        with pytest.raises(ValidationError, match="too long"):
            decode_payload(cbor_bytes)

    def test_valid_fields_at_limits_accepted(self):
        """Boundary: fields exactly at their limits must be accepted."""
        cbor_bytes = cbor2.dumps({
            "p": [2],
            "name": "x" * 64,
            "ticker": "x" * 16,
            "desc": "x" * 1000,
        })
        meta = decode_payload(cbor_bytes)
        assert meta.name == "x" * 64
        assert meta.ticker == "x" * 16
        assert meta.description == "x" * 1000

    def test_absent_optional_fields_return_empty_string(self):
        """Absent optional string fields should produce empty string, not raise."""
        cbor_bytes = cbor2.dumps({"p": [2]})
        meta = decode_payload(cbor_bytes)
        assert meta.name == ""
        assert meta.ticker == ""
        assert meta.description == ""


_CLASSIFIER_REF = GlyphRef(txid="cd" * 32, vout=0)
_CLASSIFIER_PKH = Hex20(bytes(range(20)))


class TestScriptClassifierSecurityAudit2026:
    """Regression tests for MEDIUM: script classifiers must use fullmatch not match."""

    def test_is_ft_script_rejects_newline_trailing(self):
        """MEDIUM: is_ft_script with .match() + $ allowed newline-trailing hex bypass."""
        valid_hex = build_ft_locking_script(_CLASSIFIER_PKH, _CLASSIFIER_REF).hex()
        assert is_ft_script(valid_hex)
        assert not is_ft_script(valid_hex + "\n")
        assert not is_ft_script(valid_hex + "00")

    def test_is_nft_script_rejects_newline_trailing(self):
        """MEDIUM: is_nft_script with .match() also had the same bypass."""
        valid_hex = build_nft_locking_script(_CLASSIFIER_PKH, _CLASSIFIER_REF).hex()
        assert is_nft_script(valid_hex)
        assert not is_nft_script(valid_hex + "\n")
        assert not is_nft_script(valid_hex + "00")

    def test_is_ft_script_rejects_prefix_only(self):
        """is_ft_script must reject a string that is a valid prefix but truncated."""
        valid_hex = build_ft_locking_script(_CLASSIFIER_PKH, _CLASSIFIER_REF).hex()
        assert not is_ft_script(valid_hex[:30])  # truncated

    def test_commit_script_re_both_variants_match(self):
        """COMMIT_SCRIPT_RE must match both NFT (OP_2) and FT (OP_1) commit scripts."""
        from pyrxd.glyph.script import COMMIT_SCRIPT_RE, COMMIT_SCRIPT_NFT_RE, COMMIT_SCRIPT_FT_RE
        from pyrxd.glyph.script import build_commit_locking_script
        pkh = Hex20(bytes(range(20)))
        nft_script = build_commit_locking_script(b"\xab" * 32, pkh, is_nft=True)
        ft_script  = build_commit_locking_script(b"\xab" * 32, pkh, is_nft=False)
        assert COMMIT_SCRIPT_RE.fullmatch(nft_script.hex())
        assert COMMIT_SCRIPT_RE.fullmatch(ft_script.hex())
        assert COMMIT_SCRIPT_NFT_RE.fullmatch(nft_script.hex())
        assert COMMIT_SCRIPT_FT_RE.fullmatch(ft_script.hex())
        assert not COMMIT_SCRIPT_NFT_RE.fullmatch(ft_script.hex())
        assert not COMMIT_SCRIPT_FT_RE.fullmatch(nft_script.hex())


# ===========================================================================
# 4. Owner-PKH substitution across commit / reveal
# ===========================================================================


class TestMintToRecipient:
    """
    Mint-to-recipient (commit spender PKH ≠ reveal recipient PKH) is a
    first-class supported flow. The commit script's embedded PKH is the
    *spender* of the commit UTXO (signs the reveal); ``owner_pkh`` on
    RevealParams is the *recipient* of the minted token. pyrxd performs
    no authorization check on recipient selection — the caller owns that
    trust boundary.

    This class pins that behaviour so the old spender==recipient cross-check
    is not reintroduced by reflex. See CHANGELOG 0.2.0.
    """

    def test_distinct_spender_and_recipient_pkh_accepted(self):
        """prepare_reveal must accept commit-spender PKH ≠ reveal-recipient PKH."""
        builder = GlyphBuilder()
        commit = builder.prepare_commit(CommitParams(
            metadata=NFT_METADATA,
            owner_pkh=HONEST_PKH,       # wallet signs reveal
            change_pkh=HONEST_PKH,
            funding_satoshis=1_000_000,
        ))
        reveal = builder.prepare_reveal(RevealParams(
            commit_txid=HONEST_TXID,
            commit_vout=0,
            commit_value=546,
            cbor_bytes=commit.cbor_bytes,
            owner_pkh=ATTACKER_PKH,     # recipient ≠ spender — legitimate
            is_nft=True,
        ))
        extracted = extract_owner_pkh_from_nft_script(reveal.locking_script)
        assert bytes(extracted) == bytes(ATTACKER_PKH)

    def test_commit_script_pkh_independent_of_nft_script_pkh(self):
        """The commit's P2PKH tail and the NFT locking script's P2PKH can differ."""
        commit_script = build_commit_locking_script(bytes(32), HONEST_PKH)
        assert bytes(HONEST_PKH) in commit_script

        nft_script = build_nft_locking_script(ATTACKER_PKH, HONEST_REF)
        extracted = extract_owner_pkh_from_nft_script(nft_script)
        assert bytes(extracted) == bytes(ATTACKER_PKH)


# ===========================================================================
# 5. Script-classifier confusion
# ===========================================================================


class TestClassifierConfusion:
    """is_nft_script / is_ft_script must not be fooled by crafted inputs."""

    def test_garbage_ref_still_classifies_as_nft(self):
        """
        KNOWN LIMITATION: the classifier is a pure structural regex. A script
        with a garbage ref (all 0xAA) still passes is_nft_script. Semantic
        validation (does the ref point at a real commit?) is the INDEXER's
        job, not the classifier's.
        """
        garbage_ref_bytes = b"\xaa" * 36
        # Hand-build an NFT-shaped script with a garbage ref
        fake_script = (
            b"\xd8"
            + garbage_ref_bytes
            + b"\x75\x76\xa9\x14"
            + bytes(20)
            + b"\x88\xac"
        )
        assert len(fake_script) == 63
        assert is_nft_script(fake_script.hex())
        # And the extractor faithfully returns the garbage ref
        extracted = extract_ref_from_nft_script(fake_script)
        # 32 bytes of 0xaa reversed is still 32 bytes of 0xaa
        assert extracted.txid == "aa" * 32

    def test_script_too_short_does_not_match_nft_regex(self):
        """The regex is anchored (^ ... $) and requires exact hex length."""
        too_short = b"\xd8" + b"\xaa" * 35 + b"\x75\x76\xa9\x14" + bytes(20) + b"\x88\xac"
        # 1 + 35 + 4 + 20 + 2 = 62 bytes, not 63
        assert len(too_short) == 62
        assert not is_nft_script(too_short.hex())

    def test_script_too_long_does_not_match_nft_regex(self):
        """Extra trailing byte breaks the anchored regex."""
        too_long = (
            b"\xd8"
            + b"\xaa" * 36
            + b"\x75\x76\xa9\x14"
            + bytes(20)
            + b"\x88\xac\x00"  # trailing byte
        )
        assert len(too_long) == 64
        assert not is_nft_script(too_long.hex())

    def test_commit_script_does_not_pass_either_classifier(self):
        """A commit (HASH256 ...) script must never be mistaken for NFT or FT."""
        commit_script = build_commit_locking_script(bytes(32), HONEST_PKH)
        assert not is_nft_script(commit_script.hex())
        assert not is_ft_script(commit_script.hex())

    def test_all_zero_script_does_not_pass_classifier(self):
        """A zero-filled 63-byte buffer lacks the 0xd8 header."""
        zeros = bytes(63)
        assert not is_nft_script(zeros.hex())

    def test_p2pkh_does_not_classify_as_ft(self):
        """Plain P2PKH must not be mistaken for an FT script."""
        p2pkh = b"\x76\xa9\x14" + bytes(20) + b"\x88\xac"
        assert not is_ft_script(p2pkh.hex())
        assert not is_nft_script(p2pkh.hex())

    def test_uppercase_hex_still_classifies(self):
        """Classifier lowercases input, so uppercase hex is still accepted."""
        nft = build_nft_locking_script(HONEST_PKH, HONEST_REF)
        assert is_nft_script(nft.hex().upper())


# ===========================================================================
# 6. GlyphRef encoding edge cases
# ===========================================================================


class TestGlyphRefEdgeCases:
    """Wire-format edge cases."""

    def test_all_zero_txid_encodes_and_decodes(self):
        ref = GlyphRef(txid=Txid("0" * 64), vout=0)
        wire = ref.to_bytes()
        assert wire == bytes(36)
        assert GlyphRef.from_bytes(wire) == ref

    def test_max_vout_roundtrip(self):
        ref = GlyphRef(txid=Txid(HONEST_TXID), vout=0xFFFFFFFF)
        recovered = GlyphRef.from_bytes(ref.to_bytes())
        assert recovered.vout == 0xFFFFFFFF
        assert recovered.txid == ref.txid

    def test_max_vout_wire_bytes(self):
        ref = GlyphRef(txid=Txid(HONEST_TXID), vout=0xFFFFFFFF)
        wire = ref.to_bytes()
        assert wire[32:] == b"\xff\xff\xff\xff"

    def test_vout_overflow_by_one_rejected(self):
        with pytest.raises(ValidationError):
            GlyphRef(txid=Txid(HONEST_TXID), vout=0x1_0000_0000)

    def test_roundtrip_with_all_0xff_txid(self):
        """All 0xff txid is structurally valid (f*64 is valid hex)."""
        ref = GlyphRef(txid=Txid("f" * 64), vout=123)
        recovered = GlyphRef.from_bytes(ref.to_bytes())
        assert recovered == ref

    def test_roundtrip_with_mixed_txid(self):
        txid = "01234567" * 8  # 64 hex chars
        ref = GlyphRef(txid=Txid(txid), vout=0xDEADBEEF)
        recovered = GlyphRef.from_bytes(ref.to_bytes())
        assert recovered == ref

    def test_zero_length_bytes_rejected(self):
        with pytest.raises(ValidationError, match="36 bytes"):
            GlyphRef.from_bytes(b"")

    def test_35_bytes_rejected(self):
        with pytest.raises(ValidationError, match="36 bytes"):
            GlyphRef.from_bytes(b"\x00" * 35)

    def test_37_bytes_rejected(self):
        with pytest.raises(ValidationError, match="36 bytes"):
            GlyphRef.from_bytes(b"\x00" * 37)

    def test_uppercase_txid_rejected_by_txid_type(self):
        """Txid is strictly lowercase hex."""
        with pytest.raises(ValidationError):
            GlyphRef(txid=Txid("A" * 64), vout=0)

    def test_non_hex_txid_rejected(self):
        with pytest.raises(ValidationError):
            GlyphRef(txid=Txid("z" * 64), vout=0)


# ===========================================================================
# 7. ScriptSig suffix push-data encoding
# ===========================================================================


class TestScriptSigSuffixEncoding:
    """
    The suffix is <0x03 'gly'> <pushdata> <cbor>.
    Verify the length-prefix encoding is correct at every boundary.
    """

    def _suffix_body(self, cbor_bytes: bytes) -> bytes:
        """Return just the push-data portion (everything after the 'gly' push)."""
        suffix = build_reveal_scriptsig_suffix(cbor_bytes)
        assert suffix[:4] == b"\x03gly"
        return suffix[4:]

    def test_75_bytes_uses_direct_push(self):
        """Exactly 75 bytes: encoded as single length byte 0x4b + data."""
        cbor = bytes(75)
        body = self._suffix_body(cbor)
        assert body[0] == 75
        assert body[1:] == cbor
        # Total suffix: 4 (gly push) + 1 (len) + 75 (data) = 80
        assert len(build_reveal_scriptsig_suffix(cbor)) == 80

    def test_76_bytes_switches_to_pushdata1(self):
        """Exactly 76 bytes: encoded as 0x4c 0x4c + data (OP_PUSHDATA1)."""
        cbor = bytes(76)
        body = self._suffix_body(cbor)
        assert body[0] == 0x4c         # OP_PUSHDATA1
        assert body[1] == 76           # length
        assert body[2:] == cbor
        # Total suffix: 4 + 2 + 76 = 82
        assert len(build_reveal_scriptsig_suffix(cbor)) == 82

    def test_1_byte_direct_push(self):
        cbor = b"\x2a"
        body = self._suffix_body(cbor)
        assert body == b"\x01\x2a"

    def test_empty_cbor_pushes_zero(self):
        """Edge case: 0-byte CBOR encodes as OP_0 (0x00) + empty data."""
        body = self._suffix_body(b"")
        assert body == b"\x00"

    def test_255_bytes_uses_pushdata1(self):
        cbor = bytes(255)
        body = self._suffix_body(cbor)
        assert body[0] == 0x4c
        assert body[1] == 255
        assert body[2:] == cbor
        assert len(build_reveal_scriptsig_suffix(cbor)) == 4 + 2 + 255

    def test_256_bytes_switches_to_pushdata2(self):
        """256 bytes: encoded as 0x4d <len_le_2bytes> + data (OP_PUSHDATA2)."""
        cbor = bytes(256)
        body = self._suffix_body(cbor)
        assert body[0] == 0x4d
        assert body[1:3] == (256).to_bytes(2, "little")
        assert body[3:] == cbor
        assert len(build_reveal_scriptsig_suffix(cbor)) == 4 + 3 + 256

    def test_65535_bytes_uses_pushdata2_max(self):
        cbor = bytes(65535)
        body = self._suffix_body(cbor)
        assert body[0] == 0x4d
        assert body[1:3] == (65535).to_bytes(2, "little")
        assert body[3:] == cbor

    def test_65536_bytes_rejected(self):
        with pytest.raises(ValidationError, match="too large"):
            build_reveal_scriptsig_suffix(bytes(65536))

    def test_inspector_parses_every_boundary(self):
        """
        The on-chain inspector must decode every suffix size the encoder
        emits — otherwise valid reveals would be silently dropped by indexers.
        Probes the 75/76/255/256 boundaries round-trip through the real
        inspector._parse_reveal_scriptsig code path.
        """
        inspector = GlyphInspector()
        for size_hint in (1, 74, 75, 76, 200, 255, 256, 300):
            # Pad description (limit 1000) so CBOR comes out at approximately size_hint.
            # name is capped at 64 chars; description allows up to 1000.
            meta = GlyphMetadata(protocol=[2], description="x" * max(0, size_hint - 10))
            cbor_bytes = cbor2.dumps(meta.to_cbor_dict())
            suffix = build_reveal_scriptsig_suffix(cbor_bytes)
            # Prepend dummy sig + pubkey to look like a real reveal scriptSig
            dummy_sig = bytes([0x47]) + bytes(71)
            dummy_pk = bytes([0x21]) + bytes(33)
            scriptsig = dummy_sig + dummy_pk + suffix
            decoded = inspector.extract_reveal_metadata(scriptsig)
            assert decoded is not None, f"Inspector failed at size {len(cbor_bytes)}"
            assert list(decoded.protocol) == [2]


# ===========================================================================
# 8. Miscellaneous hardening checks
# ===========================================================================


class TestMiscHardening:
    """Catch-all for invariants that don't fit cleanly into one category."""

    def test_commit_script_wrong_hash_length_rejected(self):
        with pytest.raises(ValidationError, match="32 bytes"):
            build_commit_locking_script(bytes(31), HONEST_PKH)

    def test_commit_script_33_byte_hash_rejected(self):
        with pytest.raises(ValidationError, match="32 bytes"):
            build_commit_locking_script(bytes(33), HONEST_PKH)

    def test_commit_script_empty_hash_rejected(self):
        with pytest.raises(ValidationError):
            build_commit_locking_script(b"", HONEST_PKH)

    def test_hex20_wrong_length_rejected(self):
        """Hex20 enforces exactly 20 bytes at the trust boundary."""
        with pytest.raises(ValidationError, match="20 bytes"):
            Hex20(bytes(19))
        with pytest.raises(ValidationError, match="20 bytes"):
            Hex20(bytes(21))

    def test_glyph_media_over_limit_rejected(self):
        with pytest.raises(ValidationError, match="too large"):
            GlyphMedia(mime_type="image/png", data=bytes(100_001))

    def test_glyph_media_blank_mime_rejected(self):
        with pytest.raises(ValidationError, match="Invalid MIME type"):
            GlyphMedia(mime_type="", data=b"data")

    def test_extract_ref_on_commit_script_rejected(self):
        """Pass a commit script to the NFT ref extractor — must reject."""
        commit_script = build_commit_locking_script(bytes(32), HONEST_PKH)
        with pytest.raises(ValidationError):
            extract_ref_from_nft_script(commit_script)

    def test_extract_ref_empty_bytes_rejected(self):
        with pytest.raises(ValidationError):
            extract_ref_from_nft_script(b"")

    def test_extract_ref_first_byte_wrong_rejected(self):
        """Even a 63-byte buffer is rejected if the header byte is not 0xd8."""
        fake = b"\x00" + bytes(62)
        assert len(fake) == 63
        with pytest.raises(ValidationError):
            extract_ref_from_nft_script(fake)

    def test_inspector_ignores_truncated_scriptsig(self):
        """A scriptSig that runs out of bytes mid-push must not crash or
        succeed — it must return None (not a glyph)."""
        inspector = GlyphInspector()
        # 0x05 promises 5 bytes but only 2 follow — parser walks off the end
        truncated = b"\x05\xaa\xbb"
        # Must NOT raise — must return None or a safe value
        result = inspector.extract_reveal_metadata(truncated)
        assert result is None

    def test_inspector_ignores_scriptsig_with_no_gly_marker(self):
        """A scriptSig with pushes but no 'gly' marker is not a reveal."""
        inspector = GlyphInspector()
        dummy_sig = bytes([0x47]) + bytes(71)
        dummy_pk = bytes([0x21]) + bytes(33)
        result = inspector.extract_reveal_metadata(dummy_sig + dummy_pk)
        assert result is None
