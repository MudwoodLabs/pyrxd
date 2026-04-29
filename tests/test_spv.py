"""Tests for pyrxd.spv — Bitcoin SPV primitives.

This is the highest-risk test file in the repo: a missing check here means an
attacker can submit a forged SPV proof and drain a Maker's RXD. Tests are
organized so that every audit finding from the JS prototype (audits 02 and 05)
has an explicit test demonstrating the defense.
"""

from __future__ import annotations

import pytest

from pyrxd.security.errors import SpvVerificationError, ValidationError
from pyrxd.spv import (
    CovenantParams,
    P2PKH,
    P2SH,
    P2TR,
    P2WPKH,
    SpvProofBuilder,
    build_branch,
    compute_root,
    extract_merkle_root,
    hash256,
    strip_witness,
    verify_chain,
    verify_header_pow,
    verify_payment,
    verify_tx_in_block,
)

# --------------------------------------------------------------------------- fixtures

# Real mainnet block 840000 header (80 bytes, hex).
# Block 840000 was the first block after the 4th halving (2024-04-20).
# Known BE hash: 0000000000000000000320283a2e9c41851d59dbdd7fb4e5ae3a9c1d6a25e9d0.
BLOCK_840000 = (
    "00e05f2aab948491071265ad552351d0ad625745668da54b01720100000000000000"
    "00004f89a5d73bd4d4887f25981fe81892ccafda10c27f52d6f3dd28183a7c411b03"
    "b7072366194203177d9863ea"
)
# Consecutive block 840001.
BLOCK_840001 = (
    "04002020a583da1c3ff29b687248ff737822f8ce4827033a28200300000000000000"
    "0000bcc07f8618b7b063f833100724e2b40d6ee9dfa78087bfbe5d3441058a63de38"
    "0e082366194203176d9026cc"
)


def _p2pkh_output(value: int, hash20: bytes) -> bytes:
    """Build a minimal P2PKH output: value(8) + len(1) + script(25)."""
    return (
        value.to_bytes(8, "little")
        + bytes([25])
        + b"\x76\xa9\x14"
        + hash20
        + b"\x88\xac"
    )


# --------------------------------------------------------------------------- audit findings


class TestAuditFindings:
    """Each test corresponds to a specific audit finding from the JS prototype.

    A naive port would miss every one of these defenses. They are what this
    phase exists to defend.
    """

    # ----- Audit 02-F-1 — 64-byte tx Merkle forgery ------------------------

    def test_02_f1_64byte_merkle_forgery_rejected(self) -> None:
        """Audit 02-F-1: a 64-byte 'tx' can collide with a Merkle interior node."""
        fake_tx = b"\xab" * 64
        with pytest.raises(SpvVerificationError, match="64-byte"):
            verify_tx_in_block(
                fake_tx, "a" * 64, b"\x00" * 33, pos=1, header=b"\x00" * 80
            )

    def test_02_f1_65byte_tx_not_rejected_by_length(self) -> None:
        """65 bytes is above the threshold — length defense does NOT fire."""
        tx_65 = b"\xab" * 65
        try:
            verify_tx_in_block(
                tx_65, "a" * 64, b"\x00" * 33, pos=1, header=b"\x00" * 80
            )
        except SpvVerificationError as e:
            assert "64-byte" not in str(
                e
            ), "65-byte tx should not trigger 64-byte forgery defense"
        except (ValidationError, Exception):
            # Other errors (hash mismatch, root mismatch, etc.) are expected.
            pass

    # ----- Audit 02-F-3 — malformed nBits rejection ------------------------

    def test_02_f3_nbits_exponent_over_1d_rejected(self) -> None:
        """Audit 02-F-3: nBits with exponent > 0x1d must be rejected."""
        header = bytearray(b"\x00" * 80)
        header[72] = 0x01  # mantissa byte 0 nonzero
        header[73] = 0x00
        header[74] = 0x00
        header[75] = 0x1E  # exponent 0x1e > 0x1d
        with pytest.raises((ValidationError, SpvVerificationError)):
            verify_header_pow(bytes(header))

    def test_02_f3_nbits_negative_mantissa_rejected(self) -> None:
        """Audit 02-F-3: mantissa sign-bit set (negative target) must be rejected."""
        header = bytearray(b"\x00" * 80)
        header[72] = 0x00
        header[73] = 0x00
        header[74] = 0x80  # mantissa high bit set
        header[75] = 0x17
        with pytest.raises((ValidationError, SpvVerificationError)):
            verify_header_pow(bytes(header))

    def test_02_f3_nbits_zero_mantissa_rejected(self) -> None:
        """Audit 02-F-3: zero mantissa (trivially satisfied target) must be rejected."""
        header = bytearray(b"\x00" * 80)
        header[72] = 0x00
        header[73] = 0x00
        header[74] = 0x00
        header[75] = 0x17
        with pytest.raises((ValidationError, SpvVerificationError)):
            verify_header_pow(bytes(header))

    # ----- Audit 05-F-3 — chain anchor enforcement -------------------------

    def test_05_f3_chain_anchor_enforced(self) -> None:
        """Audit 05-F-3: chain_anchor mismatch must reject (testnet/alt-chain defense)."""
        header = bytes.fromhex(BLOCK_840000)
        wrong_anchor = b"\xff" * 32
        with pytest.raises(SpvVerificationError, match="chain_anchor"):
            verify_chain([header], chain_anchor=wrong_anchor)

    def test_05_f3_chain_anchor_correct_accepts(self) -> None:
        """Audit 05-F-3: the real anchor value must pass."""
        header = bytes.fromhex(BLOCK_840000)
        real_anchor = header[4:36]
        hashes = verify_chain([header], chain_anchor=real_anchor)
        assert len(hashes) == 1

    # ----- Audit 05-F-8 — Merkle depth binding -----------------------------

    def test_05_f8_merkle_depth_binding(self) -> None:
        """Audit 05-F-8: branch depth must match expected_depth."""
        raw_tx = b"\x00" * 65
        branch_depth_2 = (
            b"\x00" + b"\xab" * 32 + b"\x00" + b"\xcd" * 32
        )  # 2 levels
        header = b"\x00" * 80
        with pytest.raises(SpvVerificationError, match="depth"):
            verify_tx_in_block(
                raw_tx,
                "a" * 64,
                branch_depth_2,
                pos=1,
                header=header,
                expected_depth=3,
            )

    # ----- Audit 05-F-9 — coinbase as payment guard ------------------------

    def test_05_f9_coinbase_rejected(self) -> None:
        """Audit 05-F-9: pos=0 is the coinbase and cannot be used as payment."""
        raw_tx = b"\x00" * 65
        branch = b"\x00" + b"\xab" * 32  # 1 level
        header = b"\x00" * 80
        with pytest.raises(SpvVerificationError, match="coinbase"):
            verify_tx_in_block(
                raw_tx, "a" * 64, branch, pos=0, header=header
            )

    # ----- Audit 03-C2 — OP_RETURN guard -----------------------------------

    def test_03_c2_op_return_payment_rejected(self) -> None:
        """Audit 03-C2: OP_RETURN outputs must not be accepted as payments."""
        # 8-byte value + len=25 + script starting with 0x6a (OP_RETURN).
        op_return_script = b"\x6a\xa9\x14" + b"\x00" * 20 + b"\x88\xac"
        raw_tx = (
            (1000).to_bytes(8, "little")
            + bytes([25])
            + op_return_script
            + b"\x00" * 35
        )
        with pytest.raises(SpvVerificationError, match="OP_RETURN"):
            verify_payment(
                raw_tx, 0, b"\x00" * 20, P2PKH, min_satoshis=1000
            )

    # ----- Audit 02-F-5 — value & hash validation --------------------------

    def test_payment_zero_value_rejected(self) -> None:
        """Audit 02-F-5: 0-sat output must be rejected."""
        raw_tx = _p2pkh_output(0, b"\x00" * 20) + b"\x00" * 35
        with pytest.raises(SpvVerificationError, match="value is 0"):
            verify_payment(raw_tx, 0, b"\x00" * 20, P2PKH, min_satoshis=1000)

    def test_payment_insufficient_value_rejected(self) -> None:
        """Audit 02-F-5: value below threshold must be rejected."""
        raw_tx = _p2pkh_output(999, b"\x00" * 20) + b"\x00" * 35
        with pytest.raises(SpvVerificationError, match="999"):
            verify_payment(raw_tx, 0, b"\x00" * 20, P2PKH, min_satoshis=1000)

    def test_payment_hash_mismatch_rejected(self) -> None:
        """Audit 02-F-5: hash mismatch must reject (prefix-only is insufficient)."""
        raw_tx = _p2pkh_output(1000, b"\xaa" * 20) + b"\x00" * 35
        with pytest.raises(SpvVerificationError, match="hash mismatch"):
            verify_payment(raw_tx, 0, b"\xbb" * 20, P2PKH, min_satoshis=1000)

    # ----- Audit 02-F-11 — full-output boundary ----------------------------

    def test_02_f11_truncated_output_rejected(self) -> None:
        """Audit 02-F-11: truncated output at end of tx must be rejected before parse."""
        # Only 10 bytes after offset 0 — not enough for a full P2PKH output.
        raw_tx = b"\x00" * 10
        with pytest.raises(SpvVerificationError, match="truncated"):
            verify_payment(
                raw_tx, 0, b"\x00" * 20, P2PKH, min_satoshis=1000
            )


# --------------------------------------------------------------------------- mainnet fixtures


class TestMainnetFixtures:
    """Byte-for-byte tests against real mainnet blocks 840000 and 840001."""

    def test_block_840000_pow_valid(self) -> None:
        """Block 840000 header must pass PoW."""
        header = bytes.fromhex(BLOCK_840000)
        hash_le = verify_header_pow(header)
        assert len(hash_le) == 32
        # Known mainnet BE hash starts with many zero bytes.
        hash_be = hash_le[::-1].hex()
        assert hash_be.startswith(
            "000000000000000000"
        ), f"unexpected hash: {hash_be}"
        # Exact match on the known hash value.
        assert (
            hash_be
            == "0000000000000000000320283a032748cef8227873ff4872689bf23f1cda83a5"
        )

    def test_block_840000_tampered_nonce_fails(self) -> None:
        """Tampered block 840000 (zero'd nonce) must fail PoW."""
        tampered = bytes.fromhex(BLOCK_840000[:-8] + "00000000")
        with pytest.raises(SpvVerificationError):
            verify_header_pow(tampered)

    def test_chain_840000_to_840001_valid(self) -> None:
        """Consecutive mainnet chain must verify."""
        headers = [bytes.fromhex(BLOCK_840000), bytes.fromhex(BLOCK_840001)]
        hashes = verify_chain(headers)
        assert len(hashes) == 2

    def test_chain_840001_before_840000_fails(self) -> None:
        """Out-of-order chain must fail (link broken)."""
        headers = [bytes.fromhex(BLOCK_840001), bytes.fromhex(BLOCK_840000)]
        with pytest.raises(SpvVerificationError):
            verify_chain(headers)

    def test_chain_tampered_second_header_fails(self) -> None:
        """Tampered second header must fail."""
        tampered = bytes.fromhex(BLOCK_840001[:-8] + "00000000")
        with pytest.raises(SpvVerificationError):
            verify_chain([bytes.fromhex(BLOCK_840000), tampered])

    def test_merkle_root_extracted_from_840000(self) -> None:
        """Merkle root extracted at bytes 36..68 of the header."""
        header = bytes.fromhex(BLOCK_840000)
        root = extract_merkle_root(header)
        assert len(root) == 32
        assert root == header[36:68]


# --------------------------------------------------------------------------- PoW details


class TestPoW:
    def test_non_80_byte_header_rejected_short(self) -> None:
        with pytest.raises(ValidationError):
            verify_header_pow(b"\x00" * 79)

    def test_non_80_byte_header_rejected_long(self) -> None:
        with pytest.raises(ValidationError):
            verify_header_pow(b"\x00" * 81)

    def test_empty_header_rejected(self) -> None:
        with pytest.raises(ValidationError):
            verify_header_pow(b"")

    def test_hash256_is_double_sha256(self) -> None:
        """hash256 must be double-SHA256 (Bitcoin convention)."""
        import hashlib

        data = b"hello world"
        expected = hashlib.sha256(hashlib.sha256(data).digest()).digest()
        assert hash256(data) == expected


# --------------------------------------------------------------------------- chain details


class TestChain:
    def test_empty_headers_rejected(self) -> None:
        with pytest.raises(ValidationError):
            verify_chain([])

    def test_bad_chain_anchor_length_rejected(self) -> None:
        with pytest.raises(ValidationError):
            verify_chain(
                [bytes.fromhex(BLOCK_840000)], chain_anchor=b"\x00" * 31
            )

    def test_header_wrong_length_rejected(self) -> None:
        with pytest.raises(ValidationError):
            verify_chain([b"\x00" * 79])


# --------------------------------------------------------------------------- witness


class TestWitnessStripping:
    def test_legacy_tx_returned_unchanged(self) -> None:
        """Legacy (non-segwit) tx should pass through unchanged."""
        legacy_tx = bytes.fromhex(
            "01000000"  # version
            "01"  # 1 input
            + "00" * 32  # prev txid
            + "ffffffff"  # prev vout
            + "00"  # empty scriptSig
            + "ffffffff"  # sequence
            + "01"  # 1 output
            + "e803000000000000"  # 1000 sats
            + "19"
            + "76a914"
            + "00" * 20
            + "88ac"  # P2PKH script
            + "00000000"  # locktime
        )
        result = strip_witness(legacy_tx)
        assert result == legacy_tx

    def test_segwit_marker_detected_and_stripped(self) -> None:
        """Segwit tx: marker/flag/witness must be stripped; byte 4 no longer 0x00 0x01."""
        segwit_tx = bytes.fromhex(
            "01000000"  # version
            "00"  # segwit marker
            "01"  # segwit flag
            "01"  # 1 input
            + "00" * 32
            + "ffffffff"
            + "00"
            + "ffffffff"
            + "01"
            + "e803000000000000"
            + "19"
            + "76a914"
            + "00" * 20
            + "88ac"
            + "01"  # 1 witness item
            + "00"  # 0-length witness item
            + "00000000"
        )
        result = strip_witness(segwit_tx)
        # After stripping, byte 4 is the first byte of the input-count varint.
        # A 1-input tx has varint=0x01 there, so must NOT be 0x00.
        assert result[4] != 0x00

    def test_stripped_hash_matches_txid_roundtrip(self) -> None:
        """Strip + hash round-trip: stripped tx's hash matches the legacy-serialization txid."""
        # Build a known legacy tx, compute its txid, wrap with marker/flag/witness,
        # strip, and confirm hash matches.
        legacy_tx = bytes.fromhex(
            "01000000"
            "01"
            + "11" * 32
            + "00000000"
            + "00"
            + "ffffffff"
            + "01"
            + "0100000000000000"
            + "19"
            + "76a914"
            + "22" * 20
            + "88ac"
            + "00000000"
        )
        legacy_txid = hash256(legacy_tx)

        # Wrap into segwit-style (same body + empty witness).
        segwit_tx = (
            legacy_tx[:4]  # version
            + b"\x00\x01"  # marker + flag
            + legacy_tx[4:-4]  # inputs + outputs (unchanged)
            + b"\x01\x00"  # one witness item, 0 length
            + legacy_tx[-4:]  # locktime
        )
        stripped = strip_witness(segwit_tx)
        assert stripped == legacy_tx
        assert hash256(stripped) == legacy_txid

    def test_short_tx_rejected(self) -> None:
        with pytest.raises(ValidationError):
            strip_witness(b"\x00" * 5)

    def test_bad_segwit_flag_rejected(self) -> None:
        """Marker 0x00 with flag != 0x01 must be rejected."""
        bad = bytes.fromhex(
            "01000000"
            "00"
            "02"  # invalid flag
            "01"
            + "00" * 40
        )
        with pytest.raises(ValidationError):
            strip_witness(bad)


# --------------------------------------------------------------------------- merkle


class TestMerkle:
    def test_build_branch_direction_encoding(self) -> None:
        """Direction bits derived from pos bits."""
        # pos=3 = binary 11 -> dir[0]=1, dir[1]=1.
        siblings = ["aa" * 32, "bb" * 32]
        branch = build_branch(siblings, pos=3)
        assert len(branch) == 66  # 2 * 33
        assert branch[0] == 0x01
        assert branch[33] == 0x01

    def test_build_branch_pos_zero(self) -> None:
        """pos=0: all direction bits 0 (siblings on right)."""
        siblings = ["cc" * 32]
        branch = build_branch(siblings, pos=0)
        assert branch[0] == 0x00

    def test_build_branch_mixed_direction(self) -> None:
        """pos=2 = binary 10 -> dir[0]=0, dir[1]=1."""
        siblings = ["11" * 32, "22" * 32]
        branch = build_branch(siblings, pos=2)
        assert branch[0] == 0x00
        assert branch[33] == 0x01

    def test_build_branch_sibling_reversed(self) -> None:
        """Sibling hex (BE display) is stored reversed (LE) in the branch."""
        siblings = ["01" + "00" * 31]  # first byte 0x01 in BE
        branch = build_branch(siblings, pos=0)
        # LE reversed: last byte 0x01
        assert branch[-1] == 0x01
        assert branch[1] == 0x00

    def test_build_branch_negative_pos_rejected(self) -> None:
        with pytest.raises(ValidationError):
            build_branch([], pos=-1)

    def test_build_branch_bad_sibling_length_rejected(self) -> None:
        with pytest.raises(ValidationError):
            build_branch(["aa"], pos=0)

    def test_compute_root_single_level(self) -> None:
        """1 sibling on right: root = hash256(leaf_LE || sibling_LE)."""
        leaf_le = b"\x01" * 32
        sibling_le = b"\x02" * 32
        txid_be = leaf_le[::-1].hex()
        branch = bytes([0x00]) + sibling_le
        root = compute_root(txid_be, branch)
        expected = hash256(leaf_le + sibling_le)
        assert root == expected

    def test_compute_root_single_level_right(self) -> None:
        """1 sibling on left: root = hash256(sibling || leaf)."""
        leaf_le = b"\x01" * 32
        sibling_le = b"\x02" * 32
        txid_be = leaf_le[::-1].hex()
        branch = bytes([0x01]) + sibling_le
        root = compute_root(txid_be, branch)
        expected = hash256(sibling_le + leaf_le)
        assert root == expected

    def test_non_multiple_of_33_rejected(self) -> None:
        with pytest.raises(ValidationError):
            compute_root("a" * 64, b"\x00" * 34)

    def test_extract_merkle_root_offset(self) -> None:
        """Merkle root is at bytes 36..68 of the 80-byte header."""
        header = bytes(range(80))
        root = extract_merkle_root(header)
        assert root == bytes(range(36, 68))

    def test_extract_merkle_root_bad_length(self) -> None:
        with pytest.raises(ValidationError):
            extract_merkle_root(b"\x00" * 79)


# --------------------------------------------------------------------------- payment types


class TestPaymentTypes:
    def test_valid_p2pkh_output_accepted(self) -> None:
        hash20 = b"\x33" * 20
        raw_tx = _p2pkh_output(1000, hash20) + b"\x00" * 35
        # Should not raise.
        verify_payment(raw_tx, 0, hash20, P2PKH, min_satoshis=1000)

    def test_p2wpkh_valid(self) -> None:
        hash20 = b"\x44" * 20
        value = (2000).to_bytes(8, "little")
        script = b"\x00\x14" + hash20  # 22 bytes
        raw_tx = value + bytes([22]) + script + b"\x00" * 40
        verify_payment(raw_tx, 0, hash20, P2WPKH, min_satoshis=1000)

    def test_p2sh_valid(self) -> None:
        hash20 = b"\x55" * 20
        value = (3000).to_bytes(8, "little")
        script = b"\xa9\x14" + hash20 + b"\x87"  # 23 bytes
        raw_tx = value + bytes([23]) + script + b"\x00" * 40
        verify_payment(raw_tx, 0, hash20, P2SH, min_satoshis=1000)

    def test_p2tr_valid(self) -> None:
        hash32 = b"\x66" * 32
        value = (4000).to_bytes(8, "little")
        script = b"\x51\x20" + hash32  # 34 bytes
        raw_tx = value + bytes([34]) + script + b"\x00" * 40
        verify_payment(raw_tx, 0, hash32, P2TR, min_satoshis=1000)

    def test_p2tr_wrong_hash_length_rejected(self) -> None:
        """P2TR expects 32-byte hash; passing 20 bytes must raise ValidationError."""
        hash32 = b"\x66" * 32
        value = (4000).to_bytes(8, "little")
        script = b"\x51\x20" + hash32
        raw_tx = value + bytes([34]) + script + b"\x00" * 40
        with pytest.raises(ValidationError):
            verify_payment(raw_tx, 0, b"\x00" * 20, P2TR, min_satoshis=1000)

    def test_unknown_type_rejected(self) -> None:
        with pytest.raises(ValidationError):
            verify_payment(
                b"\x00" * 50, 0, b"\x00" * 20, "p2xxx", min_satoshis=1000
            )

    def test_negative_offset_rejected(self) -> None:
        with pytest.raises(ValidationError):
            verify_payment(
                b"\x00" * 50, -1, b"\x00" * 20, P2PKH, min_satoshis=1000
            )

    def test_wrong_script_len_rejected(self) -> None:
        """P2PKH with script_len byte != 25 must be rejected."""
        raw_tx = (
            (1000).to_bytes(8, "little")
            + bytes([24])  # wrong length
            + b"\x76\xa9\x14"
            + b"\x00" * 20
            + b"\x88\xac"
            + b"\x00" * 35
        )
        with pytest.raises(SpvVerificationError, match="script length"):
            verify_payment(raw_tx, 0, b"\x00" * 20, P2PKH, min_satoshis=1000)

    def test_p2pkh_wrong_suffix_rejected(self) -> None:
        """P2PKH suffix must be OP_EQUALVERIFY OP_CHECKSIG (0x88ac)."""
        hash20 = b"\x33" * 20
        raw_tx = (
            (1000).to_bytes(8, "little")
            + bytes([25])
            + b"\x76\xa9\x14"
            + hash20
            + b"\x88\xad"  # wrong suffix (should be 0x88ac)
            + b"\x00" * 35
        )
        with pytest.raises(SpvVerificationError, match="suffix"):
            verify_payment(raw_tx, 0, hash20, P2PKH, min_satoshis=1000)

    def test_wrong_script_prefix_rejected(self) -> None:
        """P2PKH prefix must be 76a914; anything else (non-OP_RETURN) must trip prefix check."""
        hash20 = b"\x33" * 20
        raw_tx = (
            (1000).to_bytes(8, "little")
            + bytes([25])
            + b"\x76\xa9\x15"  # wrong prefix last byte (0x15 instead of 0x14)
            + hash20
            + b"\x88\xac"
            + b"\x00" * 35
        )
        with pytest.raises(SpvVerificationError, match="prefix"):
            verify_payment(raw_tx, 0, hash20, P2PKH, min_satoshis=1000)


# --------------------------------------------------------------------------- CovenantParams


class TestCovenantParams:
    def _valid_kwargs(self, **overrides: object) -> dict:
        base = dict(
            btc_receive_hash=b"\x00" * 20,
            btc_receive_type="p2pkh",
            btc_satoshis=1000,
            chain_anchor=b"\x00" * 32,
            anchor_height=840000,
            merkle_depth=12,
        )
        base.update(overrides)
        return base

    def test_valid_p2pkh_params(self) -> None:
        params = CovenantParams(**self._valid_kwargs())
        assert params.btc_receive_type == P2PKH

    def test_invalid_receive_type(self) -> None:
        with pytest.raises(ValidationError):
            CovenantParams(**self._valid_kwargs(btc_receive_type="p2xxx"))

    def test_zero_satoshis_rejected(self) -> None:
        with pytest.raises(ValidationError):
            CovenantParams(**self._valid_kwargs(btc_satoshis=0))

    def test_negative_satoshis_rejected(self) -> None:
        with pytest.raises(ValidationError):
            CovenantParams(**self._valid_kwargs(btc_satoshis=-1))

    def test_short_chain_anchor_rejected(self) -> None:
        with pytest.raises(ValidationError):
            CovenantParams(**self._valid_kwargs(chain_anchor=b"\x00" * 31))

    def test_p2tr_needs_32_byte_hash(self) -> None:
        """P2TR requires 32-byte hash; passing 20-byte hash must raise."""
        with pytest.raises(ValidationError):
            CovenantParams(
                **self._valid_kwargs(
                    btc_receive_type="p2tr", btc_receive_hash=b"\x00" * 20
                )
            )

    def test_p2tr_with_32_byte_hash_accepted(self) -> None:
        params = CovenantParams(
            **self._valid_kwargs(
                btc_receive_type="p2tr", btc_receive_hash=b"\x00" * 32
            )
        )
        assert params.btc_receive_type == P2TR

    def test_p2pkh_with_32_byte_hash_rejected(self) -> None:
        with pytest.raises(ValidationError):
            CovenantParams(**self._valid_kwargs(btc_receive_hash=b"\x00" * 32))

    def test_merkle_depth_zero_rejected(self) -> None:
        with pytest.raises(ValidationError):
            CovenantParams(**self._valid_kwargs(merkle_depth=0))

    def test_merkle_depth_33_rejected(self) -> None:
        with pytest.raises(ValidationError):
            CovenantParams(**self._valid_kwargs(merkle_depth=33))

    def test_covenant_params_is_frozen(self) -> None:
        """CovenantParams dataclass is frozen — assignment must fail."""
        params = CovenantParams(**self._valid_kwargs())
        with pytest.raises(Exception):
            params.btc_satoshis = 2000  # type: ignore[misc]


# --------------------------------------------------------------------------- SpvProofBuilder end-to-end


class TestSpvProofBuilder:
    """End-to-end: SpvProofBuilder rejects bad proofs and accepts synthetic valid proofs.

    We don't have a real mainnet SPV proof on disk, but we can construct a
    synthetic one that ties together:
        * a valid real mainnet header (840000)
        * a manually-built 1-level Merkle tree with a crafted leaf tx
        * the leaf tx crafted to also contain a valid payment output

    The trick: since we need the Merkle root to match the real header, we'd
    have to forge the whole block — which we can't. Instead, we verify
    the builder's *failure modes* (which is what actually matters for
    security) and use a mock-header approach for success-path tests.
    """

    def _params(self, **overrides: object) -> CovenantParams:
        base = dict(
            btc_receive_hash=b"\x77" * 20,
            btc_receive_type=P2PKH,
            btc_satoshis=1000,
            chain_anchor=bytes.fromhex(BLOCK_840000)[4:36],
            anchor_height=839999,
            merkle_depth=1,
        )
        base.update(overrides)
        return CovenantParams(**base)  # type: ignore[arg-type]

    def test_builder_rejects_short_raw_tx(self) -> None:
        """Stripped raw_tx <= 64 bytes must be rejected (64-byte Merkle forgery)."""
        params = self._params()
        builder = SpvProofBuilder(params)
        # Construct a 60-byte legacy tx (<= 64 bytes).
        short_tx_hex = "aa" * 60
        with pytest.raises(SpvVerificationError, match="64"):
            builder.build(
                txid_be="00" * 32,
                raw_tx_hex=short_tx_hex,
                headers_hex=[BLOCK_840000],
                merkle_be=[],
                pos=1,
                output_offset=4,
            )

    def test_builder_rejects_txid_mismatch(self) -> None:
        """hash256(raw_tx) != txid must be rejected."""
        params = self._params()
        builder = SpvProofBuilder(params)
        # 80-byte bogus tx (> 64).
        raw_tx_hex = "bb" * 80
        with pytest.raises(SpvVerificationError, match="txid"):
            builder.build(
                txid_be="00" * 32,  # intentionally wrong
                raw_tx_hex=raw_tx_hex,
                headers_hex=[BLOCK_840000],
                merkle_be=[],
                pos=1,
                output_offset=4,
            )

    def test_builder_rejects_wrong_chain_anchor(self) -> None:
        """Params' chain_anchor mismatch must propagate to builder."""
        params = self._params(chain_anchor=b"\xff" * 32)
        builder = SpvProofBuilder(params)
        raw_tx_bytes = b"\xcc" * 80
        # Compute the matching txid so we at least get past the tx-integrity check.
        txid_le = hash256(raw_tx_bytes)
        txid_be = txid_le[::-1].hex()
        with pytest.raises(SpvVerificationError, match="chain_anchor"):
            builder.build(
                txid_be=txid_be,
                raw_tx_hex=raw_tx_bytes.hex(),
                headers_hex=[BLOCK_840000],
                merkle_be=[],
                pos=1,
                output_offset=4,
            )

    def test_builder_rejects_coinbase_pos(self) -> None:
        """pos=0 must be rejected before payment check."""
        params = self._params()
        builder = SpvProofBuilder(params)
        raw_tx_bytes = b"\xdd" * 80
        txid_be = hash256(raw_tx_bytes)[::-1].hex()
        with pytest.raises(SpvVerificationError, match="coinbase"):
            builder.build(
                txid_be=txid_be,
                raw_tx_hex=raw_tx_bytes.hex(),
                headers_hex=[BLOCK_840000],
                merkle_be=["ee" * 32],
                pos=0,
                output_offset=4,
            )

    def test_builder_rejects_proof_when_root_does_not_match(self) -> None:
        """A branch that doesn't hash to any header's root must be rejected."""
        params = self._params()
        builder = SpvProofBuilder(params)
        raw_tx_bytes = b"\xee" * 80
        txid_be = hash256(raw_tx_bytes)[::-1].hex()
        # A 1-level branch whose computed root won't match 840000's root.
        with pytest.raises(SpvVerificationError, match="root"):
            builder.build(
                txid_be=txid_be,
                raw_tx_hex=raw_tx_bytes.hex(),
                headers_hex=[BLOCK_840000],
                merkle_be=["ff" * 32],
                pos=1,
                output_offset=4,
            )

    @staticmethod
    def _grind_header(
        version: bytes, prev: bytes, merkle_le: bytes, nbits: bytes
    ) -> bytes:
        """Grind a nonce until the resulting header's hash beats the nBits target.

        Uses nBits with large target (exponent 0x1d / mantissa 0x7fffff).
        target_BE = 0x000000_7fffff_00..00 — hash_BE first 3 bytes must be 0
        (equivalently hash_LE last 3 bytes must be 0), so probability 1/2^24.
        Fast-path: hash directly with hashlib and only call the full verifier
        on matches. This finishes within ~5 seconds on CPython.
        """
        time_field = b"\x00\x00\x00\x00"
        base = version + prev + merkle_le + time_field + nbits
        for nonce in range(100_000_000):
            header = base + nonce.to_bytes(4, "little")
            # Fast gate: hash's LE bytes 29..31 must be 0 for PoW to even
            # have a chance. Use the module-level hash256 helper.
            h = hash256(header)
            if h[29] == 0 and h[30] == 0 and h[31] == 0:
                try:
                    verify_header_pow(header)
                    return header
                except SpvVerificationError:
                    continue
        raise RuntimeError("could not grind header in 100M tries")

    # Class-level cache of ground synthetic headers, keyed by (satoshis, hash20).
    # Each grind takes ~5s on CPython; cache avoids repeat work across tests.
    _synthetic_cache: dict = {}

    def _build_synthetic_proof_inputs(
        self, hash20: bytes, satoshis: int
    ) -> tuple[str, str, list[str], list[str], int, int, bytes]:
        """Build a complete synthetic proof bundle (cached across tests).

        Returns:
            (txid_be_hex, raw_tx_hex, headers_hex, merkle_be, pos, output_offset, anchor).
        """
        key = (satoshis, bytes(hash20))
        if key in self._synthetic_cache:
            return self._synthetic_cache[key]

        payment_output = _p2pkh_output(satoshis, hash20)
        raw_tx = (
            b"\x01\x00\x00\x00"  # version
            + b"\x01"  # 1 input
            + b"\x00" * 32
            + b"\xff\xff\xff\xff"
            + b"\x00"
            + b"\xff\xff\xff\xff"
            + b"\x01"  # 1 output
            + payment_output
            + b"\x00\x00\x00\x00"
        )
        assert len(raw_tx) > 64
        txid_le = hash256(raw_tx)
        txid_be_hex = txid_le[::-1].hex()

        output_offset = 4 + 1 + 41 + 1
        assert raw_tx[output_offset : output_offset + 8] == satoshis.to_bytes(
            8, "little"
        )

        sibling_le = b"\xab" * 32
        sibling_be_hex = sibling_le[::-1].hex()
        merkle_root_le = hash256(sibling_le + txid_le)

        anchor = b"\x99" * 32
        nbits = b"\xff\xff\x7f\x1d"  # large target, exponent 0x1d
        header = self._grind_header(
            b"\x00\x00\x00\x20", anchor, merkle_root_le, nbits
        )
        result = (
            txid_be_hex,
            raw_tx.hex(),
            [header.hex()],
            [sibling_be_hex],
            1,
            output_offset,
            anchor,
        )
        self._synthetic_cache[key] = result
        return result

    def test_builder_full_success_synthetic_block(self) -> None:
        """Full end-to-end with a synthetic block whose PoW target is relaxed.

        We grind the nonce until hash < target so the PoW check passes. This
        exercises the entire pipeline (witness strip + tx-integrity + PoW +
        chain anchor + Merkle inclusion + payment) on a single known-valid
        proof.
        """
        hash20 = b"\x77" * 20
        (
            txid_be_hex,
            raw_tx_hex,
            headers_hex,
            merkle_be,
            pos,
            output_offset,
            anchor,
        ) = self._build_synthetic_proof_inputs(hash20, satoshis=5000)

        params = CovenantParams(
            btc_receive_hash=hash20,
            btc_receive_type=P2PKH,
            btc_satoshis=1000,
            chain_anchor=anchor,
            anchor_height=100_000,
            merkle_depth=1,
        )
        builder = SpvProofBuilder(params)
        proof = builder.build(
            txid_be=txid_be_hex,
            raw_tx_hex=raw_tx_hex,
            headers_hex=headers_hex,
            merkle_be=merkle_be,
            pos=pos,
            output_offset=output_offset,
        )
        assert proof.txid == txid_be_hex
        assert proof.covenant_params is params
        # Direct construction without _token is now rejected (sentinel guard)
        from pyrxd.spv.proof import _BUILDER_TOKEN
        assert proof._token is _BUILDER_TOKEN

    def test_builder_rejects_insufficient_payment(self) -> None:
        """Synthetic valid-chain proof whose payment value < min_satoshis must reject."""
        hash20 = b"\x77" * 20
        (
            txid_be_hex,
            raw_tx_hex,
            headers_hex,
            merkle_be,
            pos,
            output_offset,
            anchor,
        ) = self._build_synthetic_proof_inputs(hash20, satoshis=500)

        params = CovenantParams(
            btc_receive_hash=hash20,
            btc_receive_type=P2PKH,
            btc_satoshis=1000,  # threshold above 500
            chain_anchor=anchor,
            anchor_height=100_000,
            merkle_depth=1,
        )
        builder = SpvProofBuilder(params)
        with pytest.raises(SpvVerificationError, match="500"):
            builder.build(
                txid_be=txid_be_hex,
                raw_tx_hex=raw_tx_hex,
                headers_hex=headers_hex,
                merkle_be=merkle_be,
                pos=pos,
                output_offset=output_offset,
            )

    def test_builder_rejects_wrong_payment_hash(self) -> None:
        """Synthetic valid-chain proof with hash mismatch must reject."""
        hash20 = b"\x77" * 20
        (
            txid_be_hex,
            raw_tx_hex,
            headers_hex,
            merkle_be,
            pos,
            output_offset,
            anchor,
        ) = self._build_synthetic_proof_inputs(hash20, satoshis=5000)

        params = CovenantParams(
            btc_receive_hash=b"\xaa" * 20,  # wrong hash
            btc_receive_type=P2PKH,
            btc_satoshis=1000,
            chain_anchor=anchor,
            anchor_height=100_000,
            merkle_depth=1,
        )
        builder = SpvProofBuilder(params)
        with pytest.raises(SpvVerificationError, match="hash mismatch"):
            builder.build(
                txid_be=txid_be_hex,
                raw_tx_hex=raw_tx_hex,
                headers_hex=headers_hex,
                merkle_be=merkle_be,
                pos=pos,
                output_offset=output_offset,
            )

    def test_builder_rejects_wrong_merkle_depth(self) -> None:
        """Synthetic proof whose branch depth != covenant_params.merkle_depth rejects."""
        hash20 = b"\x77" * 20
        (
            txid_be_hex,
            raw_tx_hex,
            headers_hex,
            merkle_be,
            pos,
            output_offset,
            anchor,
        ) = self._build_synthetic_proof_inputs(hash20, satoshis=5000)

        params = CovenantParams(
            btc_receive_hash=hash20,
            btc_receive_type=P2PKH,
            btc_satoshis=1000,
            chain_anchor=anchor,
            anchor_height=100_000,
            merkle_depth=5,  # expect 5-level branch but our branch is 1 level
        )
        builder = SpvProofBuilder(params)
        with pytest.raises(SpvVerificationError, match="depth"):
            builder.build(
                txid_be=txid_be_hex,
                raw_tx_hex=raw_tx_hex,
                headers_hex=headers_hex,
                merkle_be=merkle_be,
                pos=pos,
                output_offset=output_offset,
            )
