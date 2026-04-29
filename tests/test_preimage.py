"""Tests for Radiant BIP143 sighash preimage, including hashOutputHashes.

Test vectors for hashOutputHashes were generated from radiantjs
(GetHashOutputHashes in lib/transaction/sighash.js) on 2026-04-21 and
verified against the confirmed mainnet reveal tx
dac1e2dfed64fbfd0f0fe6b925e144cfc32ef76803abc7a6a4058406d707b407.
"""
import pytest

from pyrxd.script.script import Script
from pyrxd.transaction.transaction_output import TransactionOutput
from pyrxd.transaction.transaction_preimage import (
    _compute_hash_output_hashes,
    _get_push_refs,
)

# ---------------------------------------------------------------------------
# Fixtures: script hex strings used across vectors
# ---------------------------------------------------------------------------

P2PKH_AA = "76a914" + "aa" * 20 + "88ac"   # standard P2PKH, no refs
P2PKH_BB = "76a914" + "bb" * 20 + "88ac"
# NFT singleton: OP_PUSHINPUTREFSINGLETON (0xd8) + 36-byte ref + P2PKH tail
_REF = "b73ea8b33a8d8f15b25d25b9e6892926f893a7fdb6a97695d029732aa4ae01cd00000000"
NFT_SCRIPT = "d8" + _REF + "7576a914" + "cc" * 20 + "88ac"


def _out(script_hex: str, satoshis: int) -> TransactionOutput:
    return TransactionOutput(Script(bytes.fromhex(script_hex)), satoshis)


# ---------------------------------------------------------------------------
# _get_push_refs
# ---------------------------------------------------------------------------

class TestGetPushRefs:
    def test_p2pkh_has_no_refs(self):
        assert _get_push_refs(bytes.fromhex(P2PKH_AA)) == []

    def test_nft_singleton_has_one_ref(self):
        refs = _get_push_refs(bytes.fromhex(NFT_SCRIPT))
        assert len(refs) == 1
        assert refs[0] == bytes.fromhex(_REF)

    def test_pushinputref_opcode(self):
        # OP_PUSHINPUTREF (0xd0) followed by 36-byte ref
        ref = bytes(range(36))
        script = bytes([0xd0]) + ref
        refs = _get_push_refs(script)
        assert len(refs) == 1
        assert refs[0] == ref

    def test_duplicate_refs_deduplicated(self):
        ref = bytes(range(36))
        script = bytes([0xd8]) + ref + bytes([0xd8]) + ref
        refs = _get_push_refs(script)
        assert len(refs) == 1

    def test_multiple_refs_sorted(self):
        ref_a = b"\xff" + bytes(35)
        ref_b = b"\x00" + bytes(35)
        script = bytes([0xd8]) + ref_a + bytes([0xd8]) + ref_b
        refs = _get_push_refs(script)
        assert len(refs) == 2
        assert refs[0] == ref_b   # 00... sorts before ff...
        assert refs[1] == ref_a

    def test_skips_data_pushes_correctly(self):
        # OP_PUSH3 'gly' then OP_PUSHINPUTREFSINGLETON + ref
        ref = bytes(range(36))
        script = bytes([0x03, 0x67, 0x6c, 0x79]) + bytes([0xd8]) + ref
        refs = _get_push_refs(script)
        assert len(refs) == 1
        assert refs[0] == ref

    def test_empty_script(self):
        assert _get_push_refs(b"") == []


# ---------------------------------------------------------------------------
# _compute_hash_output_hashes — known-good vectors from radiantjs
# ---------------------------------------------------------------------------

class TestComputeHashOutputHashes:
    def test_two_p2pkh_outputs(self):
        # radiantjs: v1_all
        outputs = [_out(P2PKH_AA, 100_000), _out(P2PKH_BB, 50_000)]
        result = _compute_hash_output_hashes(outputs)
        assert result.hex() == "131577023e4b1972c69b79fe851412e64390576ea90514ed5b83e9bfcc261304"

    def test_single_p2pkh_output(self):
        # radiantjs: v2_all
        outputs = [_out(P2PKH_AA, 546)]
        result = _compute_hash_output_hashes(outputs)
        assert result.hex() == "42053adc8c31d4299864f45101c180c7397471cd13b2ac0451217754649b33cf"

    def test_nft_singleton_output(self):
        # radiantjs: v3_all — NFT has one OP_PUSHINPUTREFSINGLETON ref
        outputs = [_out(NFT_SCRIPT, 442_546)]
        result = _compute_hash_output_hashes(outputs)
        assert result.hex() == "148f582c4c97db5fe686d68a5ed054a4b6946c0f498051a5f9df0040af48e791"

    def test_nft_plus_p2pkh_all_outputs(self):
        # radiantjs: v4_all
        outputs = [_out(NFT_SCRIPT, 442_546), _out(P2PKH_AA, 100_000)]
        result = _compute_hash_output_hashes(outputs)
        assert result.hex() == "049613e42ad3c0e25a8bfa55065d8481e35633dd9df743c7e98914d401edf4b2"

    def test_sighash_single_index_0(self):
        # radiantjs: v4_idx0 — only NFT output, same as v3_all
        outputs = [_out(NFT_SCRIPT, 442_546), _out(P2PKH_AA, 100_000)]
        result = _compute_hash_output_hashes(outputs, index=0)
        assert result.hex() == "148f582c4c97db5fe686d68a5ed054a4b6946c0f498051a5f9df0040af48e791"

    def test_sighash_single_index_1(self):
        # radiantjs: v4_idx1 — only P2PKH output
        outputs = [_out(NFT_SCRIPT, 442_546), _out(P2PKH_AA, 100_000)]
        result = _compute_hash_output_hashes(outputs, index=1)
        assert result.hex() == "d3a62446cf608f656518faa07460984194bb21a7c43e5af8584e4b6a70228ae4"

    def test_returns_32_bytes(self):
        outputs = [_out(P2PKH_AA, 1000)]
        assert len(_compute_hash_output_hashes(outputs)) == 32


# ---------------------------------------------------------------------------
# Two-pass signing: stale unlocking_script must be cleared between txs
# ---------------------------------------------------------------------------

class TestTwoPassSigning:
    def test_stale_signature_without_reset(self):
        """Reproduces the bypass bug: sign() skips re-signing if unlocking_script is set."""
        from pyrxd.keys import PrivateKey
        from pyrxd.script.type import P2PKH, to_unlock_script_template, encode_pushdata
        from pyrxd.transaction.transaction import Transaction, TransactionInput

        pk = PrivateKey(b"\x12" * 32)
        addr = pk.public_key().address()

        src_out = _out(P2PKH_AA, 1_000_000)
        src_tx = Transaction(tx_inputs=[], tx_outputs=[src_out])
        src_tx.txid = lambda: "aa" * 32

        inp = TransactionInput(
            source_transaction=src_tx,
            source_output_index=0,
            unlocking_script_template=P2PKH().unlock(pk),
        )

        # Trial tx
        trial_tx = Transaction(tx_inputs=[inp], tx_outputs=[_out(P2PKH_BB, 500_000)])
        trial_tx.sign()
        trial_script = inp.unlocking_script.serialize()

        # Final tx without reset — bypass skips re-signing
        final_tx = Transaction(tx_inputs=[inp], tx_outputs=[_out(P2PKH_BB, 400_000)])
        final_tx.sign()  # bypass=True: unlocking_script not None → skipped
        assert inp.unlocking_script.serialize() == trial_script  # stale!

    def test_reset_forces_resign(self):
        """After clearing unlocking_script, sign() produces a fresh signature for the final tx."""
        from pyrxd.keys import PrivateKey
        from pyrxd.script.type import P2PKH
        from pyrxd.transaction.transaction import Transaction, TransactionInput

        pk = PrivateKey(b"\x12" * 32)

        src_out = _out(P2PKH_AA, 1_000_000)
        src_tx = Transaction(tx_inputs=[], tx_outputs=[src_out])
        src_tx.txid = lambda: "aa" * 32

        inp = TransactionInput(
            source_transaction=src_tx,
            source_output_index=0,
            unlocking_script_template=P2PKH().unlock(pk),
        )

        trial_tx = Transaction(tx_inputs=[inp], tx_outputs=[_out(P2PKH_BB, 500_000)])
        trial_tx.sign()
        trial_script = inp.unlocking_script.serialize()

        # THE FIX: clear before final tx
        inp.unlocking_script = None

        final_tx = Transaction(tx_inputs=[inp], tx_outputs=[_out(P2PKH_BB, 400_000)])
        final_tx.sign()
        assert inp.unlocking_script.serialize() != trial_script  # fresh signature
