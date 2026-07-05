"""Targeted assertions that kill surviving cosmic-ray mutants.

Each test names the mutant class it kills (module + line refers to the
2026-07 baseline run; see docs/how-to/mutation-testing.md). These are
behavior pins, not implementation mirrors: every expected value is derived
in-test from the spec (stdlib hashing, documented formulas, docstring
examples), never from the code under test.

Grouped by mutation scope so the per-scope cosmic-ray test commands stay
fast: `task mutate transaction|script|dmint` all include this file.
"""

from __future__ import annotations

import hashlib

import pytest

from pyrxd.script.script import Script
from pyrxd.script.type import P2PKH
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_input import TransactionInput
from pyrxd.transaction.transaction_output import TransactionOutput

_P2PKH_AA = bytes.fromhex("76a914" + "aa" * 20 + "88ac")
_P2PKH_BB = bytes.fromhex("76a914" + "bb" * 20 + "88ac")


def _sha256d(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def _out(script: bytes, sats: int, change: bool = False) -> TransactionOutput:
    return TransactionOutput(Script(script), sats, change=change)


def _in(txid: str = "ab" * 32, vout: int = 0, sequence: int = 0xFFFFFFFF) -> TransactionInput:
    tx_in = TransactionInput(source_txid=txid, source_output_index=vout, sequence=sequence)
    tx_in.satoshis = 10_000
    tx_in.locking_script = Script(_P2PKH_AA)
    return tx_in


class TestTransactionIdentity:
    """transaction.py — txid/hash/serialize mutants."""

    def test_txid_is_reversed_double_sha256_of_serialization(self):
        """Kills the L91 `hash()[::-1]` → `hash()[::1]` survivors: txid MUST
        be the byte-reversed double-SHA256, re-derived here with hashlib
        alone. An unreversed txid would silently break every outpoint
        reference this SDK ever signs."""
        tx = Transaction(tx_inputs=[_in()], tx_outputs=[_out(_P2PKH_AA, 5_000)])
        raw = tx.serialize()
        assert tx.txid() == _sha256d(raw)[::-1].hex()
        assert tx.hash() == _sha256d(raw)

    def test_is_coinbase_requires_exactly_one_all_zero_input(self):
        """Kills the L83 `== 1` → `>= 1` and txid-comparison survivors."""
        coinbase = Transaction(tx_inputs=[_in(txid="00" * 32)])
        assert coinbase.is_coinbase()
        normal = Transaction(tx_inputs=[_in(txid="ab" * 32)])
        assert not normal.is_coinbase()
        two_inputs = Transaction(tx_inputs=[_in(txid="00" * 32), _in(txid="ab" * 32)])
        assert not two_inputs.is_coinbase()

    def test_preimage_index_bounds(self):
        """Kills the L97 guard survivors (`0 <=` → `-1 <=`, `<` → `<=`):
        out-of-range indexes must raise, never wrap to inputs[-1]."""
        tx = Transaction(tx_inputs=[_in()], tx_outputs=[_out(_P2PKH_AA, 5_000)])
        with pytest.raises(ValueError):
            tx.preimage(-1)
        with pytest.raises(ValueError):
            tx.preimage(1)

    def test_constructor_preserves_extra_kwargs(self):
        """Kills the L45 `dict(**kwargs) or {}` → `and {}` survivor, which
        would silently drop caller metadata."""
        tx = Transaction(note="keepme")
        assert tx.kwargs == {"note": "keepme"}


class TestTransactionAccounting:
    """transaction.py — fee/value arithmetic mutants."""

    def test_get_fee_is_subtraction(self):
        """Kills the L133 `-` → `%` survivor: 10_000 in − 3_000 out = 7_000
        (the `%` mutant would report 1_000)."""
        tx = Transaction(tx_inputs=[_in()], tx_outputs=[_out(_P2PKH_AA, 3_000)])
        assert tx.total_value_in() == 10_000
        assert tx.total_value_out() == 3_000
        assert tx.get_fee() == 7_000

    def test_estimated_byte_length_formula(self):
        """Kills the L156 `41` NumberReplacer survivors by pinning the
        documented per-input formula: 4 (version) + varint(#in) +
        varint(#out) + 4 (locktime) + per-input (40 outpoint/sequence + 1
        script-len varint = 41, + template estimate) + per-output (8 +
        script varint + script)."""
        from pyrxd.keys import PrivateKey

        pk_template = P2PKH().unlock(PrivateKey())  # fresh throwaway key
        tx_in = _in()
        tx_in.unlocking_script_template = pk_template
        tx = Transaction(tx_inputs=[tx_in], tx_outputs=[_out(_P2PKH_AA, 5_000)])
        expected = 4 + 1 + 1 + 4 + (41 + 107) + (8 + 1 + len(_P2PKH_AA))
        assert tx.estimated_byte_length() == expected

    def test_fee_change_distribution_docstring_example(self):
        """Kills the L181–L217 change-distribution survivors with the
        docstring's own worked example: change=10 over 3 change outputs
        must yield [4, 3, 3] (sum preserved, remainder to the first)."""
        src = Transaction(tx_outputs=[_out(_P2PKH_AA, 1_010)])
        tx_in = TransactionInput(source_transaction=src, source_output_index=0)
        tx = Transaction(
            tx_inputs=[tx_in],
            tx_outputs=[
                _out(_P2PKH_BB, 1_000),
                _out(_P2PKH_AA, None, change=True),
                _out(_P2PKH_AA, None, change=True),
                _out(_P2PKH_AA, None, change=True),
            ],
        )
        tx.fee(0)  # explicit zero fee → change pool is exactly 10
        assert [o.satoshis for o in tx.outputs if o.change] == [4, 3, 3]

    def test_fee_drops_change_outputs_when_dust(self):
        """Kills the `change <= change_count` branch survivors: when the
        pool can't give each change output more than 1 photon, ALL change
        outputs are removed and the surplus goes to miners."""
        src = Transaction(tx_outputs=[_out(_P2PKH_AA, 1_002)])
        tx_in = TransactionInput(source_transaction=src, source_output_index=0)
        tx = Transaction(
            tx_inputs=[tx_in],
            tx_outputs=[
                _out(_P2PKH_BB, 1_000),
                _out(_P2PKH_AA, None, change=True),
                _out(_P2PKH_AA, None, change=True),
            ],
        )
        tx.fee(0)  # change pool = 2 == change_count → drop them
        assert [o for o in tx.outputs if o.change] == []
        assert len(tx.outputs) == 1

    def test_fee_random_distribution_not_implemented(self):
        """Pins the L203 'random' branch: it must raise NotImplementedError,
        not fall through to equal distribution."""
        src = Transaction(tx_outputs=[_out(_P2PKH_AA, 2_000)])
        tx_in = TransactionInput(source_transaction=src, source_output_index=0)
        tx = Transaction(tx_inputs=[tx_in], tx_outputs=[_out(_P2PKH_AA, None, change=True)])
        with pytest.raises(NotImplementedError):
            tx.fee(0, change_distribution="random")


class TestSignValidation:
    """transaction.py — sign()'s missing-amount validation mutants (L106–108)."""

    def test_sign_rejects_uncomputed_change_output(self):
        tx = Transaction(tx_inputs=[_in()], tx_outputs=[_out(_P2PKH_AA, None, change=True)])
        with pytest.raises(ValueError, match="fee\\(\\)"):
            tx.sign()

    def test_sign_rejects_missing_amount_on_regular_output(self):
        tx = Transaction(tx_inputs=[_in()], tx_outputs=[_out(_P2PKH_AA, None)])
        with pytest.raises(ValueError, match="missing an amount"):
            tx.sign()
