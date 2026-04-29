"""Coverage gap tests — brings up undertested modules.

Targets (from 2026-04-24 coverage audit):
- fee_models/satoshis_per_kilobyte.py  (19% → target ≥ 80%)
- transaction/transaction.py           (36% → target ≥ 65%)
- transaction/__init__.py              (new public API)
- script/__init__.py                   (new public API)
- pyrxd/__init__.py top-level imports  (new)
"""
from __future__ import annotations

import pytest

# ---------------------------------------------------------------------------
# Top-level pyrxd public API (new __init__.py)
# ---------------------------------------------------------------------------

class TestToplevelImports:
    def test_glyphbuilder_importable_from_rxdpy(self):
        from pyrxd import GlyphBuilder
        assert GlyphBuilder is not None

    def test_glyphmetadata_importable_from_rxdpy(self):
        from pyrxd import GlyphMetadata
        assert GlyphMetadata is not None

    def test_glyphprotocol_importable_from_rxdpy(self):
        from pyrxd import GlyphProtocol
        assert GlyphProtocol is not None

    def test_glyphref_importable_from_rxdpy(self):
        from pyrxd import GlyphRef
        assert GlyphRef is not None

    def test_gravitytrade_importable_from_rxdpy(self):
        from pyrxd import GravityTrade
        assert GravityTrade is not None

    def test_privatekey_importable_from_rxdpy(self):
        from pyrxd import PrivateKey
        assert PrivateKey is not None

    def test_rxdsdkerror_importable_from_rxdpy(self):
        from pyrxd import RxdSdkError
        assert issubclass(RxdSdkError, Exception)

    def test_validationerror_importable_from_rxdpy(self):
        from pyrxd import ValidationError, RxdSdkError
        assert issubclass(ValidationError, RxdSdkError)

    def test_version_string_present(self):
        import pyrxd
        # Don't pin the exact version — that brittle assertion broke
        # on every release. Pin the *shape* (PEP 440 — non-empty,
        # starts with a digit) and that the symbol is exported.
        assert isinstance(pyrxd.__version__, str)
        assert len(pyrxd.__version__) > 0
        assert pyrxd.__version__[0].isdigit()

    def test_all_defines_exported_names(self):
        import pyrxd
        assert hasattr(pyrxd, "__all__")
        for name in pyrxd.__all__:
            assert hasattr(pyrxd, name), f"__all__ lists {name!r} but it's not defined"


# ---------------------------------------------------------------------------
# script/__init__.py — new curated public surface
# ---------------------------------------------------------------------------

class TestScriptPublicAPI:
    def test_script_importable(self):
        from pyrxd.script import Script
        s = Script()
        assert s is not None

    def test_script_chunk_importable(self):
        from pyrxd.script import ScriptChunk
        assert ScriptChunk is not None

    def test_p2pkh_importable(self):
        from pyrxd.script import P2PKH
        assert P2PKH is not None

    def test_p2pk_importable(self):
        from pyrxd.script import P2PK
        assert P2PK is not None

    def test_op_return_importable(self):
        from pyrxd.script import OpReturn
        assert OpReturn is not None

    def test_bare_multisig_importable(self):
        from pyrxd.script import BareMultisig
        assert BareMultisig is not None

    def test_script_template_importable(self):
        from pyrxd.script import ScriptTemplate
        assert ScriptTemplate is not None

    def test_all_defines_exported_names(self):
        import pyrxd.script as s
        assert hasattr(s, "__all__")
        for name in s.__all__:
            assert hasattr(s, name), f"script.__all__ lists {name!r} but it's not defined"


# ---------------------------------------------------------------------------
# transaction/__init__.py — new curated public surface
# ---------------------------------------------------------------------------

class TestTransactionPublicAPI:
    def test_transaction_importable(self):
        from pyrxd.transaction import Transaction
        assert Transaction is not None

    def test_transaction_input_importable(self):
        from pyrxd.transaction import TransactionInput
        assert TransactionInput is not None

    def test_transaction_output_importable(self):
        from pyrxd.transaction import TransactionOutput
        assert TransactionOutput is not None

    def test_insufficient_funds_importable(self):
        from pyrxd.transaction import InsufficientFunds
        assert issubclass(InsufficientFunds, ValueError)

    def test_all_defines_exported_names(self):
        import pyrxd.transaction as t
        assert hasattr(t, "__all__")
        for name in t.__all__:
            assert hasattr(t, name), f"transaction.__all__ lists {name!r} but it's not defined"


# ---------------------------------------------------------------------------
# fee_models/satoshis_per_kilobyte.py
# ---------------------------------------------------------------------------

from pyrxd.script.script import Script
from pyrxd.script.type import P2PKH
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_input import TransactionInput
from pyrxd.transaction.transaction_output import TransactionOutput
from pyrxd.fee_models.satoshis_per_kilobyte import SatoshisPerKilobyte


def _make_locking() -> Script:
    return Script("76a914" + "ab" * 20 + "88ac")


def _make_unlocking() -> Script:
    # P2PKH-shaped unlocking script: push DER sig (71 bytes) + push pubkey (65 bytes)
    return Script("47" + "30" * 71 + "01" + "41" + "04" + "ab" * 64)


def _minimal_tx(in_satoshis: int = 10_000, out_satoshis: int = 9_000) -> Transaction:
    """Build a minimal Transaction with enough state for SatoshisPerKilobyte."""
    locking = _make_locking()
    # Build source tx with its output first, then reference it
    src_out = TransactionOutput(locking_script=locking, satoshis=in_satoshis)
    src_tx = Transaction(tx_inputs=[], tx_outputs=[src_out])

    tx_in = TransactionInput(
        source_transaction=src_tx,  # src_tx.outputs[0] = src_out
        source_output_index=0,
        unlocking_script=_make_unlocking(),
    )
    tx_out = TransactionOutput(locking_script=locking, satoshis=out_satoshis)
    return Transaction(tx_inputs=[tx_in], tx_outputs=[tx_out])


class TestSatoshisPerKilobyte:
    def test_basic_fee_is_positive(self):
        model = SatoshisPerKilobyte(500)
        tx = _minimal_tx()
        fee = model.compute_fee(tx)
        assert fee > 0

    def test_fee_scales_with_rate(self):
        tx = _minimal_tx()
        fee_low = SatoshisPerKilobyte(100).compute_fee(tx)
        fee_high = SatoshisPerKilobyte(1000).compute_fee(tx)
        assert fee_high > fee_low

    def test_fee_is_integer(self):
        model = SatoshisPerKilobyte(500)
        tx = _minimal_tx()
        fee = model.compute_fee(tx)
        assert isinstance(fee, int)

    def test_zero_rate_gives_zero_fee(self):
        model = SatoshisPerKilobyte(0)
        tx = _minimal_tx()
        assert model.compute_fee(tx) == 0

    def test_no_unlocking_script_or_template_raises(self):
        """Input with neither unlocking_script nor template raises ValueError."""
        locking = _make_locking()
        src_out = TransactionOutput(locking_script=locking, satoshis=10_000)
        src_tx = Transaction(tx_inputs=[], tx_outputs=[src_out])
        tx_in = TransactionInput(
            source_transaction=src_tx,
            source_output_index=0,
            unlocking_script=None,
            unlocking_script_template=None,
        )
        tx = Transaction(tx_inputs=[tx_in], tx_outputs=[TransactionOutput(locking_script=locking, satoshis=9_000)])
        model = SatoshisPerKilobyte(500)
        with pytest.raises(ValueError, match="unlocking script"):
            model.compute_fee(tx)

    def test_varint_size_boundaries(self):
        """Exercise the 3-byte varint branch by having >253 outputs."""
        locking = _make_locking()
        src_out = TransactionOutput(locking_script=locking, satoshis=1_000_000)
        src_tx = Transaction(tx_inputs=[], tx_outputs=[src_out])
        tx_in = TransactionInput(
            source_transaction=src_tx,
            source_output_index=0,
            unlocking_script=_make_unlocking(),
        )
        many_outputs = [TransactionOutput(locking_script=locking, satoshis=1000) for _ in range(254)]
        tx = Transaction(tx_inputs=[tx_in], tx_outputs=many_outputs)
        fee = SatoshisPerKilobyte(1000).compute_fee(tx)
        assert fee > 0


# ---------------------------------------------------------------------------
# transaction/transaction.py — additional method coverage
# ---------------------------------------------------------------------------

class TestTransactionMethods:
    def _hex_tx(self) -> str:
        return (
            "01000000029e8d016a7b0dc49a325922d05da1f916d1e4d4f0cb840c9727f3d22ce8d1363f"
            "000000008c493046022100e9318720bee5425378b4763b0427158b1051eec8b08442ce3fbfbf"
            "7b30202a44022100d4172239ebd701dae2fbaaccd9f038e7ca166707333427e3fb2a2865b19a"
            "7f27014104510c67f46d2cbb29476d1f0b794be4cb549ea59ab9cc1e731969a7bf5be95f7ad"
            "5e7f904e5ccf50a9dc1714df00fbeb794aa27aaff33260c1032d931a75c56f2ffffffff"
            "a3195e7a1ab665473ff717814f6881485dc8759bebe97e31c301ffe7933a656f020000008b"
            "48304502201c282f35f3e02a1f32d2089265ad4b561f07ea3c288169dedcf2f785e6065efa"
            "022100e8db18aadacb382eed13ee04708f00ba0a9c40e3b21cf91da8859d0f7d99e0c50141"
            "042b409e1ebbb43875be5edde9c452c82c01e3903d38fa4fd89f3887a52cb8aea9dc8aec7e"
            "2c9d5b3609c03eb16259a2537135a1bf0f9c5fbbcbdbaf83ba402442ffffffff"
            "02206b1000000000001976a91420bb5c3bfaef0231dc05190e7f1c8e22e098991e88ac"
            "f0ca0100000000001976a9149e3e2d23973a04ec1b02be97c30ab9f2f27c3b2c88ac00000000"
        )

    def test_txid_is_hex_64_chars(self):
        tx = Transaction.from_hex(self._hex_tx())
        assert tx is not None
        assert len(tx.txid()) == 64

    def test_hash_is_32_bytes(self):
        tx = Transaction.from_hex(self._hex_tx())
        assert tx is not None
        assert len(tx.hash()) == 32

    def test_total_value_out(self):
        tx = Transaction.from_hex(self._hex_tx())
        assert tx is not None
        assert tx.total_value_out() == 1076000 + 117488

    def test_byte_length_matches_serialized(self):
        tx = Transaction.from_hex(self._hex_tx())
        assert tx is not None
        assert tx.byte_length() == len(tx.serialize())

    def test_is_coinbase_false_for_normal_tx(self):
        tx = Transaction.from_hex(self._hex_tx())
        assert tx is not None
        assert tx.is_coinbase() is False

    def test_is_coinbase_true_for_coinbase_input(self):
        locking = _make_locking()
        # is_coinbase() checks: len(inputs)==1 and inputs[0].source_txid == "00"*32
        coinbase_in = TransactionInput(
            source_txid="00" * 32,
            source_output_index=0,
            unlocking_script=Script("03" + "ab" * 3),
        )
        tx = Transaction(tx_inputs=[coinbase_in], tx_outputs=[TransactionOutput(locking_script=locking, satoshis=5000)])
        assert tx.is_coinbase() is True

    def test_from_hex_returns_none_on_garbage(self):
        result = Transaction.from_hex("deadbeef")
        assert result is None

    def test_add_inputs_multiple(self):
        tx_in1 = TransactionInput(source_txid="aa" * 32, source_output_index=0,
                                   unlocking_script=Script("00"))
        tx_in2 = TransactionInput(source_txid="bb" * 32, source_output_index=1,
                                   unlocking_script=Script("00"))
        tx = Transaction(tx_inputs=[], tx_outputs=[])
        tx.add_inputs([tx_in1, tx_in2])
        assert len(tx.inputs) == 2

    def test_add_outputs_multiple(self):
        locking = _make_locking()
        out1 = TransactionOutput(locking_script=locking, satoshis=1000)
        out2 = TransactionOutput(locking_script=locking, satoshis=2000)
        tx = Transaction(tx_inputs=[], tx_outputs=[])
        tx.add_outputs([out1, out2])
        assert len(tx.outputs) == 2
        assert tx.total_value_out() == 3000

    def test_preimage_out_of_range_raises(self):
        tx = Transaction.from_hex(self._hex_tx())
        assert tx is not None
        with pytest.raises(ValueError, match="out of range"):
            tx.preimage(99)

    def test_fee_change_distribution_equal(self):
        """Transaction.fee() with equal distribution sets change output amounts."""
        locking = _make_locking()
        src_out = TransactionOutput(locking_script=locking, satoshis=100_000)
        src_tx = Transaction(tx_inputs=[], tx_outputs=[src_out])
        tx_in = TransactionInput(
            source_transaction=src_tx,
            source_output_index=0,
            unlocking_script=_make_unlocking(),
        )
        spend_out = TransactionOutput(locking_script=locking, satoshis=50_000, change=False)
        change_out = TransactionOutput(locking_script=locking, satoshis=None, change=True)
        tx = Transaction(tx_inputs=[tx_in], tx_outputs=[spend_out, change_out])
        tx.fee(SatoshisPerKilobyte(500))
        assert change_out.satoshis is not None
        assert change_out.satoshis > 0

    def test_fee_random_distribution_raises_not_implemented(self):
        locking = _make_locking()
        src_out = TransactionOutput(locking_script=locking, satoshis=100_000)
        src_tx = Transaction(tx_inputs=[], tx_outputs=[src_out])
        tx_in = TransactionInput(
            source_transaction=src_tx,
            source_output_index=0,
            unlocking_script=_make_unlocking(),
        )
        tx = Transaction(tx_inputs=[tx_in], tx_outputs=[])
        with pytest.raises(NotImplementedError):
            tx.fee(change_distribution="random")

    def test_fee_no_source_transaction_raises(self):
        tx_in = TransactionInput(
            source_txid="ab" * 32,
            source_output_index=0,
            unlocking_script=Script("00"),
        )
        tx = Transaction(tx_inputs=[tx_in], tx_outputs=[])
        with pytest.raises(ValueError, match="Source transactions"):
            tx.fee(100)

    def test_serialize_round_trip(self):
        tx = Transaction.from_hex(self._hex_tx())
        assert tx is not None
        assert tx.serialize().hex() == self._hex_tx()

    def test_get_fee_requires_value_in_minus_out(self):
        """get_fee() = total_value_in - total_value_out."""
        locking = _make_locking()
        src_out = TransactionOutput(locking_script=locking, satoshis=10_000)
        src_tx = Transaction(tx_inputs=[], tx_outputs=[src_out])
        tx_in = TransactionInput(
            source_transaction=src_tx,
            source_output_index=0,
            unlocking_script=Script("00"),
        )
        tx_out = TransactionOutput(locking_script=locking, satoshis=9_500)
        tx = Transaction(tx_inputs=[tx_in], tx_outputs=[tx_out])
        assert tx.total_value_in() == 10_000
        assert tx.total_value_out() == 9_500
        assert tx.get_fee() == 500
