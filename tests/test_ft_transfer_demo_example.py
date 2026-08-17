"""``examples/ft_transfer_demo.py`` — the wallet adapter it teaches must actually work.

The example was rewritten to call :class:`~pyrxd.glyph.client.GlyphClient` instead of
re-implementing the transfer path. That swap only holds if its ``SingleKeyWallet``
really satisfies what :mod:`pyrxd.glyph.transfer` asks of a wallet — and an example
that does not run is worse than a long one that does, because a reader assumes it was
tried.

So this drives the example's own adapter through the real library path against a
scripted client. If the transfer path ever needs a third method from a wallet, this
fails and the example gets fixed with it.
"""

from __future__ import annotations

import importlib
import os
import sys
from unittest.mock import AsyncMock, MagicMock

import pytest

from pyrxd.glyph.script import build_ft_locking_script
from pyrxd.glyph.types import GlyphRef
from pyrxd.keys import PrivateKey
from pyrxd.network.electrumx import UtxoRecord
from pyrxd.script.script import Script
from pyrxd.script.type import P2PKH
from pyrxd.security.types import Hex20
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_output import TransactionOutput

FEE_RATE = 10_000  # Radiant's relay floor
HOLDING = 50_000_000
AMOUNT = 250


def _import_demo():
    """Import the example by path, the way the dMint demo test does."""
    demo_dir = os.path.join(os.path.dirname(__file__), "..", "examples")
    sys.path.insert(0, demo_dir)
    try:
        return importlib.import_module("ft_transfer_demo")
    finally:
        sys.path.pop(0)


def _src(vout: int, spk: bytes, value: int) -> bytes:
    outs = [TransactionOutput(Script(b""), 0) for _ in range(vout)]
    outs.append(TransactionOutput(Script(spk), value))
    return Transaction(tx_inputs=[], tx_outputs=outs).serialize()


@pytest.fixture
def scripted():
    """A key holding one FT UTXO of the target token plus one plain-RXD UTXO."""
    key = PrivateKey()
    pkh = Hex20(key.public_key().hash160())
    ref = GlyphRef(txid="aa" * 32, vout=0)

    ft_script = build_ft_locking_script(pkh, ref)
    rxd_spk = P2PKH().lock(key.address()).serialize()
    ft_utxo = UtxoRecord(tx_hash="bb" * 32, tx_pos=0, value=HOLDING, height=100)
    rxd_utxo = UtxoRecord(tx_hash="cc" * 32, tx_pos=0, value=500_000_000, height=100)

    txmap = {"bb" * 32: _src(0, ft_script, HOLDING), "cc" * 32: _src(0, rxd_spk, 500_000_000)}

    client = MagicMock()
    client.get_utxos = AsyncMock(return_value=[ft_utxo, rxd_utxo])
    client.get_transaction = AsyncMock(side_effect=lambda t: txmap[str(t)])
    client.broadcast = AsyncMock(return_value="ff" * 32)
    return client, key, ref


class TestTheAdapterSatisfiesTheTransferPath:
    @pytest.mark.asyncio
    async def test_collect_spendable_returns_triples(self, scripted) -> None:
        client, key, _ref = scripted
        demo = _import_demo()
        wallet = demo.SingleKeyWallet(key)

        triples = await wallet.collect_spendable(client)
        assert len(triples) == 2
        for utxo, address, signing_key in triples:
            assert address == key.public_key().address()
            assert signing_key is key
            assert hasattr(utxo, "tx_hash")

    def test_addresses_exposes_a_used_record(self, scripted) -> None:
        """``select_ft_inputs`` scans ``[r for r in wallet.addresses.values() if r.used]``."""
        _client, key, _ref = scripted
        demo = _import_demo()
        wallet = demo.SingleKeyWallet(key)

        records = [r for r in wallet.addresses.values() if r.used]
        assert len(records) == 1
        assert records[0].address == key.public_key().address()

    @pytest.mark.asyncio
    async def test_a_transfer_builds_end_to_end_through_glyphclient(self, scripted) -> None:
        """The claim the rewrite rests on: the example's wallet drives the real path.

        This used to stub a ``GlyphScanner``, because ``select_ft_inputs`` ran a scan
        over every used address before selecting inputs. That scan was removed — its
        result was discarded after an emptiness check the classification loop already
        answers — so there is nothing left to stub and the whole path below is real
        code: input selection against the on-chain locking scripts, fee funding, and
        the build.
        """
        client, key, ref = scripted
        demo = _import_demo()

        glyph = demo.GlyphClient(client, demo.SingleKeyWallet(key), fee_rate=FEE_RATE)
        build = await glyph.build_ft_transfer(ref, AMOUNT, Hex20(PrivateKey().public_key().hash160()))

        # The check the example itself makes before broadcasting: on Radiant the
        # recipient output's photon value IS the unit count.
        assert build.tx.outputs[0].satoshis == AMOUNT
        assert build.fee > 0
        assert isinstance(build.serialize(), bytes)
