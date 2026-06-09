"""Tests for the async swap resolver helpers (pyrxd.swap.resolve)."""

from __future__ import annotations

import asyncio

import pytest

from pyrxd.keys import PrivateKey
from pyrxd.script.type import P2PKH
from pyrxd.security.errors import ValidationError
from pyrxd.swap.resolve import fetch_funding_input, fetch_transaction
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_output import TransactionOutput


def _utxo_tx(value: int = 1000) -> Transaction:
    tx = Transaction()
    tx.add_output(TransactionOutput(P2PKH().lock(PrivateKey().public_key().hash160()), value))
    return tx


class _FakeClient:
    """Minimal stand-in for ElectrumXClient.get_transaction."""

    def __init__(self, raw_by_txid: dict[str, bytes]):
        self._raw = raw_by_txid

    async def get_transaction(self, txid):
        return self._raw[str(txid)]


def test_fetch_transaction_returns_parsed_tx() -> None:
    tx = _utxo_tx()
    client = _FakeClient({tx.txid(): tx.serialize()})
    got = asyncio.run(fetch_transaction(client, tx.txid()))
    assert got.txid() == tx.txid()


def test_fetch_transaction_rejects_hash_mismatch() -> None:
    real = _utxo_tx(1000)
    other = _utxo_tx(2000)
    # Server returns `other` bytes when `real`'s txid is requested.
    client = _FakeClient({real.txid(): other.serialize()})
    with pytest.raises(ValidationError, match="hash"):
        asyncio.run(fetch_transaction(client, real.txid()))


def test_fetch_funding_input_builds_funding() -> None:
    key = PrivateKey()
    tx = Transaction()
    tx.add_output(TransactionOutput(P2PKH().lock(key.public_key().hash160()), 1234))
    client = _FakeClient({tx.txid(): tx.serialize()})
    fi = asyncio.run(fetch_funding_input(client, txid=tx.txid(), vout=0, key=key))
    assert fi.vout == 0
    assert fi.source_tx.outputs[0].satoshis == 1234


def test_fetch_funding_input_rejects_bad_vout() -> None:
    tx = _utxo_tx()
    client = _FakeClient({tx.txid(): tx.serialize()})
    with pytest.raises(ValidationError, match="out of range"):
        asyncio.run(fetch_funding_input(client, txid=tx.txid(), vout=5, key=PrivateKey()))
