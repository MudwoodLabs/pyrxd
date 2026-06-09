"""Tests for watch-only UTXO discovery from an account xpub (issue #8 A')."""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock

import pytest

from pyrxd.agent import WatchOnlyTxBuilder, collect_watch_only_utxos
from pyrxd.agent.signer import AgentSigner
from pyrxd.hash import hash256
from pyrxd.hd.bip32 import Xpub
from pyrxd.hd.wallet import HdWallet
from pyrxd.keys import PrivateKey
from pyrxd.network.electrumx import UtxoRecord, script_hash_for_address
from pyrxd.script.type import P2PKH
from pyrxd.security.errors import ValidationError
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_output import TransactionOutput

MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"


def _wallet() -> HdWallet:
    return HdWallet.from_mnemonic(MNEMONIC)


def _src_for(addr: str, value: int) -> Transaction:
    tx = Transaction()
    tx.add_output(TransactionOutput(P2PKH().lock(addr), value))
    return tx


def _client_with_funds_at(funded: dict[str, Transaction], *, value: int = 100_000_000) -> MagicMock:
    """Mock ElectrumX: each address in *funded* has history + one UTXO from the given source tx."""
    by_sh = {script_hash_for_address(a): (a, src) for a, src in funded.items()}
    by_txid = {src.txid(): src for src in funded.values()}

    async def _history(sh):
        return [{"tx_hash": "ab" * 32}] if sh in by_sh else []

    async def _utxos(sh):
        if sh not in by_sh:
            return []
        _addr, src = by_sh[sh]
        return [UtxoRecord(tx_hash=src.txid(), tx_pos=0, value=value, height=800_000)]

    async def _get_tx(txid):
        return by_txid[str(txid)].serialize()

    client = MagicMock()
    client.get_history = _history
    client.get_utxos = _utxos
    client.get_transaction = _get_tx
    return client


def test_collect_finds_utxo_with_coords_and_source_tx() -> None:
    w = _wallet()
    xpub = Xpub.from_xprv(w._xprv)
    addr = w._derive_address(0, 0)
    client = _client_with_funds_at({addr: _src_for(addr, 100_000_000)})

    scan = asyncio.run(collect_watch_only_utxos(xpub, client, gap_limit=3))

    assert len(scan.utxos) == 1
    u = scan.utxos[0]
    assert (u.change, u.index) == (0, 0)
    assert u.value == 100_000_000
    # The source tx hashes to the UTXO outpoint (the agent's C1 check will pass).
    assert hash256(bytes.fromhex(u.source_tx_hex))[::-1].hex() == u.txid


def test_collect_reports_next_change_index() -> None:
    w = _wallet()
    xpub = Xpub.from_xprv(w._xprv)
    # Fund external (0,0) and internal (1,0) → next change index should be 1.
    funded = {
        w._derive_address(0, 0): _src_for(w._derive_address(0, 0), 50_000_000),
        w._derive_address(1, 0): _src_for(w._derive_address(1, 0), 25_000_000),
    }
    scan = asyncio.run(collect_watch_only_utxos(xpub, _client_with_funds_at(funded), gap_limit=3))
    assert {(u.change, u.index) for u in scan.utxos} == {(0, 0), (1, 0)}
    assert scan.next_change_index == 1


def test_collected_utxos_are_signable_by_agent() -> None:
    """End-to-end: discovery → build_send → agent signs (ownership + C1 all derived consistently)."""
    w = _wallet()
    xpub = Xpub.from_xprv(w._xprv)
    addr = w._derive_address(0, 0)
    client = _client_with_funds_at({addr: _src_for(addr, 100_000_000)})
    scan = asyncio.run(collect_watch_only_utxos(xpub, client, gap_limit=3))

    built = WatchOnlyTxBuilder(xpub).build_send(
        scan.utxos, PrivateKey().public_key().address(), photons=10_000_000, change_index=scan.next_change_index
    )
    result = AgentSigner(w).sign(built.request, confirm=lambda _s: True)
    assert Transaction.from_hex(bytes.fromhex(result.signed_tx_hex)) is not None


def test_rejects_non_xpub() -> None:
    with pytest.raises(ValidationError, match="Xpub"):
        asyncio.run(collect_watch_only_utxos("nope", MagicMock()))  # type: ignore[arg-type]
