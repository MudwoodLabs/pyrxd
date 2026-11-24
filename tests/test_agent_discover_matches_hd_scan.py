"""The watch-only scan behind ``pyrxd wallet send`` (signing-agent path) must see what
:meth:`HdWallet.refresh` sees.

``collect_watch_only_utxos`` (``src/pyrxd/agent/discover.py``) is a second, key-free spelling of
the gap-limit scan in :meth:`HdWallet._scan_chain`. The HD scan learned two rules that the
watch-only one did not:

* An address that has only received a Glyph token has no P2PKH history; a Radiant ElectrumX
  lists the token under the token script's zeroed-ref hash (#787). The HD scan counts such an
  address as used; the watch-only one counted it toward the unused gap, so 20 token-only
  addresses in a row ended its scan and hid the plain RXD beyond them, and a token-only change
  address could be handed out again as change.
* A server that reports history at every address must not keep the scan deriving forever
  (#869, ``_MAX_SCAN_ADDRESSES_PER_CHAIN``).
"""

from __future__ import annotations

import asyncio

import pytest

import pyrxd.hd.wallet as hd_wallet_mod
from pyrxd.agent import collect_watch_only_utxos
from pyrxd.glyph.scanner import owned_token_script_hashes
from pyrxd.hd.bip32 import Xpub
from pyrxd.hd.wallet import _GAP_LIMIT, HdWallet
from pyrxd.network.electrumx import UtxoRecord, script_hash_for_address
from pyrxd.script.type import P2PKH
from pyrxd.security.errors import NetworkError
from pyrxd.security.types import Hex20
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_output import TransactionOutput
from pyrxd.utils import address_to_public_key_hash

MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"


def _token_hash(address: str) -> str:
    hashes = owned_token_script_hashes(Hex20(address_to_public_key_hash(address)))
    assert hashes, "owned_token_script_hashes must name at least one token shape"
    return hashes[0]


class _Chain:
    """Fake ElectrumX keyed by script hash: plain UTXOs at some addresses, token history at others."""

    def __init__(self, plain: dict[str, int], token_only: list[str]) -> None:
        self.src: dict[str, Transaction] = {}
        self.plain_by_sh: dict[str, tuple[str, int]] = {}
        for addr, value in plain.items():
            tx = Transaction()
            tx.add_output(TransactionOutput(P2PKH().lock(addr), value))
            self.src[tx.txid()] = tx
            self.plain_by_sh[script_hash_for_address(addr)] = (tx.txid(), value)
        self.token_sh = {_token_hash(a) for a in token_only}

    async def get_history(self, sh):
        if sh in self.plain_by_sh or sh in self.token_sh:
            return [{"tx_hash": "ab" * 32, "height": 800_000}]
        return []

    async def get_utxos(self, sh):
        if sh not in self.plain_by_sh:
            return []
        txid, value = self.plain_by_sh[sh]
        return [UtxoRecord(tx_hash=txid, tx_pos=0, value=value, height=800_000)]

    async def get_transaction(self, txid):
        return self.src[str(txid)].serialize()


def _wallet_and_xpub() -> tuple[HdWallet, Xpub]:
    w = HdWallet.from_mnemonic(MNEMONIC)
    return w, Xpub.from_xprv(w._xprv)


def test_plain_funds_beyond_a_run_of_token_only_addresses_are_found() -> None:
    w, xpub = _wallet_and_xpub()
    token_only = [w._derive_address(0, i) for i in range(_GAP_LIMIT)]
    funded = w._derive_address(0, _GAP_LIMIT)
    chain = _Chain({funded: 50_000_000}, token_only)

    # The HD scan (what `pyrxd wallet send` uses with no agent) finds it ...
    hd = asyncio.run(w.collect_spendable(chain))
    assert [(a, u.value) for u, a, _k in hd] == [(funded, 50_000_000)]
    # ... and so must the watch-only scan the agent path uses.
    scan = asyncio.run(collect_watch_only_utxos(xpub, chain))
    assert [(u.change, u.index, u.value) for u in scan.utxos] == [(0, _GAP_LIMIT, 50_000_000)]


def test_token_only_change_address_is_not_handed_out_as_change() -> None:
    w, xpub = _wallet_and_xpub()
    # Internal 0 holds plain change; internal 1 holds only a token.
    chain = _Chain({w._derive_address(1, 0): 10_000_000}, [w._derive_address(1, 1)])

    asyncio.run(w.refresh(chain))
    assert w._next_change_index() == 2
    scan = asyncio.run(collect_watch_only_utxos(xpub, chain))
    assert scan.next_change_index == 2


def test_honest_path_plain_only_wallet_is_unchanged() -> None:
    w, xpub = _wallet_and_xpub()
    chain = _Chain({w._derive_address(0, 0): 7_000_000, w._derive_address(1, 0): 3_000_000}, [])
    scan = asyncio.run(collect_watch_only_utxos(xpub, chain))
    assert sorted((u.change, u.index, u.value) for u in scan.utxos) == [(0, 0, 7_000_000), (1, 0, 3_000_000)]
    assert scan.next_change_index == 1


class _HistoryEverywhere:
    def __init__(self) -> None:
        self.history_reads = 0

    async def get_history(self, sh):
        self.history_reads += 1
        await asyncio.sleep(0)  # yield, so wait_for can stop an unbounded scan instead of hanging
        return [{"tx_hash": "ab" * 32, "height": 800_000}]

    async def get_utxos(self, sh):
        return []

    async def get_transaction(self, txid):  # pragma: no cover - never reached: no UTXOs
        raise AssertionError("no UTXOs, so no source tx is fetched")


def test_scan_is_bounded_when_a_server_reports_history_everywhere(monkeypatch: pytest.MonkeyPatch) -> None:
    # Shrink the HD scan's cap so the test is fast; the watch-only scan must honour the same one.
    monkeypatch.setattr(hd_wallet_mod, "_MAX_SCAN_ADDRESSES_PER_CHAIN", 50)
    _w, xpub = _wallet_and_xpub()
    client = _HistoryEverywhere()

    async def _run() -> None:
        await asyncio.wait_for(collect_watch_only_utxos(xpub, client), timeout=10)

    with pytest.raises(NetworkError, match="refusing to keep deriving"):
        asyncio.run(_run())
    assert client.history_reads <= 51
