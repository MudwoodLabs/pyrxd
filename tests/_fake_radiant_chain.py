"""A fake Radiant chain, served by ElectrumX-shaped sources, for the covenant spend read (#850 PR 11).

The chain holds REAL transaction bytes: the covenant funding is a parsed transaction paying the
covenant script, and spends are whatever the test broadcasts (built by the production
``build_htlc_refund_tx`` / ``build_htlc_claim_tx`` through the real ``RadiantCovenantLeg``). A
source answers ``get_history`` / ``get_transaction`` / ``get_transaction_verbose`` / ``get_utxos`` /
``broadcast`` from the chain, through one of the misbehaviours a test asks for. Each source carries
a ``source_key`` derived from its own URL, so operators are counted the way production counts them.
"""

from __future__ import annotations

import hashlib
import os

from pyrxd.hash import hash256
from pyrxd.network.electrumx import UtxoRecord
from pyrxd.network.source_identity import source_key
from pyrxd.script.script import Script
from pyrxd.security.errors import NetworkError
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_input import TransactionInput
from pyrxd.transaction.transaction_output import TransactionOutput


def _txid(raw: bytes) -> str:
    return hash256(raw)[::-1].hex()


def payment(spk: bytes, value: int) -> bytes:
    """A transaction paying *value* to *spk*, from a random outpoint (the input is not checked)."""
    tx = Transaction(
        tx_inputs=[
            TransactionInput(source_txid=os.urandom(32).hex(), source_output_index=0, unlocking_script=Script(b""))
        ],
        tx_outputs=[TransactionOutput(Script(bytes(spk)), int(value))],
    )
    return tx.serialize()


class FakeRadiantChain:
    """Transactions by txid, each mined at a height or in the mempool (height 0)."""

    def __init__(self, *, tip: int = 1_000) -> None:
        self.tip = tip
        self.txs: dict[str, tuple[bytes, int]] = {}

    def add(self, raw: bytes, *, height: int = 0) -> str:
        txid = _txid(bytes(raw))
        self.txs[txid] = (bytes(raw), height)
        return txid

    def mine(self, blocks: int = 1) -> None:
        """Mine *blocks* blocks; the mempool goes into the first."""
        self.tip += blocks
        for txid, (raw, height) in list(self.txs.items()):
            if height == 0:
                self.txs[txid] = (raw, self.tip - blocks + 1)

    def confirmations(self, txid: str) -> int:
        height = self.txs[txid][1]
        return 0 if height == 0 else self.tip - height + 1

    def _parsed(self):
        return {txid: Transaction.from_hex(raw) for txid, (raw, _h) in self.txs.items()}

    def _spent(self, parsed) -> set[str]:
        return {f"{i.source_txid}:{i.source_output_index}" for tx in parsed.values() for i in tx.inputs}

    def history(self, spk: bytes) -> list[str]:
        """Every transaction that pays *spk* or spends an output that pays it."""
        parsed = self._parsed()
        paying = {
            f"{txid}:{n}"
            for txid, tx in parsed.items()
            for n, out in enumerate(tx.outputs)
            if out.locking_script.serialize() == bytes(spk)
        }
        out = []
        for txid, tx in parsed.items():
            pays = any(o.locking_script.serialize() == bytes(spk) for o in tx.outputs)
            spends = any(f"{i.source_txid}:{i.source_output_index}" in paying for i in tx.inputs)
            if pays or spends:
                out.append(txid)
        return out

    def utxos(self, spk: bytes) -> list[UtxoRecord]:
        parsed = self._parsed()
        spent = self._spent(parsed)
        return [
            UtxoRecord(tx_hash=txid, tx_pos=n, value=int(out.satoshis), height=self.txs[txid][1])
            for txid, tx in parsed.items()
            for n, out in enumerate(tx.outputs)
            if out.locking_script.serialize() == bytes(spk) and f"{txid}:{n}" not in spent
        ]


class FakeRadiantSource:
    """One source's view of a :class:`FakeRadiantChain`.

    * ``hide``: txids this source leaves out of every answer (it withholds them);
    * ``extra``: raw transactions only this source serves, as mined at the chain tip (a decoy);
    * ``depth_bonus``: added to every confirmation count it reports;
    * ``down``: every read raises.
    """

    def __init__(self, chain: FakeRadiantChain, url: str, *, hide=(), extra=(), depth_bonus: int = 0, down=False):
        self.chain = chain
        self.source_key = source_key(url)
        self.source_keys = (self.source_key,)
        self.hide = set(hide)
        self.extra = {_txid(bytes(r)): bytes(r) for r in extra}
        self.depth_bonus = depth_bonus
        self.down = down
        self.broadcasts: list[bytes] = []
        self.history_reads = 0

    def _view(self) -> FakeRadiantChain:
        view = FakeRadiantChain(tip=self.chain.tip)
        view.txs = {t: v for t, v in self.chain.txs.items() if t not in self.hide}
        for txid, raw in self.extra.items():
            view.txs[txid] = (raw, self.chain.tip)
        return view

    def _check(self) -> None:
        if self.down:
            raise NetworkError("source down")

    async def broadcast(self, raw: bytes) -> str:
        self._check()
        self.broadcasts.append(bytes(raw))
        return self.chain.add(raw)

    async def get_history(self, script_hash: bytes):
        self._check()
        self.history_reads += 1
        view = self._view()
        spks = {
            o.locking_script.serialize()
            for tx in view._parsed().values()
            for o in tx.outputs
            if hashlib.sha256(o.locking_script.serialize()).digest()[::-1] == bytes(script_hash)
        }
        out: list[dict] = []
        for spk in spks:
            out.extend({"tx_hash": t, "height": view.txs[t][1]} for t in view.history(spk))
        return out

    async def get_transaction(self, txid: str) -> bytes:
        self._check()
        view = self._view()
        if txid not in view.txs:
            raise NetworkError(f"unknown tx {txid}")
        return view.txs[txid][0]

    async def get_transaction_verbose(self, txid: str) -> dict:
        self._check()
        view = self._view()
        if txid not in view.txs:
            raise NetworkError(f"unknown tx {txid}")
        return {"txid": txid, "confirmations": view.confirmations(txid) + self.depth_bonus}

    async def get_utxos(self, script_hash: bytes):
        self._check()
        view = self._view()
        found = []
        for tx in view._parsed().values():
            for o in tx.outputs:
                spk = o.locking_script.serialize()
                if hashlib.sha256(spk).digest()[::-1] == bytes(script_hash):
                    found = view.utxos(spk)
                    break
            if found:
                break
        return found
