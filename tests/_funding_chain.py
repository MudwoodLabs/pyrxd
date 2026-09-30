"""Synthetic Radiant chains that the swap taker gate can PROVE a covenant funding against.

The taker gate (:mod:`pyrxd.gravity.funding_spv`) refuses anything it cannot verify: a raw funding
transaction that hashes to its txid, a merkle branch to a header, and that header linked to a
checkpoint through headers that each meet their own proof-of-work target. A fixture that hands it
anything less is refused — which is the point — so tests that need an HONEST funding need a real
little chain.

This builds one on top of Radiant REGTEST's real genesis header (reconstructed field by field from
``tests/vendor/radiant_core/chainparams.cpp``; its hash is asserted against the genesis pyrxd
declares), mined at regtest's own ``0x207fffff`` (about two hash attempts per header), or on top of
a caller-chosen checkpoint header at a caller-chosen difficulty for the value-bearing rule. Every
block holds a unique coinbase; the funding block also holds the funding transaction, whose output 0
pays the covenant scriptPubKey the caller names.

NOT A FICTION IN THE WAYS THAT MATTER: the gate runs its real code on these bytes. What IS chosen
by the fixture, and says so: timestamps. By default the newest header is stamped ``tip_time``
(an arbitrary far-future second unless given), which makes the gate's clock allowance for withheld
blocks zero for any test clock — tests of that allowance pass ``tip_time`` explicitly.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass

from pyrxd.constants import GENESIS_BLOCK_HASHES
from pyrxd.gravity.funding_spv import MakerFundingEvidence
from pyrxd.hash import radiant_block_hash

REGTEST_BITS = 0x207FFFFF
#: Far enough ahead that ``now - tip_time`` is negative for any clock a test passes.
FAR_FUTURE = 4_000_000_000


def _d256(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def _header(prev_hash_display: str, merkle_root_le: bytes, t: int, bits: int, nonce: int) -> bytes:
    return (
        struct.pack("<I", 1)
        + bytes.fromhex(prev_hash_display)[::-1]
        + merkle_root_le
        + struct.pack("<III", t, bits, nonce)
    )


def _target(bits: int) -> int:
    exp, mant = bits >> 24, bits & 0x007FFFFF
    return mant >> (8 * (3 - exp)) if exp <= 3 else mant << (8 * (exp - 3))


def mine(prev_hash_display: str, merkle_root_le: bytes, t: int, bits: int) -> bytes:
    target = _target(bits)
    nonce = 0
    while True:
        hdr = _header(prev_hash_display, merkle_root_le, t, bits, nonce)
        if int(radiant_block_hash(hdr), 16) <= target:
            return hdr
        nonce += 1


def regtest_genesis_header() -> bytes:
    """Radiant regtest block 0: ``CreateGenesisBlockTestnet(1657071137, 1, 0x207fffff, 1, …)``."""
    root = bytes.fromhex("364459380841db3f0ea491e8099bf98a6b7ffc5693d8ee6e46b3f8183e0257dc")[::-1]
    hdr = _header("00" * 32, root, 1657071137, REGTEST_BITS, 1)
    assert radiant_block_hash(hdr) == GENESIS_BLOCK_HASHES["regtest"]
    return hdr


def _tx(tag: bytes, outputs: list[tuple[int, bytes]]) -> bytes:
    """A syntactically real transaction: one input spending a made-up outpoint, *outputs*."""
    script_sig = bytes([len(tag)]) + tag
    body = struct.pack("<I", 1) + b"\x01" + hashlib.sha256(tag).digest() + struct.pack("<I", 0)
    body += bytes([len(script_sig)]) + script_sig + b"\xff\xff\xff\xff"
    body += bytes([len(outputs)])
    for value, spk in outputs:
        body += struct.pack("<Q", value) + bytes([len(spk)]) + spk
    return body + struct.pack("<I", 0)


def _txid(raw: bytes) -> str:
    return _d256(raw)[::-1].hex()


@dataclass
class FundingChain:
    headers: dict[int, bytes]
    txid: str
    raw_tx: bytes
    height: int
    merkle: dict
    coinbase_merkle: dict

    @property
    def top(self) -> int:
        return max(self.headers)

    def evidence(self, *, reported_confirmations: int | None = None, drop_above: int | None = None, **over):
        headers = dict(self.headers)
        if drop_above is not None:
            headers = {h: b for h, b in headers.items() if h <= drop_above}
        kw = dict(
            txid=self.txid,
            vout=0,
            height=self.height,
            raw_tx=self.raw_tx,
            merkle=dict(self.merkle),
            coinbase_merkle=dict(self.coinbase_merkle),
            headers=headers,
            reported_confirmations=reported_confirmations,
        )
        kw.update(over)
        return MakerFundingEvidence(**kw)


def build_funding_chain(
    *,
    spk: bytes,
    value: int,
    confs: int,
    base: dict[int, bytes] | None = None,
    funding_height: int | None = None,
    bits: int = REGTEST_BITS,
    tip_time: int = FAR_FUTURE,
    spacing_s: int = 300,
) -> FundingChain:
    """A chain on *base* (default: regtest genesis) whose block at *funding_height* holds a funding
    tx paying ``(value, spk)`` at output 0, buried *confs* deep (the funding block counts as 1)."""
    headers = dict(base) if base is not None else {0: regtest_genesis_header()}
    start = max(headers) + 1
    height = funding_height if funding_height is not None else start
    assert height >= start
    top = height + confs - 1
    funding = _tx(b"fund" + height.to_bytes(4, "little"), [(value, bytes(spk))])
    fund_txid = _txid(funding)
    first_t = tip_time - spacing_s * (top - start)
    cb_txid_at_h = ""
    for h in range(start, top + 1):
        cb = _tx(b"cb" + h.to_bytes(4, "little"), [(5_000_000_000, b"\x51")])
        cb_txid = _txid(cb)
        if h == height:
            cb_txid_at_h = cb_txid
            root = _d256(bytes.fromhex(cb_txid)[::-1] + bytes.fromhex(fund_txid)[::-1])
        else:
            root = bytes.fromhex(cb_txid)[::-1]
        prev = radiant_block_hash(headers[h - 1])
        headers[h] = mine(prev, root, first_t + spacing_s * (h - start), bits)
    return FundingChain(
        headers=headers,
        txid=fund_txid,
        raw_tx=funding,
        height=height,
        merkle={"block_height": height, "merkle": [cb_txid_at_h], "pos": 1},
        coinbase_merkle={"tx_hash": cb_txid_at_h, "merkle": [fund_txid]},
    )


def merkle_branch(txids_display: list[str], pos: int) -> list[str]:
    """ElectrumX's ``blockchain.transaction.get_merkle`` branch for *pos*, from a block's txids.

    Bitcoin's (and Radiant's) tree: SHA-256d over internal-order txids, the last hash of an
    odd-width level paired with itself; siblings returned in display hex, leaf level first.
    """
    level = [bytes.fromhex(t)[::-1] for t in txids_display]
    branch: list[str] = []
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        branch.append(level[pos ^ 1][::-1].hex())
        level = [_d256(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
        pos //= 2
    return branch


class NodeSpvReads:
    """The four ElectrumX reads the taker gate asks for, answered by a regtest node's own RPC.

    Mixed into the e2e suites' radiant-cli clients, which drive a real ``radiantd -regtest`` through
    ``self.rpc(method, *args)``. Every answer is the NODE's: the raw transaction, the block's own
    txid list (the branch is folded from it exactly as ElectrumX does), and the node's own headers.
    The coordinator then proves the funding against regtest's genesis with the production verifier.
    Headers are cached by height: these suites never reorganise the chain.
    """

    def rpc(self, method: str, *args):  # pragma: no cover - supplied by the client it is mixed into
        raise NotImplementedError

    async def get_transaction(self, txid) -> bytes:
        return bytes.fromhex(str(self.rpc("getrawtransaction", str(txid))))

    def _block_txids(self, height: int) -> list[str]:
        block = self.rpc("getblock", str(self.rpc("getblockhash", str(int(height)))), "1")
        return [str(t) for t in block["tx"]]

    async def get_transaction_merkle_branch(self, txid, height) -> dict:
        txids = self._block_txids(int(height))
        pos = txids.index(str(txid))
        return {"block_height": int(height), "merkle": merkle_branch(txids, pos), "pos": pos}

    async def get_transaction_id_from_pos(self, height, pos) -> dict:
        txids = self._block_txids(int(height))
        return {"tx_hash": txids[int(pos)], "merkle": merkle_branch(txids, int(pos))}

    async def get_block_headers(self, start, count) -> list[bytes]:
        cache = self.__dict__.setdefault("_header_cache", {})
        tip = int(self.rpc("getblockcount"))
        out = []
        for h in range(int(start), min(int(start) + int(count) - 1, tip) + 1):
            if h not in cache:
                cache[h] = bytes.fromhex(
                    str(self.rpc("getblockheader", str(self.rpc("getblockhash", str(h))), "false"))
                )
            out.append(cache[h])
        return out
