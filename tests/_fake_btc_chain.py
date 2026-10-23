"""A fake Bitcoin chain holding ONE Taproot HTLC funding outpoint, and sources that read it honestly or not.

For the #850 BTC disposition reader (``pyrxd.btc_wallet.disposition``) and, later, the coordinator's BTC
refund path. Design §7.1: "outpoint spends with script-path classification, mempool replacement by
BIP125 signalling, drop, depth per endpoint".

The HTLC is real: built by ``taproot.build_htlc`` from freshly generated keys, and every claim and
refund is a real signed transaction (``build_claim_tx`` / ``build_refund_tx``), so the classifier
reads real witnesses. The chain models only what spends the funding outpoint: blocks (height and a
hash that changes on a reorg), the mempool with BIP125 replacement (the original must signal, and the
replacement must pay a higher absolute fee by at least 1 sat/vB of its own size, Bitcoin Core's
default incremental relay fee), the refund's CSV maturity, a drop, and a reorg that returns or loses
the reorged transactions.

Sources read the chain with the misbehaviours the design names: lag (a head below the chain's), no
mempool view, down, a forged spender, a hidden spender, an over-reported depth, and a block that
disagrees. Each source is a distinct host (``tests._source_hosts``), so the production
``MultiSourceBtcFundingReader`` accepts them as a quorum.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field

import coincurve

from pyrxd.btc_wallet import taproot as t
from pyrxd.btc_wallet.keys import BtcKeypair, generate_keypair
from pyrxd.fee_sizing import bitcoin_virtual_size
from pyrxd.security.errors import InsufficientConfirmationsError, NetworkError
from tests._source_hosts import distinct_host

AMOUNT_SATS = 100_000
T_BTC_BLOCKS = 10
REFUND_SPK = b"\x00\x14" + b"\x33" * 20
CLAIM_SPK = b"\x00\x14" + b"\x44" * 20
#: Bitcoin Core's default incremental relay fee, 1 sat/vB (``DEFAULT_INCREMENTAL_RELAY_FEE``).
INCREMENTAL_SATS_PER_VB = 1


def _xonly(kp: BtcKeypair) -> bytes:
    return coincurve.PublicKeyXOnly.from_secret(kp._privkey.unsafe_raw_bytes()).format()


def _block_hash(height: int, fork: str) -> str:
    return hashlib.sha256(f"{fork}btc-block-{height}".encode()).hexdigest()


def _vsize(raw: bytes) -> int:
    """BIP141 vsize: the stripped form is the whole transaction less marker, flag and witness."""
    b = bytes(raw)
    witness = sum(len(t._serialize_witness(stack)) for stack in t._iter_witness_stack(b))
    return bitcoin_virtual_size(stripped_size=len(b) - 2 - witness, total_size=len(b))


@dataclass
class FakeBtcChain:
    """One chain: the HTLC funding transaction mined at ``funding_height``, the tip at ``head``."""

    head: int = 200
    funding_height: int = 150
    t_btc_blocks: int = T_BTC_BLOCKS
    fork: str = ""
    #: ``{txid: height}`` for every mined spender of the outpoint (at most one survives a reorg).
    mined: dict[str, int] = field(default_factory=dict)
    #: ``{txid: raw}`` for every spender ever seen, mined or not: what a source serves by txid.
    raws: dict[str, bytes] = field(default_factory=dict)
    #: The mempool's spender of the outpoint, if any (BIP125 allows one at a time).
    mempool: str | None = None

    def __post_init__(self) -> None:
        self.taker = generate_keypair("bcrt")
        self.maker = generate_keypair("bcrt")
        self.preimage = os.urandom(32)
        self.hashlock = hashlib.sha256(self.preimage).digest()
        self.timeout = t.Timelock(self.t_btc_blocks, t.TimeUnit.BLOCKS)
        self.htlc = t.build_htlc(
            hashlock=self.hashlock,
            claim_pubkey_xonly=_xonly(self.maker),
            refund_pubkey_xonly=_xonly(self.taker),
            timeout=self.timeout,
            network="bcrt",
        )
        self.funding_txid = os.urandom(32).hex()
        self.locator = self.htlc.with_funding(t.BtcOutpoint(txid=self.funding_txid, vout=0), AMOUNT_SATS)

    # -- the transactions

    def refund_tx(self, fee_sats: int = 500) -> bytes:
        return t.build_refund_tx(
            locator=self.locator,
            refund_privkey=self.taker._privkey.unsafe_raw_bytes(),
            timeout=self.timeout,
            to_scriptpubkey=REFUND_SPK,
            fee_sats=fee_sats,
            aux_rand=t.fresh_aux_rand(),
        )

    def claim_tx(self, fee_sats: int = 500) -> bytes:
        return t.build_claim_tx(
            locator=self.locator,
            preimage=self.preimage,
            claim_privkey=self.maker._privkey.unsafe_raw_bytes(),
            to_scriptpubkey=CLAIM_SPK,
            fee_sats=fee_sats,
            aux_rand=t.fresh_aux_rand(),
        )

    @staticmethod
    def fee_of(raw: bytes) -> int:
        return AMOUNT_SATS - sum(v for v, _spk in t.btc_spend_fields_from_raw(raw).outputs)

    # -- shape

    def funding_confirmations(self, at_head: int | None = None) -> int:
        head = self.head if at_head is None else at_head
        return max(0, head - self.funding_height + 1)

    def block_hash(self, height: int) -> str:
        # A reorg only rewrites blocks above the funding block, so every view agrees on old history.
        return _block_hash(height, self.fork if height > self.funding_height else "")

    def confirmed_spender(self, at_head: int | None = None) -> str | None:
        head = self.head if at_head is None else at_head
        for txid, height in self.mined.items():
            if height <= head:
                return txid
        return None

    # -- the network

    def submit(self, raw: bytes) -> str:
        """Accept *raw* into the mempool as a node would, or raise ``NetworkError`` with the reason."""
        raw = bytes(raw)
        txid = t.btc_txid_from_raw(raw)
        prevout = self.locator.funding_outpoint.prevout_bytes()
        fields = t.btc_spend_fields_from_raw(raw)
        if prevout not in fields.input_prevouts:
            raise NetworkError("bad-txns-inputs-missingorspent (the fake models only the HTLC outpoint)")
        if txid in self.mined or txid == self.mempool:
            raise NetworkError(
                "txn-already-in-mempool" if txid == self.mempool else "transaction already in block chain"
            )
        if self.confirmed_spender() is not None:
            raise NetworkError("bad-txns-inputs-missingorspent")
        sequence = fields.input_sequences[fields.input_prevouts.index(prevout)]
        if sequence == self.timeout.to_nsequence() and self.funding_confirmations() < self.t_btc_blocks:
            raise NetworkError("non-BIP68-final")
        if self.mempool is not None:
            old = self.raws[self.mempool]
            old_fields = t.btc_spend_fields_from_raw(old)
            if not any(q < 0xFFFFFFFE for q in old_fields.input_sequences):
                raise NetworkError("txn-mempool-conflict")
            if self.fee_of(raw) < self.fee_of(old) + INCREMENTAL_SATS_PER_VB * _vsize(raw):
                raise NetworkError("insufficient fee, rejecting replacement")
        self.raws[txid] = raw
        self.mempool = txid
        return txid

    def mine(self, blocks: int = 1) -> None:
        """Mine *blocks* blocks; the first takes the mempool's spender."""
        for i in range(blocks):
            self.head += 1
            if i == 0 and self.mempool is not None:
                self.mined[self.mempool] = self.head
                self.mempool = None

    def drop(self) -> None:
        """Evict the mempool's spender (expiry, a restart, a full mempool)."""
        self.mempool = None

    def reorg(self, depth: int, *, keep_txs: bool = True) -> None:
        """Replace the top *depth* blocks with as many empty ones on a new fork. A spender mined in
        them goes back to the mempool (*keep_txs*) or is lost."""
        cut = self.head - depth
        for txid, height in list(self.mined.items()):
            if height > cut:
                del self.mined[txid]
                self.mempool = txid if keep_txs and self.mempool is None else self.mempool
        self.fork += "r"


class FakeBtcSource:
    """One source's view of a :class:`FakeBtcChain`: the reader the BTC leg and the disposition
    reader consume. Honest unless told otherwise."""

    def __init__(
        self,
        chain: FakeBtcChain,
        *,
        lag: int = 0,
        sees_mempool: bool = True,
        down: bool = False,
        forge_spender: bytes | None = None,
        hide_spender: bool = False,
        lie_depth: int | None = None,
        lie_block: tuple[int, str] | None = None,
        spender_reads_fail: bool = False,
        no_spender_read: bool = False,
    ) -> None:
        self.chain = chain
        self.lag = lag
        self.sees_mempool = sees_mempool
        self.down = down
        self.forge_spender = forge_spender
        self.hide_spender = hide_spender
        self.lie_depth = lie_depth
        self.lie_block = lie_block
        self.spender_reads_fail = spender_reads_fail
        if no_spender_read:
            self.outpoint_spender = None  # type: ignore[assignment]
        self.source_key = distinct_host()
        self.broadcasts: list[bytes] = []

    @property
    def head(self) -> int:
        return self.chain.head - self.lag

    def _up(self) -> None:
        if self.down:
            raise NetworkError("connection refused")

    def _height_of(self, txid: str) -> int | None:
        if txid == self.chain.funding_txid:
            return self.chain.funding_height
        height = self.chain.mined.get(txid)
        return height if height is not None and height <= self.head else None

    async def outpoint_spender(self, txid: str, vout: int) -> bytes | None:
        self._up()
        if self.spender_reads_fail:
            raise NetworkError("outspend: 429 Too Many Requests")
        if (txid, vout) != (self.chain.funding_txid, 0):
            raise NetworkError("unknown outpoint")
        if self.forge_spender is not None:
            return self.forge_spender
        if self.hide_spender:
            return None
        spender = self.chain.confirmed_spender(self.head)
        if spender is None and self.sees_mempool:
            # Our mempool holds the chain's, and what this lagging view has not seen mined yet.
            later = [x for x, h in self.chain.mined.items() if h > self.head]
            spender = later[0] if later else self.chain.mempool
        return self.chain.raws[spender] if spender is not None else None

    async def confirmations(self, txid: str) -> int:
        self._up()
        if self.lie_depth is not None and txid != self.chain.funding_txid:
            return self.lie_depth
        height = self._height_of(txid)
        return 0 if height is None else self.head - height + 1

    async def tx_block(self, txid: str) -> tuple[int, str] | None:
        self._up()
        if self.lie_block is not None:
            return self.lie_block
        height = self._height_of(txid)
        return None if height is None else (height, self.chain.block_hash(height))

    async def broadcast(self, raw_tx: bytes) -> str:
        self._up()
        self.broadcasts.append(bytes(raw_tx))
        txid = t.btc_txid_from_raw(bytes(raw_tx))
        try:
            return self.chain.submit(raw_tx)
        except NetworkError as exc:
            if "already" in str(exc):
                return txid
            raise

    # The rest of the BtcFundingReader protocol, for a leg built on this source.

    async def read_output_amount_sats(self, txid: str, vout: int, *, min_confirmations: int) -> int:
        confs = await self.confirmations(txid)
        if confs < min_confirmations:
            raise InsufficientConfirmationsError(have=confs, required=min_confirmations)
        return AMOUNT_SATS

    async def txid_of(self, raw_tx: bytes) -> str:
        return t.btc_txid_from_raw(bytes(raw_tx))
