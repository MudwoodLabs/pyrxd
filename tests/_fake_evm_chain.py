"""A fake EVM chain holding ONE ``EthHtlc`` contract, and endpoints that read it honestly or not.

For the #850 disposition reader (``pyrxd.eth_wallet.disposition``). The chain models what the
reader consumes: blocks (number, hash, timestamp), the contract's ``settled`` slot as of each block,
receipts with their logs, and a ``finalized`` height. It enforces the contract's own rules when an
honest transaction is added (claim only before the timeout, refund only at or after it, once), so a
test that wants an impossible chain says so by calling :meth:`FakeEvmChain.force_receipt`.

Endpoints read the chain with the misbehaviours the design names (§2.6, §7): lag, a forged
``Refunded`` log, a hidden ``Claimed`` log, a forged receipt, a 429 on every log read, a block-range
cap, and no historic state. A log range past the endpoint's head is refused, as anvil refuses it. Each endpoint is a distinct host (``tests._source_hosts``), so the
production ``MultiSourceEthRpc`` accepts them as a quorum.
"""

from __future__ import annotations

import dataclasses
import hashlib
from dataclasses import dataclass, field
from typing import Any

from pyrxd.eth_wallet.events import CLAIMED_TOPIC0, REFUNDED_TOPIC0
from pyrxd.eth_wallet.htlc_leg import create_address
from pyrxd.eth_wallet.locator import Erc20HtlcLocator, EthHtlcLocator
from pyrxd.security.errors import NetworkError
from tests._source_hosts import distinct_host

GENESIS_TS = 1_800_000_000
BLOCK_SECONDS = 12
CHAIN_ID = 11155111
#: The key that deployed the contract: its CREATE address at nonce 0 is :data:`CONTRACT`, so the
#: reader's derivation check on the deploy transaction passes on an honest chain.
DEPLOYER = "0x" + "de" * 20
DEPLOY_NONCE = 0
CONTRACT = create_address(DEPLOYER, DEPLOY_NONCE).lower()
OTHER_CONTRACT = "0x" + "0d" * 20
TOKEN = "0x" + "70" * 20
FUNDER = "0x" + "bb" * 20


def _block_hash(number: int, fork: str = "") -> bytes:
    return hashlib.sha256(f"{fork}block-{number}".encode()).digest()


def _tx_hash(label: str) -> str:
    return "0x" + hashlib.sha256(label.encode()).hexdigest()


@dataclass
class FakeEvmChain:
    """One chain: blocks ``0..head``, the contract deployed at ``deploy_block``."""

    preimage: bytes
    timeout: int
    head: int = 100
    finalized: int = 64
    deploy_block: int = 10
    settled_at: int | None = None
    receipts: dict[str, dict[str, Any]] = field(default_factory=dict)
    #: #850 PR 7a, a token contract: ``{block: balance from that block on}`` (0 before the first),
    #: and the funding key's ``{block: transaction count from that block on}``.
    token_balances: dict[int, int] = field(default_factory=dict)
    nonces: dict[int, int] = field(default_factory=dict)
    #: The funding key's transactions in the mempool: its ``pending`` count is its count at the tip
    #: plus this.
    pending_txs: int = 0

    def __post_init__(self) -> None:
        self.hashlock = hashlib.sha256(self.preimage).digest()
        self.deploy_tx = _tx_hash("deploy")
        self.receipts[self.deploy_tx] = self._receipt(self.deploy_block, logs=[], status=1)
        #: The deploy transaction's sender and nonce. A test that names a different transaction as
        #: the deploy (one that did not create :data:`CONTRACT`) changes these.
        self.deploy_from = DEPLOYER
        self.deploy_nonce = DEPLOY_NONCE

    # -- shape

    def ts(self, number: int) -> int:
        return GENESIS_TS + number * BLOCK_SECONDS

    def first_block_at(self, ts: int) -> int:
        """The lowest block whose timestamp is ``>= ts``."""
        return max(0, -(-(ts - GENESIS_TS) // BLOCK_SECONDS))

    def balance_at(self, block: int) -> int:
        steps = [b for b in self.token_balances if b <= block]
        return self.token_balances[max(steps)] if steps else 0

    def count_at(self, block: int) -> int:
        steps = [b for b in self.nonces if b <= block]
        return self.nonces[max(steps)] if steps else 0

    def token_locator(self) -> Erc20HtlcLocator:
        return Erc20HtlcLocator(**{**dataclasses.asdict(self.locator()), "token_address": TOKEN})

    def locator(self, *, deploy_tx_hash: str | None = None) -> EthHtlcLocator:
        return EthHtlcLocator(
            chain_id=CHAIN_ID,
            contract_address=CONTRACT,
            deploy_tx_hash=deploy_tx_hash or self.deploy_tx,
            hashlock="0x" + self.hashlock.hex(),
            claimant="0x" + "aa" * 20,
            refundee="0x" + "bb" * 20,
            timeout=self.timeout,
            amount_wei=10**15,
        )

    def _receipt(
        self, block: int, *, logs: list[dict[str, Any]], status: int, block_hash: bytes | None = None
    ) -> dict[str, Any]:
        return {
            "status": status,
            "blockNumber": block,
            "blockHash": block_hash if block_hash is not None else _block_hash(block),
            "logs": logs,
        }

    # -- honest transactions (the contract's own rules)

    def claim(self, block: int, *, preimage: bytes | None = None, label: str = "claim") -> str:
        p = self.preimage if preimage is None else preimage
        if self.settled_at is not None or self.ts(block) >= self.timeout:
            raise AssertionError("the contract would revert this claim; use force_receipt for an impossible chain")
        if hashlib.sha256(p).digest() != self.hashlock:
            raise AssertionError("the contract would revert a wrong preimage")
        tx = _tx_hash(label)
        log = {
            "address": CONTRACT,
            "topics": [CLAIMED_TOPIC0],
            "data": "0x" + p.hex(),
            "transactionHash": tx,
            "blockNumber": block,
        }
        self.receipts[tx] = self._receipt(block, logs=[log], status=1)
        self.settled_at = block
        return tx

    def refund(self, block: int, *, label: str = "refund") -> str:
        if self.settled_at is not None or self.ts(block) < self.timeout:
            raise AssertionError("the contract would revert this refund; use force_receipt for an impossible chain")
        tx = _tx_hash(label)
        log = {
            "address": CONTRACT,
            "topics": [REFUNDED_TOPIC0],
            "data": "0x",
            "transactionHash": tx,
            "blockNumber": block,
        }
        self.receipts[tx] = self._receipt(block, logs=[log], status=1)
        self.settled_at = block
        return tx

    def reverted(self, block: int, *, label: str = "reverted") -> str:
        """A failed refund: mined, status 0, and (as on a real chain) no logs."""
        tx = _tx_hash(label)
        self.receipts[tx] = self._receipt(block, logs=[], status=0)
        return tx

    def force_receipt(
        self,
        block: int,
        *,
        topic0: str,
        data: str = "0x",
        address: str = CONTRACT,
        label: str,
        status: int = 1,
        block_hash: bytes | None = None,
        settles: bool = False,
    ) -> str:
        """A receipt the contract could not have produced (or one from another contract). For the
        contradiction rules, which exist because real chains are read through endpoints that lie."""
        tx = _tx_hash(label)
        log = {"address": address, "topics": [topic0], "data": data, "transactionHash": tx, "blockNumber": block}
        self.receipts[tx] = self._receipt(block, logs=[log], status=status, block_hash=block_hash)
        if settles:
            self.settled_at = block
        return tx

    def logs(self) -> list[dict[str, Any]]:
        out = []
        for r in self.receipts.values():
            if r["status"] == 1:
                out.extend(r["logs"])
        return out


class FakeEvmEndpoint:
    """One endpoint's view of a :class:`FakeEvmChain`. Honest unless told otherwise."""

    def __init__(
        self,
        chain: FakeEvmChain,
        *,
        lag: int = 0,
        fork: str = "",
        forge_refunded_tx: str | None = None,
        forge_receipt: bool = False,
        hide_claimed: bool = False,
        logs_429: bool = False,
        range_cap: int | None = None,
        archive: bool = True,
        claim_settled_at_tip: bool = False,
        extra_logs: tuple[dict[str, Any], ...] = (),
        tip_reads_fail: bool = False,
        lie_settled_at_blocks: bool = False,
        lie_canonical: bool = False,
        hide_all_logs: bool = False,
        balance_reads_fail: bool = False,
        lie_balance: int | None = None,
        nonce_reads_fail: bool = False,
        lie_nonce: int | None = None,
        pending_extra: int = 0,
        hide_receipts: tuple[str, ...] = (),
        finalized_lag: int = 0,
    ) -> None:
        self.chain = chain
        self.lag = lag
        #: Blocks this endpoint's ``finalized`` trails the chain's by, with an honest head.
        self.finalized_lag = finalized_lag
        self.fork = fork
        self.forge_refunded_tx = forge_refunded_tx
        self.forge_receipt = forge_receipt
        self.hide_claimed = hide_claimed
        self.logs_429 = logs_429
        self.range_cap = range_cap
        self.archive = archive
        self.claim_settled_at_tip = claim_settled_at_tip
        self.extra_logs = extra_logs
        self.tip_reads_fail = tip_reads_fail
        self.lie_settled_at_blocks = lie_settled_at_blocks
        self.lie_canonical = lie_canonical
        self.hide_all_logs = hide_all_logs
        self.balance_reads_fail = balance_reads_fail
        self.lie_balance = lie_balance
        self.nonce_reads_fail = nonce_reads_fail
        self.lie_nonce = lie_nonce
        #: Transactions of the funding key in THIS endpoint's pool only, on top of the chain's.
        self.pending_extra = pending_extra
        #: Transactions this endpoint answers "no receipt" for, whatever the chain holds.
        self.hide_receipts = hide_receipts
        self.source_key = distinct_host()
        self.expected_chain_id = CHAIN_ID
        self.log_requests: list[tuple[int, int | str]] = []

    @property
    def head(self) -> int:
        return self.chain.head - self.lag

    def _hash(self, number: int) -> bytes:
        # A fork only diverges above the deploy block, so both sides agree on old history.
        return _block_hash(number, self.fork if number > self.chain.deploy_block else "")

    async def finalized_block_number(self) -> int:
        return min(max(self.chain.finalized - self.finalized_lag, 0), self.head)

    async def block_number(self) -> int:
        return self.head

    async def latest_block_timestamp(self) -> int:
        if self.tip_reads_fail:
            raise NetworkError("eth_getBlockByNumber(latest) failed")
        return self.chain.ts(self.head)

    async def block_hash_and_timestamp(self, number: int) -> tuple[bytes, int]:
        if number > self.head:
            raise NetworkError(f"block {number} not found")
        return self._hash(number), self.chain.ts(number)

    async def canonical_block_hash(self, number: int) -> bytes:
        if number > self.head:
            return b""
        if self.lie_canonical:
            return _block_hash(number, "lie")
        return self._hash(number)

    async def get_storage_at(self, address: str, slot: int, block_identifier: str | int) -> bytes:
        assert slot == 0
        if block_identifier == "latest":
            at = self.head
            if self.claim_settled_at_tip:
                return (1).to_bytes(32, "big")
        else:
            if not self.archive and int(block_identifier) < self.head - 128:
                raise NetworkError("missing trie node (historic state unavailable)")
            at = int(block_identifier)
            if self.lie_settled_at_blocks:
                return (1).to_bytes(32, "big")
        if address.lower() != CONTRACT:
            return bytes(32)
        settled = self.chain.settled_at is not None and self.chain.settled_at <= at
        return (1 if settled else 0).to_bytes(32, "big")

    def _block_of(self, block_identifier: str | int) -> int:
        if block_identifier in ("latest", "pending"):
            return self.head
        at = int(block_identifier)
        if not self.archive and at < self.head - 128:
            raise NetworkError("missing trie node (historic state unavailable)")
        if at > self.head:
            raise NetworkError(f"block {at} not found")
        return at

    async def erc20_balance_of(self, token: str, owner: str, block_identifier: str | int) -> int:
        if self.balance_reads_fail:
            raise NetworkError("eth_call failed: 429 Too Many Requests")
        at = self._block_of(block_identifier)
        if self.lie_balance is not None:
            return self.lie_balance
        if token.lower() != TOKEN or owner.lower() != CONTRACT:
            return 0
        return self.chain.balance_at(at)

    async def get_transaction_count(self, address: str, block: str | int = "pending") -> int:
        if self.nonce_reads_fail:
            raise NetworkError("eth_getTransactionCount failed: 429 Too Many Requests")
        at = self._block_of(block)
        if self.lie_nonce is not None:
            return self.lie_nonce
        if address.lower() != FUNDER:
            return 0
        pending = self.chain.pending_txs + self.pending_extra
        return self.chain.count_at(at) + (pending if block == "pending" else 0)

    async def get_transaction_receipt(self, tx_hash: str) -> dict[str, Any] | None:
        if self.forge_receipt and tx_hash == self.forge_refunded_tx:
            block = self.chain.finalized
            return {
                "status": 1,
                "blockNumber": block,
                "blockHash": self._hash(block),
                "logs": [{"address": CONTRACT, "topics": [REFUNDED_TOPIC0], "data": "0x"}],
            }
        r = self.chain.receipts.get(tx_hash)
        if r is None or r["blockNumber"] > self.head or tx_hash in self.hide_receipts:
            return None
        return dict(r)

    async def get_transaction(self, tx_hash: str) -> dict[str, Any]:
        r = self.chain.receipts.get(tx_hash)
        if r is None or tx_hash in self.hide_receipts:
            raise NetworkError(f"transaction {tx_hash} not found")
        mined = r["blockNumber"] if r["blockNumber"] <= self.head else None
        if tx_hash == self.chain.deploy_tx:
            return {"from": self.chain.deploy_from, "nonce": self.chain.deploy_nonce, "to": None, "blockNumber": mined}
        return {"from": FUNDER, "nonce": 1, "to": CONTRACT, "blockNumber": mined}

    async def get_logs(
        self, *, address: str, topics: Any = None, from_block: int | str = "earliest", to_block: int | str = "latest"
    ) -> list[dict[str, Any]]:
        self.log_requests.append((int(from_block), to_block))
        if self.logs_429:
            raise NetworkError("eth_getLogs failed: 429 Too Many Requests")
        hi = self.head if to_block == "latest" else int(to_block)
        lo = int(from_block)
        if lo > self.head or hi > self.head:
            # What anvil 1.7.1 answers (measured in the PR 4 review): a range past the head is an
            # error, not an empty list.
            raise NetworkError(
                f"eth_getLogs failed: BlockOutOfRangeError: block height is {self.head} but requested was {max(lo, hi)}"
            )
        if self.range_cap is not None and hi - lo + 1 > self.range_cap:
            raise NetworkError(f"eth_getLogs failed: query exceeds max block range {self.range_cap}")
        out = []
        for log in self.chain.logs():
            if not (lo <= log["blockNumber"] <= min(hi, self.head)):
                continue
            if log["address"].lower() != address.lower():
                continue
            if self.hide_claimed and log["topics"][0] == CLAIMED_TOPIC0:
                continue
            if self.hide_all_logs:
                continue
            out.append(dict(log))
        out.extend(dict(log) for log in self.extra_logs if lo <= log["blockNumber"] <= hi)
        if self.forge_refunded_tx is not None and lo <= self.chain.finalized <= hi:
            out.append(
                {
                    "address": CONTRACT,
                    "topics": [REFUNDED_TOPIC0],
                    "data": "0x",
                    "transactionHash": self.forge_refunded_tx,
                    "blockNumber": self.chain.finalized,
                }
            )
        return out
