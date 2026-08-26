"""Quorum reads across independent EVM endpoints — the ETH analogue of
:class:`~pyrxd.network.bitcoin.MultiSourceBtcFundingReader`.

The gap this closes
-------------------
Every EVM read in the swap path went through one :class:`~pyrxd.eth_wallet.rpc.EthRpc`, so every
decision that turns on one — *is the counter leg really funded?*, *is this address frozen?*, *is
the claim final?* — rested on a single endpoint's word. The freeze gate's own docstring says it
plainly: it "defends a FAILING provider, not a LYING one".

Two distinct failure modes, and the second is not hypothetical:

* **A lying endpoint** answers "funded" for an empty contract, or "not frozen" for a frozen one.
  The maker reveals the preimage, the counterparty takes the other leg, and nothing comes back.
* **A stale endpoint** — far more common — is a load-balanced provider serving a lagging node.
  This stack has already been bitten by it: see the comment in ``erc20_leg.claim`` about a stale
  low balance refusing a claim and killing the secret "for a reading that was simply out of date".

Quorum answers both, because the aggregation is chosen per read to be *conservative* rather than
merely majority — see :meth:`eth_call_quorum`.

What is quorum-read, and what is deliberately not
-------------------------------------------------
Quorum applies to reads that decide an **irreversible** action. It does NOT apply to:

* **Writes and tip-local state** — ``send_raw``, ``fee_fields``, ``preflight``,
  ``get_transaction_count``, ``wait_receipt``. A transaction is broadcast once, and a nonce
  belongs to one endpoint's view of the mempool. Fanning these out would be wrong, not safer.
* **``get_logs``** — used to scrape the preimage out of a claim. It is **self-verifying**: the
  scraped value is checked against the hashlock, so a lying source cannot forge one. More sources
  would only add ways to find it, and that is a liveness question, not a safety one.

Disagreement is a refusal, not a vote
-------------------------------------
For an identity read (runtime code, a contract immutable, a block hash) any disagreement means one
endpoint is lying or lagging and **we cannot tell which**, so this refuses rather than taking the
majority. For a magnitude read (a balance, a finalized height) the conservative answer is well
defined — the lowest — and that is taken, exactly as ``MultiSourceBtcFundingReader`` takes
``min(depth)``.

Below quorum it raises. An unreachable endpoint must never silently become a smaller quorum,
because "two of three agreed" and "the only one that answered said so" are different facts.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Sequence
from typing import Any

from ..security.errors import NetworkError, ValidationError

__all__ = ["MultiSourceEthRpc", "read_contract"]


async def read_contract(
    rpc: Any,
    make_call: Callable[[Any], Awaitable[Any]],
    *,
    label: str,
    combine: Callable[[list[Any]], Any] | None = None,
) -> Any:
    """Perform one contract read, fanning out when ``rpc`` is multi-source.

    ``make_call`` takes a single-source rpc and returns the awaitable for the read, so the contract
    object is rebuilt per endpoint rather than bound to one of them. Every ERC-20 and HTLC contract
    read in this package goes through here, which is the point: a converted read gets quorum
    automatically, and an unconverted one cannot even run against a
    :class:`MultiSourceEthRpc`, because that class's ``w3`` raises.

    ``combine`` is ``None`` for an identity read (all answers must match) or an aggregator such as
    ``min`` / ``any`` for one with a conservative direction. Single-source callers are unaffected.
    """
    quorum = getattr(rpc, "eth_call_quorum", None)
    if quorum is None:
        return await make_call(rpc)
    return await quorum(make_call, label=label, combine=combine)


class MultiSourceEthRpc:
    """Several independent EVM endpoints presented as one, with quorum on the reads that matter.

    Drop-in for :class:`~pyrxd.eth_wallet.rpc.EthRpc` on the read paths the swap depends on. The
    sources must be genuinely independent to be worth anything — three URLs at one provider share
    one failure and one operator, and this class cannot tell the difference.

    :param sources: two or more ``EthRpc`` instances, each pinned to the same chain id.
    :param min_agreeing: how many must answer before an answer exists. Defaults to a true majority
        of the sources, never fewer than 2.
    """

    def __init__(self, sources: Sequence[Any], *, min_agreeing: int | None = None) -> None:
        self._sources = list(sources)
        if len(self._sources) < 2:
            raise ValidationError(
                f"MultiSourceEthRpc needs at least 2 sources, got {len(self._sources)}. One source "
                "is not a quorum — use EthRpc directly and be honest about it."
            )
        default = max(2, len(self._sources) // 2 + 1)
        self._min = default if min_agreeing is None else int(min_agreeing)
        if self._min < 2:
            raise ValidationError("min_agreeing must be at least 2; 1 is single-source with extra steps")
        if self._min > len(self._sources):
            raise ValidationError(
                f"min_agreeing={self._min} exceeds the {len(self._sources)} sources given: this "
                "quorum can never be reached, so every read would fail closed"
            )

    @property
    def sources(self) -> list[Any]:
        return list(self._sources)

    @property
    def min_agreeing(self) -> int:
        return self._min

    @property
    def primary(self) -> Any:
        """The endpoint that carries writes and tip-local state. Reads should not use it directly."""
        return self._sources[0]

    @property
    def w3(self) -> Any:
        """Deliberately fatal.

        Returning the primary's ``w3`` here would be the worst outcome available: every
        unconverted contract read would keep working, against ONE endpoint, while the object it
        was called on advertises a quorum. The failure would be invisible precisely because
        nothing broke. Raising turns a silent false guarantee into an import-time-obvious one.
        """
        raise ValidationError(
            "MultiSourceEthRpc has no single `w3`: a contract read through one endpoint's web3 "
            "would be single-source while looking quorum-backed. Route it through "
            "`pyrxd.eth_wallet.multi_rpc.read_contract`, which rebuilds the contract per source, "
            "or use `.primary` explicitly if the read genuinely does not need a quorum."
        )

    @property
    def write_w3(self) -> Any:
        """The PRIMARY endpoint's web3, for BUILDING transactions.

        A transaction is built once, against one endpoint's nonce and fee view, and broadcast once.
        Fanning that out is not a quorum — it is the same transaction sent several times. This is
        the explicit escape hatch `w3` refuses to be: a caller reaching for it is saying "this is a
        write", and a read that says it is lying.
        """
        return self.primary.w3

    async def latest_block_timestamp(self) -> int:
        """Head timestamp — quorum by MAX, which is the safe direction here and only here.

        The claim-deadline guard refuses once ``block.timestamp >= timeout``, and a reverted claim
        is still MINED with the preimage in its calldata. A lagging or hostile endpoint reports an
        EARLIER timestamp, which is exactly what makes that guard pass when it should refuse — so
        the latest head any endpoint will admit to is the conservative one. Note this is the
        opposite direction from every other magnitude read in this class, and deliberately so:
        conservative means "toward refusing", not "toward the smaller number".
        """
        return await self.eth_call_quorum(
            lambda s: s.latest_block_timestamp(), label="latest_block_timestamp", combine=max
        )

    # ---------------------------------------------------------------- fan-out

    async def _gather(self, call: Callable[[Any], Awaitable[Any]], *, label: str) -> list[Any]:
        """Every source, concurrently. Returns the successful answers; raises below quorum."""
        results = await asyncio.gather(*(call(s) for s in self._sources), return_exceptions=True)
        ok = [r for r in results if not isinstance(r, BaseException)]
        if len(ok) < self._min:
            errs = "; ".join(f"{type(r).__name__}: {r}" for r in results if isinstance(r, BaseException))
            raise NetworkError(
                f"{label}: only {len(ok)} of {len(self._sources)} endpoints answered, quorum is "
                f"{self._min}. Refusing to act on a reading fewer sources agreed on than required "
                f"[{errs}]"
            )
        return ok

    async def eth_call_quorum(
        self,
        make_call: Callable[[Any], Awaitable[Any]],
        *,
        label: str,
        combine: Callable[[list[Any]], Any] | None = None,
    ) -> Any:
        """One contract read across every source. See :func:`read_contract`."""
        return self._agree(await self._gather(make_call, label=label), label=label, combine=combine)

    def _agree(self, answers: list[Any], *, label: str, combine: Callable[[list[Any]], Any] | None) -> Any:
        if combine is not None:
            return combine(answers)
        first = answers[0]
        mismatched = [a for a in answers[1:] if a != first]
        if mismatched:
            raise NetworkError(
                f"{label}: endpoints disagree ({first!r} vs {mismatched[0]!r}). One of them is "
                "lying or lagging and there is no way to tell which from here, so this refuses "
                "rather than taking a majority."
            )
        return first

    # ------------------------------------------------------- quorum'd reads

    async def assert_chain(self) -> None:
        """No source may be on the WRONG chain; an unreachable one is tolerated above quorum.

        A chain mismatch is never failover-able — a quorum spanning two chains is not a weaker
        guarantee, it is a meaningless one — so a `ValidationError` from any source propagates,
        the same reasoning `FailoverElectrumXClient` uses.

        But the first version awaited every source unconditionally, which conflated "this endpoint
        is on the wrong chain" with "this endpoint returned 429". That is not a safety property, it
        is a liveness bug, and it bit during a live mainnet swap: one rate-limited public endpoint
        aborted `verify_funded` with real value already locked in the HTLC. A source that cannot be
        reached also cannot lie — and if it returns later on a different chain, every identity read
        refuses on the disagreement. So an unreachable source is tolerated as long as `min_agreeing`
        sources positively CONFIRM the chain.
        """
        results = await asyncio.gather(*(s.assert_chain() for s in self._sources), return_exceptions=True)
        for r in results:
            if isinstance(r, ValidationError):
                raise r
        confirmed = sum(1 for r in results if not isinstance(r, BaseException))
        if confirmed < self._min:
            unreachable = "; ".join(f"{type(r).__name__}: {r}" for r in results if isinstance(r, BaseException))
            raise NetworkError(
                f"assert_chain: only {confirmed} of {len(self._sources)} endpoints confirmed chain, "
                f"quorum is {self._min} [{unreachable}]"
            )

    async def get_code(self, address: str, block_identifier: str | int | None = None) -> bytes:
        """Runtime code — an IDENTITY read, so any disagreement refuses."""
        return await self.eth_call_quorum(lambda s: s.get_code(address, block_identifier), label=f"get_code({address})")

    async def get_balance(self, address: str, block_identifier: str | int | None = None) -> int:
        """Native balance — conservative MIN, so a lagging endpoint can only under-report and
        refuse a swap, never over-credit one into a reveal."""
        return await self.eth_call_quorum(
            lambda s: s.get_balance(address, block_identifier), label=f"get_balance({address})", combine=min
        )

    async def finalized_block_number(self) -> int:
        """Conservative MIN: the lowest finalized height any endpoint will vouch for."""
        return await self.eth_call_quorum(
            lambda s: s.finalized_block_number(), label="finalized_block_number", combine=min
        )

    async def block_number(self) -> int:
        """Conservative MIN. Head is used to reject a `finalized > head` over-report, so the
        lowest head makes that check strictest."""
        return await self.eth_call_quorum(lambda s: s.block_number(), label="block_number", combine=min)

    async def canonical_block_hash(self, block_number: int) -> bytes:
        """The canonical-chain binding — an IDENTITY read. Disagreement here means the endpoints
        are on different forks, which is exactly the condition worth refusing on."""
        return await self.eth_call_quorum(
            lambda s: s.canonical_block_hash(block_number), label=f"canonical_block_hash({block_number})"
        )

    async def get_transaction_receipt(self, tx_hash: str) -> dict[str, Any] | None:
        """Quorum on the two fields a swap decision turns on — did it succeed, and in which block.

        The whole receipt is not compared: endpoints legitimately differ on `effectiveGasPrice`
        formatting and log ordering, and refusing on those would be a guard refusing valid work.
        """

        async def _one(s: Any) -> tuple[Any, Any, Any] | None:
            r = await s.get_transaction_receipt(tx_hash)
            if r is None:
                return None
            return (r.get("status"), r.get("blockHash"), r.get("blockNumber"))

        agreed = await self.eth_call_quorum(_one, label=f"get_transaction_receipt({tx_hash})")
        if agreed is None:
            return None
        return await self.primary.get_transaction_receipt(tx_hash)

    # --------------------------------------------- deliberately single-source

    async def get_transaction_count(self, address: str, block: str = "pending") -> int:
        """PRIMARY only, and it must be. The nonce is the mempool view of the endpoint that will
        broadcast; taking another's would build a transaction against a state that endpoint does
        not have."""
        return await self.primary.get_transaction_count(address, block)

    async def fee_fields(self) -> dict:
        """PRIMARY only — a fee estimate is advice about one endpoint's mempool, not a fact."""
        return await self.primary.fee_fields()

    async def preflight(self, tx: dict) -> None:
        return await self.primary.preflight(tx)

    async def send_raw(self, raw_tx: bytes) -> str:
        """PRIMARY only. Broadcasting to every endpoint is not a quorum, it is the same
        transaction sent several times."""
        return await self.primary.send_raw(raw_tx)

    async def wait_receipt(self, tx_hash: str, *, timeout_s: float = 300.0) -> dict:
        return await self.primary.wait_receipt(tx_hash, timeout_s=timeout_s)

    async def get_transaction(self, tx_hash: str) -> dict:
        return await self.primary.get_transaction(tx_hash)

    async def get_logs(self, *args: Any, **kwargs: Any) -> Any:
        """PRIMARY only, deliberately. This scrapes the preimage out of a claim, and the result is
        checked against the hashlock — so a lying endpoint cannot forge one, and a missing log is a
        liveness problem rather than a safety one."""
        return await self.primary.get_logs(*args, **kwargs)

    async def close(self) -> None:
        await asyncio.gather(*(s.close() for s in self._sources), return_exceptions=True)
