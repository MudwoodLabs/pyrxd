"""Minimal async Ethereum JSON-RPC client (web3-backed), mirroring the repo's BTC client.

Follows the ``network/bitcoin.py`` / ``network/electrumx.py`` house style: a
client-owned session, ``close()`` lifecycle, ``NetworkError`` on transport failure, and a
bounded response size. web3 is imported LAZILY so ``eth_wallet`` loads with no Ethereum
dependency installed — only constructing/using :class:`EthRpc` requires web3 (a
Phase-3 network dependency), which is exactly when a live RPC endpoint is also needed.

This is the I/O layer; the security-critical preimage parsing is the pure
:func:`pyrxd.eth_wallet.secret.recover_secret` (offline-fuzzable, no web3).
"""

from __future__ import annotations

from typing import Any

from pyrxd.security.errors import NetworkError, ValidationError

__all__ = ["EthRpc"]

_MAX_RESPONSE_BYTES = 10 * 1024 * 1024  # 10 MB cap, matching the BTC client
_MAX_LOG_ENTRIES = 10_000  # bound an eth_getLogs return (a per-contract query yields a handful)


def _require_web3() -> Any:
    try:
        import web3  # type: ignore
    except ImportError as exc:  # pragma: no cover - exercised only without eth deps
        raise ValidationError("the ETH leg needs web3 (a Phase-3 network dependency); install the eth extra") from exc
    return web3


class EthRpc:
    """Thin async wrapper over ``AsyncWeb3`` for the handful of calls the leg needs.

    Construction requires web3 + an RPC URL; signing keys are NOT held here (the leg
    feeds raw bytes from :class:`PrivateKeyMaterial` to the signer at the call site).
    """

    def __init__(self, rpc_url: str, *, expected_chain_id: int) -> None:
        if not isinstance(rpc_url, str) or not rpc_url:
            raise ValidationError("rpc_url must be a non-empty string")
        if not isinstance(expected_chain_id, int) or expected_chain_id <= 0:
            raise ValidationError("expected_chain_id must be a positive int")
        web3 = _require_web3()
        self._w3 = web3.AsyncWeb3(web3.AsyncWeb3.AsyncHTTPProvider(rpc_url))
        self._expected_chain_id = expected_chain_id

    @property
    def w3(self) -> Any:
        return self._w3

    async def assert_chain(self) -> None:
        """Fail-closed if the endpoint is not the chain this swap was negotiated for."""
        try:
            cid = await self._w3.eth.chain_id
        except Exception as exc:
            raise NetworkError(f"eth_chainId failed: {exc}") from exc
        if cid != self._expected_chain_id:
            raise ValidationError(f"RPC chain_id {cid} != expected {self._expected_chain_id} (wrong network)")

    async def get_code(self, address: str, block_identifier: str | int | None = None) -> bytes:
        # block_identifier pins the read to a specific (e.g. 'finalized') block so a reorg cannot
        # swap the deployed code out from under a maker re-verifying before it locks (red-team HIGH
        # TOCTOU). None == the web3 default ('latest').
        try:
            code = (
                await self._w3.eth.get_code(address)
                if block_identifier is None
                else await self._w3.eth.get_code(address, block_identifier)
            )
        except Exception as exc:
            raise NetworkError(f"eth_getCode failed: {exc}") from exc
        b = bytes(code)
        if len(b) > _MAX_RESPONSE_BYTES:
            raise NetworkError("eth_getCode response exceeds size cap")
        return b

    async def get_balance(self, address: str, block_identifier: str | int | None = None) -> int:
        try:
            return int(
                await self._w3.eth.get_balance(address)
                if block_identifier is None
                else await self._w3.eth.get_balance(address, block_identifier)
            )
        except Exception as exc:
            raise NetworkError(f"eth_getBalance failed: {exc}") from exc

    async def get_transaction_count(self, address: str) -> int:
        """Pending nonce for the sender."""
        try:
            return int(await self._w3.eth.get_transaction_count(address, "pending"))
        except Exception as exc:
            raise NetworkError(f"eth_getTransactionCount failed: {exc}") from exc

    async def fee_fields(self) -> dict:
        """EIP-1559 fee fields (maxFeePerGas / maxPriorityFeePerGas) from the node."""
        try:
            base = (await self._w3.eth.get_block("pending")).get("baseFeePerGas", 0) or 0
            tip = await self._w3.eth.max_priority_fee
        except Exception as exc:
            raise NetworkError(f"fee estimation failed: {exc}") from exc
        tip = int(tip)
        return {"maxPriorityFeePerGas": tip, "maxFeePerGas": int(base) * 2 + tip}

    async def preflight(self, tx: dict) -> None:
        """`eth_call` the tx to detect a guaranteed revert BEFORE broadcasting.

        Fails fast (raises :class:`ValidationError`) instead of burning gas on a tx the
        node will mine-and-revert (e.g. a premature refund, a bad preimage, an
        already-settled HTLC). A transport failure is a :class:`NetworkError`. Strips
        gas/fee fields the node would reject in an eth_call.

        CONSERVATIVE CLASSIFICATION (red-team): a definite revert is recognised ONLY from
        web3's TYPED contract-exception classes — an honest node raises ContractLogicError /
        ContractCustomError / ContractPanicError for a real revert (custom errors arrive as a
        4-byte selector, e.g. NotYetExpired() -> 0x59912c06). We deliberately do NOT substring-
        match the error text: that string is RPC-controlled, so a lying node could stuff
        "revert" into a transport error to make us classify the HONEST taker refund (the only
        exit path) as a permanent ValidationError and abort it. An untyped failure is therefore
        treated as a retryable NetworkError — preflight is a gas-saving optimisation, not a
        safety gate, so under uncertainty we retry rather than permanently block the exit. A
        genuinely premature refund still reverts typed (NotYetExpired) on any honest node.
        """
        call_tx = {k: v for k, v in tx.items() if k in ("from", "to", "value", "data", "input")}
        web3 = _require_web3()
        try:
            await self._w3.eth.call(call_tx)
        except Exception as exc:
            contract_errors = tuple(
                getattr(web3.exceptions, n)
                for n in ("ContractLogicError", "ContractCustomError", "ContractPanicError")
                if hasattr(web3.exceptions, n)
            )
            if contract_errors and isinstance(exc, contract_errors):
                raise ValidationError(f"tx would revert (preflight eth_call): {exc}") from exc
            raise NetworkError(f"preflight eth_call failed: {exc}") from exc

    async def send_raw(self, raw_tx: bytes) -> str:
        try:
            h = await self._w3.eth.send_raw_transaction(raw_tx)
        except Exception as exc:
            raise NetworkError(f"eth_sendRawTransaction failed: {exc}") from exc
        return h.hex() if hasattr(h, "hex") else str(h)

    async def wait_receipt(self, tx_hash: str, *, timeout_s: float = 300.0) -> dict:
        try:
            r = await self._w3.eth.wait_for_transaction_receipt(tx_hash, timeout=timeout_s)
        except Exception as exc:
            raise NetworkError(f"wait_for_transaction_receipt failed: {exc}") from exc
        return dict(r)

    async def get_transaction(self, tx_hash: str) -> dict:
        try:
            return dict(await self._w3.eth.get_transaction(tx_hash))
        except Exception as exc:
            raise NetworkError(f"eth_getTransactionByHash failed: {exc}") from exc

    async def get_transaction_receipt(self, tx_hash: str) -> dict[str, Any] | None:
        """A single NON-BLOCKING receipt fetch (`eth_getTransactionReceipt`). Returns ``None`` when
        the tx is not currently mined — pending, or reorg-orphaned back to the mempool — instead of
        blocking like :meth:`wait_receipt` (a poller must never sleep inside one read). A transport
        failure is still a :class:`NetworkError` (fail-closed)."""
        web3 = _require_web3()
        try:
            r = await self._w3.eth.get_transaction_receipt(tx_hash)
        except Exception as exc:
            not_found = getattr(web3.exceptions, "TransactionNotFound", None)
            if not_found is not None and isinstance(exc, not_found):
                return None
            raise NetworkError(f"eth_getTransactionReceipt failed: {exc}") from exc
        return dict(r)

    async def finalized_block_number(self) -> int:
        """Block number of the `finalized` consensus checkpoint (the reorg-safe tip).

        SANITY-BOUNDED (red-team HIGH: single-source finality): a finalized value that exceeds the
        `latest` head from the SAME provider is incoherent (finalized is always <= head) and is
        rejected fail-closed — this catches a naive lying RPC that over-reports finalized to make a
        non-final claim look FINAL. It does NOT defend a fully-consistent malicious provider that
        lies about BOTH finalized and the canonical chain: for a real-value path a multi-source
        finality quorum is required (deferred; documented in claim_finality_verdict)."""
        try:
            fin = int((await self._w3.eth.get_block("finalized"))["number"])
            head = int((await self._w3.eth.get_block("latest"))["number"])
        except Exception as exc:
            raise NetworkError(f"eth_getBlock(finalized/latest) failed: {exc}") from exc
        if fin < 0 or fin > head:
            raise NetworkError(f"incoherent finalized={fin} > latest head={head}; refusing (fail-closed)")
        return fin

    async def block_number(self) -> int:
        """The current ``latest`` head block number (``eth_blockNumber``). Used alongside
        :meth:`finalized_block_number` to feed the across-time PoS finality-stall tracker the
        ``(head, finalized)`` pair (a frozen ``finalized`` while the head climbs = a stall)."""
        try:
            return int(await self._w3.eth.block_number)
        except Exception as exc:
            raise NetworkError(f"eth_blockNumber failed: {exc}") from exc

    async def canonical_block_hash(self, block_number: int) -> bytes:
        """The canonical block hash at ``block_number`` (eth_getBlockByNumber). Used to bind a
        receipt's claimed blockNumber to the canonical chain (red-team HIGH: receipt blockNumber on
        faith) — a fabricated receipt height is caught when its blockHash != the canonical hash."""
        if not isinstance(block_number, int) or isinstance(block_number, bool) or block_number < 0:
            raise NetworkError("block_number must be a non-negative int")
        try:
            blk = await self._w3.eth.get_block(block_number)
        except Exception as exc:
            raise NetworkError(f"eth_getBlockByNumber({block_number}) failed: {exc}") from exc
        h = blk.get("hash")
        return bytes(h) if h is not None else b""

    async def get_logs(
        self,
        *,
        address: str,
        topics: list[str | None | list[str]] | None = None,
        from_block: int | str = "earliest",
        to_block: int | str = "latest",
    ) -> list[dict[str, Any]]:
        """`eth_getLogs` for ONE contract address, optionally filtered by ``topics``. READ-ONLY.

        Scoped to a single address (the per-swap-unique HTLC), so the result is that contract's own
        event history — a handful of entries. Pass an int ``from_block`` (e.g. the deploy block) to
        bound the scan; ``to_block="latest"`` catches a JUST-mined claim. Detection deliberately reads
        to ``latest``, not ``finalized``: a watchtower must not MISS a fresh claim it has to race, and
        reorg-safety is asserted SEPARATELY by the finalized-checkpoint verdict (a non-final log can
        only ever cause a false PAGE, never a broadcast). Transport failure → :class:`NetworkError`;
        the entry count is bounded (a pathological return must not OOM the tower)."""
        filt: dict[str, Any] = {"address": address, "fromBlock": from_block, "toBlock": to_block}
        if topics is not None:
            filt["topics"] = topics
        try:
            raw = await self._w3.eth.get_logs(filt)
        except Exception as exc:
            raise NetworkError(f"eth_getLogs failed: {exc}") from exc
        if len(raw) > _MAX_LOG_ENTRIES:
            raise NetworkError(f"eth_getLogs returned {len(raw)} entries (> {_MAX_LOG_ENTRIES} cap); refusing")
        return [dict(log) for log in raw]

    async def close(self) -> None:
        """Close the underlying provider session if it exposes one."""
        provider = getattr(self._w3, "provider", None)
        disconnect = getattr(provider, "disconnect", None)
        if disconnect is not None:
            try:
                await disconnect()
            except Exception:  # nosec B110 — best-effort cleanup; a failed disconnect on close is non-fatal
                pass
