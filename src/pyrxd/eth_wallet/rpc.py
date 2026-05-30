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

    async def get_code(self, address: str) -> bytes:
        try:
            code = await self._w3.eth.get_code(address)
        except Exception as exc:
            raise NetworkError(f"eth_getCode failed: {exc}") from exc
        b = bytes(code)
        if len(b) > _MAX_RESPONSE_BYTES:
            raise NetworkError("eth_getCode response exceeds size cap")
        return b

    async def get_balance(self, address: str) -> int:
        try:
            return int(await self._w3.eth.get_balance(address))
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
        """
        call_tx = {k: v for k, v in tx.items() if k in ("from", "to", "value", "data", "input")}
        web3 = _require_web3()
        try:
            await self._w3.eth.call(call_tx)
        except Exception as exc:
            # A revert (require/custom error) means the tx WOULD fail on-chain — a
            # ValidationError, not a transport problem. web3 surfaces these as
            # ContractLogicError / ContractCustomError (custom errors arrive as a 4-byte
            # selector, e.g. NotYetExpired() -> 0x59912c06). Everything else is transport.
            contract_errors = tuple(
                getattr(web3.exceptions, n)
                for n in ("ContractLogicError", "ContractCustomError", "ContractPanicError")
                if hasattr(web3.exceptions, n)
            )
            s = str(exc).lower()
            if (contract_errors and isinstance(exc, contract_errors)) or "revert" in s or "execution reverted" in s:
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

    async def finalized_block_number(self) -> int:
        """Block number of the `finalized` consensus checkpoint (the reorg-safe tip)."""
        try:
            blk = await self._w3.eth.get_block("finalized")
        except Exception as exc:
            raise NetworkError(f"eth_getBlock(finalized) failed: {exc}") from exc
        return int(blk["number"])

    async def close(self) -> None:
        """Close the underlying provider session if it exposes one."""
        provider = getattr(self._w3, "provider", None)
        disconnect = getattr(provider, "disconnect", None)
        if disconnect is not None:
            try:
                await disconnect()
            except Exception:  # nosec B110 — best-effort cleanup; a failed disconnect on close is non-fatal
                pass
