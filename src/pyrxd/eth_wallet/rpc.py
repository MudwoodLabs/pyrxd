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

import logging
import re
from typing import Any

from pyrxd.network.redaction import redact_endpoint_secrets, redact_endpoints_in
from pyrxd.network.source_identity import source_key
from pyrxd.security.errors import NetworkError, RxdSdkError, ValidationError

__all__ = ["EthRpc"]

_MAX_RESPONSE_BYTES = 10 * 1024 * 1024  # 10 MB cap, matching the BTC client
_MAX_LOG_ENTRIES = 10_000  # bound an eth_getLogs return (a per-contract query yields a handful)


def _require_web3() -> Any:
    try:
        import web3  # type: ignore
    except ImportError as exc:  # pragma: no cover - exercised only without eth deps
        raise ValidationError(
            "the ETH leg needs web3 (a Phase-3 network dependency); install it with: pip install 'pyrxd[eth]'"
        ) from exc
    return web3


def _chain_quotes_a_secret(exc: BaseException, url: str) -> bool:
    """Whether *exc*, or anything chained under it, quotes a credential-bearing part of *url*.

    The chain matters as much as the message. ``logger.exception`` and ``--debug`` print every
    ``__cause__`` and ``__context__``, so an error whose own text was redacted still leaks the key
    if the aiohttp exception it was raised ``from`` is printed underneath it.
    """
    seen: set[int] = set()
    cur: BaseException | None = exc
    while cur is not None and id(cur) not in seen:
        seen.add(id(cur))
        text = f"{type(cur).__name__}: {cur}"
        # The SECRET parts only: `redact_endpoints_in` also normalises a keyless URL's spelling
        # (drops a trailing "/"), which is a change but not a leak.
        if redact_endpoint_secrets(text, url) != text:
            return True
        nxt = cur.__cause__ if cur.__cause__ is not None else cur.__context__
        cur = nxt
    return False


def _scrubbed(kind: type[RxdSdkError], message: str, exc: BaseException, url: str) -> RxdSdkError:
    """*kind*(*message*) with *url*'s credential parts redacted, chained to *exc* only if that is safe.

    The ONE place an :class:`EthRpc` turns a library exception into text. aiohttp's
    ``ClientResponseError`` quotes the full request URL — ``https://host/v3/<API-KEY>`` — so a 429
    or a 5xx from a keyed provider put the key into the exception, from there into the watchtower's
    page text, its log and its webhook. When nothing in the chain quotes a secret the original
    exception stays attached as ``__cause__`` for debugging; when something does, the chain is cut.
    """
    err = kind(str(redact_endpoints_in(message, url)))
    err.__cause__ = None if _chain_quotes_a_secret(exc, url) else exc
    err.__suppress_context__ = True
    return err


class _RedactingLogger:
    """The provider's logger, with the endpoint's credential parts removed from every line.

    web3's ``AsyncHTTPProvider`` logs its full ``endpoint_uri`` — at DEBUG on every request, and at
    INFO ("Successfully disconnected from: <url>") on ``close()``. The watchtower logs at INFO, so
    an orderly shutdown wrote the key to its log.
    """

    def __init__(self, logger: logging.Logger, url: str) -> None:
        self._logger = logger
        self._url = url

    def _emit(self, level: int, msg: object, *args: Any, **kwargs: Any) -> None:
        if not self._logger.isEnabledFor(level):
            return
        try:
            text = (str(msg) % args) if args else str(msg)
        except (TypeError, ValueError):  # a malformed format string must not lose the line
            text = " ".join(str(x) for x in (msg, *args))
        kwargs.setdefault("stacklevel", 3)
        self._logger.log(level, "%s", redact_endpoints_in(text, self._url), **kwargs)

    def debug(self, msg: object, *args: Any, **kwargs: Any) -> None:
        self._emit(logging.DEBUG, msg, *args, **kwargs)

    def info(self, msg: object, *args: Any, **kwargs: Any) -> None:
        self._emit(logging.INFO, msg, *args, **kwargs)

    def warning(self, msg: object, *args: Any, **kwargs: Any) -> None:
        self._emit(logging.WARNING, msg, *args, **kwargs)

    def error(self, msg: object, *args: Any, **kwargs: Any) -> None:
        self._emit(logging.ERROR, msg, *args, **kwargs)

    def exception(self, msg: object, *args: Any, **kwargs: Any) -> None:
        kwargs.setdefault("exc_info", True)
        self._emit(logging.ERROR, msg, *args, **kwargs)

    def critical(self, msg: object, *args: Any, **kwargs: Any) -> None:
        self._emit(logging.CRITICAL, msg, *args, **kwargs)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._logger, name)


_DIGITS = re.compile(r"[0-9]+")


def _honest_jsonrpc(value: Any) -> bool:
    """The only ``jsonrpc`` an honest server sends."""
    return value == "2.0" and isinstance(value, str)


def _honest_id(value: Any) -> bool:
    """An id web3 could have sent: an int, or its digits as a string (a proxy that stringifies)."""
    if isinstance(value, bool):
        return False
    return isinstance(value, int) or (isinstance(value, str) and _DIGITS.fullmatch(value) is not None)


def _honest_code(value: Any) -> bool:
    """A JSON-RPC error code is an integer."""
    return isinstance(value, int) and not isinstance(value, bool)


def _scrub_values(value: Any, url: str) -> Any:
    """*value* with *url*'s credential parts removed from every string VALUE in it.

    Dict KEYS are never rewritten, and neither is anything that is not a string. The redactor
    treats each query value of *url* as a whole-token secret, so a URL ending ``?x=message`` would
    otherwise rename an ``error``'s ``message`` key, and ``?v=2`` would turn ``"2.0"`` into
    ``"<redacted>.0"`` — both of which made web3 reject honest responses.
    """
    if isinstance(value, str):
        return str(redact_endpoints_in(value, url))
    if isinstance(value, dict):
        return {k: _scrub_values(v, url) for k, v in value.items()}
    if isinstance(value, list):
        return [_scrub_values(v, url) for v in value]
    if isinstance(value, tuple):
        return tuple(_scrub_values(v, url) for v in value)
    return value


def _scrub_error(error: Any, url: str) -> Any:
    """An ``error`` member: string values scrubbed, keys kept, ``code`` kept when it is an int."""
    if isinstance(error, dict):
        return {k: (v if k == "code" and _honest_code(v) else _scrub_values(v, url)) for k, v in error.items()}
    return _scrub_values(error, url)


def _scrub_response(response: Any, url: str) -> Any:
    """*response* with the endpoint's credential parts removed from the text a server wrote.

    A JSON-RPC error, or a malformed response, arrives as a SUCCESSFUL HTTP response, so it never
    reaches the ``except`` in ``make_request``; web3 raises from it later (``Web3RPCError``,
    ``BadResponseFormat``) and quotes what the server wrote — which can echo the request path, key
    included, in any member it likes.

    The rule is: an HONEST response is returned byte-identical, and anything else is scrubbed.

    * A well-formed single response — a dict carrying exactly one of ``result`` and ``error``, a
      ``jsonrpc`` of ``"2.0"`` and an ``id`` that is an int or a digit string — keeps its
      ``result``, ``jsonrpc`` and ``id`` as sent, and its ``error.code`` too when that is an int.
      A response whose ``jsonrpc`` or ``id`` has any other shape is NOT well-formed: web3 rejects it
      and quotes the whole response, ``result`` included. Every other string VALUE is scrubbed; no
      key is ever rewritten. The redactor treats each URL query value as a whole-token secret, so
      rewriting a protocol member or a key unconditionally broke honest responses for ordinary
      URLs (``?v=2`` turned ``"2.0"`` into ``"<redacted>.0"``).
    * Anything else — a dict with both ``result`` and ``error`` or with neither, a misshapen
      ``jsonrpc`` or ``id``, a bare list or string where a single response was due — is scrubbed IN
      FULL, ``result`` included. web3
      rejects those shapes and quotes them, so nothing honest is lost. (A batch response is a list
      by design; ``make_batch_request`` applies this function to each element instead.)
    """
    if (
        not isinstance(response, dict)
        or (("result" in response) == ("error" in response))
        or not _honest_jsonrpc(response.get("jsonrpc"))
        or not _honest_id(response.get("id"))
    ):
        return _scrub_values(response, url)
    out: dict[Any, Any] = {}
    for k, v in response.items():
        if _kept_as_sent(k, v):
            out[k] = v
        elif k == "error":
            out[k] = _scrub_error(v, url)
        else:
            out[k] = _scrub_values(v, url)
    return out


def _kept_as_sent(member: Any, value: Any) -> bool:
    """Whether a well-formed response's *member* is returned untouched (see :func:`_scrub_response`)."""
    if member == "result":
        return True
    if member == "jsonrpc":
        return _honest_jsonrpc(value)
    if member == "id":
        return _honest_id(value)
    return False


_PROVIDER_CLASS: Any = None


def _redacting_http_provider(web3: Any, rpc_url: str) -> Any:
    """``AsyncHTTPProvider`` for *rpc_url* whose transport failures never quote the URL's secrets.

    It also removes them from what a server wrote into a response before web3 raises from it,
    leaving an honest response byte-identical (:func:`_scrub_response`). This is the layer every request crosses — :class:`EthRpc`'s own methods AND the contract reads
    the legs make through ``rpc.w3`` / :func:`~pyrxd.eth_wallet.multi_rpc.read_contract`, which
    never pass through an :class:`EthRpc` method and so are not covered by :meth:`EthRpc._failed`.
    A failure whose chain quotes nothing secret is re-raised UNCHANGED (same type, so web3's own
    handling and every caller's ``except`` clause see what they always saw). One that does is
    replaced by a :class:`NetworkError` carrying the redacted text, with the chain cut. The
    provider's own log lines go through :class:`_RedactingLogger`.

    NOT covered: web3's ``HTTPSessionManager`` logs the URI at DEBUG when it caches a session. It is
    a separate object with a class-level logger; at the INFO level the watchtower runs at, it is
    silent.
    """
    global _PROVIDER_CLASS
    if _PROVIDER_CLASS is None:

        class _RedactingAsyncHTTPProvider(web3.AsyncWeb3.AsyncHTTPProvider):  # type: ignore[misc,name-defined]
            def __init__(self, endpoint_uri: str) -> None:
                super().__init__(endpoint_uri)
                self.logger = _RedactingLogger(type(self).logger, str(endpoint_uri))

            async def make_request(self, method: Any, params: Any) -> Any:
                try:
                    response = await super().make_request(method, params)
                except Exception as exc:
                    if not _chain_quotes_a_secret(exc, str(self.endpoint_uri)):
                        raise
                    raise _scrubbed(
                        NetworkError, f"{method} transport failure: {exc}", exc, str(self.endpoint_uri)
                    ) from None
                return _scrub_response(response, str(self.endpoint_uri))

            async def make_batch_request(self, batch_requests: Any) -> Any:
                try:
                    response = await super().make_batch_request(batch_requests)
                except Exception as exc:
                    if not _chain_quotes_a_secret(exc, str(self.endpoint_uri)):
                        raise
                    raise _scrubbed(
                        NetworkError, f"batch request transport failure: {exc}", exc, str(self.endpoint_uri)
                    ) from None
                if isinstance(response, list):
                    return [_scrub_response(r, str(self.endpoint_uri)) for r in response]
                return _scrub_response(response, str(self.endpoint_uri))

        _PROVIDER_CLASS = _RedactingAsyncHTTPProvider
    return _PROVIDER_CLASS(rpc_url)


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
        #: The source this endpoint is (its operator group, :func:`~pyrxd.network.source_identity.source_key`),
        #: for :class:`~pyrxd.eth_wallet.multi_rpc.MultiSourceEthRpc` to count it by. Derived before
        #: web3 is touched, so an unparseable URL fails here.
        self.source_key = source_key(rpc_url)
        #: The URL as given, which may carry a key. Never printed: kept so error text that quotes it can
        #: be redacted (:class:`~pyrxd.eth_wallet.multi_rpc.MultiSourceEthRpc` reads it for that only).
        self._rpc_url = rpc_url
        web3 = _require_web3()
        self._w3 = web3.AsyncWeb3(_redacting_http_provider(web3, rpc_url))
        self._expected_chain_id = expected_chain_id

    @property
    def expected_chain_id(self) -> int:
        """The chain this endpoint is pinned to — what :meth:`assert_chain` holds it to.

        Public so a leg can check that the chain id it SIGNS with is this one. ``assert_chain`` only
        compares the endpoint with this value; a leg signing for a different chain passed it, and
        its signed bytes then reached a provider on the wrong network.
        """
        return self._expected_chain_id

    def _failed(self, what: str, exc: BaseException, *, kind: type[RxdSdkError] = NetworkError) -> RxdSdkError:
        """The error every method below raises for a failed call: ``"<what>: <exc>"``, redacted.

        Through here, not an f-string at each site, so a new method cannot forget the redaction
        (see :func:`_scrubbed`). Callers ``raise`` the return value.
        """
        return _scrubbed(kind, f"{what}: {exc}", exc, self._rpc_url)

    @property
    def w3(self) -> Any:
        return self._w3

    @property
    def write_w3(self) -> Any:
        """The web3 used to BUILD transactions. Identical to ``w3`` here.

        It exists so the legs can name the difference between building a transaction (which has to
        happen against one endpoint) and reading state (which should not). ``MultiSourceEthRpc``
        makes ``w3`` fatal precisely so an unconverted READ cannot quietly run single-source; the
        write sites say ``write_w3`` and mean it.
        """
        return self.w3

    async def latest_block_timestamp(self) -> int:
        """Head timestamp, for the claim-deadline guard (wants the LATEST any source admits to)."""
        return int((await self.w3.eth.get_block("latest"))["timestamp"])

    async def latest_block_timestamp_quorum(self) -> int:
        """Same read; the multi-source class returns the quorum-th head instead. One endpoint has
        one answer, so all three accessors coincide here."""
        return await self.latest_block_timestamp()

    async def latest_block_timestamp_min(self) -> int:
        """Same read; the name exists so the multi-source class can aggregate it the OTHER way for
        the staleness and refund-maturity guards. Identical here — one endpoint has one answer."""
        return await self.latest_block_timestamp()

    async def assert_chain(self) -> None:
        """Fail-closed if the endpoint is not the chain this swap was negotiated for."""
        try:
            cid = await self._w3.eth.chain_id
        except Exception as exc:
            raise self._failed("eth_chainId failed", exc)
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
            raise self._failed("eth_getCode failed", exc)
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
            raise self._failed("eth_getBalance failed", exc)

    async def get_transaction_count(self, address: str, block: str = "pending") -> int:
        """Nonce for the sender. Defaults to ``pending`` so a freshly built tx does not collide
        with one still in the mempool.

        The ``block`` parameter exists so a caller can compare the two: ``pending != latest`` means
        this sender has transactions in flight. That is the difference between "the HTLC holds
        nothing" and "the HTLC holds nothing YET", which a balance read alone cannot tell apart —
        see the resume guard in :meth:`Erc20HtlcLeg._push_and_bind`.
        """
        try:
            return int(await self._w3.eth.get_transaction_count(address, block))
        except Exception as exc:
            raise self._failed("eth_getTransactionCount failed", exc)

    async def fee_fields(self) -> dict:
        """EIP-1559 fee fields (maxFeePerGas / maxPriorityFeePerGas) from the node."""
        try:
            base = (await self._w3.eth.get_block("pending")).get("baseFeePerGas", 0) or 0
            tip = await self._w3.eth.max_priority_fee
        except Exception as exc:
            raise self._failed("fee estimation failed", exc)
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
                raise self._failed("tx would revert (preflight eth_call)", exc, kind=ValidationError)
            raise self._failed("preflight eth_call failed", exc)

    async def send_raw(self, raw_tx: bytes) -> str:
        try:
            h = await self._w3.eth.send_raw_transaction(raw_tx)
        except Exception as exc:
            raise self._failed("eth_sendRawTransaction failed", exc)
        return h.hex() if hasattr(h, "hex") else str(h)

    async def wait_receipt(self, tx_hash: str, *, timeout_s: float = 300.0) -> dict:
        try:
            r = await self._w3.eth.wait_for_transaction_receipt(tx_hash, timeout=timeout_s)
        except Exception as exc:
            raise self._failed("wait_for_transaction_receipt failed", exc)
        return dict(r)

    async def get_transaction(self, tx_hash: str) -> dict:
        try:
            return dict(await self._w3.eth.get_transaction(tx_hash))
        except Exception as exc:
            raise self._failed("eth_getTransactionByHash failed", exc)

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
            raise self._failed("eth_getTransactionReceipt failed", exc)
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
            raise self._failed("eth_getBlock(finalized/latest) failed", exc)
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
            raise self._failed("eth_blockNumber failed", exc)

    async def canonical_block_hash(self, block_number: int) -> bytes:
        """The canonical block hash at ``block_number`` (eth_getBlockByNumber). Used to bind a
        receipt's claimed blockNumber to the canonical chain (red-team HIGH: receipt blockNumber on
        faith) — a fabricated receipt height is caught when its blockHash != the canonical hash."""
        if not isinstance(block_number, int) or isinstance(block_number, bool) or block_number < 0:
            raise NetworkError("block_number must be a non-negative int")
        try:
            blk = await self._w3.eth.get_block(block_number)
        except Exception as exc:
            raise self._failed(f"eth_getBlockByNumber({block_number}) failed", exc)
        h = blk.get("hash")
        return bytes(h) if h is not None else b""

    async def get_logs(
        self,
        *,
        address: str,
        topics: list[str | list[str] | None] | None = None,
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
            raise self._failed("eth_getLogs failed", exc)
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
