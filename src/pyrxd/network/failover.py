"""Request-level failover across a network's ElectrumX endpoints.

The gap this closes
-------------------
:class:`~pyrxd.network.electrumx.ElectrumXClient` races its URLs **at connect
time** and then sticks to the winner: once the socket is up, a server that goes
away mid-session fails the call, and its own docstring is explicit that "there is
no in-call retry; callers that want retry semantics should layer it above
``_call``". Nothing layered it. So a single unreachable server was a hard outage
for every wallet operation.

This module is that layer, and it is strictly *above* the transport: it owns one
:class:`ElectrumXClient` per endpoint and, when a call fails with a transport
error, retries the same call against the next endpoint. Nothing is bolted into
the reader loop, the id-correlation map, or ``_call`` — those keep their existing
single-connection semantics exactly.

Chain binding
-------------
Each endpoint is verified with :meth:`ElectrumXClient.assert_chain` the first time
it is used (when the profile carries a genesis hash). Failing over to a server
that is on a *different chain* would be worse than the outage it is avoiding, so
a chain mismatch is **not** treated as a failover-able fault: it raises. An
endpoint listed under ``[networks.regtest]`` that answers with mainnet's genesis
is a configuration error or an attack, and quietly skipping it would hide both.

What is retried, and what is not
--------------------------------
* **Reads** (balance, utxos, history, headers, transaction fetches) — retried.
  They are pure queries; repeating one has no effect beyond a second round trip.
* **``broadcast``** — retried, but under strict conditions. See the long comment
  on :meth:`FailoverElectrumXClient.broadcast`; this is the one call where getting
  the retry rule wrong can cost money.
* **``call_extension``** — NOT retried by default. It reaches arbitrary indexer
  RPCs whose side effects this module cannot know. Callers that know a specific
  extension method is a pure read opt in with ``idempotent=True``.
* **Node verdicts** (:class:`~pyrxd.security.errors.PolicyRejection`) — never
  retried, on any method. "Your transaction is invalid / underpriced / already
  known" is an answer, not a failure; re-asking a different node mostly produces
  the same answer, and shopping for a node that likes a rejected transaction is
  the opposite of what a failover layer should do.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from typing import Any, TypeVar

from ..hash import double_sha256
from ..merkle_path import MerklePath
from ..security.errors import NetworkError, PolicyRejection, TlsPinMismatchError, ValidationError
from ..security.types import BlockHeight, Hex32, Photons, RawTx, Txid
from .electrumx import ElectrumXClient, UtxoRecord
from .registry import Endpoint, NetworkProfile

logger = logging.getLogger(__name__)

__all__ = ["FailoverElectrumXClient"]

_T = TypeVar("_T")

_DEFAULT_TIMEOUT: float = 30.0

# Node reject reasons that mean "I already have this exact transaction". Verified
# against Radiant-Core @ tag v3.1.2 (the pin in tests/vendor/radiant_core/MANIFEST.json):
#   src/validation.cpp:605          -> "txn-already-in-mempool"
#   src/validation.cpp:692          -> "txn-already-known"
#   src/node/transaction.cpp:69-70  -> RPC_TRANSACTION_ALREADY_IN_CHAIN (-27),
#                                      "transaction already in block chain"
_ALREADY_HAVE_MARKERS: tuple[str, ...] = (
    "txn-already-in-mempool",
    "txn-already-known",
    "already in block chain",
)
_ALREADY_HAVE_CODE: int = -27


def _is_already_have(exc: PolicyRejection) -> bool:
    """True when a rejection means the node already holds this exact transaction."""
    if exc.code == _ALREADY_HAVE_CODE:
        return True
    reason = (exc.reason or "").lower()
    return any(marker in reason for marker in _ALREADY_HAVE_MARKERS)


def _txid_of(raw_tx: bytes) -> Txid:
    """Radiant txid for *raw_tx*: SHA-256d of the serialised transaction, reversed.

    Same derivation as :meth:`pyrxd.transaction.transaction.Transaction.txid`. Note
    this is NOT the block-header hash function (Radiant uses double SHA-512/256
    there — see :func:`pyrxd.network.registry.block_hash_hex`); transaction ids
    stayed SHA-256d.
    """
    return Txid(double_sha256(bytes(raw_tx))[::-1].hex())


class FailoverElectrumXClient:
    """An :class:`ElectrumXClient`-shaped facade that fails over between endpoints.

    Drop-in for the read/broadcast surface the SDK and CLI actually use, so callers
    written against ``ElectrumXClient`` keep working unchanged.

    Parameters
    ----------
    profile:
        The network's endpoint list (preference-ordered) plus its expected genesis
        hash. Build one with :meth:`NetworkProfile.build`.
    timeout:
        Per-request timeout handed to each underlying client (default 30s). Note
        the worst case for one logical call is ``timeout * len(endpoints)``.
    client_factory:
        Injected seam: ``Endpoint -> ElectrumXClient``. Tests pass fakes; production
        leaves it ``None`` and gets real clients.
    verify_chain:
        Verify each endpoint's genesis hash on first use (default ``True``). Only
        turn this off for a chain pyrxd has no constant for — and then you are
        trusting the URL, which is what got us here. Leaving it ``True`` for a
        profile that carries no genesis hash is a construction error and raises:
        the check must never silently become a no-op.

    Notes
    -----
    A **single-endpoint** profile is supported and degenerates to plain
    ``ElectrumXClient`` behaviour: nothing to fail over to, so a transport error
    surfaces to the caller exactly as before (plus the one-time chain check).
    Configuring exactly one endpoint therefore remains the documented way to get
    the old, no-failover behaviour.
    """

    def __init__(
        self,
        profile: NetworkProfile,
        *,
        timeout: float = _DEFAULT_TIMEOUT,
        client_factory: Callable[[Endpoint], ElectrumXClient] | None = None,
        verify_chain: bool = True,
    ) -> None:
        if not isinstance(profile, NetworkProfile):
            raise ValidationError(f"profile must be a NetworkProfile, got {type(profile).__name__}")
        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValidationError("timeout must be a positive number")
        if verify_chain and profile.genesis_hash is None:
            # Fail CLOSED. `_client_for` used to skip `assert_chain` outright when the
            # profile had no genesis hash, so "pyrxd has no constant for this chain"
            # silently degraded into "do not verify the chain at all" — the one check
            # that catches a regtest-labelled config pointed at a mainnet server. A
            # check that quietly turns itself off is worse than no check, because it
            # is believed. Callers who really are on a chain pyrxd has no constant for
            # must say so with `verify_chain=False` and own that decision.
            raise ValidationError(
                f"no genesis hash is known for network {profile.network!r}, so this client's "
                "endpoints cannot be verified to be on the chain you asked for. Use one of the "
                "networks pyrxd ships a genesis constant for, or pass verify_chain=False to "
                "accept an unverified chain binding explicitly."
            )
        self._profile = profile
        self._timeout = float(timeout)
        self._factory = client_factory or self._default_factory
        self._verify_chain = bool(verify_chain)
        # Mutable preference order: a working endpoint is promoted to the front so
        # the next call does not re-pay the timeout on a known-dead primary.
        self._order: list[Endpoint] = list(profile.endpoints)
        self._clients: dict[str, ElectrumXClient] = {}
        self._chain_verified: set[str] = set()
        self._lock = asyncio.Lock()

    # ------------------------------------------------------------------ properties

    @property
    def profile(self) -> NetworkProfile:
        return self._profile

    @property
    def urls(self) -> tuple[str, ...]:
        """Endpoint URLs in current preference order."""
        return tuple(endpoint.url for endpoint in self._order)

    @property
    def active_url(self) -> str:
        """The endpoint the next call will try first."""
        return self._order[0].url

    # ------------------------------------------------------------------ lifecycle

    async def __aenter__(self) -> FailoverElectrumXClient:
        # Deliberately lazy: connecting eagerly would make an unreachable primary
        # fail at `async with` time, before the failover logic ever runs.
        return self

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        await self.close()

    async def close(self) -> None:
        """Close every underlying client. Safe to call more than once."""
        clients = list(self._clients.values())
        self._clients.clear()
        self._chain_verified.clear()
        for client in clients:
            try:
                await client.close()
            except Exception:  # best-effort teardown; a close error is not actionable
                logger.debug("error closing an ElectrumX client (ignored)")

    # ------------------------------------------------------------------ read surface

    async def get_transaction(self, txid: Txid) -> RawTx:
        return await self._run("get_transaction", lambda c: c.get_transaction(txid))

    async def get_transaction_verbose(self, txid: Txid) -> dict[str, Any]:
        return await self._run("get_transaction_verbose", lambda c: c.get_transaction_verbose(txid))

    async def get_transaction_merkle(self, txid: Txid, height: BlockHeight) -> MerklePath:
        return await self._run("get_transaction_merkle", lambda c: c.get_transaction_merkle(txid, height))

    async def get_balance(self, script_hash: Hex32 | bytes | str) -> tuple[Photons, Photons]:
        return await self._run("get_balance", lambda c: c.get_balance(script_hash))

    async def get_utxos(self, script_hash: Hex32 | bytes | str) -> list[UtxoRecord]:
        return await self._run("get_utxos", lambda c: c.get_utxos(script_hash))

    async def get_history(self, script_hash: Hex32 | bytes | str) -> list[dict]:
        return await self._run("get_history", lambda c: c.get_history(script_hash))

    async def get_block_header(self, height: BlockHeight) -> bytes:
        return await self._run("get_block_header", lambda c: c.get_block_header(height))

    async def get_tip_height(self) -> BlockHeight:
        return await self._run("get_tip_height", lambda c: c.get_tip_height())

    async def call_extension(self, method: str, params: list | None = None, *, idempotent: bool = False) -> Any:
        """Call an indexer-extension RPC.

        NOT retried unless *idempotent* is set. This method is an escape hatch onto
        arbitrary server methods; a failover layer has no way to know whether
        replaying ``some.extension.method`` is harmless. Defaulting to "retry"
        would be exactly the blind retry of a possibly-non-idempotent call that
        this module is careful to avoid. Pass ``idempotent=True`` for a read
        (``glyph.get_token``, ``wave.resolve``, ...).
        """
        return await self._run(
            f"call_extension:{method}",
            lambda c: c.call_extension(method, params),
            retryable=idempotent,
        )

    async def assert_chain(self, expected_genesis_hash: str) -> str:
        """Verify the active endpoint's chain. Failover applies (a dead endpoint is skipped)."""
        return await self._run("assert_chain", lambda c: c.assert_chain(expected_genesis_hash))

    # ------------------------------------------------------------------ broadcast

    async def broadcast(self, raw_tx: bytes) -> Txid:
        """Broadcast *raw_tx*, retrying the SAME BYTES on the next endpoint after a
        transport failure.

        Why retrying a broadcast is safe here — and what makes it unsafe elsewhere
        --------------------------------------------------------------------------
        A broadcast is not a pure read, so "just retry it" deserves an argument
        rather than a shrug. Three properties make this specific retry safe:

        1. **The bytes are captured once, before the first attempt.** Every retry
           replays the identical serialised transaction. The dangerous version of
           this feature would take a *builder callback* and re-run it on failure:
           a rebuild can select different UTXOs, a different fee, or produce a
           different signature, and broadcasting a *different* transaction that
           spends the same inputs is a double-spend attempt, not a retry. Radiant
           has no RBF — ``src/validation.cpp:667`` rejects any mempool conflict
           outright as ``txn-mempool-conflict`` — so a conflicting sibling cannot
           replace the first transaction, but it CAN be the one that gets mined
           and strand the transaction the caller believes it sent. Hence: bytes in,
           bytes out, never a rebuild. The signature is ``broadcast(raw_tx: bytes)``
           precisely so this class *cannot* rebuild anything.

        2. **The transaction id is a pure function of those bytes**
           (``SHA-256d(raw)`` reversed), so a retry cannot change the identity of
           what was sent. Whichever endpoint accepts it, the caller gets the same
           txid — there is no "which node's answer do I believe?" question.

        3. **Only transport failures trigger the retry.** A
           :class:`~pyrxd.security.errors.PolicyRejection` — the node evaluated the
           transaction and said no — is returned to the caller immediately. Asking
           a second node to accept a transaction the first one rejected is not
           resilience; it is looking for a node with laxer rules, and it would
           bury the reject reason that makes the failure diagnosable.

        The failure this actually fixes is the **lost response**: the node accepted
        the transaction and the socket died before the reply arrived. Retrying then
        is not just safe, it is necessary — otherwise the caller reports failure for
        a transaction that is live on the network. When a later endpoint answers
        "I already have this" (``txn-already-known`` / ``txn-already-in-mempool`` /
        already-in-chain), that is treated as **success** — but only after the claim is
        **corroborated by a read** (:meth:`_holds_tx`): the endpoint must serve the same
        bytes back. An uncorroborated ``-27`` is a claim any hostile or broken server can
        make for free, and honoring it reports a live transaction where there is none.

        That last conversion applies only to a *retry*. On the very first attempt an
        "already known" rejection still raises, unchanged — there the caller is
        broadcasting something the network already has without any transport fault
        to explain it, which is information worth surfacing rather than swallowing.
        """
        validated = RawTx(raw_tx)  # validate + freeze the bytes ONCE — see (1) above
        payload = bytes(validated)
        expected_txid = _txid_of(payload)

        last_exc: Exception | None = None
        attempted = 0
        for endpoint in self._candidates():
            try:
                client = await self._client_for(endpoint)
                result = await client.broadcast(payload)
            except PolicyRejection as exc:
                if attempted > 0 and _is_already_have(exc):
                    # "I already have this" is a CLAIM, not evidence (audit B6). Corroborate it
                    # with a READ before honoring it: ask this endpoint for the transaction and
                    # require the bytes back to be the ones we sent. Without that, a hostile or
                    # broken secondary answering every broadcast with RPC -27 made this method
                    # report SUCCESS for a transaction no node ever accepted — the caller then
                    # polls for a ghost, and a swap driver believes a leg is locked when nothing
                    # is on-chain. A node that cannot produce what it claims to hold is skipped
                    # like any other failure (fail-closed), never honored.
                    if await self._holds_tx(endpoint, expected_txid, payload):
                        logger.info(
                            "broadcast: %s already has tx %s after a transport failure elsewhere "
                            "(corroborated by a read-back) — treating as success",
                            endpoint.url,
                            expected_txid,
                        )
                        self._promote(endpoint)
                        return expected_txid
                    last_exc = exc
                    attempted += 1
                    logger.warning(
                        "broadcast: %s claimed to already have tx %s but could NOT produce it on read-back; "
                        "refusing to report success — next endpoint",
                        endpoint.url,
                        expected_txid,
                    )
                    continue
                raise  # a node verdict is an answer, not a failure — see (3) above
            except TlsPinMismatchError:
                raise  # a substituted server must never be silently routed around
            except NetworkError as exc:
                last_exc = exc
                attempted += 1
                logger.warning("broadcast failed on %s (%s); next endpoint", endpoint.url, type(exc).__name__)
                await self._discard(endpoint)
                continue
            if str(result) != str(expected_txid):
                # The txid is a pure function of the bytes we sent; a server that
                # returns a different one is either broken or answering about some
                # other transaction. Refuse to hand that value back to a caller who
                # will use it to poll for confirmation — and do NOT promote a server
                # that just demonstrated it answers about the wrong transaction.
                raise NetworkError(f"ElectrumX returned txid {result} for a transaction whose id is {expected_txid}")
            self._promote(endpoint)
            return expected_txid
        raise NetworkError(f"broadcast failed on all {len(self._order)} ElectrumX endpoint(s)") from last_exc

    async def _holds_tx(self, endpoint: Endpoint, expected_txid: Txid, payload: bytes) -> bool:
        """Does *endpoint* really hold the transaction it just claimed to already have?

        Fail-closed corroboration for the ``already-have``-after-a-transport-failure branch of
        :meth:`broadcast`. The endpoint must return, on a plain read, bytes identical to what we
        sent — which is exactly the statement "this transaction is out there" that the branch
        converts into a success. Anything else (no read surface, an error, different bytes) is
        ``False``: the claim is not honored.

        Residual, stated plainly: this makes an endpoint corroborate its own claim, so a fully
        hostile endpoint that both rejects with ``-27`` and echoes the bytes back still passes.
        What it removes is the far cheaper failure — a broken or lazily-hostile server whose
        ``-27`` is not backed by any transaction at all — and it costs one read on a path that
        has already failed once. Corroboration across INDEPENDENT sources is the operator's job
        (see :class:`pyrxd.network.bitcoin.MultiSourceBtcFundingReader` for that shape).
        """
        try:
            client = await self._client_for(endpoint)
        except Exception:
            return False
        read = getattr(client, "get_transaction", None)
        if not callable(read):
            logger.warning(
                "broadcast: %s has no get_transaction read surface, so its 'already known' claim "
                "cannot be corroborated; fail-closed",
                endpoint.url,
            )
            return False
        try:
            raw = await read(expected_txid)
        except Exception:
            return False
        return bytes(raw) == bytes(payload)

    # ------------------------------------------------------------------ internals

    def _default_factory(self, endpoint: Endpoint) -> ElectrumXClient:
        return ElectrumXClient(
            [endpoint.url],
            allow_insecure=endpoint.allow_insecure,
            timeout=self._timeout,
            spki_pins=endpoint.spki_pins,
        )

    def _candidates(self) -> list[Endpoint]:
        """Snapshot of the endpoints to try, in preference order."""
        return list(self._order)

    def _promote(self, endpoint: Endpoint) -> None:
        """Make *endpoint* the primary for subsequent calls (sticky failover)."""
        if self._order and self._order[0].key == endpoint.key:
            return
        remaining = [e for e in self._order if e.key != endpoint.key]
        self._order = [endpoint, *remaining]

    async def _client_for(self, endpoint: Endpoint) -> ElectrumXClient:
        """Return (creating if needed) the chain-verified client for *endpoint*."""
        genesis = self._profile.genesis_hash if self._verify_chain else None
        async with self._lock:
            client = self._clients.get(endpoint.key)
            if client is None:
                client = self._factory(endpoint)
                self._clients[endpoint.key] = client
            needs_check = genesis is not None and endpoint.key not in self._chain_verified
        if needs_check and genesis is not None:
            # Outside the lock: a genesis read is a network round trip, and holding
            # the creation lock across it would serialise every concurrent caller.
            # A duplicate check under a race costs one extra cheap read, nothing more.
            await client.assert_chain(genesis)
            self._chain_verified.add(endpoint.key)
        return client

    async def _discard(self, endpoint: Endpoint) -> None:
        """Close and forget the client for *endpoint* after a transport failure."""
        client = self._clients.pop(endpoint.key, None)
        self._chain_verified.discard(endpoint.key)
        if client is None:
            return
        try:
            await client.close()
        except Exception:  # the endpoint is already known-bad; a close error adds nothing
            logger.debug("error closing failed ElectrumX client (ignored)")

    async def _run(
        self,
        description: str,
        op: Callable[[ElectrumXClient], Awaitable[_T]],
        *,
        retryable: bool = True,
    ) -> _T:
        """Run *op* against the preferred endpoint, failing over on transport errors.

        ``PolicyRejection`` and ``ValidationError`` (which is what a chain-binding
        mismatch raises) propagate immediately — neither is a transport fault, and
        both mean "trying another server is the wrong move".
        """
        last_exc: Exception | None = None
        for endpoint in self._candidates():
            try:
                client = await self._client_for(endpoint)
                result = await op(client)
            except PolicyRejection:
                raise
            except TlsPinMismatchError:
                raise  # a substituted server must never be silently routed around
            except NetworkError as exc:
                last_exc = exc
                logger.warning("%s failed on %s (%s)", description, endpoint.url, type(exc).__name__)
                await self._discard(endpoint)
                if not retryable:
                    raise
                continue
            self._promote(endpoint)
            return result
        raise NetworkError(f"{description} failed on all {len(self._order)} ElectrumX endpoint(s)") from last_exc
