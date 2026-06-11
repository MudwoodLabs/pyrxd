"""Concrete transports for the watchtower daemon shell (v1 alert-only, BTC).

Thin adapters that satisfy the watchtower ports by composing EXISTING pyrxd network
code — they add no new heavy dependencies, so they can live in the package while the
operational entrypoint (arg parsing, real-client construction, the poll loop) stays in
``scripts/watchtower_run.py``.

* :class:`JsonDirRecordStore` — discovers the operator's in-flight swaps from a
  directory of ``SwapRecord`` JSON files (the same JSON the coordinator persists),
  skipping terminal swaps and unreadable files.
* :class:`ElectrumRxdChainSource` — ``RxdChainSource`` over any client exposing
  ``get_tip_height()`` + ``get_transaction_verbose(txid)`` (ElectrumXClient, or a thin
  ssh-tr shim). RXD is single-source in v1 (the ``ChainObserver`` flags it).
* :class:`OutspendBtcClaimSource` — ``BtcClaimSource`` from an injected ``outspend``
  callable (claim detection) + a ``BtcFundingReader`` for the quorum-agreed depth
  (wire ``MultiSourceBtcFundingReader`` here). :func:`mempool_space_outspend` is the
  default outspend backend.
* :class:`LoggingAlertChannel` / :class:`CallbackAlertChannel` — the page sinks; the
  callback channel is where the shell plugs an authenticated webhook / push.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
from collections.abc import Awaitable, Callable
from pathlib import Path

from pyrxd.gravity.swap_state import SwapRecord, is_terminal
from pyrxd.gravity.watch.alerts import Page, Severity
from pyrxd.gravity.watch.quorum import BtcClaimStatus
from pyrxd.security.errors import NetworkError, ValidationError

logger = logging.getLogger(__name__)

__all__ = [
    "CallbackAlertChannel",
    "CompositeAlertChannel",
    "ElectrumRxdChainSource",
    "JsonDirRecordStore",
    "LoggingAlertChannel",
    "MultiSourceRxdChainSource",
    "OutspendBtcClaimSource",
    "WebhookAlertChannel",
    "mempool_space_outspend",
    "page_to_dict",
]


def page_to_dict(page: Page) -> dict:
    """Stable JSON shape for a :class:`Page` (the webhook body / dead-man payload)."""
    return {
        "swap_id": page.swap_id,
        "intent": page.intent.value if page.intent is not None else None,
        "severity": page.severity.value,
        "message": page.message,
        "recommended_action": page.recommended_action,
        "deadline_rxd_height": page.deadline_rxd_height,
        "low_corroboration": page.low_corroboration,
    }


class JsonDirRecordStore:
    """``RecordStore`` over a directory of ``SwapRecord`` JSON files (``<swap_id>.json``).

    The swap id is the file stem. ONE corrupt file is skipped (logged) — it must not blind the
    tower to the rest. But two BLIND conditions RAISE (red-team MEDIUM — the reconciler turns a
    raise into a PAGE, so "watching nothing" can never masquerade as a healthy swaps=0 tick):
      * the records dir does not exist (typo / unmounted / wrong path);
      * files are present but EVERY one is unreadable (we can read none of them).
    A genuinely empty existing dir returns ``[]`` (0 swaps, healthy). Read-only: v1 never writes.
    """

    def __init__(self, records_dir: str | Path) -> None:
        self._dir = Path(records_dir)

    async def list_active(self) -> list[tuple[str, SwapRecord]]:
        if not self._dir.is_dir():
            raise NetworkError(
                f"watchtower records dir {self._dir} does not exist (typo/unmounted?) — refusing to "
                "report 0 swaps as healthy"
            )
        out: list[tuple[str, SwapRecord]] = []
        # Exclude v2 pre-signed-refund sidecars (``<swap_id>.refund.json``): they live beside the
        # records (the default --refund-blobs-dir) and are NOT SwapRecords, so counting them here would
        # spam per-tick "unreadable record" warnings and could trip the all-unreadable "watching nothing"
        # page. They are loaded separately, keyed by swap_id, in the executor.
        paths = [p for p in sorted(self._dir.glob("*.json")) if not p.name.endswith(".refund.json")]
        failed = 0
        for path in paths:
            try:
                rec = SwapRecord.from_dict(json.loads(path.read_text()))
            except Exception:
                failed += 1
                logger.warning("skipping unreadable swap record %s", path, exc_info=True)
                continue
            if is_terminal(rec.state):
                continue
            out.append((path.stem, rec))
        if failed and failed == len(paths):
            # Every record present failed to parse → we are BLIND, not "0 active". Page.
            raise NetworkError(f"all {failed} record(s) in {self._dir} are unreadable — the tower is watching nothing")
        return out


class ElectrumRxdChainSource:
    """``RxdChainSource`` over a client with ``get_tip_height()`` +
    ``get_transaction_verbose(txid) -> dict`` (with a ``confirmations`` field)."""

    def __init__(self, client) -> None:
        self._c = client

    async def tip_height(self) -> int:
        # A failure here propagates → the reconciler fails closed (PAGE_SQUEEZED), which is
        # correct: a down RXD node during a swap must alert, not silently watch.
        return int(await self._c.get_tip_height())

    async def covenant_confirmations(self, outpoint: str) -> int | None:
        txid = outpoint.split(":", 1)[0]
        try:
            verbose = await self._c.get_transaction_verbose(txid)
        except Exception:
            # tip_height (called first in observe) already surfaced a down node; reaching
            # here with a lookup failure means the covenant tx is not resolvable yet
            # (unmined) → None (no lock height), which the gate treats fail-closed.
            logger.debug("covenant tx %s not resolvable yet", txid, exc_info=True)
            return None
        confs = verbose.get("confirmations")
        if not isinstance(confs, int) or isinstance(confs, bool) or confs < 1:
            return None
        return confs


class MultiSourceRxdChainSource:
    """Quorum ``RxdChainSource`` over N INDEPENDENT Radiant readers (the operator's own
    node + public ElectrumX servers), mirroring :class:`network.bitcoin.MultiSourceBtcFundingReader`.

    RXD reads are single-source in v1, so every observation is flagged low-corroboration
    (a wrong read → a false page, never a false broadcast). Composing >= ``quorum``
    independent sources lets a lone lagging/lying/down source NOT drive a decision; wire
    this and pass ``rxd_corroborated=True`` to the :class:`ChainObserver` to clear the flag.

    Semantics (conservative; fail-closed toward NOT auto-acting):

    * ``tip_height`` — the MINIMUM height across responders (the chain is only as advanced
      as its most-pessimistic source, defeating an over-reporter); fail-closed
      (:class:`NetworkError`) below quorum.
    * ``covenant_confirmations`` — answers "is the maker's asset locked?", which gates the
      autonomous BTC refund (``None`` ⇒ not locked ⇒ refund-eligible). The two conclusions
      have OPPOSITE safety directions, so they get different evidence bars:
        - **LOCKED** is believed on ANY single source that sees the covenant (returns the
          MIN depth among those that see it) — refusing to refund is the safe error.
        - **NOT locked** (``None``, which ENABLES a broadcast) is returned ONLY when
          >= ``quorum`` sources were provably REACHABLE this cycle (their ``tip_height``
          succeeded) AND none saw the covenant — a corroborated absence.
        - otherwise (too few reachable sources to corroborate absence) it raises
          :class:`NetworkError`, which the reconciler turns into a PAGE, never a refund.
      The reachability gate closes the absent-vs-unreachable trap: the underlying adapters
      map both "unmined" and "unreachable" to ``None``, so a down source could otherwise
      masquerade as "the asset is not locked" → a wrongful autonomous refund. Only a source
      that proved reachable (tip read OK) may cast an "absent" vote.

    A failing source is dropped from each read; if that drops the responding/reachable count
    below quorum, the read fails closed as above.
    """

    def __init__(self, sources: list, *, quorum: int = 2) -> None:
        sources = list(sources)
        if quorum < 1:
            raise ValidationError("quorum must be >= 1")
        if len(sources) < quorum:
            raise ValidationError(f"need at least quorum={quorum} RXD sources, got {len(sources)}")
        self._sources = sources
        self._quorum = quorum

    @property
    def corroborated(self) -> bool:
        """True iff this is a genuine multi-source quorum (>= 2 sources AND quorum >= 2).

        The :class:`ChainObserver` reads this to STRUCTURALLY justify ``rxd_corroborated=True``
        — so corroboration cannot be asserted over a single source (audit LOW-R2). A single
        source (or quorum 1) is not corroboration however the flag is set.
        """
        return self._quorum >= 2 and len(self._sources) >= self._quorum

    async def _gather(self, coro_fn) -> list:
        """Run ``coro_fn`` on every source; return only the successful (non-Exception)
        results. A failing source is dropped — it never fails the whole read."""
        results = await asyncio.gather(*(coro_fn(s) for s in self._sources), return_exceptions=True)
        return [x for x in results if not isinstance(x, Exception)]

    async def tip_height(self) -> int:
        oks = [int(h) for h in await self._gather(lambda s: s.tip_height())]
        if len(oks) < self._quorum:
            raise NetworkError(
                f"RXD tip height corroborated by only {len(oks)} source(s); require "
                f"quorum={self._quorum} of {len(self._sources)}. Fail-closed."
            )
        return min(oks)  # only as advanced as the most-pessimistic source

    async def _live_and_covenant(self, src, outpoint: str) -> tuple[bool, int | None]:
        """``(reachable, covenant_depth_or_None)`` for one source. Reachability is proven by
        a successful ``tip_height``; ONLY a reachable source may later count as an "absent"
        vote (a down node's ``None`` must never read as "the asset is not locked")."""
        try:
            await src.tip_height()
        except Exception:
            return (False, None)  # unreachable → no vote on covenant presence/absence
        try:
            depth = await src.covenant_confirmations(outpoint)
        except Exception:
            depth = None
        if depth is not None and (not isinstance(depth, int) or isinstance(depth, bool) or depth < 1):
            depth = None
        return (True, depth)

    async def covenant_confirmations(self, outpoint: str) -> int | None:
        results = await asyncio.gather(
            *(self._live_and_covenant(s, outpoint) for s in self._sources), return_exceptions=True
        )
        ok = [r for r in results if not isinstance(r, Exception)]
        present = [d for (_live, d) in ok if d is not None]
        reachable = sum(1 for (live, _d) in ok if live)
        if present:
            return min(present)  # LOCKED — believed on any sighting; conservative (min) depth
        if reachable >= self._quorum:
            return None  # >= quorum reachable sources, none saw it → corroborated NOT locked
        raise NetworkError(
            f"RXD covenant lock status uncorroborated: only {reachable} reachable source(s) "
            f"< quorum={self._quorum}; fail-closed (refusing to conclude 'not locked')."
        )

    async def close(self) -> None:
        await asyncio.gather(*(s.close() for s in self._sources if hasattr(s, "close")), return_exceptions=True)


# outspend(funding_txid, vout) -> (spent, spending_txid_or_None)
OutspendFn = Callable[[str, int], Awaitable[tuple[bool, "str | None"]]]


class OutspendBtcClaimSource:
    """``BtcClaimSource`` = injected outspend backend(s) (claim DETECTION) + a ``BtcFundingReader``
    for the quorum-agreed depth (wire ``MultiSourceBtcFundingReader``).

    Multi-source detection (red-team MEDIUM): the maker-claim DETECTION boolean is the trigger that
    arms the whole claim-race assessment, so a SINGLE lagging/lying/MITM'd ``/outspend`` source that
    reports "unspent" silently SUPPRESSES the PAGE_CLAIM — the worst failure for an alert-only tower.
    Pass several INDEPENDENT outspend backends (the same Esplora set used for depth): detection then
    fails TOWARD paging — if ANY source sees the outpoint spent (with a txid) we treat it as claimed
    (a missed claim is the real harm; a false page is cheap — the operator just verifies, and the
    DEPTH read below is still the conservative quorum-min, so a single lying "spent" cannot fake
    reorg-safety into a SAFE auto-claim). If EVERY detection source errors we fail closed (raise →
    the reconciler pages a decision-required), never a silent "unspent". One source still works
    (degrades to v1 behaviour)."""

    def __init__(self, *, outspend_fn: OutspendFn | None = None, outspend_fns=None, funding_reader) -> None:
        fns = list(outspend_fns) if outspend_fns is not None else ([outspend_fn] if outspend_fn is not None else [])
        if not fns:
            raise ValidationError("OutspendBtcClaimSource requires outspend_fn or a non-empty outspend_fns")
        self._outspends = fns
        self._reader = funding_reader

    async def claim_status(self, funding_txid: str, funding_vout: int) -> BtcClaimStatus:
        errors: list[Exception] = []
        for outspend in self._outspends:
            try:
                spent, spender = await outspend(funding_txid, funding_vout)
            except Exception as exc:  # one source down must not blind detection
                errors.append(exc)
                logger.warning("claim-detection source failed for %s:%d: %r", funding_txid, funding_vout, exc)
                continue
            if spent and spender:
                return BtcClaimStatus(claimed=True, claim_txid=spender)
        if errors and len(errors) == len(self._outspends):
            # Every independent detection source failed → blind to the claim. Fail-closed.
            raise NetworkError(f"all {len(errors)} claim-detection source(s) failed: {errors[0]!r}")
        return BtcClaimStatus(claimed=False)

    async def confirmations(self, claim_txid: str) -> int:
        return int(await self._reader.confirmations(claim_txid))

    async def funding_confirmations(self, funding_txid: str) -> int | None:
        """Funding-tx depth via the SAME quorum reader (conservative min). Returns ``None`` if the read
        fails (down/unknown) so decide() fails closed (no autonomous refund) instead of guessing — a
        genuine 0 (unconfirmed) is returned as 0 and the maturity gate keeps watching."""
        try:
            return int(await self._reader.confirmations(funding_txid))
        except Exception:
            logger.debug("funding-depth read failed for %s", funding_txid, exc_info=True)
            return None


async def mempool_space_outspend(
    session, base_url: str, funding_txid: str, vout: int, *, timeout_s: float = 15.0
) -> tuple[bool, str | None]:
    """Query an Esplora/mempool.space ``/api/tx/{txid}/outspend/{vout}`` → ``(spent, spending_txid)``.

    ``session`` is an aiohttp ``ClientSession``. Returns the spending txid only when the outpoint is
    spent and the server reports a 64-char txid. An explicit per-REQUEST ``timeout_s`` (red-team LOW)
    bounds a slow source: without it the call inherits aiohttp's 300s session default, so one slow
    Esplora can outlast the dead-man's-switch window and trip a false "tower DOWN" page.
    """
    url = f"{base_url.rstrip('/')}/api/tx/{funding_txid}/outspend/{vout}"
    async with session.get(url, timeout=aiohttp_timeout(timeout_s)) as resp:
        resp.raise_for_status()
        data = await resp.json()
    spent = bool(data.get("spent"))
    spender = data.get("txid") if spent else None
    if not (isinstance(spender, str) and len(spender) == 64):
        spender = None
    return spent, spender


class LoggingAlertChannel:
    """An ``AlertChannel`` that logs each page at a severity-mapped level. Always
    available; the dead-man's-switch monitor can tail this log."""

    _LEVELS = {Severity.INFO: logging.INFO, Severity.WARN: logging.WARNING, Severity.CRITICAL: logging.ERROR}

    def __init__(self, logger_: logging.Logger | None = None) -> None:
        self._log = logger_ or logging.getLogger("pyrxd.watchtower.alerts")

    async def send(self, page: Page) -> None:
        self._log.log(self._LEVELS.get(page.severity, logging.INFO), "WATCHTOWER %s", page.message)


class CallbackAlertChannel:
    """An ``AlertChannel`` delegating to an injected ``async (Page) -> None`` — where the
    shell plugs an authenticated webhook / push. A send failure propagates so the
    :class:`~pyrxd.gravity.watch.alerts.DedupAlerter` retries it next tick."""

    def __init__(self, send_fn: Callable[[Page], Awaitable[None]]) -> None:
        if not callable(send_fn):
            raise ValidationError("CallbackAlertChannel requires a callable send_fn")
        self._fn = send_fn

    async def send(self, page: Page) -> None:
        await self._fn(page)


class WebhookAlertChannel:
    """POSTs each page as JSON to a webhook (ntfy / Pushover / Slack / custom).

    Authenticity / tamper-evidence: an optional ``auth_header`` (e.g. a bearer token)
    and/or an HMAC-SHA256 signature over the exact body bytes (``hmac_secret``), sent as
    ``X-Watchtower-Signature: sha256=<hex>`` so the receiver can verify the page came
    from the tower and was not altered. A non-2xx response raises (the
    :class:`~pyrxd.gravity.watch.alerts.DedupAlerter` then retries next tick — dedup
    advances only on a successful send). ``session`` is an injected aiohttp ClientSession.
    """

    def __init__(
        self,
        url: str,
        *,
        session,
        auth_header: dict[str, str] | None = None,
        hmac_secret: bytes | str | None = None,
        timeout_s: float = 10.0,
    ) -> None:
        if not isinstance(url, str) or not url:
            raise ValidationError("WebhookAlertChannel requires a non-empty url")
        self._url = url
        self._session = session
        self._headers = dict(auth_header or {})
        self._secret = hmac_secret.encode() if isinstance(hmac_secret, str) else hmac_secret
        self._timeout_s = timeout_s

    async def send(self, page: Page) -> None:
        body = json.dumps(page_to_dict(page), separators=(",", ":")).encode()
        headers = {"Content-Type": "application/json", **self._headers}
        if self._secret:
            sig = hmac.new(self._secret, body, hashlib.sha256).hexdigest()
            headers["X-Watchtower-Signature"] = f"sha256={sig}"
        timeout = aiohttp_timeout(self._timeout_s)
        async with self._session.post(self._url, data=body, headers=headers, timeout=timeout) as resp:
            resp.raise_for_status()


def aiohttp_timeout(seconds: float):
    """A ClientTimeout if aiohttp is importable, else the bare number (so the channel is
    importable/testable without aiohttp installed; the real session interprets either)."""
    try:
        import aiohttp

        return aiohttp.ClientTimeout(total=seconds)
    except Exception:  # pragma: no cover - aiohttp is a dep in practice
        return seconds


class CompositeAlertChannel:
    """Fan a page out to several channels (e.g. log + webhook). Sends to ALL, then raises
    the first error if any failed — so a webhook outage still logs locally, and the
    DedupAlerter retries (re-sending to all; a duplicate log line is the only cost)."""

    def __init__(self, *channels) -> None:
        if not channels:
            raise ValidationError("CompositeAlertChannel requires at least one channel")
        self._channels = channels

    async def send(self, page: Page) -> None:
        first_error: Exception | None = None
        for ch in self._channels:
            try:
                await ch.send(page)
            except Exception as exc:
                logger.warning("alert channel %s failed: %r", type(ch).__name__, exc)
                if first_error is None:
                    first_error = exc
        if first_error is not None:
            raise first_error
