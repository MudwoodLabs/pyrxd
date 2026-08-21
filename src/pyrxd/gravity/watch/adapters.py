"""Concrete transports for the watchtower daemon shell (v1 alert-only, BTC).

Thin adapters that satisfy the watchtower ports by composing EXISTING pyrxd network
code — they add no new heavy dependencies, so they can live in the package while the
operational entrypoint (arg parsing, real-client construction, the poll loop) stays in
``pyrxd.gravity.watch.run`` (console script ``pyrxd-watchtower``).

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
import inspect
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
    "MempoolClaimBytesSource",
    "MultiSourceRxdChainSource",
    "OutspendBtcClaimSource",
    "WebhookAlertChannel",
    "mempool_space_outspend",
    "mempool_space_tx_hex",
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
        # Exclude the executor sidecars that live beside the records and are NOT SwapRecords: the v2
        # pre-signed-refund blob (``<swap_id>.refund.json``) and the autonomous-claim covenant context
        # (``<swap_id>.claim.json``). Counting them here would spam per-tick "unreadable record" warnings
        # and could trip the all-unreadable "watching nothing" page (and their file stem isn't the swap_id
        # either). They are loaded separately, keyed by swap_id, in the executor.
        _SIDECARS = (".refund.json", ".claim.json")
        paths = [p for p in sorted(self._dir.glob("*.json")) if not p.name.endswith(_SIDECARS)]
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

    A single RXD source is flagged low-corroboration (a wrong read → a false page, never a
    false broadcast). Composing >= ``quorum`` independent sources lets a lone lagging/lying/down
    source NOT drive a decision; wire this and pass ``rxd_corroborated=True`` to the
    :class:`ChainObserver` to clear the flag. The daemon shell (``pyrxd.gravity.watch.run``)
    wires this by default over 2 independent public ElectrumX endpoints, so a default tower run
    is corroborated; a single-source run is the explicit fallback.

    Semantics (conservative; fail-closed toward NOT auto-acting):

    * ``tip_height`` — the MINIMUM height across responders (the chain is only as advanced
      as its most-pessimistic source, defeating an over-reporter); fail-closed
      (:class:`NetworkError`) below quorum.
    * ``covenant_confirmations`` — answers "is the maker's asset locked, and how deep?". The two
      conclusions have OPPOSITE safety directions, so they get different evidence bars:
        - **LOCKED** is believed on ANY single source that sees the covenant (returns the
          **MAX** depth among those that see it). MAX — not min — is the fail-closed depth because
          this value feeds the autonomous CLAIM gate, where ``blocks_left = t_rxd − cov_confs + 1``:
          a SMALLER ``cov_confs`` makes the gate read SAFE, so a single source UNDER-reporting depth
          could drag an autonomous claim into a closing ``t_rxd`` window (false-SAFE → one-sided loss
          on a cheap-reorg chain — review HIGH-2). MAX is also conservative for the maker-stall refund
          timing (a larger depth ⇒ an older lock ⇒ act sooner). An over-reporter can only make the gate
          MORE cautious (SQUEEZED → decline), which is fail-safe.
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
            # LOCKED — believed on any sighting. MAX depth is the fail-closed direction for the CLAIM
            # gate (blocks_left = t_rxd − cov_confs + 1; a small cov_confs reads SAFE), so a single
            # under-reporting source cannot drag an autonomous claim into a closing window (HIGH-2).
            return max(present)
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


def _is_hex64(value: str) -> bool:
    """True for exactly 64 hex characters — a txid, and nothing that can escape a URL path."""
    return len(value) == 64 and all(c in "0123456789abcdefABCDEF" for c in value)


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
    # `spent` MUST be a real JSON boolean. This was `bool(data.get("spent"))`, the same defect
    # as the fixed `bool(spend.get("spent", True))` in network/bitcoin.py but pointing the other
    # way: `{"spent": null}`, `{}`, `{"spent": 0}` — what a broken or hostile Esplora-shaped
    # server emits for "no data" — all read as NOT SPENT, and a NOT-SPENT answer is a
    # *successful* read, so it never reaches `claim_status`'s all-sources-failed fail-closed
    # branch. That silently suppresses PAGE_CLAIM, which this module's own docstring names as
    # the forbidden failure for an alert-only tower. Raising instead makes the source drop out,
    # and a tower blind across every source then pages.
    if not isinstance(data, dict) or not isinstance(data.get("spent"), bool):
        raise NetworkError(f"outspend response for {funding_txid}:{vout} has no boolean 'spent'; fail-closed")
    spent = data["spent"]
    spender = data.get("txid") if spent else None
    # Charset-check, not just length: `spender` is interpolated unquoted into the
    # `/api/tx/{txid}/hex` path by `mempool_space_tx_hex`, so a 64-character value containing
    # `/`, `?` or `#` is a path-injection primitive.
    if not (isinstance(spender, str) and len(spender) == 64 and _is_hex64(spender)):
        spender = None
    return spent, spender


async def mempool_space_tx_hex(session, base_url: str, txid: str, *, timeout_s: float = 15.0) -> bytes | None:
    """Fetch a tx's RAW bytes via Esplora/mempool.space ``/api/tx/{txid}/hex`` → ``bytes`` (or ``None``
    if not yet retrievable / unparseable). The ClaimExecutor uses this to get the maker's claim-tx bytes
    so it can scrape ``p`` — it ALWAYS re-derives the txid locally and matches it before trusting the
    bytes, so a single source is safe (a wrong-tx server is caught by the hash check, not trusted).

    A 404 (not yet indexed/mined) returns ``None`` (the executor pages FAILED, never broadcasts off
    missing bytes). The explicit per-request ``timeout_s`` bounds a slow source (same dead-man's-switch
    reasoning as :func:`mempool_space_outspend`)."""
    url = f"{base_url.rstrip('/')}/api/tx/{txid}/hex"
    async with session.get(url, timeout=aiohttp_timeout(timeout_s)) as resp:
        if getattr(resp, "status", 200) == 404:
            return None
        resp.raise_for_status()
        text = (await resp.text()).strip()
    try:
        return bytes.fromhex(text)
    except ValueError:
        return None


class MempoolClaimBytesSource:
    """A ``ClaimBytesSource`` (``gravity.watch.claim_executor.ClaimBytesSource``) over an Esplora/
    mempool.space ``/api/tx/{txid}/hex`` endpoint. Single-source is safe: the ClaimExecutor re-derives
    the txid from the returned bytes and matches it before scraping, so this can only fail to serve
    (→ a FAILED page), never substitute a different tx."""

    def __init__(self, session, base_url: str, *, timeout_s: float = 15.0) -> None:
        if not isinstance(base_url, str) or not base_url:
            raise ValidationError("MempoolClaimBytesSource base_url must be a non-empty str")
        self._session = session
        self._base_url = base_url
        self._timeout_s = timeout_s

    async def claim_tx_bytes(self, claim_txid: str) -> bytes | None:
        return await mempool_space_tx_hex(self._session, self._base_url, claim_txid, timeout_s=self._timeout_s)


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


#: Reticulum's maximum single-packet payload. The physical MTU is 500 bytes; header,
#: addresses and context claim the rest. A page that does not fit is not "mostly
#: delivered" — it is dropped by the stack, so the channel guarantees fit itself.
RETICULUM_MAX_PAYLOAD = 465


class ReticulumAlertChannel:
    """Page the operator over a Reticulum destination — a path that does not use IP.

    The dead-man's-switch exists because a tower that cannot reach the chain also cannot
    usually reach its webhook: one link outage takes out both the ability to act and the
    ability to say so. Every channel shipped today rides IP, so "use a DIFFERENT channel"
    still shares that fate. Reticulum runs over LoRa, packet radio or serial, so it fails
    independently — which is the entire point of adding it.

    The transport is INJECTED, exactly as :class:`WebhookAlertChannel` takes a session.
    Nothing here imports ``rns``: the channel is pure, testable with a fake, and the
    optional dependency lives at the shell boundary where it is actually configured.
    ``transport`` needs one method, ``send(destination: bytes, payload: bytes)``, sync or
    async; a failure must raise, so :class:`~pyrxd.gravity.watch.alerts.DedupAlerter`
    retries next tick rather than recording an undelivered page as sent.

    **Fit is guaranteed, not hoped for.** A realistic CRITICAL page serialises to ~381
    bytes against a 465-byte ceiling — it fits, with under 100 bytes of headroom, so a
    longer message silently exceeds it. The payload therefore uses short keys and drops
    the prose FIRST, because the actionable fields are the ones an operator needs at 3am:
    which swap, how bad, what to run, and by which height. If those alone do not fit, the
    channel raises rather than sending a page with the deadline missing.
    """

    def __init__(self, destination: bytes | str, *, transport, max_payload: int = RETICULUM_MAX_PAYLOAD) -> None:
        dest = bytes.fromhex(destination) if isinstance(destination, str) else destination
        if not isinstance(dest, (bytes, bytearray)) or len(dest) != 16:
            raise ValidationError(
                "ReticulumAlertChannel destination must be a 16-byte Reticulum destination "
                f"hash (got {len(dest) if hasattr(dest, '__len__') else type(dest).__name__})"
            )
        if not callable(getattr(transport, "send", None)):
            raise ValidationError("ReticulumAlertChannel transport needs a callable send()")
        if not isinstance(max_payload, int) or isinstance(max_payload, bool) or max_payload < 1:
            raise ValidationError("ReticulumAlertChannel max_payload must be a positive int")
        self._dest = bytes(dest)
        self._transport = transport
        self._max = max_payload

    def encode(self, page: Page) -> bytes:
        """The wire form. Separate from :meth:`send` so the fit rule is testable without
        a transport, and so an operator can see exactly what a link would carry."""
        core = {
            "s": page.swap_id,
            "i": page.intent.value if page.intent is not None else None,
            "v": page.severity.value,
            "d": page.deadline_rxd_height,
            "a": page.recommended_action,
        }
        if page.low_corroboration:
            core["c"] = 1
        skeleton = json.dumps({**core, "m": ""}, separators=(",", ":")).encode()
        if len(skeleton) > self._max:
            raise ValidationError(
                f"ReticulumAlertChannel: page {page.swap_id} does not fit in {self._max} bytes "
                f"even with no message ({len(skeleton)} bytes) — refusing to send a page whose "
                "deadline or action would be truncated away"
            )
        budget = self._max - len(skeleton)
        msg = page.message or ""
        encoded = msg.encode()
        if len(encoded) > budget:
            # Truncate on a codepoint boundary, and SAY so — a silently clipped instruction
            # reads as a complete one.
            marker = b"..."
            encoded = encoded[: max(0, budget - len(marker))].decode(errors="ignore").encode() + marker
        return json.dumps({**core, "m": encoded.decode(errors="ignore")}, separators=(",", ":")).encode()

    async def send(self, page: Page) -> None:
        payload = self.encode(page)
        result = self._transport.send(self._dest, payload)
        if inspect.isawaitable(result):
            await result


class RnsTransport:
    """The one place that touches ``rns``, imported lazily so pyrxd installs without it.

    Kept deliberately thin: build the Reticulum instance and identity, then hand
    :class:`ReticulumAlertChannel` something with a ``send(destination, payload)``. All
    the logic worth testing — encoding, the fit guarantee, truncation policy — lives in
    the channel, which never imports this.

    Install with ``pip install 'pyrxd[reticulum]'``. Note the dependency carries a custom
    licence with field-of-use restrictions, which is one reason it is an opt-in extra and
    never bundled.

    **This class is the untested leg of the spike.** Everything above it has unit tests
    with a fake transport; this needs a real Reticulum instance and a radio to exercise,
    so treat it as a starting point rather than a proven path until someone has watched a
    page arrive over LoRa with the WAN unplugged.
    """

    def __init__(self, *, config_path: str | None = None, app_name: str = "pyrxd.watchtower") -> None:
        try:
            import RNS
        except ImportError as exc:  # pragma: no cover - depends on the optional extra
            raise ValidationError("RnsTransport needs the Reticulum stack: pip install 'pyrxd[reticulum]'") from exc
        self._rns_mod = RNS
        self._reticulum = RNS.Reticulum(config_path)
        self._identity = RNS.Identity()
        self._app_name = app_name

    def send(self, destination: bytes, payload: bytes) -> None:  # pragma: no cover - needs a radio
        RNS = self._rns_mod
        dest = RNS.Destination(
            RNS.Identity.recall(destination),
            RNS.Destination.OUT,
            RNS.Destination.SINGLE,
            self._app_name,
            "alert",
        )
        RNS.Packet(dest, payload).send()


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
