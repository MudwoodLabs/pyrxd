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

import json
import logging
from collections.abc import Awaitable, Callable
from pathlib import Path

from pyrxd.gravity.swap_state import SwapRecord, is_terminal
from pyrxd.gravity.watch.alerts import Page, Severity
from pyrxd.gravity.watch.quorum import BtcClaimStatus
from pyrxd.security.errors import ValidationError

logger = logging.getLogger(__name__)

__all__ = [
    "CallbackAlertChannel",
    "ElectrumRxdChainSource",
    "JsonDirRecordStore",
    "LoggingAlertChannel",
    "OutspendBtcClaimSource",
    "mempool_space_outspend",
]


class JsonDirRecordStore:
    """``RecordStore`` over a directory of ``SwapRecord`` JSON files (``<swap_id>.json``).

    The swap id is the file stem. Terminal swaps and unreadable/invalid files are
    skipped (the latter logged) — one corrupt file must not blind the tower to the rest.
    Read-only: v1 never writes.
    """

    def __init__(self, records_dir: str | Path) -> None:
        self._dir = Path(records_dir)

    async def list_active(self) -> list[tuple[str, SwapRecord]]:
        out: list[tuple[str, SwapRecord]] = []
        if not self._dir.is_dir():
            logger.warning("watchtower records dir %s does not exist", self._dir)
            return out
        for path in sorted(self._dir.glob("*.json")):
            try:
                rec = SwapRecord.from_dict(json.loads(path.read_text()))
            except Exception:
                logger.warning("skipping unreadable swap record %s", path, exc_info=True)
                continue
            if is_terminal(rec.state):
                continue
            out.append((path.stem, rec))
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


# outspend(funding_txid, vout) -> (spent, spending_txid_or_None)
OutspendFn = Callable[[str, int], Awaitable[tuple[bool, "str | None"]]]


class OutspendBtcClaimSource:
    """``BtcClaimSource`` = an injected outspend backend (claim detection) + a
    ``BtcFundingReader`` for the quorum-agreed depth (wire ``MultiSourceBtcFundingReader``)."""

    def __init__(self, *, outspend_fn: OutspendFn, funding_reader) -> None:
        self._outspend = outspend_fn
        self._reader = funding_reader

    async def claim_status(self, funding_txid: str, funding_vout: int) -> BtcClaimStatus:
        spent, spender = await self._outspend(funding_txid, funding_vout)
        if spent and spender:
            return BtcClaimStatus(claimed=True, claim_txid=spender)
        return BtcClaimStatus(claimed=False)

    async def confirmations(self, claim_txid: str) -> int:
        return int(await self._reader.confirmations(claim_txid))


async def mempool_space_outspend(session, base_url: str, funding_txid: str, vout: int) -> tuple[bool, str | None]:
    """Query mempool.space ``/api/tx/{txid}/outspend/{vout}`` → ``(spent, spending_txid)``.

    ``session`` is an aiohttp ``ClientSession``. Returns the spending txid only when the
    outpoint is spent and the server reports a 64-char txid.
    """
    url = f"{base_url.rstrip('/')}/api/tx/{funding_txid}/outspend/{vout}"
    async with session.get(url) as resp:
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
