"""An interrupted BTC fund, seen by the watchtower (#842).

``SwapCoordinator.taker_funds_btc`` writes the signed funding transaction to the record
(``pending_btc_funding_tx``) BEFORE it broadcasts, and replaces it with the locator once the lock
confirms. A fund that is interrupted in between (the runner died, or its read-back failed after the
broadcast) leaves a NEGOTIATED record whose BTC may be on chain. Until #842 the tower read that record
as "no action due", so a maker claim with ``p`` on that HTLC went unobserved.

The tower now treats such a record as an UNRECORDED lock:

* the HTLC outpoint is output 0 of the record's own bytes, checked against the HTLC the terms describe
  (:func:`~pyrxd.btc_wallet.htlc_leg.recorded_htlc_funding_tx`, the check the leg's resume uses). No
  endpoint names it, so no endpoint chooses what the others verify;
* the observer watches that outpoint as it watches a recorded lock, and ``decide()`` runs the
  BTC_LOCKED rules over a view of the record at BTC_LOCKED, with every page's action prefixed by
  ``resume_interrupted_fund``, both autonomy flags False, and its own situation tags;
* those rules run only once the BTC side gives a reason (:func:`unrecorded_fund_engaged`): a spender
  is seen, or some source reports the funding at least ``min(G, t_btc)`` deep. Before that the record
  is watched: the BTC reads still run every tick, but the covenant is not read and nothing pages, so a
  healthy fund pages nothing (Mythos review of #891, F3). The exception is a tick whose outspend
  sources all fail: that is a reconcile error, as for a recorded lock. The silence holds past t_rxd
  too, a known gap (combined Mythos pass, 1.1) for a fund not yet engaged when the maker can refund the
  covenant and claim;
* a fund that went quiet (BTC confirmed at least ``G`` deep on some source, nothing else due) pages
  ``PAGE_RESUME_FUND`` once, at WARN.

``G`` is :data:`DEFAULT_UNRECORDED_FUND_GRACE_BLOCKS` unless the tower is told otherwise. It must exceed
the funding runner's ``min_confirmations``: a healthy runner records the lock within one poll of that
depth, so a fund still unrecorded at ``G`` has stopped. The tower cannot read that setting, so it is
the operator's to keep consistent.

One lying source can engage the rules: it can report a fund no other source has seen. The rules then
fail toward paging. With the covenant pinned and t_rxd near, the refund's maturity cannot be read (the
quorum depth is unread), and that pages CRITICAL until it is ACKed. This is deliberate: one source is
then the only evidence that BTC sits in an HTLC the maker can soon claim after refunding the covenant,
and a false page is the cheap mistake. It cannot arm a broadcast.
"""

from __future__ import annotations

import dataclasses

from pyrxd.btc_wallet import taproot as t
from pyrxd.btc_wallet.htlc_leg import htlc_for_terms, recorded_htlc_funding_tx
from pyrxd.btc_wallet.taproot import TimeUnit
from pyrxd.gravity.swap_state import RecordRole, SwapRecord, SwapState
from pyrxd.security.errors import ValidationError

__all__ = [
    "DEFAULT_UNRECORDED_FUND_GRACE_BLOCKS",
    "is_unrecorded_btc_fund",
    "unrecorded_btc_fund_locator",
    "unrecorded_fund_engaged",
    "unrecorded_lock_view",
]

#: How deep (BTC blocks, on the deepest source) an unrecorded fund must be before the tower pages it
#: as interrupted. Chosen, not measured: ``dust_swap_run`` and ``btc_swap_two_host`` fund with
#: ``min_confirmations=1`` and poll every 60 s, so a runner still alive records the lock within a
#: minute of depth 1. Callers with a higher ``min_confirmations`` need a higher value.
DEFAULT_UNRECORDED_FUND_GRACE_BLOCKS = 3


def is_unrecorded_btc_fund(record: SwapRecord) -> bool:
    """Whether *record* is a taker's (or single operator's, or role-less) BTC fund that was written
    before its broadcast and never recorded as a lock. Only ``taker_funds_btc`` writes
    ``pending_btc_funding_tx``, so a maker's record carrying one is not this case."""
    return (
        record.state is SwapState.NEGOTIATED
        and record.terms.counter_chain == "btc"
        and record.pending_btc_funding_tx is not None
        and record.counterchain_locator is None
        and record.role is not RecordRole.MAKER
    )


def unrecorded_btc_fund_locator(record: SwapRecord, *, network: str) -> t.BtcHtlcLocator:
    """The locator of the HTLC the record's pending fund pays: output 0 of its bytes, which must pay
    the HTLC the terms describe exactly ``terms.btc_sats``. Raises :class:`ValidationError` otherwise
    (a corrupt record, or another swap's bytes), which the reconciler pages by swap id."""
    if not is_unrecorded_btc_fund(record):
        raise ValidationError("unrecorded_btc_fund_locator needs a record with an unrecorded BTC fund")
    htlc = htlc_for_terms(record.terms, network=network)
    raw = recorded_htlc_funding_tx(record.terms, htlc, str(record.pending_btc_funding_tx))
    return htlc.with_funding(t.BtcOutpoint(txid=t.btc_txid_from_raw(raw), vout=0), record.terms.btc_sats)


def unrecorded_lock_view(record: SwapRecord, locator: t.BtcHtlcLocator | None = None) -> SwapRecord:
    """*record* as the BTC_LOCKED record it would be had the fund been recorded: the state ``decide()``
    and the observer apply their rules to. Never persisted, never handed to an executor."""
    if not is_unrecorded_btc_fund(record):
        raise ValidationError("unrecorded_lock_view needs a record with an unrecorded BTC fund")
    return dataclasses.replace(record, state=SwapState.BTC_LOCKED, counterchain_locator=locator)


def unrecorded_fund_engaged(
    record: SwapRecord, *, spend_seen: bool, deepest_confirmations: int | None, grace_blocks: int
) -> bool:
    """Whether the BTC side gives the tower a reason to apply the lock rules to an unrecorded fund: a
    spender was seen (a claim makes ``p`` public at any depth), or some source reports the funding at
    least ``grace_blocks`` deep, or at least ``t_btc`` deep when that is fewer (the refund opens then).
    The observer reads the covenant, and ``decide()`` runs the BTC_LOCKED rules, only when this holds."""
    if spend_seen:
        return True
    if deepest_confirmations is None:
        return False
    threshold = grace_blocks
    if record.terms.t_btc.unit is TimeUnit.BLOCKS:
        threshold = min(threshold, record.terms.t_btc.value)
    return deepest_confirmations >= max(1, threshold)
