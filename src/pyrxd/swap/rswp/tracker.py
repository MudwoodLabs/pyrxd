"""Maker offer lifecycle tracker: record posted RSWP offers, poll ElectrumX to
classify OPEN / FILLED / CANCELLED, and roll up per-asset net position.

This module never broadcasts, never signs, and never guesses. The chain is the
only source of truth for classification:

* OPEN means the offered UTXO is still unspent (``blockchain.scripthash.listunspent``).
  A hostile/buggy server can falsely claim "still unspent" for something that
  was actually spent — that is a **liveness** failure only (a stale OPEN the
  caller re-polls away), never a safety one: it can never make a real fill or
  cancel disappear, only delay noticing it.
* FILLED / CANCELLED require a **confirmed** spender: the spending tx must
  appear in the offered scripthash's history at a block ``height > 0``, actually
  consume the offered outpoint, and (for FILLED) its output[0] must byte-match
  (value AND locking script) the demanded output the maker's own ``0xC3``-signed
  advertisement committed to. Every tx read goes through the txid-verified
  :func:`pyrxd.swap.resolve.fetch_transaction`, and an *unconfirmed* claimed
  spender is treated as still-OPEN (re-poll), so a fabricated mempool tx cannot
  flip an offer to FILLED.

  **Trust model (read this — it is not consensus-grade):** classification trusts
  the *queried ElectrumX server's* report of what is confirmed. A fully hostile
  or MITM'd server can still forge FILLED/CANCELLED by presenting a fabricated
  spend it *claims* is confirmed — the confirmation gate only stops the naive
  (unconfirmed) forgery, not a server that lies about ``height``. This tracker is
  a convenience position view, **not** a settlement validator. For
  trust-minimized proof of a fill, SPV-verify the spending tx (Merkle inclusion
  + header PoW via :mod:`pyrxd.spv`) or cross-check ≥2 independent servers before
  treating FILLED as "paid" (e.g. before releasing an off-chain good). SPV
  inclusion in ``classify`` is a tracked follow-up.
* Anything that confirmed-spends the offered UTXO but does not match the demand
  (most commonly the maker's own :func:`pyrxd.swap.rswp.orders.build_cancel_tx`)
  is CANCELLED.

Persistence is deliberately NOT this module's job — :class:`OfferTracker`
wraps a plain Python list the caller owns; :func:`load_offers` / :func:`save_offers`
are a thin JSON file convenience, not a database.
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING

from ...gravity.swap_order import decode_rswp_order
from ...hash import sha256
from ...security.errors import ValidationError
from ...security.types import Txid
from ..resolve import fetch_transaction
from ..types import Asset, SwapTerms

if TYPE_CHECKING:
    from ...network.electrumx import ElectrumXClient

__all__ = [
    "ClassifyResult",
    "OfferStatus",
    "OfferTracker",
    "TrackedOffer",
    "classify",
    "load_offers",
    "net_position",
    "save_offers",
]


class OfferStatus(Enum):
    """Where a posted offer stands, as read from the chain (never inferred)."""

    OPEN = "open"  # offered UTXO still unspent — fillable or still cancellable
    FILLED = "filled"  # spent by a tx whose output[0] byte-matches the demanded output
    CANCELLED = "cancelled"  # spent, but NOT by a tx matching the demand (maker's own revocation)


@dataclass(frozen=True)
class TrackedOffer:
    """One posted maker offer, as recorded by the caller — chain-public data only.

    ``outpoint_txid``/``outpoint_vout`` is the offered UTXO (the exact-amount
    give-side output — see :func:`pyrxd.swap.rswp.orders.prepare_offered_utxo`).
    ``terms`` is the human-readable trade (:class:`~pyrxd.swap.types.SwapTerms`).
    ``posted_advert_txid`` is the broadcast RSWP advertisement, if any — required
    by :func:`classify` to read the exact demanded output (value + script) that
    distinguishes FILLED from CANCELLED; an offer negotiated purely off-chain
    has none, and classification then degrades to OPEN vs "spent, unverifiable
    fill" (reported CANCELLED — see :func:`classify`). No key material of any
    kind belongs on this dataclass, ever.
    """

    outpoint_txid: Txid
    outpoint_vout: int
    terms: SwapTerms
    posted_advert_txid: Txid | None = None
    created_height: int | None = None

    def __post_init__(self) -> None:
        if self.outpoint_vout < 0:
            raise ValidationError(f"TrackedOffer outpoint_vout must be non-negative, got {self.outpoint_vout}")
        if self.created_height is not None and self.created_height < 0:
            raise ValidationError(f"TrackedOffer created_height must be non-negative, got {self.created_height}")

    def to_dict(self) -> dict:
        return {
            "outpoint_txid": str(self.outpoint_txid),
            "outpoint_vout": self.outpoint_vout,
            "terms": self.terms.to_dict(),
            "posted_advert_txid": None if self.posted_advert_txid is None else str(self.posted_advert_txid),
            "created_height": self.created_height,
        }

    @classmethod
    def from_dict(cls, d: dict) -> TrackedOffer:
        advert = d.get("posted_advert_txid")
        height = d.get("created_height")
        return cls(
            outpoint_txid=Txid(str(d["outpoint_txid"])),
            outpoint_vout=int(d["outpoint_vout"]),
            terms=SwapTerms.from_dict(d["terms"]),
            posted_advert_txid=None if advert is None else Txid(str(advert)),
            created_height=None if height is None else int(height),
        )


@dataclass(frozen=True)
class ClassifyResult:
    """The verdict :func:`classify` reached for one :class:`TrackedOffer`.

    ``spending_txid`` is the settlement proof: the transaction that spent the
    offered UTXO. ``None`` only when ``status`` is OPEN (nothing has spent it).
    """

    status: OfferStatus
    spending_txid: str | None


def _script_hash(script: bytes) -> bytes:
    """ElectrumX ``script_hash``: ``sha256(script)`` reversed to display (little-endian) order.

    Same one-liner as ``pyrxd.cli.swap_cmds.electrumx_script_hash``, kept local rather than
    imported so this network module never depends on the CLI package.
    """
    return sha256(script)[::-1]


# Cap on confirmed history candidates fetched while hunting the offered outpoint's spender (review MEDIUM
# DoS): a hostile ElectrumX can pad the scripthash history with confirmed-looking non-matching entries, each
# costing a full-tx fetch. Beyond the cap the offer falls to OPEN (re-poll) — the same safe liveness-only
# disposition as "no confirmed spender yet", never a false FILLED.
_MAX_HISTORY_FETCHES = 256


async def classify(client: ElectrumXClient, offer: TrackedOffer) -> ClassifyResult:
    """Classify ``offer`` against the live chain — see the module docstring for the
    security argument. Every transaction this reads (the offered UTXO's own source
    tx, every history candidate, and the advert) goes through the txid-verified
    :func:`pyrxd.swap.resolve.fetch_transaction`, so a hostile ElectrumX server
    cannot substitute a different transaction at any step.
    """
    source_tx = await fetch_transaction(client, offer.outpoint_txid)
    if not 0 <= offer.outpoint_vout < len(source_tx.outputs):
        raise ValidationError(f"TrackedOffer outpoint vout {offer.outpoint_vout} is out of range for its own source Tx")
    offered_out = source_tx.outputs[offer.outpoint_vout]
    script_hash = _script_hash(offered_out.locking_script.serialize())

    utxos = await client.get_utxos(script_hash)
    still_unspent = any(u.tx_hash == str(offer.outpoint_txid) and u.tx_pos == offer.outpoint_vout for u in utxos)
    if still_unspent:
        return ClassifyResult(status=OfferStatus.OPEN, spending_txid=None)

    # Spent (or the server claims so) — find the CONFIRMED spending tx among the scripthash's history.
    # A settlement disposition (FILLED/CANCELLED) requires the spender be in a block (height > 0): an
    # unconfirmed/mempool-only "spender" is not a settled fact and, if fabricated, must not flip the offer.
    history = await client.get_history(script_hash)
    spending_tx = None
    spending_txid: str | None = None
    spend_input_index = 0
    fetches = 0
    for entry in history:
        candidate_txid = str(entry["tx_hash"])
        if candidate_txid == str(offer.outpoint_txid):
            continue  # the tx that CREATED this output, not one that spends it
        try:
            entry_height = int(entry.get("height", 0))
        except (TypeError, ValueError):
            entry_height = 0
        if entry_height <= 0:
            continue  # unconfirmed (mempool) — not a settled spender; skip
        if fetches >= _MAX_HISTORY_FETCHES:
            break  # DoS cap — an un-found spender falls to OPEN below (safe, liveness-only)
        fetches += 1
        candidate = await fetch_transaction(client, candidate_txid)
        spend_idx = next(
            (
                k
                for k, i in enumerate(candidate.inputs)
                if i.source_txid == str(offer.outpoint_txid) and i.source_output_index == offer.outpoint_vout
            ),
            None,
        )
        if spend_idx is not None:
            spending_tx = candidate
            spending_txid = candidate_txid
            spend_input_index = spend_idx
            break

    if spending_tx is None:
        # The UTXO reads spent but no CONFIRMED matching spender is in history yet — treat as still-OPEN
        # (re-poll) rather than trusting the unconfirmed report. Matches the "stale OPEN is liveness-only,
        # never safety" posture in the module docstring, and denies a fabricated mempool spend a FILLED.
        return ClassifyResult(status=OfferStatus.OPEN, spending_txid=None)

    # FILLED requires proof: the advertised demand, decoded from the maker's own signed
    # advert (never from `terms`, which is caller-declared and unverified against chain).
    if offer.posted_advert_txid is None or not spending_tx.outputs:
        return ClassifyResult(status=OfferStatus.CANCELLED, spending_txid=spending_txid)

    advert_tx = await fetch_transaction(client, offer.posted_advert_txid)
    if not advert_tx.outputs:
        raise ValidationError("posted advert Tx has no outputs to decode an RSWP order from")
    order = decode_rswp_order(advert_tx.outputs[0].locking_script.serialize())
    if order.demanded_outputs is None or len(order.demanded_outputs) != 1:
        # An unparseable/multi-output demand carries no enforceable settlement proof
        # (mirrors the SIGHASH_SINGLE "exactly one demanded output" invariant elsewhere).
        return ClassifyResult(status=OfferStatus.CANCELLED, spending_txid=spending_txid)
    demanded = order.demanded_outputs[0]

    # SIGHASH_SINGLE binds the maker's demand to the output at the SAME index as the maker's signing input.
    # A fill built by another wallet may place the maker input at index != 0, so check THAT output — not
    # output[0] — else a genuine fill is misreported CANCELLED and the maker's net_position silently drops a
    # given/received leg (review MEDIUM).
    if spend_input_index < len(spending_tx.outputs):
        settled = spending_tx.outputs[spend_input_index]
        if settled.satoshis == demanded.value and settled.locking_script.serialize() == demanded.script:
            return ClassifyResult(status=OfferStatus.FILLED, spending_txid=spending_txid)
    return ClassifyResult(status=OfferStatus.CANCELLED, spending_txid=spending_txid)


class OfferTracker:
    """A maker's posted-offer registry. The store is just ``self.offers`` — a plain
    Python list the caller owns, mutates, and persists (see :func:`save_offers` /
    :func:`load_offers`). This class adds ElectrumX-backed classification on top of
    it; it is NOT a database.
    """

    def __init__(self, offers: list[TrackedOffer] | None = None) -> None:
        self.offers: list[TrackedOffer] = list(offers) if offers is not None else []

    def add(self, offer: TrackedOffer) -> None:
        self.offers.append(offer)

    async def classify_all(self, client: ElectrumXClient) -> list[ClassifyResult]:
        """Classify every tracked offer, in ``self.offers`` order (one :func:`classify`
        call each — sequential, so a single hostile/unreachable server fails clearly
        on the offer it broke rather than silently skipping it)."""
        return [await classify(client, offer) for offer in self.offers]


def load_offers(path: str | Path) -> list[TrackedOffer]:
    """Load tracked offers from a JSON file. A missing file returns an empty list —
    that is the natural "nothing tracked yet" starting state, not an error."""
    p = Path(path)
    if not p.exists():
        return []
    raw = json.loads(p.read_text())
    if not isinstance(raw, list):
        raise ValidationError("Offer store file must contain a JSON list at its top level")
    return [TrackedOffer.from_dict(d) for d in raw]


def save_offers(path: str | Path, offers: Iterable[TrackedOffer]) -> None:
    """Persist tracked offers to a JSON file, atomically (write to a Tmp file, then rename)."""
    p = Path(path)
    data = [offer.to_dict() for offer in offers]
    tmp = p.with_name(p.name + ".tmp")
    tmp.write_text(json.dumps(data, indent=2))
    os.replace(tmp, p)


def _asset_key(asset: Asset) -> str:
    """Stable, JSON-friendly per-asset key: ``"rxd"`` or ``"ft:<genesis txid>:<vout>"``."""
    if asset.kind == "rxd":
        return "rxd"
    ref = asset.ref
    if ref is None:  # unreachable: Asset.__post_init__ requires a ref for kind == "ft"
        raise ValidationError("Ft asset is missing its Ref despite the Asset invariant")
    return f"ft:{ref.txid}:{ref.vout}"


def net_position(offers: Sequence[TrackedOffer], statuses: Sequence[OfferStatus]) -> dict[str, dict[str, int]]:
    """Per-asset totals across ``offers`` given their parallel ``statuses`` (same
    order and length — typically the result of :meth:`OfferTracker.classify_all`).

    For every asset key (see :func:`_asset_key`):

    * ``given``    — total amount the maker handed over across FILLED offers
                     where this asset was the give side.
    * ``received`` — total amount the maker took in across FILLED offers
                     where this asset was the receive side.
    * ``exposed``  — total amount still at risk: the give side of every OPEN
                     offer (a taker could complete it at any time).

    CANCELLED offers contribute nothing (the maker's own revocation returned
    the offered asset, minus a network fee this function does not track).
    Pure function — no I/O, no chain calls — and exact integers throughout;
    Radiant/Glyph amounts are always whole photons, never fractional.
    """
    if len(offers) != len(statuses):
        raise ValidationError(f"offers ({len(offers)}) and statuses ({len(statuses)}) must be the same Length")
    totals: dict[str, dict[str, int]] = {}

    def _bucket(key: str) -> dict[str, int]:
        return totals.setdefault(key, {"given": 0, "received": 0, "exposed": 0})

    for offer, status in zip(offers, statuses, strict=True):
        give, receive = offer.terms.give, offer.terms.receive
        if status is OfferStatus.FILLED:
            _bucket(_asset_key(give))["given"] += give.amount
            _bucket(_asset_key(receive))["received"] += receive.amount
        elif status is OfferStatus.OPEN:
            _bucket(_asset_key(give))["exposed"] += give.amount
        # CANCELLED: no change — the maker's revocation returned the asset.

    return totals
