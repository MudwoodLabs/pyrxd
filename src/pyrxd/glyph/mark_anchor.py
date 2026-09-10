"""The block a transaction is in — and an honest account of how much that is worth.

HashMark §7.6 form 2 asks what a name pointed at AT THE BLOCK THAT CARRIED THE MARK. That block is
an input nobody was supplying: `_classify_raw_tx` takes a txid and raw bytes and returns no height,
blockhash or confirmation count at all. This is that input.

WHAT IT IS NOT. The height here is **the endpoint's claim**, not a proof. pyrxd has no Radiant
header verifier, no Radiant proof-of-work check and no Radiant merkle-inclusion check:
``pyrxd.spv`` is Bitcoin (SHA-256d) and says so in its own source, and ``registry.block_hash_hex``
can hash a Radiant header but nothing checks that header's work or its place on the most-work
chain.

AND MERKLE INCLUSION ALONE WOULD NOT FIX THAT — read this before "improving" it. Fetching a merkle
path and checking it against a header the same server supplied proves nothing against a hostile
server: with no proof-of-work check, fabricating a header whose merkle root commits to the
transaction is free. Inclusion-without-work catches accidental inconsistency and buys nothing
against a server that is lying on purpose, while looking exactly like security.

Two cheaper-than-SPV steps DO buy something, and this module implements neither, so do not read the
paragraph above as "nothing short of full SPV is worth doing":

  * CHECKING THE HEADER'S OWN PROOF-OF-WORK (does it hash below its stated target) makes fabricating
    a header cost real work instead of nothing. It still does not prove the header is on the
    most-work chain, which is what a reorg-depth argument needs.
  * COMPARING HEIGHTS FROM INDEPENDENT ENDPOINTS turns one lie into a detectable disagreement. That
    is a weaker claim than consensus, and it is the same independence argument ``source`` exists to
    make checkable one level up.

What this module ships today is the caveat, because neither of those is built here yet. The honest
ordering is: caveat now, the two steps above as real improvements, a Radiant SPV client for a claim
that does not need a caveat at all.

WHAT IT IS. ``get_transaction_verbose`` binds the echoed txid, so an endpoint cannot answer about a
DIFFERENT transaction — that much is checked. Beyond it, an endpoint that lies about the height
moves the point in time a name is resolved at, which is why the caller must not take the height
from the same source that supplied the name→glyph binding. ``source`` is carried so that
independence is checkable rather than assumed.

NO DEPTH DEFAULT, deliberately. ``min_confirmations`` is required. The registry in
``btc_wallet/chains.py`` states the rule this follows: *"Confirmation depth must be value-scaled
PER CHAIN. Depth buys reorg-resistance priced in that chain's hashrate; '6 confirmations' folklore
transfers across chains even less than it transfers across values"* — and it "deliberately does NOT
ship depth defaults". Neither does this.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from pyrxd.network._guards import nonneg_int
from pyrxd.security.errors import NetworkError, ValidationError

#: Text attached to every anchor. Deliberately not optional and deliberately blunt: the whole
#: value of form 2 rests on this height, and a reader who does not know it is unverified will
#: over-trust the sentence built on top of it.
UNVERIFIED_CAVEAT = (
    "height reported by the endpoint and NOT verified: pyrxd has no Radiant header, "
    "proof-of-work or merkle-inclusion check, so an endpoint that lies about the height moves "
    "the point in time this answer is about"
)


@dataclass(frozen=True)
class MarkAnchor:
    """Where a transaction sits in the chain, according to some endpoint."""

    txid: str
    #: ``None`` when the endpoint reports no confirmations — an unmined transaction has no block,
    #: and form 2 is unavailable for it by construction rather than by policy.
    height: int | None
    confirmations: int
    #: What the CALLER required. Carried so the verdict can say what bar was applied.
    min_confirmations: int
    #: An opaque tag naming who said this. Compared against the name→glyph binding's source so
    #: one hostile endpoint cannot move both answers.
    source: str
    caveat: str = UNVERIFIED_CAVEAT
    #: Always ``False``. There is no Radiant SPV in this codebase; see the module docstring.
    height_is_verified: bool = False

    @property
    def provisional(self) -> bool:
        """Below the caller's bar — real, but shallow enough to be reorged out."""
        return self.height is not None and self.confirmations < self.min_confirmations

    @property
    def usable_for_point_in_time(self) -> bool:
        """Has a block, and is buried to the depth the caller asked for."""
        return self.height is not None and not self.provisional


async def resolve_mark_anchor(
    *,
    txid: str,
    fetch_verbose: Callable[[str], Awaitable[dict]],
    source: str,
    min_confirmations: int,
    tip_height: int | None = None,
) -> MarkAnchor:
    """Ask an endpoint where ``txid`` is, and return it qualified.

    ``fetch_verbose`` should be an ``ElectrumXClient.get_transaction_verbose``-shaped call: it
    binds the echoed txid to the one requested, which is the one thing here that IS checked.

    :raises ValidationError: if ``min_confirmations`` is not a positive int. There is no default
        on purpose — see the module docstring.
    :raises NetworkError: if the endpoint's answer is unreadable. Fail closed: an unreadable
        depth must not read as depth 0 and then as "unconfirmed", because an unconfirmed mark and
        a mark whose depth could not be read are different facts and only one of them is benign.
    """
    if not isinstance(min_confirmations, int) or isinstance(min_confirmations, bool) or min_confirmations < 1:
        raise ValidationError(
            "min_confirmations must be an int >= 1 and has no default: confirmation depth is "
            "value-scaled per chain, and a shipped default would be folklore"
        )

    info = await fetch_verbose(txid)
    if not isinstance(info, dict):
        raise NetworkError(f"get_transaction_verbose did not return a dict for {txid}")

    # BIND THE ECHO HERE, not beside. `ElectrumXClient.get_transaction_verbose` does bind it, but
    # it is not the only shipped source of this shape, and this function is the funnel every path
    # crosses with both values in hand. Without it `MarkAnchor.txid` was simply the txid REQUESTED
    # however different the answer was.
    echoed = info.get("txid")
    if isinstance(echoed, str) and echoed.lower() != txid.lower():
        raise NetworkError(f"endpoint answered about {echoed} when asked about {txid}; fail-closed")

    # NO `or 0`. It short-circuited `finite_int` for every falsy value, so null, "", false and -1
    # all became depth 0 and then read as "unmined" - the exact conflation this module's own
    # contract forbids, and the opposite of how the height branch below treats a negative.
    raw_confs = info.get("confirmations", 0)
    if raw_confs is None:
        raw_confs = 0
    try:
        confirmations = nonneg_int(raw_confs)
    except ValueError as exc:
        raise NetworkError(f"endpoint reported an unreadable confirmation depth for {txid}; fail-closed") from exc

    # HEIGHT IS DERIVED, NOT READ. Measured against a live mainnet node and both shipped public
    # ElectrumX servers, `getrawtransaction <txid> true` returns
    # ['blockhash','blocktime','confirmations','hash','locktime','size','time','txid','version'] -
    # NEITHER `height` NOR `blockheight`. Reading those keys meant `height` was always None in
    # production, so form 2 could never fire honestly; worse, the ONLY way to obtain a usable
    # anchor was an endpoint that ADDED a key no honest source emits, so the feature was reachable
    # exclusively by anomalous or hostile responses.
    #
    # `tip - confirmations + 1` uses what the endpoint really returns. It is the same endpoint's
    # claim, which the caveat already says; a caller wanting better supplies `tip_height` from
    # somewhere independent.
    height: int | None = None
    if confirmations > 0:
        if tip_height is None:
            raise NetworkError(
                f"cannot place {txid}: it has {confirmations} confirmations but no chain tip was "
                "supplied, and this endpoint shape carries no height field of its own"
            )
        try:
            tip = nonneg_int(tip_height)
        except ValueError as exc:
            raise NetworkError(f"unusable chain tip height for {txid}; fail-closed") from exc
        height = tip - confirmations + 1
        if height < 0:
            raise NetworkError(
                f"endpoint reports {confirmations} confirmations against tip {tip} for {txid}, "
                "which places it before the genesis block; fail-closed"
            )

    return MarkAnchor(
        txid=txid,
        height=height,
        confirmations=confirmations,
        min_confirmations=min_confirmations,
        source=source,
    )


__all__ = ["UNVERIFIED_CAVEAT", "MarkAnchor", "resolve_mark_anchor"]
