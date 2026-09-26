"""The block a transaction is in — and an honest account of how much that is worth.

HashMark §7.6 form 2 asks what a name pointed at AT THE BLOCK THAT CARRIED THE MARK. That block is
an input nobody was supplying: `_classify_raw_tx` takes a txid and raw bytes and returns no height,
blockhash or confirmation count at all. This is that input.

WHAT IT IS NOT. The height here is **the endpoint's claim**, not a proof. pyrxd verifies no Radiant
header chain — no proof-of-work check, no most-work check — and no Radiant merkle inclusion:
``pyrxd.spv`` is Bitcoin (SHA-256d) and says so in its own source. With ``fetch_header`` the height
is BOUND to the endpoint's own header (the header at that height must hash to the block the endpoint
says holds the transaction), which is a check of the endpoint against itself, not verification:
nothing checks that header's work or its place on the most-work chain.

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

This module builds neither: an anchor is ONE endpoint's word, and it ships the caveat. The second
step IS taken one level up, for HashMark §7.6 form 2 only — ``judge_name_at_mark`` refuses unless a
second endpoint places the mark in the same block (and agrees on every chain step's height). An
anchor used anywhere else — ``pyrxd verify``'s block line, for one — is still a single endpoint's
claim. The honest ordering is: caveat now, the two steps above as real improvements, a Radiant SPV
client for a claim that does not need a caveat at all.

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

from pyrxd.security.errors import NetworkError, ValidationError
from pyrxd.security.json_guards import nonneg_int

#: Text attached to every anchor. Deliberately not optional and deliberately blunt: the whole
#: value of form 2 rests on this height, and a reader who does not know it is unverified will
#: over-trust the sentence built on top of it.
UNVERIFIED_CAVEAT = (
    "height reported by the endpoint and NOT verified: it was not checked against any block header, "
    "and nothing checks proof-of-work or merkle inclusion, so an endpoint that lies about the height "
    "moves the point in time this answer is about"
)

#: The caveat for an anchor whose height was BOUND to the block the endpoint says holds the
#: transaction (``resolve_mark_anchor(fetch_header=...)``). The unbound caveat's "not checked
#: against any block header" is not true of it, so it would be a false sentence; this one says exactly
#: what the binding is — a check of the endpoint against ITSELF — and what it is not. A hostile
#: endpoint can serve the real header of block X at whatever height it likes, because nothing
#: checks proof-of-work or the chain the header sits in.
BOUND_CAVEAT = (
    "height reported by the endpoint and checked only against the endpoint itself (its header at "
    "that height hashes to the block it says holds the transaction), NOT verified: pyrxd checks no "
    "proof-of-work or merkle inclusion, so an endpoint that lies about the height moves the point "
    "in time this answer is about"
)

#: How far either side of ``tip - confirmations + 1`` a binding looks for the transaction's block.
#: The formula usually comes out LOW: the tip is ElectrumX's indexed height (``headers.subscribe``)
#: while ``confirmations`` comes from its node, which gets each block first — measured by the 0.25.0
#: panel on both shipped servers, one block low in 7 of 470 paired samples, both at once. It can
#: also come out HIGH, when the node answering the verbose call is behind the index (an ElectrumX
#: failing over between nodes, or a reorg). The search is symmetric because a returned height must
#: still hash to the block the node names, so looking lower costs nothing and refuses nobody honest.
#: Two is headroom, not a model.
MAX_INDEX_LAG_BLOCKS = 2


class AnchorBindingError(NetworkError):
    """The endpoint answered, but no header in the search window binds the height to its block.

    Not "unreachable": the endpoint answered the depth and the block hash. A caller reporting this
    should suggest re-running or asking another server, rather than "check that the server is
    reachable" — and should say WHICH of three things happened, from the attributes rather than by
    parsing the message:

    * ``disagrees`` — every height in the window was served and none hashes to the block the node
      named: the endpoint's index and its node disagree (or it is serving inconsistent data).
    * ``unserved`` non-empty — some (or all) of the headers could not be read, so nothing
      established a disagreement: the matching header may simply be the one that never arrived.
      "Its index and its node disagree" would be a false sentence here, and was one (0.25.0
      review, round 2: an honest chain whose request for the mark's own header went unanswered).
    * both empty — the endpoint named no block to bind to at all.

    ``served`` and ``unserved`` are the heights, in the order they were tried.
    """

    def __init__(self, message: str, *, served: tuple[int, ...] = (), unserved: tuple[int, ...] = ()) -> None:
        super().__init__(message)
        self.served = tuple(served)
        self.unserved = tuple(unserved)

    @property
    def disagrees(self) -> bool:
        """True only when every height asked was served and none matched."""
        return bool(self.served) and not self.unserved


#: What ``--min-confirmations N`` MEANS, worded to match :attr:`MarkAnchor.provisional` below:
#: the floor holds when ``confirmations >= N``, and an endpoint's confirmation count INCLUDES the
#: block the transaction is in (``height = tip - confirmations + 1``). So N counts the block itself.
#: The CLI said "N is how many blocks must sit on top of the mark's block", which is one more than
#: the check requires. One sentence, next to the check, for every surface that explains the flag.
MIN_CONFIRMATIONS_MEANING = "N confirmations: the block itself and N−1 built on top of it"


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
    #: ``True`` when ``height`` was bound to the endpoint's own header (the header at ``height``
    #: hashes to the block the endpoint named). A check of the endpoint against ITSELF — which is
    #: why ``height_is_verified`` stays False. Carried so a verdict built on the height can say
    #: truthfully whether the height was header-checked, rather than assuming either way.
    header_bound: bool = False

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
    fetch_header: Callable[[int], Awaitable[bytes]] | None = None,
) -> MarkAnchor:
    """Ask an endpoint where ``txid`` is, and return it qualified.

    ``fetch_verbose`` should be an ``ElectrumXClient.get_transaction_verbose``-shaped call: it
    binds the echoed txid to the one requested, which is the one thing here that IS checked.

    ``fetch_header`` (``ElectrumXClient.get_block_header``-shaped) BINDS the derived height to the
    block the endpoint says holds the transaction: the header at that height must hash to the
    verbose reply's ``blockhash``. Without it the height is ``tip - confirmations + 1`` alone,
    which is one block LOW whenever an endpoint's index trails its node — measured on both shipped
    servers at once, so a second endpoint agreeing does not catch it. With it, heights up to
    :data:`MAX_INDEX_LAG_BLOCKS` above the formula are tried, and a height no header confirms is
    never returned: that raises instead. The CLI always passes it.

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
    # claim, which the caveat already says. It is also one block LOW whenever the endpoint's index
    # trails its node, on every endpoint at once — so a caller that can fetch headers passes
    # `fetch_header`, and the height is then bound to the block hash below.
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

    if height is not None and fetch_header is not None:
        height = await _bind_to_block(txid, height, info.get("blockhash"), fetch_header)
        return MarkAnchor(
            txid=txid,
            height=height,
            confirmations=confirmations,
            min_confirmations=min_confirmations,
            source=source,
            caveat=BOUND_CAVEAT,
            header_bound=True,
        )

    return MarkAnchor(
        txid=txid,
        height=height,
        confirmations=confirmations,
        min_confirmations=min_confirmations,
        source=source,
    )


async def _bind_to_block(
    txid: str, derived: int, blockhash: object, fetch_header: Callable[[int], Awaitable[bytes]]
) -> int:
    """The height whose header hashes to ``blockhash``, searched outward from ``derived``.

    THE FORMULA WAS WRONG IN A WAY TWO SERVERS AGREE ON. ``tip`` is ElectrumX's indexed height and
    ``confirmations`` is its node's count; for a few seconds after every block the node has the
    new block and the index does not, so ``tip - confirmations + 1`` is one block low — on every
    server at once. Measured by the 0.25.0 panel: both shipped servers one block low together in
    7 of 470 paired samples, and a live ``verify --wave-name`` printed ESTABLISHED at a block the
    mark is not in. The block HASH comes from the node and does not lag, so the height is taken
    from the header that hashes to it rather than from the arithmetic.

    Both directions, nearest first (``derived``, +1, -1, +2, -2; see :data:`MAX_INDEX_LAG_BLOCKS`):
    the formula is usually low, occasionally high, and a match is exact whichever side it is on. A
    header that cannot be read at one candidate (above the index's tip, say) does not stop the
    search. Fail closed otherwise — a block number the header check did not confirm is never
    returned, and the failure is an :class:`AnchorBindingError`.
    """
    from ..hash import radiant_block_hash  # the pure-stdlib one: this module must import under Pyodide

    if not (
        isinstance(blockhash, str) and len(blockhash) == 64 and all(c in "0123456789abcdefABCDEF" for c in blockhash)
    ):
        raise AnchorBindingError(
            f"endpoint reports {txid} as confirmed but gives no block hash to bind its height to; fail-closed"
        )
    want = blockhash.lower()
    offsets = [0] + [sign * step for step in range(1, MAX_INDEX_LAG_BLOCKS + 1) for sign in (1, -1)]
    served: list[int] = []
    unserved: list[int] = []
    unreadable: list[str] = []
    for candidate in (derived + offset for offset in offsets):
        if candidate < 0:
            continue
        try:
            header = bytes(await fetch_header(candidate))
            observed = radiant_block_hash(header)
        except (NetworkError, ValidationError, TypeError, ValueError) as exc:
            unserved.append(candidate)
            unreadable.append(f"{candidate}: {exc}")
            continue
        if observed == want:
            return candidate
        served.append(candidate)
    tail = "Re-run in a moment, or ask another server; no block number is reported that a header has not confirmed"
    # "ITS INDEX AND ITS NODE DISAGREE" ONLY WHEN EVERY HEADER ARRIVED. With one missing, the
    # others not matching is exactly what an honest chain looks like — the missing one may be the
    # match — so the message then names what was not served instead of accusing the endpoint.
    if unserved:
        could_not = f"(headers it could not serve: {'; '.join(unreadable)})"
        if served:
            message = (
                f"the endpoint answered, but it did not serve a usable header at heights "
                f"{', '.join(map(str, sorted(unserved)))} {could_not}, and none of the headers it did "
                f"serve (heights {', '.join(map(str, sorted(served)))}) is the block it says holds {txid} "
                f"({want[:16]}…), so which block that is could not be checked. {tail}"
            )
        else:
            message = (
                f"the endpoint answered, but it did not serve a usable header at any of heights "
                f"{', '.join(map(str, sorted(unserved)))} {could_not}, so which block holds {txid} "
                f"({want[:16]}…) could not be checked. {tail}"
            )
        raise AnchorBindingError(message, served=tuple(served), unserved=tuple(unserved))
    lo, hi = max(derived - MAX_INDEX_LAG_BLOCKS, 0), derived + MAX_INDEX_LAG_BLOCKS
    raise AnchorBindingError(
        f"the endpoint answered, but the block it says holds {txid} ({want[:16]}…) is not its header "
        f"at any height from {lo} to {hi}: its index and its node disagree about which block that is, "
        f"or it is serving inconsistent data. {tail}",
        served=tuple(served),
    )


def mark_anchor_dict(anchor) -> dict:
    """The display shape of a :class:`~pyrxd.glyph.mark_anchor.MarkAnchor`.

    ``caveat`` and ``height_is_verified`` are carried, never dropped: the height is one
    endpoint's claim — at most checked against that endpoint's own header — and nothing checks
    proof-of-work or merkle inclusion. A consumer that shows the number and not the caveat has
    published the unqualified sentence this module exists to prevent.
    """
    # Function-local: `_inspect_core` is a far larger module than this one, and a
    # top-level import would make every consumer of a dataclass pay for the whole
    # classifier. It is Pyodide-clean either way — that is what
    # `tests/web/test_mark_anchor_bridge.py` measures.
    from ._inspect_core import _sanitize_display_string

    return {
        "height": anchor.height,
        "confirmations": anchor.confirmations,
        "min_confirmations": anchor.min_confirmations,
        "provisional": anchor.provisional,
        "deep_enough": anchor.usable_for_point_in_time,
        "source": _sanitize_display_string(anchor.source),
        "height_is_verified": anchor.height_is_verified,
        "caveat": anchor.caveat,
    }


__all__ = [
    "BOUND_CAVEAT",
    "MAX_INDEX_LAG_BLOCKS",
    "MIN_CONFIRMATIONS_MEANING",
    "UNVERIFIED_CAVEAT",
    "AnchorBindingError",
    "MarkAnchor",
    "mark_anchor_dict",
    "resolve_mark_anchor",
]
