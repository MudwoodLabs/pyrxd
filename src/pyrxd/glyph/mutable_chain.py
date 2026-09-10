"""Walk a mutable glyph's singleton spend chain, and prove the walk reached the tip.

WHY A WALK AT ALL. A mutable Glyph's state is changed by publishing update envelopes, and
"what did this token say at block N" is only answerable by replaying them in order. An index
can list the transactions; it cannot be trusted to say what the token pointed at, and an index
was observed serving a WAVE name's MINT-TIME target after two on-chain updates had moved it.
So: **index for discovery, chain for proof** - the candidate set may come from anywhere, and
every link in it is verified here against the transactions themselves.

THE CHAIN IS THE SINGLETON, NOT THE HISTORY LIST. Measured on Radiant mainnet, an index's
history for one WAVE name contains transactions that never touch the token. For
``custodian-gate-x7f3.rxd``::

    458585  f644794b  MINT    mut out 1     <- chain
    458591  315b4630  UPDATE  mut out 1     <- chain   (spends f644794b:1)
    458591  2cee4847  -       no mut out             (spends 315b4630:0 and :2 - siblings)
    458601  3c7b43df  UPDATE  mut out 1     <- chain   (spends 315b4630:1)

`2cee4847` is in the index's list, shares a block with a real update, and is spent FROM by the
next real update - and it is not part of the singleton's history. Folding it in, or letting it
order the chain, would be wrong. The chain is followed one mutable output at a time.

HEIGHT CANNOT ORDER IT. Two of those transactions share height 458591, and elsewhere a name has
two update envelopes at one height. The spend links are the order.

THE REF IS THE IDENTITY. Every mutable output in a chain carries the same ref (``78e25bdc...:1``
above, constant from mint to tip). A step whose mutable output carries a DIFFERENT ref is not a
continuation of this token, and is refused rather than followed.

WHAT "COMPLETE" MEANS, and why it is not a detail. A truncated history is how a superseded value
becomes authoritative: stop one transaction early and the walk reports the previous target with
no sign anything is missing. So a walk is complete only when every link verified AND the final
mutable output is proved UNSPENT. Anything else sets ``complete=False`` with a reason, and the
caller degrades. Absence of evidence is reported as absence of evidence.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, field

from pyrxd.security.errors import ValidationError

from .inspector import GlyphInspector

#: Bound on how far a walk will follow, so a padded candidate set cannot make this run forever.
#: Modelled on ``swap/rswp/tracker.py``'s ``_MAX_HISTORY_FETCHES``. Hitting it is reported, never
#: silently truncated - a silent truncation is exactly the failure this module exists to prevent.
MAX_CHAIN_STEPS = 256


@dataclass(frozen=True)
class ChainStep:
    """One transaction in the singleton's own history."""

    txid: str
    #: The mutable output this transaction produced, which the next step must spend.
    mut_vout: int
    #: ``"mint"`` (a full payload), ``"update"`` (partial), or ``"unreadable"``.
    kind: str
    #: The envelope's ``attrs``, raw. Empty for a step carrying no envelope.
    attrs: dict = field(default_factory=dict)
    #: Set only for ``unreadable``.
    reason: str = ""


@dataclass(frozen=True)
class MutableChainWalk:
    """The result. Read ``complete`` before reading anything else."""

    ref: str
    steps: tuple[ChainStep, ...]
    tip_txid: str
    tip_vout: int
    tip_proved_unspent: bool
    #: Every link verified AND the tip proved unspent. False means DEGRADE - the steps below are
    #: a prefix of the truth, not the truth, and the caller must not present them as current.
    complete: bool
    reason: str = ""
    #: Candidates that are not in this singleton's chain. Reported rather than dropped, because
    #: "the index gave me transactions that do not belong to this token" is worth seeing.
    excluded: tuple[str, ...] = ()

    @property
    def has_unreadable_step(self) -> bool:
        return any(s.kind == "unreadable" for s in self.steps)


def _mut_output(inspector: GlyphInspector, outputs: list[tuple[int, bytes]]) -> tuple[int, str] | None:
    """The (vout, ref) of this transaction's mutable output, or None."""
    for glyph in inspector.find_glyphs(outputs):
        if glyph.glyph_type == "mut":
            # The outpoint form the inspect path uses (`_inspect_core.py:516`), not the repr.
            return glyph.vout, f"{glyph.ref.txid}:{glyph.ref.vout}"
    return None


def _envelope_of(inspector: GlyphInspector, scriptsigs: Sequence[bytes]) -> tuple[str, dict, str]:
    """(kind, attrs, reason) for the first glyph envelope among these scriptSigs.

    An UNREADABLE envelope wins over "nothing here": the two are opposite facts, and a walk that
    silently skipped one would report a token as unchanged when an update could not be read.
    """
    unreadable_reason = ""
    for scriptsig in scriptsigs:
        envelope = inspector.classify_glyph_scriptsig(scriptsig)
        if envelope is None:
            continue
        if envelope.kind == "payload":
            return "mint", dict(envelope.metadata.attrs or {}), ""
        if envelope.kind == "update":
            return "update", dict((envelope.fields or {}).get("attrs") or {}), ""
        unreadable_reason = unreadable_reason or envelope.reason
    if unreadable_reason:
        return "unreadable", {}, unreadable_reason
    return "none", {}, ""


async def walk_mutable_chain(
    *,
    mint_txid: str,
    candidates: Sequence[str],
    fetch_tx: Callable[[str], Awaitable[object]],
    is_unspent: Callable[[str, int], Awaitable[bool | None]] | None = None,
    max_steps: int = MAX_CHAIN_STEPS,
) -> MutableChainWalk:
    """Follow a mutable glyph from ``mint_txid`` along its own spend chain.

    ``candidates`` is a DISCOVERY hint - typically an index's history for the token. Membership
    is not taken from it: a candidate joins the chain only by spending the previous step's
    mutable output and producing one carrying the same ref.

    ``fetch_tx`` must return a parsed transaction with ``.inputs`` (``source_txid``,
    ``source_output_index``, ``unlocking_script``) and ``.outputs`` (``satoshis``,
    ``locking_script``). It is the caller's job to bind the returned transaction to the txid
    requested; a server that answers with a different transaction is out of scope here.

    ``is_unspent(txid, vout)`` proves the tip. Omitting it is not a shortcut: the walk then
    reports ``complete=False``, because an unproved tip cannot be distinguished from a truncated
    history.

    :raises ValidationError: only for a CONTRADICTION - a step whose mutable output carries a
        different ref. Absence degrades; contradiction raises. That split follows
        ``glyph/dmint/chain.py``'s S2 verifier, where a server disagreeing with itself is not a
        "no result".
    """
    inspector = GlyphInspector()
    pool = {t.lower() for t in candidates}
    pool.discard(mint_txid.lower())

    mint_tx = await fetch_tx(mint_txid)
    outputs = [(o.satoshis, bytes(o.locking_script.serialize())) for o in mint_tx.outputs]
    found = _mut_output(inspector, outputs)
    if found is None:
        return MutableChainWalk(
            ref="",
            steps=(),
            tip_txid=mint_txid,
            tip_vout=-1,
            tip_proved_unspent=False,
            complete=False,
            reason=f"{mint_txid} has no mutable output — it is not a mutable glyph mint",
            excluded=tuple(sorted(pool)),
        )
    vout, ref = found
    kind, attrs, why = _envelope_of(inspector, [bytes(i.unlocking_script.serialize()) for i in mint_tx.inputs])
    steps = [ChainStep(txid=mint_txid, mut_vout=vout, kind=kind, attrs=attrs, reason=why)]

    cur_txid, cur_vout = mint_txid, vout
    truncated_reason = ""
    while len(steps) < max_steps:
        spender = None
        for cand in sorted(pool):
            tx = await fetch_tx(cand)
            if not any(
                str(getattr(i, "source_txid", "")).lower() == cur_txid.lower() and i.source_output_index == cur_vout
                for i in tx.inputs
            ):
                continue
            spender = (cand, tx)
            break
        if spender is None:
            break
        cand, tx = spender
        pool.discard(cand)

        outs = [(o.satoshis, bytes(o.locking_script.serialize())) for o in tx.outputs]
        nxt = _mut_output(inspector, outs)
        if nxt is None:
            # The singleton was spent to something that is not a mutable output. The chain ends
            # here and the token's state cannot advance further, but this is the END of a history
            # rather than a gap in one - so it is not a contradiction.
            truncated_reason = f"{cand} spends the mutable output and produces none — chain ends"
            cur_txid, cur_vout = cand, -1
            break
        nxt_vout, nxt_ref = nxt
        if nxt_ref != ref:
            raise ValidationError(
                f"{cand} spends this token's mutable output but its own mutable output carries "
                f"ref {nxt_ref}, not {ref} — that is a different token, not a continuation"
            )
        kind, attrs, why = _envelope_of(inspector, [bytes(i.unlocking_script.serialize()) for i in tx.inputs])
        steps.append(ChainStep(txid=cand, mut_vout=nxt_vout, kind=kind, attrs=attrs, reason=why))
        cur_txid, cur_vout = cand, nxt_vout
    else:
        truncated_reason = f"walk stopped at the {max_steps}-step cap — the chain may continue"

    proved = False
    reason = truncated_reason
    if cur_vout < 0:
        reason = reason or "the chain ends in a non-mutable output"
    elif is_unspent is None:
        reason = reason or "no tip proof was available — an unproved tip cannot be told apart from a truncated history"
    else:
        answer = await is_unspent(cur_txid, cur_vout)
        proved = answer is True
        if not proved:
            reason = reason or (
                f"{cur_txid}:{cur_vout} is not proved unspent"
                + ("" if answer is False else " (the source could not say)")
            )

    unreadable = [s for s in steps if s.kind == "unreadable"]
    if unreadable and not reason:
        reason = f"{unreadable[0].txid} carries an envelope that could not be read: {unreadable[0].reason}"

    return MutableChainWalk(
        ref=ref,
        steps=tuple(steps),
        tip_txid=cur_txid,
        tip_vout=cur_vout,
        tip_proved_unspent=proved,
        complete=bool(proved and not reason),
        reason=reason,
        excluded=tuple(sorted(pool)),
    )


@dataclass(frozen=True)
class FoldedRecord:
    """A mutable glyph's ``attrs`` as of some point in its chain."""

    attrs: dict
    #: How many chain steps were folded to produce it.
    steps_applied: int
    #: The last step included. Empty if only the mint was.
    through_txid: str
    #: True when a step in the folded range could not be read. The result is then a fold of
    #: what WAS readable, which is not the same thing as the record - callers must degrade.
    incomplete: bool
    reason: str = ""


def fold_chain(walk: MutableChainWalk, *, through_index: int | None = None) -> FoldedRecord:
    """Replay a walk's updates onto the mint, shallow-merging ``attrs``.

    THE RULE: an update that OMITS a field leaves that field UNCHANGED. Decided in
    ``docs/solutions/design-decisions/wave-update-fold-omission-means-unchanged.md``, and the
    argument is that deletion is not representable - Photonic's ``filterAttrs`` drops
    ``null``/``undefined`` before merging, so if omission meant *clear* a field could be
    destroyed only by accident and never on purpose. Measured, the two candidate rules disagree
    on 3 of the 7 real chains on mainnet, and only about ``expires``.

    NEW SEMANTICS, NOT A PORT. Photonic computes only CURRENT state, by merging the mint with the
    LATEST envelope, ordered by an index's array - and its stored row is path-dependent, so two
    of its wallets can disagree about one name. This replays every step in spend order, which is
    deterministic where the reference is not. It agrees with the reference on all 7 observed
    chains.

    VALUES ARE NORMALISED TO STRINGS. The two readers disagree on type: ``GlyphMetadata.attrs``
    is ``dict[str, str]`` so a mint stringifies, while ``decode_update_payload`` returns raw
    CBOR. Merged raw, a field's type would depend on which envelope last wrote it - ``expires``
    is ``'1849006310'`` from a mint and ``1849006310`` from an update, and ``str > int`` raises
    in Python 3. Normalising here means a consumer never has to ask which envelope won.

    :param through_index: fold only the first N+1 steps. ``None`` folds all of them.
    """
    steps = walk.steps if through_index is None else walk.steps[: through_index + 1]
    attrs: dict = {}
    unreadable = None
    for step in steps:
        if step.kind == "unreadable":
            unreadable = unreadable or step
            continue
        for key, value in step.attrs.items():
            attrs[str(key)] = str(value)
    reason = ""
    if unreadable is not None:
        reason = (
            f"{unreadable.txid} carries an envelope that could not be read ({unreadable.reason}); "
            "this is a fold of what was readable, not the record"
        )
    return FoldedRecord(
        attrs=attrs,
        steps_applied=len(steps),
        through_txid=steps[-1].txid if steps else "",
        incomplete=unreadable is not None,
        reason=reason,
    )


__all__ = ["MAX_CHAIN_STEPS", "ChainStep", "FoldedRecord", "MutableChainWalk", "fold_chain", "walk_mutable_chain"]
