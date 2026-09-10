"""HashMark §7.6 form 2 — what a WAVE name pointed at AT THE BLOCK THAT CARRIED THE MARK.

Form 1 (shipped, ``cli/glyph_inspect.py``) answers a present-tense question and refuses the
inference: it reports ``names_resolving_now`` with ``point_in_time: false`` and a caveat saying
names change hands. That hedge is doing real protective work, and form 2 replaces it with an
authoritative sentence — so every gap here costs more than the same gap costs there.

WHAT A FORM-2 VERDICT MEANS, EXACTLY: *the key that signed this mark also controlled the glyph at
ref R — which an index reports as this name — at block N.* It does not establish authorship, it
does not establish consent, and it says nothing whatever about location. A signature proves key
custody; if a key is extracted, marks can be produced anywhere by anyone holding it.

THE VERDICT IS STRUCTURALLY NARROW, not narrow by docstring. ``form`` is an int rather than a bool
so no caller can read a single flag optimistically; ``expiry`` is a string state rather than a
number so nobody can compare it to a clock; ``binding_verified`` starts False and stays False until
something actually checks the name→glyph binding on chain. Rules that live only in prose decay -
this project has a whole solutions note about it.

FOUR THINGS MUST HOLD, or the verdict degrades to form 1 WITH A REASON:

1. The mark has a block, buried to the caller's bar (``MarkAnchor.usable_for_point_in_time``).
2. The name's chain walked completely and its tip is proved (``MutableChainWalk.complete``).
3. Every step in the folded range was readable. An unreadable envelope means the fold is of what
   was readable, which is not the record.
4. The height and the name→glyph binding came from DIFFERENT sources. One endpoint that supplies
   both can move the answer twice - pick the block, then pick what the name said then.

Degrading is not a failure mode here, it is the design. Form 1 with a reason is always available
and always honest; a form-2 sentence built on an unproved input is neither.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from .mark_anchor import MarkAnchor
from .mutable_chain import MutableChainWalk, fold_chain

#: `attrs.expires` is NOT the expiry. Photonic's own source says the indexer is authoritative on
#: renewals - it extends expiry from TREASURY PAYMENTS, which no envelope walk observes - and that
#: the CBOR field is "display-level". So form 2 cannot answer "was this name expired at block N",
#: and says so rather than reading a number that looks like an answer.
EXPIRY_UNKNOWN = "unknown: renewals are decided by treasury payments this walk does not observe"


@dataclass(frozen=True)
class WaveIdentityVerdict:
    """What can be said about a name and a mark. Read ``form`` first."""

    #: 1 = present-tense only (degraded). 2 = established at ``height``. An int, not a bool.
    form: int
    #: The glyph this is ABOUT, always. If the name→glyph binding is wrong, this stays true of
    #: the ref and simply says nothing about the name — which is the correct failure.
    ref: str
    #: How the name→glyph binding was obtained. Compared with the anchor's source.
    binding_source: str
    #: False until something verifies the binding ON CHAIN. Nothing does yet.
    binding_verified: bool
    target_at_height: str | None
    height: int | None
    provisional: bool
    expiry: str
    #: Empty iff ``form == 2``.
    degraded_reason: str
    caveat: str

    @property
    def is_point_in_time(self) -> bool:
        return self.form == 2


def _degrade(*, ref: str, binding_source: str, reason: str, anchor: MarkAnchor) -> WaveIdentityVerdict:
    return WaveIdentityVerdict(
        form=1,
        ref=ref,
        binding_source=binding_source,
        binding_verified=False,
        target_at_height=None,
        height=anchor.height,
        provisional=anchor.provisional,
        expiry=EXPIRY_UNKNOWN,
        degraded_reason=reason,
        caveat=anchor.caveat,
    )


def judge_name_at_mark(
    *,
    ref: str,
    binding_source: str,
    anchor: MarkAnchor,
    walk: MutableChainWalk,
    step_heights: Mapping[str, int | None],
) -> WaveIdentityVerdict:
    """Compose an anchor and a completed walk into a form-2 verdict, or degrade to form 1.

    Pure: every network answer is already in ``anchor``, ``walk`` and ``step_heights``, so each
    degrade path is reachable in a test without a chain.

    ``step_heights`` maps each walked txid to its block height. A step whose height is unknown
    cannot be placed relative to the mark, so the walk cannot be folded "as of" anything and the
    verdict degrades — an unplaceable step is not a step that happened after.
    """
    if not anchor.usable_for_point_in_time:
        if anchor.height is None:
            reason = "the mark has no block (unmined, or pasted without one) — form 2 needs one"
        else:
            reason = (
                f"the mark is {anchor.confirmations} confirmations deep, below the "
                f"{anchor.min_confirmations} required — too shallow to build a claim on"
            )
        return _degrade(ref=ref, binding_source=binding_source, reason=reason, anchor=anchor)

    if binding_source == anchor.source:
        return _degrade(
            ref=ref,
            binding_source=binding_source,
            reason=(
                f"the block height and the name→glyph binding both came from {anchor.source!r}; "
                "one source that supplies both can choose the block AND what the name said then"
            ),
            anchor=anchor,
        )

    if not walk.complete:
        return _degrade(
            ref=ref,
            binding_source=binding_source,
            reason=f"the name's chain did not walk completely: {walk.reason}",
            anchor=anchor,
        )

    missing = [s.txid for s in walk.steps if step_heights.get(s.txid) is None]
    if missing:
        return _degrade(
            ref=ref,
            binding_source=binding_source,
            reason=f"no block height for {missing[0]} — a step that cannot be placed cannot be ordered against the mark",
            anchor=anchor,
        )

    # The last step at or before the mark's block. Steps are already in SPEND order, which is the
    # order that counts: two updates can share a height, so a height comparison alone cannot
    # order them - it can only decide which ones are in range.
    in_range = [i for i, s in enumerate(walk.steps) if (step_heights[s.txid] or 0) <= (anchor.height or 0)]
    if not in_range:
        return _degrade(
            ref=ref,
            binding_source=binding_source,
            reason=(
                f"the name's first chain step is later than the mark's block {anchor.height} — "
                "the name did not exist when the mark was made"
            ),
            anchor=anchor,
        )

    folded = fold_chain(walk, through_index=in_range[-1])
    if folded.incomplete:
        return _degrade(ref=ref, binding_source=binding_source, reason=folded.reason, anchor=anchor)

    return WaveIdentityVerdict(
        form=2,
        ref=ref,
        binding_source=binding_source,
        binding_verified=False,
        target_at_height=folded.attrs.get("target"),
        height=anchor.height,
        provisional=False,
        expiry=EXPIRY_UNKNOWN,
        degraded_reason="",
        caveat=anchor.caveat,
    )


__all__ = ["EXPIRY_UNKNOWN", "WaveIdentityVerdict", "judge_name_at_mark"]
