"""HashMark §7.6 form 2 — what a WAVE name pointed at AT THE BLOCK THAT CARRIED THE MARK.

Form 1 (shipped, ``cli/glyph_inspect.py``) answers a present-tense question and refuses the
inference: it reports ``names_resolving_now`` with ``point_in_time: false`` and a caveat saying
names change hands. That hedge is doing real protective work, and form 2 replaces it with an
authoritative sentence — so every gap here costs more than the same gap costs there.

WHAT A FORM-2 VERDICT MEANS, EXACTLY: *the key that signed this mark also controlled the glyph at
ref R — which an index reports as this name, and whose own mint payload names it — at block N.* It
does not establish authorship, it does not establish consent, and it says nothing whatever about
location. A signature proves key custody; if a key is extracted, marks can be produced anywhere by
anyone holding it.

THE VERDICT IS STRUCTURALLY NARROW, not narrow by docstring. ``form`` is an int rather than a bool
so no caller can read a single flag optimistically; ``expiry`` is a string state rather than a
number so nobody can compare it to a clock; ``binding_verified`` stays False because nothing
proves on chain that the glyph an index named is the registration IN FORCE for that name (the
check below proves only that the glyph's own mint claims the name, which a duplicate or a lapsed
registration also does). Rules that live only in prose decay - this project has a whole solutions
note about it.

SIX THINGS MUST HOLD, or the verdict degrades to form 1 WITH A REASON:

1. The mark has a block, buried to the caller's bar (``MarkAnchor.usable_for_point_in_time``).
2. The mark's block and the name→glyph binding came from DIFFERENT sources. One endpoint that
   supplies both can move the answer twice - pick the block, then pick what the name said then.
3. The name's chain walked completely and its tip is proved (``MutableChainWalk.complete``).
4. The glyph's OWN mint payload names the label that was asked about. An index that binds a name
   to someone else's glyph is otherwise believed outright.
5. EVERY BLOCK HEIGHT THE ANSWER COMPARES — the mark's, and each chain step's — was reported
   identically by at least two DIFFERENT sources (:class:`HeightReport`). The heights decide which
   update was current at the mark's block exactly as much as the binding does: an endpoint that
   reports ONE update a few blocks late, still monotonic, still plausible, moves the answer from
   one target to another. Rule 2 alone never covered that — the step heights came from the
   discovery server, which with the shipped endpoint order also supplied the mark's block.
6. Every step in the folded range was readable, and the target it folds to is text. An unreadable
   envelope means the fold is of what was readable, which is not the record.

Degrading is not a failure mode here, it is the design. Form 1 with a reason is always available
and always honest; a form-2 sentence built on an unproved input is neither.

WHAT TWO AGREEING SOURCES STILL DO NOT BUY. Agreement turns one endpoint's lie into a visible
disagreement; it is not proof. The mark's height can be checked against each endpoint's OWN block
header (the CLI does; :attr:`HeightReport.mark_header_bound` records it), the step heights are not,
and nothing checks proof-of-work or merkle inclusion — so two endpoints that tell the SAME lie still
move the answer. The residual trust is "two independent servers do not collude", and the form-2
caveat says exactly which heights were header-checked.
"""

from __future__ import annotations

import itertools
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

import cbor2

from pyrxd.network._guards import nonneg_int
from pyrxd.security.errors import ValidationError

from .mark_anchor import MarkAnchor
from .mutable_chain import MutableChainWalk, fold_chain
from .wave_rules import WAVE_ROOT_DOMAIN, _indexer_name_problem, _is_wave_marked, indexed_wave_name

#: `attrs.expires` is NOT the expiry. Photonic's own source says the indexer is authoritative on
#: renewals - it extends expiry from TREASURY PAYMENTS, which no envelope walk observes - and that
#: the CBOR field is "display-level". So form 2 cannot answer "was this name expired at block N",
#: and says so rather than reading a number that looks like an answer.
EXPIRY_UNKNOWN = "unknown: renewals are decided by treasury payments this walk does not observe"


@dataclass(frozen=True)
class HeightReport:
    """Where ONE endpoint places the mark and each step of the name's chain.

    ``judge_name_at_mark`` needs at least two of these from DIFFERENT sources, agreeing on every
    height it compares, before it will say which target was in force at the mark's block. A
    report is the endpoint's word, labelled — the judge does the comparing, so no caller can
    "corroborate" by assertion.

    ``None`` / an absent txid means THIS endpoint does not place it in a block (it reports it
    unconfirmed, or does not list it at all). Two endpoints that both leave a step unplaced agree;
    one that places it and one that does not disagree, and that degrades.
    """

    #: Who said this — the endpoint's URL in the CLI. Compared across reports.
    source: str
    #: The block this endpoint places the mark in.
    mark_height: int | None
    #: txid -> block height, for the chain steps this endpoint places in a block.
    step_heights: Mapping[str, int | None] = field(default_factory=dict)
    #: Why this endpoint's heights could not be obtained, if they could not. An error is not a
    #: report that nothing is confirmed, and must not be read as one: it degrades, naming it.
    error: str = ""
    #: ``True`` when ``mark_height`` was bound to this endpoint's own header
    #: (:attr:`~pyrxd.glyph.mark_anchor.MarkAnchor.header_bound`). The verdict's caveat says the
    #: mark was header-checked only when EVERY report says so — a default of False makes the weaker
    #: sentence the one a caller gets without asking.
    mark_header_bound: bool = False


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
    #: Always False: nothing proves on chain that this glyph is the registration IN FORCE for the
    #: name. A form-2 verdict has checked that the glyph's own mint NAMES it (rule 4), which is
    #: weaker — a duplicate claim or a lapsed registration names it too.
    binding_verified: bool
    target_at_height: str | None
    height: int | None
    provisional: bool
    expiry: str
    #: Empty iff ``form == 2``.
    degraded_reason: str
    caveat: str
    #: The sources whose block heights agreed, on a form-2 verdict. Empty on a degrade.
    height_sources: tuple[str, ...] = ()

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


def _corroborated_caveat(sources: Sequence[str], *, mark_header_bound: bool) -> str:
    """The form-2 caveat: what the agreement covers, which heights a header checked, what nothing did.

    TRUE BY CONSTRUCTION, not by assumption. It said "pyrxd has no Radiant header ... check" on the
    same screen as a bound anchor's caveat saying the header WAS checked (0.25.0 panel, round 3).
    Whether the mark was header-checked comes from the reports themselves; the step heights never
    are; and proof-of-work and merkle inclusion are checked by nothing.
    """
    header = (
        "The mark's height was also checked against each endpoint's own block header; the step heights were not."
        if mark_header_bound
        else "No height here was checked against a block header."
    )
    return (
        f"block heights — the mark's and every chain step's — were reported identically by "
        f"{' and '.join(repr(s) for s in sources)}, and are NOT verified. {header} Nothing checks "
        "proof-of-work or merkle inclusion, so one endpoint's lie now shows as a disagreement, but "
        "endpoints that agree on the same lie still move the point in time this answer is about"
    )


def _requested_label(name: str) -> str:
    """The label a ``--wave-name`` asks about, or ``ValidationError`` when it is not a top-level name.

    THE DOMAIN MUST BE EXACTLY ``rxd`` — the maintainer's rule, as
    :func:`~pyrxd.glyph.wave_rules.parse_wave_name` states it: split on the FIRST dot, and
    everything after it must be ``rxd``. This used to split on the LAST dot and drop the domain,
    so ``--wave-name alice.evil`` was judged — and printed — as ``alice.rxd``: a verdict about a
    name nobody asked for, rendered as the one they did. ``sub.alice.rxd`` is refused the same way.

    THE LABEL is held to the INDEXER'S rule (:func:`~pyrxd.glyph.wave_rules._indexer_name_problem`),
    not pyrxd's stricter write rule: this asks about names that exist, and the indexer registers
    names pyrxd would not write (``ab``, ``ALICE``). Lower-cased as the indexer keys it.
    """
    if not isinstance(name, str):
        raise ValidationError(f"a WAVE name must be text, got {type(name).__name__}")
    label, dot, domain = name.partition(".")
    if dot and domain != WAVE_ROOT_DOMAIN:
        hint = " (it must be lowercase)" if domain.lower() == WAVE_ROOT_DOMAIN else ""
        raise ValidationError(
            f"{name!r} has domain {domain!r}; a WAVE name's domain must be exactly {WAVE_ROOT_DOMAIN!r}{hint}. "
            "Other roots and subdomains are not resolved here"
        )
    problem = _indexer_name_problem(label)
    if problem:
        raise ValidationError(f"the label {label!r} {problem}, so the indexer never registers it")
    return label.lower()


def _mint_claimed_label(walk: MutableChainWalk) -> tuple[str | None, str]:
    """``(label, why_not)`` — the name the INDEXER would register from the glyph's own mint payload.

    EXACTLY the indexer's reading, and no looser. The payload must be WAVE-marked by its own
    membership test (:func:`~pyrxd.glyph.wave_rules._is_wave_marked`); the name is ``attrs.name``,
    falling back to ``app.data.name`` (:func:`~pyrxd.glyph.wave_rules.indexed_wave_name`); it must
    pass ``validate_wave_name`` (:func:`~pyrxd.glyph.wave_rules._indexer_name_problem`, which
    checks the LOWER-CASED name); it is keyed lower-cased; and its parent must be the root, since
    only top-level names are asked about here.

    This used to strip whitespace and a trailing ``.rxd`` first, so ``" alice "``, ``"alice.rxd"``
    and ``"alice.RXD"`` all read as ``alice`` — three names the indexer REFUSES. That mattered
    most for the middle one: pyrxd through 0.24.0 wrote ``attrs.name = "alice.rxd"``, which the
    indexer never registered (#728), so an index that binds ``alice`` to such a glyph is itself
    evidence of a lie. Accepting it would have waved that lie through.
    """
    mint = walk.steps[0] if walk.steps else None
    if mint is None or mint.kind != "mint" or not mint.envelope_cbor:
        return None, "the walk carries no readable mint payload to take the glyph's own name from"
    try:
        payload = cbor2.loads(mint.envelope_cbor)
    except Exception:  # the walker already decoded these bytes; a failure here is not a claim
        return None, "the glyph's mint payload does not decode"
    if not isinstance(payload, dict):
        return None, "the glyph's mint payload is not a CBOR map"
    if not _is_wave_marked(payload):
        return None, "the glyph's own mint is not WAVE-marked, so the indexer's claim path never registers it"
    try:
        claimed, parent = indexed_wave_name(payload)
    except ValidationError as exc:
        return None, f"the glyph's mint payload cannot be read as a WAVE claim: {exc}"
    if not isinstance(claimed, str) or not claimed:
        return None, "the glyph's own mint payload names no WAVE label (no attrs.name or app.data.name)"
    problem = _indexer_name_problem(claimed)
    if problem:
        return None, (
            f"the glyph's own mint names {claimed!r}, which the indexer's validate_wave_name refuses "
            f"(it {problem}) — so it was never registered under any name"
        )
    if parent not in (None, "", WAVE_ROOT_DOMAIN):
        return None, f"the glyph's own mint claims {claimed!r} under {parent!r}, not as a top-level .rxd name"
    return claimed.lower(), ""


def _placed(value: object) -> int | None:
    """A reported height as an int, ``None`` for "not in a block". Raises ``ValueError`` on junk."""
    if value is None:
        return None
    return nonneg_int(value)


def _said(value: int | None) -> str:
    return str(value) if value is not None else "not in a block"


def judge_name_at_mark(
    *,
    ref: str,
    name: str,
    binding_source: str,
    anchor: MarkAnchor,
    walk: MutableChainWalk,
    height_reports: Sequence[HeightReport],
) -> WaveIdentityVerdict:
    """Compose an anchor and a completed walk into a form-2 verdict, or degrade to form 1.

    Pure: every network answer is already in ``anchor``, ``walk`` and ``height_reports``, so each
    degrade path is reachable in a test without a chain.

    ``name`` is the name that was ASKED about (``alice.rxd`` or ``alice``); the glyph's own mint
    payload must claim it. ``height_reports`` is one :class:`HeightReport` per endpoint; at least
    two distinct sources must agree on the mark's height (which must equal ``anchor.height``) and
    on the height of every walked step. A step whose agreed height is unknown cannot be placed
    relative to the mark, so the verdict degrades unless it is already known to fall after it.
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

    # THE CHAIN THIS VERDICT IS ABOUT. `ref` arrives from the name->glyph binding and `walk` from
    # somewhere else; nothing compared them, so a form-2 sentence could name one glyph while
    # reporting a target folded from another's chain - false about both halves, with no reason.
    if walk.ref != ref:
        return _degrade(
            ref=ref,
            binding_source=binding_source,
            reason=(
                f"the walk is of ref {walk.ref}, not {ref} — this verdict would be about one "
                "glyph and built from another's history"
            ),
            anchor=anchor,
        )

    # THE GLYPH MUST NAME ITSELF WHAT WE ASKED FOR. The binding is the indexer's word, and the
    # indexer ALONE could bind any requested name to any glyph — `bank.rxd` to someone's
    # `custodian-gate` chain — and every rule above would pass, because they are all about the
    # chain and the block, not about which name the chain is. The mint payload the walk already
    # fetched (txid-bound, hash-bound to the covenant) says which name this glyph claims; compare.
    try:
        asked = _requested_label(name)
    except ValidationError as exc:
        return _degrade(
            ref=ref, binding_source=binding_source, reason=f"cannot read the name asked about: {exc}", anchor=anchor
        )
    claimed, why_not = _mint_claimed_label(walk)
    if claimed is None:
        return _degrade(
            ref=ref,
            binding_source=binding_source,
            reason=f"{binding_source!r} bound {asked!r} to glyph {ref}, but {why_not}",
            anchor=anchor,
        )
    if claimed != asked:
        return _degrade(
            ref=ref,
            binding_source=binding_source,
            reason=(
                f"{binding_source!r} bound {asked!r} to glyph {ref}, whose own mint payload names "
                f"{claimed!r} — the index answered about a different name's glyph"
            ),
            anchor=anchor,
        )

    # EVERY HEIGHT FROM TWO SOURCES. The mark's block (above) came from one endpoint and every
    # step height from the discovery endpoint; with the shipped order those were the SAME server,
    # and even with an honest anchor, one misreported step height moved which update was current
    # at the mark. So each endpoint's word is taken separately and compared here, where the
    # answer is decided — not beside it, where a caller could forget to.
    failed = [r for r in height_reports if r.error]
    if failed:
        return _degrade(
            ref=ref,
            binding_source=binding_source,
            reason=f"{failed[0].source!r} could not report the block heights to corroborate: {failed[0].error}",
            anchor=anchor,
        )
    # AN UNLABELLED REPORT IS NOT A SECOND SOURCE. It may be the same endpoint as the labelled one,
    # and counting it as independent would let one server's word through as two — the walker's
    # rule for an unnamed candidate/tip source, applied here for the same reason.
    if any(not r.source for r in height_reports):
        return _degrade(
            ref=ref,
            binding_source=binding_source,
            reason=(
                "a block-height report carries no source label; an unattributed report may be the "
                "same endpoint as another, so it cannot count as a second source"
            ),
            anchor=anchor,
        )
    sources = list(dict.fromkeys(r.source for r in height_reports))
    if len(sources) < 2:
        only = repr(sources[0]) if sources else "no endpoint at all"
        return _degrade(
            ref=ref,
            binding_source=binding_source,
            reason=(
                f"every block height came from {only}; one endpoint that reports the heights alone "
                "can choose which update was current at the mark's block — two must agree"
            ),
            anchor=anchor,
        )

    # HEIGHTS, VALIDATED LIKE EVERY OTHER UNTRUSTED NUMBER HERE. `mark_anchor` runs the mark's own
    # depth through `finite_int` and refuses negatives; `wave._optional_int` refuses a bool
    # `expires` with a comment explaining that `isinstance(True, int)` is True in Python. This -
    # the newest and most trust-critical of the four - accepted bools, negatives and zero, and
    # `(h or 0)` turned `False` into "the genesis block", i.e. definitely before any mark.
    marks: list[tuple[str, int | None]] = []
    by_step: dict[str, list[tuple[str, int | None]]] = {step.txid: [] for step in walk.steps}
    for report in height_reports:
        try:
            marks.append((report.source, _placed(report.mark_height)))
        except ValueError as exc:
            return _degrade(
                ref=ref,
                binding_source=binding_source,
                reason=f"unusable block height for the mark from {report.source!r}: {exc}",
                anchor=anchor,
            )
        for step in walk.steps:
            try:
                by_step[step.txid].append((report.source, _placed(report.step_heights.get(step.txid))))
            except ValueError as exc:
                return _degrade(
                    ref=ref,
                    binding_source=binding_source,
                    reason=f"unusable block height for {step.txid} from {report.source!r}: {exc}",
                    anchor=anchor,
                )

    for source, height in marks:
        if height != anchor.height:
            return _degrade(
                ref=ref,
                binding_source=binding_source,
                reason=(
                    f"the endpoints disagree about the mark's block: {anchor.source!r} says {anchor.height}, "
                    f"{source!r} says {_said(height)} — one of them is wrong (behind the tip, or lying)"
                ),
                anchor=anchor,
            )

    placed: dict[str, int] = {}
    for step in walk.steps:
        said = by_step[step.txid]
        if len({h for _s, h in said}) > 1:
            return _degrade(
                ref=ref,
                binding_source=binding_source,
                reason=(
                    f"the endpoints disagree about the block of chain step {step.txid}: "
                    + ", ".join(f"{s!r} says {_said(h)}" for s, h in said)
                    + " — which update was current at the mark depends on it"
                ),
                anchor=anchor,
            )
        agreed = said[0][1] if said else None
        if agreed is not None:
            placed[step.txid] = agreed

    # NON-DECREASING BY CONSENSUS: a transaction cannot be mined before the transaction it spends,
    # and this walk is spend-ordered. So a decreasing pair is not a quirk to tolerate - it is
    # EVIDENCE that the height source is lying or that state was read across a reorg, which is
    # exactly the case that must degrade.
    #
    # It is also what made `in_range` unsafe. That list is a FILTER; `fold_chain(through_index=N)`
    # folds the PREFIX `steps[:N+1]`. With heights out of order, a step the filter EXCLUDED was
    # folded in anyway, and the verdict reported its target authoritatively with an empty reason.
    # Enforcing monotonicity makes the filter a prefix, and the fold correct by construction
    # rather than by luck.
    ordered = [placed[s.txid] for s in walk.steps if s.txid in placed]
    if any(b < a for a, b in itertools.pairwise(ordered)):
        return _degrade(
            ref=ref,
            binding_source=binding_source,
            reason=(
                f"the reported block heights {ordered} decrease along a spend-ordered chain, which "
                "consensus forbids — the height source is wrong, or this was read across a reorg"
            ),
            anchor=anchor,
        )

    # A step with no height only matters while it could still be IN range. Once a step is known to
    # be after the mark, monotonicity puts every later one after it too, so an unconfirmed tip
    # update cannot affect an answer about an older block. Requiring a height for those refused
    # honest work: any name with an unconfirmed update at its tip became permanently unanswerable
    # about any block, however old.
    cutoff = -1
    for index, step in enumerate(walk.steps):
        height = placed.get(step.txid)
        if height is None:
            return _degrade(
                ref=ref,
                binding_source=binding_source,
                reason=(
                    f"no block height for {step.txid}, and it is not yet known to be after the "
                    "mark — a step that cannot be placed cannot be ordered against it"
                ),
                anchor=anchor,
            )
        if height > (anchor.height or 0):
            break
        cutoff = index

    if cutoff < 0:
        return _degrade(
            ref=ref,
            binding_source=binding_source,
            reason=(
                f"the name's first chain step is later than the mark's block {anchor.height} — "
                "the name did not exist when the mark was made"
            ),
            anchor=anchor,
        )

    folded = fold_chain(walk, through_index=cutoff)
    if folded.incomplete:
        return _degrade(ref=ref, binding_source=binding_source, reason=folded.reason, anchor=anchor)

    # THE TARGET IS WHATEVER THE NAME'S OWNER PUBLISHED. The fold preserves values rather than
    # stringifying them (see `fold_chain`), so `attrs.target` can be any CBOR value — an integer
    # of 40,000 bits, a map, a list. A form-2 sentence says "the name pointed at <target>" and a
    # caller compares it with the signer's address, and neither means anything unless it is
    # text. So a non-text target degrades, with its type named, instead of being handed on to
    # every renderer and `json.dumps` downstream — which is where it crashed.
    target = folded.attrs.get("target")
    if target is not None and not isinstance(target, str):
        return _degrade(
            ref=ref,
            binding_source=binding_source,
            reason=(
                f"the name's `target` at that block is not text (it is {type(target).__name__}), so not an address — "
                "there is nothing to compare the signing key with"
            ),
            anchor=anchor,
        )

    return WaveIdentityVerdict(
        form=2,
        ref=ref,
        binding_source=binding_source,
        binding_verified=False,
        target_at_height=target,
        height=anchor.height,
        provisional=False,
        expiry=EXPIRY_UNKNOWN,
        degraded_reason="",
        caveat=_corroborated_caveat(sources, mark_header_bound=all(r.mark_header_bound for r in height_reports)),
        height_sources=tuple(sources),
    )


__all__ = ["EXPIRY_UNKNOWN", "HeightReport", "WaveIdentityVerdict", "judge_name_at_mark"]
