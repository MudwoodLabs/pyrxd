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

import io
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, field

import cbor2

from pyrxd.hash import hash256
from pyrxd.security.errors import ValidationError

from .inspector import GlyphInspector
from .payload import GLY_MARKER
from .script import parse_mutable_nft_script

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
        return any(s.kind in RECORD_UNKNOWN_KINDS for s in self.steps)


def _mut_outputs(inspector: GlyphInspector, outputs: list[tuple[int, bytes]]) -> list[tuple[int, str, bytes]]:
    """Every mutable output as ``(vout, ref, payload_hash)``.

    ALL of them, not the first. Taking the first raised "that is a different token" on a
    legitimate transaction that updates TWO glyphs and happens to list the other one's mutable
    output earlier - a guard refusing valid work, by the harshest exit this module has, decided by
    output ORDER. Consensus permits the shape; the ref decides which output is ours.
    """
    found = []
    for glyph in inspector.find_glyphs(outputs):
        if glyph.glyph_type != "mut":
            continue
        parsed = parse_mutable_nft_script(glyph.script)
        if parsed is None:  # pragma: no cover - find_glyphs classified it as mut
            continue
        # The outpoint form the inspect path uses (`_inspect_core.py:516`), not the repr.
        found.append((glyph.vout, f"{glyph.ref.txid}:{glyph.ref.vout}", parsed[1]))
    return found


def _mut_output_for(
    inspector: GlyphInspector, outputs: list[tuple[int, bytes]], ref: str | None
) -> tuple[int, str, bytes] | None:
    """The mutable output carrying ``ref``; with ``ref=None``, the only one (or None if ambiguous)."""
    candidates = _mut_outputs(inspector, outputs)
    if ref is not None:
        matching = [c for c in candidates if c[1] == ref]
        return matching[0] if len(matching) == 1 else None
    return candidates[0] if len(candidates) == 1 else None


#: Step kinds that mean THIS STEP'S RECORD IS NOT KNOWN — as opposed to known-and-empty.
#:
#: All three arise AFTER a mutable output carrying a ``payload_hash`` was found, so in every one of
#: them the chain committed to a record and this walker cannot read it. They differ in diagnosis,
#: not in whether the record is known: ``unreadable`` decoded to nothing usable, ``unbound`` revealed
#: bytes that are not what the output commits to, and ``none`` revealed no envelope at all.
#:
#: ONE SET, DERIVED BY EVERY CONSUMER. This was three hand-kept tuples, and they had already drifted:
#: ``fold_chain`` listed only ``unreadable``, so an ``unbound`` step folded as though it were a
#: readable no-op and ``FoldedRecord.incomplete`` stayed False — silently clearing the flag that
#: ``wave_identity`` rule 3 reads to enforce "every step in the folded range was readable".
#: ``none`` was in no list at all, so a step whose output commits to a payload nobody revealed
#: folded as "unchanged" and reported the PREVIOUS target as current.
RECORD_UNKNOWN_KINDS = frozenset({"unreadable", "unbound", "none"})


def _envelope_of(inspector: GlyphInspector, scriptsigs: Sequence[bytes], payload_hash: bytes) -> tuple[str, dict, str]:
    """(kind, attrs, reason) for the envelope THE COVENANT COMMITS TO.

    THE BINDING THIS EXISTS FOR. A mutable output's script carries ``payload_hash``, and measured
    on every real mainnet step of two WAVE chains it is exactly ``sha256d`` of that step's envelope
    CBOR. The chain therefore says which bytes are the record - in the output this walker already
    parses - and the reference implementation resolves the envelope that way too. Reading "the
    first ``gly`` push in any input" instead let the publisher choose:

      * a decoy envelope in an earlier input replaced the record wholesale (a different WAVE
        name's real update, folded as this name's);
      * a readable decoy in front of an UNREADABLE envelope flipped ``complete`` False -> True and
        cleared ``has_unreadable_step``, defeating the very degrade this module advertises;
      * a substituted transaction body rewrote the target outright.

    Matching the committed hash forecloses all three at once: an envelope that is not the one the
    output commits to is not this step's record, whatever input it sits in.

    An envelope is still reported as ``unreadable`` when the committed one cannot be decoded - the
    reason it exists is unchanged - and ``"unbound"`` is a distinct answer from ``"none"``: bytes
    are present and none of them are the record.
    """
    saw_marker = False
    unreadable_reason = ""
    for scriptsig in scriptsigs:
        items, _complete = inspector._walk_pushes(scriptsig)
        for i, item in enumerate(items):
            if item != GLY_MARKER or i + 1 >= len(items):
                continue
            saw_marker = True
            blob = items[i + 1]
            if hash256(blob) != payload_hash:
                continue  # somebody else's envelope, or a decoy - not what the covenant commits to
            if ambiguous := _ambiguous_encoding(blob):
                unreadable_reason = ambiguous
                continue
            envelope = inspector.classify_glyph_scriptsig(bytes([len(GLY_MARKER)]) + GLY_MARKER + _push(blob))
            if envelope is None:  # pragma: no cover - the marker and blob were just rebuilt
                continue
            if envelope.kind == "payload":
                return "mint", dict(_as_attrs(envelope.metadata.attrs)), ""
            if envelope.kind == "update":
                return "update", dict(_as_attrs((envelope.fields or {}).get("attrs"))), ""
            unreadable_reason = envelope.reason
    if unreadable_reason:
        return "unreadable", {}, unreadable_reason
    if saw_marker:
        return (
            "unbound",
            {},
            (
                "this transaction carries glyph envelopes, but none of them hashes to the payload_hash "
                "its own mutable output commits to - so none of them is this token's record"
            ),
        )
    return (
        "none",
        {},
        (
            "this transaction's mutable output commits to a payload_hash, but the transaction "
            "reveals no glyph envelope at all - so this step's record was never published"
        ),
    )


def _ambiguous_encoding(blob: bytes) -> str:
    """Why these committed bytes have more than one reading, or "" if they have exactly one.

    FORM 2 IS AN AUTHORITY CLAIM, so it reads more strictly than the rest of the SDK. Two shapes
    `cbor2` accepts silently give one committed blob two different meanings, both measured:

      * TRAILING BYTES - `cbor2.loads(env + b"...")` decodes the first item and discards the rest.
        The `payload_hash` binding stops an attacker SUBSTITUTING the record; it does not make the
        record unambiguous, because a reader that stops at the first item and one that refuses
        leftovers disagree about the very same committed bytes.
      * DUPLICATE KEYS - `cbor2.loads` defaults to `allow_duplicate_keys=True` and returns the LAST
        value. First-wins is an equally defensible reading, so `target` written twice resolves to
        one address here and possibly another elsewhere - a cross-implementation split on exactly
        the question form 2 answers.

    THIS DELIBERATELY DOES NOT TIGHTEN ``decode_payload``. That reader is shipped and serves every
    glyph on the chain, and the only corpus available here is six real envelopes - all of which
    pass this check, which is not evidence enough to start refusing mints. Narrowing the CLAIM
    rather than the decoder puts the strictness where the authority is: an ambiguous envelope
    reports ``unreadable`` and the verdict degrades to form 1 with this reason, so nothing is
    refused that form 1 could already answer.
    """
    buf = io.BytesIO(blob)
    try:
        cbor2.load(buf)
    except Exception:
        return ""  # undecodable is the classifier's answer to give, not this one's
    if rest := buf.read():
        return f"{len(rest)} bytes follow the CBOR item, so these bytes have two readings"
    try:
        cbor2.loads(blob, allow_duplicate_keys=False)
    except Exception as exc:
        return f"the envelope names a key more than once and readers disagree on which wins ({exc})"
    return ""


def _push(blob: bytes) -> bytes:
    """Minimal push encoding, to hand a single envelope back through the classifier."""
    if len(blob) < 0x4C:
        return bytes([len(blob)]) + blob
    if len(blob) <= 0xFF:
        return b"\x4c" + bytes([len(blob)]) + blob
    if len(blob) <= 0xFFFF:
        return b"\x4d" + len(blob).to_bytes(2, "little") + blob
    return b"\x4e" + len(blob).to_bytes(4, "little") + blob


def _as_attrs(value: object) -> dict:
    """``attrs`` as a mapping, or empty. NEVER ``dict()`` on publisher-chosen CBOR.

    ``decode_update_payload`` constrains the TOP-LEVEL keys and says nothing about the shape of
    ``attrs``, so `dict(value)` met whatever the publisher wrote: a text string raised ValueError
    out of the walk, an int raised TypeError, and a CBOR ARRAY of pairs was silently reinterpreted
    as a map. The first two broke this module's stated contract that only a ref contradiction
    raises; the third let an array masquerade as the record.

    Non-string keys are refused here too. `payload.py` refuses them one level up, with a comment
    saying `str(1)` and `"1"` would collide and "let a writer overwrite a field it never named" -
    and `attrs`, where `target` actually lives, is the level that guard does not reach.
    """
    if not isinstance(value, dict):
        return {}
    return {k: v for k, v in value.items() if isinstance(k, str)}


async def walk_mutable_chain(
    *,
    mint_txid: str,
    candidates: Sequence[str],
    fetch_tx: Callable[[str], Awaitable[object]],
    is_unspent: Callable[[str, int], Awaitable[bool | None]] | None = None,
    candidate_source: str = "",
    tip_source: str = "",
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
    # ONE SOURCE MUST NOT SUPPLY BOTH HALVES. Omitting the updates from `candidates` AND answering
    # "unspent" for the earlier tip needs only two lies from one endpoint, and produces
    # `complete=True` over a stale record with `reason=''` - verbatim the failure this module says
    # it prevents. `judge_name_at_mark` already refuses when the block height and the name->glyph
    # binding share a source; the same rule belongs here, where the discovery hint and the tip
    # proof meet. Unnamed sources are treated as possibly-identical, because they might be.
    if candidate_source == tip_source:
        source_conflict = (
            f"the candidate set and the tip proof came from the same source ({candidate_source!r}); "
            "one source that supplies both can omit the later updates AND certify the earlier tip"
            if candidate_source
            else "the candidate set and the tip proof are unattributed, so they may be one source "
            "that can omit the later updates AND certify the earlier tip"
        )
    else:
        source_conflict = ""

    # A cap of 0 or less made the loop body unreachable, so the walk returned the MINT as the tip
    # with `reason=''` - a confident answer about a chain it never walked. Refuse instead: a cap
    # that cannot express "walk at least one step" is a caller bug, not a shorter walk.
    if not isinstance(max_steps, int) or isinstance(max_steps, bool) or max_steps < 1:
        raise ValidationError(f"max_steps must be an int >= 1, got {max_steps!r}")

    inspector = GlyphInspector()
    pool = {t.lower() for t in candidates}
    pool.discard(mint_txid.lower())

    # FETCH EACH CANDIDATE AT MOST ONCE. The spender search reads the whole remaining pool on every
    # step, so an uncached walk cost `steps x candidates` round trips against whatever endpoint the
    # consumer supplied. Measured on the 3-step mainnet chain with a 1,000-txid discovery hint:
    # 3,007 fetches uncached, 1,004 cached. A transaction does not change between steps, so every
    # one of those repeats bought nothing; the growth is what matters, not today's constant.
    fetched: dict[str, object] = {}

    async def _fetch_once(txid: str) -> object:
        key = txid.lower()
        if key not in fetched:
            fetched[key] = await fetch_tx(txid)
        return fetched[key]

    mint_tx = await _fetch_once(mint_txid)
    outputs = [(o.satoshis, bytes(o.locking_script.serialize())) for o in mint_tx.outputs]
    found = _mut_output_for(inspector, outputs, None)
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
    vout, ref, payload_hash = found
    kind, attrs, why = _envelope_of(
        inspector, [bytes(i.unlocking_script.serialize()) for i in mint_tx.inputs], payload_hash
    )
    steps = [ChainStep(txid=mint_txid, mut_vout=vout, kind=kind, attrs=attrs, reason=why)]
    # THE FRONT OF THE HISTORY, guarded like the back. The tip proof stops suffix truncation; the
    # prefix had no check at all, and `mint_txid` arrives from the same untrusted place as the
    # candidates. Starting the walk at a mid-chain UPDATE produced `complete=True` over a record
    # whose mint-only fields were simply absent - a fold "onto the mint" with no mint in it.
    if kind != "mint":
        return MutableChainWalk(
            ref=ref,
            steps=(),
            tip_txid=mint_txid,
            tip_vout=vout,
            tip_proved_unspent=False,
            complete=False,
            reason=(
                f"{mint_txid} carries a {kind!r} envelope, not a full payload — a walk that does "
                "not start at the mint is missing the base record, not just its beginning"
            ),
            excluded=tuple(sorted(pool)),
        )

    cur_txid, cur_vout = mint_txid, vout
    truncated_reason = ""
    while len(steps) < max_steps:
        # EVERY spender, not the first. `sorted(pool)` picked the lexicographically smallest txid,
        # so an index that added ONE fabricated conflicting spend hijacked the chain for about
        # seven hashes of grinding - and the real confirmed update was then returned in `excluded`,
        # i.e. the walk asserted the truth did not belong to the token. Nothing here can tell a
        # real spend from a forged one: no signature, script or confirmation is checked. So two
        # claimants is an AMBIGUITY this cannot resolve, and it degrades saying so. Denial is a far
        # better failure than a silent, grindable hijack.
        spenders = []
        for cand in sorted(pool):
            tx = await _fetch_once(cand)
            if any(
                str(getattr(i, "source_txid", "")).lower() == cur_txid.lower() and i.source_output_index == cur_vout
                for i in tx.inputs
            ):
                spenders.append((cand, tx))
        if not spenders:
            break
        if len(spenders) > 1:
            truncated_reason = (
                f"{len(spenders)} candidates claim to spend {cur_txid}:{cur_vout} "
                f"({', '.join(c for c, _ in spenders)}) — this cannot tell a real spend from a "
                "forged one, so the chain is ambiguous here rather than resolved by txid order"
            )
            break
        cand, tx = spenders[0]
        pool.discard(cand)

        outs = [(o.satoshis, bytes(o.locking_script.serialize())) for o in tx.outputs]
        nxt = _mut_output_for(inspector, outs, ref)
        if nxt is None and _mut_outputs(inspector, outs):
            raise ValidationError(
                f"{cand} spends this token's mutable output but carries no mutable output for ref "
                f"{ref} — that is a different token, not a continuation"
            )
        if nxt is None:
            # The singleton was spent to something that is not a mutable output. The chain ends
            # here and the token's state cannot advance further, but this is the END of a history
            # rather than a gap in one - so it is not a contradiction.
            truncated_reason = f"{cand} spends the mutable output and produces none — chain ends"
            cur_txid, cur_vout = cand, -1
            break
        nxt_vout, _nxt_ref, nxt_payload_hash = nxt
        kind, attrs, why = _envelope_of(
            inspector, [bytes(i.unlocking_script.serialize()) for i in tx.inputs], nxt_payload_hash
        )
        steps.append(ChainStep(txid=cand, mut_vout=nxt_vout, kind=kind, attrs=attrs, reason=why))
        cur_txid, cur_vout = cand, nxt_vout
    else:
        truncated_reason = f"walk stopped at the {max_steps}-step cap — the chain may continue"

    proved = False
    reason = truncated_reason
    # A negative tip vout means the chain ended in a non-mutable output, and the branch that set it
    # already named the transaction that did so. There is therefore no outpoint left to prove, and
    # no fallback message to add: the `reason or "the chain ends in a non-mutable output"` default
    # that used to sit here could never be read, because every path to `cur_vout < 0` sets
    # `truncated_reason` first. A string nobody can reach is a claim nobody can check.
    if cur_vout >= 0:
        if is_unspent is None:
            reason = reason or (
                "no tip proof was available — an unproved tip cannot be told apart from a truncated history"
            )
        else:
            answer = await is_unspent(cur_txid, cur_vout)
            proved = answer is True
            if not proved:
                reason = reason or (
                    f"{cur_txid}:{cur_vout} is not proved unspent"
                    + ("" if answer is False else " (the source could not say)")
                )

    if source_conflict and not reason:
        reason = source_conflict
    unreadable = [s for s in steps if s.kind in RECORD_UNKNOWN_KINDS]
    if unreadable and not reason:
        reason = f"{unreadable[0].txid}: {unreadable[0].reason}"

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
        if step.kind in RECORD_UNKNOWN_KINDS:
            unreadable = unreadable or step
            continue
        for key, value in step.attrs.items():
            attrs[str(key)] = str(value)
    reason = ""
    if unreadable is not None:
        reason = f"{unreadable.txid}: {unreadable.reason}; this is a fold of what was readable, not the record"
    return FoldedRecord(
        attrs=attrs,
        steps_applied=len(steps),
        through_txid=steps[-1].txid if steps else "",
        incomplete=unreadable is not None,
        reason=reason,
    )


__all__ = [
    "MAX_CHAIN_STEPS",
    "RECORD_UNKNOWN_KINDS",
    "ChainStep",
    "FoldedRecord",
    "MutableChainWalk",
    "fold_chain",
    "walk_mutable_chain",
]
