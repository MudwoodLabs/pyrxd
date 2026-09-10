"""§7.6 form 2: what a name pointed at AT THE MARK'S BLOCK — and every way it must refuse to say.

Form 1 is shipped and hedged: `names_resolving_now`, `point_in_time: false`, and a caveat that
names change hands. That hedge protects people. Form 2 replaces it with an authoritative sentence,
so every gap costs more here than the same gap costs there — which is why most of this file is
degrade paths rather than the happy one.

The happy path is real, on real mainnet bytes. `custodian-gate-x7f3.rxd` moved from `1CPfirXZ…` to
`14XmXG3d…` at height 458591, and form 2 distinguishes the eras a present-tense lookup conflates::

    mark at 458586  ->  1CPfirXZahPrTb93QouwBfKDoz1ykfcBb7
    mark at 458595  ->  14XmXG3dSBWZUukGT3xzS9zxpiZ53vgx1i
"""

from __future__ import annotations

import json
import pathlib

import pytest

from pyrxd.glyph.mark_anchor import MarkAnchor
from pyrxd.glyph.mutable_chain import walk_mutable_chain
from pyrxd.glyph.wave_identity import EXPIRY_UNKNOWN, judge_name_at_mark
from pyrxd.transaction.transaction import Transaction

_FIX = pathlib.Path(__file__).parent / "fixtures" / "wave_update_chain_mainnet.json"
_CHAIN = json.loads(_FIX.read_text())
_RAW = {t["txid"]: bytes.fromhex(t["raw"]) for t in _CHAIN["transactions"]}
_HEIGHTS = {t["txid"]: t["height"] for t in _CHAIN["transactions"]}

MINT = "f644794b3fb9ab8330b236debbe1989ce1034e5b2a8f8f2516e05f4e54f3cf31"
MINT_TARGET = "1CPfirXZahPrTb93QouwBfKDoz1ykfcBb7"
MOVED = "14XmXG3dSBWZUukGT3xzS9zxpiZ53vgx1i"

BINDING = "index-B"
NODE = "node-A"


async def _fetch(txid: str):
    return Transaction.from_hex(_RAW[txid])


async def _unspent(_t: str, _v: int) -> bool:
    return True


async def _walk():
    return await walk_mutable_chain(mint_txid=MINT, candidates=list(_RAW), fetch_tx=_fetch, is_unspent=_unspent)


def _anchor(height: int | None, *, confs: int = 50, floor: int = 6, source: str = NODE) -> MarkAnchor:
    return MarkAnchor(txid="ma" * 32, height=height, confirmations=confs, min_confirmations=floor, source=source)


# ---------------------------------------------------------------------------
# 1. It answers the question form 1 cannot
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("mark_height", "expected"),
    [(458586, MINT_TARGET), (458590, MINT_TARGET), (458595, MOVED), (458605, MOVED)],
)
async def test_it_reports_the_target_in_force_at_the_marks_block(mark_height: int, expected: str) -> None:
    verdict = judge_name_at_mark(
        ref=(await _walk()).ref,
        binding_source=BINDING,
        anchor=_anchor(mark_height),
        walk=await _walk(),
        step_heights=_HEIGHTS,
    )
    assert verdict.form == 2, verdict.degraded_reason
    assert verdict.target_at_height == expected
    assert verdict.is_point_in_time


async def test_the_eras_actually_differ() -> None:
    """Non-vacuity. If the name had been repointed to the address it already had, every
    assertion above would hold against an implementation that ignores updates entirely."""
    assert MINT_TARGET != MOVED


async def test_a_form2_verdict_still_refuses_to_answer_expiry() -> None:
    """Photonic's own source: the indexer decides renewals from TREASURY PAYMENTS, which this
    walk never observes, and `attrs.expires` is display-level. A number here would be a lie
    with the shape of an answer."""
    walk = await _walk()
    verdict = judge_name_at_mark(
        ref=walk.ref, binding_source=BINDING, anchor=_anchor(458605), walk=walk, step_heights=_HEIGHTS
    )
    assert verdict.form == 2
    assert verdict.expiry == EXPIRY_UNKNOWN
    assert not verdict.expiry.isdigit()


async def test_the_binding_is_never_claimed_as_verified() -> None:
    """Nothing checks the name→glyph binding on chain yet, so it stays False even on a form-2
    verdict — and the verdict names the REF it is actually about."""
    walk = await _walk()
    verdict = judge_name_at_mark(
        ref=walk.ref, binding_source=BINDING, anchor=_anchor(458605), walk=walk, step_heights=_HEIGHTS
    )
    assert verdict.binding_verified is False
    assert verdict.ref == walk.ref
    assert verdict.binding_source == BINDING


# ---------------------------------------------------------------------------
# 2. Every degrade path — form 1 WITH A REASON, never silence and never a guess
# ---------------------------------------------------------------------------


async def test_no_block_degrades() -> None:
    """A pasted script has no block, so form 2 is unavailable by construction."""
    walk = await _walk()
    verdict = judge_name_at_mark(
        ref=walk.ref, binding_source=BINDING, anchor=_anchor(None, confs=0), walk=walk, step_heights=_HEIGHTS
    )
    assert verdict.form == 1
    assert "no block" in verdict.degraded_reason
    assert verdict.target_at_height is None


async def test_a_shallow_mark_degrades_and_names_the_bar() -> None:
    walk = await _walk()
    verdict = judge_name_at_mark(
        ref=walk.ref,
        binding_source=BINDING,
        anchor=_anchor(458605, confs=2, floor=6),
        walk=walk,
        step_heights=_HEIGHTS,
    )
    assert verdict.form == 1
    assert "2 confirmations deep, below the 6" in verdict.degraded_reason


async def test_one_source_for_both_answers_degrades() -> None:
    """THE independence property. An endpoint that supplies the height AND the name→glyph
    binding can choose the block, then choose what the name said at it."""
    walk = await _walk()
    verdict = judge_name_at_mark(
        ref=walk.ref,
        binding_source=NODE,  # same as the anchor's source
        anchor=_anchor(458605, source=NODE),
        walk=walk,
        step_heights=_HEIGHTS,
    )
    assert verdict.form == 1
    assert "both came from" in verdict.degraded_reason


async def test_an_incomplete_walk_degrades() -> None:
    """A truncated history is how a superseded target becomes authoritative."""
    truncated = await walk_mutable_chain(
        mint_txid=MINT,
        candidates=list(_RAW),
        fetch_tx=_fetch,  # no tip proof
    )
    verdict = judge_name_at_mark(
        ref=truncated.ref, binding_source=BINDING, anchor=_anchor(458605), walk=truncated, step_heights=_HEIGHTS
    )
    assert verdict.form == 1
    assert "did not walk completely" in verdict.degraded_reason


async def test_a_step_with_no_height_degrades() -> None:
    """A step that cannot be PLACED cannot be ordered against the mark — and quietly treating
    it as 'before' would fold in an update that may have come after."""
    walk = await _walk()
    holes = {**_HEIGHTS, walk.steps[-1].txid: None}
    verdict = judge_name_at_mark(
        ref=walk.ref, binding_source=BINDING, anchor=_anchor(458605), walk=walk, step_heights=holes
    )
    assert verdict.form == 1
    assert "no block height for" in verdict.degraded_reason


async def test_a_mark_older_than_the_name_degrades() -> None:
    walk = await _walk()
    verdict = judge_name_at_mark(
        ref=walk.ref, binding_source=BINDING, anchor=_anchor(458000), walk=walk, step_heights=_HEIGHTS
    )
    assert verdict.form == 1
    assert "did not exist when the mark was made" in verdict.degraded_reason


async def test_every_degrade_carries_a_reason_and_never_a_target() -> None:
    """Swept, so a future path cannot be added that degrades silently."""
    walk = await _walk()
    cases = [
        _anchor(None, confs=0),
        _anchor(458605, confs=1, floor=6),
        _anchor(458000),
        _anchor(458605, source=BINDING),
    ]
    for anchor in cases:
        verdict = judge_name_at_mark(
            ref=walk.ref,
            binding_source=BINDING,
            anchor=anchor,
            walk=walk,
            step_heights=_HEIGHTS,
        )
        if verdict.form == 1:
            assert verdict.degraded_reason, f"a degrade with no reason: {anchor}"
            assert verdict.target_at_height is None, "a degraded verdict must not carry a target"
            assert verdict.expiry == EXPIRY_UNKNOWN


async def test_the_caveat_survives_onto_every_verdict() -> None:
    """The height is the endpoint's claim in BOTH forms; a form-2 verdict must not shed the
    qualifier just because it managed to answer."""
    walk = await _walk()
    for anchor in (_anchor(458605), _anchor(None, confs=0)):
        verdict = judge_name_at_mark(
            ref=walk.ref, binding_source=BINDING, anchor=anchor, walk=walk, step_heights=_HEIGHTS
        )
        assert "NOT verified" in verdict.caveat
