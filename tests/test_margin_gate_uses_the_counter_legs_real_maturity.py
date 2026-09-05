"""``assert_timelock_margin`` must price ``t_btc`` at the maturity CONSENSUS enforces.

WHICH SIDE OF THE INEQUALITY A TERM LANDS ON is what decides whether rounding is safe — not
whether the term is a "deadline" or a "reserve". The gate is::

    maker_refund_opens_s < taker_refund_opens_s + margin_s   ->  raise

``t_rxd`` builds the LHS (rounding down shrinks it — STRICTER), while ``t_btc`` and ``margin``
both build the RHS (rounding down shrinks the bar — PERMISSIVE). #624 derived exactly that for
``margin`` and fixed it to ceil, and then recorded in the comment beside it that "``t_btc``/
``t_rxd`` above are DEADLINES and floor correctly", grouping ``t_btc`` with the term on the OTHER
side. The same premise was written into ``test_reserves_use_the_ceiling_conversion``'s docstring as
the reason ``t_btc`` was safe to leave out of its derived field set — so the guard built for the
class carried the error of the instance. Both sentences are corrected; this file is the test that
would have contradicted them.

AND CEILING ``t_btc`` WOULD ALSO BE WRONG. It is a deadline; its maturity is not a rounding of
anything. BIP68 quantises a SECONDS relative lock to 512-second units
(``tests/vendor/radiant_core/primitives_transaction.h:129-149`` — ``SEQUENCE_LOCKTIME_TYPE_FLAG``
selects "units of 512 seconds", ``SEQUENCE_LOCKTIME_GRANULARITY = 9``), and OP_CSV then compares
the masked operand numerically against the spending input's nSequence
(``tests/vendor/radiant_core/interpreter.cpp:3025-3055``). The gate was instead quantising it onto
``policy.block_interval_s``. Those two grids disagree in BOTH directions, so no rounding rule fixes
it — only the exact quantity does, which is what ``Timelock.consensus_maturity_s`` returns.

REACHABILITY, CHECKED RATHER THAN ASSUMED. Nothing in ``pyrxd`` or ``scripts/`` constructs a
SECONDS-tagged ``t_btc``, so every in-tree swap is unaffected by this change. But
``NegotiatedTerms`` does not PIN ``t_btc`` to BLOCKS the way it pins ``t_rxd``: ``from_dict`` takes
the unit tag straight off the wire and both of that class's own guards are unit-scoped (its own
"SCOPE, HONESTLY" comment says so). The terms envelope is authored by the MAKER and validated by
the taker, so the tag is counterparty-controlled. ``test_a_seconds_tagged_t_btc_is_not_a_fiction``
below builds one through the real wire form rather than by hand.
"""

from __future__ import annotations

import pytest

from pyrxd.btc_wallet.taproot import (
    SEQUENCE_LOCKTIME_MASK,
    Timelock,
    TimeUnit,
    refund_leaf_script,
)
from pyrxd.gravity.swap_coordinator import MarginPolicy, assert_timelock_margin
from pyrxd.security.errors import ValidationError

_BIP68_UNIT_S = 512
_POLICY = MarginPolicy.estimated(block_interval_s=600.0)
_MARGIN_S = _POLICY.margin.value * _POLICY.block_interval_s  # 36 blk x 600 s = 21600 s


def _consensus_maturity_s(t: Timelock) -> int:
    """The chain's own number, written out independently of the code under test.

    A test that called ``consensus_maturity_s`` to compute its own expectation would agree with
    the implementation by construction and prove nothing.
    """
    if t.unit is TimeUnit.BLOCKS:
        return int(t.value * _POLICY.block_interval_s)
    return (t.value // _BIP68_UNIT_S) * _BIP68_UNIT_S


def _accepts(t_btc: Timelock, t_rxd_blocks: int) -> bool:
    try:
        assert_timelock_margin(t_btc, Timelock(t_rxd_blocks, TimeUnit.BLOCKS), _POLICY)
    except ValidationError:
        return False
    return True


def _true_gap_s(t_btc: Timelock, t_rxd_blocks: int) -> float:
    return t_rxd_blocks * _POLICY.rxd_block_interval_s - _consensus_maturity_s(t_btc)


def _old_grid_accepts(t_btc: Timelock, t_rxd_blocks: int) -> bool:
    """The PRE-FIX verdict: `floor(t_btc -> blocks) * block_interval_s` as the counter-leg maturity.

    Every fixture below asserts that this disagrees with the fix, so a fixture that drifts onto a
    value where the two grids happen to agree fails loudly instead of passing while proving
    nothing — the way a test can pass on a scenario that no longer discriminates.
    """
    old_taker_s = t_btc.normalize_to(TimeUnit.BLOCKS, block_interval_s=_POLICY.block_interval_s).value * (
        _POLICY.block_interval_s
    )
    return t_rxd_blocks * _POLICY.rxd_block_interval_s >= old_taker_s + _MARGIN_S


# ---------------------------------------------------------------------------
# The two grids, and how far apart they get — measured, not asserted
# ---------------------------------------------------------------------------


def test_the_two_grids_disagree_in_both_directions():
    """Non-vacuity for every fixture below. If BIP68's 512 s grid and the 600 s block grid ever
    stopped disagreeing, every case in this file would pass while discriminating nothing.

    Swept over the whole range the fixtures use. The block grid runs up to 592 s LOW (the
    PERMISSIVE side: the gate thought the taker's refund opened earlier than it does) and up to
    504 s HIGH (the OVER-STRICT side: honest terms refused). Bounded by one ``block_interval_s``
    either way, which is why this is an erosion of the margin and not a way to erase it.
    """
    diffs = {v: (v // 512) * 512 - (v // 600) * 600 for v in range(200_000)}
    assert max(diffs.values()) == 592
    assert max(diffs, key=diffs.get) == 20_992
    assert min(diffs.values()) == -504
    assert min(diffs, key=diffs.get) == 17_400


@pytest.mark.parametrize("value", [512, 1023, 1024, 17_400, 20_992, 59_399, 65_535])
def test_the_maturity_matches_the_bytes_the_refund_leaf_actually_pushes(value):
    """ROUND-TRIP THROUGH THE TRANSPORT THAT CARRIES IT. The number the gate reasons about has to
    be the number the on-chain script enforces, so read the operand back out of the emitted leaf
    rather than off the function that produced it.
    """
    t = Timelock(value, TimeUnit.SECONDS)
    leaf = refund_leaf_script(b"\x02" * 32, t)
    # `<operand> OP_CSV OP_DROP ...` — the leading minimal push is the CSV operand.
    n = leaf[0]
    assert 1 <= n <= 75, "the operand is no longer a direct data push; re-read the leaf builder"
    operand = int.from_bytes(leaf[1 : 1 + n], "little")
    units = operand & SEQUENCE_LOCKTIME_MASK
    assert t.consensus_maturity_s(block_interval_s=600.0) == units * _BIP68_UNIT_S
    assert t.consensus_maturity_s(block_interval_s=600.0) == _consensus_maturity_s(t)


def test_a_blocks_tagged_lock_is_priced_at_the_interval_with_no_rounding():
    assert Timelock(36, TimeUnit.BLOCKS).consensus_maturity_s(block_interval_s=600.0) == 21_600.0


@pytest.mark.parametrize("bad", [0.0, -1.0, float("nan"), float("inf")])
def test_the_maturity_refuses_an_unusable_interval(bad):
    with pytest.raises(ValidationError):
        Timelock(36, TimeUnit.BLOCKS).consensus_maturity_s(block_interval_s=bad)


# ---------------------------------------------------------------------------
# The gate's verdict must follow the TRUE gap, on both sides
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("seconds", "t_rxd_blocks"),
    [
        # PERMISSIVE side. The old expression put the taker's refund at 20400 s where BIP68 puts
        # it at 20992 s, so it accepted terms whose real gap is 21008 s against a 21600 s margin —
        # 592 s of the taker's cross-chain safety buffer, chosen by whoever authored the envelope.
        (20_992, 140),
        (59_399, 269),
    ],
)
def test_terms_short_of_the_margin_are_refused(seconds, t_rxd_blocks):
    t_btc = Timelock(seconds, TimeUnit.SECONDS)
    assert _true_gap_s(t_btc, t_rxd_blocks) < _MARGIN_S, "fixture no longer sits on the short side"
    assert _old_grid_accepts(t_btc, t_rxd_blocks), "fixture no longer discriminates"
    assert not _accepts(t_btc, t_rxd_blocks)


@pytest.mark.parametrize(
    ("seconds", "t_rxd_blocks"),
    [
        # OVER-STRICT side, and the reason this is not simply "make the gate stricter": the old
        # expression put the refund at 17400 s where BIP68 puts it at 16896 s, so it REFUSED terms
        # with 21804 s of real gap against a 21600 s margin. A guard that refuses valid work is a
        # bug, and this direction is the half a ceil-everything fix would have made worse.
        (17_400, 129),
        (24_012, 151),
    ],
)
def test_honest_terms_that_clear_the_margin_are_accepted(seconds, t_rxd_blocks):
    t_btc = Timelock(seconds, TimeUnit.SECONDS)
    assert _true_gap_s(t_btc, t_rxd_blocks) >= _MARGIN_S, "fixture no longer sits on the honest side"
    assert not _old_grid_accepts(t_btc, t_rxd_blocks), "fixture no longer discriminates"
    assert _accepts(t_btc, t_rxd_blocks)


@pytest.mark.parametrize("seconds", [17_400, 20_992, 59_399])
def test_the_verdict_boundary_sits_exactly_on_the_consensus_gap(seconds):
    """Sweep the t_rxd that flips the verdict and check it is the first one whose TRUE gap clears
    the margin — an off-by-one on either side of the boundary is what the old grid produced."""
    t_btc = Timelock(seconds, TimeUnit.SECONDS)
    flips = [n for n in range(1, 400) if _accepts(t_btc, n) and not _accepts(t_btc, n - 1)]
    assert len(flips) == 1, f"the verdict is not monotone in t_rxd: {flips}"
    boundary = flips[0]
    assert _true_gap_s(t_btc, boundary) >= _MARGIN_S
    assert _true_gap_s(t_btc, boundary - 1) < _MARGIN_S


# ---------------------------------------------------------------------------
# The honest path: every BLOCKS-tagged swap this tree builds is untouched
# ---------------------------------------------------------------------------


def test_no_blocks_tagged_verdict_moved():
    """The whole in-tree corpus is BLOCKS-tagged, so this change must be a NO-OP for it. Compared
    against the pre-fix expression (``floor(t_btc -> blocks) * block_interval_s``) rather than
    against a remembered list of verdicts."""
    for btc in range(1, 120):
        t_btc = Timelock(btc, TimeUnit.BLOCKS)
        old = t_btc.normalize_to(TimeUnit.BLOCKS, block_interval_s=600.0).value * 600.0
        assert t_btc.consensus_maturity_s(block_interval_s=600.0) == old
        for rxd in range(1, 400, 7):
            assert _accepts(t_btc, rxd) == (rxd * _POLICY.rxd_block_interval_s >= old + _MARGIN_S)


def test_the_dust_defaults_still_pass():
    """A named honest case, in the shape a real run uses: t_rxd=180 blk (15.0 h) against t_btc=36
    blk (6.0 h) with the 36-block margin (6.0 h)."""
    assert _accepts(Timelock(36, TimeUnit.BLOCKS), 180)


# ---------------------------------------------------------------------------
# ...and the situation is one that can actually occur
# ---------------------------------------------------------------------------


def test_a_seconds_tagged_t_btc_is_not_a_fiction():
    """A fixture the real system could never produce verifies nothing. ``t_rxd`` IS pinned to
    BLOCKS; ``t_btc`` is not, and the unit tag comes off the wire — so build the terms the way a
    counterparty's envelope reaches the taker, through ``NegotiatedTerms.from_dict``."""
    import hashlib
    import os

    import coincurve

    from pyrxd.gravity.swap_state import NegotiatedTerms

    xonly = coincurve.PublicKeyXOnly.from_secret(os.urandom(32)).format().hex()
    wire = {
        "hashlock": hashlib.sha256(os.urandom(32)).hexdigest(),
        "btc_sats": 100_000,
        "radiant_amount": 1_000,
        "t_btc": {"value": 20_992, "unit": "seconds"},
        "t_rxd": {"value": 140, "unit": "blocks"},
        "asset_variant": "rxd",
        "genesis_ref": "",
        "taker_dest_hash": "11" * 32,
        "maker_dest_hash": "22" * 32,
        "btc_claim_pubkey_xonly": xonly,
        "btc_refund_pubkey_xonly": xonly,
    }
    terms = NegotiatedTerms.from_dict(wire)
    assert terms.t_btc == Timelock(20_992, TimeUnit.SECONDS), (
        "NegotiatedTerms now pins t_btc to BLOCKS — if that is deliberate, this whole file is "
        "unreachable and should say so rather than testing a shape the wire can no longer carry"
    )
    # ...and the gate the taker runs on it refuses, where it used to accept.
    with pytest.raises(ValidationError, match="insufficient margin"):
        assert_timelock_margin(terms.t_btc, terms.t_rxd, _POLICY)


def test_the_refusal_message_quotes_the_consensus_number():
    """The message is a CLAIM. It used to print ``{btc_blocks} blk x {interval}s`` beside the
    seconds figure the inequality used, so the two disagreed for exactly the terms in dispute."""
    with pytest.raises(ValidationError) as e:
        assert_timelock_margin(Timelock(20_992, TimeUnit.SECONDS), Timelock(140, TimeUnit.BLOCKS), _POLICY)
    assert "20992s, which BIP68 quantises to 20992s" in str(e.value)
    assert "5.83 h" in str(e.value), "20992 s is 5.83 h — the hours and the seconds must agree"
