"""#567: the timelock margin gate must be judged in WALL CLOCK, not in raw block counts.

`t_btc` counts BITCOIN blocks (~600 s). `t_rxd` counts RADIANT blocks (~300 s nominal, 222 s
measured median). `assert_timelock_margin` compared them one-for-one, because `normalize_to(BLOCKS)`
is the identity for a BLOCKS-tagged Timelock and `policy.rxd_block_interval_s` never entered.

    t_btc=144 blk (24.0 h)   t_rxd=180 blk (15.0 h)   raw gap 36  ->  the old gate ACCEPTS

The Radiant refund opens nine hours BEFORE the counter-leg deadline. The maker refunds the leg it
locked while `p` is still secret, then claims the counter leg with `p` — both legs. That is the
layout #482 exists to prevent, reached through the gate #482 corrected.

WHY IT SURVIVED: the conflation is PRE-EXISTING and was FAIL-SAFE under the old rule. Requiring
`t_btc > t_rxd` in raw counts meant BTC wall-clock exceeded Radiant's by more than 2x, so the bug
made the check STRICTER than the protocol needed. Inverting the direction turned the same
conflation fail-open. The units were only ever safe BECAUSE of the direction.

THE PROPERTY BELOW IS ONE-DIRECTIONAL, DELIBERATELY: `gate.ok => the inequality holds`. It never
asserts the converse. A biconditional (`gate.ok == model.safe`) would make this test a false-alarm
generator whose only resolutions are to copy the gate's own reserves into the oracle — making it a
mirror that cannot disagree — or to LOOSEN a fund-safety gate to satisfy a test. Soundness-only can
never push the gate toward accepting more. That the gate refuses valid work is a real defect on this
chain, and it is covered by the NAMED HONEST ROWS below, not by the property.
"""

from __future__ import annotations

import pytest

import pyrxd.btc_wallet.taproot as t
from pyrxd.gravity.swap_coordinator import MarginPolicy, assert_timelock_margin, generate_secret
from pyrxd.security.errors import ValidationError
from tests.test_swap_coordinator import FakeRadiantLeg, _coordinator, _terms

#: Nominal Bitcoin block interval. The BTC leg is the one the maker CLAIMS.
I_BTC = 600.0
#: Radiant nominal. The measured mainnet median is 222 s (`MarginPolicy` docstring, 2026-08-26),
#: which makes every configuration WORSE, so the nominal is the conservative choice for a test
#: that must not pass by picking a friendly number.
I_RXD = 300.0


def _policy(*, margin_blocks: int, i_rxd: float = I_RXD, i_btc: float = I_BTC) -> MarginPolicy:
    return MarginPolicy(
        margin=t.Timelock(margin_blocks, t.TimeUnit.BLOCKS),
        block_interval_s=i_btc,
        rxd_block_interval_s=i_rxd,
        is_measured=False,
        accept_flat_burial=True,
    )


def _is_safe(*, t_btc: int, t_rxd: int, elapsed: int, margin_blocks: int, i_rxd: float, i_btc: float) -> bool:
    """The safety property, in seconds, written from the PROTOCOL and not from the gate.

    The maker's Radiant refund must not open until the taker's counter-leg refund has opened and
    the margin has elapsed on top. `t_rxd` is a relative CSV from covenant MINING, so the blocks
    already elapsed are gone.
    """
    maker_refund_opens_s = (t_rxd - elapsed) * i_rxd
    taker_refund_opens_s = t_btc * i_btc
    margin_s = margin_blocks * i_btc
    return maker_refund_opens_s >= taker_refund_opens_s + margin_s


def _gate_accepts(*, t_btc: int, t_rxd: int, elapsed: int = 0, margin_blocks: int = 36, i_rxd: float = I_RXD) -> bool:
    try:
        assert_timelock_margin(
            t.Timelock(t_btc, t.TimeUnit.BLOCKS),
            t.Timelock(t_rxd, t.TimeUnit.BLOCKS),
            _policy(margin_blocks=margin_blocks, i_rxd=i_rxd),
            elapsed_blocks=elapsed,
        )
        return True
    except ValidationError:
        return False


# ─────────────────────────────────────────────────────────── named rows: MUST REFUSE ──


class TestTheConfigurationsThatMustBeRefused:
    """Every row is a REAL configuration this repo has published, shipped as a default, or run."""

    def test_the_shipped_dust_defaults(self) -> None:
        """`--t-rxd-blocks 20` (`scripts/dust_swap_run.py`) at a typical measured margin of 3 gives
        `t_btc = 20 - 3 - 4 = 13`. With the 2-block covenant burial step 5 requires before the taker
        funds, 18 RXD blocks remain = 1.51 h, against a BTC refund at 13 x 600 s = 2.17 h.

        The maker's refund opens 40 MINUTES BEFORE the taker's, at the MEAN block rate. A maker who
        simply waits takes both legs — no timing attack, no covenant ageing, no hostile parameters.
        The raw-count check reported a 4-block SURPLUS on this.
        """
        assert not _is_safe(t_btc=13, t_rxd=20, elapsed=2, margin_blocks=3, i_rxd=I_RXD, i_btc=I_BTC)
        assert not _gate_accepts(t_btc=13, t_rxd=20, elapsed=2, margin_blocks=3)

    @pytest.mark.parametrize(("t_rxd", "t_btc"), [(80, 40), (144, 104), (200, 160), (300, 260)])
    def test_the_runner_derivation_at_every_realistic_parameter(self, t_rxd: int, t_btc: int) -> None:
        """`t_btc = t_rxd - margin - 4` at margin 36. The real wall-clock margin is NEGATIVE at
        every one of these and worsens as t_rxd grows: +0.0 h, -5.3 h, -10.0 h, -18.3 h."""
        assert not _is_safe(t_btc=t_btc, t_rxd=t_rxd, elapsed=0, margin_blocks=36, i_rxd=I_RXD, i_btc=I_BTC)
        assert not _gate_accepts(t_btc=t_btc, t_rxd=t_rxd, margin_blocks=36)

    def test_the_reported_case(self) -> None:
        """#567's headline: 180 RXD blocks "exceeds" 144 BTC blocks by 36 raw, and is 15 h against
        24 h."""
        assert not _gate_accepts(t_btc=144, t_rxd=180, margin_blocks=36)

    def test_the_only_ACCEPT_vector_in_the_published_conformance_file(self) -> None:
        """`margin-ok-gap-40-margin-36` — t_btc=20 / t_rxd=60 / margin=36 — is 5.0 h against
        3.33 h + a 6.0 h margin. #482 corrected the DIRECTION of those vectors and never checked the
        accept case against the units, so the file still publishes an unsafe configuration as the
        reference for "correct". Regenerating the vectors is part of this change."""
        assert not _is_safe(t_btc=20, t_rxd=60, elapsed=0, margin_blocks=36, i_rxd=I_RXD, i_btc=I_BTC)
        assert not _gate_accepts(t_btc=20, t_rxd=60, margin_blocks=36)


# ─────────────────────────────────────────────────────── named rows: MUST BE ACCEPTED ──


class TestTheHonestConfigurationsThatMustStillFund:
    """A guard that refuses valid work is a defect here: Radiant has no RBF and no CPFP, so a
    refused claim can forfeit an asset. The property above cannot catch that — only these can."""

    @pytest.mark.parametrize(
        ("t_rxd", "t_btc", "margin_blocks", "i_rxd"),
        [
            (60, 23, 3, I_RXD),  # 5.0 h vs 3.83 h + 0.5 h
            (60, 15, 3, 222.0),  # at the MEASURED median: 3.70 h vs 2.50 h + 0.5 h
            (144, 60, 3, I_RXD),  # a day-long Radiant lock
            (300, 130, 6, I_RXD),
        ],
    )
    def test_an_honest_swap_still_funds(self, t_rxd: int, t_btc: int, margin_blocks: int, i_rxd: float) -> None:
        assert _is_safe(t_btc=t_btc, t_rxd=t_rxd, elapsed=0, margin_blocks=margin_blocks, i_rxd=i_rxd, i_btc=I_BTC), (
            "fixture is not actually safe — fix the row, not the gate"
        )
        assert _gate_accepts(t_btc=t_btc, t_rxd=t_rxd, margin_blocks=margin_blocks, i_rxd=i_rxd)

    def test_the_boundary_is_inclusive(self) -> None:
        """Equality satisfies the protocol requirement, so it must fund. An exclusive boundary here
        refuses a swap an honest maker sized exactly."""
        # t_rxd * 300 == t_btc * 600 + margin * 600  ->  t_rxd = 2*(t_btc + margin)
        t_btc, margin_blocks = 20, 6
        t_rxd = 2 * (t_btc + margin_blocks)
        assert _is_safe(t_btc=t_btc, t_rxd=t_rxd, elapsed=0, margin_blocks=margin_blocks, i_rxd=I_RXD, i_btc=I_BTC)
        assert _gate_accepts(t_btc=t_btc, t_rxd=t_rxd, margin_blocks=margin_blocks)
        assert not _gate_accepts(t_btc=t_btc, t_rxd=t_rxd - 1, margin_blocks=margin_blocks)


# ───────────────────────────────────────────────── the soundness property, through the gate ──

try:
    from hypothesis import given
    from hypothesis import strategies as st

    _HAS_HYPOTHESIS = True
except ImportError:  # pragma: no cover
    _HAS_HYPOTHESIS = False


@pytest.mark.skipif(not _HAS_HYPOTHESIS, reason="hypothesis not installed")
class TestSoundness:
    """ONE DIRECTION: whatever the gate accepts must satisfy the wall-clock inequality.

    Never the converse. See the module docstring for why a biconditional would be a defect.
    """

    @given(
        t_btc=st.integers(min_value=1, max_value=2000),
        t_rxd=st.integers(min_value=1, max_value=60000),
        elapsed=st.integers(min_value=0, max_value=500),
        margin_blocks=st.integers(min_value=1, max_value=144),
        i_rxd=st.sampled_from([9.0, 36.0, 222.0, 300.0, 600.0]),
        i_btc=st.sampled_from([540.0, 600.0, 900.0]),
    )
    def test_anything_the_gate_accepts_is_safe_in_wall_clock(
        self, t_btc: int, t_rxd: int, elapsed: int, margin_blocks: int, i_rxd: float, i_btc: float
    ) -> None:
        try:
            assert_timelock_margin(
                t.Timelock(t_btc, t.TimeUnit.BLOCKS),
                t.Timelock(t_rxd, t.TimeUnit.BLOCKS),
                _policy(margin_blocks=margin_blocks, i_rxd=i_rxd, i_btc=i_btc),
                elapsed_blocks=elapsed,
            )
        except ValidationError:
            return  # refusals are always sound; this property says nothing about them
        assert _is_safe(
            t_btc=t_btc, t_rxd=t_rxd, elapsed=elapsed, margin_blocks=margin_blocks, i_rxd=i_rxd, i_btc=i_btc
        ), (
            f"the gate ACCEPTED an unsafe configuration: t_btc={t_btc} blk x {i_btc}s, "
            f"t_rxd={t_rxd} blk x {i_rxd}s ({elapsed} elapsed), margin={margin_blocks} blk"
        )

    def test_the_property_is_NOT_vacuous(self) -> None:
        """A soundness property is trivially satisfied by a gate that refuses everything. Pin that
        both verdicts are reachable in the drawn space, so a future change that quietly starts
        refusing all input fails HERE rather than looking like a strengthened invariant."""
        accepts = sum(
            _gate_accepts(t_btc=b, t_rxd=r, margin_blocks=3)
            for b, r in ((20, 60), (10, 40), (5, 30), (30, 100), (40, 120))
        )
        refuses = sum(
            not _gate_accepts(t_btc=b, t_rxd=r, margin_blocks=36)
            for b, r in ((144, 180), (40, 80), (104, 144), (13, 20), (20, 60))
        )
        assert accepts >= 3, f"only {accepts}/5 honest rows accepted — the gate may refuse everything"
        assert refuses >= 3, f"only {refuses}/5 unsafe rows refused — the gate may accept everything"


# ─────────────────────────────────────── the same property through the PRODUCTION entry point ──


class TestThroughTheProductionEntryPoint:
    """D14's lesson, applied to this change from the start.

    The tests above call `assert_timelock_margin` directly — they prove the MECHANISM. When the
    step-7 BTC dispatch was added, every hand-called test stayed green after the dispatch was
    removed, because none of them reached the coordinator. At least one test must drive
    `pre_btc_lock_check` itself.
    """

    @pytest.mark.asyncio
    async def test_an_unsafe_wall_clock_config_is_refused_by_pre_btc_lock_check(self) -> None:
        _secret, h = generate_secret()
        # 144/180 — the reported case. Raw gap 36 clears a 36-block margin; wall-clock is 15h vs 24h.
        terms = _terms(hashlock=h, t_rxd_blocks=180, t_btc_blocks=144)
        coord = _coordinator(terms=terms, radiant_leg=FakeRadiantLeg(report_confs=1), policy=_policy(margin_blocks=36))
        gate = await coord.pre_btc_lock_check(terms)
        assert not gate.ok, "the coordinator funded a swap whose Radiant refund opens 9h early"

    @pytest.mark.asyncio
    async def test_an_honest_config_still_funds_through_pre_btc_lock_check(self) -> None:
        _secret, h = generate_secret()
        terms = _terms(hashlock=h, t_rxd_blocks=144, t_btc_blocks=60)
        coord = _coordinator(terms=terms, radiant_leg=FakeRadiantLeg(report_confs=1), policy=_policy(margin_blocks=3))
        gate = await coord.pre_btc_lock_check(terms)
        assert gate.ok, gate.reason
