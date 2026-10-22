"""#850 PR 1b: the watchtower reads the record's role, and an observed covenant no longer silences a
due refund (design §5.1, §8.1).

* A TAKER (or single-operator, or role-unknown) record at BTC_LOCKED pages its refund once the
  counter leg's deadline passes, whether or not the maker's covenant is observed. The maker locks
  first, so the covenant is normally on chain for the taker's whole swap, and the old rule
  ("asset lock observed -> WATCH") left a taker unpaged for good when the maker locked and then
  never claimed (#850 item 6).
* While the covenant is observed the BTC refund is never AUTONOMOUS: the maker can still claim
  (the claim leaf has no timelock), and only an operator then knows to claim the covenant.
* A MAKER's record is never told to refund the counter leg or run ``mutual_refund``: those are the
  taker's steps. It is told to refund its covenant at t_rxd.
* No autonomy for a record that does not name the taker (or the single operator) as its writer.
* The taker's record now carries the covenant outpoint its fund was verified against.
"""

from __future__ import annotations

import dataclasses

import pytest

from pyrxd.gravity.record_sink import JsonFileRecordSink
from pyrxd.gravity.swap_state import RecordRole, SwapRole, SwapState
from pyrxd.gravity.watch import Intent, Observations
from tests.test_swap_coordinator import FakeBtcLeg, FakeRadiantLeg, _coordinator, generate_secret
from tests.test_swap_coordinator import _terms as _coord_terms
from tests.test_watch_decide import LOCK, _btc_terms, _decide, _decide_e, _eth, _eth_btc_locked_obs, _record

_MAKER_PAGE = "refund your covenant by its CSV leg"


def _btc(state: SwapState, role: RecordRole | None):
    return dataclasses.replace(_record(state, terms=_btc_terms()), role=role)


def _btc_locked_obs(*, funding: int | None, covenant: bool) -> Observations:
    return Observations(
        maker_has_claimed_btc=False,
        now_rxd_height=150,
        asset_locked_at_height=LOCK if covenant else None,
        btc_funding_confirmations=funding,
    )


# --------------------------------------------------------------------------- BTC, taker side


@pytest.mark.parametrize("role", [RecordRole.TAKER, RecordRole.NONE, None])
def test_a_matured_btc_refund_is_paged_with_the_covenant_observed_and_never_autonomous(role) -> None:
    d = _decide(_btc(SwapState.BTC_LOCKED, role), _btc_locked_obs(funding=36, covenant=True))
    assert d.intent is Intent.PAGE_REFUND and d.recommended_action == "taker_refund_btc"
    assert d.autonomous_btc_refund is False
    assert "maker can still claim" in d.reason and "watch until the refund is buried" in d.reason


@pytest.mark.parametrize(
    ("role", "armed"), [(RecordRole.TAKER, True), (RecordRole.NONE, True), (None, False), (RecordRole.MAKER, False)]
)
def test_without_a_covenant_autonomy_follows_the_role(role, armed) -> None:
    """Honest path for the keyless refund: the taker's own record, maker never locked, CSV matured."""
    d = _decide(_btc(SwapState.BTC_LOCKED, role), _btc_locked_obs(funding=36, covenant=False))
    assert d.intent is Intent.PAGE_REFUND
    assert d.autonomous_btc_refund is armed


def test_before_maturity_the_tower_still_watches_with_the_covenant_observed() -> None:
    d = _decide(_btc(SwapState.BTC_LOCKED, RecordRole.TAKER), _btc_locked_obs(funding=35, covenant=True))
    assert d.intent is Intent.WATCH and "covenant is observed" in d.reason


# --------------------------------------------------------------------------- maker side


def test_a_maker_btc_locked_record_past_the_counter_deadline_is_told_to_refund_its_covenant() -> None:
    d = _decide(_btc(SwapState.BTC_LOCKED, RecordRole.MAKER), _btc_locked_obs(funding=36, covenant=True))
    assert d.intent is Intent.PAGE_REFUND and _MAKER_PAGE in d.recommended_action
    assert "taker_refund_btc" not in d.recommended_action and d.autonomous_btc_refund is False
    assert d.deadline_rxd_height is not None  # t_rxd, from the observed covenant


def test_a_maker_btc_locked_record_before_the_deadline_watches() -> None:
    d = _decide(_btc(SwapState.BTC_LOCKED, RecordRole.MAKER), _btc_locked_obs(funding=35, covenant=True))
    assert d.intent is Intent.WATCH


def test_a_maker_both_locked_record_near_t_rxd_is_told_to_refund_its_covenant_not_mutual_refund() -> None:
    obs = Observations(maker_has_claimed_btc=False, now_rxd_height=LOCK + 72, asset_locked_at_height=LOCK)
    maker = _decide(_btc(SwapState.BOTH_LOCKED, RecordRole.MAKER), obs)
    assert maker.intent is Intent.PAGE_REFUND and _MAKER_PAGE in maker.recommended_action
    taker = _decide(_btc(SwapState.BOTH_LOCKED, RecordRole.TAKER), obs)
    assert taker.intent is Intent.PAGE_REFUND and taker.recommended_action == "mutual_refund"  # unchanged


def test_eth_maker_records_are_told_to_refund_their_covenant() -> None:
    btc_locked = dataclasses.replace(_eth(SwapState.BTC_LOCKED), role=RecordRole.MAKER)
    past = _decide_e(btc_locked, _eth_btc_locked_obs(now_unix_s=4_000_000_001, lock=LOCK))
    assert past.intent is Intent.PAGE_REFUND and _MAKER_PAGE in past.recommended_action
    before = _decide_e(btc_locked, _eth_btc_locked_obs(now_unix_s=1, lock=LOCK))
    assert before.intent is Intent.WATCH
    both = dataclasses.replace(_eth(SwapState.BOTH_LOCKED), role=RecordRole.MAKER)
    near = Observations(
        maker_has_claimed_btc=False,
        now_rxd_height=LOCK + 72,
        asset_locked_at_height=LOCK,
        eth_claim_detected=False,
        eth_claim_finality=None,
    )
    d = _decide_e(both, near)
    assert d.intent is Intent.PAGE_REFUND and _MAKER_PAGE in d.recommended_action


def test_an_eth_taker_records_pin_is_proof_the_maker_locked_when_the_depth_read_fails() -> None:
    """Security review LOW: the ETH branch read only the observation, so a pinned taker record
    whose depth read failed was paged "maker never locked"."""
    rec = dataclasses.replace(
        _eth(SwapState.BTC_LOCKED), role=RecordRole.TAKER, radiant_covenant_outpoint="ab" * 32 + ":0"
    )
    d = _decide_e(rec, _eth_btc_locked_obs(now_unix_s=4_000_000_001, lock=None))
    assert d.intent is Intent.PAGE_REFUND
    assert "maker never locked" not in d.reason and "maker locked the covenant" in d.reason


def test_an_eth_taker_record_with_the_covenant_observed_pages_past_the_deadline() -> None:
    rec = dataclasses.replace(_eth(SwapState.BTC_LOCKED), role=RecordRole.TAKER)
    d = _decide_e(rec, _eth_btc_locked_obs(now_unix_s=4_000_000_001, lock=LOCK))
    assert d.intent is Intent.PAGE_REFUND and d.recommended_action == "taker_refund_btc"
    assert d.autonomous_btc_refund is False


@pytest.mark.parametrize("pending", [None, "0x" + "e1" * 32])
def test_the_eth_refund_page_names_our_recorded_refund_while_it_is_not_final(pending) -> None:
    """#850 PR 5b (design §4.4, M6): the record now stays BTC_LOCKED after our refund is sent, so the
    page keeps firing until the refund is final. It names the recorded refund, so it reads as "follow
    it", not "send one"."""
    rec = dataclasses.replace(_eth(SwapState.BTC_LOCKED), role=RecordRole.TAKER)
    if pending is not None:
        rec = dataclasses.replace(rec, counter_refund_tx_hash=pending, counter_refund_nonce=3)
    d = _decide_e(rec, _eth_btc_locked_obs(now_unix_s=4_000_000_001, lock=LOCK))
    assert d.intent is Intent.PAGE_REFUND and d.recommended_action == "taker_refund_btc"
    assert ("is recorded and not yet final" in d.reason) is (pending is not None)
    if pending is not None:
        assert pending in d.reason


# --------------------------------------------------------------------------- the claim race


@pytest.mark.parametrize(("role", "armed"), [(RecordRole.TAKER, True), (None, False), (RecordRole.MAKER, False)])
def test_the_autonomous_claim_is_armed_only_for_the_takers_record(role, armed) -> None:
    obs = Observations(
        maker_has_claimed_btc=True, now_rxd_height=LOCK + 10, asset_locked_at_height=LOCK, btc_claim_confirmations=6
    )
    d = _decide(_btc(SwapState.SECRET_REVEALED, role), obs)
    assert d.intent is Intent.PAGE_CLAIM
    assert d.autonomous_asset_claim is armed
    # A claim race that is NOT armed says why (security review LOW: the round-1 note skipped it).
    assert ("Not autonomous" in d.reason) is (not armed)


# --------------------------------------------------------------------------- the coordinator


async def test_the_takers_record_pins_the_covenant_its_fund_was_verified_against(tmp_path) -> None:
    """Production entry point: a TAKER fund persists the covenant outpoint the gate re-ran against
    (design §2.9), so the claim and the tower follow that outpoint rather than re-discovering it."""
    _p, h = generate_secret()
    terms = _coord_terms(hashlock=h)
    rxd = FakeRadiantLeg()
    coord = _coordinator(terms=terms, btc_leg=FakeBtcLeg(), radiant_leg=rxd, role=SwapRole.TAKER)
    sink = JsonFileRecordSink(tmp_path / "swap.json")
    coord._persist = sink
    verified: list[str] = []
    real_verify = coord.taker_verify_asset_funding

    async def _spy(*a, **k):
        result = await real_verify(*a, **k)
        verified.append(result[0])
        return result

    coord.taker_verify_asset_funding = _spy
    await coord.taker_funds_btc(terms)
    on_disk = sink.load_record()
    assert on_disk.state is SwapState.BTC_LOCKED
    assert verified, "the fund never re-verified the covenant"
    assert on_disk.radiant_covenant_outpoint == verified[-1], "the record does not pin the verified covenant"
    assert on_disk.radiant_covenant_spk_hex == bytes(await rxd.expected_covenant_scriptpubkey(terms)).hex()


@pytest.mark.parametrize("eth", [False, True])
def test_a_maker_params_mismatch_record_is_told_to_refund_its_covenant(eth) -> None:
    """Review M2: PARAMS_MISMATCH arises in the maker's process, and it was paged the taker's step."""
    if eth:
        rec = dataclasses.replace(_eth(SwapState.PARAMS_MISMATCH), role=RecordRole.MAKER)
        d = _decide_e(rec, _eth_btc_locked_obs(now_unix_s=1, lock=LOCK))
    else:
        d = _decide(_btc(SwapState.PARAMS_MISMATCH, RecordRole.MAKER), _btc_locked_obs(funding=36, covenant=True))
    assert d.intent is Intent.PAGE_REFUND and _MAKER_PAGE in d.recommended_action
    assert "taker_refund_btc" not in d.recommended_action and d.autonomous_btc_refund is False


def test_a_maker_with_an_unreadable_funding_depth_is_paged_once_t_rxd_matures() -> None:
    """Review L3: the maker branch keyed only on the funding depth, so an unreadable depth watched
    forever, even after t_rxd made the maker's covenant refund due."""
    rec = _btc(SwapState.BTC_LOCKED, RecordRole.MAKER)
    late = Observations(maker_has_claimed_btc=False, now_rxd_height=LOCK + 200, asset_locked_at_height=LOCK)
    assert _decide(rec, late).intent is Intent.PAGE_REFUND
    early = Observations(maker_has_claimed_btc=False, now_rxd_height=LOCK + 1, asset_locked_at_height=LOCK)
    d = _decide(rec, early)
    assert d.intent is Intent.WATCH and "could not be read" in d.reason


def test_a_role_less_page_says_why_it_is_not_autonomous() -> None:
    """Review L2: operators upgrading with pre-signed refunds lost autonomy silently."""
    d = _decide(_btc(SwapState.BTC_LOCKED, None), _btc_locked_obs(funding=36, covenant=False))
    assert d.autonomous_btc_refund is False and "names no role" in d.reason
