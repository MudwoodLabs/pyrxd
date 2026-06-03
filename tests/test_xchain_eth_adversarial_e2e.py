"""TWO-PARTY ADVERSARIAL ETH↔RXD swap tests (Tier-A) — the safety property single-operator can't prove.

The dust runs + the happy/refund e2e prove the MECHANISM (the legs compose on real chains). They are
single-operator (one party = maker AND taker), which structurally cannot test the thing an atomic
swap exists for: an HONEST party following the protocol cannot be made to lose funds by an
ADVERSARIAL counterparty who deviates. See docs/brainstorms/.../TWO_PARTY_ADVERSARIAL_TEST_DESIGN.md.

This drives the REAL coordinator as the HONEST party against an ``_AdversaryActor`` that controls the
counterparty's legs directly and deviates (stalls, races). It asserts the honest party's OUTCOME (it
never ends in a state where the adversary holds both legs), not its internals. Role isolation: the
honest taker's coordinator only ever observes the public envelope (terms + the on-chain covenant SPK
+ the on-chain ETH claim tx) — never the maker's secret p or keys until they appear on-chain.

Scenarios:
  S1 — hostile maker GRIEFING / free-option: maker reaches BOTH_LOCKED then STALLS (never claims ETH),
       intending to refund the RXD covenant via CSV AND claim ETH at the last moment, taking both.
       Defense under test: the honest taker's proactive asset-refund (C1,
       maybe_refund_asset_on_maker_stall) — it refunds BEFORE t_rxd-N, never waits. Assert: the taker
       reclaims its RXD; the maker is NEVER able to hold both legs.
  S2 — asset-timeout RACE: maker reveals p by claiming ETH, then the test verifies the reorg-finality
       gate keeps the honest taker from claiming RXD until the ETH claim is FINAL (so the maker can't
       race a CSV refund against a not-yet-final claim). Assert: the taker only claims once SAFE.

Run it:  XCHAIN_ETH_REGTEST=1 pytest tests/test_xchain_eth_adversarial_e2e.py -m integration -s
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

pytest.importorskip("web3")
pytest.importorskip("eth_keys")

# tests.* import path (conftest adds the repo root; see test_xchain_eth_glyph_real_rxindexer_e2e).
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pyrxd.gravity.swap_coordinator import should_taker_refund_proactively
from pyrxd.gravity.swap_state import SwapState

# Reuse the real chain harness from the happy-path e2e (one source of truth for the node/anvil/legs).
from tests.test_xchain_eth_swap_regtest_e2e import (
    _anvil_mine,
    _anvil_now,
    _build,
    _rxd_pay,
    env,  # the module-scoped fixture (radiant regtest node + anvil)
)

pytestmark = pytest.mark.integration

__all__ = ["env"]  # re-export the fixture so pytest resolves it here


class _AdversaryActor:
    """The HOSTILE counterparty. Holds the maker's secret + drives the maker's legs DIRECTLY, so it
    can deviate from the protocol the honest coordinator follows. It never shares p/keys with the
    honest side — the honest taker must observe everything on-chain.

    The maker side here is the same coordinator object (the e2e builds one coordinator that drives
    both legs); the adversary models a hostile maker by simply CHOOSING WHEN (or whether) to call the
    maker steps, while we assert the honest TAKER-side methods keep the taker safe."""

    def __init__(self, coord, p_secret):
        self._coord = coord
        self._p = p_secret
        self.has_claimed = False

    async def maker_claims_eth(self):
        rec = await self._coord.maker_claims_btc(self._p)
        self.has_claimed = True
        return rec

    def maker_stalls(self):
        """The deviation: do nothing. The maker withholds its ETH claim, hoping to grief."""
        return None


class TestEthAdversarial:
    async def test_S1_hostile_maker_stall_taker_refunds_proactively(self, env):
        """S1: maker reaches BOTH_LOCKED then STALLS. The honest taker's proactive-refund trigger
        must fire as t_rxd-N approaches, and the taker reclaims its RXD — the maker can never end up
        holding both legs."""
        node, url = env
        # Short t_rxd so the stall window is reachable on regtest quickly. (S1 never claims ETH, so
        # the eth_leg recorder is unused here.)
        coord, cov, p_secret, _eth_leg, rpc, _ref = _build(node, url, t_rxd_blocks=12, asset_variant="rxd")
        terms = coord.record.terms
        adversary = _AdversaryActor(coord, p_secret)

        try:
            # 1. Taker funds ETH; maker locks RXD → BOTH_LOCKED.
            rec = await coord.taker_funds_btc(terms, now_unix_s=_anvil_now(url))
            assert rec.state is SwapState.BTC_LOCKED
            asset_locked_at = int(node.rxd("getblockcount"))
            _rxd_pay(node, cov.funded_spk, terms.radiant_amount)
            rec = await coord.post_asset_lock_revalidate(cov.funded_spk, now_unix_s=_anvil_now(url))
            assert rec.state is SwapState.BOTH_LOCKED

            # 2. The maker STALLS (never claims). The honest taker polls the proactive-refund trigger.
            adversary.maker_stalls()
            # Before the window: trigger must NOT fire (taker keeps waiting, correctly).
            assert (
                should_taker_refund_proactively(
                    now_block_height=asset_locked_at + 1,
                    asset_locked_at_height=asset_locked_at,
                    t_rxd=terms.t_rxd,
                    safety_window_blocks=coord.config.maker_stall_safety_window_blocks,
                    maker_has_claimed_btc=adversary.has_claimed,
                    block_interval_s=coord.config.margin_policy.block_interval_s,
                )
                is False
            )

            # 3a. Advance RXD to within the safety window of t_rxd maturity (maturity - N). Maker
            #     STILL hasn't claimed. The C1 DECISION trigger must now FIRE ("stop waiting").
            n = coord.config.maker_stall_safety_window_blocks
            node.rxd_mine(terms.t_rxd.value - n)
            assert (
                should_taker_refund_proactively(
                    now_block_height=int(node.rxd("getblockcount")),
                    asset_locked_at_height=asset_locked_at,
                    t_rxd=terms.t_rxd,
                    safety_window_blocks=n,
                    maker_has_claimed_btc=adversary.has_claimed,
                    block_interval_s=coord.config.margin_policy.block_interval_s,
                )
                is True
            ), "C1 proactive-refund decision must fire as t_rxd-N approaches on a maker stall"

            # 3b. The RXD CSV refund SPEND needs the covenant buried t_rxd deep (BIP68). Mine to full
            #     maturity, then the honest taker's refund executes and reclaims the asset. (The
            #     decision fires early; the spend lands once CSV matures — both within t_ETH > t_RXD,
            #     so the taker reclaims RXD before the maker's later ETH deadline. THE SAFETY WINDOW.)
            node.rxd_mine(n)  # now at/just past maturity
            rec = await coord.maybe_refund_asset_on_maker_stall(
                now_block_height=int(node.rxd("getblockcount")),
                asset_locked_at_height=asset_locked_at,
                maker_has_claimed_btc=adversary.has_claimed,
            )
            assert rec.state is SwapState.ASSET_REFUNDED_TAKER_ACTS, (
                f"honest taker must proactively refund on maker stall, got {rec.state.value}"
            )

            # 4. SAFETY ASSERTION: the RXD covenant is now spent BY THE TAKER's refund — the maker
            #    can no longer claim it. The maker never got the asset; the taker reclaimed it.
            cov_txid = rec.radiant_covenant_outpoint.split(":")[0]
            assert node.rxd("gettxout", cov_txid, "0") in (None, ""), "covenant must be spent by the taker refund"
            # And the maker never revealed p / never claimed the ETH (it stalled).
            assert adversary.has_claimed is False
        finally:
            await rpc.close()

    async def test_S2_race_reorg_gate_blocks_premature_claim(self, env):
        """S2: maker reveals p by claiming ETH, but the claim is NOT yet final. The honest taker's
        reorg-finality gate must REFUSE to claim the RXD covenant (stays SECRET_REVEALED) — so a
        hostile maker cannot race a CSV refund against a claim the taker acted on prematurely. Only
        once the ETH claim is FINAL may the taker claim."""
        node, url = env
        coord, cov, p_secret, eth_leg, rpc, _ref = _build(node, url, t_rxd_blocks=60, asset_variant="rxd")
        terms = coord.record.terms
        adversary = _AdversaryActor(coord, p_secret)

        try:
            rec = await coord.taker_funds_btc(terms, now_unix_s=_anvil_now(url))
            assert rec.state is SwapState.BTC_LOCKED
            asset_locked_at = int(node.rxd("getblockcount"))
            _rxd_pay(node, cov.funded_spk, terms.radiant_amount)
            rec = await coord.post_asset_lock_revalidate(cov.funded_spk, now_unix_s=_anvil_now(url))
            assert rec.state is SwapState.BOTH_LOCKED

            # Maker claims ETH (reveals p) — but we DON'T mine anvil forward, so the claim is NOT final.
            rec = await adversary.maker_claims_eth()
            assert rec.state is SwapState.SECRET_REVEALED
            claim_tx = eth_leg.last_claim_tx
            assert claim_tx is not None

            # The honest taker tries to claim RXD. The ETH claim is not finalized → the gate must
            # hold (stay SECRET_REVEALED), NOT claim. (anvil --slots-in-an-epoch 1 → finalized=latest-2;
            # without mining after the claim it is not yet at/under finalized.)
            now_rxd = int(node.rxd("getblockcount"))
            rec = await coord.taker_scrape_and_claim_asset(
                claim_tx, now_rxd_height=now_rxd, asset_locked_at_height=asset_locked_at
            )
            assert rec.state is SwapState.SECRET_REVEALED, (
                f"taker must NOT claim RXD before the ETH claim is final, got {rec.state.value}"
            )

            # Now finalize the ETH claim → the gate goes SAFE and the taker claims.
            _anvil_mine(url, 3)
            now_rxd = int(node.rxd("getblockcount"))
            rec = await coord.taker_scrape_and_claim_asset(
                claim_tx, now_rxd_height=now_rxd, asset_locked_at_height=asset_locked_at
            )
            assert rec.state is SwapState.COMPLETED, (
                f"taker should complete once the ETH claim is final, got {rec.state.value}"
            )
        finally:
            await rpc.close()
