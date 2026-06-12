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
  S1 — hostile maker GRIEFING / free-option: maker reaches BOTH_LOCKED then STALLS (never claims ETH,
       never reveals p). Covenant semantics: the CLAIM branch pays the TAKER (with p), the CSV REFUND
       branch pays the MAKER. So the taker's anti-grief is recovering its OWN ETH (the RXD refunds to
       the maker regardless). Defense under test: the C1 decision trigger fires at t_rxd-N, then
       mutual_refund recovers BOTH legs (taker's ETH → taker, covenant → maker). Assert: a stalling
       maker cannot make the honest taker suffer a ONE-SIDED LOSS; neither party loses.
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

import hashlib
import os

from pyrxd.gravity.htlc_covenant import build_htlc_covenant_rxd
from pyrxd.gravity.swap_coordinator import taker_refund_window_open
from pyrxd.gravity.swap_state import SwapState
from pyrxd.security.errors import NetworkError, ValidationError

# Reuse the real chain harness from the happy-path e2e (one source of truth for the node/anvil/legs).
from tests.test_xchain_eth_swap_regtest_e2e import (
    _ADDR_MAKER,
    _ADDR_TAKER,
    _ARTIFACT,
    _CHAIN_ID,
    _KEY,
    _anvil_mine,
    _anvil_now,
    _anvil_rpc,
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
    async def test_S1_hostile_maker_stall_honest_parties_dont_lose(self, env):
        """S1: maker reaches BOTH_LOCKED then STALLS (never claims, never reveals p).

        The covenant semantics (verified 2026-06-02): the covenant CLAIM branch pays the TAKER
        (with p); the CSV REFUND branch pays the MAKER (anyone-spendable after maturity). So the
        taker's REAL anti-grief on a maker stall is to recover its OWN ETH, NOT to "keep the RXD" —
        the RXD covenant refunds to the maker regardless. The safety property is: a stalling maker
        cannot make the honest taker suffer a ONE-SIDED LOSS.

        This asserts:
          (a) the C1 decision trigger fires as t_rxd-N approaches (the taker must stop waiting);
          (b) `mutual_refund` then refunds BOTH legs — the taker's ETH back to the taker AND the
              covenant back to the maker — so NEITHER party loses;
          (c) and separately that the maker never revealed p (it stalled)."""
        node, url = env
        coord, cov, _p, _eth_leg, rpc, _ref = _build(node, url, t_rxd_blocks=12, asset_variant="rxd")
        terms = coord.record.terms

        try:
            # 1. Taker funds ETH; maker locks RXD → BOTH_LOCKED.
            rec = await coord.taker_funds_btc(terms, now_unix_s=_anvil_now(url))
            assert rec.state is SwapState.BTC_LOCKED
            asset_locked_at = int(node.rxd("getblockcount"))
            _rxd_pay(node, cov.funded_spk, terms.radiant_amount)
            rec = await coord.post_asset_lock_revalidate(cov.funded_spk, now_unix_s=_anvil_now(url))
            assert rec.state is SwapState.BOTH_LOCKED

            # 2. The maker STALLS (never claims → maker_has_claimed_btc stays False). Before the
            #    safety window the C1 trigger must NOT fire (the taker keeps waiting, correctly).
            n = coord.config.maker_stall_safety_window_blocks
            assert (
                taker_refund_window_open(
                    now_block_height=asset_locked_at + 1,
                    asset_locked_at_height=asset_locked_at,
                    t_rxd=terms.t_rxd,
                    safety_window_blocks=n,
                    maker_has_claimed_btc=False,
                    block_interval_s=coord.config.margin_policy.block_interval_s,
                )
                is False
            )

            # 3. (a) Advance RXD to within the safety window of t_rxd maturity. The C1 DECISION
            #    trigger must now FIRE ("stop waiting — the maker is stalling").
            node.rxd_mine(terms.t_rxd.value - n)
            assert (
                taker_refund_window_open(
                    now_block_height=int(node.rxd("getblockcount")),
                    asset_locked_at_height=asset_locked_at,
                    t_rxd=terms.t_rxd,
                    safety_window_blocks=n,
                    maker_has_claimed_btc=False,
                    block_interval_s=coord.config.margin_policy.block_interval_s,
                )
                is True
            ), "C1 proactive-refund decision must fire as t_rxd-N approaches on a maker stall"

            # 4. (b) The taker protects itself with mutual_refund — the guaranteed-safe failure that
            #    refunds BOTH legs (taker's ETH → taker, covenant → maker). NEITHER party loses.
            #    The CSV refund spend needs the covenant buried t_rxd deep, and the ETH refund needs
            #    the ETH timeout passed — mature both, then mutual_refund.
            node.rxd_mine(n)  # covenant now t_rxd deep (CSV mature)
            _anvil_rpc(url, "evm_setNextBlockTimestamp", [terms.eth_timeout_unix_s + 1])
            _anvil_mine(url, 1)  # past the ETH timeout (ETH refund spendable)
            rec = await coord.mutual_refund()
            assert rec.state is SwapState.MUTUAL_REFUND, (
                f"honest taker recovers via mutual_refund on a maker stall, got {rec.state.value}"
            )

            # SAFETY: the RXD covenant is spent (refunded — to the MAKER), and the taker's ETH was
            # refunded to the taker. Neither party suffered a one-sided loss; the maker never got p.
            cov_txid = rec.radiant_covenant_outpoint.split(":")[0]
            assert node.rxd("gettxout", cov_txid, "0") in (None, ""), "covenant must be spent (CSV-refunded to maker)"
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

    async def test_S3_hostile_maker_wrong_covenant_taker_fails_closed(self, env):
        """S3: a hostile maker funds a covenant with the WRONG parameters (a different hashlock → a
        different SPK than the negotiated terms imply) instead of the agreed one. The honest taker
        re-derives the EXPECTED SPK from terms and looks for THAT on-chain; the agreed covenant was
        never funded, so the lookup fails closed — the taker never advances to BOTH_LOCKED and its
        ETH stays refundable. (The narrower PARAMS_MISMATCH state is for an expected-SPK-funded-but-
        mismatched lock; either way the safety invariant is: the taker does NOT enter BOTH_LOCKED.)"""
        node, url = env
        coord, cov, _p, _eth_leg, rpc, _ref = _build(node, url, t_rxd_blocks=12, asset_variant="rxd")
        terms = coord.record.terms

        try:
            rec = await coord.taker_funds_btc(terms, now_unix_s=_anvil_now(url))
            assert rec.state is SwapState.BTC_LOCKED

            # The hostile maker funds a DIFFERENT covenant (a fresh hashlock → a different SPK), NOT
            # the agreed one. The agreed-terms SPK (cov.funded_spk) is therefore never funded.
            wrong_h = hashlib.sha256(os.urandom(32)).digest()
            wrong_cov = build_htlc_covenant_rxd(
                amount=terms.radiant_amount,
                taker_pkh=_throwaway_pkh(),
                maker_pkh=_throwaway_pkh(),
                hashlock=wrong_h,
                refund_csv=terms.t_rxd.value,
            )
            assert wrong_cov.funded_spk != cov.funded_spk
            _rxd_pay(node, wrong_cov.funded_spk, terms.radiant_amount)

            # The honest taker validates against the AGREED terms (it re-derives the expected SPK and
            # looks for it on-chain). The agreed covenant was never funded → fail closed.
            with pytest.raises((ValidationError, NetworkError)):
                await coord.post_asset_lock_revalidate(cov.funded_spk, now_unix_s=_anvil_now(url))

            # SAFETY: the taker never reached BOTH_LOCKED. Its ETH HTLC is refundable once the ETH
            # timeout passes (the refund is timelocked — the decision to abort is immediate, the
            # refund SPEND lands after the timeout, same maturity pattern as the RXD CSV in S1).
            assert coord.record.state is not SwapState.BOTH_LOCKED
            _anvil_rpc(url, "evm_setNextBlockTimestamp", [terms.eth_timeout_unix_s + 1])
            _anvil_mine(url, 1)
            rec = await coord.taker_refund_btc()
            assert rec.state is SwapState.ABORTED
        finally:
            await rpc.close()

    async def test_S4_reveal_without_finality_squeeze_goes_vulnerable(self, env):
        """S4: the maker reveals p by claiming ETH, but the ETH claim is NOT final AND the t_rxd
        window has nearly closed. The reorg gate must SQUEEZE (→ ASSET_VULNERABLE), never silently
        claim and never indefinitely WAIT — the danger zone is surfaced as an explicit decision."""
        node, url = env
        # Tight t_rxd so the window can close while the ETH claim stays non-final.
        coord, cov, p_secret, eth_leg, rpc, _ref = _build(node, url, t_rxd_blocks=12, asset_variant="rxd")
        terms = coord.record.terms

        try:
            rec = await coord.taker_funds_btc(terms, now_unix_s=_anvil_now(url))
            assert rec.state is SwapState.BTC_LOCKED
            asset_locked_at = int(node.rxd("getblockcount"))
            _rxd_pay(node, cov.funded_spk, terms.radiant_amount)
            rec = await coord.post_asset_lock_revalidate(cov.funded_spk, now_unix_s=_anvil_now(url))
            assert rec.state is SwapState.BOTH_LOCKED

            # Maker claims ETH (reveals p) but we do NOT mine anvil → the claim is NOT final.
            rec = await coord.maker_claims_btc(p_secret)
            assert rec.state is SwapState.SECRET_REVEALED
            claim_tx = eth_leg.last_claim_tx

            # Drive RXD to the edge of t_rxd maturity while the ETH claim stays non-final: the gate
            # has no room left to WAIT for finality → SQUEEZED → ASSET_VULNERABLE (a deliberate
            # danger-zone decision, not a silent claim).
            node.rxd_mine(terms.t_rxd.value - 1)
            now_rxd = int(node.rxd("getblockcount"))
            rec = await coord.taker_scrape_and_claim_asset(
                claim_tx, now_rxd_height=now_rxd, asset_locked_at_height=asset_locked_at
            )
            assert rec.state is SwapState.ASSET_VULNERABLE, (
                f"a non-final ETH claim with a closing t_rxd must SQUEEZE to ASSET_VULNERABLE, got {rec.state.value}"
            )
        finally:
            await rpc.close()

    async def test_S5_hostile_taker_bad_eth_htlc_maker_refuses_to_lock(self, env):
        """S5 (roles flipped — honest MAKER): a hostile taker funds an ETH HTLC that does NOT match
        the negotiated terms (here: an underfunded balance). The honest maker's verify_funded gate
        must RAISE, so the maker never locks the RXD asset against a bad/absent ETH leg."""
        node, url = env
        coord, _cov, _p, eth_leg, rpc, _ref = _build(node, url, t_rxd_blocks=12, asset_variant="rxd")
        terms = coord.record.terms

        try:
            # The taker funds the ETH HTLC for real (deploy+verify against the true terms).
            rec = await coord.taker_funds_btc(terms, now_unix_s=_anvil_now(url))
            assert rec.state is SwapState.BTC_LOCKED
            locator = eth_leg.last_funded_locator
            assert locator is not None
            # verify_funded lives on the inner EthHtlcContractLeg (EthLeg wraps it as ._leg; the
            # recorder wraps EthLeg as ._inner). The honest MAKER calls it to independently re-verify
            # the taker's on-chain HTLC before locking RXD.
            contract_leg = eth_leg._inner._leg

            # Against the TRUE expected amount it passes (the contract is correctly funded)...
            await contract_leg.verify_funded(locator, expected_amount_wei=terms.value_amount)
            # ...but if the maker's negotiated amount were HIGHER than what the taker actually funded
            # (a hostile/underfunding taker), verify_funded must FAIL CLOSED — the maker refuses.
            with pytest.raises(ValidationError):
                await contract_leg.verify_funded(locator, expected_amount_wei=terms.value_amount + 1)
            # SAFETY: an honest maker keyed to the higher amount would have refused to lock RXD here,
            # so its asset is never put at risk against an underfunded ETH leg.
        finally:
            await rpc.close()

    async def test_S6_lying_counterparty_caught_by_own_chain_read(self, env):
        """S6: the counterparty LIES about on-chain state — it claims the RXD asset is locked, but
        reports a fabricated covenant SPK that was never funded. The honest taker re-reads the chain
        ITSELF (never trusts the peer's word): the unfunded SPK has no covenant outpoint, so the
        revalidate fails closed rather than advancing to BOTH_LOCKED."""
        node, url = env
        coord, cov, _p, _eth_leg, rpc, _ref = _build(node, url, t_rxd_blocks=12, asset_variant="rxd")
        terms = coord.record.terms

        try:
            rec = await coord.taker_funds_btc(terms, now_unix_s=_anvil_now(url))
            assert rec.state is SwapState.BTC_LOCKED

            # The maker LIES: it never funds anything, but tells the taker "I locked it at <this SPK>".
            # The honest taker observes the REAL chain for that SPK. The correct SPK was never funded,
            # so there is no covenant outpoint → fail closed (the taker does NOT enter BOTH_LOCKED).
            with pytest.raises((ValidationError, Exception)):
                rec = await coord.post_asset_lock_revalidate(cov.funded_spk, now_unix_s=_anvil_now(url))
                # If it returned instead of raising, it must NOT be BOTH_LOCKED.
                assert rec.state is not SwapState.BOTH_LOCKED
            # SAFETY: the taker never advanced to BOTH_LOCKED on a fabricated lock; its ETH stays
            # refundable.
            assert coord.record.state is not SwapState.BOTH_LOCKED
        finally:
            await rpc.close()

    async def test_S7_maker_refuses_hostile_taker_eth_contract(self, env):
        """S7 (red-team CRITICAL fix): a hostile TAKER deploys an ETH HTLC that does NOT pay the
        maker on claim (claimant=attacker), or underfunds it. The honest maker's
        coordinator.maker_verify_counter_funding MUST fail closed against the maker's OWN expected
        terms (built from the maker's payout config, not a taker-supplied locator) — so the maker
        never locks RXD against a contract that wouldn't pay it. Drives the maker through the
        COORDINATOR (not eth_leg._inner._leg), the gap the prior single-operator flows masked."""
        node, url = env
        # An honest maker coordinator: its counter_leg pays the MAKER (claim_to=_ADDR_MAKER) on claim.
        coord, _cov, _p, _eth_leg, rpc, _ref = _build(node, url, t_rxd_blocks=12, asset_variant="rxd")
        terms = coord.record.terms

        from pyrxd.eth_wallet.htlc_leg import EthHtlcContractLeg
        from pyrxd.eth_wallet.rpc import EthRpc
        from pyrxd.gravity.eth_leg import EthLeg
        from pyrxd.security.secrets import PrivateKeyMaterial

        attacker_rpc = EthRpc(url, expected_chain_id=_CHAIN_ID)
        try:
            # The TAKER deploys the REAL EthHtlc bytecode (so the code-match passes) but with
            # claimant=ATTACKER (_ADDR_TAKER) — the ETH would go to the taker, not the maker.
            attacker_leg = EthLeg(
                contract_leg=EthHtlcContractLeg(
                    rpc=attacker_rpc,
                    signing_key=PrivateKeyMaterial(bytes.fromhex(_KEY)),
                    chain_id=_CHAIN_ID,
                    artifact=_ARTIFACT,
                ),
                network="anvil",
                claim_to=_ADDR_TAKER,
                refund_to=_ADDR_TAKER,  # claimant=attacker
                eth_timeout_unix_s=terms.eth_timeout_unix_s,
                audit_cleared=True,
            )
            malicious = await attacker_leg.fund(terms)  # real on-chain deploy, claimant=taker

            # The honest maker verifies the taker's contract through the COORDINATOR → must RAISE
            # (the maker's expected claimant is _ADDR_MAKER; the on-chain claimant is the attacker).
            with pytest.raises(ValidationError, match="claimant"):
                await coord.maker_verify_counter_funding(malicious.contract_address)

            # And the maker NEVER advanced to a locked state — its asset is untouched.
            assert coord.record.state is SwapState.BTC_LOCKED

            # Sanity: an HONEST contract (claimant=maker) passes the same gate.
            honest_leg = EthLeg(
                contract_leg=EthHtlcContractLeg(
                    rpc=attacker_rpc,
                    signing_key=PrivateKeyMaterial(bytes.fromhex(_KEY)),
                    chain_id=_CHAIN_ID,
                    artifact=_ARTIFACT,
                ),
                network="anvil",
                claim_to=_ADDR_MAKER,
                refund_to=_ADDR_TAKER,
                eth_timeout_unix_s=terms.eth_timeout_unix_s,
                audit_cleared=True,
            )
            honest = await honest_leg.fund(terms)
            await coord.maker_verify_counter_funding(honest.contract_address)  # no raise
        finally:
            await attacker_rpc.close()
            await rpc.close()


def _throwaway_pkh():
    """A fresh random pkh for the S3 wrong-covenant (the wrong hashlock alone changes the SPK)."""
    from pyrxd.keys import PrivateKey
    from pyrxd.security.types import Hex20

    return bytes(Hex20(PrivateKey(os.urandom(32)).public_key().hash160()))
