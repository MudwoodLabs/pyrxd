"""GENUINELY-SEPARATED active-adversary ETH↔RXD swap test (P2, two-party plan RUNG 1).

`test_xchain_eth_adversarial_e2e.py` (S1–S7) drives ONE coordinator object as BOTH parties and its
`_AdversaryActor` either does nothing (`maker_stalls`) or is handed `p` directly — single-process
contamination the two-party plan flags: the lethal *active* free option (the maker really broadcasts
the reveal on-chain) is never executed against a taker that only ever sees the public chain.

This test closes that gap for the flagship scenario. The honest taker runs a real `SwapCoordinator`
with **role=TAKER** (the P3 guard) and is **never handed `p`**; the hostile maker is a SEPARATE
object (`_ActiveAdversaryMaker`) with its OWN EthLeg/rpc that ACTIVELY claims the taker-funded ETH
HTLC — revealing `p` on-chain. The honest taker then recovers `p` **from the chain** (fetch the
claim's calldata+logs by its public tx hash) and claims the covenant. Safety is asserted from
CHAIN-re-derived facts (which holder script the covenant paid), never from the coordinator's internal
SwapState.

What this proves / what it does NOT: separation is at the OBJECT + secret level (the honest
coordinator never receives `p` and never broadcasts the reveal — asserted). Fully separate OS
processes / hosts / independent chain access are P4 (two-host networked regtest); this runs both sides
in one process against one shared regtest node + anvil. The honest taker enters the claim flow off the
*observed* reveal via the first-class `SwapCoordinator.taker_observed_reveal()` transition, which
verifies the reveal FROM CHAIN (`sha256(p)==H` + the R6 provenance gate) before advancing
BOTH_LOCKED -> SECRET_REVEALED — replacing the resume-seam that fabricated that state
(`eth_swap_two_host.py`). The honest side never holds or broadcasts `p`.

Run it:  XCHAIN_ETH_REGTEST=1 pytest tests/test_xchain_eth_active_adversary_e2e.py -m integration -s
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

pytest.importorskip("web3")
pytest.importorskip("eth_keys")

# tests.* import path (conftest adds the repo root; mirrors test_xchain_eth_adversarial_e2e).
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pyrxd.eth_wallet.htlc_leg import EthHtlcContractLeg
from pyrxd.eth_wallet.rpc import EthRpc
from pyrxd.gravity.eth_leg import EthLeg
from pyrxd.gravity.swap_state import SwapRole, SwapState
from pyrxd.security.secrets import PrivateKeyMaterial

# Reuse the real chain harness from the happy-path e2e (one source of truth for node/anvil/legs).
from tests.test_xchain_eth_swap_regtest_e2e import (
    _ADDR_MAKER,
    _ADDR_TAKER,
    _ARTIFACT,
    _CHAIN_ID,
    _KEY,
    _anvil_mine,
    _anvil_now,
    _build,
    _rxd_pay,
    env,  # the module-scoped fixture (radiant regtest node + anvil)
)

pytestmark = pytest.mark.integration

__all__ = ["env"]  # re-export the fixture so pytest resolves it here


def _scan_value_for_spk(node, spk: bytes) -> int:
    """Total CONFIRMED UTXO value (photons) currently paying ``spk`` on the RXD chain."""
    res = node.rxd("scantxoutset", "start", json.dumps([{"desc": f"raw({bytes(spk).hex()})"}]))
    return round(sum(u["amount"] for u in res.get("unspents", [])) * 1e8)


class _ActiveAdversaryMaker:
    """A HOSTILE maker with its OWN keys/objects, SEPARATE from the honest taker's coordinator.

    It holds ``p`` and drives the maker's ETH claim DIRECTLY via its own :class:`EthLeg` — never
    sharing ``p`` or its objects with the honest side, which must observe everything on-chain. Unlike
    the same-object ``_AdversaryActor`` in test_xchain_eth_adversarial_e2e, this executes the ACTIVE
    free option: it really broadcasts the ETH claim, publishing ``p`` on-chain."""

    def __init__(self, url: str, *, p_raw: bytes, eth_timeout_unix_s: int) -> None:
        self._p = p_raw
        self._rpc = EthRpc(url, expected_chain_id=_CHAIN_ID)
        self._leg = EthLeg(
            contract_leg=EthHtlcContractLeg(
                rpc=self._rpc,
                signing_key=PrivateKeyMaterial(bytes.fromhex(_KEY)),
                chain_id=_CHAIN_ID,
                artifact=_ARTIFACT,
            ),
            network="anvil",
            claim_to=_ADDR_MAKER,
            refund_to=_ADDR_TAKER,
            eth_timeout_unix_s=eth_timeout_unix_s,
            audit_cleared=True,
        )

    async def claim_eth_revealing_p(self, locator) -> str:
        """The free-option reveal: claim the taker-funded ETH HTLC with ``p`` (pays the maker) →
        ``p`` is now PUBLIC on-chain. Returns the claim tx hash the honest taker scrapes ``p`` FROM."""
        return await self._leg.claim(locator, self._p)

    async def close(self) -> None:
        await self._rpc.close()


class TestEthActiveAdversary:
    async def test_A1_active_freeoption_maker_reveals_honest_taker_recovers_from_chain(self, env):
        """A1: the maker ACTIVELY claims the ETH (reveals p on-chain) via a SEPARATE keyed actor; the
        honest taker (role=TAKER, never handed p) recovers p FROM THE CHAIN and claims the covenant.

        Asserts from chain-re-derived facts: the covenant is spent to the TAKER holder script (the
        asset reached the honest taker) and NOT the maker holder — the swap COMPLETED atomically, no
        one-sided loss. Isolation is proven structurally: the honest coordinator never broadcast the
        reveal (its eth_leg.last_claim_tx stays None — the adversary's separate leg did it)."""
        node, url = env
        # Honest taker coordinator — role=TAKER (P3 guard). _build generates p, but we hand it ONLY to
        # the adversary; the honest coordinator never receives it (recovers it from chain in step 5).
        coord, cov, p_secret, eth_leg, rpc, _ref = _build(
            node, url, t_rxd_blocks=60, asset_variant="rxd", role=SwapRole.TAKER
        )
        terms = coord.record.terms
        adv = _ActiveAdversaryMaker(url, p_raw=p_secret.unsafe_raw_bytes(), eth_timeout_unix_s=terms.eth_timeout_unix_s)

        try:
            # 1. The MAKER (adversary) funds the RXD covenant FIRST and it is mined (HZ-1). The
            #    adversary still holds p and the ETH claim path — locking the asset buys it nothing
            #    and is exactly what a real free-option attacker must do to get a taker to lock at
            #    all. The honest taker's pre-lock gate reads this covenant on the real chain and
            #    would refuse to fund ETH against an unfunded maker.
            asset_locked_at = int(node.rxd("getblockcount"))
            _rxd_pay(node, cov.funded_spk, terms.radiant_amount)

            # 2. Honest taker funds the ETH counter-leg (deploys the HTLC). Its locator (contract
            #    address) is PUBLIC on-chain — the only thing the adversary needs to claim it. The
            #    taker then observes the covenant and advances to BOTH_LOCKED (re-deriving the SPK).
            rec = await coord.taker_funds_btc(terms, now_unix_s=_anvil_now(url))
            assert rec.state is SwapState.BTC_LOCKED
            locator = eth_leg.last_funded_locator
            assert locator is not None
            rec = await coord.post_asset_lock_revalidate(cov.funded_spk, now_unix_s=_anvil_now(url))
            assert rec.state is SwapState.BOTH_LOCKED

            # 3. ACTIVE FREE OPTION: the adversary claims the ETH with p via its OWN leg → p is now
            #    PUBLIC on-chain. The honest coordinator is never handed p and never broadcasts here.
            claim_hash = await adv.claim_eth_revealing_p(locator)
            _anvil_mine(url, 3)  # finalize the ETH claim (anvil --slots-in-an-epoch 1 → finalized=latest-2)

            # 4. The honest taker OBSERVES the reveal on-chain: taker_observed_reveal fetches the claim
            #    by its PUBLIC hash, verifies sha256(p)==H + the R6 provenance gate FROM CHAIN, and
            #    advances BOTH_LOCKED -> SECRET_REVEALED. The honest side never holds/broadcasts p.
            assert coord.record.state is SwapState.BOTH_LOCKED
            rec = await coord.taker_observed_reveal(claim_hash)
            assert rec.state is SwapState.SECRET_REVEALED

            # 5. Honest taker recovers p FROM THE CHAIN (fetch calldata+logs by the public claim hash),
            #    runs the R6 provenance + finalized-checkpoint reorg gate, then claims the covenant
            #    (CLAIM branch → taker).
            now_rxd = int(node.rxd("getblockcount"))
            rec = await coord.taker_scrape_and_claim_asset(
                claim_hash, now_rxd_height=now_rxd, asset_locked_at_height=asset_locked_at
            )
            assert rec.state is SwapState.COMPLETED, (
                f"honest taker should claim the covenant off the observed reveal, got {rec.state.value}"
            )
            node.rxd_mine(1)  # confirm the covenant claim so scantxoutset sees the payout

            # 6. SAFETY from CHAIN reads: the covenant was spent to the TAKER holder (asset reached the
            #    honest taker) and NOT the maker — a COMPLETED atomic swap, no one-sided loss.
            cov_txid = rec.radiant_covenant_outpoint.split(":")[0]
            assert node.rxd("gettxout", cov_txid, "0") in (None, ""), "covenant outpoint must be spent (claimed)"
            assert _scan_value_for_spk(node, cov.taker_holder_script) == terms.radiant_amount, (
                "the covenant claim must pay the TAKER holder script (asset reached the honest taker)"
            )
            assert _scan_value_for_spk(node, cov.maker_holder_script) == 0, (
                "the maker must NOT have grabbed the covenant"
            )

            # ISOLATION: the honest coordinator NEVER broadcast the reveal — the separate adversary
            # leg did. (The honest coord could claim ETH, but must not have here.)
            assert eth_leg.last_claim_tx is None, (
                "the honest taker coordinator must NEVER have claimed the ETH — the adversary revealed p"
            )
        finally:
            await adv.close()
            await rpc.close()

    async def test_A2_active_late_reveal_nonfinal_squeezes_to_vulnerable(self, env):
        """A2: the maker TIMES the free option — it reveals p (claims ETH) but the claim is NOT final
        AND the t_rxd window is closing. The honest taker (separate, never handed p) must SQUEEZE →
        ASSET_VULNERABLE — surfacing the danger zone as an explicit decision, never silently claiming
        the covenant off a non-final reveal (which a reorg of the ETH claim would turn into one-sided
        loss). The genuinely-separated + active-reveal analogue of S4."""
        node, url = env
        # Tight t_rxd so the window can close while the ETH claim stays non-final.
        coord, cov, p_secret, eth_leg, rpc, _ref = _build(
            node, url, t_rxd_blocks=12, asset_variant="rxd", role=SwapRole.TAKER
        )
        terms = coord.record.terms
        adv = _ActiveAdversaryMaker(url, p_raw=p_secret.unsafe_raw_bytes(), eth_timeout_unix_s=terms.eth_timeout_unix_s)

        try:
            # HZ-1: maker locks the covenant first (mined), then the honest taker funds ETH. The
            # attack under test is the TIMING of the reveal, not a maker that never locks.
            asset_locked_at = int(node.rxd("getblockcount"))
            _rxd_pay(node, cov.funded_spk, terms.radiant_amount)
            rec = await coord.taker_funds_btc(terms, now_unix_s=_anvil_now(url))
            assert rec.state is SwapState.BTC_LOCKED
            locator = eth_leg.last_funded_locator
            rec = await coord.post_asset_lock_revalidate(cov.funded_spk, now_unix_s=_anvil_now(url))
            assert rec.state is SwapState.BOTH_LOCKED

            # Active reveal — anvil auto-mines the claim (1 block) so it is MINED but NOT finalized
            # (finalized = latest-2). We do NOT mine 3 more, so the finality gate sees a non-final claim.
            claim_hash = await adv.claim_eth_revealing_p(locator)
            rec = await coord.taker_observed_reveal(claim_hash)
            assert rec.state is SwapState.SECRET_REVEALED

            # Drive RXD to the edge of t_rxd maturity while the ETH claim stays non-final → the gate
            # has no room left to WAIT for finality → SQUEEZED → ASSET_VULNERABLE (deliberate, not silent).
            node.rxd_mine(terms.t_rxd.value - 1)
            now_rxd = int(node.rxd("getblockcount"))
            rec = await coord.taker_scrape_and_claim_asset(
                claim_hash, now_rxd_height=now_rxd, asset_locked_at_height=asset_locked_at
            )
            assert rec.state is SwapState.ASSET_VULNERABLE, (
                f"a non-final reveal with a closing t_rxd must SQUEEZE to ASSET_VULNERABLE, got {rec.state.value}"
            )

            # SAFETY: the taker did NOT silently claim the covenant off the non-final reveal — the
            # covenant outpoint is still UNSPENT, and the danger is surfaced for a deliberate policy call.
            cov_txid = coord.record.radiant_covenant_outpoint.split(":")[0]
            assert node.rxd("gettxout", cov_txid, "0") not in (None, ""), (
                "covenant must remain UNSPENT — no silent claim off a non-final reveal"
            )
            assert eth_leg.last_claim_tx is None
        finally:
            await adv.close()
            await rpc.close()
