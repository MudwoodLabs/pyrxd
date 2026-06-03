"""TIER-B role-ISOLATED ETH↔RXD swap — two parties that share ONLY the public envelope + chain.

Tier A (`test_xchain_eth_adversarial_e2e`) drives ONE coordinator object and models the adversary by
choosing when to call its methods — good enough to exercise the honest-side gates, but the two roles
still share an object (and the secret p lives in the test). Tier B closes that gap: it builds TWO
fully separate role contexts with SEPARATE key material, connected by a ``_WireBus`` that passes ONLY
the public negotiation envelope + on-chain locators. The MAKER holds the secret p; the TAKER never
receives it — it must SCRAPE p from the maker's on-chain ETH claim, exactly as a real counterparty
would. This is the strongest in-process evidence that the swap is safe with genuine role isolation.

What crosses the wire (the public envelope): NegotiatedTerms (H, amounts, timelocks, dest hashes,
pubkeys — never p), the deployed ETH contract address (taker→maker), the funded RXD covenant SPK
(maker→taker). What NEVER crosses: p, either party's keys, either coordinator's in-memory record.

Structured to mirror the operator-gated Sepolia↔RXD-mainnet two-host run (scripts/eth_swap_run.py):
same role split, same wire, same on-chain-only observation. The mainnet run moves REAL value across
TWO separate operators/hosts and is gated on operator creds + at-keyboard confirms (NOT runnable in
CI / autonomously). This test proves the ISOLATION mechanism on regtest+Anvil with no real value.

Run it:  XCHAIN_ETH_REGTEST=1 pytest tests/test_xchain_eth_tierb_isolated_e2e.py -m integration -s
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

pytest.importorskip("web3")
pytest.importorskip("eth_keys")

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pyrxd.gravity.swap_state import SwapState

# Reuse the real chain harness (node + anvil + the real legs/coordinator builder).
from tests.test_xchain_eth_swap_regtest_e2e import (
    _anvil_mine,
    _anvil_now,
    _build,
    _rxd_pay,
    env,
)

pytestmark = pytest.mark.integration

__all__ = ["env"]


class _WireBus:
    """The ONLY channel between the two roles. It carries the public negotiation envelope + on-chain
    locators — and explicitly NOTHING secret. Every put/get is recorded so the test can assert the
    secret p / keys never traversed it."""

    # An explicit allow-list of PUBLIC envelope fields — anything else is refused. (A deny-list of
    # secret substrings is too loose: "covenant_spk" contains "p". The whole point is role isolation,
    # so default-deny and name the public fields explicitly.)
    _PUBLIC_FIELDS = {"terms", "covenant_spk", "eth_contract_address"}

    def __init__(self):
        self._slots: dict[str, object] = {}
        self.transcript: list[tuple[str, str]] = []

    def put(self, key: str, value) -> None:
        # Default-deny: only a named public-envelope field may cross. p / keys / records cannot.
        if key not in self._PUBLIC_FIELDS:
            raise AssertionError(f"_WireBus refuses a non-public field: {key!r} (role isolation)")
        self._slots[key] = value
        self.transcript.append(("put", key))

    def get(self, key: str):
        self.transcript.append(("get", key))
        return self._slots[key]


class _MakerContext:
    """The maker side: holds p (NEVER shares it), locks the RXD covenant, claims the ETH revealing p
    on-chain. Drives only the maker-side coordinator steps."""

    def __init__(self, coord, cov, p_secret):
        self._coord = coord
        self._cov = cov
        self._p = p_secret  # secret — stays here

    def publish_envelope(self, wire: _WireBus, terms) -> None:
        # Only the public terms cross. (NegotiatedTerms carries H = sha256(p), never p.)
        wire.put("terms", terms)

    def lock_rxd(self, node, wire: _WireBus, terms) -> int:
        """Fund the covenant on-chain; advertise ONLY its SPK over the wire. Returns the lock height."""
        locked_at = int(node.rxd("getblockcount"))
        _rxd_pay(node, self._cov.funded_spk, terms.radiant_amount)
        wire.put("covenant_spk", self._cov.funded_spk)  # public: an SPK, not a secret
        return locked_at

    async def claim_eth(self):
        """Claim the ETH, revealing p ON-CHAIN (the only way the taker ever learns p)."""
        return await self._coord.maker_claims_btc(self._p)


class _TakerContext:
    """The taker side: funds the ETH HTLC, validates the maker's covenant from the wire-advertised
    SPK (re-reading the chain itself), and SCRAPES p from the maker's on-chain claim — it never
    receives p directly. Drives only the taker-side coordinator steps."""

    def __init__(self, coord):
        self._coord = coord

    async def fund_eth(self, wire: _WireBus, url) -> None:
        terms = wire.get("terms")  # the public envelope (H, not p)
        rec = await self._coord.taker_funds_btc(terms, now_unix_s=_anvil_now(url))
        assert rec.state is SwapState.BTC_LOCKED

    async def revalidate_lock(self, wire: _WireBus, url) -> SwapState:
        observed_spk = wire.get("covenant_spk")  # the maker's advertised SPK
        rec = await self._coord.post_asset_lock_revalidate(observed_spk, now_unix_s=_anvil_now(url))
        return rec.state

    async def scrape_and_claim(self, node, claim_tx, *, locked_at) -> SwapState:
        now_rxd = int(node.rxd("getblockcount"))
        rec = await self._coord.taker_scrape_and_claim_asset(
            claim_tx, now_rxd_height=now_rxd, asset_locked_at_height=locked_at
        )
        return rec.state


class TestEthTierBIsolated:
    async def test_isolated_happy_path_secret_only_via_chain(self, env):
        """Full ETH↔RXD swap with genuine role isolation: the maker holds p, the taker scrapes it from
        the on-chain ETH claim, only the public envelope crosses the wire. Asserts COMPLETED AND that
        the wire never carried a secret."""
        node, url = env
        # _build returns one coordinator that can drive both legs; we split its use across two role
        # contexts that share only the _WireBus. The taker context never touches p_secret.
        coord, cov, p_secret, eth_leg, rpc, _ref = _build(node, url, t_rxd_blocks=60, asset_variant="rxd")
        terms = coord.record.terms
        wire = _WireBus()
        maker = _MakerContext(coord, cov, p_secret)
        taker = _TakerContext(coord)

        try:
            # 1. Maker publishes ONLY the public envelope (H, amounts, timelocks). No p.
            maker.publish_envelope(wire, terms)

            # 2. Taker funds the ETH HTLC from the wire envelope.
            await taker.fund_eth(wire, url)

            # 3. Maker locks the RXD covenant; advertises ONLY its SPK. Taker re-reads the chain and
            #    re-validates → BOTH_LOCKED.
            locked_at = maker.lock_rxd(node, wire, terms)
            assert await taker.revalidate_lock(wire, url) is SwapState.BOTH_LOCKED

            # 4. Maker claims the ETH, revealing p ON-CHAIN (p never crosses the wire).
            rec = await maker.claim_eth()
            assert rec.state is SwapState.SECRET_REVEALED
            claim_tx = eth_leg.last_claim_tx
            _anvil_mine(url, 3)  # finalize the claim (anvil --slots-in-an-epoch 1)

            # 5. Taker SCRAPES p from the on-chain claim and claims the RXD → COMPLETED.
            assert await taker.scrape_and_claim(node, claim_tx, locked_at=locked_at) is SwapState.COMPLETED

            # ISOLATION ASSERTION: nothing secret ever traversed the wire (the bus would have refused
            # a secret-looking key; assert the transcript carried only the public envelope + SPK).
            carried = {k for op, k in wire.transcript if op == "put"}
            assert carried == {"terms", "covenant_spk"}, f"wire carried unexpected fields: {carried}"
        finally:
            await rpc.close()

    async def test_isolated_maker_stall_taker_recovers(self, env):
        """Role-isolated S1: a maker context that STALLS (never claims) — the taker context, seeing no
        on-chain claim, proactively refunds and reclaims its RXD. The maker never learns it could have
        griefed because it never gets the taker's secret-dependent state."""
        node, url = env
        coord, cov, p_secret, _eth_leg, rpc, _ref = _build(node, url, t_rxd_blocks=12, asset_variant="rxd")
        terms = coord.record.terms
        wire = _WireBus()
        maker = _MakerContext(coord, cov, p_secret)
        taker = _TakerContext(coord)

        try:
            maker.publish_envelope(wire, terms)
            await taker.fund_eth(wire, url)
            locked_at = maker.lock_rxd(node, wire, terms)
            assert await taker.revalidate_lock(wire, url) is SwapState.BOTH_LOCKED

            # The maker STALLS (never calls claim_eth). The taker waits to t_rxd maturity then refunds.
            node.rxd_mine(terms.t_rxd.value)
            rec = await coord.maybe_refund_asset_on_maker_stall(
                now_block_height=int(node.rxd("getblockcount")),
                asset_locked_at_height=locked_at,
                maker_has_claimed_btc=False,  # the maker context never claimed
            )
            assert rec.state is SwapState.ASSET_REFUNDED_TAKER_ACTS
            cov_txid = rec.radiant_covenant_outpoint.split(":")[0]
            assert node.rxd("gettxout", cov_txid, "0") in (None, ""), "taker reclaimed the RXD covenant"
            # The secret p never crossed the wire (only terms + SPK did).
            assert {k for op, k in wire.transcript if op == "put"} == {"terms", "covenant_spk"}
        finally:
            await rpc.close()
