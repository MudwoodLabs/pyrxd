# Watchtower v1 — Phase 0 Verification (2026-06-03)

Gating checks for `docs/plans/2026-06-03-feat-htlc-swap-watchtower-plan.md` Phase 0. All findings are read from code on `feat/gravity-ref-ft-covenant-spike`.

## 1. SPV F-01 / F-04 — CONFIRMED FIXED on this branch

The watchtower's finality gate trusts BTC headers, so these must be closed. Fixed in commit **`c91b1e7`** ("fix(spv): harden SPV primitive — close red-team exploitable cluster"):

- **F-01 (no difficulty floor / min-difficulty forge):** `expected_nbits` (+ `expected_nbits_next` retarget window) threaded through `verify_header_chain` ([src/pyrxd/spv/chain.py:25-83](../../../src/pyrxd/spv/chain.py#L25-L83)) and pinned in `CovenantParams` ([src/pyrxd/spv/proof.py:202-251](../../../src/pyrxd/spv/proof.py#L202-L251), threaded at `:404-405`). Rationale documented inline ([proof.py:48,68](../../../src/pyrxd/spv/proof.py#L48)): a forged min-difficulty chain off a real anchor would otherwise pass for ~$0.
- **F-04 (coinbase guard bypass via `pos = k·2^depth`):** structural coinbase reject — a coinbase is identified by its null-outpoint first input, independent of `pos` ([proof.py:371-376](../../../src/pyrxd/spv/proof.py#L371-L376)), in addition to the `pos==0` fast-fail ([:350-353](../../../src/pyrxd/spv/proof.py#L350)).

→ No pre-flight blocker. The gate may trust BTC headers.

## 2. `decide()` consumption shape — CONFIRMED (no re-derivation)

The two pure functions the watchtower's `decide()` consumes (never re-derives):

- `should_taker_refund_proactively(*, now_block_height, asset_locked_at_height, t_rxd: Timelock, safety_window_blocks: int, maker_has_claimed_btc: bool, block_interval_s=600.0) -> bool` ([swap_coordinator.py:465](../../../src/pyrxd/gravity/swap_coordinator.py#L465))
- `assess_claim_finality(*, counter_claim_finality: CounterClaimFinality, now_rxd_height: int, asset_locked_at_height: int, t_rxd: Timelock, policy: MarginPolicy) -> ClaimFinality` → SAFE / WAIT / SQUEEZED ([swap_coordinator.py:535](../../../src/pyrxd/gravity/swap_coordinator.py#L535))

The counter-leg verdict is built with the existing adapter `CounterClaimFinality.from_btc_depth(confirmations, required_depth)` ([finality.py:64](../../../src/pyrxd/gravity/finality.py#L64)) — `FINAL` iff `confirmations >= required_depth`, else `NOT_YET_FINAL_LIVE`. `decide()` supplies `confirmations` from the quorum BTC reader and `required_depth = policy.btc_claim_reorg_depth` (normalised). All inputs are observations + record/policy; the gate logic is untouched.

## 3. RXD data sources — SINGLE-SOURCE today (v2 quorum blocker; v1 corroboration flag)

Confirmed: BTC has `MultiSourceBtcDataSource` + `MultiSourceBtcFundingReader` ([network/bitcoin.py:723,1056](../../../src/pyrxd/network/bitcoin.py#L723)), but **there is no Radiant/RXD multi-source class**. RXD height/confirmations come from a single source:
- `getblockcount` over the single ssh-tr node ([scripts/radiant_mainnet_chainio.py:135](../../../scripts/radiant_mainnet_chainio.py#L135), [scripts/_dust_swap_shared.py:203](../../../scripts/_dust_swap_shared.py#L203)), or
- one `ElectrumXClient.get_tip_height` ([network/electrumx.py:378](../../../src/pyrxd/network/electrumx.py#L378)); `RxinDexerClient.__init__(self, client: ElectrumXClient)` wraps exactly one client ([network/rxindexer.py:72](../../../src/pyrxd/network/rxindexer.py#L72)).

→ **v1 (alert-only):** RXD-derived pages carry a `low_corroboration` flag; a poisoned RXD read causes a false *page*, not a false broadcast — acceptable. **v2 (autonomous):** a ≥2 independent RXD source quorum is a HARD blocker before any RXD-finality-driven broadcast. `ChainTracker` ([network/chaintracker.py](../../../src/pyrxd/network/chaintracker.py)) is BTC-header-only and cannot supply RXD burial.

## Verdict
Phase 0 clear. Proceed to Phase 1 (pure `decide()` + reconciler). No blockers for alert-only v1; the RXD-quorum and ETH-RPC-quorum gaps are correctly deferred to v2/v3.
