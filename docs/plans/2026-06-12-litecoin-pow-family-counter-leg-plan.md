---
title: Litecoin as a Bitcoin-family (PoW-depth) counter chain
type: plan
date: 2026-06-12
status: DONE — spike GO, shipped with full dual-chain regtest proof (see Outcome)
parent: docs/ROADMAP.md (Tier 2.3) → docs/plans/2026-06-12-tier2-xchain-swap-library-plan.md
---

# Litecoin counter-leg — the chain-family effort, de-risked by spike

## The reframe (mirrors the Base decision exactly)

The feared scope was "generalize every `counter_chain == 'btc'` dispatch site." Grounding
showed that is unnecessary: `counter_chain == "btc"` already names the **PoW-depth
family** semantics (depth finality, same-clock BLOCKS timelocks), all of which hold for
Litecoin; the concrete chain is pinned by the leg/locator `network` tag (bech32 HRP) —
exactly as `counter_chain == "eth"` named the finalized-checkpoint family and Base was
pinned by chain id. **Zero coordinator dispatch changes.**

## The go/no-go spike (2026-06-12, measured)

Stood up the official Litecoin Core v0.21.5.5 binary on regtest and drove pyrxd's OWN
taproot builders (`build_htlc` / `build_claim_tx` / `build_refund_tx` / `scrape_secret`)
against live Litecoin consensus, `network="rltc"`:

- taproot softfork: **active, since: 0** (regtest from genesis); CSV active;
- P2TR `rltc1p…` address valid (witness v1);
- correct-preimage claim **accepted**; wrong-preimage **rejected**
  (`witness program hash mismatch` — the identical Bitcoin reject reason);
- preimage scraped from the on-chain witness;
- premature CSV refund rejected `non-BIP68-final`; matured refund **accepted**; both
  spend paths broadcast and confirmed.

Verdict: **GO** — the Taproot-HTLC leg is chain-agnostic across the family.

## What shipped

- `docker/litecoin-regtest.Dockerfile` — official release binary; PROVENANCE NOTE: the
  litecoin release publishes no checksum manifest, so the SHA-256 measured from the
  official download on 2026-06-12 is pinned in the Dockerfile (re-measure on bump).
- `pyrxd.btc_wallet.chains` — `PowChain` / `KNOWN_POW_CHAINS` (bitcoin 600 s, litecoin
  150 s) + `pow_chain_by_network` (fail-closed on unvetted tags). Mirrors
  `eth_wallet.chains`; deliberately ships NO depth defaults (depth must be value-scaled
  per chain's cost-to-reorg).
- `AUDIT_CLEARED_NETWORKS` += `rltc`/`tltc` (isolated test chains); `_TESTNET_HRPS` +=
  same (testnet base58/WIF versions; LTC mainnet stays on the fallback path — bech32m
  HRP is authoritative for the P2TR flows).
- Chain knobs on both regtest suites: `BTC_FAMILY_CHAIN=ltc`
  (`test_btc_htlc_regtest_e2e.py`) and `XCHAIN_BTC_FAMILY=ltc`
  (`test_xchain_swap_regtest_e2e.py` — image/cli/HRP/`block_interval_s`, with a
  build-from-Dockerfile fallback for the local-only image).
- Top-level exports + registry unit tests; how-to gains "Bitcoin family — Litecoin works
  today" beside the Base section.

## One real finding the LTC run surfaced

`test_reveal_with_closing_window_pages_squeezed` hard-coded a t_rxd window tuned to
Bitcoin's interval. On Litecoin the gate **correctly** returned WAIT (a 6-block LTC reorg
depth converts to only 3 RXD blocks of reserve — the window genuinely had room), exposing
the hidden chain assumption in the TEST, not the gate. The test now derives its squeeze
window from the same policy math the gate uses, so it forces a squeeze on whichever chain
the run targets. This is precisely the class of assumption the dual-chain run exists to
flush out.

## Outcome — dual-chain proof, all green

| Suite | Bitcoin | Litecoin |
|---|---|---|
| BTC-leg consensus (`test_btc_htlc_regtest_e2e.py`) | 2 passed | 2 passed |
| Full coordinator e2e (`test_xchain_swap_regtest_e2e.py`, 10 tests: happy/mutual-refund/maker-stall/watchtower) | 10 passed | 10 passed |

Pre-audit posture unchanged: mainnet `"ltc"` refuses to run without the post-audit
`audit_cleared=True` opt-in, like every value-bearing network.
