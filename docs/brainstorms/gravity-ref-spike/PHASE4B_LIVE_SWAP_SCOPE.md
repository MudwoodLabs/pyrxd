# Phase 4b — live cross-chain BTC↔RXD atomic swap: scope (not yet executed)

Phase 4a (coordinator + FSM) is built + simulated (commit 49e4421). Phase 4b is the
**first real end-to-end cross-chain atomic swap**: a real Bitcoin Taproot HTLC funded on
a Bitcoin chain, the secret revealed on one chain and scraped to claim the other, with the
Radiant covenant (Phase 2/3, already mainnet-proven on its own leg) as the asset side.

This proves what NOTHING so far has: the two legs bound by one secret, end-to-end. The
Radiant leg is mainnet-proven; the BTC leg is BIP341-vector-validated but never broadcast.

## The hard dependency this phase introduces (absent in Phases 1–3)

- **Real Bitcoin funds + a broadcast path.** `tr` is Radiant-only; there is no BTC node.
  pyrxd's BTC data sources (`network/bitcoin.py` MempoolSpaceSource/BlockstreamSource) are
  **read-only** (headers/tx/merkle for SPV) — there is **no Bitcoin broadcast method**.
- The earlier BTC sweeps proved `POST https://mempool.space/api/tx` (and the signet/testnet4
  equivalents) accept a raw tx. So broadcast is wireable via that endpoint; it just isn't in
  the client yet.
- `btc_wallet/keys.py` already supports the `tb` HRP (signet/testnet), so Taproot HTLC
  addresses on signet/testnet work with no code change.

## Recommended path: SIGNET first, then a tiny mainnet swap

**Do the first cross-chain swap on Bitcoin SIGNET** (free faucet coins, real consensus,
real Taproot/CSV/BIP68 enforcement) ↔ Radiant mainnet. Rationale:
- The atomicity, timelock-ordering, and secret-scrape logic are identical on signet vs
  mainnet — signet exercises the real BTC consensus rules at zero BTC cost.
- Only the Radiant side moves a small recoverable asset (already routine this session).
- A subsequent ~dust mainnet swap can confirm real-BTC behavior once signet passes.
Caveat to flag: signet block timing differs from mainnet, so the *margin numbers* must
still be derived from MAINNET BTC inter-block data for any real-value claim (Phase-4a
margin policy already requires a measured value in real-value mode).

## What must be built/wired for 4b (software, no funds)

1. **BTC broadcast + UTXO helpers** (`btc_wallet` or `network/bitcoin.py`):
   - `broadcast_raw_tx(hex, network)` → POST /tx (mainnet | signet | testnet4 base URL).
   - fetch UTXOs for a (taproot) address; fetch a confirmed tx's witness (for scrape_secret).
   These are small, read/write HTTP — mirror the existing MempoolSpaceSource style.
2. **A concrete `RadiantLeg` + `BitcoinTaprootLeg` wiring** behind the coordinator's
   duck-typed surface (Phase 4a already defines the method names): BTC `fund/claim/refund/
   scrape_secret/derive_funding_scriptpubkey` (taproot.py exists — wire broadcast + UTXO
   fetch); Radiant `expected_covenant_scriptpubkey/covenant_outpoint/claim_asset/refund_asset`
   (wrap build_htlc_claim/refund + the tr node).
3. **A real indexer for the REF-authenticity gate** (H4): RXinDexer or a node-backed check
   that the genesis txid:vout + payload hash + `gly` marker resolve — fail-closed if down.
4. **The measured margin** (C2/C3): derive from observed mainnet BTC inter-block distribution
   (a stated percentile) + a Radiant reorg depth + the cross-chain conversion. Feed the
   coordinator's `MarginPolicy(require_measured=True)`.

## The live swap runbook (MAKER_SECRET_TAKER_LOCKS_BTC_FIRST)

1. Maker generates secret p, H = sha256(p). Negotiate terms (amounts, t_BTC > t_RXD + margin,
   asset variant). Coordinator pre_btc_lock_check (REF auth + H freshness + margin + promised
   params).
2. **Taker locks BTC FIRST**: funds the P2TR HTLC (signet) — claim leaf OP_SHA256<H>, refund
   leaf CSV to taker.
3. **Maker locks the asset SECOND**: funds the Radiant HTLC covenant (Phase 2/3 — proven).
   Taker post_asset_lock_revalidate (on-chain covenant SPK == expected from terms+H), else
   refund BTC (PARAMS_MISMATCH).
4. **Maker claims BTC** (reveals p in the BTC witness).
5. **Taker scrapes p** from the BTC claim witness (scrape_secret, by sha256==H) and **claims
   the Radiant asset** before t_RXD.
6. Failure paths to also exercise: MUTUAL_REFUND (maker never claims → both refund after their
   timelocks); MAKER_STALLS (maker stalls past t_RXD−N → taker proactively refunds the asset).

## Acceptance for 4b
- A real signet BTC HTLC ↔ Radiant-mainnet asset swap completes (COMPLETED) with verifiable
  txids on both chains; the preimage scraped from the BTC witness actually unlocks the Radiant
  claim.
- A deliberate MUTUAL_REFUND and a deliberate MAKER_STALLS both end with each party whole.
- Then (optional) a dust mainnet-BTC repeat.
- Honesty: signet ≠ mainnet for timing; margin from mainnet data before any real-value swap.

## Cost / risk
- Signet BTC = free (faucet). Radiant asset = small recoverable (routine). Mainnet repeat =
  dust BTC. The real cost is the broadcast/UTXO/indexer wiring + careful runbook execution
  with the confirmation waits (BTC ~10min/block, the CSV/timelock-ordering margins are hours).
- External audit of the cross-chain atomicity + the parser remains the HARD GATE before any
  production/mainnet-product claim — 4b is a proof-of-mechanism, not a product launch.
