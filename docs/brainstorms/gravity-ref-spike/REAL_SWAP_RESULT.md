# Gravity FT↔BTC — first real cross-chain swap (2026-05-21)

A live, end-to-end Glyph **fungible-token ↔ Bitcoin** atomic swap, settled on
Radiant mainnet against a **real Bitcoin mainnet payment** verified by SPV.

## What happened

A maker offered 1,000 units of a Glyph FT (**GSWAP2**) for 10,000 sats of BTC.
A taker paid the BTC on Bitcoin mainnet; the Radiant covenant verified that
payment via an on-chain SPV proof (real BTC headers + Merkle inclusion) and
released the FT to the taker. No custodian, no bridge, no trusted relayer —
the covenant alone gates the release on proof of the Bitcoin payment.

## Verifiable transactions

**Radiant (Glyph FT side):**
- FT genesis (GSWAP2, 1,000 units): `3c0cf043c7d760fe9f821feeab1a7fae205f2aab8e9a6268e7d0125997b8b4ea:0`
  (reveal `eacc7c4f201fa6c29901f9f28342ff8521440fb801bd1be6e738c3a47a3d2859`)
- FT funded into the swap covenant: `9dab8c33199929447d5754e86909e420dc0b8d98d6f68065652c4b66ce3fb110`
- **Settlement (finalize, SPV-gated):** `04a2f1bfeacaf703b1dcacc59ef3d097d73f973cb12de0265c8133a6001bb789`
  — releases the 1,000 FT units to the taker.

**Bitcoin (payment side):**
- **Payment to the maker (10,000 sats, P2WPKH):**
  `d79f30dd7722c988b9debb2df4ff0fb32c3e8e61f29d395da0c3860b40d75294`
  confirmed in block **950,453**.
- Maker receive address: `bc1qdwz0n8l72x5eqzakkqsx42p7pdmepzyrgumwzk`

## What the covenant verified on-chain (Radiant consensus)

1. Chain-identity anchor: header h1's prevHash == a committed real mainnet
   block (950,452).
2. 12 real Bitcoin block headers (950,453–950,464), each with valid
   proof-of-work and chain-linking.
3. Merkle inclusion of the payment tx in block 950,453 (depth-13 tree,
   sentinel-padded to the covenant's 20-level capacity).
4. The payment output pays the maker's committed address for ≥ the required
   satoshis.
5. FT conservation + the swap hardening (single ref, exact amount, single
   output) + a hash-compare pinning the FT to the taker's address.

## Honest scope (what this does and does not show)

- **Real, not synthetic.** Real BTC moved on Bitcoin mainnet; the proof uses
  real headers/Merkle, verified by Radiant consensus (`testmempoolaccept` +
  broadcast).
- **Taker payment shape (current limitation).** This covenant variant requires
  the taker's BTC payment to be a single-input segwit tx (the conforming
  payment was built with pyrxd's `build_payment_tx`). An **any-wallet** variant
  (multi-input, change anywhere) is designed, prototyped, and integrated
  (compiles + passes static guards) but is **not yet proven on-chain or
  audited** — see the any-wallet design note. A production "pay from any
  wallet" claim depends on that work + an external audit of the BTC-tx parser.
- **Not yet audited.** This is spike/validation work. External audit of the
  covenant — especially the SPV parsing path — is a hard gate before any
  production/mainnet-product claim.

## Parameters that matter (operational lessons)

- The covenant's `btcChainAnchor` must be set **just before** the BTC payment,
  with a **wide header window (N)**, or the payment can land outside the
  provable window. (Set anchor = payment_block − 1 after the payment confirms.)
- The covenant's **Merkle depth (M) must exceed the real block's tree depth**
  (mainnet blocks routinely exceed depth 12). Use the sentinel M=20 variant.
- The wide-window covenant is ~10 KB, so funding it costs ~1 RXD — a real
  per-swap cost to weigh in production parameter choice.
