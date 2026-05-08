# dMint Follow-up: PoW Distributed Mint (Future Work)

> ⚠️ **This document is out of date — see code instead.**
>
> Written when pyrxd shipped only the premine-at-deploy path. Since
> then pyrxd has gained **full V2 deploy** support and **V1 mint**
> support against live mainnet contracts (RBG and other live V1
> deploys). The "what is NOT implemented" sections below are wrong:
> the V2 contract builder, ASERT/LWMA difficulty bytecode, V1+V2
> parsers, V1+V2 mint tx builders, an external-miner shim, and a
> reference Python miner all ship today.
>
> **Authoritative sources for current dMint capability:**
>
> - [`src/pyrxd/glyph/dmint.py`](../src/pyrxd/glyph/dmint.py) —
>   builders, parsers, miner, verifier
> - [`src/pyrxd/glyph/builder.py`](../src/pyrxd/glyph/builder.py) —
>   `prepare_dmint_deploy` (V2; refuses to run without
>   `allow_v2_deploy=True` opt-in until V1 deploy lands in M2)
> - [`examples/dmint_claim_demo.py`](../examples/dmint_claim_demo.py) —
>   manual real-mainnet V1 mint runner
> - [`docs/plans/2026-05-07-feat-dmint-v1-mint-and-reference-miner-plan.md`](plans/2026-05-07-feat-dmint-v1-mint-and-reference-miner-plan.md) —
>   current dMint roadmap (M1 V1 mint shipped; M2 V1 deploy; M3 V2
>   deploy proof, deferred)
>
> **What's still genuinely future work:**
>
> - V1 deploy builder (M2 — `prepare_dmint_deploy` still emits V2;
>   needs a `version="v1"` opt-in path)
> - Live-mainnet V2 deploy proof (M3, deferred indefinitely — no
>   ecosystem demand)
> - EPOCH and SCHEDULE DAA modes (raise `NotImplementedError`; no
>   observed contract uses them)
> - Native fast miner — pyrxd ships a slow Python reference; users
>   wanting GPU/multi-core go through the external-miner shim to
>   `glyph-miner`
>
> Full rewrite of this doc lands when M2 closes.

---

**(Original document — historically accurate at writing time, no
longer reflects the current code. Retained for context.)**

pyrxd 0.2.x implements the **premine-at-deploy** FT path. This document
captures what a future PoW-capable SDK would need to implement Photonic's
full dMint protocol, and why most consumers do not require it.

## What pyrxd 0.2.x implements

- `GlyphMetadata.for_dmint_ft(...)` — metadata with `p:[1,4]` (FT + DMINT markers)
- `GlyphBuilder.prepare_ft_deploy_reveal(...)` — reveal scripts for a
  premine-at-deploy FT: entire supply to treasury PKH at vout[0]
- `FtUtxoSet.build_transfer_tx(...)` — conservation-enforcing FT transfer
- CBOR cross-decoder tests (pyrxd encode ↔ RXinDexer reference decoder)
- Deploy structural integration tests + VPS `testmempoolaccept` proof

The `p:[1,4]` marker tells indexers this token follows the dMint protocol.
For premine-only consumers the only relevant part of that protocol is the
**deploy shape** — a single reveal output carrying the full supply. The PoW
ongoing-mint machinery is not used.

## What is NOT implemented: PoW distributed mint

Photonic's dMint protocol supports a second mode beyond premine: holders
can mine new tokens by solving a PoW challenge embedded in a covenant UTXO
that remains on-chain after deploy. pyrxd does not implement this.

Specifically missing:

### 1. Difficulty covenant UTXO

The deploy reveal would produce a second output — the "dMint covenant UTXO"
— containing the mining difficulty parameters. This UTXO is spent and
re-created by each minting transaction, updating the difficulty.

Radiant implementation would need:
- A covenant script enforcing ASERT or LWMA difficulty adjustment
- The minting tx must satisfy a hash-less-than-target check (`OP_SHA256`
  of the minting tx's nonce field < current target)
- The covenant re-creates itself at the next output with updated params

### 2. Per-mint commit/reveal

Each minting event uses a two-tx commit/reveal (same shape as NFT minting
in pyrxd today, but carrying FT outputs). The commit locks a small UTXO;
the reveal spends it, proves PoW, and produces new FT outputs.

`GlyphBuilder.prepare_commit` and `prepare_reveal` handle the basic shape
but don't carry the PoW nonce or covenant interaction.

### 3. ASERT / LWMA difficulty adjustment

The difficulty target adjusts per-block (ASERT) or per-window (LWMA).
Implementing this in a Radiant script covenant requires bignum comparison
(`OP_BIN2NUM`, `OP_DIV`) — the same operations the Gravity Protocol uses
for BTC header work. Feasible but non-trivial.

## When premine-only is enough

A **premine-only** token mints the entire supply to a treasury wallet at
deploy. Distribution happens via plain FT transfers
(`FtUtxoSet.build_transfer_tx`) as the issuer hands out tokens. No
post-deploy minting occurs.

The `p:[1,4]` marker is appropriate for premine-only deploys because:

1. Photonic Wallet and most RXD indexers recognize it as the correct FT
   token class for fungible tokens with explicit supply
2. It is forward-compatible — if a downstream consumer later needs a
   secondary PoW mint phase, the token ref is already correctly typed

Using `p:[1]` alone (plain FT, no dMint marker) also works for the
premine shape. The choice between `[1]` and `[1,4]` is a downstream
decision — `[1,4]` reads as "this token participates in the dMint
protocol family even if it never uses the PoW phase," which some
indexers prefer.

## Implementing PoW dMint (future contributor guide)

If a future contributor wants to add full PoW dMint support:

1. **Difficulty covenant script** — model after `pyrxd/gravity/covenant.py`.
   Encode difficulty params as constructor arguments baked into bytecode.
   The covenant must re-create itself at output index N with updated target.

2. **Mint tx builder** — new function `build_mint_tx(covenant_utxo, nonce,
   miner_pkh, fee_sats)`. The nonce is a 4-byte field in the tx that the
   miner varies to find a valid PoW solution.

3. **Difficulty verification** — `OP_SHA256` of the serialized mint tx
   (minus nonce field) must be `<=` the current target. This is a script
   constraint enforced by the covenant, not by pyrxd.

4. **Tests** — unit tests can use a trivially easy target (all-ones). VPS
   integration test can mine one token against the live covenant.

The Photonic Wallet TypeScript source (`lib/dmint.ts`) is the reference
implementation. pyrxd's `cbor2`-based CBOR encoding already matches
Photonic's payload format (verified by `tests/test_cbor_cross_decoder.py`).
