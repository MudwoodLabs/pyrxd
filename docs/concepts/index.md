# Concepts

Background reading for understanding *why* pyrxd works the way it does
and how Radiant differs from related blockchains.

```{toctree}
:maxdepth: 1

architecture
gravity
covenant-building-blocks
partial-tx-swaps
glyph-structures-and-terminology
glyph-inspect-tool
radiant-fts-are-on-chain
dmint-v1-deploy
v1-mint-mechanics
external-miner-protocol
parallel-mining
```

## Available now

- **[Architecture & module map](architecture.md)** — the codebase shape for
  contributors: the L0→L4 layering (primitives → wallets → protocols → CLI),
  the one-way dependency rule + PEP 562 lazy exports, a per-subsystem map with
  import paths, the trust boundaries (what's pre-audit / dust-only), and an
  "I want to X → touch Y" table. **Start here to contribute.**
- **[Covenant building blocks](covenant-building-blocks.md)** — Radiant's
  differentiated tech as composable primitives: the HTLC covenants (RXD/FT/NFT),
  the consensus-enforced soulbound NFT covenant, the REF-authenticity gate
  (consensus enforces ref *uniqueness*, not mint *provenance*), and
  credential-bound swap gating — each with its import path and its on-chain
  proof. Read this to build *with* covenants rather than only running the
  shipped swap.

- **[Gravity: cross-chain atomic swaps](gravity.md)** — what the
  Gravity protocol is, what a covenant is, and the difference between
  the mainnet-proven sentinel-artifact path and the experimental
  covenant variants. Read this before integrating `pyrxd.gravity`.
- **[Same-chain partial-transaction swaps](partial-tx-swaps.md)** — the
  `pyrxd.swap` offer/accept API for trading RXD and Glyph FTs in one
  transaction via `SIGHASH_SINGLE | ANYONECANPAY`, how its safety rests
  on the maker's signature (not the declared terms), and when to use it
  instead of cross-chain Gravity. Read this before integrating
  `pyrxd.swap`.
- **[Understanding Glyph structures and terminology](glyph-structures-and-terminology.md)** —
  the difference between a `txid`, an `outpoint`, a `GlyphRef`, and a
  `contract_id`; what each `ft` / `nft` / `mut` / `commit-*` / `dmint`
  output type actually means; and which identifier to paste where in
  the inspect tool. Read this first if you've ever been confused by
  why pasting a "contract id" shows you the *deploy* transaction
  instead of your *transfer*.
- **[The Glyph inspect tool: structural match, not semantic correctness](glyph-inspect-tool.md)** —
  what a green check from `glyph inspect` (CLI and browser) actually
  means: it classifies which on-chain *shape* a script or transaction
  matches, offline — it does **not** assert the FT will spend or the
  contract will mint. Read this to understand the trust boundary before
  trusting an inspect result.
- **[Radiant FTs are on-chain (not metadata-on-P2PKH)](radiant-fts-are-on-chain.md)** —
  the most common confusion when porting from Atomicals / Runes / SPL
  is to assume Radiant FTs are plain UTXOs with off-chain meaning. This
  page explains the difference and shows the 75-byte FT script layout,
  the conservation rule, and what wallet code has to filter for.
- **[V1 dMint deploys: N parallel singleton contracts in one reveal](dmint-v1-deploy.md)** —
  what the deploy commit + reveal shapes look like on mainnet (anchored
  to Radiant Glyph Protocol), why pyrxd refuses to emit V2 by default,
  and the five Photonic divergences pyrxd ships with. Read this before
  using `prepare_dmint_deploy` with `DmintV1DeployParams`.
- **[V1 dMint mint mechanics: claiming a contract UTXO](v1-mint-mechanics.md)** —
  the *claim* side of a V1 dMint contract: the canonical 4-output mint
  transaction, the 72-byte scriptSig push convention, the 64-byte PoW
  preimage layout, and the FT-conservation covenant check the script
  enforces on the reward output. The companion to the *deploy* page above.
- **[External miner protocol: JSON-over-stdio subprocess contract](external-miner-protocol.md)** —
  the wire protocol `mine_solution_external` uses to drive a fast
  external miner binary as a child process. Documents the request /
  response JSON shapes, exit-code handling, the `EXTERNAL_MINER` /
  `EXTERNAL_MINER_TIMEOUT_S` env vars used by the dMint claim demo,
  what the library re-verifies before trusting a returned nonce, and
  a 20-line reference miner that fits the contract.
- **[Parallel mining and the bundled miner](parallel-mining.md)** — the two
  miners pyrxd ships (the slow-but-correct in-process `mine_solution` and the
  fast subprocess `mine_solution_external`), the bundled `pyrxd.contrib.miner`
  added in 0.5.1 so you don't have to supply your own, and how parallel workers
  divide the nonce space. Read this to mine a dMint claim at a useful rate.

## Adjacent reading (not yet promoted to concept docs)

The research notes in
[`docs/dmint-research-photonic.md`](../dmint-research-photonic.md),
[`docs/dmint-research-mainnet.md`](../dmint-research-mainnet.md), and
[`docs/dmint-followup.md`](../dmint-followup.md) cover slices of dMint
material at protocol-implementer depth.

## Planned concept articles

- How Radiant differs from Bitcoin (refs, `hashOutputHashes`,
  ref-aware sighash, the additional BIP143 field)
- The Glyph token model: NFT, FT, dMint, mutable, container, WAVE
- pyrxd's security model: typed primitives, `SecretBytes` memory
  hygiene, signer separation, threat boundaries

If you have a use case that would make a useful concept article,
open an [issue](https://github.com/MudwoodLabs/pyrxd/issues).
