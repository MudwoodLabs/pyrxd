# Concepts

Background reading for understanding *why* pyrxd works the way it does
and how Radiant differs from related blockchains.

```{toctree}
:maxdepth: 1

gravity
partial-tx-swaps
glyph-structures-and-terminology
radiant-fts-are-on-chain
dmint-v1-deploy
external-miner-protocol
```

## Available now

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
- **[External miner protocol: JSON-over-stdio subprocess contract](external-miner-protocol.md)** —
  the wire protocol `mine_solution_external` uses to drive a fast
  external miner binary as a child process. Documents the request /
  response JSON shapes, exit-code handling, the `EXTERNAL_MINER` /
  `EXTERNAL_MINER_TIMEOUT_S` env vars used by the dMint claim demo,
  what the library re-verifies before trusting a returned nonce, and
  a 20-line reference miner that fits the contract.

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
