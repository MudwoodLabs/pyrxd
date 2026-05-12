# Concepts

Background reading for understanding *why* pyrxd works the way it does
and how Radiant differs from related blockchains.

```{toctree}
:maxdepth: 1

gravity
radiant-fts-are-on-chain
dmint-v1-deploy
glyph-inspect-tool
```

## Available now

- **[Gravity: cross-chain atomic swaps](gravity.md)** — what the
  Gravity protocol is, what a covenant is, and the difference between
  the mainnet-proven sentinel-artifact path and the experimental
  covenant variants. Read this before integrating `pyrxd.gravity`.
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
- **[Glyph inspect tool: structural match, not semantic correctness](glyph-inspect-tool.md)** —
  what `pyrxd glyph inspect` (CLI) and the browser-hosted Pyodide
  inspector at `/inspect/` actually classify, the structural-match
  qualifier on every output, the tx-shape banner (FT/NFT/dMint
  deploy/claim, burn, mutable update), V1-vs-V2 mint scriptSig decode,
  and the SHA-256 install-time integrity model of the browser variant.

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
