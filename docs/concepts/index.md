# Concepts

Background reading for understanding *why* pyrxd works the way it does
and how Radiant differs from related blockchains.

```{toctree}
:maxdepth: 1

gravity
```

## Available now

- **[Gravity: cross-chain atomic swaps](gravity.md)** — what the
  Gravity protocol is, what a covenant is, and the difference between
  the mainnet-proven sentinel-artifact path and the experimental
  covenant variants. Read this before integrating `pyrxd.gravity`.

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
