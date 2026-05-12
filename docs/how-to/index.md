# How-to guides

Task-oriented recipes for solving specific problems. Each guide assumes
you already know the basics and want a focused answer to "how do I X."

```{toctree}
:maxdepth: 1

migrate-0.4-to-0.5
scan-address-for-glyphs
```

## Available now

- **[Migrate from pyrxd 0.4.x to 0.5.0](migrate-0.4-to-0.5.md)** — three
  breaking signature changes on the V1 dMint mint path, with
  before/after snippets. Read this first if you upgraded from a 0.4.x
  pin and your build is now raising `TypeError` or `ValidationError`
  from `pyrxd.glyph.dmint`.
- **[Scan a Radiant address for Glyphs](scan-address-for-glyphs.md)** —
  given an address, list every Glyph NFT and FT it currently holds.
  Async recipe that wires `GlyphScanner` to an open `ElectrumXClient`,
  with notes on filtering by type and the structural-match trust
  boundary.

## Coming soon

Additional how-to guides are being written. The runnable demos in
[`examples/`](https://github.com/MudwoodLabs/pyrxd/tree/main/examples) and
the [API Reference](../api/index.rst) cover the same surface in the
meantime.

Suggested guides on the roadmap (open an
[issue](https://github.com/MudwoodLabs/pyrxd/issues) to influence priority):

- How to broadcast a transaction
- How to verify an SPV proof
- How to build a custom locking script
- How to handle Radiant's BIP143 quirks (`hashOutputHashes`, ref-aware sighash)
