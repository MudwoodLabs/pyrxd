# How-to guides

Task-oriented recipes for solving specific problems. Each guide assumes
you already know the basics and want a focused answer to "how do I X."

```{toctree}
:maxdepth: 1

migrate-0.4-to-0.5
handle-radiant-bip143-quirks
```

## Available now

- **[Migrate from pyrxd 0.4.x to 0.5.0](migrate-0.4-to-0.5.md)** — three
  breaking signature changes on the V1 dMint mint path, with
  before/after snippets. Read this first if you upgraded from a 0.4.x
  pin and your build is now raising `TypeError` or `ValidationError`
  from `pyrxd.glyph.dmint`.
- **[Handle Radiant's BIP143 sighash quirks](handle-radiant-bip143-quirks.md)** —
  the `hashOutputHashes` field Radiant inserts into the BIP143
  preimage, how it commits to ref opcodes (`OP_PUSHINPUTREF` /
  `OP_PUSHINPUTREFSINGLETON`), and the pitfalls when porting a signer
  from Bitcoin, BCH, or BSV.

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
- How to scan an address for Glyphs
