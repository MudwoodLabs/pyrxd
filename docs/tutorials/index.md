# Tutorials

End-to-end walkthroughs that take you from zero to a working result. Each
tutorial covers one concrete task — generate a key, mint an NFT, deploy a
fungible token, run a Gravity swap.

```{toctree}
:maxdepth: 1

your-first-radiant-transaction
mint-a-glyph-nft
mint-a-glyph-ft
```

## Available now

- **[Your first Radiant transaction](your-first-radiant-transaction.md)** —
  fresh `pip install` to a built, signed RXD send. Walks through
  `pyrxd wallet new`, `pyrxd address`, `pyrxd balance --refresh`,
  `pyrxd utxos`, and a short Python script using
  `HdWallet.build_send_tx(...)`. Broadcast is gated behind a
  `DRY_RUN=0 I_UNDERSTAND_THIS_IS_REAL=yes` env-var pair so dry-run
  is always the default.
- **[Mint a Glyph NFT](mint-a-glyph-nft.md)** — author CBOR metadata,
  build a commit transaction, wait for confirmation, build the reveal,
  and broadcast. Uses a synthetic key by default so you can run every
  step before you have a funded wallet; flip to a real WIF at the end.
- **[Mint a Glyph FT](mint-a-glyph-ft.md)** — start-to-finish: design a
  fungible token, build the commit + reveal transactions with
  `GlyphBuilder.prepare_commit` and `prepare_ft_deploy_reveal`, and
  broadcast a single 75-byte FT output carrying the full premine
  supply. DRY_RUN by default; opt in to broadcast.

## Planned tutorials

Tutorials are being written as the v0.5.x line stabilises. In the
meantime, the runnable end-to-end demos in
[`examples/`](https://github.com/MudwoodLabs/pyrxd/tree/main/examples) are
the closest thing — they exercise the same flows that the future tutorials
will explain step-by-step.

If you have a use case that would make a useful tutorial, please open an
[issue](https://github.com/MudwoodLabs/pyrxd/issues) describing it.
