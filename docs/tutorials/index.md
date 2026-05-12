# Tutorials

End-to-end walkthroughs that take you from zero to a working result. Each
tutorial covers one concrete task — generate a key, mint an NFT, deploy a
fungible token, run a Gravity swap.

```{toctree}
:maxdepth: 1

your-first-radiant-transaction
```

## Available now

- **[Your first Radiant transaction](your-first-radiant-transaction.md)** —
  fresh `pip install` to a built, signed RXD send. Walks through
  `pyrxd wallet new`, `pyrxd address`, `pyrxd balance --refresh`,
  `pyrxd utxos`, and a short Python script using
  `HdWallet.build_send_tx(...)`. Broadcast is gated behind a
  `DRY_RUN=0 I_UNDERSTAND_THIS_IS_REAL=yes` env-var pair so dry-run
  is always the default.

## Planned tutorials

Tutorials are being written as the v0.5.x line stabilises. In the
meantime, the runnable end-to-end demos in
[`examples/`](https://github.com/MudwoodLabs/pyrxd/tree/main/examples) are
the closest thing — they exercise the same flows that the future tutorials
will explain step-by-step.

If you have a use case that would make a useful tutorial, please open an
[issue](https://github.com/MudwoodLabs/pyrxd/issues) describing it.
