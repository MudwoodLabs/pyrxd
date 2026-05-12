# Tutorials

End-to-end walkthroughs that take you from zero to a working result. Each
tutorial covers one concrete task — generate a key, mint an NFT, deploy a
fungible token, run a Gravity swap.

```{toctree}
:maxdepth: 1

mint-a-glyph-ft
```

## Available now

- **[Mint a Glyph FT](mint-a-glyph-ft.md)** — start-to-finish: design a
  fungible token, build the commit + reveal transactions with
  `GlyphBuilder.prepare_commit` and `prepare_ft_deploy_reveal`, and
  broadcast a single 75-byte FT output carrying the full premine
  supply. DRY_RUN by default; opt in to broadcast.

## Coming soon

More tutorials are being written as the v0.5.x line stabilises. In the
meantime, the runnable end-to-end demos in
[`examples/`](https://github.com/MudwoodLabs/pyrxd/tree/main/examples) are
the closest thing — they exercise the same flows that the future tutorials
will explain step-by-step.

If you have a use case that would make a useful tutorial, please open an
[issue](https://github.com/MudwoodLabs/pyrxd/issues) describing it.
