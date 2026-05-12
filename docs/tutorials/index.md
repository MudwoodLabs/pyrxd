# Tutorials

End-to-end walkthroughs that take you from zero to a working result. Each
tutorial covers one concrete task — generate a key, mint an NFT, deploy a
fungible token, run a Gravity swap.

```{toctree}
:maxdepth: 1

mint-from-a-dmint-contract
```

## Available now

- **[Mint from a V1 dMint contract on Radiant mainnet](mint-from-a-dmint-contract.md)** —
  end-to-end walkthrough of mining and claiming one mint from a live
  V1 dMint contract (anchored to Glyph Protocol / GLYPH). Covers
  `find_dmint_contract_utxos`, the `EXTERNAL_MINER` JSON-over-stdio
  miner protocol, the four-output mint-tx shape, and the broadcast
  handshake. This is the most advanced tutorial in the set — it touches
  the network, costs real RXD, and is irreversible.

## Coming soon

More tutorials are being written as the v0.5.x line stabilises. In the
meantime, the runnable end-to-end demos in
[`examples/`](https://github.com/MudwoodLabs/pyrxd/tree/main/examples) are
the closest thing — they exercise the same flows that the future tutorials
will explain step-by-step.

If you have a use case that would make a useful tutorial, please open an
[issue](https://github.com/MudwoodLabs/pyrxd/issues) describing it.
