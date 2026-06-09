# Tutorials

End-to-end walkthroughs that take you from zero to a working result. Each
tutorial covers one concrete task — generate a key, mint an NFT, deploy a
fungible token, run a Gravity swap.

```{toctree}
:maxdepth: 1

quickstart
your-first-radiant-transaction
inspect-a-radiant-transaction
mint-a-glyph-nft
mint-a-glyph-ft
mint-from-a-dmint-contract
```

## Available now

- **[5-minute quickstart: your first token on a local chain](quickstart.md)** —
  the fastest path from `pip install` to a real on-chain Glyph NFT, minted on a
  private regtest chain that runs entirely on your machine. One command
  (`pyrxd regtest up`) stands up the node and hands you a pre-funded key; a
  companion script mints the token; one command tears it all down. No faucet,
  no mainnet RXD, nothing at risk. **Start here if you want to build.**
- **[Your first Radiant transaction](your-first-radiant-transaction.md)** —
  fresh `pip install` to a built, signed RXD send. Walks through
  `pyrxd wallet new`, `pyrxd address`, `pyrxd balance --refresh`,
  `pyrxd utxos`, and a short Python script using
  `HdWallet.build_send_tx(...)`. Broadcast is gated behind a
  `DRY_RUN=0 I_UNDERSTAND_THIS_IS_REAL=yes` env-var pair so dry-run
  is always the default.
- **[Inspect a Radiant transaction in the browser](inspect-a-radiant-transaction.md)** —
  the gentlest first-contact with pyrxd. No install, no wallet, no
  funded UTXOs. Open the browser-hosted inspect tool, paste real
  mainnet txids, and decode an FT transfer, a dMint mint claim, a
  Glyph deploy reveal, and a plain RXD send. Start here if you're
  new to Radiant or pyrxd.
- **[Mint a Glyph NFT](mint-a-glyph-nft.md)** — author CBOR metadata,
  build a commit transaction, wait for confirmation, build the reveal,
  and broadcast. Uses a synthetic key by default so you can run every
  step before you have a funded wallet; flip to a real WIF at the end.
- **[Mint a Glyph FT](mint-a-glyph-ft.md)** — start-to-finish: design a
  fungible token, build the commit + reveal transactions with
  `GlyphBuilder.prepare_commit` and `prepare_ft_deploy_reveal`, and
  broadcast a single 75-byte FT output carrying the full premine
  supply. DRY_RUN by default; opt in to broadcast.
- **[Mint from a V1 dMint contract on Radiant mainnet](mint-from-a-dmint-contract.md)** —
  end-to-end walkthrough of mining and claiming one mint from a live
  V1 dMint contract (anchored to Glyph Protocol / GLYPH). Covers
  `find_dmint_contract_utxos`, the `EXTERNAL_MINER` JSON-over-stdio
  miner protocol, the four-output mint-tx shape, and the broadcast
  handshake. This is the most advanced tutorial in the set — it touches
  the network, costs real RXD, and is irreversible.

## Planned tutorials

Tutorials are being written as the v0.5.x line stabilises. In the
meantime, the runnable end-to-end demos in
[`examples/`](https://github.com/MudwoodLabs/pyrxd/tree/main/examples) are
the closest thing — they exercise the same flows that the future tutorials
will explain step-by-step.

If you have a use case that would make a useful tutorial, please open an
[issue](https://github.com/MudwoodLabs/pyrxd/issues) describing it.
