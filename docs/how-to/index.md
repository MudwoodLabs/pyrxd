# How-to guides

Task-oriented recipes for solving specific problems. Each guide assumes
you already know the basics and want a focused answer to "how do I X."

```{toctree}
:maxdepth: 1

broadcast-a-transaction
recover-funds-across-wallet-paths
use-the-public-testnet
issue-a-dmint-token
build-a-cross-chain-swap
migrate-0.4-to-0.5
verify-an-spv-proof
spv-verification-pitfalls
```

## Available now

- **[Broadcast a transaction](broadcast-a-transaction.md)** — push a
  signed tx through `ElectrumXClient.broadcast(...)`, recognise the
  four common rejection symptoms (`bad-txns-inputs-missingorspent`,
  `txn-mempool-conflict`, `min relay fee not met`,
  `mandatory-script-verify-flag-failed`), and poll for confirmation.
- **[Recover funds across wallet paths](recover-funds-across-wallet-paths.md)** —
  when a restored seed shows a zero balance but the explorer shows funds, scan
  the BIP44 coin-type/account paths (Photonic, Chainbow, Electron, Tangem) to
  find which derivation actually holds the money. Read-only; `pyrxd wallet
  recover --scan` or the `pyrxd.hd.discover` API.
- **[Use the public Radiant testnet](use-the-public-testnet.md)** — when to
  graduate from the local regtest quickstart to the shared public testnet, how to
  run `radiantd -testnet`, point pyrxd at it, and get testnet coins from the
  (best-effort, community-run) faucet. For most work, stay on regtest.
- **[Issue and mine your own dMint token](issue-a-dmint-token.md)** — launch a
  permissionless, PoW-mined fungible token (no premine, no central issuer) and
  mine the first claim, end to end from the CLI: `glyph init-metadata --type
  dmint-ft`, `glyph deploy-dmint`, `glyph claim-dmint`. Testnet-first — deploying
  your own contract is the one dMint flow that doesn't need mainnet.
- **[Build a cross-chain atomic swap](build-a-cross-chain-swap.md)** — embed the
  trustless BTC/ETH ↔ RXD HTLC swap: the role/timelock safety invariant, the
  `SwapCoordinator` + legs surface, and the proven regtest/Anvil harnesses to copy
  from. Pre-audit — regtest/testnet only, no real value.
- **[Migrate from pyrxd 0.4.x to 0.5.0](migrate-0.4-to-0.5.md)** — three
  breaking signature changes on the V1 dMint mint path, with
  before/after snippets. Read this first if you upgraded from a 0.4.x
  pin and your build is now raising `TypeError` or `ValidationError`
  from `pyrxd.glyph.dmint`.
- **[Verify an SPV proof](verify-an-spv-proof.md)** — given a txid, a
  Merkle path, and a block header, confirm the tx is in the block.
  Covers the raise-on-failure `verify_tx_in_block` recipe, fetching a
  proof from ElectrumX / mempool.space, common failure modes, and the
  covenant-bound `SpvProofBuilder` flow.
- **[SPV verification pitfalls](spv-verification-pitfalls.md)** — the
  non-obvious ways an SPV verifier stays insecure *even after* it
  "checks the Merkle proof": the missing difficulty floor, confirmation
  depth from a reported height, the 64-byte node and coinbase-position
  forgeries, quorum-is-not-a-forgery-defense, and what to differential-test.
  Implementation-agnostic; the companion *why* to the *how* above.

## Coming soon

Additional how-to guides are being written. The runnable demos in
[`examples/`](https://github.com/MudwoodLabs/pyrxd/tree/main/examples) and
the [API Reference](../api/index.rst) cover the same surface in the
meantime.

Suggested guides on the roadmap (open an
[issue](https://github.com/MudwoodLabs/pyrxd/issues) to influence priority):

- How to broadcast a transaction
- How to build a custom locking script
- How to scan an address for Glyphs
- How to handle Radiant's BIP143 quirks (`hashOutputHashes`, ref-aware sighash)
