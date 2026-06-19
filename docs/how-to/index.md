# How-to guides

Task-oriented recipes for solving specific problems. Each guide assumes
you already know the basics and want a focused answer to "how do I X."

```{toctree}
:maxdepth: 1

receive-and-check-balance
transfer-a-glyph-token
use-the-signing-agent
recover-funds-across-wallet-paths
broadcast-a-transaction
use-the-public-testnet
scan-address-for-glyphs
issue-a-dmint-token
build-a-cross-chain-swap
run-a-two-host-swap-dry-run
verify-an-spv-proof
spv-verification-pitfalls
handle-radiant-bip143-quirks
migrate-0.4-to-0.5
```

## Available now

- **[Receive funds and check your balance](receive-and-check-balance.md)** — the
  read-only wallet basics: `pyrxd address` for a receive address, `pyrxd balance
  --refresh` to confirm money arrived, `pyrxd utxos` to see exactly what you
  hold, and `wallet export-xpub` for watch-only receiving. No signing, no
  mnemonic.
- **[Transfer a Glyph token after you mint it](transfer-a-glyph-token.md)** — the
  canonical second task: send an FT or NFT to someone with `glyph transfer-ft
  REF AMOUNT --to ADDR` / `glyph transfer-nft REF --to ADDR`. Explains that `REF`
  is the token's genesis ref (not the UTXO), FT conservation + change, and why an
  NFT transfer needs a little plain RXD for the fee.
- **[Use the local signing agent](use-the-signing-agent.md)** — unlock the wallet
  once into a foreground agent (`pyrxd agent unlock`); the seed lives in one
  process, `wallet send` signs against it with no mnemonic re-entry, and you
  approve each spend in the agent's terminal. Covers `--idle-timeout`,
  `--auto-confirm-under`, and `agent status` / `lock`.
- **[Recover funds across wallet paths](recover-funds-across-wallet-paths.md)** —
  when a restored seed shows a zero balance but the explorer shows funds, scan
  the BIP44 coin-type/account paths (Photonic, Chainbow, Electron, Tangem) to
  find which derivation actually holds the money, then `pyrxd wallet sweep` it to
  a reachable address. Read-only scan; `pyrxd wallet recover --scan` or the
  `pyrxd.hd.discover` API.
- **[Broadcast a transaction](broadcast-a-transaction.md)** — push a
  signed tx through `ElectrumXClient.broadcast(...)`, recognise the
  four common rejection symptoms (`bad-txns-inputs-missingorspent`,
  `txn-mempool-conflict`, `min relay fee not met`,
  `mandatory-script-verify-flag-failed`), and poll for confirmation.
- **[Use the public Radiant testnet](use-the-public-testnet.md)** — when to
  graduate from the local regtest quickstart to the shared public testnet, how to
  run `radiantd -testnet`, point pyrxd at it, and get testnet coins from the
  (best-effort, community-run) faucet. For most work, stay on regtest.
- **[Scan an address for Glyphs](scan-address-for-glyphs.md)** — given any
  Radiant address, list the Glyph tokens (NFTs and FTs) held at it. An async
  ElectrumX recipe returning typed objects you can filter in-process — the
  library counterpart to `pyrxd glyph list`.
- **[Issue and mine your own dMint token](issue-a-dmint-token.md)** — launch a
  permissionless, PoW-mined fungible token (no premine, no central issuer) and
  mine the first claim, end to end from the CLI: `glyph init-metadata --type
  dmint-ft`, `glyph deploy-dmint`, `glyph claim-dmint`. Testnet-first — deploying
  your own contract is the one dMint flow that doesn't need mainnet.
- **[Build a cross-chain atomic swap](build-a-cross-chain-swap.md)** — embed the
  trustless BTC/ETH ↔ RXD HTLC swap: the role/timelock safety invariant, the
  `SwapCoordinator` + legs surface, and the proven regtest/Anvil harnesses to copy
  from. Pre-audit — regtest/testnet only, no real value.
- **[Run a two-host swap dry-run](run-a-two-host-swap-dry-run.md)** — split the
  single-process ETH↔RXD swap across two operators on two hosts, each holding only
  their own keys and exchanging only the public negotiation envelope out-of-band: the
  first real exercise of untrusted-counterparty verification. The prep for a genuine
  two-party adversarial run. Pre-audit — regtest/testnet only, no real value.
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
- **[Handle Radiant's BIP143 sighash quirks](handle-radiant-bip143-quirks.md)** —
  for porting a sighash implementation from Bitcoin/BCH/BSV: the extra
  `hashOutputHashes` field and ref-aware preimage Radiant adds. You only need
  this if you build preimages by hand — `Transaction.sign(...)` handles it for
  you.
- **[Breaking changes since pyrxd 0.4.x](migrate-0.4-to-0.5.md)** — the only
  public-API break since 0.4.x is the three V1-dMint mint-path signature changes
  in 0.5.0 (`build_pow_preimage` and friends), with before/after snippets. Every
  release since (0.5.x → current) is additive and drop-in. Read this only if
  you're upgrading from a 0.4.x pin and hitting `TypeError` / `ValidationError`
  from `pyrxd.glyph.dmint`.

## Coming soon

Additional how-to guides are being written. The runnable demos in
[`examples/`](https://github.com/MudwoodLabs/pyrxd/tree/main/examples) and
the [API Reference](../api/index.rst) cover the same surface in the
meantime.

Suggested guides on the roadmap (open an
[issue](https://github.com/MudwoodLabs/pyrxd/issues) to influence priority):

- How to build a custom locking script
- How to run a same-chain partial-transaction swap (`pyrxd.swap`)
