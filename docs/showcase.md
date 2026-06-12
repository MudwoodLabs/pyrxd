# What you can build on Radiant

`pyrxd` is a Python SDK for the [Radiant (RXD) blockchain](https://radiantcore.org/):
transaction building, HD wallets, the Glyph token protocol (NFT / FT / dMint),
same-chain swaps, and trustless **cross-chain atomic swaps**. This page is a
tour of what is real and proven today, with on-chain transactions you can open
in a block explorer and runnable examples you can read.

A note on honesty up front: every link below points either to a real on-chain
transaction or to code in this repository. Where a capability is proven only by
a small proof run — not by an external security audit — this page says so
explicitly. Read those caveats before moving real value.

## Trustless cross-chain atomic swaps

The headline. `pyrxd.gravity` implements **HTLC** (hash-time-locked contract)
atomic swaps between Radiant and other chains. The mechanism, in one breath:
both sides lock their asset to the same hash; revealing the secret preimage to
claim one side mathematically reveals it to claim the other; if nobody claims,
a **timelock** lets each party refund. There is no middleman and no custodian —
the swap either completes for both parties or unwinds for both. That is what
"atomic" means.

### Proven swap directions

Each row below is a real swap that was carried out end-to-end on real chains
this week. Open any transaction in its explorer.

| Direction | Networks | Proof (claim transactions) |
|---|---|---|
| **BTC ↔ RXD** | Bitcoin **mainnet** ↔ Radiant **mainnet** (real value, both sides) | BTC claim: [`0e2ba620…f6e3`](https://mempool.space/tx/0e2ba620073b5bd08ddfa6d418912eff7705eaab947afdbe56040a833e8ef6e3) · RXD claim: [`d9f8dee9…f67db`](https://radiantexplorer.com/tx/d9f8dee91ba7a1f874b4003e44898beddc4fac00ea670920990ed4589a8f67db) |
| **ETH ↔ RXD** | Ethereum **Sepolia testnet** ↔ Radiant **mainnet** | ETH claim (Sepolia): [`0x30d06fe7…961e`](https://sepolia.etherscan.io/tx/0x30d06fe783054c98f25b4cb010e83e9b2d66ae22c069b4f9be802e24a0b2961e) · RXD claim: [`3704227c…26c8`](https://radiantexplorer.com/tx/3704227cadcc3b4cf9ee1cd6ceb62219a9a1cc9a5cce9b7cb52bc709c91e26c8) |
| **Glyph NFT ↔ ETH** | NFT on Radiant **mainnet** ↔ Ethereum **Sepolia testnet** | NFT minted: [`04123935…d3ae`](https://radiantexplorer.com/tx/0412393546ea3bbaa96a5040a0cb4f086d2c1faa5c8e3375e658e60b3fdbd3ae) · NFT claimed: [`b717f9a5…1367`](https://radiantexplorer.com/tx/b717f9a5f8d085c92479331a0dddfa290dd43d42d37c398508db204dbd851367) · ETH HTLC ([`0x25Aa6302…0BFd`](https://sepolia.etherscan.io/address/0x25Aa6302FfFc35ED87827f1052f4ce8f44810BFd)) claim: [`0x0bad6831…fbc0`](https://sepolia.etherscan.io/tx/0x0bad68311ad4433edda16550def29f1c05e975cf66fbaf4b3ac8f117f2f6fbc0) |
| **Glyph FT ↔ ETH** | FT on Radiant **mainnet** ↔ Ethereum **Sepolia testnet** | FT minted: [`e36c5503…ced23`](https://radiantexplorer.com/tx/e36c5503e4d4398ce1ed762e94d9f021c0f64901f008135f31d33e10d49ced23) · FT claimed: [`db97f0d1…9b51`](https://radiantexplorer.com/tx/db97f0d1bd6e8d7eb03e4d6e36e49ff378852552455fb3d942b5d493ff929b51) · ETH HTLC ([`0x5a2D2084…EAF0`](https://sepolia.etherscan.io/address/0x5a2D2084f19F85A676fa6872069760aA0e54EAF0)) claim: [`0x67a338bd…295ad`](https://sepolia.etherscan.io/tx/0x67a338bd4ba53eb2fa307626eb86ac14bbc6910e9b5a7e31317d8c2194f295ad) |

**Network labels are exact.** BTC and RXD legs were on **mainnet** with real
value. **Every ETH leg was on the Ethereum Sepolia testnet — not Ethereum
mainnet.**

> **Pre-audit caveat — read this.** These were small "dust" / proof runs whose
> only purpose was to demonstrate the mechanism on real chains. **They are not a
> security proof and this is not production-ready.** A single-operator proof run
> shows the plumbing works; it does not exercise an adversarial untrusted
> counterparty, and an external security audit is the hard gate before moving
> real value with someone you don't trust. Treat the cross-chain swap code as
> pre-audit.

### Build it

- **[How-to: build a cross-chain atomic swap](how-to/build-a-cross-chain-swap.md)** —
  the `SwapCoordinator` + legs surface (`from pyrxd import SwapCoordinator, …`), the
  role/timelock safety invariant, and the proven regtest/Anvil harnesses to copy from.
- [`examples/gravity_swap_demo.py`](../examples/gravity_swap_demo.py) — the full
  Gravity swap flow (offer → claim → payment → finalize). Defaults to a safe
  dry-run that builds every transaction but broadcasts nothing.
- Concept walkthrough: [`docs/concepts/gravity.md`](concepts/gravity.md).

## Native tokens

Radiant carries tokens natively via the **Glyph** protocol. `pyrxd` builds all
of them — and the NFT/FT mints above are themselves on-chain proof that the mint
path works on mainnet.

- **NFTs** — [`examples/glyph_mint_demo.py`](../examples/glyph_mint_demo.py):
  a two-phase commit/reveal NFT mint on Radiant mainnet.
  Tutorial: [`docs/tutorials/mint-a-glyph-nft.md`](tutorials/mint-a-glyph-nft.md).
- **Fungible tokens** — [`examples/ft_deploy_premine.py`](../examples/ft_deploy_premine.py):
  issue your own FT with a full premine; the reveal output's outpoint becomes
  the permanent token ref.
  Tutorial: [`docs/tutorials/mint-a-glyph-ft.md`](tutorials/mint-a-glyph-ft.md).
- **dMint (permissionless mining-based issuance)** —
  [`examples/dmint_v1_deploy_demo.py`](../examples/dmint_v1_deploy_demo.py):
  deploy a V1 dMint token that emits N parallel contract UTXOs, each mineable
  independently so claims race in parallel.
  Concept: [`docs/concepts/dmint-v1-deploy.md`](concepts/dmint-v1-deploy.md).

New to all this? The fastest way to mint a real token with zero risk is the
local-regtest quickstart: [`docs/tutorials/quickstart.md`](tutorials/quickstart.md)
(stand up a private chain in Docker, mint, tear it down).

## Same-chain swaps

For trading two assets that both live on Radiant — RXD ↔ token, or token ↔
token — `pyrxd.swap` gives you a guard-railed **partial-transaction** API. It
uses signature-level atomicity (`SIGHASH_SINGLE | ANYONECANPAY`): the maker
signs one input committing to one output of what they want back, the taker adds
their own inputs/outputs to complete the trade, and the whole thing settles in a
**single** transaction — no escrow, no covenant, no second transaction. Because
both legs are in one transaction, it confirms wholly or not at all.

The core `create_offer` / `accept_offer` flow is **pure Python and needs no
node** — you can build and verify an offer entirely offline and only touch the
network to broadcast.

- [`examples/partial_swap_demo.py`](../examples/partial_swap_demo.py) — the full
  offer → transport → accept → verify flow, self-contained and runnable with no
  node and no network.
- Concept: [`docs/concepts/partial-tx-swaps.md`](concepts/partial-tx-swaps.md).

This same-chain swap API is implemented and unit-tested (including adversarial
cases); as with every value-moving primitive here, treat an external audit as
the gate before real-value, untrusted-counterparty use.

## Start building

1. **5-minute quickstart** — [`docs/tutorials/quickstart.md`](tutorials/quickstart.md):
   `pip install pyrxd`, bring up a local regtest chain in Docker, and mint your
   first real on-chain Glyph token — no faucet, no mainnet RXD, nothing at risk.
2. **Browse the runnable examples** — the [`examples/` index](../examples/README.md)
   gives a guided path through end-to-end scripts for every flow above, each
   labeled with its network and whether it defaults to a safe dry-run.
3. **Read the concepts** — [`docs/concepts/index.md`](concepts/index.md) covers
   Glyph structures, Gravity, dMint, and partial-tx swaps in depth.
