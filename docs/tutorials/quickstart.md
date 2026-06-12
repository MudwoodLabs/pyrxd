# 5-minute quickstart: your first token on a local chain

The fastest path from `pip install pyrxd` to a real, on-chain Glyph token —
minted on a private **regtest** chain that runs entirely on your machine. No
testnet faucet, no mainnet RXD, no money at risk. When you're done you tear the
whole chain down with one command.

This is the recommended starting point for new contributors. It exercises the
real SDK and the real node consensus rules — the only thing that isn't "real"
is that the chain is yours alone and disposable.

## What you'll need

- **Docker** — the regtest node runs in a container.
- **pyrxd installed** — `pip install pyrxd`, or `poetry install` from a checkout.

That's it. The regtest node image is built for you in Step 0 — there's no image
to find or pull. Everything below is regtest-only and reached over `docker exec`;
the node binds to localhost and is never exposed.

## Step 0 — build the regtest node image (one time)

```console
$ pyrxd regtest setup
building radiant-core:v3.1.1-amd64 from the official Radiant-Core v3.1.1 release…
(first build pulls ubuntu:22.04 + the release binary; subsequent builds are cached)
built radiant-core:v3.1.1-amd64
next: pyrxd regtest up
```

`setup` fetches the **official** Radiant-Core release daemon, verifies its SHA-256
against the release checksum file, and wraps it in a small local image. It's a
one-time step (the build is cached afterwards). To track a newer release later,
`pyrxd regtest setup --version vX.Y.Z`.

## Step 1 — stand up a local chain

```console
$ pyrxd regtest up
regtest node up
  container: pyrxd-devnet  (image radiant-core:v3.1.1-amd64)
  height:    101
  rpc:       user=pyrxd password=pyrxd wallet=devnet

pre-funded dev key (import with PrivateKey(wif)):
  address: mxeCaRUMTjAmRch131Tt5Hac4ZWvaQomJP
  wif:     cVZMZLBJ8RMrZrEoeST9Be4bBxiFtcMA2UaPaZH1WdHd9UL5WVc1
  funded:  100 RXD

next:
  pyrxd regtest mine 1            # advance the chain
  pyrxd regtest fund <address> 50 # faucet 50 RXD to any address
  pyrxd regtest down              # tear it all down
```

`up` starts the node, mines 101 blocks to mature a coinbase (so there's
spendable RXD), creates a dev wallet, and hands you a **pre-funded key**. The
printed WIF imports straight into the SDK — `PrivateKey(wif)` derives that exact
regtest address.

`up` is idempotent: run it again and it reports the running node rather than
wiping it. Use `pyrxd regtest up --fresh` when you want a clean chain.

## Step 2 — mint a Glyph NFT

The repo ships a companion script that mints an NFT against the running node.
It pulls a funded UTXO from the dev wallet, builds the two-phase commit/reveal
with `GlyphBuilder`, broadcasts each transaction through the
node, and mines a block to confirm each one:

```console
$ python examples/regtest_quickstart.py
minting from mxeCaRUMTjAmRch131Tt5Hac4ZWvaQomJP  (UTXO 15bd14177471…:0, 5,000,000,000,000 photons)
commit:  c10108ef496cac1f75fa9ccab4ce112bee0d6539f27c9f7edcc7a7c8a7572f33  (7,160,546 photons, confirmed)
reveal:  94ac6d18113d48f5166f4629091015c872e954814963a92fec0f92b27178095a  (NFT output 3,454,046 photons, confirmed)

NFT minted on regtest.
  genesis ref: c10108ef496cac1f75fa9ccab4ce112bee0d6539f27c9f7edcc7a7c8a7572f33:0   <- this is the token's permanent identity
  owner:       mxeCaRUMTjAmRch131Tt5Hac4ZWvaQomJP
```

Your txids will differ — they're real transactions on your chain. A Glyph token
is minted in two transactions: a **commit** that locks a hash of the metadata,
then a **reveal** that publishes the metadata and creates the token output. The
token's permanent identity is its **genesis ref** — the commit `txid:vout`.

The transaction-building in `regtest_quickstart.py` is the same logic as
[`examples/glyph_mint_demo.py`](https://github.com/MudwoodLabs/pyrxd/tree/main/examples/glyph_mint_demo.py),
which mints on mainnet via ElectrumX — only the transport is swapped to the
local node.

## Step 3 — look at what you minted

The reveal output is a genuine NFT: its locking script carries
`OP_PUSHINPUTREFSINGLETON` (the singleton ref that makes it one-of-one), and the
reveal's input carries the `gly` envelope with your metadata. Decode it on the
node:

```console
$ docker exec pyrxd-devnet radiant-cli -regtest -rpcuser=pyrxd -rpcpassword=pyrxd \
    getrawtransaction <reveal-txid> 1
```

Look at `vout[0].scriptPubKey.asm` — it begins with `OP_PUSHINPUTREFSINGLETON`.

You can also mine more blocks or fund any address from the faucet:

```console
$ pyrxd regtest mine 5
mined 5 block(s) — height 108

$ pyrxd regtest fund mvv7uazxVYtz7Y3WfLwKuYxYikNKfJEF8T 25
funded mvv7uazxVYtz7Y3WfLwKuYxYikNKfJEF8T with 25 RXD
  txid: b21d8dafbd6769b3ed58d62e1a163af93f94042879b420605de9c33bb8a53d51
```

## Step 4 — swap two assets (next)

With a token in hand, the natural next step is to trade it. pyrxd has a
same-chain swap API — a maker offers an asset and a taker funds the other side,
with a single signature making the trade atomic (either both legs settle or
neither does). It runs in one process, no node required:

```console
$ python examples/partial_swap_demo.py
```

See [Same-chain partial-transaction swaps](../concepts/partial-tx-swaps.md) for
how the `SIGHASH_SINGLE | ANYONECANPAY` signature enforces the trade, and
[Gravity](../concepts/gravity.md) for the cross-chain (HTLC) swap design.

## Tear it down

```console
$ pyrxd regtest down
regtest node down
```

That removes the container and wipes the chain — nothing is left running.

## Command reference

| Command | What it does |
| --- | --- |
| `pyrxd regtest up` | Start the node, mine 101, print a pre-funded key |
| `pyrxd regtest up --fresh` | Same, but wipe any existing chain first |
| `pyrxd regtest info` | Connection details + current height |
| `pyrxd regtest mine <n>` | Mine `n` blocks (default 1) |
| `pyrxd regtest fund <addr> <rxd>` | Faucet RXD to any address, confirmed in a block |
| `pyrxd regtest down` | Stop and remove the node (wipes the chain) |

## Where to go next

- [Your first Radiant transaction](your-first-radiant-transaction.md) — the
  wallet CLI and a signed RXD send.
- [Mint a Glyph NFT](mint-a-glyph-nft.md) — the same mint flow, explained step
  by step.
- [Mint a Glyph FT](mint-a-glyph-ft.md) — fungible tokens.
