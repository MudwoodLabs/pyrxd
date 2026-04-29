# Gravity: cross-chain atomic swaps

**Audience:** developers integrating cross-chain BTC↔RXD swaps via
`pyrxd.gravity`, and anyone who's seen the phrase "sentinel-artifact
path mainnet-proven" and wondered what it actually means.

**Status:** sentinel-path swaps proven on mainnet. Other covenant
variants are experimental and not yet validated for real funds.

## What Gravity is

Gravity is a cross-chain atomic swap protocol. It lets two parties
trade RXD on Radiant for BTC on Bitcoin (or vice versa) without a
centralized exchange, without trusting each other, and without one
party being able to run off with the other's coins.

Mechanics in plain terms:

1. Alice has RXD, wants BTC. Bob has BTC, wants RXD.
2. Alice locks her RXD into a special on-chain contract on Radiant
   (a "covenant" — see below).
3. The covenant releases Alice's RXD to Bob **only when Bob proves on
   the Radiant chain that he has paid the agreed BTC** to Alice's
   address on Bitcoin. The proof is an SPV (Simplified Payment
   Verification) proof: a block header chain plus a Merkle proof of
   inclusion.
4. If Bob never delivers the BTC, Alice can reclaim her RXD after a
   timeout via the covenant's `forfeit` path.
5. No exchange. No custody. No KYC. The chain itself is the escrow.

The conceptual lineage runs through Bitcoin's HTLCs (Lightning), the
Decred / Litecoin atomic swap work, and SPV-anchored DeFi
constructions on Bitcoin Cash. Gravity is the Radiant-specific
expression of that pattern.

## What a covenant is

A **covenant** is a transaction-output script that constrains *not
just who can spend it, but how the spender can re-spend it.* A
standard P2PKH output says "whoever has this private key can
spend." A covenant says something stronger like:

> "Whoever spends this must send exactly N coins to address X, AND
> attach a valid SPV proof of payment Y to BTC address Z, AND wait
> for at least T confirmations on the source chain."

The covenant is enforced by the Radiant validators when the spending
transaction is checked. No off-chain enforcer is needed. If the spend
doesn't satisfy every clause, the network rejects it and the funds
stay locked.

Gravity is built on covenants because cross-chain swaps need this
level of script-level enforcement. Without it, either party could
walk away with both legs.

## Why there are multiple covenant variants in pyrxd

Look in `pyrxd/gravity/artifacts/` and you'll see eight covenant
artifact files plus a `maker_offer.artifact.json` helper:

| Artifact | Status |
|---|---|
| `maker_covenant_flat_12x20_sentinel_all.artifact.json` | ✅ mainnet-proven |
| `maker_covenant_flat_12x10_11_12_13_14_p2wpkh.artifact.json` | ⚠️ experimental |
| `maker_covenant_flat_6x10_11_12_13_14_p2wpkh.artifact.json` | ⚠️ experimental |
| `maker_covenant_flat_6x13_p2wpkh.artifact.json` | ⚠️ experimental |
| `maker_covenant_unified_p2wpkh.artifact.json` | ⚠️ superseded |
| `maker_covenant_trade.artifact.json` | ⚠️ experimental |
| `maker_covenant_6x12_p2wpkh.artifact.json` | ❌ banned (pre-audit) |
| `maker_covenant_flat_6x12_p2wpkh.artifact.json` | ❌ banned (pre-audit) |

These aren't different *features*. They are an **iteration trail of
attempted designs** — each is a different shape for the same "Maker
locks RXD, accepts BTC payment proof, releases" covenant.

They differ along three real axes.

### Axis 1: Merkle-proof depth handling

A Bitcoin block's Merkle tree depth depends on how many transactions
are in that block. A block with ~4,000 txs has Merkle depth 12. A
quiet block with 500 txs has depth 9. A busy block with 16,000+ txs
might be depth 14 or higher.

The Gravity covenant has to verify "this BTC tx is included in this
block" by walking the Merkle proof. Each variant handles depth
differently:

| Variant | Depth handling |
|---|---|
| `flat_6x12` (banned) | Fixed depth-12 only |
| `flat_6x13` | Fixed depth-13 |
| `flat_12x10_11_12_13_14` | Branched: selectable from 10/11/12/13/14 |
| `unified` | Fixed depth-20 |
| `flat_12x20_sentinel_all` ✅ | Variable: depth-12 (or any 12–20) padded to depth-20 with sentinel bytes |

**Why this matters concretely:** the first attempted real swap used
the `unified_p2wpkh` artifact, which was compiled at fixed depth-20.
The actual BTC payment landed in a block with Merkle depth 12. The
covenant tried to read the proof at the byte offset for a depth-20
proof, hit `OP_SPLIT range`, and the spend was rejected by the
network. Funds locked. (That trade was eventually unlocked via the
`forfeit` path — by design, the maker can always reclaim after
timeout.)

The **sentinel** variant fixes this by accepting depth-12 proofs
padded with placeholder bytes ("sentinels") up to depth-20. The
script recognizes the sentinels and validates accordingly. Any block
depth from 12 through 20 now works with one covenant.

### Axis 2: Bitcoin output type

The `_p2wpkh` variants only accept payment to native-segwit BTC
addresses (the `bc1q...` ones). A complete Gravity rollout would
also support:

| Output type | Address prefix | Status |
|---|---|---|
| **P2WPKH** (native segwit) | `bc1q...` | ✅ shipped |
| **P2PKH** (legacy) | `1...` | ❌ no covenant compiled yet |
| **P2SH** (wrapped segwit) | `3...` | ❌ no covenant compiled yet |
| **P2TR** (taproot) | `bc1p...` | ❌ no covenant compiled yet |

The SDK's API in `pyrxd/gravity/covenant.py` already declares
``_VALID_BTC_RECEIVE_TYPES = {"p2pkh": 0, "p2wpkh": 1, "p2sh": 2,
"p2tr": 3}`` — but only `p2wpkh` has a deployable covenant in the
artifacts directory. If a maker wants to receive BTC at a taproot
address, the SDK currently has no covenant to use.

This is one of the main directions covenant work needs to go: extend
the audited+sentinel pattern to the other three output types.

### Axis 3: Security upgrades over time

Gravity has been through several security audits during development.
The `pyrxd/gravity/covenant.py` deny-list captures the audit trail:

```
"MakerOfferSimple": "skips Taker signature on claim — audit 04 S3 (grief vector)"
"MakerClaimedStub": "finalize() has no SPV check — any party could drain the UTXO"
"MakerCovenant6x12": "pre-Phase-4 covenant — no nBits bound, no structural constraint"
"MakerCovenantFlat6x12": "pre-Phase-4 covenant — no nBits bound, no structural constraint"
```

The SDK refuses to load these unless the caller passes
`allow_legacy=True`, which emits a loud warning that the artifact is
unsafe for production. They're kept on disk as part of the dev
history but cannot be accidentally used.

The flat-depth-branched variants (`flat_*_10_11_12_13_14_*`) are
**post-audit alternative approaches** — they avoid the sentinel-padding
trick by branching internally on the actual Merkle depth. They're
sound in theory but haven't been validated on mainnet, so they remain
experimental until they have.

## What the SDK actually supports today

If you call `pyrxd.gravity` with the defaults (which point at
`maker_covenant_flat_12x20_sentinel_all`), you get:

- **Maker side:** lock RXD into the covenant, set deadline, accept
  the trade
- **Taker side:** pay BTC to a native-segwit (`bc1q...`) address
- **Settlement:** SPV-proven on Radiant; works for BTC blocks of
  Merkle depth 12–20
- **Fallback:** if no settlement, maker can `forfeit` after deadline
  to reclaim the RXD; cancel-tx primitive also implemented

That single shape covers the majority of Bitcoin wallets in active
use today (Sparrow, Electrum, Phoenix, BlueWallet, modern hardware
wallets — all default to native segwit).

## What's coming (no promised dates)

The clearly-needed work for a fuller Gravity in future minor
versions:

1. **Audit + ship the depth-branched variants.** Smaller covenants
   mean lower fees on each spend; might be useful for high-frequency
   makers.
2. **Compile P2PKH / P2SH / P2TR variants.** Each new output type is
   a separate sentinel-style covenant; the pattern carries over.
3. **Independent security audit of the entire Gravity surface.**
   Self-audit found and fixed the issues in the deny-list above; an
   external audit is the next step before any Gravity claims should
   be considered production-grade beyond the proven path.

If you have a use case that needs one of the un-shipped pieces, open
an issue at https://github.com/MudwoodLabs/pyrxd/issues so it can be
prioritized.

## How to use Gravity safely today

- **Stick to the default** (`maker_covenant_flat_12x20_sentinel_all`).
  Don't pass `allow_legacy=True` unless you know exactly what you
  are doing and you control both sides of the trade.
- **Verify the artifact** the SDK is using by inspecting
  `GravityMakerSession`'s configured covenant before signing
  anything irreversible.
- **Respect the deadline mechanics.** The covenant assumes both
  parties have synchronized clocks within reasonable bounds. Don't
  cut deadlines too close or honest counterparties will be unable to
  finalize before forfeit becomes available.
- **Use small amounts first.** Even with a mainnet-proven path,
  pre-1.0 software warrants the same caution as any other covenant
  protocol on a young chain.
- **Don't treat experimental variants as fallbacks.** If the proven
  path doesn't fit your use case (e.g. you need taproot support),
  the right move is to *wait* for that variant to be hardened, not
  to use the un-validated one.

## Further reading

- [`pyrxd/gravity/covenant.py`](https://github.com/MudwoodLabs/pyrxd/blob/main/src/pyrxd/gravity/covenant.py)
  — covenant artifact loader, deny-list, validation
- [`pyrxd/gravity/transactions.py`](https://github.com/MudwoodLabs/pyrxd/blob/main/src/pyrxd/gravity/transactions.py)
  — finalize / forfeit / cancel transaction builders
- [`pyrxd/spv/`](https://github.com/MudwoodLabs/pyrxd/tree/main/src/pyrxd/spv)
  — SPV proof construction and verification
- [`examples/gravity_swap_demo.py`](https://github.com/MudwoodLabs/pyrxd/blob/main/examples/gravity_swap_demo.py)
  — runnable end-to-end demo
- [`examples/gravity_full_trade.py`](https://github.com/MudwoodLabs/pyrxd/blob/main/examples/gravity_full_trade.py)
  — full live-network trade walkthrough
