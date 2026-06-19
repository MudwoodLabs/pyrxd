# Gravity: cross-chain atomic swaps

**Audience:** developers integrating cross-chain swaps via
`pyrxd.gravity` between RXD and a SHA-256d UTXO chain (BTC is
mainnet-proven; BCH is supported; see § Supported counterparty
chains for the full picture), and anyone who's seen the phrase
"sentinel-artifact path mainnet-proven" and wondered what it
actually means.

**Status:** Gravity has two cross-chain constructions. The
**SPV-oracle** path (sentinel-artifact covenant) is proven on mainnet
but is **payment-verified, not atomic** — see the honest limitation
below. The **HTLC** path (hashlock + relative-timelock) is the
atomic construction; its full cross-chain flow has been demonstrated
end-to-end on mainnet as a **proof-of-mechanism with test-size funds**.
Like the rest of pyrxd it is open-source, provided as-is under the
[LICENSE](../../LICENSE); the cross-chain swap stack is **unaudited —
verify it yourself before moving real value.**

## What Gravity is

Gravity is a cross-chain swap protocol. It lets two parties trade RXD
on Radiant for BTC on Bitcoin (or vice versa) without a centralized
exchange and without custody. There are two designs, and they differ
in one crucial property — whether the BTC leg has a refund path.

### Path A — SPV-oracle (payment-verified, NOT atomic)

1. Alice has RXD, wants BTC. Bob has BTC, wants RXD.
2. Alice locks her RXD into a covenant on Radiant.
3. The covenant releases Alice's RXD to Bob **only when Bob proves on
   the Radiant chain that he has paid the agreed BTC** to Alice's
   address on Bitcoin. The proof is an SPV (Simplified Payment
   Verification) proof: a block header chain plus a Merkle proof of
   inclusion.
4. If Bob never delivers the BTC, Alice can reclaim her RXD after a
   timeout via the covenant's `forfeit` path.

**Honest limitation (load-bearing):** Bob's BTC payment goes to a
**plain address with no refund path**. The SPV proof is a
one-directional oracle ("did this payment happen?"), so this is
**payment-verified, not atomic**: if Bob's payment is mined late or
Alice set a tight deadline, Bob can lose the BTC *and* get no RXD (the
deadline-race). No Radiant-side change can give Bob recourse, because
the irreversibility is on the Bitcoin side. The SPV machinery is
sound; the *swap built on a plain-address payment* is not atomic.

### Path B — HTLC (atomic)

The BTC goes into a **script-controlled Taproot output** with two
spend paths — claim-with-preimage and refund-after-timeout — and both
legs are bound by **one secret** (`H = sha256(p)`, using Radiant's
Bitcoin-compatible `OP_SHA256`; no adaptor signatures needed). The
asset is released on preimage reveal; each side can refund via a
relative timelock (`tx.age` / CSV on Radiant, CSV on Bitcoin) if the
other never proceeds. **Worst case is "both refund and walk away
whole" — never one-sided loss.** Its cost is a retained-state
obligation: the refunding party (or a watchtower) must keep the
refund key + script and broadcast the refund if the happy path
stalls, and the client must verify the timelock ordering (BTC refund
timeout > Radiant claim deadline) before funding.

The conceptual lineage runs through Bitcoin's HTLCs (Lightning), the
Decred / Litecoin atomic swap work, and SPV-anchored DeFi
constructions on Bitcoin Cash.

## Supported counterparty chains

> **Note — this section is about the SPV-oracle path (Path A).** Chain
> support there is governed by the SPV verifier's PoW check (SHA-256d).
> The **HTLC path (Path B) has a different gate: it requires the
> counterparty chain to support tapscript HTLC outputs (BIP341
> Taproot).** As built, `btc_wallet/taproot.py` always emits a P2TR
> (`bc1p…` bech32m) HTLC output, so the atomic path works on **Bitcoin**
> (Taproot active since 2021) and any BIP341-capable chain — but **not**
> on chains without Taproot (e.g. BCH), which would need a P2SH/P2WSH
> HTLC variant instead. So a chain can be SPV-path-supported yet not
> HTLC-path-supported, and vice versa. (Funding the HTLC and receiving
> claim/refund are *not* Taproot-restricted — any wallet can send to a
> `bc1p` address, and destinations may be P2PKH/P2WPKH/P2SH/P2TR; only
> the HTLC contract output itself is Taproot.)

Gravity's SPV verifier is chain-agnostic for **SHA-256d UTXO chains**
by deliberate design. The verifier checks proof-of-work as
`hash < target` against the header's own nBits — it does not compute
or validate difficulty algorithm transitions. As long as the maker
commits to the right `expected_nbits` at offer time, the verifier
accepts any chain of headers satisfying those nBits.

| Chain | Counterparty role | Status |
|---|---|---|
| **Bitcoin (BTC)** | proven on mainnet | ✅ shipping |
| **Bitcoin Cash (BCH)** | verifier accepts real mainnet headers | ✅ ready; integration tests in `tests/test_spv.py::TestBchMainnetFixtures` |
| **Bitcoin SV (BSV)** | same SHA-256d format | ⚠️ untested; should work with no code changes |
| Other SHA-256d UTXO chains | same SHA-256d format | ⚠️ untested |

What "ready" means for BCH:

- Real BCH mainnet block headers (840000 + 840001) pass the
  unmodified `verify_header_pow` and `verify_chain` (with
  `chain_anchor` binding).
- The shipping `maker_covenant_flat_12x20_sentinel_all` covenant
  supports BCH-style payments (P2PKH is the primary type since BCH
  has no segwit; P2SH is the secondary type for multisig flows).
- The `MempoolSpaceSource` data-source class accepts a configurable
  `base_url`, so a caller can construct
  `MempoolSpaceSource(base_url="https://mempool.cash/api")` or a
  similar BCH-side explorer endpoint without code changes. Live API
  compatibility has not been verified end-to-end.
- BCH cashaddr encoding is wallet-side, not Gravity-side. The maker
  provides raw `hash160` bytes; address-format handling stays at
  the wallet layer.

What's **not** supported, and would require more than a parameter
change:

- **Non-SHA-256d chains** (Litecoin/Dogecoin use Scrypt; Zcash uses
  Equihash; Monero uses RandomX). The SPV verifier's PoW check
  hardcodes SHA-256d. Verifying these chains' PoW on Radiant would
  require new RadiantScript opcodes (a consensus extension) or a
  different cross-chain protocol altogether (such as HTLC + adaptor
  signatures, which doesn't require on-chain PoW verification).

The asymmetric design of Gravity (counterparty chain doesn't need to
know Gravity exists; only Radiant verifies the proof) is preserved
for all supported chains.

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

The older `_p2wpkh`-suffixed covenant variants (visible in the
artifacts directory) only accepted payment to native-segwit BTC
addresses. **The shipping `maker_covenant_flat_12x20_sentinel_all`
covenant unified the dispatch** and accepts all four standard
Bitcoin output types via in-script branching on a `btcReceiveType`
parameter (0=P2PKH, 1=P2WPKH, 2=P2SH, 3=P2TR). The covenant compares
the BTC tx's output script bytes against the type-specific expected
pattern (e.g. `76 a9 14 <hash> 88 ac` for P2PKH, `00 14 <hash>` for
P2WPKH, etc.), with the hash supplied as `btcReceiveHash` and the
type supplied as `btcReceiveType`.

| Output type | Address prefix | Covenant support | End-to-end test |
|---|---|---|---|
| **P2WPKH** (native segwit) | `bc1q...` | ✅ shipped | ✅ mainnet-proven |
| **P2PKH** (legacy) | `1...` | ✅ shipped | ✅ synthetic (`TestGravityTradeP2PKH`) |
| **P2SH** (wrapped segwit) | `3...` | ✅ shipped | ⚠️ unit-level only |
| **P2TR** (taproot) | `bc1p...` | ✅ shipped | ⚠️ unit-level only |

What "covenant support ✅ shipped" means concretely:
- The Python factory in `pyrxd/gravity/covenant.py` substitutes the
  type integer into the covenant template via
  `_VALID_BTC_RECEIVE_TYPES = {"p2pkh": 0, "p2wpkh": 1, "p2sh": 2, "p2tr": 3}`.
- `tests/test_gravity.py::TestGravityOffer::test_all_btc_receive_types_accepted`
  asserts `build_gravity_offer` produces a valid offer for all four
  types.
- The SPV verifier in `pyrxd/spv/payment.py` parses all four output
  script formats; `tests/test_spv.py` exercises each at the unit
  level.

What "end-to-end test ⚠️ unit-level only" means for P2SH and P2TR:
- The covenant artifact, factory, and SPV verifier all handle these
  types correctly at the unit level.
- A full Maker-locks → Taker-pays → finalize integration test using
  the real `SpvProofBuilder.build()` pipeline against a synthetic
  P2SH-paying or P2TR-paying BTC transaction has not yet been
  written. The P2PKH analogue
  (`tests/test_gravity_trade.py::TestGravityTradeP2PKH`) is the
  pattern to copy when adding them.
- A small-amount mainnet exercise against a real P2PKH / P2SH / P2TR
  payment has not yet been performed for these types. Mainnet-proven
  status applies only to P2WPKH today.

### History note: why the docs previously said otherwise

An earlier version of this document claimed only P2WPKH was
supported. That was accurate relative to the older single-type
covenant variants (`maker_covenant_unified_p2wpkh`, the experimental
`flat_*_p2wpkh` lineage) but became stale when the sentinel-all
covenant landed and unified the dispatch. The `_p2wpkh` suffix on
older artifacts is a historical naming artifact, not a current
limitation of the shipping covenant.

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
2. **End-to-end integration tests + mainnet exercise for P2SH / P2TR.**
   The shipping sentinel covenant already supports all four output
   types via in-script dispatch (see Axis 2 above); what's missing is
   integration test coverage and a small-amount mainnet exercise for
   the two output types still marked ⚠️ unit-level only. P2PKH was
   closed out in this category in 2026-05; P2SH and P2TR remain.
3. **Independent security audit of the entire Gravity surface.**
   Self-audit found and fixed the issues in the deny-list above; an
   external review is the natural next step for the swap stack —
   until then it's unaudited, so verify it yourself before real value.

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
