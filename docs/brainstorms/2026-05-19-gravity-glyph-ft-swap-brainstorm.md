---
title: Gravity for Glyph FT/NFT — selling tokens for BTC atomically
date: 2026-05-19
status: brainstorm
---

# Gravity for Glyph FT/NFT — selling tokens for BTC atomically

## TL;DR

Today's Gravity covenant locks **plain RXD** and releases plain RXD on
settlement. To sell tokens (FT) or singletons (NFT) for BTC atomically
you need a **new covenant variant** that carries a Glyph ref through
the lock-and-release dance — the shipped covenant script doesn't carry
a ref, so a Glyph-bearing UTXO can't fund it and a ref can't appear in
the settlement output.

The BTC half of Gravity (SPV verifier, BTC-output-type dispatch,
deadline/forfeit logic) is chain-agnostic and reusable. The Radiant
half is new design work: a covenant script that carries a ref and
constrains where it lands, plus a small fix to the Gravity-specific
sighash helper that hard-codes `totalRefs = 0`. The general-purpose
preimage builder in [transaction_preimage.py](../../src/pyrxd/transaction/transaction_preimage.py)
already handles refs correctly, so this is plumbing not invention.

This is meaningful protocol work — comparable to the original Gravity
spike, though smaller than building Gravity from scratch since the
SPV/BTC machinery already exists. It is **not** a config tweak on an
existing artifact.

## Why the current covenant can't carry a ref

Two blockers — one in the covenant script, one in the Gravity-specific
sighash helper. Both apply equally to FT and NFT.

### Blocker 1: the covenant's locking script doesn't carry a ref

The shipped maker covenant
([artifacts/maker_covenant_flat_12x20_sentinel_all.artifact.json](../../src/pyrxd/gravity/artifacts/maker_covenant_flat_12x20_sentinel_all.artifact.json))
locks a plain UTXO. There's no `OP_PUSHINPUTREF` or
`OP_PUSHINPUTREFSINGLETON` in the covenant script itself. Even if you
tried to fund the covenant with a ref-bearing UTXO, the spend wouldn't
satisfy Radiant's ref-conservation rule (each ref on the input side
must reappear on the output side — sum-preserving for FT, identity for
NFT) because the covenant's settlement output also doesn't carry the
ref.

This is the load-bearing problem. You can't fix it by patching Python
— the covenant **script** has to be rewritten to carry a ref through
the spend and constrain where it lands.

### Blocker 2: the Gravity sighash helper hard-codes `totalRefs = 0`

`_compute_hash_output_hashes` at
[gravity/transactions.py:93-134](../../src/pyrxd/gravity/transactions.py#L93)
hard-codes `totalRefs = 0` and `refsHash = 32 × 0x00` for every output
it processes. That's wrong for an output carrying a ref (where
`totalRefs >= 1` and `refsHash = hash256(sorted refs concatenated)`),
so a spend that produces a ref-bearing output would sign with the
wrong sighash and Radiant validators would reject it.

**The fix is small.** A separate, correct implementation already lives
at
[transaction/transaction_preimage.py:66](../../src/pyrxd/transaction/transaction_preimage.py#L66)
— it parses outputs, walks for `OP_PUSHINPUTREF` opcodes, and computes
the real `refsHash`. The Gravity copy is a stale specialization;
delete it and reuse the general implementation. A comment at
`transaction_preimage.py:109` also wrongly claims ref count is "always
0 for standard P2PKH/FT/NFT outputs" — fix in passing.

## What a ref-bearing Gravity covenant needs to do

Sketch of the asset flow (Maker = seller of token, Taker = BTC payer):

1. Maker has a ref-bearing UTXO: an FT holding `N` units of token `T`,
   or an NFT holding singleton `S`.
2. Maker locks a UTXO into the covenant that:
   - Carries the ref (FT ref + amount `N`, or NFT singleton).
   - Encodes the agreed BTC price, BTC receive address, deadline, and
     Taker pubkey hash, same as today's Gravity.
3. Taker pays BTC to Maker's BTC address.
4. Taker submits a settlement tx on Radiant that:
   - Spends the covenant UTXO.
   - Produces an output carrying the same ref (and amount, for FT) to
     the Taker's Radiant address.
   - Attaches an SPV proof of the BTC payment, same as today.
5. Covenant validates SPV proof + ref-passthrough; spend succeeds; the
   asset is now Taker's.
6. Fallback: if no settlement by deadline, Maker can `forfeit` — the
   covenant releases the ref-bearing UTXO back to Maker.

The novel constraint vs. today's covenant: **the settlement output's
ref payload must match the covenant input's ref payload, and (for FT)
the amount must be preserved.** That's a conservation check inside
covenant script, not just at network-level validation.

## What changes vs. the sentinel covenant

| Surface | Today (plain RXD) | Ref-bearing variant |
|---|---|---|
| Covenant locking script | Plain P2SH-wrapped covenant, no ref | Covenant script carries `OP_PUSHINPUTREF` (FT) or `OP_PUSHINPUTREFSINGLETON` (NFT), with `refKind` dispatch |
| Gravity sighash helper | `totalRefs = 0` hard-coded in `gravity/transactions.py` | Reuse the general implementation in `transaction/transaction_preimage.py` (already handles refs) |
| Settlement output constraint | "Pay `N` RXD to Taker address" | "Pay ref `R` (× amount `A` for FT, singleton for NFT) to Taker address; RXD value = dust" |
| BTC-side dispatch | `btcReceiveType` 4-way (P2PKH/P2WPKH/P2SH/P2TR) | **Reused as-is** |
| SPV proof verification | Sentinel padding for Merkle depth 12–20 | **Reused as-is** |
| Deadline / forfeit | Standard | **Reused as-is**, but forfeit returns the ref-bearing UTXO to Maker |

The right mental model: this is a **fork of the sentinel covenant**
where the BTC-facing and deadline-facing half is unchanged and the
Radiant-facing half is rewritten to handle refs. The Python sighash
work is mostly de-duplication rather than new logic.

## FT and NFT in a unified ref-bearing covenant

FTs use `OP_PUSHINPUTREF` (`0xd0`) and require conservation
(sum-in = sum-out, splittable). NFTs use `OP_PUSHINPUTREFSINGLETON`
(`0xd8`) and are unique (the ref can only exist on one UTXO at a
time). See
[ft.py:3-4](../../src/pyrxd/glyph/ft.py#L3) and
[radiant-fts-are-on-chain.md](../concepts/radiant-fts-are-on-chain.md).

**Decision: build one unified ref-bearing covenant that handles both,
with an in-script `refKind` flag.** Parallels how the sentinel
covenant unified the four BTC output types via `btcReceiveType`.

What `refKind` would gate (subject to spike validation):
- `refKind = 0` (FT) → covenant uses `OP_PUSHINPUTREF` for the ref,
  carries an `amount` parameter, and the settlement clause enforces
  sum-of-input-amounts == sum-of-output-amounts for that ref.
- `refKind = 1` (NFT) → covenant uses `OP_PUSHINPUTREFSINGLETON`,
  no amount parameter (implicitly 1), settlement clause enforces the
  singleton appears on exactly one output.

Rationale:
- One audit cycle covers both asset types.
- End-to-end tests for FT and NFT run against the same artifact,
  catching cross-cutting bugs early.
- The script delta between branches is small: same ref-passthrough
  scaffolding, NFT skips the amount-equality clause.
- The fee penalty for the extra dispatch logic is paid once on the
  covenant funding and once on settlement — a few extra bytes per
  trade, not a structural cost.

The case for splitting into separate variants would be: smaller
scripts, smaller per-trade fees, simpler per-variant audit. None of
those outweigh the duplication cost at this stage, when neither
variant has been on mainnet yet. If fee profiling during the spike
shows the unified covenant is materially heavier than acceptable,
revisit then.

## Trust-minimization properties to preserve

The whole point of Gravity is no-trust, no-custody, no-KYC. The
ref-bearing variant has to preserve every property:

- **Maker can always reclaim after timeout.** Forfeit path must
  return the *original ref-bearing UTXO* (same ref, same amount for
  FT; same singleton for NFT) to Maker — not some other asset, not
  just RXD.
- **Taker cannot claim without paying.** SPV-proof-of-BTC-payment
  remains the only non-forfeit spend path.
- **Network enforces conservation.** For FT: exactly `N` units in,
  exactly `N` units out to Taker — no mint, burn, or split. For NFT:
  the singleton ref appears on exactly one output (the Taker's).
- **No partial fills via covenant.** Partial fills would require a
  split-and-relock primitive; explicitly out of scope for v1. Maker
  can post multiple smaller-lot covenants if partial-fill UX is
  needed.

## Additional work not in the table

The table above partitions the covenant-level changes. A few project-
level items aren't covered there:

- **Ref-aware factory in [covenant.py](../../src/pyrxd/gravity/covenant.py)**
  that takes `(glyph_ref, ref_kind, amount)` alongside the existing
  `(btc_receive_type, btc_receive_hash, deadline, ...)` params.
- **End-to-end tests** exercising lock → BTC payment → SPV → settle,
  one for FT and one for NFT against a synthetic Glyph.
- **Audit pass before any mainnet exercise** — new covenant, full
  audit treatment, no `allow_legacy=True` shortcut.
- **Out of scope for v1:** cancel-tx (cooperative early-exit) — the
  forfeit path covers failure. Multi-ref outputs. Partial fills.

## Alternatives considered

- **Two-leg swap (Gravity BTC→RXD, then OTC RXD→FT).** Not atomic.
  Either side can stiff on leg 2. Only viable for trusted
  counterparties; doesn't fit "sell credits to whoever shows up with
  BTC."
- **Radiant Swap DEX (`swap.*`).** Mentioned in
  [rxindexer.py:8](../../src/pyrxd/network/rxindexer.py#L8) but not
  yet wired up in pyrxd, and trades on Radiant only — does not accept
  BTC. Useful as the eventual FT-for-RXD venue, complementary to
  Gravity not a replacement.

## Open questions

1. **Multi-ref outputs.** Some FT designs and most NFT collections
   can carry multiple refs on one UTXO. The first variant should
   constrain `totalRefs == 1` (single asset per covenant) for
   simplicity; multi-ref is a future extension.

2. **FT change.** If Maker wants to lock 1,000 units but their FT
   UTXO holds 5,000, options are: (a) require Maker to split off
   exactly 1,000 to a fresh UTXO before posting the covenant; (b)
   build a covenant funding tx that produces both a covenant-locked
   output (1,000) and a Maker-change output (4,000). Start with (a)
   — cleaner, no covenant-side complexity. (Does not apply to NFT
   since singletons can't be split.)

3. **Photonic precedent.** Per memory, Photonic is the default
   reference for Glyph/dMint protocol questions. Check whether
   Photonic's TypeScript codebase has done anything analogous
   (ref-bearing covenants, ref-passthrough constraints) before
   committing to a script shape.

4. **Deny-list semantics.** The ref-bearing covenant should carry
   its own deny-list — failure modes are different enough from the
   RXD covenant deny-list in
   [covenant.py](../../src/pyrxd/gravity/covenant.py) that mixing
   them would confuse the audit story.

## Suggested next step

Not "start writing the covenant." The next step is:

1. **Check Photonic** for any prior art on ref-bearing covenants /
   ref-passthrough constraints.
2. **De-duplicate the sighash helper first** — delete
   `gravity/transactions.py`'s `_compute_hash_output_hashes` in favor
   of the general one in `transaction/transaction_preimage.py`, fix
   the stale ref-count comment there, and confirm existing Gravity
   tests still pass. The script spike below needs a working signer
   for ref-bearing outputs; this is the prerequisite.
3. **Spike the Radiant-side script** — write a candidate covenant
   template (no BTC half yet), verify on regtest that it can:
   (a) lock a ref-bearing UTXO (FT and NFT), (b) release it to a
   target address on a single-clause spend, (c) be reclaimed via a
   timeout path.
4. **Only then bolt on the BTC half** — splice the SPV proof and
   `btcReceiveType` dispatch in from the sentinel covenant.

The risk surface is overwhelmingly on the Radiant ref-handling side;
the BTC side is solved. Sequencing the spike that way puts the
unknown work first, where it belongs.
