---
title: "Folding WAVE updates — omission means UNCHANGED, because deletion is not representable"
status: decided
date: 2026-09-09
category: design-decisions
related_files:
  - src/pyrxd/glyph/payload.py (decode_update_payload)
  - src/pyrxd/glyph/inspector.py (classify_glyph_scriptsig)
  - src/pyrxd/glyph/wave.py (WaveAttrs)
  - tests/fixtures/wave_update_chain_mainnet.json
---

## The question

A mutable Glyph is changed by publishing a second `gly` envelope carrying **only the mutated
fields**. To answer "what did this name point at at block N" (HashMark §7.6 form 2, #598), pyrxd
must fold a sequence of those partial envelopes onto the mint state. Two readings were live:

- **(a) replay-merge** — fold every update in order, shallow-merging `attrs`. Omission leaves a
  field alone.
- **(b) latest-as-snapshot** — the newest envelope's `attrs` replaces the record wholesale.
  Omission clears a field.

They are not academic: **they disagree on 3 of the 7 real update chains on mainnet.**

## Decision

**(a) replay-merge, shallow, `attrs` only, ordered by the spend chain.** An update that omits a
field leaves that field unchanged.

## Why — the argument that settles it

`filterAttrs` in Photonic's `packages/lib/src/token.ts` keeps only `string | number | boolean`
under 100 chars. `null` and `undefined` are dropped before anything is merged, so **there is no
representable way to delete an attr.**

That forecloses (b). If omission meant *clear*, then:

- a writer changing one field would have to re-state every other field, and forgetting one would
  silently destroy it; and
- there would still be no way to delete a field **on purpose**, since `null` is filtered out.

So under (b) a field can be destroyed only by accident and never deliberately. That is not a
protocol anyone designs. Under (a), omission means *unchanged* — the safe default — and deletion is
simply not expressible, which is a coherent (if limited) design.

Photonic's own writer agrees in spirit: `waveTarget.ts` re-asserts the current expiry on every
target update *"so a target update doesn't drop the expires attr from the latest on-chain state"* —
i.e. its authors treat dropping a field as an accident to be prevented, not a way to clear it.

## What the reference implementation actually does, and why we could not just copy it

Read from Photonic-Wallet `upstream/main` and verified directly:

- **`packages/lib/src/wave.ts` contains no update logic at all.**
- The semantics live in `packages/app/src/electrum/worker/NFT.ts` (`reconcileRefTrackedNfts`):
  `attrs: { ...g.attrs, ...attrs }` — a shallow merge, `attrs` only.
- It reads **only the latest** mod envelope. Intermediate mods are never read.
- Ordering is delegated to the indexer: `const current = refResult[refResult.length - 1]`.
- The merge site is **untested** upstream.

The consequence that matters: **Photonic's answer is observer-dependent.** Its stored row is
path-dependent accumulation — a wallet that watched every update has merged each one; a wallet
restored from seed computes only *mint ⊕ latest*. Two Photonic wallets can therefore disagree about
the same name. There is no single "reference answer" to copy, so pyrxd has to pick a deterministic
rule and say so.

## Measured: what the choice actually changes

Seven real mainnet chains, decoded through pyrxd's own reader.

| name | replay-merge `expires` | latest-snapshot `expires` | |
|---|---|---|---|
| `create.rxd` | 1851078556 | 1851078556 | same |
| `first-of-the-free.rxd` | 1850756228 | 1850756228 | same |
| `custodian-gate-x7f3.rxd` | 1850743929 | 1850743929 | same |
| `ars.rxd` | 1849096950 | 1849096950 | same |
| `xxl.rxd` | 1849006310 | **absent** | **DIFFER** |
| `vodica.rxd` | 1848488727 | **absent** | **DIFFER** |
| `arsen444354.rxd` | 1848488677 | **absent** | **DIFFER** |

Two facts worth keeping:

1. **The disagreement is confined to `expires`.** `target` — the field form 2 actually needs — is
   identical under both rules on every observed chain. The rule matters for completeness, not for
   the answer form 2 gives today.
2. **Replay-merge agrees with *mint ⊕ latest* on 7 of 7 chains.** So the deterministic rule chosen
   here matches what a freshly restored Photonic wallet computes, everywhere we can observe. It
   diverges only in being defined for cases Photonic leaves to wallet history.

## Consequences and limits

- **`attrs` only, one level, shallow.** Photonic never re-derives top-level mod fields from chain;
  applying them would invent state the reference never computes. All 22 observed update envelopes
  carry `attrs` and nothing else — a top-level field is therefore unexpected, and should be
  **reported**, not folded silently.
- **Ordering comes from the spend chain, not from height.** `ars.rxd` has two update envelopes at
  the same height (453133), so height cannot order a chain. This is stricter than Photonic, which
  takes the indexer's array order.
- **`expires` is carried, never consumed.** Photonic's own source calls it *"display-level"* and
  says the indexer decides renewals from treasury payments this fold never sees. So the fold must
  not present it as an expiry, and "was this name expired at block N" stays **unanswerable** from
  envelopes alone. An AST scan pins that no shipped code reads it.
- **Deletion is unavailable.** If the protocol ever needs it, it needs a representable tombstone
  first; until then a folded record can only grow keys.

## Two constraints found while building the fixture

Both would have produced a fold that looks right and is not.

**1. The two readers disagree on value TYPE.** `GlyphMetadata.attrs` is declared `dict[str, str]`,
so the mint reader stringifies every value; `decode_update_payload` returns raw CBOR and keeps
native types. Measured on `xxl.rxd`:

```
MINT   via GlyphMetadata.attrs:      expires='1849006310'   (str)
UPDATE via decode_update_payload:    expires absent; target='1PwiHEA…'
```

Merge those naively and a field's type depends on which envelope last wrote it — `expires` is a
`str` when only the mint set it and an `int` when an update did. In Python 3 comparing a `str` to
an `int` raises, so a consumer doing `attrs["expires"] > now` would work or crash depending on the
name's update history. **The fold must normalise, or read the mint from raw CBOR rather than
through `GlyphMetadata`.**

**2. A WAVE mint's own target is not in the inspect result at all.** `_classify_raw_tx`'s `metadata`
dict carries `classification`, `name`, `ticker`, `description`, `decimals`, `protocol`,
`input_index` — and no `attrs`. Measured: for `xxl.rxd`'s mint the tool reports
`classification: wave`, `name: xxl.rxd`, and the target `162AELcX…` appears nowhere in the JSON, in
the human output, or anywhere in the result.

So the tool classifies a token as a WAVE name and then omits the one field that makes it a name.
That is the shape #556 fixed for TIMELOCK — "classify a token as TIMELOCK and then discard the only
field that says when it unlocks" — and it is why the fold reads envelopes directly rather than
through the inspect path. Tracked separately; it is not the fold's problem to solve, but the fold
cannot be built on that surface.

## Status of the code

**The decision is the deliverable; the fold is not written yet.** It has no production caller until
the chain walker (#598 Phase 1) exists to supply an ordered sequence, and a capability whose only
references are its definition and its tests is not finished. The fold lands with that walker, and
the three DIFFER rows above are its acceptance fixture — a case where the rejected rule gives a
different answer is what makes the test able to express the decision.
