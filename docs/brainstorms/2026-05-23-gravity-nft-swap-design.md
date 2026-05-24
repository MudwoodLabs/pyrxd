---
title: Gravity NFT↔BTC swap — covenant design
date: 2026-05-23
status: design — singleton conservation analyzed from source; designs compared + converged
---

# Gravity NFT↔BTC swap — covenant design

Follow-on to the FT↔BTC swap (proven on mainnet, single-input + any-wallet).
NFTs are a **separate design**, not an FT parameter flip — but the analysis
below shows the NFT case is actually **simpler** than FT.

## Why NFT ≠ FT (from source)

| | FT holder | NFT singleton |
|---|---|---|
| Script | `76a914<pkh>88ac` **`bd`** `d0 <ref> dec0e9aa…` (75B) | **`d8 <ref> 75`** `76a914<pkh>88ac` (63B) |
| Ref opcode | `OP_PUSHINPUTREF` (`0xd0`) | `OP_PUSHINPUTREFSINGLETON` (`0xd8`) |
| `OP_STATESEPARATOR` | yes (`bd`) | **none** |
| Conservation rule | `codeScriptHashValueSum`: FT value must flow to outputs with the **same code-script hash** (`interpreter.cpp` epilogue) | **singleton ref must appear on exactly ONE output**, carried from an input — disallow-siblings (`validation.h` / `script.cpp:601-606`). **No codeScriptHashValueSum.** |
| `codeScriptHash` of holder | bytes after `bd` (prologue excluded) | whole script (no separator ⇒ index 0, `script.cpp:644`) — **but irrelevant**, NFT conservation doesn't use it |

**The load-bearing difference:** FT is welded to its *code-script* (you cannot
hold it in a foreign covenant — that was the whole FT blocker). The NFT is
welded only to its *singleton ref*. So an NFT **can be held directly in a
covenant**, which an FT cannot.

> **CORRECTION (divergent review 2026-05-23, verified against
> `validation.h:919-968`):** an earlier version of this note said consensus
> requires the singleton "to land on **exactly one** output." That is WRONG.
> `validatePushRefRule` only enforces **outputs ⊆ inputs** (a singleton on an
> output must trace to an input), and `validateDisallowedSiblingsRefRule` only
> forbids the ref on a *different*-than-allowed output. **Consensus does NOT
> require the singleton to appear on any output — it permits BURNING the NFT
> (zero output copies), and never welds it to a code-script.** Therefore
> "exactly one output" is enforced **solely by the covenant** (`outputs.length
> == 1` + `refOutputCount(ref) == 1`) — there is no consensus backstop. For an
> irreversible one-of-one this is the dominant security fact: the covenant body
> is the sole guarantor of conservation. See the plan for the full threat-model
> consequences.

## NFT execution → where covenant logic attaches

`d8 <ref>` pushes the ref; `75` (`OP_DROP`) drops it; the trailing
`76a914<pkh>88ac` is the P2PKH spend auth. So the singleton prologue
(`d8 <ref> 75`) is a no-op for authorization; the covenant logic replaces the
trailing P2PKH:

```
d8 <ref> 75 <covenant-logic>
```

The covenant body runs after the ref is dropped. Changing the covenant body
changes the whole-script `codeScriptHash` — **but NFT conservation never reads
`codeScriptHash`**, so that's harmless.

## The two designs converge

- **Lock-into-covenant:** the covenant UTXO carries the singleton (holds the
  NFT) and gates release.
- **Spend-path-gating** (the FT approach): the covenant gates the spend of an
  NFT-shaped UTXO.

For NFT these are the **same construction**: `d8 <ref> 75 <covenant-logic>` both
holds the singleton AND gates the spend. There's no FT-style code-script
constraint forcing a separate holder. **Chosen design: the single converged
form.**

## Chosen covenant shape

Funded UTXO (the NFT held in the swap covenant):
```
d8 <ref> 75 <SPV + hardening + hash-compare covenant logic>
```

Spend paths (reuse the FT covenant's BTC half verbatim):
- **finalize (SPV proof):** verify the BTC payment (anchor + N headers PoW +
  M-depth Merkle + payment to `btcReceiveHash` ≥ `btcSatoshis`, the 4-way
  output-type scan, the any-wallet input parser), then require
  `hash256(tx.outputs[0].lockingBytecode) == EXPECTED_TAKER_NFT_HASH`.
- **forfeit (CLTV):** after the deadline, require
  `hash256(tx.outputs[0].lockingBytecode) == EXPECTED_MAKER_NFT_HASH`.

`EXPECTED_*_NFT_HASH = hash256(build_nft_locking_script(dest_pkh, ref))` — the
standard 63-byte NFT script for the destination. Hash-compare (not embedded
bytes) avoids the phantom-ref hazard exactly as in FT.

### Hardening — DIFFERENT from FT (no amount)

NFT has no amount, so the FT hardening changes:
- `tx.outputs.length == 1` — output-count clamp (KEEP).
- **`tx.outputs.refOutputCount(ref) == 1`** — the singleton on exactly one
  output (KEEP — this IS the NFT conservation, made explicit).
- **DROP `refValueSum(ref) == AMOUNT`** — meaningless for a singleton (value
  is irrelevant; an NFT is identity, not quantity). Replace with nothing, or
  optionally pin the NFT carrier's photon value if a fixed dust is desired.
- The singleton's built-in disallow-siblings already prevents duplication;
  `refOutputCount == 1` + `outputs.length == 1` + hash-compare pin the
  destination.

### Phantom-ref note

The NFT script's leading `d8 <ref>` is the **intended** singleton (offset 0,
36-byte operand — parses correctly). The covenant body must contain no bare
`0xd0`–`0xd8` in opcode position (hash-compare keeps the NFT-script bytes out
of the covenant). The `count_input_refs` guard must show exactly the genesis
singleton ref. **Subtlety vs FT:** the boundary is NOT an `OP_STATESEPARATOR`
(there is none); the guard simply asserts one ref = the genesis singleton.

## Build plan (mirrors the FT pipeline, with the NFT deltas)

1. Generator/fuse: emit `d8 <ref> 75` + the SPV/any-wallet/hardening/hash-compare
   body. The BTC half (SPV verify, 4-way output scan, varint input parser) is
   **reused verbatim** from the FT any-wallet covenant. Deltas: singleton
   prologue instead of P2PKH+`bd d0`+epilogue; hardening drops the amount
   check; expected-hashes are NFT scripts.
2. Compile (`rxdc 0.1.0`); static guards (exactly one singleton ref; no bare
   ref-opcode in the covenant body).
3. On-chain proof: mint a fresh NFT, fund into the covenant, real BTC payment,
   finalize → NFT to taker; forfeit path; negatives (no-payment, duplicate-
   singleton attempt, wrong destination).
4. External audit (hard gate; NFT irreversibility raises the bar).

## Security note (NFT irreversibility)

An NFT is one-of-one — a botched swap can't be made whole by fungible
top-up. So the deadline/forfeit margins and the audit gate matter more than
for FT. Keep the same anchor-just-in-time + wide-N + wide-M operational
lessons. Per-offer derived `btcReceiveHash` (H1 binding) applies unchanged.
