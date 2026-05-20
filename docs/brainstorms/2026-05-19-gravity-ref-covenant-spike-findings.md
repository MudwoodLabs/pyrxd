---
title: Gravity ref-bearing covenant — spike-first findings revise the estimate
date: 2026-05-19
status: brainstorm
---

# Gravity ref-bearing covenant — spike-first findings

## Why this spike

The plan
[2026-05-19-feat-gravity-ref-bearing-covenant-plan.md](../plans/2026-05-19-feat-gravity-ref-bearing-covenant-plan.md)
carried a 9–12 week estimate, much of it derived from the brainstorm's
reading of the *intent* of `gravity/transactions.py` rather than from
reading the actual shipping covenant script. Per
[spike-first-then-convergent-design-divergent-review-panels.md](../solutions/design-decisions/spike-first-then-convergent-design-divergent-review-panels.md),
doc/inference-derived estimates in this codebase have run 3–4× high
three times in a row because the code generalized past its docs. This
spike reads the current code before trusting the number.

**This is read-only findings.** No code written; no estimate is
"approved" — it is revised against what the code actually does.

## What the code actually does

### Finding 1: the settlement output is built compositionally, via introspection — not value-only

The sentinel covenant
(`maker_covenant_flat_12x20_sentinel_all.artifact.json`, contract
`MakerCovenantFlat12x20`) constrains the settlement output like this
(from the artifact `asm`, finalize branch tail):

```
76a914 $takerRadiantPkh OP_CAT 88ac OP_CAT
OP_0 OP_OUTPUTBYTECODE OP_EQUALVERIFY
OP_0 OP_OUTPUTVALUE $totalPhotonsInOutput OP_GREATERTHANOREQUAL OP_VERIFY
```

It **builds the expected output scriptPubKey byte-by-byte with
`OP_CAT`** (`76a914` + taker PKH + `88ac` = a plain P2PKH), then
asserts that output 0's actual bytecode equals it via
`OP_OUTPUTBYTECODE OP_EQUALVERIFY`, and that output 0's value clears
`totalPhotonsInOutput` via `OP_OUTPUTVALUE`.

The `asm` uses `OP_CAT` **260 times** and `OP_HASH256` 53 times — this
is already a covenant that assembles scripts and hashes
compositionally. It is **not** a value-only covenant that would need
new machinery to describe a ref-bearing output.

**Implication:** adding a ref to the settlement output is *additive*
work in an existing pattern — CAT the FT/NFT epilogue into the
expected-output construction — not a from-scratch output-description
system. The brainstorm's framing ("the covenant script has no way to
carry a ref") was directionally true (the bytes aren't there today)
but over-stated the *difficulty* (the construction mechanism is).

### Finding 2: the FT/NFT epilogues are small, fixed, and already built in Python

[glyph/script.py:build_ft_locking_script](../../src/pyrxd/glyph/script.py#L135):

```python
p2pkh = b"\x76\xa9\x14" + owner_pkh + b"\x88\xac"          # 25 bytes
epilogue = b"\xbd\xd0" + ref.to_bytes() + b"\xde\xc0\xe9\xaa\x76\xe3\x78\xe4\xa2\x69\xe6\x9d"
# = OP_STATESEPARATOR OP_PUSHINPUTREF <36-byte ref> <12-byte FT fingerprint>
# total script = 75 bytes
```

So the FT settlement output the covenant must assert is just the
existing P2PKH construction (`76a914 <takerPkh> 88ac`) **plus a
fixed 50-byte epilogue** where only the 36-byte ref is a parameter.
`build_nft_locking_script` exists too (63-byte singleton). The covenant
change is: CAT `bd d0 <glyph_ref> dec0e9aa76e378e4a269e69d` after the
P2PKH for the FT artifact (and the singleton variant for NFT).

### Finding 3: ref-parsing is shipped and tested — not new work

`_get_push_refs` ([transaction_preimage.py:18](../../src/pyrxd/transaction/transaction_preimage.py#L18))
already parses both `OP_PUSHINPUTREF` (`0xd0`) and
`OP_PUSHINPUTREFSINGLETON` (`0xd8`), and is tested at
[tests/test_preimage.py:34-79](../../tests/test_preimage.py#L34) for
FT, NFT, multi-ref, and empty-script cases. The general
`_compute_hash_output_hashes` ([transaction_preimage.py:66](../../src/pyrxd/transaction/transaction_preimage.py#L66))
already computes the correct `refsHash`. The Phase-1 de-dup is real
but small, and the "new ref-aware sighash code path" the plan worried
about is **already written and covered**.

### Finding 4: the constructor already has 10 params and a four-way BTC dispatch

The sentinel constructor:

```
makerPkh, takerRadiantPkh, btcReceiveHash, btcReceiveType, btcSatoshis,
btcChainAnchor, expectedNBits, expectedNBitsNext, claimDeadline,
totalPhotonsInOutput
```

Adding `glyph_ref` (and, for FT, `amount`) is one or two more
constructor params substituted the same way `btcReceiveHash` is —
the substitution machinery in
[covenant.py:203-267](../../src/pyrxd/gravity/covenant.py#L203)
handles it with no structural change.

## What this does NOT make free

Unlike the BCH case (where the SPV verifier was already chain-agnostic
and the work was *zero*), the ref-bearing covenant still needs genuine
new work:

1. **The settlement output now carries a ref, so it is no longer a
   plain P2PKH.** The taker receives an FT/NFT output, which means the
   covenant's `totalPhotonsInOutput` check must coexist with a
   dust-value ref output — different value semantics.
2. **Ref-conservation is a consensus rule the covenant must not
   violate.** The covenant builds the *expected* output bytecode; the
   network separately enforces that input refs == output refs. The
   covenant and the consensus rule must agree, or the spend is
   rejected. This is the genuine design risk and still needs regtest
   validation.
3. **The two Critical security findings stand** (multi-ref smuggling,
   SPV proof reuse) — those are about *what the covenant must
   additionally constrain*, and the introspection mechanism makes them
   *expressible* (`OP_OUTPUTBYTECODE` can assert the full ref-bearing
   script, including that there's exactly one ref) but someone still
   has to write and audit those clauses.
4. **`OP_OUTPUTBYTECODE` on a ref-bearing output is a script path the
   sentinel covenant has never exercised.** Regtest validation is
   still required — Finding 1 says the *mechanism* exists, not that
   the *specific spend* has been proven.

## Revised estimate

| Phase | Plan estimate | Spike-revised | Why |
|---|---|---|---|
| 1 — sighash de-dup | 3–5 days | **1–2 days** | `_get_push_refs` + correct `_compute_hash_output_hashes` already shipped and tested; de-dup is small. Regtest harness still needed but lighter than feared. |
| 2 — covenant spike | 2–3 weeks | **1–2 weeks** | Output construction mechanism (`OP_CAT` + `OP_OUTPUTBYTECODE`) already exists; work is additive (CAT the epilogue) not from-scratch. Ref-conservation regtest validation is the real unknown and keeps this from collapsing further. |
| 3 — types + validator | 5–7 days | **5–7 days** | Unchanged — Python type discipline + opcode-stream validator + property tests are real work regardless of covenant findings. |
| 4 — BTC half + builders | 2–3 weeks | **1.5–2 weeks** | Builders extend an existing introspection-output pattern; golden-byte regtest gate unchanged. |
| 5 — e2e + red-team | 2–3 weeks | **2–3 weeks** | Unchanged — the test surface is the test surface; security findings stand. |
| 6 — async verifier | 5–7 days | **5–7 days** | Unchanged. |
| 7 — audit + docs | 1 week | **1 week** | Unchanged. |
| **Total** | **9–12 weeks** | **~6.5–9 weeks** | |

The collapse is real but **smaller than the doc's headline 3–4×
cases**, and that is the honest finding: this is not the BCH situation
where the work was already done. The covenant genuinely needs new
ref-bearing clauses and regtest proof of ref-conservation. What the
spike corrects is the *framing* — "build a new output-description
system" → "extend an existing compositional-output covenant" — which
takes ~2.5–3 weeks off the estimate, mostly in Phases 1, 2, and 4.

## What did NOT change

- The split FT/NFT artifact decision (security) stands.
- Both Critical security findings stand and still gate Phase 4→5.
- The golden-byte regtest gate (anti-synthetic-divergence) stands —
  in fact Finding 4 makes it *more* important: `OP_OUTPUTBYTECODE` on
  a ref output is unexercised, so synthetic round-trip would be
  exactly the trap the dMint incidents warn about.

## Phase-2 addendum (2026-05-19): Photonic prior-art check

Read the Photonic Wallet TypeScript source (a local checkout of the
public `photonic-wallet` repo) for ref-bearing covenant prior art.
Findings:

- **Photonic has no transfer / swap / escrow covenant.** Its only
  ref-bearing covenant is the self-rebuilding dMint `powmint.rxd`,
  which preserves refs by byte-slicing its own state script forward
  (`bytes newState = 0x04 + bytes4(newHeight) +
  tx.inputs[...].stateScript.split(5)[1]; require(tx.outputs[i].stateScript
  == newState)` — powmint.rxd:49) and counts ref outputs via
  `refOutputCount(tokenRef)` / `codeScriptCount()` introspection
  (powmint.rxd:42).
- **Its FT/NFT scripts are passive.** `ftScript` / `nftScript`
  (script.ts:245-263) push the ref but do **not** enforce "this output
  carries this ref"; ref conservation is enforced by the *receiver's*
  covenant at consensus level, not by the sender. `swap.ts` is
  UI-level pre-signed-tx logic, **not** a locked covenant.

**Implication — the Gravity pattern is novel.** Locking a ref-bearing
UTXO and enforcing on settlement that the ref flows to a *specific
Taker destination* via a script we construct
(`require(tx.outputs[k].lockingBytecode == <constructed bytes incl.
ref>)`) is **not** something Photonic exemplifies. The closest
mechanism is dMint's `require(output.stateScript == rebuilt_bytes)`,
which — combined with Finding 1 (the sentinel covenant already CATs
output scripts and asserts them via `OP_OUTPUTBYTECODE`) — makes the
construction feasible. But there is no battle-tested precedent for
*ref-to-arbitrary-destination*, so:

- The external-audit gate (already in the plan) is **non-negotiable**,
  not a recommendation.
- The golden-byte + `testmempoolaccept` gates matter even more — this
  is genuinely new bytecode, not a variant of a proven shape.

The construction primitive to use: build the expected Taker output
bytecode in-script by CATing `<ftScript/nftScript bytes with the
locked ref spliced in>`, then `OP_<k> OP_OUTPUTBYTECODE OP_EQUALVERIFY`
— mirroring the sentinel covenant's existing P2PKH-output assertion,
extended to carry the ref opcode + 36-byte ref + FT fingerprint.

## Recommended next step

The plan estimates were updated to the spike-revised column. Phase 2
proceeds: draft the FT + NFT covenant templates (Radiant-only, no BTC
half yet), validate lock → release → forfeit against the mainnet node
on `tr`, and record benchmark vectors. Ref-conservation validation on
a real spend remains the dominant unknown.
