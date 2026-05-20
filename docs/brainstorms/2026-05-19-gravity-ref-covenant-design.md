---
title: Ref-bearing Gravity covenant — Phase 2 design (post adversarial review)
date: 2026-05-19
status: design — REVISED after divergent review panel (2026-05-20); see Review Outcome
---

# Ref-bearing Gravity covenant — Phase 2 design

**Purpose.** Concrete covenant design for FT-for-BTC swaps, written
*before* compiling any bytecode so it can take the adversarial-review
checkpoint the plan
([2026-05-19-feat-gravity-ref-bearing-covenant-plan.md](../plans/2026-05-19-feat-gravity-ref-bearing-covenant-plan.md),
Phase 2) requires. Grounded in the real sentinel covenant asm and the
shipped FT/NFT script builders — not in inference.

## Review Outcome (divergent panel, 2026-05-20)

Four reviewers (security-sentinel, architecture-strategist,
code-simplicity, Radiant-script correctness) reviewed this design
**independently** before any bytecode. They converged on one root cause
and several structural improvements. Verdict: **the design's threat
handling was incomplete in a CRITICAL way** — the first draft asserted
only `output[0]`'s bytecode and left every other output unconstrained.
That single under-constraint enables three exploitable attacks. The
two "open questions" the first draft *flagged* were not open; they were
live. Revised mandates below.

### CRITICAL — the covenant must constrain the WHOLE transaction, not just output[0]

The first draft asserted `OP_0 OP_OUTPUTBYTECODE OP_EQUALVERIFY` and
`OP_0 OP_OUTPUTVALUE >= dust`. That is insufficient. Three attacks, one
root cause:

1. **Output-count blindness.** Nothing constrains `OP_TXOUTPUTCOUNT`;
   the spender controls outputs[1..n].
2. **Multi-ref smuggling (was "open question #2" — it is live).** Maker
   funds with two refs (sold ref R + valuable piggyback R2). Radiant
   ref-conservation forces R2 onto *some* output; the covenant pins
   only output[0]=R, so the Maker routes R2 to a Maker-controlled
   output[1]. Taker pays BTC, gets R; Maker keeps R2.
3. **FT value-splitting (was "open question #1" — it is live, and
   consensus does NOT cover it).** Radiant FT conservation sums value
   across **all** outputs sharing the FT script
   ([glyph/script.py:53-54,70](../../src/pyrxd/glyph/script.py#L53):
   "R can split"). Lock N units; settle by sending Taker output[0] = 1
   unit (passes bytecode match + dust) and Maker output[1] = N−1 units
   under the same FT script. `sum_in == sum_out` holds globally; the
   covenant is satisfied; the Taker is shorted N−1.

**Mandated fixes (must be in-script AND proven to REJECT the negative
case on regtest before any byte is trusted):**

- `OP_TXOUTPUTCOUNT <n> OP_NUMEQUALVERIFY` — pin the exact output count.
- `OP_0 OP_OUTPUTVALUE <lockedFtUnits> OP_NUMEQUALVERIFY` — **exact** FT
  value to the Taker, not `>= dust`. (FT units are the output's photon
  value under the FT script.)
- A single-input-ref assertion (`OP_REFDATASUMMARY_UTXO` /
  `refoutputcount`-style — exact opcode TBD on regtest) so a
  multi-ref funding UTXO cannot settle.

This reverses the first draft's FT-amount simplification: **the exact
amount check is required after all**, because consensus governs only
the aggregate, never output[0]'s share. The `lockedFtUnits` value
must therefore be bound into the covenant (constructor param or
asserted equal to the input value).

### Structural improvements (adopted)

- **FT-only v1.** Drop NFT from v1 (Simplicity + others). NFT is a
  second script layout, compile, regtest trail, and audit surface that
  does not serve the "sell credits/tokens" need. Ship FT; NFT is a
  near-mechanical repeat when a real NFT-sale need appears.
- **Build-time template source, not three forked artifacts**
  (Architecture). The security rejection of `refKind` dispatch was
  about *runtime* selectability, not *build-time* templating. Keep one
  human-audited template source with a single substituted
  `<<OUTPUT_CLAUSE>>` region; emit distinct artifacts from it. Avoids
  triplicate drift (a sentinel SPV fix would otherwise need 3× hand-
  application + re-audit).
- **`glyphRef` needs a new `_FIXED_LENGTHS` entry = 36** (Architecture).
  It is NOT "like btcReceiveHash" (that's 32-byte Sha256). Declared as
  plain `bytes` it would skip length validation
  ([covenant.py:217,247](../../src/pyrxd/gravity/covenant.py#L217)) and
  a 35/37-byte ref would silently produce an on-chain-rejected
  covenant. Add `GlyphRef: 36` to the loader.
- **Drop subaddress derivation; reject duplicate BTC addresses in the
  off-chain verifier instead** (Simplicity). `glyphRef` is already in
  the P2SH hash, so the covenant address is already offer-unique. The
  SPV-reuse risk is purely off-chain (a verifier crediting one BTC
  payment to two offers sharing a receive address). An off-chain
  duplicate-address check is less machinery than a key-derivation
  scheme and gives the same property. (Security flagged nonce-
  uniqueness as a HIGH gap in the derivation approach — dropping it
  removes the gap.)
- **Share the FT fingerprint constant** between the covenant template
  generator and `glyph/script.py` (Architecture) so a Glyph version
  bump breaks loudly at build, not silently on-chain.
- **Spike-harness builder is allowed before the production builder**
  (Architecture) — you need *some* tx to submit to regtest. The
  "no Python builders until conservation proven" gate applies to the
  *shipped* builders; a disposable spike harness to produce the
  regtest spend is fine and necessary.

The body below is the original draft, retained for the construction
detail; read it through the lens of the mandates above.

## Spike results (2026-05-20) — opcodes confirmed, FT-amount question RESOLVED

Read-only spike against pyrxd source + the live mainnet node on `tr`,
before writing any bytecode:

1. **All required opcodes exist** ([constants.py:285-320](../../src/pyrxd/constants.py#L285)):
   `OP_TXOUTPUTCOUNT` (`0xc4`), `OP_OUTPUTVALUE` (`0xcc`),
   `OP_OUTPUTBYTECODE` (`0xcd`), and the full ref family —
   `OP_REFVALUESUM_OUTPUTS` (`0xdc`), `OP_REFOUTPUTCOUNT_OUTPUTS`
   (`0xde`), `OP_REFDATASUMMARY_OUTPUT` (`0xe2`), etc. The three
   mandated fixes are all expressible.

2. **FT amount == photon value (1 photon = 1 FT unit).** This resolves
   the load-bearing open question and *confirms* the mandated fix #3
   uses the right opcode. Evidence:
   [glyph_cmds.py:933](../../src/pyrxd/cli/glyph_cmds.py#L933) —
   `ft_amount = utxo.value  # 1 photon = 1 FT unit`. The FT-CSH
   conservation epilogue (`dec0e9aa76e378e4a269e69d`) sums **photon
   values** across ref-bearing outputs sharing the ref.

   ⚠️ **Misleading docstring corrected:** `ft.py:15-17` calls
   `ft_amount` and `value` "orthogonal." They are distinct *dataclass
   fields* but the SAME on-chain quantity — the FT carrier's photon
   value IS its token amount. So `OP_0 OP_OUTPUTVALUE <lockedUnits>
   OP_NUMEQUALVERIFY` (fix #3) **is correct** — `OP_OUTPUTVALUE`
   returns the photon value, which equals the FT amount. (Briefly
   looked wrong mid-spike because of that docstring; the code at
   glyph_cmds.py:933 is authoritative.)

   Consequence: `lockedFtUnits` = the locked covenant UTXO's photon
   value. The Taker's settlement output[0] must have **exactly** that
   photon value, and `OP_TXOUTPUTCOUNT` must clamp so no sibling FT
   output siphons the rest.

3. **`testmempoolaccept` path confirmed available** on `tr` (node
   synced, wallet funded ~180 RXD) for the negative-case-rejection
   proofs the mandates require.

## Toolchain reconciliation (2026-05-20)

The shipped artifacts were built with `rxdc 0.1.0`; the local
RadiantScript compiler is `rxdc 1.1.0-v2` (`~/apps/RadiantScript`,
a lerna monorepo; `packages/cashc` is the `rxdc` compiler). Checked
whether the version gap breaks compatibility — **it does not:**

- **Artifact format `version: 9` is identical** across the bump
  (shipped sentinel: `version=9` int; compiler `generateArtifact`
  emits `version: 9`). pyrxd's loader keys (`contract`, `hex`, `abi`)
  are all produced; `hex` is an optional artifact field generated via
  `@radiantscript/utils` `scriptToBytecode`.
- **`^0.9.0` is a language pragma**, distinct from the compiler
  package version. The opcode set it targets is the same
  `0xc4`/`0xcc`/`0xdc`/`0xde` family pyrxd already encodes in
  `constants.py`.
- **`TokenSwap.rxd` / `FungibleToken.rxd` examples exist** in the
  compiler repo and use `tx.outputs.refValueSum($ref)` — the exact
  idiom for fix #3. ⚠️ But `TokenSwap.rxd` *itself* has the panel's
  bug: it checks only aggregate `refValueSum` equality and
  `>= amount`, never clamps output count or pins the recipient's
  exact share. **Do not copy it naively** — it is the textbook
  instance of the under-constraint the panel caught.

**Build-session results (2026-05-20):**

- **Compiler built and runs.** `~/apps/RadiantScript/packages/cashc`
  builds with `npm run build` (Node 22); the `rxdc` CLI is
  `dist/main/cashc-cli.js`. Despite the package version `1.1.0-v2`, it
  **stamps `compilerVersion: rxdc 0.1.0`** and emits all 6 artifact
  keys incl. `hex` — i.e. it IS the compiler that built the shipped
  artifacts. No codegen-version gap.
- **Grammar gotcha:** the `examples/radiant/*.rxd` files (with
  `function transfer(...)`, `pragma ^0.9.0`) **do not parse** — wrong
  grammar generation. The accepted grammar is `pragma radiantscript
  ^0.1.0` with bare `function (...)` (see
  `packages/cashc/test/valid-contract-files/rxd_fungible_token.rxd`).
  Write the swap covenant in THAT syntax.
- **Codegen-drift question dissolved.** It was the wrong question. The
  mainnet FT *output* locking script's conservation epilogue
  (`dec0e9aa76e378e4a269e69d`) is **hard-coded as a literal byte
  constant** in pyrxd's `build_ft_locking_script`
  ([script.py:138](../../src/pyrxd/glyph/script.py#L138)) — it is NOT
  re-derived from a compiler. The freshly-compiled `FungibleToken.rxd`
  produces a *different* epilogue (`c0e9aa...`, reordered opcodes) —
  proving you must NOT regenerate the FT script from source; you must
  reproduce the exact mainnet bytes.

**Consequence for the swap covenant (simplifies it):** the covenant
does **not** re-implement FT conservation. It CATs the *literal*
mainnet FT epilogue into the constructed settlement output, then
asserts the full output bytecode via `OP_OUTPUTBYTECODE
OP_EQUALVERIFY`. FT conservation rides inside that constructed FT
script (enforced by the network when the output is later spent). The
swap covenant's narrower job: bind ref + exact photon value (=FT
amount) + output count, and assert the exact FT output script. This
sidesteps codegen drift entirely — the epilogue is a literal, not a
compiled artifact.

## ⚠️ CRITICAL deployment-model finding (2026-05-20) — bare script, NOT P2SH

While funding a real minted FT into the compiled covenant on mainnet,
hit the load-bearing constraint the design (and the shipped Gravity
covenant) got wrong:

**A ref-bearing covenant cannot be P2SH-wrapped.** Radiant
ref-conservation requires the ref opcode (`OP_PUSHINPUTREF` `0xd0`) to
appear **in the output scriptPubKey**. A P2SH output is `a914<hash>87`
— it shows no ref. So funding a covenant as plain P2SH would *burn*
the ref (conservation violation → tx rejected). Confirmed against a
live glyph UTXO: its scriptPubKey starts with `d8...` (bare ref
opcode), **not** `a914` (P2SH). Photonic's covenants and the dMint
contract UTXO are all **bare scripts** too.

**The contrast with shipped Gravity is real and explains the gap:**
- Plain-RXD Gravity covenant → P2SH-wrapped. Fine — no ref to expose.
- Ref-bearing FT/NFT covenant → **must be a bare script**: the full
  covenant logic lives in the scriptPubKey, prefixed/structured so the
  ref opcode is visible for conservation.

**Impact on the design:**
- The `compute_p2sh_*` machinery the spike reused does NOT apply to the
  ref-bearing variant. The covenant deploys as a bare ref-bearing
  scriptPubKey; "funding" = an FT transfer whose output IS that bare
  covenant script (carrying the ref → conservation satisfied).
- The covenant script must itself begin with (or contain)
  `OP_PUSHINPUTREF <REF>` so the locked UTXO's scriptPubKey exposes the
  ref. The compiled spike already does `pushInputRef(REF)` in its
  preamble — need to confirm that places the ref opcode in the
  *locking* script (deploy form), not only in the *spending* path.
- This is exactly the deploy-model divergence the dMint incidents warn
  about; caught at the funding step *before* burning the real FT.

**Status:** the FT is minted and held safe (ref
`57296874…:0`, 100k units); covenant compiles; but the
bare-vs-P2SH deploy model must be resolved before funding. This is the
next concrete step — recompute the covenant as a bare ref-bearing
scriptPubKey, then fund + run the attack-rejection proofs.

---

**Single review question this doc must survive:** *what does shipping
this normalize, and what is the day-1 attack?*

## Context the design rests on (verified, with sources)

1. **The sentinel covenant already constructs its settlement output
   compositionally and asserts it by introspection** — it does not use
   `hashOutputs`. From the real artifact asm
   (`maker_covenant_flat_12x20_sentinel_all`, finalize branch):

   ```
   76a914 $takerRadiantPkh OP_CAT 88ac OP_CAT     # build P2PKH scriptPubKey
   OP_0 OP_OUTPUTBYTECODE OP_EQUALVERIFY           # assert output[0] == it
   OP_0 OP_OUTPUTVALUE $totalPhotonsInOutput OP_GREATERTHANOREQUAL OP_VERIFY
   ```

   The forfeit branch is structurally identical, swapping `$makerPkh`
   for `$takerRadiantPkh` and gating on
   `$claimDeadline OP_CHECKLOCKTIMEVERIFY OP_DROP`:

   ```
   $claimDeadline OP_CHECKLOCKTIMEVERIFY OP_DROP
   76a914 $makerPkh OP_CAT 88ac OP_CAT
   OP_0 OP_OUTPUTBYTECODE OP_EQUALVERIFY
   OP_0 OP_OUTPUTVALUE $totalPhotonsInOutput OP_GREATERTHANOREQUAL
   ```

2. **The FT/NFT locking scripts are fixed-shape with one variable
   field (the 36-byte ref).** From `glyph/script.py`:

   - **FT (75 bytes):** `76a914 <pkh:20> 88ac` `bd` `d0` `<ref:36>`
     `dec0e9aa76e378e4a269e69d`
     (P2PKH + `OP_STATESEPARATOR` + `OP_PUSHINPUTREF` + ref + 12-byte
     FT conservation fingerprint)
   - **NFT (63 bytes):** `d8` `<ref:36>` `7576a914 <pkh:20> 88ac`
     (`OP_PUSHINPUTREFSINGLETON` + ref + `OP_DROP OP_DUP` + P2PKH tail)

3. **Photonic has no transfer/swap covenant to copy** (see
   [spike-findings addendum](2026-05-19-gravity-ref-covenant-spike-findings.md)).
   dMint's self-rebuild (`require(output.stateScript == rebuilt_bytes)`)
   is the closest mechanism; ref-to-arbitrary-destination is novel.

## The design

Two separate artifacts (`maker_covenant_ft_v1`, `maker_covenant_nft_v1`)
per the plan's security decision. Each is a fork of the sentinel
covenant where **only the constructed-output bytecode changes** —
everything BTC-facing (SPV proof, `btcReceiveType` dispatch,
sentinel-padded Merkle depth, `claimDeadline`) is reused verbatim.

### New constructor param

Add `glyphRef` (36 bytes) to the constructor, substituted into the hex
template exactly like `btcReceiveHash`. **This binds the ref into the
P2SH redeem-script hash** — the offer's identity includes the exact ref
being sold (Security #1: ref substitution is impossible because a
different ref produces a different P2SH address).

FT also adds `ftAmount`? **No — see the FT-amount decision below.**

### Settlement clause (FT)

Replace the sentinel's P2PKH-output construction with the FT script
construction, then assert by introspection as today:

```
76a914 $takerRadiantPkh OP_CAT 88ac OP_CAT      # P2PKH prefix  (unchanged)
bd OP_CAT                                        # + OP_STATESEPARATOR
d0 OP_CAT                                        # + OP_PUSHINPUTREF
$glyphRef OP_CAT                                 # + the locked ref (constructor param)
dec0e9aa76e378e4a269e69d OP_CAT                  # + FT conservation fingerprint
OP_0 OP_OUTPUTBYTECODE OP_EQUALVERIFY            # assert output[0] == the FT script
OP_0 OP_OUTPUTVALUE <dust> OP_GREATERTHANOREQUAL OP_VERIFY
```

The settlement output is now a 75-byte FT output to the Taker's PKH
carrying the locked ref. RXD value drops to dust (the value side is no
longer the asset; the ref is).

### Settlement clause (NFT)

Same shape, NFT script layout:

```
d8 $glyphRef OP_CAT                              # OP_PUSHINPUTREFSINGLETON + ref
7576a914 OP_CAT $takerRadiantPkh OP_CAT 88ac OP_CAT
OP_0 OP_OUTPUTBYTECODE OP_EQUALVERIFY
OP_0 OP_OUTPUTVALUE <dust> OP_GREATERTHANOREQUAL OP_VERIFY
```

(Exact CAT ordering and minimal-push encoding of the literal opcode
bytes is a compile detail to validate on regtest; the structure is what
matters for review.)

### Forfeit clause (FT and NFT)

Identical change: the sentinel forfeit builds `76a914 $makerPkh 88ac`;
the ref version builds the **same FT/NFT script but to `$makerPkh`**, so
the reclaimed UTXO carries the original ref back to the Maker. Gated by
`$claimDeadline OP_CHECKLOCKTIMEVERIFY` unchanged.

This satisfies the trust property "forfeit returns the *original*
ref-bearing UTXO" — the reclaimed output is constructed to carry the
same `$glyphRef`.

## How the four threats are handled

| Threat | Handling in this design |
|---|---|
| **Ref substitution (Security #1)** | `glyphRef` is a constructor param → baked into the P2SH hash. A different ref ⇒ different covenant address ⇒ Maker never funded it. The settlement clause constructs the expected output from `$glyphRef`, so the Taker cannot redirect a different ref. |
| **Multi-ref smuggling (Security #2, Critical)** | The settlement/forfeit output bytecode is asserted *exactly* (`OP_EQUALVERIFY` on full scriptPubKey), so the output carries exactly the one constructed ref. **Open question:** does asserting output[0]'s bytecode also need an explicit ref-*count* constraint on the spend to stop a *second* smuggled ref riding a different output? Radiant ref-conservation should force any input ref onto an output, so a smuggled funding ref must appear somewhere — needs an explicit `refoutputcount`-style check or a total-outputs constraint. **MUST resolve on regtest before shipping.** |
| **SPV proof reuse across offers (Security #5, Critical)** | Subaddress derivation: `btcReceiveHash` derived from `(makerPkh, glyphRef, nonce)` so each offer's BTC receive address is unique → one BTC payment proves exactly one covenant. (Chosen over OP_RETURN to avoid excluding consumer BTC wallets.) |
| **refKind branch confusion (Security #6)** | Eliminated by construction: two separate artifacts, no in-script `refKind` dispatch, no selectable branch. |

## The FT-amount decision (important)

**The FT amount is NOT carried in the ref or in a covenant param.**
Per the Photonic finding (`fungible.rxd`), Radiant FT conservation is a
**consensus-level value check** — `codeScriptValueSum(inputs) >=
codeScriptValueSum(outputs)` for outputs sharing the FT code-script
hash. The FT "amount" is the UTXO's photon value under the FT script,
not a separate field.

Consequence for the covenant: by constructing the exact FT output
script (which includes the FT fingerprint) and asserting it via
`OP_OUTPUTBYTECODE`, **the covenant pins the ref and the script shape;
Radiant consensus pins the amount conservation.** This means:

- The plan's `FtAmount`/`amount` constructor param and the
  `sum-in == sum-out` *in-script* check are likely **unnecessary** —
  consensus already enforces it. This simplifies the covenant.
- **Open question to confirm on regtest:** does locking N FT units into
  the covenant and asserting the FT output script guarantee the Taker
  receives exactly N, or could a malicious settlement split value? The
  `OP_OUTPUTVALUE >= dust` check governs RXD, not FT units. Need to
  verify the FT-fingerprint consensus check covers this. **This is the
  single most important thing to validate before writing the builder.**

If consensus does NOT fully cover it, fall back to an explicit
in-script value assertion. Either way, this is a regtest question, not
a design-by-inference question.

## What stays exactly as the sentinel covenant

- SPV proof verification (block headers, Merkle proof, sentinel padding
  depth 12–20)
- `btcReceiveType` four-way dispatch (P2PKH/P2WPKH/P2SH/P2TR)
- `btcChainAnchor`, `expectedNBits`, `expectedNBitsNext` PoW binding
- `claimDeadline` + `OP_CHECKLOCKTIMEVERIFY` forfeit gate
- The P2SH-wrapping and `CovenantArtifact` substitution machinery

## Open questions to resolve on regtest (before bytecode is "done")

1. **FT conservation coverage** (above) — does asserting the FT output
   script + consensus conservation guarantee the Taker gets exactly the
   locked amount? *Highest priority.*
2. **Multi-ref smuggling** — is exact-output-bytecode assertion
   sufficient, or is an explicit ref-count constraint needed?
3. **Minimal-push encoding** of the literal opcode bytes (`bd`, `d0`,
   `d8`, the fingerprint) inside `OP_CAT` chains — confirm the compiler
   emits them as data pushes, not as executed opcodes.
4. **Script size / fee** — measure both artifacts vs sentinel; confirm
   ≤ 1.5× gate.
5. **`OP_OUTPUTBYTECODE` on a ref-bearing output** — never exercised by
   the sentinel covenant; confirm the node accepts the spend
   (`testmempoolaccept`) before any golden-byte fixture is trusted.

## Recommended sequence (unchanged from plan, now concrete)

1. **Adversarial review of THIS doc** (the checkpoint) — answer the
   single review question above.
2. Draft FT template → compile → regtest lock/release/forfeit →
   resolve open questions 1–3.
3. Repeat for NFT.
4. Benchmark (open question 4), record in spike-findings.
5. Only then bolt on the BTC half (Phase 4) and write Python builders.

**Do not write the Python tx builders or the BTC half until the FT
conservation question (1) is answered on a real regtest spend.** That
is the load-bearing unknown; everything downstream depends on it.
