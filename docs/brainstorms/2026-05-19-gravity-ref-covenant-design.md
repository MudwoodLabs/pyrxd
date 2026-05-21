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

## ⚠️ DEEPER finding (2026-05-20) — an FT cannot move into an arbitrary ref-bearing covenant

Recomputed the covenant as a **bare** scriptPubKey (it correctly leads
with `OP_PUSHINPUTREF <REF>`, confirmed) and built the funding tx
(FT input → covenant output carrying the ref). The funding dry-run
(`testmempoolaccept`) **rejected** with:

```
19: bad-txns-inputs-outputs-invalid-transaction-reference-operations-mempool
```

The refs match exactly (verified byte-for-byte), so this is NOT a ref
mismatch — it is a **conservation-structure** problem:

- A Radiant FT is bound to **its own code-script** (the
  `dec0e9aa…` FT-CSH epilogue). Conservation is enforced as
  `codeScriptValueSum(FT-code-script, inputs) ==
  codeScriptValueSum(FT-code-script, outputs)` — i.e. the FT value must
  flow to outputs **carrying the same FT code-script**.
- My covenant output declares the ref via `OP_PUSHINPUTREF <REF>` but
  is a *swap covenant script*, NOT the FT's code-script. So the FT's
  `codeScriptValueSum` drops to zero on the output side → conservation
  violation → rejected. (Caught in **dry-run** — the FT was NOT burned.)

**Implication — this is an architecture-level constraint, not a bug:**
you cannot lock an FT into an arbitrary covenant by simply declaring
its ref. The FT is welded to its FT-CSH code-script. To hold an FT in
a covenant, the covenant output must EITHER:

1. **Be the FT code-script itself**, with the swap logic layered so the
   covenant controls the *spend* of a normal FT UTXO (e.g. the covenant
   key/condition is what the FT's P2PKH-prefix checks) — i.e. wrap the
   covenant *inside* the FT script's spend path, not the FT inside the
   covenant; or
2. Use a **different token model** (NFT singleton, or a mutable/contract
   ref) whose conservation rule the covenant can satisfy; or
3. Have the covenant satisfy the FT's `codeScriptValueSum` by being
   counted as an equivalent code-script (likely not possible for an
   arbitrary script).

Option 1 is the probable path and it **inverts the design**: rather
than "lock the FT into the swap covenant," the swap condition must be
expressed *within* an FT-shaped output (or a covenant that re-emits the
exact FT code-script on settlement while gating the spend). This needs
genuine redesign + a likely fresh divergent-review pass.

**Status:** FT minted and **held safe** (ref `57296874…:0`,
100k units — dry-run rejection means nothing was burned). Covenant
compiles with correct hardening opcodes. The blocker is now an
architecture question, not a coding one: *how does an FT-CSH-conserved
token get held by a swap covenant?*

### Photonic investigation (2026-05-20) — and an UNRESOLVED contradiction

Read Photonic's swap + vault code for the canonical pattern:

- **`swap.ts`** (`packages/app/src/swap.ts`) does NOT use a holding
  covenant. It moves the FT to an FT-script at a dedicated **swap
  sub-address** (`ftScript(swapAddress, ref)` — still a normal
  conserving FT UTXO) and uses **SIGHASH-flagged partial signatures**
  (`tx.ts:21,47`) for atomicity. So one real model is: *FTs are never
  held in a non-FT covenant — they stay FT-shaped and swaps are
  pre-signed atomic txs.*

- **`vault.ts`** (`packages/lib/src/vault.ts`) DOES claim to vault FTs
  with an added CLTV constraint, via `vaultFtRedeemScript` (vault.ts:268):
  ```
  <locktime> OP_CHECKLOCKTIMEVERIFY OP_DROP
  OP_STATESEPARATOR OP_PUSHINPUTREF <ref>
  OP_REFOUTPUTCOUNT_OUTPUTS OP_INPUTINDEX OP_CODESCRIPTBYTECODE_UTXO
  OP_HASH256 OP_DUP OP_CODESCRIPTHASHVALUESUM_UTXOS OP_OVER
  OP_CODESCRIPTHASHVALUESUM_OUTPUTS OP_GREATERTHANOREQUAL OP_VERIFY
  OP_CODESCRIPTHASHOUTPUTCOUNT_OUTPUTS OP_NUMEQUALVERIFY
  ```
  i.e. the covenant constraint is *prepended* and the **full FT
  conservation epilogue is embedded inside the redeem script**.

**The unresolved contradiction (do NOT build until settled):**
`vault.ts` funds the vault to a **P2SH output**
(`p2shOutputScript` = `OP_HASH160 <hash> OP_EQUAL`, vault.ts:303) —
which exposes **no ref**, exactly the shape the mainnet node REJECTED
in my funding dry-run. And Photonic has **no FT-vault tests**
(searched `packages/lib/test/` — none), so this path may be
**aspirational/untested** (per memory: Photonic is the default
reference but not infallible). Two live possibilities, unresolved:

1. Photonic's FT vault has the same conservation bug my spike hit
   (P2SH funding burns the ref) — i.e. it doesn't actually work
   on-chain for FTs. My mainnet rejection is hard evidence this is
   plausible.
2. Radiant's conservation rule looks *past* the P2SH hash somehow
   (counts refs in the revealed redeem script on the spend side, with
   some funding-side accommodation I haven't found).

**I will not guess between these.** The authoritative answer is in
**Radiant Core's actual conservation algorithm** (the consensus code
that emits `bad-txns-inputs-outputs-invalid-transaction-reference-operations`),
which I have not read. Next session: read that consensus code (or test
Photonic's FT vault directly on regtest/mainnet with a tiny amount) to
determine whether ANY P2SH-wrapped FT covenant can conserve, OR whether
the swap.ts "pre-signed atomic, FT stays FT-shaped" model is the only
viable one. The covenant design depends entirely on which is true.

## ✅ RESOLVED (2026-05-20) — read the consensus source; the DEEPER finding's diagnosis was WRONG

Read Radiant Core's actual induction-rule algorithm (local source
`~/apps/Radiant-Core`, v3.0.0):

- `ReferenceParser::validateTransactionReferenceOperations`
  (`src/validation.h:991`)
- `CScript::GetPushRefs` (`src/script/script.cpp:555`)

**What the rule actually does:** it extracts refs by *linearly scanning
the raw scriptPubKey bytes* for the ref opcodes (0xd0 PUSHINPUTREF,
0xd1 REQUIREINPUTREF, 0xd2/0xd3 DISALLOW…, 0xd8 PUSHINPUTREFSINGLETON),
skipping pushdata operands but otherwise **purely syntactic** — it does
NOT understand the semantics of the script. The conservation rule
(`validatePushRefRule`, validation.h:919): every push/require ref in any
OUTPUT must appear in some INPUT (set_difference outputs−inputs must be
empty); singleton refs are checked separately against the input
singleton set (validation.h:1063). The FT *amount* conservation
(`codeScriptValueSum`) is a SEPARATE, interpreter-side check
(introspection opcodes) — it is **not** what emits this reject string.

**The actual root cause (verified by walking the 264-byte covenant spk
the same way GetPushRefs does):** the covenant embeds the literal
FT-epilogue bytes (`…dec0e9aa76e378e4a269e69d`) twice as
`OP_OUTPUTBYTECODE` comparison data. A `0xd8` byte at **offset 224**,
sitting inside that embedded template data, gets parsed as a real
`OP_PUSHINPUTREFSINGLETON` consuming the next 36 bytes as a **phantom
ref** `343c4872…269e69d7e00`. That phantom singleton is in no input →
`singletonRefSatisfied = false` → reject. The legitimate
`OP_PUSHINPUTREF <REF>` at offset 0 (matching the FT input) is fine; the
phantom is the killer.

Re-confirmed live: `testmempoolaccept` on the recorded
`.funding_info.json` hex against the mainnet node (`ssh tr`, v2.3.0,
block 430721) reproduced the exact reject string.

**Corrections to the DEEPER finding above:**
- It is NOT a `codeScriptValueSum` / FT-code-script-welding problem.
  That diagnosis was a plausible-sounding guess; the source disproves it.
- It is NOT P2SH-vs-bare. The failing tx was BARE (spk starts `d0`,
  264 bytes — verified). The brief's "P2SH-wrapped" framing was wrong.
- The Photonic `vault.ts` "unresolved contradiction" is moot for our
  purposes: their P2SH funding hides ALL ref opcodes from the parser
  (so a P2SH FT vault funds with zero output refs and would itself fail
  conservation differently) — but our bare covenant's problem is the
  phantom ref, which is fixable.

**Why this is good news:** the blocker is a **script-encoding** problem,
not an architecture dead-end. An FT *can* be held in a bare ref-bearing
covenant — provided the covenant scriptPubKey contains **no byte
sequence that the linear parser will mis-read as a ref opcode followed
by 36 consumable bytes** at any position its pushdata-skipping actually
reaches.

**Mitigations to evaluate next (in order of preference):**
1. **Build the embedded expected-bytecode via `OP_CAT` from fragments**
   so that no `0xd0`/`0xd8` (and `0xd1`–`0xd3`) byte ever lands on a
   scan boundary as a bare opcode — i.e. keep every such byte *inside* a
   pushdata operand the parser skips. This is the surgical fix; the
   phantom at offset 224 is in raw script position, not behind a push.
2. Restructure the comparison so the FT epilogue is never present as
   raw script bytes (e.g. compare a hash of expected bytecode rather
   than the bytecode itself, if introspection allows
   `OP_OUTPUTBYTECODE OP_HASH256 <h> OP_EQUAL`).
3. Only if 1–2 fail: reconsider whether the settlement output must be
   epilogue-shaped inside the covenant at all.

**Next concrete step:** rebuild `build_covenant.py` so the embedded
template bytes are emitted as push-wrapped data, re-scan the resulting
spk with the GetPushRefs walk (must show exactly ONE ref = the FT ref),
then re-run the funding `testmempoolaccept`. Caveat to close first:
local source is v3.0.0 but the live node is v2.3.0 — confirm
ReferenceParser is unchanged between the two tags before trusting the
walk as ground truth.

## ✅✅ ON-CHAIN CONFIRMATION (2026-05-20) — TWO layers, both now understood

After the layer-1 fix (hash-compare covenant, no embedded epilogue bytes
→ phantom ref gone), I re-ran the funding `testmempoolaccept` on the
mainnet node. Two more facts surfaced, both verified:

1. **The spike used the wrong ref.** A Radiant FT's ref is its **genesis
   outpoint** (the commit/mint origin), which persists across transfers
   — NOT the current UTXO's txid. The on-chain FT at `57296874…:0`
   carries ref `1d5cc8…098c:0` = the commit tx `8c09738386d84132…:0`,
   not `57296874…`. The covenant must declare the genesis ref. Fixed.

2. **There is a SECOND gate, and it is the real architectural one.** With
   the correct ref and a fee above 10k photons/byte, the reject advanced
   from `…reference-operations` → `min relay fee not met` → finally
   `mandatory-script-verify-flag-failed (Script failed an
   OP_NUMEQUALVERIFY operation)`. That last failure is the **FT's own
   conservation epilogue executing at spend time** — `…dec0e9aa76e378…`
   contains `OP_CODESCRIPTHASHVALUESUM_UTXOS` (`e3`) /
   `OP_CODESCRIPTHASHVALUESUM_OUTPUTS` (`e4`) and a final
   `OP_NUMEQUALVERIFY`. Per `interpreter.cpp:2215`
   (`getCodeScriptHashValueSumOutputs`), it sums photons of **outputs
   whose code-script HASH matches the FT's**. Moving the FT into a
   covenant output (whose code-script ≠ the FT epilogue) yields
   outputs-sum 0 ≠ inputs-sum 100,000 → fail.

**So the DEEPER finding's conclusion was right after all** (the FT is
welded to its code-script) — it was just attributed to the wrong reject
string. The reference-induction rule (layer 1) and the
`codeScriptHashValueSum` epilogue (layer 2) are **independent gates**.
Fixing layer 1 was necessary but not sufficient.

**What this means for the design (the inversion is now mandatory, not
optional):** you cannot hold an FT inside a foreign swap covenant. The
settlement output must itself be **FT-code-script-shaped** so the FT's
epilogue conserves. The swap condition has to be expressed either:
- as a covenant that gates the *spend path* of a normal FT UTXO (the
  covenant key/condition is what the FT's P2PKH-prefix checks), re-emitting
  the exact FT code-script on settlement; or
- via the pre-signed-atomic model (Photonic `swap.ts`): the FT stays
  FT-shaped at a swap sub-address, atomicity from SIGHASH partial sigs —
  no holding covenant at all.

This needs a genuine redesign + fresh divergent-review pass before any
bytecode. The hash-compare covenant and the phantom-ref/genesis-ref fixes
are committed on `feat/gravity-ref-ft-covenant-spike`; they remain useful
as the *output-validation* half of the inverted design. The test FT
(`57296874…:0`, 100k units) is UNSPENT — every probe was a dry-run.

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

---

## Phase 1 design note — custody mechanism RESOLVED (2026-05-20)

This is the Phase-1 deliverable from
[2026-05-20-feat-gravity-ft-covenant-spend-path-plan.md](../plans/2026-05-20-feat-gravity-ft-covenant-spend-path-plan.md).
The load-bearing conservation question is **answered from the consensus
source** (not regtest yet — that is the Phase-2 confirmation), and it
answers favorably: **mechanism 1a is viable by construction.**

### The reframed question, answered from source

`getCodeScriptHashValueSum*` groups outputs/UTXOs by their
**`codeScriptHash`**. That hash is computed in
`Radiant-Core/src/script/script_execution_context.h:275-285`:

```cpp
// Create the codeScriptHash
if (stateSeperatorByteIndex >= script.size()) {
    ... hash of empty tail ...
} else {
    CScript::const_iterator scriptStateSeperatorIterator =
        script.begin() + stateSeperatorByteIndex;
    CHashWriter ...;
    hashWriter << CFlatData(CScript(scriptStateSeperatorIterator, script.end()));
    scriptSummary.codeScriptHash = hashWriter.GetHash();
}
```

The hash covers **`script.begin() + stateSeperatorByteIndex` → `end()`**
— i.e. the bytes **from `OP_STATESEPARATOR` (`0xbd`) onward**. Everything
*before* the separator (the prologue: P2PKH or covenant) is **excluded
from the codeScriptHash**.

`stateSeperatorByteIndex` is the position of the single
`OP_STATESEPARATOR`, located by `GetPushRefs`
(`src/script/script.cpp:609-624,644`); two separators → `GetPushRefs`
returns false → tx rejected; zero separators → index 0 (whole script
hashed).

### Consequence — 1a works by construction

For an FT `prologue ‖ bd ‖ d0 <ref> ‖ dec0e9aa76e378e4a269e69d`:

- `codeScriptHash = hash( bd d0 <ref> dec0e9aa76e378e4a269e69d )` —
  the separator + ref-push + FT-CSH epilogue. **Prologue-independent.**
- A **covenant-prologue** FT input
  (`<covenant-condition> bd d0 <ref> dec0…`) and a **standard-P2PKH-prologue**
  FT output (`76a914<pkh>88ac bd d0 <ref> dec0…`) therefore share the
  **same** `codeScriptHash` ⇒ `codeScriptHashValueSum` counts them
  together ⇒ **they conserve.**

This is exactly what Option A needs: gate the spend via the prologue
(which is not hashed), settle to the standard FT script
(`build_ft_locking_script`, the one `EXPECTED_TAKER_FT_HASH` is computed
from), and conservation holds.

### Decisions locked

1. **Mechanism: 1a** (covenant condition replaces/precedes the P2PKH
   prologue, *before* the `bd` separator). 1b is rejected (no on-chain
   custody — see plan C2).
2. **Prologue constraint (hard):** the covenant prologue must contain
   **no `OP_STATESEPARATOR` (`0xbd`) in opcode position** before the
   FT epilogue's separator — otherwise `GetPushRefs` takes the wrong
   boundary (or fails on a second separator), shifting/breaking the
   `codeScriptHash`. The prologue must also contain no stray ref-opcode
   bytes in opcode position (phantom-ref guard already covers this).
3. **Custody invariant (C1):** the covenant has **exactly two spend
   paths** — finalize-on-SPV-proof and forfeit-after-CLTV — and **no
   Maker-only pre-deadline reclaim**. The existing RXD covenant's
   `cancel()` branch is NOT inherited.
4. **Settlement output:** the standard FT script for the destination
   pkh (`build_ft_locking_script(dest_pkh, genesis_ref)`); covenant
   asserts `hash256(outputs[0].lockingBytecode) == EXPECTED_*_FT_HASH`.

### Still unproven (Phase 2 must confirm on a real node)

The source says 1a *should* conserve. Phase 2 must still
`testmempoolaccept` an actual covenant-prologue FT spend → standard-FT
output and confirm: (a) no `OP_NUMEQUALVERIFY`/conservation failure,
(b) the prologue's bytes are genuinely outside the hashed region in
practice (no off-by-one at the separator index), (c) all negative cases
(no-cancel, SPV-reuse, ==-not->= amount) reject. The source read
de-risks the unknown from "unknown" to "very likely yes" — it does not
replace the on-chain proof.

---

## Phase 2 — RADIANT-ONLY COVENANT PROVEN ON-CHAIN (2026-05-20)

Mechanism 1a is validated on the live mainnet node (`ssh tr`). The
covenant-prologue FT (`GravityFtPrologue` compiled + `bd d0 <ref>
dec0e9aa76e378e4a269e69d` epilogue, 217 B) was exercised end-to-end.

**Leg A — conservation (broadcast).** Standard test FT
`57296874…:0` → covenant-prologue FT UTXO. `sendrawtransaction` →
txid `22912a58196dbf627b3db631d151af5f4c69922e3c69635f0d5ed6b383abc594`,
vout 0 = the 100k-photon covenant-prologue FT. Confirms the Phase-1
source prediction empirically: a covenant-prologue (custom-prologue) FT
output shares the standard FT's `codeScriptHash` and conserves.

**Leg B — release (`testmempoolaccept` allowed).** Spend the
prologue-FT via `settle` (selector OP_0, taker sig) → standard taker FT
output. txid `069c46c8…`, `"allowed": true`. Executes the full path:
taker `OP_CHECKSIGVERIFY`, the 3 hardening constraints
(`outputs.length==1`, `refOutputCount==1`, `refValueSum==AMOUNT`), the
hash-compare (`hash256(output[0]) == EXPECTED_TAKER_FT_HASH`), and the FT
epilogue conservation — all pass.

**Negative-case matrix — all reject on-chain** (`build_leg_b_negatives.py`):

| Case | reject-reason | constraint |
|---|---|---|
| `extra_output` (2 outputs) | OP_NUMEQUALVERIFY | output-count clamp |
| `wrong_taker` (FT to attacker pkh) | false top stack | hash-compare |
| `short_amount` (value = AMOUNT-1) | OP_NUMEQUALVERIFY | refValueSum==AMOUNT |
| `cancel_attempt` (selector OP_2) | OP_NUMEQUALVERIFY | no third branch — **C1** |

`cancel_attempt` proves the **custody invariant**: selectors other than
settle(0)/forfeit(1) hit `OP_1 OP_NUMEQUALVERIFY` in the else-branch and
fail. There is no Maker-only pre-deadline reclaim — the day-1 theft the
divergent review caught (C1) is structurally impossible.

**What is NOT yet proven:** this covenant has **no BTC/SPV gate** — the
`settle` path is gated by a taker sig only (keeps the spike tx
well-formed). The BTC-payment requirement (SPV proof) and the on-chain
SPV-reuse binding (H1) are Phase-4 work. The conservation + custody +
hardening half is done; cross-chain atomicity is not.

**Asset state:** Leg A is broadcast, so the test FT now lives in the
covenant-prologue UTXO `22912a58…:0`, recoverable via `settle` (taker
key) or `forfeit` (maker key, after CLTV deadline 430806). Harnesses:
`build_prologue_ft.py`, `build_leg_a.py`, `build_leg_b.py`,
`build_leg_b_negatives.py`.

---

## Phase 4 fusion design note (2026-05-20) — splice the BTC/SPV half onto the FT prologue

**Goal:** produce one FT covenant = `<FT prologue + SPV finalize/forfeit> bd d0 <ref> dec0e9aa76e378e4a269e69d`, fusing the Phase-2-proven FT prologue with the production SPV covenant
(`gravity-rxd-prototype/contracts/maker_covenant_trade.rxd`, generated by
`generators/gen_maker_covenant.js 6 12 --flat --btc-type p2wpkh`).

### What stays identical (reuse verbatim)
The entire `finalize` SPV block from the production covenant: chain-identity
anchor (`h1Prev == btcChainAnchor`), the fixed 1-input segwit tx-layout
constraint, the N=6 header PoW checks (`nBits == expectedNBits ||
expectedNBitsNext`), the M=12 Merkle branch fold, root-membership
(`current == root1..root6`), and the BTC payment check (`value >=
btcSatoshis`, `scriptSection` prefix + `hash == btcReceiveHash`). The
`claimDeadline >= FLOOR` S1 guard stays. No `cancel` branch (C1 holds).

### What changes for FT (the contained delta)

1. **Constructor (gen flat path, lines 332–342).** Add FT params and drop the
   ones the FT epilogue/hardening subsume:
   - ADD `bytes36 REF` (the genesis ref — also pushed by the appended epilogue),
     `int amount` (exact FT units), `bytes32 expectedTakerFtHash`,
     `bytes32 expectedMakerFtHash`.
   - KEEP `makerPkh`, `btcReceiveHash`, `btcSatoshis`, `btcChainAnchor`,
     `expectedNBits`, `expectedNBitsNext`, `claimDeadline`.
   - DROP `takerRadiantPkh` and `totalPhotonsInOutput` (the taker destination
     is pinned by `expectedTakerFtHash`; the value is pinned exactly by the
     FT hardening, not a `>=` floor).

2. **Shared preamble (after the `claimDeadline` require, before `return`).**
   Prepend the Phase-2-proven FT hardening, which runs on BOTH branches:
   ```
   bytes36 ref = pushInputRef(REF);
   require(tx.outputs.length == 1);              // output-count clamp
   require(tx.outputs.refOutputCount(ref) == 1); // single ref
   require(tx.outputs.refValueSum(ref) == amount); // EXACT amount (== not >=, closes H2)
   ```

3. **finalize output routing (gen lines 473–478) →** replace the P2PKH route
   with hash-compare to the taker FT script:
   ```
   require(hash256(tx.outputs[0].lockingBytecode) == expectedTakerFtHash);
   ```
   (Drop the `LockingBytecodeP2PKH(takerRadiantPkh)` + `value >=` lines — the
   destination is the exact FT script, the value is the exact `refValueSum`.)

4. **forfeit (gen lines 484–489) →** keep `tx.time >= claimDeadline`, replace
   the route with `require(hash256(tx.outputs[0].lockingBytecode) ==
   expectedMakerFtHash);`.

5. **Append the FT epilogue** to the compiled bytecode (NOT in the .rxd source —
   the compiler would emit it differently): `bd d0 <ref-bytes> dec0e9aa76e378e4a269e69d`.
   This is the codeScriptHash boundary. The substituter does this after
   placeholder substitution, exactly as Phase-2 `build_prologue_ft.py` does.

### H1 — on-chain SPV-reuse binding (the security review's blocker)
The production covenant binds the BTC payment to `(btcReceiveHash,
btcSatoshis)`. Two concurrent FT offers from the same maker to the same BTC
address would both accept the same SPV proof. The off-chain dup-check is
insufficient for settle-by-anyone. **Binding:** derive `btcReceiveHash`
per-offer as `hash160( makerPubkey ‖ REF ‖ nonce )` (a fresh BTC receive
subaddress per offer), with the nonce a real distinct input so two
same-(maker,REF,amount) offers still differ. This is a Phase-4 generator+
builder concern; it is enforced on-chain because the covenant only accepts a
proof of payment to *its* committed `btcReceiveHash`. Prove on regtest/mainnet:
one BTC payment settles offer A but offer B's covenant REJECTS that proof.

### The two static guards that must pass on the fused, compiled artifact
Before any on-chain step (this is the novel Phase-4 risk):
1. **No bare `0xbd` (OP_STATESEPARATOR) in opcode position** anywhere in the
   compiled prologue+SPV block — else the codeScriptHash boundary shifts off
   the epilogue's `bd`. The SPV block is full of `split`/byte literals; a
   stray `0xbd` in opcode position (not push-wrapped) would break conservation.
   Walk with the opcode-aware walker; assert the FIRST opcode-position `0xbd`
   is the epilogue separator.
2. **`count_input_refs(full_script) == {REF: n}`** — exactly the genesis ref,
   no phantom. The large SPV block could contain a `0xd0`–`0xd8` byte in opcode
   position; the guard catches it.

If either guard fails, the SPV block needs a byte-level fix (push-wrap the
offending literal, or restructure) before proceeding — same class of fix as
the Phase-1 phantom-ref resolution.

### Build approach
Extend `gen_maker_covenant.js` with an FT mode (`--ft` flag): emit the FT
constructor params, the hardening preamble, and the hash-compare routes;
keep everything else. Generate, compile with `rxdc 0.1.0`, run the two static
guards, THEN the on-chain legs (fund FT into the fused covenant; finalize with
a real SPV proof; forfeit; negatives). Reuse `build_finalize_tx`'s SPV-proof
scriptSig assembly from pyrxd `gravity/transactions.py`.

### Phase 4 — fusion compiles + passes both static guards (2026-05-20)

The fused FT covenant is built (`fuse_ft_covenant.py` applies the 4 deltas to
a generated `gen_maker_covenant.js 6 12 --flat --btc-type p2wpkh` covenant)
and compiled: `GravityFtCovenant.rxd` / `.artifact.json`, `rxdc 0.1.0`,
**4819-byte** prologue (full SPV half + FT hardening + hash-compare routes).

**The novel Phase-4 risk is retired.** With realistic substituted params +
the appended `bd d0 <ref> dec0…` epilogue (full script 4936 B), both static
guards PASS:
- **Guard 1 (codeScriptHash boundary):** exactly one opcode-position `0xbd`,
  at offset 4886 = the epilogue separator. The entire SPV block — full of
  `split`/byte-literals — contains no bare `OP_STATESEPARATOR`, so the FT
  conserves exactly as the Phase-2 prologue did.
- **Guard 2 (phantom-free):** `count_input_refs` == `{genesis_ref: 2}` (the
  prologue push + epilogue push of the same ref dedup to one distinct ref).
  No `0xd0`–`0xd8` byte in the ~4.9KB SPV block was mis-parsed as a ref.

So the SPV+FT fusion is byte-valid by construction. Remaining Phase-4 work is
mechanical relative to this: the H1 per-offer `btcReceiveHash` binding, the
tx builders (reusing `build_finalize_tx`'s SPV scriptSig assembly), and the
on-chain legs (fund → finalize-with-real-SPV-proof → forfeit → negatives).
NOT yet proven on-chain — the guards are static; the spend still needs a
real SPV proof + `testmempoolaccept`.

---

## Phase 4 — H1 SPV-proof-reuse binding design (2026-05-20)

**Threat (security review, blocker).** `btcReceiveHash` and `btcSatoshis`
are committed *constructor* params (baked into the covenant bytecode →
part of the covenant address). The `finalize` SPV check is
`require(value >= btcSatoshis); require(hash == btcReceiveHash)`
(maker_covenant_trade.rxd:459/464). If two concurrent offers from the same
maker commit the **same** `btcReceiveHash`, one real BTC payment satisfies
**both** covenants' `finalize`. Since anyone can settle, an attacker
observes the payment, grabs the proof, and drains *both* FTs with one BTC
payment. An off-chain duplicate-address check is insufficient (the proof is
valid on-chain for both).

**Mitigation: per-offer derived BTC receive address. On-chain enforced by
construction.**

`btcReceiveHash := hash160( makerBtcChildPubkey(offerIndex) )` where
`makerBtcChildPubkey` is a BIP32 child of the maker's BTC key at a
per-offer index/path. pyrxd already has the machinery: `hd.bip32`
(`ckd`, `Xprv`/`Xpub`) and BRC-42 `PublicKey.derive_child`
(keys.py:125) — no new crypto.

Why this closes H1 on-chain (not just off-chain):
1. Each offer derives a **distinct** child pubkey → distinct
   `btcReceiveHash` → since `btcReceiveHash` is a code-script param, a
   **distinct covenant address**. Offer A and offer B are different
   scripts at different addresses.
2. Offer B's `finalize` runs `require(hash == btcReceiveHash_B)`. A proof
   of payment to A's address carries `hash == btcReceiveHash_A != _B` →
   **rejects**. One payment cannot satisfy two offers.
3. The maker controls the derived address (it's their own BIP32 child), so
   they can spend the received BTC later. The covenant requires only that
   payment *lands* there — no maker signature on the Radiant side.

**Closing the nonce-uniqueness gap the review flagged.** The earlier
"subaddress from (makerPkh, glyphRef, nonce)" framing had a free-floating
nonce that two same-(maker,REF,amount) offers could collide on. Here the
distinguishing input is the **BIP32 child index**, which is the offer's
identity and is *baked into the covenant address* — two offers with the
same index would be the literally same covenant UTXO (can't coexist
unspent), and different indices give different addresses. So uniqueness is
structural, not a hope about nonce entropy. The maker MUST use a fresh
index per offer; a wallet-side monotonic counter (or derive the index from
a hash of (REF, amount, timestamp)) suffices, and reuse is self-defeating
(it just re-funds the same covenant address).

**What the Taker verifies (Phase-3 thin check).** By **funding outpoint**
(not scripthash): the on-chain covenant at that outpoint commits a specific
`btcReceiveHash`; the Taker confirms it matches the offer they were given
and that no *other* live covenant shares it. Because the address is derived
and committed, "two live offers share a btcReceiveHash" is detectable and,
on-chain, harmless (they'd be the same covenant address).

**Build impact (Phase 4).**
- The FT offer factory derives the child BTC key at a fresh index and
  computes `btcReceiveHash` from it (record the index in the offer so the
  maker can later sweep the BTC).
- No covenant *script* change — `btcReceiveHash` is already a committed
  param; we only change how its value is *chosen* (derived, not a fixed
  maker address).
- On-chain proof (finalize leg): fund two FT covenants with different
  derived `btcReceiveHash`, build one SPV proof of payment to A's address,
  show A's `finalize` accepts and B's `finalize` **rejects** the same
  proof. This is the H1 blocker test, run at the Phase-4 on-chain gate.

### Phase 4 — fused covenant FUNDS + FORFEITS on-chain (2026-05-20)

The fully-substituted fused FT covenant (~4.9KB) was exercised on the live
mainnet node with real broadcasts:

- **Funding (broadcast `5a9cfc47…`):** standard FT → fused-covenant FT UTXO.
  `testmempoolaccept` allowed, then broadcast. Re-confirms conservation on
  the production-shaped covenant (not just the bare Phase-2 prologue). The
  funding tx is ~5.3KB (the covenant output is ~4.9KB) → ~53M-photon fee at
  the 10k/byte floor; size is the real cost of the SPV half.
- **Forfeit (broadcast `f0d8c4fe…`):** spend the fused covenant via `forfeit`
  (selector OP_1, CLTV `tx.time >= claimDeadline`, nLockTime 1779000000) →
  standard MAKER FT output. `testmempoolaccept` allowed, broadcast; FT
  recovered to the maker as a standard FT, conserving.

**Forfeit scriptSig discipline (learned on-chain):** `forfeit()` takes NO
params and does NO sig check — it is gated by CLTV alone (anyone may
broadcast after the deadline; the FT goes to the maker's FT address
regardless, matching production `forfeit()` and the trust-minimized model).
A first attempt pushed `<makerSig> <makerPk> OP_1` and was rejected with
`non-mandatory-script-verify-flag (Extra items left on stack)` — the branch
never consumes a sig. Correct scriptSig is the bare `OP_1` selector (bare
covenant → no redeem-script push).

**Still unproven on-chain:** the `finalize` (settle) path with a real SPV
proof, and the H1 two-offer-rejection test. Forfeit needs no BTC proof, so
it proved the funding + conservation + FT-recovery half of the fused
covenant; finalize is the remaining cross-chain leg.

### Phase 4 — finalize/settle PROVEN with a real SPV proof (2026-05-20)

The fused FT covenant's `finalize` (SPV-gated settle) path is now proven on
the live mainnet node — the cross-chain leg, completing the swap.

**Approach.** A synthetic-but-PoW-valid chain (anchor `0x99*32`,
nBits `0x1d7fffff`) is sufficient: the covenant runs the *same*
PoW/Merkle/anchor checks the Python verifier does, so the node accepts it
iff the covenant bakes the matching `btcChainAnchor`/`expectedNBits`. No
real Bitcoin block needed — fetching one is unnecessary for the consensus
proof. (`build_finalize_proof.py` mines 6 chained headers via the real
`verify_header_pow` grinder; the payment's Merkle root is in h1, h2–h6 are
filler. Verified against `SpvProofBuilder` before going on-chain.)

**On-chain (real broadcasts):**
- Funded the FT into a fused covenant baked with the proof's SPV params
  (funding `0518ab7e…`).
- `finalize` (`d7877fcb…`): covenant FT input + SPV scriptSig
  (`<h1>..<h6> <branch 12-level sentinel-padded> <rawTx> OP_0`) + fee →
  standard TAKER FT. `testmempoolaccept` allowed, then broadcast; FT
  settled to the taker, conserving. The covenant executed the full SPV
  block (anchor + 6× PoW + 12-level Merkle + P2WPKH payment to
  `btcReceiveHash` ≥ `btcSatoshis`) + the 3 FT hardening constraints +
  hash-compare + FT epilogue conservation.

**Both spend paths of the fused FT↔BTC covenant are now proven end-to-end
on a real mineable chain:** fund→forfeit (recovery) and
fund→finalize-via-SPV (settle). The conservation + custody + hardening +
cross-chain-atomicity halves are all validated on mainnet consensus.

**Still remaining (designed, not yet on-chain):** the H1 two-offer-
rejection test (fund two covenants with different derived `btcReceiveHash`,
one proof → A accepts / B rejects); production builders + golden vectors;
`--ft` generator mode; then external audit before mainnet activation.

### Phase 4 — H1 SPV-proof-reuse PROVEN closed on-chain (2026-05-20)

The per-offer-derived `btcReceiveHash` binding is now empirically validated
on the live mainnet node, with both controls:

- **Distinct covenants:** covenant A (`btcReceiveHash` = `25db43…`) and
  covenant B (`btcReceiveHash` = `140b40…`) compile to **different**
  scriptPubKeys → different covenant addresses (the binding is structural,
  not entropy-based).
- **Negative (the security property):** funded covenant B (`eeae386a…`),
  attempted `finalize` with the SPV proof that pays **A** → REJECTED with
  `mandatory-script-verify-flag-failed (OP_EQUALVERIFY)`, exactly at the
  covenant's `require(hash == btcReceiveHash)` payment check. **A payment
  to offer A's address cannot settle offer B.**
- **Positive control:** a freshly-mined proof paying **B** → covenant B
  `finalize` ACCEPTED (`2d5c332d…`, broadcast). So the rejection is
  specifically the address mismatch, not an incidental failure.

**Conclusion:** the SPV-proof-reuse attack (security review H1) is closed
on-chain by construction. Since each offer's per-offer-derived
`btcReceiveHash` produces a distinct covenant that only honors a payment
to its own committed address, one BTC payment cannot drain two concurrent
offers. This was the last security-critical on-chain proof.

---

## Any-wallet BTC payment — design note (2026-05-20)

**Problem.** The current covenant's BTC-payment check requires a
**single-input** tx with the payment at a **fixed output offset** (47 for
native segwit, 70 for P2SH-P2WPKH; `maker_covenant_trade.rxd:45-67`). Most
real wallets draw from **multiple UTXOs** and place change anywhere, so a
normal "send to this address" payment is **rejected — and there is no BTC
refund path** (`gravity-rxd-prototype/docs/SEGWIT_SUPPORT.md`). For a usable
FT↔BTC swap the taker must be able to pay from any standard wallet.

**Why the redesign is SAFE (the load-bearing fact).** The covenant binds
the BTC tx by hashing it as the Merkle leaf: `current = hash256(rawTx)`
(`maker_covenant_trade.rxd:337`), then folds the branch up to a real,
PoW-verified header's merkle root. **So `rawTx` is cryptographically pinned
to a real Bitcoin block — an attacker cannot supply a forged tx.** Given a
pinned tx, the covenant may parse its bytes any way it likes.

The audit-03-C2 finding was NOT "parsing is unsafe" — it was specifically
that an **attacker-supplied `outputOffset` unlocking arg** could point the
payment check at arbitrary bytes (forging a payment from unrelated tx
data). The fix removed that arg and hard-coded the offset, at the cost of
wallet compatibility. **The correct any-wallet fix preserves C2's intent
even better: the covenant computes every offset ITSELF from the pinned tx —
no attacker-supplied offsets anywhere.**

**Design — on-chain parse of the pinned `rawTx`:**

1. **Strip is already handled** (the proof carries the witness-stripped tx;
   `hash256(stripped) == txid` is enforced upstream in the verifier and the
   leaf binding makes the covenant parse the same bytes).
2. **Skip version (4B).**
3. **Read input-count varint** at offset 4. Support the 1-byte form
   (`< 0xfd`, i.e. ≤252 inputs — covers every real tx); reject `0xfd/fe/ff`
   (absurd input counts) to avoid multi-byte varint handling. This is a
   *covenant-chosen* bound on the pinned tx, not an attacker offset.
4. **Skip N inputs.** Each input = 36B outpoint + scriptSig-len varint +
   scriptSig + 4B sequence. After witness-strip, scriptSig is empty for
   native segwit (`00`) and fixed-23B for P2SH-P2WPKH. To support arbitrary
   single-sig segwit inputs the loop reads each input's scriptSig-len varint
   (1-byte form) and skips that many bytes — a bounded per-input walk,
   unrolled up to a max-input cap (e.g. 4–8 inputs, the common case;
   document the cap like the Merkle-depth cap).
5. **Read output-count varint**, then **scan each output** (8B value +
   scriptPubKey-len varint + scriptPubKey): for the one whose scriptPubKey
   == the expected `btcReceiveType`/`btcReceiveHash` shape, require its
   value ≥ `btcSatoshis`. Scanning (vs. fixed index) is what lets change sit
   anywhere. The scan is over the *pinned* tx, so it's forgery-proof.
6. **Everything else unchanged:** the 6-header PoW chain, the Merkle fold,
   and (for the FT covenant) the FT hardening + hash-compare output routing.

**Caps to document (analogous to Merkle-depth sentinel padding):**
- max inputs skipped (script size grows ~linearly; pick 4–8, unrolled).
- max outputs scanned (same).
A tx exceeding the caps is rejected — a *liveness* limit (taker consolidates
or trims change), never a *safety* hole.

**Cost.** GRAVITY_ANALYSIS.md estimated ~200–400 extra script bytes for the
input-skip + output-scan; with input/output caps unrolled it is larger but
bounded. The fused FT covenant is already ~4.9KB; this adds to funding fee
(already ~0.5 RXD). Acceptable for the capability.

**Re-prove plan (this is a security-critical SPV-parsing change):**
1. Implement as a generator mode (extends `gen_maker_covenant.js`); keep the
   single-input fast path or replace it.
2. Static guards on the compiled artifact (no bare `0xbd`; single ref).
3. On-chain finalize proof with a **multi-input, change-first** synthetic
   tx (the shape the old covenant rejected) → must ACCEPT; plus the negative
   cases (no payment to `btcReceiveHash` → reject; value < `btcSatoshis` →
   reject; payment present but to wrong hash → reject).
4. **External audit of the new parsing path is a hard gate** — it is the
   most security-critical code in the covenant (it decides "did the BTC
   payment really happen?"). Do not announce an any-wallet swap as
   production-ready before that audit.

**Status:** designed, not built. The existing constrained covenant remains
the proven one (single-input P2WPKH/P2TR/P2SH-P2WPKH). The live FT offer
`85ae317e…:0` uses the constrained covenant and is forfeitable.
