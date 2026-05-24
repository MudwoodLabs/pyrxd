---
title: Gravity NFT↔BTC atomic swap covenant
type: feat
date: 2026-05-23
status: draft — revised after divergent review (2026-05-23)
---

# Gravity NFT↔BTC atomic swap covenant

> **Divergent review (2026-05-23)** — security-sentinel + architecture-strategist
> + code-simplicity-reviewer, parallel + independent. One **Critical** finding
> corrected a falsified KEY FACT (verified against Radiant Core source):
>
> - **C1 — singleton conservation is COVENANT-ONLY, not consensus.** Consensus
>   (`validatePushRefRule`, `validation.h:919-934`; `validateDisallowedSiblingsRefRule`,
>   `:945-968`) only enforces **outputs ⊆ inputs** and "the singleton may not
>   appear on a *different*-than-allowed output." It does **NOT** require the
>   singleton to appear on any output — **consensus permits BURNING the NFT
>   (zero output copies).** So "exactly one output" is enforced *solely* by the
>   covenant's `outputs.length==1` + `refOutputCount(ref)==1`. There is **no
>   consensus backstop.** For an irreversible one-of-one, a finalize that burns
>   the NFT (BTC already paid) is consensus-valid; only the covenant stops it.
>   The earlier draft's claim that consensus disallow-siblings gives a
>   redundant "exactly one" guarantee was **wrong.**
>
> Other folded findings: carrier-value must be PINNED (not optional — a
> dropped amount check with no carrier-value floor can make the honest
> single-output finalize unconstructable → strand the NFT); the C1-custody
> invariant (no maker-only pre-deadline reclaim) must be stated + tested; the
> phantom-ref guard lost its `0xbd` positional anchor (count-only is too weak —
> needs parser-equivalence + offset-0 singleton anchor); the on-chain harnesses
> are rewrites not "adapts" (the FT post-compile epilogue append *deletes* for
> NFT; the `bd`-position guard *inverts*); Phases 1+2 merged; several
> self-admittedly-harmless checks cut.

## Overview

Add **NFT↔BTC** atomic swaps to Gravity, as a follow-on to the FT↔BTC swap
(proven end-to-end on mainnet, single-input + any-wallet — see
[2026-05-20-feat-gravity-ft-covenant-spend-path-plan.md](2026-05-20-feat-gravity-ft-covenant-spend-path-plan.md)
and `docs/brainstorms/gravity-ref-spike/REAL_SWAP_RESULT.md`).

The design is settled in
[2026-05-23-gravity-nft-swap-design.md](../brainstorms/2026-05-23-gravity-nft-swap-design.md).
**The headline: NFT is a separate design from FT but is actually *simpler*,
and the NFT delta over the proven FT covenant is small.** Most of the covenant
(the entire BTC-verification half) is reused verbatim; this plan is mostly
"swap the FT prologue/hardening for the NFT equivalents and re-prove on-chain."

**Do not over-build.** The BTC half is done and mainnet-proven. The new
surface is: an NFT-shaped covenant prologue, two hardening tweaks, NFT
expected-hashes, and the on-chain proof.

## Problem Statement

The FT swap covenant only handles fungible tokens. A maker who wants to sell a
**one-of-one NFT** (a Glyph singleton) for BTC, trustlessly, can't use it — the
FT covenant is welded to the FT code-script and enforces an amount, neither of
which fits a singleton.

## Proposed Solution (from the design note, verified against Radiant Core source)

**Why NFT ≠ FT (and why it's simpler — CORRECTED after review):** NFT
singleton conservation (`OP_PUSHINPUTREFSINGLETON`, `script.cpp:601-606`)
enforces only that (a) any singleton ref on an OUTPUT traces to an INPUT
(`validatePushRefRule`, outputs ⊆ inputs, `validation.h:919-934`), and (b) the
ref does not appear on a *different* output than the disallow-sibling op
designates (`validateDisallowedSiblingsRefRule`, `:945-968`). **Consensus does
NOT require the singleton to appear on any output — it permits the NFT to be
burned (zero output copies), and it does not weld the NFT to any code-script
(no `codeScriptHashValueSum`).** So:
- An NFT **can be held directly in a covenant** (no code-script weld) — this is
  what makes the design simpler than FT, and it is correct.
- **BUT "exactly one output" is a COVENANT property, not a consensus one.** The
  only thing forcing the singleton onto exactly one output *that is the taker's
  NFT* is the covenant's `outputs.length==1` + `refOutputCount(ref)==1` +
  hash-compare. **Consensus provides no backstop against a burn or a
  misdirected NFT.** For an irreversible one-of-one, the covenant body is the
  sole guarantor of conservation — strictly more load-bearing than in FT
  (where consensus `codeScriptHashValueSum` independently enforced FT value
  conservation). This is the dominant security fact for the whole design.

**The two candidate designs converge.** NFT script is
`d8 <ref:36> 75 76a914<pkh>88ac` (63 B, no `OP_STATESEPARATOR`): `d8<ref>`
pushes the ref, `75` (`OP_DROP`) drops it, the trailing P2PKH is the spend
auth. Replacing the trailing P2PKH with covenant logic yields:

```
d8 <ref> 75 <covenant-logic>
```

This single form **both holds the singleton (the covenant UTXO carries the
NFT) AND gates its release** — "lock-into-covenant" and "spend-path-gating" are
the same construction for NFT. **Chosen: this converged form.**

Spend paths (BTC half **reused verbatim** from the FT any-wallet covenant):
- **finalize(SPV proof):** verify the BTC payment (anchor + N=12 headers PoW +
  M=20 sentinel Merkle; the 4-way output-type scan P2WPKH/P2PKH/P2SH/P2TR; the
  varint multi-input parser; `btcReceiveHash` match — NOTE: the "per-offer
  derived H1 binding" was NEVER implemented, see C-ECON-1; payment is bound only
  by receiveHash+satoshis+anchor), then
  `require(hash256(tx.outputs[0].lockingBytecode) ==
  EXPECTED_TAKER_NFT_HASH)`.
- **forfeit(CLTV):** after the deadline,
  `require(hash256(tx.outputs[0].lockingBytecode) == EXPECTED_MAKER_NFT_HASH)`.

`EXPECTED_*_NFT_HASH = hash256(build_nft_locking_script(dest_pkh, ref))`
([glyph/script.py:127](../../src/pyrxd/glyph/script.py#L127)). Hash-compare (not
embedded bytes) avoids the phantom-ref hazard, exactly as in FT.

## Technical Approach

### Reuse vs new (the delta is small)

| Component | Status | Source |
|---|---|---|
| BTC SPV half (anchor, N=12 PoW, M=20 sentinel Merkle) | **Reuse verbatim** | FT any-wallet covenant `GravityFtCovenantAnyWallet20.rxd` |
| 4-way output-type scan (P2WPKH/P2PKH/P2SH/P2TR) | **Reuse verbatim** | `fuse_anywallet.py` `_scan_one` |
| Varint multi-input parser + caps | **Reuse verbatim** | `fuse_anywallet.py` input-skip |
| H1 per-offer `btcReceiveHash` binding | ⚠️ **NOT IMPLEMENTED** (audit 2026-05-24 C-ECON-1) | claimed BIP32 derivation does not exist; cross-offer replay unmitigated — use a fresh BTC addr per offer |
| Anchor-just-in-time + wide-N/M operational lessons | **Reuse** | [feedback_gravity_anchor_timing] (memory) |
| `count_input_refs` phantom-ref guard | **Reuse** | `glyph/script.py` |
| NFT prologue `d8<ref>75` (NEW) | **New** | replaces FT `P2PKH + bd + d0<ref> + epilogue` |
| Hardening (NFT variant) | **Modified** | drop `refValueSum==AMOUNT`; keep `outputs.length==1` + `refOutputCount(ref)==1`; **ADD `tx.outputs[0].value == NFT_CARRIER_VALUE`** (see review: pinned, not optional) |
| Expected-hashes = NFT scripts (NEW) | **New** | `build_nft_locking_script` |
| NFT covenant fuse transform (NEW) | **New** | `fuse_nft_covenant.py` (analog of `fuse_ft_covenant.py`) |
| `build_fused_ft_spk.py` analog | **REWRITE (not adapt)** | the FT version appends the epilogue POST-COMPILE (`bd d0 <ref> dec0…`, line 98) + a `bds==[len(prologue)]` guard; **NFT has no epilogue** (ref is in the prologue) and **no `0xbd`** → the epilogue-append deletes and the `bd` guard inverts. The funded NFT UTXO is the compiled script verbatim. |
| `fund_fused.py` / `build_ft_finalize.py` analogs | **Adapt + 1 decision** | re-point FT-input plumbing at the NFT-shaped input; **decide the NFT carrier output value** (the `FT_AMOUNT` slot) — must agree across the covenant pin, the fund tx, and the finalize tx |
| `fuse_anywallet.py` (reused) — ordering coupling | **Reuse, with a contract** | it is anchored to the literal contract name `GravityFtCovenantFlat` (line 99) + exact-indent source strings (lines 24, 95); `fuse_nft_covenant.py` must NOT rename the contract before any-wallet runs, or that transform silently no-ops. Document the transform-order contract. |
| NFT mint | **Reuse** | `examples/glyph_mint_demo.py` (commit/reveal, `DRY_RUN`/`GLYPH_WIF`, like the FT premine) |

### NFT-specific deltas (the entire new surface)

1. **Prologue:** `d8 <ref> 75` instead of FT's `76a914<pkh>88ac bd d0 <ref>
   dec0…`. The covenant body runs after `OP_DROP`.
2. **Hardening (CARRIES ALL OF NFT CONSERVATION — there is no consensus
   backstop, per C1):**
   - KEEP `tx.outputs.length == 1` — output-count clamp.
   - KEEP `tx.outputs.refOutputCount(ref) == 1` — forces the singleton onto
     exactly one output. **This is the sole guard against burning the NFT**
     (consensus permits zero output copies). Treat as a Critical invariant,
     not "hardening."
   - **DROP** `tx.outputs.refValueSum(ref) == AMOUNT` — a singleton has no
     amount.
   - **ADD `tx.outputs[0].value == NFT_CARRIER_VALUE`** (a constructor param,
     a fixed dust e.g. 1000 photons). **Pinned, not optional** (review): with
     `outputs.length==1` and no carrier-value constraint, the honest finalize
     tx may be unconstructable (no clean single-output balance) → a paid taker
     strands an irreversible NFT. Pin it so the single-output tx is always
     constructable, and so the fund/finalize/expected-hash all agree.
3. **Expected-hashes:** `EXPECTED_*_NFT_HASH` from `build_nft_locking_script`
   (the standard 63-B NFT script), not the FT script.
4. **Custody invariant (C1, carried from the FT review — STRICTER here):**
   the covenant has **exactly two spend selectors** — finalize(SPV proof) and
   forfeit(`tx.time >= claimDeadline`) — and **NO branch releases the NFT to
   the maker before `claimDeadline`** (no cancel/else fall-through). Because
   the NFT is *held in* the covenant (not gating a separate UTXO), a
   pre-deadline maker-reclaim path = clean theft of a paying taker's BTC.
   Verify the fuse preserves exactly the two-selector structure (no else
   branch); prove the negative on-chain (Phase 3).
5. **Phantom-ref guard (UPGRADED — the `0xbd` anchor is gone):** the leading
   `d8<ref>` is the intended singleton (offset 0, 36-B operand). The guard must
   do more than count: (a) **parser-equivalence** — confirm `count_input_refs`
   walks opcode-lengths identically to consensus `GetPushRefs` so a body byte
   mis-parsed as a ref can't slip past a count==1; (b) **positional anchor** —
   assert the singleton sits at offset 0 with a 36-B operand and `0x75`
   immediately after (manually reintroducing the positional check FT got from
   its `0xbd` boundary); (c) no other `0xd0`–`0xd8` reachable in opcode
   position. A bare `0xbd` is harmless for NFT — do NOT spend effort guarding
   it; the real hazard is a stray ref-opcode.

### Implementation Phases

Three phases (review merged the two no-spend phases): build+statically-validate
(no spend) → on-chain proof gate → audit gate.

#### Phase 1 — Build, compile, statically validate (no spend, ~1–1.5 day)

- [ ] `fuse_nft_covenant.py`: transform a generated `12 20 --flat
  --btc-type p2wpkh` covenant into the NFT form — replace the prologue with
  `d8<ref>75` + the NFT hardening (drop amount, ADD the `outputs[0].value ==
  NFT_CARRIER_VALUE` pin), keep the BTC half. **Transform-order contract:** do
  NOT rename the contract before `fuse_anywallet.py` runs (it matches the
  literal `GravityFtCovenantFlat` name + exact-indent strings, lines 24/95/99);
  rename last. Then apply the **existing** `fuse_anywallet.py` (BTC-payment
  block unchanged — confirm its anchors still match).
- [ ] Compile with local `rxdc 0.1.0` → `GravityNftCovenantAnyWallet20.rxd` /
  `.artifact.json`. Confirm `compilerVersion` stamp matches shipped artifacts.
- [ ] Constructor params: `REF`, `btcReceiveHash`, `btcSatoshis`,
  `btcChainAnchor`, `expectedNBits`, `expectedNBitsNext`, `claimDeadline`,
  `NFT_CARRIER_VALUE`, `expectedTakerNftHash`, `expectedMakerNftHash`
  (note: **no `amount`**).
- [ ] **Static guard (upgraded — replaces the FT `bds==[len(prologue)]` check,
  which inverts for NFT):** on the substituted artifact (the funded UTXO is the
  compiled script verbatim — NO epilogue append):
  - `count_input_refs == {genesis singleton}` AND the singleton sits at offset
    0 with a 36-B operand and `0x75` at offset 37 (positional anchor).
  - parser-equivalence: `count_input_refs` walks opcode-lengths identically to
    consensus `GetPushRefs` (so a count==1 can't hide a mis-parsed body ref).
  - (No `0xbd` guard — harmless for NFT.)
- [ ] Extend `validate_anywallet_parse.py`: add a settlement-output check that
  output[0] is a valid 63-B NFT script for the taker (`is_nft_script` +
  `extract_ref_from_nft_script`). **Cut the Python consensus-rule
  re-derivation** (review): let Phase-3 `testmempoolaccept` be the authority on
  singleton conservation, not a Python reimplementation of `validation.h`.

**Success:** compiles clean; ABI has the expected params incl `NFT_CARRIER_VALUE`,
no `amount`; the upgraded guard passes; NFT settlement-output check passes.

#### Phase 2 — On-chain proof on mainnet (the hard gate, ~0.5 day active + ~1–2 h waiting)

Apply the hard-won operational lessons up front (see
[feedback_gravity_anchor_timing]): **anchor set just-in-time** (= payment
block − 1, after the payment confirms), **wide N=12 / M=20**, **near forfeit
deadline** (now + a few hours, so test assets are recoverable).

- [ ] Mint a fresh NFT via `examples/glyph_mint_demo.py` (`DRY_RUN=0`,
  `GLYPH_WIF=<funded>`). Capture the genesis ref + 63-B NFT script.
- [ ] Send a real BTC payment to the maker's derived address **first**
  (single-input is fine, or multi-input to also re-exercise the any-wallet
  parser); wait for confirmation; capture block B.
- [ ] Bake the NFT covenant: `btcChainAnchor = block B−1`, `expectedNBits`
  from B, near deadline; run the static guards on the substituted artifact.
- [ ] Fund the NFT into the covenant (`d8<ref>75<body>` UTXO).
- [ ] Build the real-headers SPV proof (12 headers B..B+11, real Merkle of the
  payment in B, sentinel-padded to 20) and **finalize** →
  `testmempoolaccept` then broadcast → **NFT settles to the taker as a
  standard NFT** (singleton conserved). **This is the headline proof.**
- [ ] **Forfeit path:** fund a SECOND covenant with a near deadline (don't wait
  out a long deadline) and prove forfeit → NFT back to maker.
- [ ] **Negatives (must reject on-chain). The covenant-only invariants (C1)
  matter most — consensus does NOT back them:**
  - **NFT-burn (covenant-only, NEW):** a finalize producing **zero** outputs
    carrying the ref → must reject via `refOutputCount==1`. (Consensus *permits*
    this; the covenant is the only stop.)
  - **two-output clone (covenant-only, NEW):** `outputs.length==2`, output[0]
    = taker NFT, output[1] also carries the ref → must reject via
    `outputs.length==1`.
  - **pre-deadline maker reclaim (C1-custody, NEW):** attempt to release the
    NFT to the maker before `claimDeadline` → must reject (no such branch).
  - **wrong carrier value (NEW):** output[0] value ≠ `NFT_CARRIER_VALUE` →
    must reject (the pin) — and confirm the honest single-output finalize IS
    constructable at that value.
  - no-payment: a real in-block tx that doesn't pay the maker → reject
    (`OP_VERIFY` / `require(found)`).
  - wrong destination: settlement output is an NFT to the *wrong* pkh → reject
    (hash-compare).
  - **SPV-proof cross-offer replay:** ⚠️ only rejects when offers use DIFFERENT
    `btcReceiveHash` (trivial). Same-address reuse → one proof finalizes both
    (C-ECON-1, UNMITIGATED; the "per-offer binding" was never built).
- [ ] **Re-run the any-wallet parser negatives** (wrong-hash, insufficient-
  value) against the NFT-fused artifact — the parser now runs inside a
  structurally different script; don't assume "verbatim reuse" transfers
  (architecture review).
- [ ] Sweep the maker BTC back to the user; recover the NFT (settle or
  forfeit). No test asset stranded.

**Success:** finalize accepted + broadcast on mainnet; forfeit proven; ALL
negatives reject on-chain (especially the covenant-only burn/clone/reclaim
trio); both-chain txids recorded; BTC swept back.

#### Phase 3 — Audit gate + docs (hard gate before any production claim)

- [ ] Document the NFT result in `REAL_SWAP_RESULT.md` (both-chain txids,
  honest scope).
- [ ] **External audit of the SPV/BTC-tx parser (shared FT+NFT) is a HARD
  GATE** before any production/mainnet-product claim. **NFT irreversibility
  (one-of-one, no fungible make-whole) raises the bar** above FT — a parser
  bug that forges a payment steals an irreplaceable asset; and per C1, the
  covenant body is the *sole* guarantor of singleton conservation (no consensus
  backstop), so the auditor must scrutinize `outputs.length==1` +
  `refOutputCount==1` + the no-burn/no-clone/no-pre-deadline-reclaim properties
  specifically.
- [ ] The convergence rationale is recorded in the design note + Alternatives
  table (no separate deny-list task needed — review).

## Alternative Approaches Considered

| Alternative | Why rejected |
|---|---|
| **Lock-into-covenant vs spend-path-gating as two designs** | They **converge** for NFT (`d8<ref>75<body>` does both) — no choice needed. Documented in the design note. |
| **Reuse the FT covenant with a `refKind` param** | Different conservation semantics (singleton vs amount) + branch-confusion security risk (flagged in the FT divergent review). Separate artifact, separate audit surface. |
| **Hold the NFT outside the covenant (pre-signed atomic)** | The whole point is trustless custody; lock-into-covenant gives on-chain custody for free (NFT conservation permits it). |
| **Embed the NFT script bytes for output validation** | Phantom-ref hazard (a `0xd8` byte mis-parsed as a singleton). Hash-compare instead, as proven for FT. |

## Acceptance Criteria

### Functional
- [ ] **NFT swap end-to-end on mainnet:** maker locks a Glyph NFT; taker pays
  BTC; taker settles via SPV proof; the singleton NFT lands on the taker's
  address; no duplication AND no burn.
- [ ] **Forfeit:** maker reclaims the NFT singleton after `claimDeadline` (via
  a near-deadline test covenant); NO maker reclaim before the deadline.
- [ ] **Any-wallet / 4-way receive:** reuse confirmed (taker multi-input;
  maker P2WPKH/P2PKH/P2SH/P2TR).
- [ ] **Negatives reject on-chain:** the covenant-only trio (NFT-burn,
  two-output clone, pre-deadline maker reclaim) PLUS no-payment, wrong
  destination, wrong carrier value, SPV-proof cross-offer replay.

### Non-functional
- [ ] **Upgraded** phantom-ref guard: one (genesis singleton) ref at offset 0
  with `0x75` at 37; parser-equivalence with consensus `GetPushRefs`.
- [ ] Carrier value pinned (`outputs[0].value == NFT_CARRIER_VALUE`); honest
  single-output finalize proven constructable.
- [ ] Genesis-ref discipline (the singleton ref is the NFT's identity).
- [ ] All on-chain test assets recoverable (near deadline; BTC swept back).
- [ ] Honest scope recorded: what's proven on-chain vs designed-but-unproven.

### Quality gates
- [ ] Phase-1 static guard passes before any spend.
- [ ] On-chain finalize + forfeit + ALL negatives proven (Phase 2) before any
  "NFT swap works" claim — **especially the covenant-only burn/clone/reclaim
  trio (no consensus backstop, C1).**
- [ ] **External audit of the parser (hard gate) before any production claim**
  — weightier than FT due to NFT irreversibility + covenant-only conservation.

## Risk Analysis & Mitigation

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| **NFT burned on finalize** (consensus permits zero output copies — C1) | Med | **Critical** (irreversible) | Covenant `refOutputCount(ref)==1` is the SOLE guard; prove the zero-output-burn negative rejects on-chain (Phase 2) — no consensus backstop |
| **Pre-deadline maker reclaim** (NFT held in covenant; would steal a paying taker's BTC) | Med | **Critical** | Exactly two spend selectors, no cancel/else branch; prove the pre-deadline-reclaim negative rejects on-chain |
| **Honest single-output finalize unconstructable** → NFT stranded | Med | High | Pin `outputs[0].value == NFT_CARRIER_VALUE`; prove constructability on-chain |
| Phantom ref from body bytes (no `bd` boundary) | Med | High | Upgraded guard: parser-equivalence + offset-0 positional anchor; hash-compare keeps NFT bytes out |
| Anchor-timing / Merkle-depth mismatch (the 2 FT stumbles) | Med | Med | Apply both lessons up front: anchor=payment_block−1 just-in-time, M=20, wide N=12, near deadline |
| SPV-proof cross-offer replay | **Med** | High | ⚠️ UNMITIGATED (C-ECON-1) — per-offer binding never built; mitigated only by maker using a fresh BTC addr per offer. Real fix = offer-committed derived address or OP_RETURN tag |
| NFT irreversibility magnifies any parser/covenant bug | — | High | External audit is a hard gate; this is the dominant reason it matters more than FT |
| Funding the ~11 KB covenant is expensive (~1 RXD) | High | Low | Known cost (same as FT M=20); recover via settle/forfeit |

## Success Metrics

| Metric | Measurement | Target |
|---|---|---|
| NFT swap atomic on mainnet | finalize broadcast + NFT at taker | Yes |
| Forfeit works | NFT reclaimed after deadline | Yes |
| Negatives reject | `testmempoolaccept` reject reasons captured | All 3 reject |
| Reuse ratio | new covenant bytes vs FT any-wallet | majority reused (BTC half verbatim) |
| Test assets recovered | NFT + BTC accounted for | 100% (minus network fees) |

## Divergent review outcomes (2026-05-23)

Three reviewers, parallel + independent (security-sentinel, architecture-strategist,
code-simplicity-reviewer). No contradictions between them; one Critical
correction verified against source.

| Sev | Finding | Disposition |
|---|---|---|
| **Critical** | "Consensus enforces exactly-one-output" is FALSE — consensus permits NFT burn (zero copies); conservation is COVENANT-only | **Folded.** KEY FACT corrected; added on-chain burn + two-output negatives; flagged the covenant as sole guarantor throughout |
| High | Carrier value: dropping the amount check with no replacement can make the honest single-output finalize unconstructable → strand the NFT | **Folded.** `NFT_CARRIER_VALUE` pin is now required (not optional); constructability proven on-chain |
| High (C1) | "No maker-only pre-deadline reclaim" custody invariant not stated/tested (worse than FT — NFT is held *in* the covenant) | **Folded.** Stated as invariant; pre-deadline-reclaim negative added |
| High | Lost `0xbd` positional anchor → count-only phantom-ref guard too weak | **Folded.** Guard upgraded: parser-equivalence + offset-0 singleton anchor |
| High (arch) | Harnesses are rewrites not "adapts" (FT epilogue-append *deletes*; `bd`-guard *inverts*); `fuse_anywallet.py` name/indent coupling | **Folded.** Reuse table relabeled; transform-order contract documented |
| Med | BTC-half residual risks (reorg/N, SPV replay, parser caps) become irreversible; params inherited from FT un-re-derived | **Folded.** SPV-replay negative added; N documented as a per-offer knob (raise for high-value) |
| Simplicity | Phases 1+2 merge; cut Guard 2, the Python consensus re-derivation, the dust-pin *optionality*, the self-canceling deny-list, the forfeit either/or | **Folded** (dust-pin: resolved to *required pin*, satisfying both the simplicity cut and the security need) |

**Endorsed (kept):** the convergence of the two NFT designs; the three-phase
shape; reuse of the BTC half; the audit gate; all Phase-2 negatives.

## Future Considerations

- Container NFTs / multi-ref glyphs (the v1 covenant assumes a single
  singleton ref; `outputs.length==1` + `refOutputCount==1` would need
  rethinking for multi-ref).
- Mutable NFTs (`build_mutable_nft_script`) have a different shape
  (`20<hash>75bd d8<ref>…`) — separate analysis if ever needed.
- Production builders (the spike harnesses → `src/pyrxd/gravity/`),
  generator `--nft` mode (currently a post-process fuse transform).

## References

### Internal
- **Design note:** [2026-05-23-gravity-nft-swap-design.md](../brainstorms/2026-05-23-gravity-nft-swap-design.md)
- **FT plan (the pipeline this mirrors):** [2026-05-20-feat-gravity-ft-covenant-spend-path-plan.md](2026-05-20-feat-gravity-ft-covenant-spend-path-plan.md)
- **FT real-swap results (incl any-wallet):** `docs/brainstorms/gravity-ref-spike/REAL_SWAP_RESULT.md`
- **NFT script + helpers:** [glyph/script.py:127](../../src/pyrxd/glyph/script.py#L127) (`build_nft_locking_script`), `:199` (`is_nft_script`), `:258` (`extract_ref_from_nft_script`)
- **NFT mint:** `examples/glyph_mint_demo.py`
- **FT fuse pipeline (mirror these):** `docs/brainstorms/gravity-ref-spike/fuse_ft_covenant.py`, `fuse_anywallet.py`, `build_fused_ft_spk.py`, `fund_fused.py`, `build_ft_finalize.py`, `build_finalize_proof*.py`, `validate_anywallet_parse.py`
- **Covenant generator:** `gravity-rxd-prototype/generators/gen_maker_covenant.js`
- **Consensus source:** `Radiant-Core/src/validation.h` (singleton rule), `src/script/script.cpp:601-606`, `:644`

### Conventions
- Spike harnesses in `docs/brainstorms/gravity-ref-spike/`; WIFs/txids in gitignored dotfiles; branch `feat/gravity-ref-ft-covenant-spike`.
- Operational lessons: [feedback_gravity_anchor_timing] (anchor just-in-time, wide N/M, near deadline).
- Honesty: separate proven-on-chain from designed-but-unproven in every writeup.

## Provenance: proven vs. designed-but-unproven

**Proven on mainnet (reused):** the entire BTC half — SPV verify, 4-way output
scan, varint multi-input parser, H1 binding (from the FT any-wallet swap).

**Designed-but-unproven (this plan converts these):** the NFT prologue
`d8<ref>75<body>` + singleton-conservation interaction; that an NFT held in the
covenant releases to a taker NFT output and conserves; the duplicate-singleton
negative. All flagged for the Phase-3 on-chain gate before any claim. Effort
estimates are PROJECTED, not measured.
