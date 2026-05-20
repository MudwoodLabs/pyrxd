---
title: Ref-bearing Gravity covenant — atomic Glyph FT/NFT ↔ BTC swaps
type: feat
date: 2026-05-19
status: SUPERSEDED (2026-05-20) — core architecture falsified on-chain
superseded_by: docs/plans/2026-05-20-feat-gravity-ft-covenant-spend-path-plan.md
---

> **⚠️ SUPERSEDED 2026-05-20.** This plan's central model — *lock the
> ref-bearing FT UTXO **into** the covenant* — was **falsified on-chain**:
> an FT's `codeScriptHashValueSum` epilogue rejects a foreign-code-script
> output, so an FT cannot be held in a foreign covenant. The corrected
> architecture (covenant gates the FT's **spend-path**; FT-shaped
> settlement output; hash-compare not embedded bytes; FT ref = genesis
> outpoint) and an FT-only v1 scope live in
> [2026-05-20-feat-gravity-ft-covenant-spend-path-plan.md](2026-05-20-feat-gravity-ft-covenant-spend-path-plan.md).
> Phase 1 (sighash de-dup) here was completed and merged (PR #124) and is
> carried forward. Read the new plan for everything else.

# Ref-bearing Gravity covenant — atomic Glyph FT/NFT ↔ BTC swaps

## Overview

Today's Gravity covenant family swaps **plain RXD for BTC** atomically and
trust-minimized. This plan adds a new covenant variant — the
**ref-bearing covenant** — that lets a Maker offer Glyph fungible tokens
(FT) or NFT singletons in exchange for BTC, with the same trust
properties: no custody, no exchange, no KYC, covenant-enforced timeout
and forfeit.

The variant is a **fork of the shipping sentinel covenant** that keeps
the entire BTC-facing half (SPV verifier, four-way BTC output-type
dispatch, sentinel-padded Merkle depth handling, deadline mechanics)
and rewrites the Radiant-facing half to carry a Glyph ref through
lock-and-release. The plan ships **two separate covenant artifacts**
— `maker_covenant_ft_v1.artifact.json` (FT, uses `OP_PUSHINPUTREF`)
and `maker_covenant_nft_v1.artifact.json` (NFT singleton, uses
`OP_PUSHINPUTREFSINGLETON`).

The brainstorm at
[docs/brainstorms/2026-05-19-gravity-glyph-ft-swap-brainstorm.md](../brainstorms/2026-05-19-gravity-glyph-ft-swap-brainstorm.md)
originally committed to a unified in-script `refKind` dispatch.
Security and architecture review during plan refinement reversed that
decision: FT (`0xd0`) and NFT (`0xd8`) are different opcodes with
different conservation semantics (sum-in == sum-out vs. singleton
identity), not output-format variants like `btcReceiveType`. Two
artifacts means two smaller audit surfaces, no branch-selection
attack class (Security Sentinel rated this High severity), and the
ability to deny-list one variant without affecting the other. The
unified-covenant idea remains under "Future Considerations" if a
future audit shows the maintenance overhead of two artifacts
outweighs the security partitioning.

This plan turns the brainstorm direction into phased, reviewable,
auditable work.

## Problem Statement

**Concrete user need:** "I want to sell credits/tokens (FT) or a unique
collectible (NFT) for BTC without trusting a custodian, without an
exchange, and without forcing the buyer through KYC."

**Why this isn't doable today:**

1. The shipping maker covenant
   ([gravity/artifacts/maker_covenant_flat_12x20_sentinel_all.artifact.json](../../src/pyrxd/gravity/artifacts/maker_covenant_flat_12x20_sentinel_all.artifact.json))
   builds its settlement output as a plain P2PKH (`76a914 <takerPkh>
   88ac`, asserted via `OP_OUTPUTBYTECODE`) with no ref bytes.
   Funding it with a ref-bearing UTXO violates Radiant's
   ref-conservation rule (each ref on the input must reappear on an
   output); the funding tx is rejected. **Note (per
   [spike-findings](../brainstorms/2026-05-19-gravity-ref-covenant-spike-findings.md)):
   the covenant already constructs output scripts compositionally with
   `OP_CAT`, so adding a ref is additive work in an existing pattern —
   not a from-scratch output-description system.**

2. The Gravity-specific sighash helper
   `_compute_hash_output_hashes` at
   [gravity/transactions.py:93-134](../../src/pyrxd/gravity/transactions.py#L93)
   hard-codes `totalRefs = 0` and `refsHash = 32 × 0x00` for every
   output it processes. Even if the covenant script carried a ref,
   signed spends would produce the wrong sighash for ref-bearing
   outputs and get rejected by validators.

**The alternatives don't meet the user need:**

- **Off-chain custodian** — defeats the trust property.
- **Two-leg swap (Gravity BTC→RXD, then OTC RXD→FT)** — not atomic;
  either side can stiff on leg 2.
- **Radiant Swap DEX (`swap.*`)** — referenced at
  [rxindexer.py:8](../../src/pyrxd/network/rxindexer.py#L8) but trades
  on Radiant only; does not accept BTC.

## Proposed Solution

Build **two separate ref-bearing covenant artifacts** — one for FT,
one for NFT singleton. Each carries the same SPV/BTC half as the
sentinel covenant; the Radiant half differs in opcode and
conservation discipline.

| Artifact | Asset | Opcode | Conservation rule |
|---|---|---|---|
| `maker_covenant_ft_v1` | FT | `OP_PUSHINPUTREF` (`0xd0`) | Settlement output carries the same ref + same amount; sum-in == sum-out enforced by Radiant ref-conservation |
| `maker_covenant_nft_v1` | NFT singleton | `OP_PUSHINPUTREFSINGLETON` (`0xd8`) | Settlement output carries the singleton on exactly one output; no amount field |

A discriminated-union API in Python:

- `RefKind(IntEnum)` — `FT = 0`, `NFT = 1` (boundary conversion only;
  the artifact name carries the discrimination at script level).
- `FtAmount = NewType("FtAmount", int)` — prevents accidentally
  mixing FT units with photons/satoshis at type-check time.
- `GravityFTOffer` and `GravityNFTOffer` — distinct frozen
  dataclasses, both extend a shared `_BaseGravityOffer` (extracted
  from today's `GravityOffer.__post_init__` validators).

The covenant flow mirrors today's Gravity:

1. Maker locks a ref-bearing UTXO into the covenant (ref + amount for
   FT; ref alone for NFT).
2. Taker pays BTC to Maker's BTC address.
3. Taker (or anyone with the SPV proof) submits a settlement tx that
   spends the covenant UTXO, produces a ref-bearing output to Taker,
   and attaches the SPV proof.
4. Covenant validates SPV proof + ref-passthrough + amount
   conservation; spend succeeds; asset is now Taker's.
5. Fallback: if no settlement by deadline, Maker can `forfeit` to
   reclaim the original ref-bearing UTXO.

## Technical Approach

### Architecture

**File-level partition** of new vs reused code:

| Component | Status | Path |
|---|---|---|
| SPV proof builder/verifier | Reused as-is | [src/pyrxd/spv/](../../src/pyrxd/spv/) |
| BTC output-type dispatch (P2PKH/P2WPKH/P2SH/P2TR) | Reused as-is | covenant script param `btcReceiveType` |
| Sentinel-padded Merkle proof handling (depth 12–20) | Reused as-is | covenant script |
| Sighash helper (correct, ref-aware) | Reused (de-dup target) | [transaction_preimage.py:66](../../src/pyrxd/transaction/transaction_preimage.py#L66) |
| Sighash helper (stale, hardcoded) | **Delete** | [gravity/transactions.py:93-134](../../src/pyrxd/gravity/transactions.py#L93) |
| Deny-list / artifact loader | Extend | [gravity/covenant.py:59-76](../../src/pyrxd/gravity/covenant.py#L59) |
| `_LAZY_EXPORTS` | Extend | [src/pyrxd/__init__.py](../../src/pyrxd/__init__.py), [gravity/__init__.py](../../src/pyrxd/gravity/__init__.py) |
| Ref-bearing covenant templates (NEW) | **Two new artifacts** | `gravity/artifacts/maker_covenant_ft_v1.artifact.json`, `gravity/artifacts/maker_covenant_nft_v1.artifact.json` |
| Shared offer base + ref-bearing types (NEW) | **New** | `gravity/types.py` (extend with `_BaseGravityOffer`, `RefKind`, `FtAmount`, `GravityFTOffer`, `GravityNFTOffer`) |
| Ref-bearing factory (NEW) | **New** | `gravity/ref/covenant.py` |
| Ref-bearing tx builders (NEW) | **New** | `gravity/ref/transactions.py` |
| Funding-input pre-flight validator (NEW) | **New** | `gravity/ref/validation.py` (opcode-stream walker, never byte-scan) |
| Taker offer-verification API (NEW, async) | **New** | `gravity/ref/verify.py` |
| End-to-end + red-team tests (NEW) | **New** | `tests/test_gravity_ref.py`, `test_gravity_ref_trade.py`, `test_gravity_ref_red_team.py`, `test_gravity_ref_verify.py` |

### Implementation Phases

The phases are sequenced so each one ends in a green `task ci`, no
partial states leaking into main. Phase boundaries are also natural
PR boundaries.

---

#### Phase 1: Sighash de-duplication (foundation)

**Goal:** delete the duplicate `_compute_hash_output_hashes` in
`gravity/transactions.py` and reuse the correct one in
`transaction_preimage.py`. Existing Gravity tests must still pass
byte-for-byte (the two implementations are equivalent for the
`totalRefs=0` path that today's Gravity uses).

**Tasks:**

- [ ] Decide adapter shape:
  - **Option A:** reconstruct `TransactionOutput` instances at the
    Gravity call site in `_sign_radiant_p2sh_input`
    ([gravity/transactions.py:170](../../src/pyrxd/gravity/transactions.py#L170))
    and call the general helper.
  - **Option B:** extract the byte-stream parsing loop in
    `gravity/transactions.py:106-124` into a shared helper that calls
    `_get_push_refs` from `transaction_preimage.py:18`.
  - **Recommendation:** B — closer to the brainstorm's "delete the
    duplicate" intent, no object reconstruction overhead.
- [x] Implement chosen adapter; delete the Gravity `_compute_hash_output_hashes`. **Done 2026-05-19:** chose a cleaner variant of Option A — the adapter parses `outputs_serialized` via the existing `TransactionOutput.from_hex` reader and delegates to the general impl. No new byte-parser written; reuses two already-tested primitives. ([gravity/transactions.py:96](../../src/pyrxd/gravity/transactions.py#L96))
- [x] Fix the stale comment at
  [transaction_preimage.py:109](../../src/pyrxd/transaction/transaction_preimage.py#L109)
  that incorrectly claims ref count is "always 0 for standard
  P2PKH/FT/NFT outputs." **Done 2026-05-19.**
- [x] Add `TestSighashBackcompat` golden-vector regression test.
  **Done 2026-05-19** — placed in `tests/test_gravity.py` (not
  `test_gravity_trade.py`; that's where the pure-function builder tests
  live). Golden vectors are inline module constants captured from the
  pre-refactor impl, parameterized, asserted byte-identical. Also added
  `test_ft_output_now_computes_real_refshash` (proves the FT path no
  longer hashes as totalRefs=0) and `test_malformed_trailing_bytes_rejected`.
- [ ] **DEFERRED to Phase 2: adversarial sighash vectors for `totalRefs >= 1`
  sourced from a confirmed broadcast.** These need a real ref-bearing
  Gravity covenant spend, which doesn't exist until Phase 2. Partial
  coverage landed now: `test_ft_output_now_computes_real_refshash`
  exercises the `totalRefs=1` path with a synthetic FT script, and the
  refactored adapter was run live against the real on-chain ref output
  in mainnet tx `dac1e2df...` (8104 confs, 1 ref) — confirming the
  ref-aware path runs on real consensus bytes. Full sort-order /
  dedup / mixed-opcode regtest fixtures come with the Phase 2 covenant.
- [x] Confirm `tests/test_gravity_trade.py::TestGravityTradeP2PKH` and
  `TestGravityTradeFinalize` still pass. **Done — 199 passed across
  gravity + preimage + trade + red-team suites.**
- [x] Confirm `tests/test_preimage.py::TestComputeHashOutputHashes` (mainnet
  tx `dac1e2df...` pinned vectors) still passes. **Done.**

**Success criteria:**
- [x] Gravity + preimage + trade + red-team suites green (199 passed). `task ci` not yet run end-to-end on this branch — pending before PR.
- [x] Coverage for `gravity/transactions.py` holds (91%); the refactored adapter is exercised by the new tests.
- [x] Live cross-check against the mainnet node on `tr`: refactored adapter ran on the real on-chain ref-bearing output in tx `dac1e2df...` (8104 confs).
- [ ] One PR. Title: `refactor(gravity): de-duplicate _compute_hash_output_hashes`. (Regtest fixture-capture harness deferred with the Phase-2 covenant work — see deferred item above.)

**Estimated effort:** 1–2 days (spike-revised down from 3–5: the
ref-aware `_get_push_refs` + `_compute_hash_output_hashes` are already
shipped and tested at
[tests/test_preimage.py:34-79](../../tests/test_preimage.py#L34), so
the de-dup is small; regtest harness setup is lighter than feared).
See [spike-findings](../brainstorms/2026-05-19-gravity-ref-covenant-spike-findings.md).

---

#### Phase 2: Photonic prior-art check + Radiant-side script spike

**Goal:** establish whether Photonic (the canonical Glyph reference per
[CLAUDE.md memory](../../docs/concepts/gravity.md)) has prior art on
ref-bearing covenants, then spike a **Radiant-only** covenant script
that carries a ref through lock and release (no BTC half yet).

**Tasks:**

- [ ] Read Photonic's TypeScript codebase for any ref-bearing covenant
  / ref-passthrough constraint patterns. Document findings in a new
  brainstorm at `docs/brainstorms/2026-05-MM-gravity-ref-spike-findings.md`.
- [ ] Draft **two candidate covenant templates** — one for FT, one
  for NFT. Required clauses for each:
  - Settlement clause: covenant **constructor params** include
    `glyph_ref` (substituted into the hex template like
    `btcReceiveHash` — this binds the ref into the P2SH hash;
    Security #1). The clause builds the settlement output script with
    the locked ref opcode and ref bytes, pushes expected amount (FT)
    or just the singleton (NFT), enforces conservation.
  - Forfeit clause: pop expected reclaim signature, verify against
    Maker pubkey, build reclaim output with the same ref
    opcode/bytes and amount.
  - **Critical (Security #2):** Both templates must independently
    enforce `totalRefs == 1` on settlement output and forfeit output
    so a Python-bypassing Maker who funds with a multi-ref UTXO
    cannot smuggle an extra ref through. Python pre-flight (Phase 3)
    is not sufficient on its own.
  - **Critical (Security #5):** The covenant must bind the BTC
    payment to **offer-unique** data. Today's sentinel covenant
    binds to `(btcReceiveHash, btcReceiveType, btcSatoshis)`; two
    concurrent ref-bearing offers from the same Maker to the same
    BTC address satisfy each others' SPV proofs. **Mitigation:
    subaddress derivation.** Each offer's `btcReceiveHash` is
    derived from `(maker_pubkey_hash, glyph_ref, nonce)` so each
    offer has a fresh receiving address. Rationale: any BTC wallet
    that can send to an address can pay (no OP_RETURN authoring
    requirement → no Taker funnel cost). Maker key management
    overhead is small — Makers already manage pubkey rotation.
    Phase 2 spike validates the derivation scheme; if it proves
    impractical, fall back to OP_RETURN-carrying-P2SH-hash with a
    documented Taker-wallet-compatibility note.
  - **No `refKind` in-script dispatch.** Templates compile separately;
    the artifact name and constructor params discriminate.
- [ ] Compile candidate to `*.artifact.json` shape matching
  [gravity/artifacts/maker_offer.artifact.json](../../src/pyrxd/gravity/artifacts/maker_offer.artifact.json):
  `{version, compilerVersion, contract, abi, asm, hex}` with
  `<paramName>` placeholders for substitution.
- [ ] Drive the spike on regtest (per memory:
  [Radiant Core (current) not radiant-node (old)](../../docs/concepts/gravity.md)).
  Validate:
  - (a) lock a 75-byte FT UTXO and a 63-byte NFT singleton UTXO into
    the covenant; both funding txs accepted by Radiant validators.
  - (b) release each via a single-clause spend to a target address;
    ref appears on the output, conservation holds.
  - (c) reclaim via timeout (block-height bound); ref returns to Maker.
- [ ] Document attempted designs that didn't work in the spike-findings
  brainstorm (follows the
  [2026-05-19-gravity-p2pkh-spike-findings.md](../brainstorms/2026-05-19-gravity-p2pkh-spike-findings.md)
  precedent).

**Success criteria:**
- Spike-findings brainstorm published.
- Two working artifact drafts (regtest-validated, **not** mainnet-ready,
  **not** shipped under `gravity/artifacts/` yet — live in a scratch
  location).
- **Benchmark vector table in the brainstorm** (Performance #1 + #2):
  - Sentinel covenant settlement bytes (baseline).
  - FT covenant settlement bytes.
  - NFT covenant settlement bytes.
  - FT funding tx size; NFT funding tx size.
  - Per-trade fee in photons at the project's documented relay floor
    (cite the floor constant, don't invent a number).
- **Absolute acceptance gates (replace the original 30% threshold):**
  - Settlement tx ≤ 1.5× sentinel settlement tx size.
  - FT funding tx ≤ 1.5× sentinel funding tx size.
  - Per-trade Taker-paid fee ≤ documented "acceptable swap fee"
    constant (TBD in spike if no such constant exists; needs Maker/
    Taker UX context).
- **Adversarial review checkpoint** (per `expert-panel-pivot` lesson,
  scaled down): one half-day red-team pass on the artifact draft
  before Phase 4 begins. Single question: "what does shipping this
  normalize, and what's the day-1 attack?" Findings recorded in the
  spike-findings brainstorm.

**Estimated effort:** 1–2 weeks (spike-revised down from 2–3). The
sentinel covenant already constructs settlement-output scripts
compositionally with `OP_CAT` (260× in the asm) and asserts them via
`OP_OUTPUTBYTECODE`/`OP_OUTPUTVALUE` — so carrying a ref is *additive*
(CAT the FT/NFT epilogue into the expected-output construction), not a
from-scratch output-description system. The remaining dominant unknown
is regtest validation that ref-conservation and the covenant's
expected-output assertion agree — that is what keeps this from
collapsing further. Two artifacts still add time vs. one. See
[spike-findings](../brainstorms/2026-05-19-gravity-ref-covenant-spike-findings.md).

---

#### Phase 3: Funding-input pre-flight validation + type discipline

**Goal:** before any covenant code can sign a funding tx, the Python
must verify the source UTXO matches what the covenant expects. This
prevents a class of "mis-funded covenant" bugs that lock assets until
deadline with no recovery.

**Tasks (type discipline):**

- [ ] Extract `_BaseGravityOffer` in `src/pyrxd/gravity/types.py` — a
  `@dataclass(frozen=True, slots=True, kw_only=True)` holding the
  BTC + deadline + Taker fields shared across plain-RXD, FT, and
  NFT offers. Move the shared `__post_init__` validation logic from
  today's `GravityOffer` ([types.py:60-80](../../src/pyrxd/gravity/types.py#L60))
  into the base.
- [ ] `GravityOffer` (existing) extends `_BaseGravityOffer`. Add a
  no-op subclass-specific `__post_init__` if any plain-RXD-only
  validation exists.
- [ ] `GravityFTOffer` extends `_BaseGravityOffer`. Fields: `glyph_ref:
  GlyphRef`, `amount: FtAmount`. Frozen, slots, kw_only.
- [ ] `GravityNFTOffer` extends `_BaseGravityOffer`. Field:
  `glyph_ref: GlyphRef`. No amount.
- [ ] `RefKind(IntEnum)` in `types.py`: `FT = 0`, `NFT = 1`. Used at
  the script-boundary; out-of-range becomes free `ValueError` via
  `RefKind(value)`.
- [ ] `FtAmount = NewType("FtAmount", int)` in `types.py`. Prevents
  unit confusion with photons/satoshis at type-check time. Zero
  runtime cost.

**Tasks (validators — opcode-stream walker, no byte-scan):**

- [ ] New subpackage `src/pyrxd/gravity/ref/` with `validation.py`:
  - `_validate_ft_funding_input(utxo, expected_ref, expected_amount)`
    — parses 75-byte FT locking script (per
    [glyph/script.py:135](../../src/pyrxd/glyph/script.py#L135))
    by **walking the opcode stream** (skip push payloads per the
    canonical walker at `glyph/dmint.py:1513`). Bare-byte scans are
    prohibited — cite
    [funding-utxo-byte-scan-dos.md](../solutions/logic-errors/funding-utxo-byte-scan-dos.md)
    in the module docstring. Asserts ref bytes match
    `expected_ref.to_bytes()` and FT amount matches.
  - `_validate_nft_funding_input(utxo, expected_ref)` — same shape
    for 63-byte NFT singleton script
    ([glyph/script.py:127](../../src/pyrxd/glyph/script.py#L127)).
  - Both prefixed `_` (private) per existing helper-privacy
    convention in `gravity/transactions.py` (`_varint`,
    `_validate_txid`, etc.). Callers go through the factory.
  - Error messages follow the
    [covenant.py:249-253](../../src/pyrxd/gravity/covenant.py#L249)
    triad: `f"<field> must be <expected>; got <actual>. <consequence>"`.

**Tasks (factories — two, not one):**

- [ ] In `src/pyrxd/gravity/ref/covenant.py`:
  - `build_gravity_ft_offer(glyph_ref, amount, btc_receive_type,
    btc_receive_hash, deadline, ...) -> GravityFTOffer`
  - `build_gravity_nft_offer(glyph_ref, btc_receive_type,
    btc_receive_hash, deadline, ...) -> GravityNFTOffer`
- [ ] Each factory loads its specific artifact name
  (`maker_covenant_ft_v1` or `maker_covenant_nft_v1`) and calls the
  matching pre-flight validator. Cross-kind loading raises
  `ValidationError`.

**Tests (consolidated — `tests/test_gravity_ref.py`, validators + types
together per Kieran #9):**

- [ ] `TestFundingInputMismatch` — wrong ref, wrong amount, multi-ref
  UTXO, non-FT locking script, wrong-kind UTXO (NFT into FT
  validator).
- [ ] `TestArtifactKindIsolation` — `build_gravity_ft_offer` rejects
  the NFT artifact name; vice versa.
- [ ] `TestFundingDenyListFalsePositive` (per
  [funding-utxo-byte-scan-dos.md](../solutions/logic-errors/funding-utxo-byte-scan-dos.md)):
  construct a legitimate 75-byte FT funding script where the 20-byte
  miner P2PKH payload happens to contain bytes in the `0xD0–0xD8`
  ref-opcode range. Validator must accept. Document the
  false-positive rate in the test docstring (target: 0%).
- [ ] **Hypothesis property tests** (per
  [fuzzing-strategy-graduated-approach.md](../solutions/design-decisions/fuzzing-strategy-graduated-approach.md)):
  `tests/property/test_ref_validation_robustness.py` —
  `validate_ft_funding_input(arbitrary_bytes_as_script)` and
  `validate_nft_funding_input(...)` never raise anything but
  `ValidationError`. ~50 LOC, runs in existing pytest.
- [ ] `TestRefKindIntEnumBoundaries` — `RefKind(2)` raises `ValueError`;
  free out-of-range rejection.
- [ ] `TestFtAmountTypeDiscipline` — at the mypy/pyright level, passing
  a `Photons` or bare `int` where `FtAmount` is expected fails (test
  enforced via the type-check CI step).

**Success criteria:**
- `task ci` green. `coverage-security` 100% on `gravity/ref/validation.py`.
- New types exposed via `_LAZY_EXPORTS` in
  [src/pyrxd/__init__.py](../../src/pyrxd/__init__.py) under a new
  `# Gravity — ref-bearing` section comment, alphabetical:
  `GravityFTOffer`, `GravityNFTOffer`, `RefKind`,
  `build_gravity_ft_offer`, `build_gravity_nft_offer`,
  `verify_ref_offer` (Phase 6). Validators stay unexported (private
  per convention).
- `src/pyrxd/gravity/__init__.py` updates its eager `__all__` list
  (not lazy — different mechanism from the top-level init, per
  Pattern Recognition).
- One PR. Title: `feat(gravity): add ref-bearing offer types + funding
  pre-flight validator`.

**Estimated effort:** 5–7 days (up from 3–5 due to the additional
property tests and shared-base extraction).

---

#### Phase 4: Bolt on the BTC half — full covenant + tx builders

**Goal:** splice the SPV proof + `btcReceiveType` dispatch from the
sentinel covenant into the Phase-2 Radiant-side spike. Produce a
shippable artifact.

**Tasks:**

- [ ] Merge the SPV-proof clauses from the sentinel covenant
  ([gravity/artifacts/maker_covenant_flat_12x20_sentinel_all.artifact.json](../../src/pyrxd/gravity/artifacts/maker_covenant_flat_12x20_sentinel_all.artifact.json))
  into both Phase-2 ref-bearing templates. The sentinel-padded
  Merkle-depth handling (depth 12–20) is reused verbatim.
- [ ] `btcReceiveType` four-way dispatch (P2PKH/P2WPKH/P2SH/P2TR)
  reused verbatim.
- [ ] Final artifacts ship at:
  - `src/pyrxd/gravity/artifacts/maker_covenant_ft_v1.artifact.json`
  - `src/pyrxd/gravity/artifacts/maker_covenant_nft_v1.artifact.json`
- [ ] Tx builders in `src/pyrxd/gravity/ref/transactions.py`:
  - `build_ft_maker_offer_tx(...)` / `build_nft_maker_offer_tx(...)`
    — Maker funds the covenant with a ref-bearing UTXO.
  - `build_ft_finalize_tx(...)` / `build_nft_finalize_tx(...)` —
    Taker (or anyone) settles with SPV proof; output carries the ref
    to Taker.
  - `build_ft_forfeit_tx(...)` / `build_nft_forfeit_tx(...)` — Maker
    reclaims after deadline.
  - **No `cancel_tx`** — out of v1 scope per brainstorm; forfeit
    covers failure.
- [ ] Pre-broadcast validator (scoped per Simplicity #5 — a thin
  check, not a full simulator): "does each input ref appear on
  exactly one output of expected kind." Reject locally with a clear
  error before broadcast. Prevents the "tx rejected by validators,
  assets stalled to deadline" failure for the common pre-flight
  bugs. **Add Hypothesis property tests** on this validator (same
  graduated-fuzzing pattern as Phase 3).
- [ ] **Typed exception discipline** (per
  [dmint-v1-mint-scriptsig-divergence.md](../solutions/logic-errors/dmint-v1-mint-scriptsig-divergence.md)):
  introduce or reuse a `PolicyRejection` exception type for tx
  rejections that surface from regtest/mainnet. Ensure ElectrumX
  `code 1` rejections are *not* reclassified as `NetworkError` (this
  masked a critical V1 dMint bug for weeks).

**Tests (in `tests/test_gravity_ref.py`):**

- [ ] Class-per-builder: `TestBuildFTMakerOfferTx`,
  `TestBuildFTFinalizeTx`, `TestBuildFTForfeitTx`, and the three NFT
  analogs. Mirrors
  [tests/test_gravity.py::TestBuildFinalizeTx](../../tests/test_gravity.py#L93).
- [ ] `TestRefArtifactSubstitution` — verify `<paramName>`
  placeholders substitute correctly for `glyph_ref` and `amount`
  params in both artifacts.

**Tests (golden bytes from real regtest — per
[dmint-v1-mint-shape-mismatch.md](../solutions/logic-errors/dmint-v1-mint-shape-mismatch.md)):**

- [ ] `TestRefArtifactGoldenVectors` (**mandatory before merge**):
  For each of the six builders (FT and NFT × offer/finalize/forfeit),
  capture byte-for-byte expected output from a **regtest broadcast
  that actually confirmed** during Phase 2 validation. Assert
  `tx.serialize() == _REGTEST_CONFIRMED_BYTES_<TX>` with the regtest
  txid and block height cited in the test fixture. **No builder
  lands without an externally-confirmed byte fixture** — synthetic
  round-trip through pyrxd's own parser does not satisfy this gate.
- [ ] `testmempoolaccept` gate: every settlement and forfeit tx
  produced by the new builders must be accepted by a real Radiant
  Core regtest node via `testmempoolaccept` (or actual broadcast +
  confirmation) before the PR can merge. The pre-broadcast validator
  is informational only; it does not satisfy this gate.

**Success criteria:**
- `task ci` green.
- Both artifacts load via `CovenantArtifact.load("maker_covenant_ft_v1")`
  and `CovenantArtifact.load("maker_covenant_nft_v1")`.
- Golden byte vectors checked in; each cites a regtest txid + block
  height in the fixture file.
- `testmempoolaccept` evidence checked in (regtest run logs or CI
  artifact).
- One PR. Title: `feat(gravity): ship ref-bearing covenant artifacts + tx builders`.

**Estimated effort:** 1.5–2 weeks (spike-revised down from 2–3:
builders extend the existing introspection-output pattern rather than
inventing one). The golden-byte regtest gate is unchanged — and
**more** important per the spike: `OP_OUTPUTBYTECODE` on a ref-bearing
output is a script path the sentinel covenant has never exercised, so
synthetic round-trip would be exactly the dMint trap. See
[spike-findings](../brainstorms/2026-05-19-gravity-ref-covenant-spike-findings.md).

---

#### Phase 5: End-to-end + red-team test coverage

**Goal:** match or exceed the existing Gravity test discipline. The
brainstorm called out
[tests/test_gravity_trade.py::TestGravityTradeP2PKH](../../tests/test_gravity_trade.py#L945)
as the pattern to copy — full lock → BTC payment → SPV → settle, no
verifier mocking, real `SpvProofBuilder.build()` against a synthetic
BTC tx and pre-mined PoW header.

**Tasks (end-to-end, in `tests/test_gravity_ref_trade.py`):**

- [ ] `TestGravityFTTrade` — clone the P2PKH pattern, swap in the FT
  covenant. Full lock → BTC payment → SPV → settle. Synthetic BTC
  tx, pre-mined header from
  `tests/fixtures/spv_synthetic_headers.json` (extend the fixture if
  needed; pre-generated and committed, per
  [test_gravity_trade.py:912-917](../../tests/test_gravity_trade.py#L912)).
- [ ] `TestGravityNFTTrade` — same shape for NFT singleton.
- [ ] `TestGravityFTForfeit` and `TestGravityNFTForfeit` — deadline
  expiry, Maker reclaims.
- [ ] `TestThirdPartySettlement` — anyone with the SPV proof can
  settle (today's Gravity property must survive in the ref variant).

**Tasks (red-team, in a new dedicated file
`tests/test_gravity_ref_red_team.py` mirroring
[tests/test_gravity_red_team.py](../../tests/test_gravity_red_team.py)):**

- [ ] `TestRefArtifactTampering` — byte mutation of both artifacts;
  deny-list bypass attempts; ASCII reinjection.
- [ ] `TestRefArtifactOutpointBinding` (per Security Sentinel
  cross-cutting recommendation): verify each settlement proof is
  consumed atomically with the covenant input — no replay against a
  re-funded covenant at the same P2SH hash (relevant to
  `dmint-deploy-reveal-hashlock-reuse.md` learning).
- [ ] `TestRefBoundToP2SHHash` (Security #1): mutate `glyph_ref` in
  the substituted hex bytes; assert P2SH hash changes. Confirms the
  ref is a covenant constructor param, not a witness.
- [ ] `TestRefParamEncodingEdges`:
  - Wrong-length `glyph_ref` (not 36 bytes)
  - `amount = 0` (rejected at factory; FT only)
  - `amount = 2^64 - 1` (uint64 boundary; serializes; presumably fails
    conservation at settlement — assert behavior)
  - `RefKind(2)` raises `ValueError` (IntEnum boundary)
- [ ] `TestMultiRefSourceRejected` (Security #2 — Critical): funding
  UTXO carries multiple refs.
  - Part A: Python pre-flight rejects.
  - Part B (**bypass the validator, fund directly**): the covenant
    **script itself** must reject. If script-level rejection cannot
    be confirmed via regtest broadcast, Phase 2 design did not
    satisfy Security #2 and must be revisited.
- [ ] `TestSPVProofReuseAcrossOffers` (Security #5 — Critical): two
  Maker offers with the same `(btcReceiveHash, btcReceiveType,
  btcSatoshis)`. Submit the same SPV proof to both settlement
  attempts. Expected behavior depends on Phase 2's chosen
  mitigation; the test asserts only-one settles.
- [ ] `TestRefSortOrderConsensus` — uses two refs that sort
  differently than declaration order. Sighash uses sorted order
  ([transaction_preimage.py:80-91](../../src/pyrxd/transaction/transaction_preimage.py#L80));
  the script-level constraint must read refs in the same order.
- [ ] `TestSettlementAmountSplit` — settlement tx tries to split N
  into two outputs (Taker + attacker). Rejected by ref-conservation.
- [ ] `TestSingletonDuplicationAttempt` — settlement tx tries to
  produce NFT singleton on two outputs. Rejected.
- [ ] `TestRefSubstitution` — settlement output carries a different
  ref of the same kind. Rejected.
- [ ] `TestSourceRefBurnedPreSettlement` — source ref destroyed
  post-funding (some FTs have admin burn keys). Verify forfeit still
  works (it returns the locked UTXO; the ref's external state
  doesn't affect that).
- [ ] `TestSettlementReorgAcrossDeadline` — settlement tx reorgs out
  near deadline; forfeit races re-confirmation. Document expected
  behavior.
- [ ] `TestForfeitFeeStarvation` (Security #4): Maker's only
  fee-bearing UTXO is double-spent by attacker at deadline; verify
  forfeit can be funded from any UTXO (covenant must not require a
  specific fee source).
- [ ] `TestDuplicateOfferDisambiguation`
  ([dmint-deploy-reveal-hashlock-reuse.md](../solutions/logic-errors/dmint-deploy-reveal-hashlock-reuse.md)):
  two identical-param offers from the same Maker produce identical
  P2SH script hashes. Verifier must disambiguate by funding outpoint,
  not by scripthash history ordering.
- [ ] `TestPolicyRejectionSurfaced`
  ([dmint-v1-mint-scriptsig-divergence.md](../solutions/logic-errors/dmint-v1-mint-scriptsig-divergence.md)):
  when the covenant rejects a malformed witness/scriptSig, the
  resulting error is a typed `PolicyRejection`, not a generic
  `NetworkError`. ElectrumX `code 1` reclassification masked a
  critical V1 dMint bug.

**Tasks (CLI surface, in
[wallet_cmds.py](../../src/pyrxd/cli/wallet_cmds.py)):**

- [ ] One `gravity-ref` command group with subcommands `offer`,
  `settle`, `forfeit` (per Simplicity #6). Each subcommand must show
  the human-readable ref + amount + deadline before signing —
  surfaces the Maker/Taker pre-confirmation UX gap from SpecFlow.

**Success criteria:**
- `task ci` green. `coverage-overall` ≥85% maintained.
- Both end-to-end FT and NFT trades demonstrably work against
  synthetic BTC + pre-mined PoW headers.
- All Critical-rated security tests pass (`TestMultiRefSourceRejected`
  Part B and `TestSPVProofReuseAcrossOffers` are blockers).
- Red-team coverage at least matches the existing Gravity red-team
  test count proportional to the covenant surface.

**Estimated effort:** 2–3 weeks.

---

#### Phase 6: Taker verification API + cross-feature integration

**Goal:** SpecFlow surfaced this as the brainstorm's biggest gap — a
Taker has no first-class API for verifying what they're buying before
paying BTC. Build it as a first-class deliverable.

**Tasks (verifier — async, per Kieran #5):**

- [ ] New module `src/pyrxd/gravity/ref/verify.py`:
  - `async def verify_ref_offer(offer, *, funding_outpoint,
    expected_ref, expected_amount=None, resolver, btc_confirmations=N)
    -> VerifyResult` — Taker-side check.
  - **Takes a specific funding outpoint** (`txid:vout`) rather than
    searching by scripthash — per
    [dmint-deploy-reveal-hashlock-reuse.md](../solutions/logic-errors/dmint-deploy-reveal-hashlock-reuse.md):
    a Maker reposting the same offer produces an identical P2SH
    hash, so "find the offer by scripthash" is ambiguous.
  - Calls `RxinDexerClient.glyph_get_token(ref)` and/or
    `glyph_get_metadata(ref)`
    ([rxindexer.py:120,133](../../src/pyrxd/network/rxindexer.py#L120))
    to fetch token metadata (decimals, ticker, supply where
    available). **The original plan referenced a non-existent
    `glyph_resolve` method — corrected by Performance Oracle.**
  - Confirms covenant `glyph_ref` matches `expected_ref`; confirms
    covenant `amount` (FT) matches `expected_amount`.
  - Returns a **structured `VerifyResult` dataclass** (Security #8):
    `verified: bool`, `warnings: list[str]`, `failure_reason: str |
    None`. **Raises** on missing metadata (fail-closed, never returns
    a falsy "verified=False" that callers might misinterpret as
    "verification ran cleanly and the offer is bad" vs. "verification
    couldn't complete").
  - Requires `btc_confirmations >= N` confirmations of the funding
    tx (Security #7). N parameterized; documented default.
  - **In-process TTL cache** (Performance #5): 60-second TTL keyed by
    ref bytes — token metadata is near-immutable.
  - **Latency budget:** ≤ 500ms p95 for a single offer verification.
- [ ] **Phantom-metadata warning** (Security UX): when the resolver
  shows the same `btcReceiveHash` on another live ref-bearing offer,
  the result includes a warning (`VerifyResult.warnings`). Documented
  in [docs/red-team-checklist.md](../red-team-checklist.md) as a
  Taker-visible risk; out of v1 enforcement scope.

**Tests (in `tests/test_gravity_ref_verify.py`):**

- [ ] `@pytest.mark.asyncio` on every test. Async resolver fixture.
- [ ] `TestVerifyRefOffer` — happy path, ref mismatch, amount
  mismatch, missing metadata (must **raise**, not return falsy),
  outpoint-not-found.
- [ ] `TestVerifyRefOfferDoesNotReturnFalsy` (Security #8 hardening):
  assert the API contract that catching exceptions and proceeding is
  documented as a security bug.
- [ ] `TestVerifyRefOfferCacheTTL` — second call within 60s hits
  cache; after TTL, network roundtrip again.
- [ ] `TestVerifyRefOfferConcurrentOfferWarning` — two live offers
  share `btcReceiveHash`; warning surfaced.

**Scope cuts from original plan:**

- ~~`verify_ref_offer_via_wave`~~ dropped — WAVE deferred per
  [wave-protocol-deferred-until-consumer.md](../solutions/design-decisions/wave-protocol-deferred-until-consumer.md);
  no concrete consumer needs it in this plan. Listed under Future
  Considerations.
- ~~Glyph inspector integration~~ deferred to a separate post-merge
  follow-up issue. Different file
  ([inspect.js](../inspect_static/inspect/inspect.js)), different
  reviewer attention, different risk profile (per Simplicity #4).
  Filed as a tracked follow-up before this plan closes.

**Success criteria:**
- `task ci` green.
- All async tests pass with `pytest-asyncio`.
- One PR. Title: `feat(gravity): async Taker-side ref-offer verification API`.

**Estimated effort:** 5–7 days (smaller after WAVE + inspector cuts).

---

#### Phase 7: Audit pass + deny-list seeding

**Goal:** before any mainnet exercise, the ref-bearing covenant gets a
full audit treatment.

**Tasks:**

- [ ] **This audit pass is `audit 06`** — one greater than the most
  recent `audit 05-F-N` series at
  [gravity/trade.py:19,23,182](../../src/pyrxd/gravity/trade.py#L19).
  Use hyphenated form: `audit 06-S1`, `audit 06-F-1`, ... matching
  the most recent convention. Findings recorded inline at point of
  enforcement.
- [ ] Create `docs/audits/` directory (does not exist yet) and add
  a top-of-file audit index in `gravity/ref/covenant.py` mapping
  `audit 06 → docs/audits/2026-MM-DD-ref-covenant-audit.md` (one new
  file; ~1 page summary of audit findings + dispositions).
  Otherwise future readers see `audit 06-S3` and have to grep.
- [ ] Extend [gravity/covenant.py:59-76](../../src/pyrxd/gravity/covenant.py#L59)
  deny-list with ref-bearing entries. **Use a `[ref-v1] ` reason
  prefix** on the existing `_BANNED_NAMES` / `_BANNED_BYTECODE_SHA256`
  dicts (per Simplicity #3) — separate dicts would be premature
  partitioning for ~1 entry. The prefix supports the same audit
  story with `grep '\[ref-v1\]'`.
- [ ] If the unified `refKind` dispatch design surfaces during audit
  (since the plan reversed away from it), add an explicit deny-list
  entry for it with reason: `[ref-v1] in-script refKind dispatch —
  branch-confusion attack class; split FT/NFT preferred (audit 06-S2)`.
- [ ] If the audit surfaces any attempted-and-rejected designs from
  Phase 2's spike, add them to the deny-list with reasons.
- [ ] **External audit is a hard gate**, not a recommendation, for
  any mainnet exercise of the ref-bearing variant (Security
  cross-cutting recommendation). NFT-irreversibility raises the bar
  above the plain-RXD covenant. Per
  [docs/concepts/gravity.md:219-222](../concepts/gravity.md#L219).
  Plan-of-plan follow-up; this plan ships through internal audit
  only, no mainnet activation.

**Tasks (documentation):**

- [ ] Update [docs/concepts/gravity.md](../concepts/gravity.md):
  - Add a new section on ref-bearing covenants (FT + NFT support).
  - Status table: shipping (RXD), shipping with limits (ref v1, FT
    tested on mainnet at small amount, NFT not yet).
  - Open-amount and partial-fill limitations called out.
- [ ] CHANGELOG entry under unreleased "Added" section, citing the new
  artifact and Taker-verification API.
- [ ] Small-amount mainnet exercise after audit (separate task post-audit,
  not in this plan).

**Success criteria:**
- Internal audit signed off.
- Deny-list extended.
- Docs updated.
- One PR. Title: `chore(gravity): ref covenant audit pass + deny-list +
  docs`.

**Estimated effort:** 1 week.

## Alternative Approaches Considered

| Alternative | Why rejected |
|---|---|
| **Off-chain custodian** | Defeats Gravity's trust property. |
| **Two-leg swap (Gravity BTC→RXD, then RXD→FT)** | Not atomic; either side can stiff on leg 2. Only viable for trusted counterparties. |
| **Radiant Swap DEX (`swap.*`)** | Trades on Radiant only; does not accept BTC. Complementary to Gravity, not a replacement. |
| **Unified `refKind`-dispatched covenant** | The brainstorm's original direction. Rejected during plan review: FT (`0xd0`) and NFT (`0xd8`) are different opcodes with different conservation semantics, not output-format variants like `btcReceiveType`. In-script dispatch creates a branch-confusion attack class (Security: High). Future-consolidation option if measured data eventually shows the split's maintenance cost outweighs the security partitioning. |
| **OP_RETURN-carrying-P2SH-hash for SPV proof binding** | Strongest cryptographic binding (one BTC tx → one covenant), but excludes Taker wallets that can't author OP_RETURN payloads (most consumer mobile wallets). Subaddress derivation chosen instead; OP_RETURN remains a fallback if subaddress derivation proves impractical in the Phase 2 spike. |
| **Patch existing sentinel covenant in-place** | Would break the mainnet-proven RXD path. New artifact preserves the existing one untouched. |
| **Generalize the sighash helper to accept either bytes or list** | Adds a union type to a security-critical function; harder to audit. Cleaner to extract the byte-stream parser and reuse `_get_push_refs`. |

## Acceptance Criteria

### Functional Requirements

- [ ] **FT swap end-to-end:** Maker locks 1,000 FT units; Taker pays BTC;
  Taker settles; 1,000 units land on Taker's Radiant address; FT
  conservation holds on every output.
- [ ] **NFT swap end-to-end:** Maker locks NFT singleton; Taker pays BTC;
  Taker settles; singleton appears on Taker's address; no
  duplication.
- [ ] **Forfeit:** if deadline passes without settlement, Maker reclaims
  the original ref-bearing UTXO (ref + amount intact for FT; singleton
  intact for NFT).
- [ ] **Third-party settlement:** anyone holding the SPV proof can
  submit the settlement tx; today's Gravity property survives.
- [ ] **Pre-flight validation:** Maker cannot fund the covenant with a
  wrong-kind or wrong-ref UTXO; the factory rejects before signing.
- [ ] **Taker verification:** `verify_ref_offer` confirms ref, amount,
  and (where available) token metadata before Taker pays.

### Non-Functional Requirements

- [ ] **Fee profile:** FT and NFT covenant script size + settlement
  tx size each measured against the sentinel covenant (absolute
  byte counts, not just ratios). Targets:
  - Settlement tx ≤ 1.5× sentinel settlement tx size
  - Funding tx ≤ 1.5× sentinel funding tx size
  - Per-trade Taker-paid fee documented in spike-findings brainstorm
- [ ] **Sighash backcompat:** existing plain-RXD Gravity trades produce
  identical sighash bytes after Phase 1 de-duplication (parameterized
  golden vector test) **and** new adversarial vectors for `totalRefs
  >= 1` produce correct sighashes (validated against regtest
  broadcasts, not just round-trip).
- [ ] **No `allow_legacy=True` shortcut:** the new artifacts get the
  full audit treatment and clean deny-list.
- [ ] **Coverage:** `coverage-security` 100% on new modules
  (`gravity/ref/validation.py`, `gravity/ref/covenant.py`,
  `gravity/ref/verify.py`); `coverage-overall` ≥85%.
- [ ] **Async discipline:** `verify_ref_offer` is `async def`;
  validators stay sync (local-only parsing).
- [ ] **Type discipline:** `RefKind(IntEnum)` boundary at script
  layer; `FtAmount = NewType("FtAmount", int)` prevents unit confusion
  with photons/satoshis; mypy/pyright enforced in CI.

### Quality Gates

- [ ] `task ci` green at the end of each phase. Pre-push hook
  installed (per
  [local-ci-parity-via-task-ci-and-pre-push-hook.md](../solutions/integration-issues/local-ci-parity-via-task-ci-and-pre-push-hook.md));
  no `--no-verify` pushes except WIP.
- [ ] Conventional Commits with DCO sign-off
  ([CONTRIBUTING.md:130-142](../../CONTRIBUTING.md#L130)).
- [ ] Internal audit signed off (Phase 7). External audit is a hard
  gate before any mainnet exercise (post-plan).
- [ ] Documentation in
  [docs/concepts/gravity.md](../concepts/gravity.md) updated to
  reflect ref-bearing variant status.
- [ ] Brainstorm spike-findings doc published (Phase 2).
- [ ] Both Critical-severity security tests pass
  (`TestMultiRefSourceRejected` Part B script-level enforcement, and
  `TestSPVProofReuseAcrossOffers`).

## Success Metrics

| Metric | Measurement | Target |
|---|---|---|
| FT swap demonstrably atomic | End-to-end test green | Yes |
| NFT swap demonstrably atomic | End-to-end test green | Yes |
| Trust properties preserved | Red-team test suite passes (Critical-rated tests are blockers) | Yes |
| Settlement tx size | Byte count vs sentinel | ≤ 1.5× sentinel |
| Funding tx size | Byte count vs sentinel | ≤ 1.5× sentinel |
| Per-trade Taker-paid fee | Photons at documented relay floor | Documented in spike-findings brainstorm |
| Sighash backcompat | Golden vector regression test | Byte-identical |
| Mainnet small-amount exercise (post-audit) | Out of plan scope; tracked separately | Successful settlement on real BTC+RXD |

## Dependencies & Prerequisites

- **Radiant Core (current fork) on regtest** for the Phase 2 spike.
  Per memory:
  [project_radiant_core_current_repo](../../docs/concepts/gravity.md).
- **RXinDexer client** wired up for the Phase 6 Taker verification API
  ([rxindexer.py](../../src/pyrxd/network/rxindexer.py) has `glyph_*`
  RPCs; `swap_*` family is documented but not yet implemented and is
  not needed for this plan).
- **Existing SPV proof builder + sentinel covenant** unchanged; this
  plan adds alongside, does not modify.
- **Photonic codebase access** for the Phase 2 prior-art check.

## Risk Analysis & Mitigation

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| **Synthetic round-trip tests mask on-chain divergence (recurring dMint failure mode, 2× in 2026-05)** | High | High | Phase 4 golden-byte fixtures from real regtest broadcasts + `testmempoolaccept` gate; no builder merges on round-trip-through-own-parser alone |
| **Multi-ref smuggling at funding (Security Critical)** | Medium | High | Script-level `totalRefs==1` enforcement in Phase 2 templates; both Python pre-flight + script-level red-team tests in Phase 5 |
| **SPV proof reuse across concurrent offers (Security Critical)** | Medium | High (NFT) | Phase 2 spike chooses offer-binding mitigation (subaddress derivation, OP_RETURN, or doc-only); Phase 5 `TestSPVProofReuseAcrossOffers` |
| Two artifacts duplicate audit attention | Low | Medium | Internal audit (Phase 7) covers both; external audit (post-plan) is a hard gate before mainnet |
| Photonic has no prior art and Radiant-side script needs more design iteration than budgeted | Medium | Medium | Phase 2 is the bounded high-risk phase; extend the spike if needed before committing to Phase 4 |
| Sighash de-dup breaks plain-RXD Gravity trades silently | Low | High | Phase 1 golden vector regression test (multi-scenario, parameterized); byte-identical assertion; **adversarial vectors for `totalRefs >= 1`** added in this revision |
| Internal audit surfaces structural issues post-Phase-4 | Medium | High | Audit is Phase 7, before mainnet — discovery here defers mainnet exercise, doesn't break shipped code |
| Maker funds a covenant with a wrong-kind artifact and assets stall to deadline | Low | High | Phase 3 funding-input pre-flight validator + artifact-kind isolation tests |
| BTC reorg vanishes a confirmed payment, NFT-side loss is irreversible (vs RXD fungibility) | Low | High (NFT) | Document recommendation for deeper BTC confirmation count for high-value ref-bearing offers (parameter `btc_confirmations` in `verify_ref_offer`); out of v1 enforcement scope |
| Squatted ticker / phantom metadata fools Taker | Medium | Medium | Phase 6 verification API fails closed on missing metadata; doc note in red-team checklist; full provenance enforcement is post-v1 |
| ElectrumX reclassifies `code 1` policy rejection as `NetworkError` (recurring V1 dMint failure mode) | Low | High | Phase 4 typed `PolicyRejection`; Phase 5 `TestPolicyRejectionSurfaced` red-team test |

## Resource Requirements

- **One implementer** with familiarity with: Radiant script,
  BIP143-style sighash extension, the existing Gravity codebase, FT/NFT
  conservation rules.
- **Audit pair** (internal) for Phase 7; should not be the implementer.
- **Regtest Radiant Core node** for Phase 2 spike validation.
- **Total estimated effort:** ~6.5–9 weeks across all phases
  (spike-revised from 9–12 — see
  [spike-findings](../brainstorms/2026-05-19-gravity-ref-covenant-spike-findings.md)).
  Phase breakdown: Phase 1 — 1–2 days (sighash de-dup; ref-parsing
  already shipped); Phase 2 — 1–2 weeks (additive covenant work on an
  existing compositional-output pattern; ref-conservation regtest
  validation is the dominant unknown); Phase 3 — 5–7 days (type
  discipline + opcode-stream validator + property tests); Phase 4 —
  1.5–2 weeks (BTC half + golden-byte regtest fixtures +
  `testmempoolaccept` gate); Phase 5 — 2–3 weeks (end-to-end +
  red-team); Phase 6 — 5–7 days (async verifier); Phase 7 — 1 week
  (audit + docs). The collapse is real but smaller than the
  spike-first doc's headline 3–4× cases — this is genuinely new
  ref-bearing covenant work, not (like the BCH case) work the existing
  design had already done.

## Future Considerations

Out of scope for v1 but design-aware:

- **Unified `refKind`-dispatched covenant.** Plan default is split
  FT/NFT artifacts (security: avoids branch-confusion attack class).
  A future consolidation into one artifact with in-script `refKind`
  dispatch could reduce maintenance overhead, but only after measured
  data shows the split's audit/maintenance cost outweighs the
  security partitioning. External audit gate.
- **Multi-ref outputs.** Some FT designs and most NFT collections
  carry multiple refs per UTXO. v1 constrains `totalRefs == 1`; v2
  could relax.
- **Partial fills.** Would require a split-and-relock primitive. v1
  Maker can post multiple smaller-lot covenants instead.
- **Cancel-tx (cooperative early-exit).** Brainstorm dropped from v1;
  forfeit covers the failure path. Add later if Maker UX demands it.
- **WAVE-name first-class offers** (`verify_ref_offer_via_wave`).
  Cut from Phase 6 per WAVE-deferred policy. Trigger to revisit:
  a concrete downstream consumer needs Wave name → ref → offer
  lookup.
- **Glyph inspector integration.** Pattern-match the new covenants'
  P2SH hashes in `docs/inspect_static/inspect/inspect.js`. Separate
  follow-up issue.
- **Reclaim-to-new-address forfeit.** For NFTs where the original
  Maker reclaim key may be compromised, a future cancel-tx could allow
  reclaim-to-different-address with two-of-two Maker+Taker signatures.
- **External audit.** Per
  [docs/concepts/gravity.md:219](../concepts/gravity.md#L219), external
  audit is a **hard gate** for any mainnet exercise of the ref-bearing
  variant (NFT-irreversibility raises the bar). Plan-of-plan
  follow-up.

## Documentation Plan

| Doc | Update |
|---|---|
| [docs/concepts/gravity.md](../concepts/gravity.md) | New "ref-bearing covenant" section; status table; v1 limitations |
| [docs/red-team-checklist.md](../red-team-checklist.md) | New red-team categories: multi-ref smuggling, SPV proof reuse across offers, sort-order consensus, phantom metadata, duplicate-offer disambiguation |
| [docs/brainstorms/2026-05-MM-gravity-ref-spike-findings.md](../brainstorms/) | New (Phase 2 deliverable) |
| [docs/audits/2026-MM-DD-ref-covenant-audit.md](../audits/) | New (Phase 7 deliverable, audit 06 index target) |
| [CHANGELOG.md](../../CHANGELOG.md) | Unreleased "Added" entries for FT/NFT artifacts + Taker verification API |
| `examples/gravity_ref_ft_demo.py` (new) | Runnable FT swap demo, mirrors `examples/gravity_swap_demo.py` |
| ~~`examples/gravity_ref_nft_demo.py`~~ | Deferred to post-merge follow-up (per Simplicity #7) — NFT differs from FT by parameter choice, not by demo shape |

## References & Research

### Internal References

- **Brainstorm:** [docs/brainstorms/2026-05-19-gravity-glyph-ft-swap-brainstorm.md](../brainstorms/2026-05-19-gravity-glyph-ft-swap-brainstorm.md)
- **Existing Gravity overview:** [docs/concepts/gravity.md](../concepts/gravity.md)
- **Sighash de-dup targets:**
  [transaction_preimage.py:66](../../src/pyrxd/transaction/transaction_preimage.py#L66)
  (correct, reuse) and
  [gravity/transactions.py:93](../../src/pyrxd/gravity/transactions.py#L93) (delete)
- **FT/NFT script construction:**
  [glyph/script.py:127,135](../../src/pyrxd/glyph/script.py#L127),
  [glyph/ft.py:91-328](../../src/pyrxd/glyph/ft.py#L91)
- **GlyphRef:** [glyph/types.py:32-95](../../src/pyrxd/glyph/types.py#L32)
- **End-to-end test pattern:**
  [tests/test_gravity_trade.py::TestGravityTradeP2PKH at line 945](../../tests/test_gravity_trade.py#L945)
- **Red-team test pattern:**
  [tests/test_gravity_red_team.py:143-501](../../tests/test_gravity_red_team.py#L143)
- **Sighash mainnet vectors:**
  [tests/test_preimage.py::TestComputeHashOutputHashes](../../tests/test_preimage.py)
  pinned against tx `dac1e2dfed64fbfd0f0fe6b925e144cfc32ef76803abc7a6a4058406d707b407`
- **Covenant loader + deny-list:** [gravity/covenant.py:59-194](../../src/pyrxd/gravity/covenant.py#L59)
- **Lazy public API:** [src/pyrxd/__init__.py](../../src/pyrxd/__init__.py),
  [gravity/__init__.py](../../src/pyrxd/gravity/__init__.py)
- **WAVE resolver:** [glyph/wave.py:206-264](../../src/pyrxd/glyph/wave.py#L206)
- **Photonic reference:** `docs/dmint-research-photonic.md` §2.1 (ref-preservation pattern)

### Conventions

- **Commit style:** Conventional Commits, ≤72 char subject, DCO sign-off
  ([CONTRIBUTING.md:130-142](../../CONTRIBUTING.md#L130))
- **CI gate:** `task ci`; coverage gates `coverage-security` (100%) and
  `coverage-overall` (≥85%) ([CONTRIBUTING.md:62-74](../../CONTRIBUTING.md#L62))
- **Audit citations:** inline `audit NN-SX` / `audit NN-F-N` (hyphenated)
  comments at point of enforcement. Existing audits: `04`, `05`. **This
  plan reserves `audit 06`** for its Phase-7 audit pass. Top-of-file
  index in `gravity/ref/covenant.py` maps `audit 06 → docs/audits/...`.
- **Brainstorm/plan naming:** `YYYY-MM-DD-<topic>-{brainstorm,plan}.md`

### Related Work

- [docs/brainstorms/2026-05-19-gravity-bch-spike-findings.md](../brainstorms/2026-05-19-gravity-bch-spike-findings.md) — BCH-support spike (informs the SPV reuse story)
- [docs/brainstorms/2026-05-19-gravity-p2pkh-spike-findings.md](../brainstorms/2026-05-19-gravity-p2pkh-spike-findings.md) — P2PKH support, informed BTC-output dispatch reuse
- [docs/dmint-followup.md](../dmint-followup.md), [docs/threat-model.md](../threat-model.md), [docs/red-team-checklist.md](../red-team-checklist.md) — adjacent security context

### Institutional learnings applied (recurring failure modes prevented)

- [docs/solutions/design-decisions/spike-first-then-convergent-design-divergent-review-panels.md](../solutions/design-decisions/spike-first-then-convergent-design-divergent-review-panels.md) — read current code before trusting doc-derived estimates; run a divergent review pass to prune over-design. **Applied:** divergent review = the 6-reviewer deepen pass; spike-first = [2026-05-19-gravity-ref-covenant-spike-findings.md](../brainstorms/2026-05-19-gravity-ref-covenant-spike-findings.md), which revised the estimate from 9–12 to ~6.5–9 weeks after reading the actual covenant asm.
- [docs/solutions/logic-errors/dmint-v1-mint-shape-mismatch.md](../solutions/logic-errors/dmint-v1-mint-shape-mismatch.md) — synthetic round-trip passed; real bytes diverged. **Applied:** Phase 4 golden-byte fixtures from real regtest broadcasts.
- [docs/solutions/logic-errors/dmint-v1-mint-scriptsig-divergence.md](../solutions/logic-errors/dmint-v1-mint-scriptsig-divergence.md) — `code 1` reclassified as `NetworkError` masked critical bug. **Applied:** Phase 4 typed `PolicyRejection`; Phase 5 `TestPolicyRejectionSurfaced`.
- [docs/solutions/logic-errors/funding-utxo-byte-scan-dos.md](../solutions/logic-errors/funding-utxo-byte-scan-dos.md) — bare-byte deny-list rejected ~51% of legitimate inputs. **Applied:** Phase 3 opcode-stream walker (no byte-scan); `TestFundingDenyListFalsePositive`.
- [docs/solutions/logic-errors/dmint-v1-classifier-gap.md](../solutions/logic-errors/dmint-v1-classifier-gap.md) — synthetic V2 fixtures passed; mainnet inspection failed. **Applied:** Glyph inspector integration deferred + requires real-bytes fixture when it lands.
- [docs/solutions/logic-errors/dmint-deploy-reveal-hashlock-reuse.md](../solutions/logic-errors/dmint-deploy-reveal-hashlock-reuse.md) — reused hashlocks confuse scripthash-history walkers. **Applied:** Phase 6 `verify_ref_offer` takes funding outpoint, not scripthash; `TestDuplicateOfferDisambiguation`.
- [docs/solutions/design-decisions/fuzzing-strategy-graduated-approach.md](../solutions/design-decisions/fuzzing-strategy-graduated-approach.md) — graduated Hypothesis → Atheris → OSS-Fuzz strategy. **Applied:** Stage-1 Hypothesis property tests on funding validators (Phase 3) and pre-broadcast validator (Phase 4).
- [docs/solutions/design-decisions/wave-protocol-deferred-until-consumer.md](../solutions/design-decisions/wave-protocol-deferred-until-consumer.md) — WAVE deferred until concrete consumer. **Applied:** `verify_ref_offer_via_wave` cut from Phase 6.
- [docs/solutions/design-decisions/expert-panel-pivot-before-coding.md](../solutions/design-decisions/expert-panel-pivot-before-coding.md) — pre-implementation expert review prevented coding the wrong primitive. **Applied:** half-day adversarial review checkpoint between Phase 2 spike and Phase 4 implementation.
- [docs/solutions/integration-issues/local-ci-parity-via-task-ci-and-pre-push-hook.md](../solutions/integration-issues/local-ci-parity-via-task-ci-and-pre-push-hook.md) — pre-push hook required for CI parity. **Applied:** Quality Gates section.
