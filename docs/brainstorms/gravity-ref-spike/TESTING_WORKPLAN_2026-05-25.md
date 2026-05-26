# Gravity expanded-testing work plan (2026-05-25)

Prioritized from the security-posture review. Each item lists what it *proves*,
the effort (grounded in a code read, not doc-derived), the risk, and the
provenance upgrade it buys. Ordered by leverage (value ÷ effort ÷ risk).

> **Standing truth:** the highest-leverage step overall is an **independent
> external audit** — everything to date shares one author. The items below
> harden the mechanical layer and de-risk the demo; they do NOT substitute for
> third-party review, and none of them closes a *design/trust* gap (REF
> provenance, SPV-oracle non-atomicity, indexer trust). See the posture review.

---

## Tier 1 — free, zero-risk, do first

### T1. Overnight high-iteration differential fuzz
- **Proves:** parser equivalence (Python SDK ≡ covenant ASM) at 10M+ scale,
  beyond the 2M already run.
- **How:** `scripts/fuzz_overnight.sh` (staged, not yet run). Bumps `DIFF_FUZZ_N`
  and runs the existing `test_differential_fuzz_no_novel_divergence`, plus the
  Hypothesis SPV fuzz at a high budget multiplier.
- **Effort:** ~0 (script ready). **Risk:** none (local, offline).
- **Provenance buy:** "0 novel in 2M" → "0 novel in 10M+".
- **Exit signal:** any line containing `NOVEL` or `leaked` = real finding →
  stop and investigate with the Iron Law.

### T2. Atheris on the Merkle/PoW path (currently UNFUZZED) — DONE, FOUND 2 BUGS
- **Proves:** `build_branch`, `compute_root`, `extract_merkle_root`,
  `verify_header_pow` only ever raise `ValidationError`/`SpvVerificationError` on
  adversarial input — no raw `ValueError`/`struct.error`/etc. past the boundary.
- **RESULT (2026-05-25):** harness `harness_spv_merkle_pow.py` crashed within 5k
  runs — `compute_root` AND `build_branch` both leaked a raw `ValueError`
  ("non-hexadecimal number found in fromhex()") on a non-hex / wrong-length input
  string, violating their documented `Raises: ValidationError` contract. LOW
  severity (not reachable as a swap exploit — `build()` validates the txid against
  `hash256` before these run — but a public-boundary contract violation). FIXED:
  both now validate 64-char hex before `fromhex`. 50k-run clean after. Regression:
  4 tests in `TestMerkle`. The fuzzer found what read-review + the prior sweep missed.

### T3. Land T2 as a Hypothesis CI regression
- After T2 finds nothing (or fixes what it finds), encode the contract as a
  bounded Hypothesis test in `tests/test_fuzz_spv_parsers.py` so it stays
  covered. **Effort:** ~30min. **Risk:** none.

---

## Tier 2 — local, zero-risk, moderate effort

### T4. Full any-wallet covenant deploy + spend-test on regtest
- **Proves ON REAL CONSENSUS:** R2 (scriptSig≥128B rejection) and the
  forged-payment-in-scriptsig defense — currently proven-in-sim + by-source +
  differential-fuzz, but NOT yet spent against a live covenant UTXO.
- **How:** isolated regtest (radiant-core:v2.3.0 image, the same harness used for
  R1). Deploy the compiled `GravityNftCovenantAnyWallet20.rxd` (artifact already
  present — no recompile), fund it, then attempt (a) a legit finalize, (b) a
  scriptSig≥128B finalize, (c) a forged-payment finalize. `testmempoolaccept`
  each.
- **Effort:** ~3–5h. The spike builders (`fund_fused.py` etc.) are CLI-arg
  driven, NOT network-hardcoded — adaptable to regtest — but assume a funded
  FT/NFT input, so the funding plumbing (mint a regtest singleton → fund covenant
  → build finalize) is the real work. The `.rxd` artifact exists.
- **Risk:** none (isolated regtest). **Provenance buy:** R2 + forged-payment
  "proven-in-sim" → "proven-on-consensus" — the strongest evidence class.

### T5. Two-wallet adversarial swaps on regtest (HTLC path)
- **Proves:** the deadline-race and mutual-refund FSM transitions behave on real
  consensus with two independent parties; the CSV refund actually matures and
  spends; a malicious-maker fake-singleton settles to a worthless asset
  end-to-end (the R1 *impact*, not just the consensus rule).
- **Blocker:** requires the concrete HTLC legs (T7) to exist — today they're
  test fakes. **Sequence T7 before T5.**
- **Effort:** ~4–6h once T7 lands. **Risk:** none (regtest).

---

## Tier 3 — needs real funds (your "fine to lose a little" budget)

### T6. Dust-sized mainnet happy-path + refund lifecycle
- **Proves:** the refund-leaf fix (was unspendable) and the full claim/refund
  cycle spend against REAL mainnet relay policy — which regtest does NOT model.
  This is the one place a few lost dollars buys something regtest can't.
- **How:** fund a dust HTLC on mainnet, run a real claim; separately, fund
  another, let CSV mature, run a real refund. Confirm both land.
- **Effort:** ~2–3h. **Risk:** the dust (intentional). **Needs from you:** a
  funded mainnet wallet + an amount cap. I will NOT run any adversarial mainnet
  swap regardless of budget — regtest answers those better and a live reorg
  attempt is antisocial.
- **Provenance buy:** refund-leaf + lifecycle "proven on regtest" → "proven on
  mainnet incl. relay policy".

---

## Tier 4 — unblocks Tier 2/3, but is build work not test work

### T7. Ship the concrete HTLC legs (BitcoinTaprootLeg, RadiantCovenantLeg, indexer, seen-store)
- Today the `SwapCoordinator` safety gates are only as real as injected fakes.
  Until concrete legs exist, the coordinator cannot move value and T5/T6 can't
  exercise it. This is **implementation**, gated by design review (and ideally
  the external audit), not a test task — listed here only because it blocks the
  end-to-end tests above.

---

## Cannot test (recorded so we stop trying)

- **REF provenance via consensus** — deliberate non-feature; only the off-chain
  gate addresses it, and a test can confirm the gate runs, not that the gap closed.
- **Adversarial cross-chain swaps on mainnet** — needs a live counterparty +
  irreversible chain; `testmempoolaccept` short-circuits on `missing-inputs`.
  Regtest is correct + safe.
- **The trust model** (SPV-oracle non-atomicity, indexer trust, federation vs
  trustless) — design/economic analysis, not fuzzing.
- **Unknown-unknowns** — only an independent external audit reduces this.

---

## Suggested order

T1 (overnight, now-ready) → T2 → T3 → T7 → T4 → T5 → T6, with the **external
audit** initiated in parallel as the real gate. T1–T3 are pure win (free, zero
risk). T4 is the best evidence-per-effort consensus upgrade. T6 is the only item
needing your funds and the only one regtest can't cover.
