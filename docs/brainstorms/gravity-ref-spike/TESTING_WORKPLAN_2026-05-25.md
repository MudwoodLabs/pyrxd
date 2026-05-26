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
  forged-payment-in-scriptsig defense.
- **STATUS: DROPPED — won't-fix.** Per
  [`spv-swap-deprecated-primitive-retained.md`](../../solutions/design-decisions/spv-swap-deprecated-primitive-retained.md),
  the SPV-oracle SWAP is deprecated (HTLC dominates it). R2 + forged-payment live
  ONLY on that retired swap covenant, so spend-testing them hardens a path we're
  leaving. Documented, not fixed. (The SPV *primitive* — merkle/pow/verify_payment —
  is retained for bridge-in/oracle use and stays lightly maintained, but its
  *swap* covenant is not worth regtest effort.)

> **The atomic swap is the HTLC path. Tier 2 effort goes there.** The bottleneck
> is that the HTLC swap cannot run end-to-end yet — the coordinator's legs are
> test fakes. Build them (T7), then the adversarial regtest tests (T5) unblock.

### T7. Build the concrete HTLC swap legs (THE Tier-2 starting point)
- **Why first:** `SwapCoordinator` takes `btc_leg`, `radiant_leg`, `indexer`,
  `seen_store` as injected objects; only test fakes exist, so the swap cannot
  move value or be exercised end-to-end. Everything HTLC-path is blocked on this.
- **The interface is fully defined** by the coordinator call-sites + the fakes
  (`tests/test_swap_coordinator.py`) — this is wrapping EXISTING primitives, not
  new crypto:
  - `BtcLeg`: `derive_funding_scriptpubkey`, `promised_funding_scriptpubkey`,
    `fund`, `claim`, `refund`, `scrape_secret` — wrap `btc_wallet/taproot.py`
    (`build_htlc`, `build_claim_tx`, `build_refund_tx`, `scrape_secret`) + a
    BTC broadcast / UTXO-tracking layer.
  - `RadiantLeg`: `expected_covenant_scriptpubkey`, `covenant_outpoint`,
    `claim_asset`, `refund_asset` — wrap `gravity/transactions.py` covenant
    builders + Radiant broadcast.
  - `Indexer`: `verify_ref` — the R1 gate dependency (resolve a genesis ref to a
    real Glyph reveal via RXinDexer).
  - `SeenStore`: `has_seen` / `mark_seen` — a persistent set (H-freshness).
- **Effort:** the primitives exist, so this is wrapper + broadcast/UTXO plumbing
  + a leg-conformance test suite. Estimate deferred to a spike read of the
  broadcast/UTXO layer (don't trust this number until the actual path is read —
  doc-derived estimates here have run high).
- **Gate:** this is implementation, ideally after (or alongside) the external
  audit, since it's the code that will move real value. Design-review the leg
  boundary before building — run a DIVERGENT review panel (architecture +
  simplicity + kieran-python + security, writing independently) on the leg
  interface design before coding, and spike-read the BTC/Radiant broadcast +
  UTXO-tracking layer to get a real effort estimate (do not trust a doc number).
- **Risk:** none to write; the risk is in what it later enables (real swaps).

### T5. Two-wallet adversarial HTLC swaps on regtest (unblocked by T7)
- **Proves ON REAL CONSENSUS:** the happy-path claim (preimage reveal) and the
  CSV refund both spend; the deadline-race and mutual-refund FSM transitions
  behave with two independent parties; the R1 *impact* end-to-end (a
  malicious-maker fake-singleton settles to a worthless asset — the regtest R1
  PoC proved the consensus rule; this proves the swap-level consequence).
- **Effort:** ~4–6h once T7 lands. **Risk:** none (isolated regtest, two wallets).

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
