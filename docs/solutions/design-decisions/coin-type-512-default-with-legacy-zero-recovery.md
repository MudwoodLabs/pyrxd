---
title: Keep coin type 512 as new-wallet default; expose legacy 0 path as first-class recovery option
date: 2026-05-03
problem_type: design_decision
component: hd-wallet
symptoms:
  - Photonic Wallet (the most-used Radiant wallet) derives at m/44'/0'/0', while pyrxd defaults to m/44'/512'/0' (SLIP-0044 spec)
  - Users restoring a Photonic mnemonic into pyrxd see an empty wallet — the funds exist but live at a path pyrxd is not looking at
  - The override mechanism (RXD_PY_SDK_BIP44_DERIVATION_PATH) exists but is undiscoverable for non-expert users
  - The override is parsed once at module-import time and is not threaded through HdWallet.from_mnemonic, so per-call configuration is impossible
  - Wallet files persist coin_type at save but the load path does not validate it against the active config — a silent default flip would silently watch the wrong addresses
severity: high
status: decided, implementation pending
related_prs:
  - "#14 (switched default from 236' to 512' on 2026-04-26)"
related_issues: []
tags:
  - hd-wallet
  - bip44
  - slip-0044
  - derivation-path
  - coin-type
  - photonic-wallet
  - migration
  - api-design
  - default-selection
  - expert-panel
  - ecosystem-coordination
  - radiant
---

## Root Cause Analysis

pyrxd inherited the BIP44 coin type problem twice. The original default `236'` was inherited from BSV-related code that pyrxd's earliest authors had been working on. PR #14 fixed that by switching to `512'`, the SLIP-0044 spec-correct value for Radiant — which is what Tangem uses, and which is what every future Radiant wallet *should* use. That fix was technically right and deliberately ignored the question of what existing software wallets were actually doing.

A week later, empirical verification (deriving the same throwaway mnemonic in pyrxd and Photonic, comparing receive addresses) confirmed that **Photonic — the dominant Radiant software wallet — uses `m/44'/0'/0'`**, Bitcoin's coin type. This was not a guess; it was a side-by-side comparison: a throwaway 12-word BIP39 mnemonic (generated for this verification, not reused, not recorded here) derived `1LWS7rzGZxsjapwkWrtxgQVs89xfaPQxuB` at `m/44'/0'/0'/0/0` in pyrxd, and the same address is what Photonic shows on import of that mnemonic. So pyrxd's spec-correct default produces empty wallets for the most common restoration case, and the recovery note in the wallet docstring points users at the wrong legacy path (`236'` instead of `0'`). The verification was later re-run with the canonical BIP39 test mnemonic `abandon abandon ... about` (publicly known, intentionally weak — see test vector at `tests/test_hd_wallet.py::TestCoinTypeKwarg::EXPECTED_0`), with the same Photonic-matching result, so the locked-in test vector is itself end-to-end Photonic-verified.

The deeper failure mode underneath is architectural: the derivation path is global module-import-time state (`_RADIANT_PATH` parsed once in `src/pyrxd/hd/wallet.py`), with no per-call override on `HdWallet.from_mnemonic`. The env var works, but only if set before the process starts. Wallet files record `coin_type` at save time and the load path does not assert it matches the active config — so a default flip in a routine `pip install -U` would silently change which addresses an exchange or indexer watches, with no error and no warning. That is the kind of behavior that ends up in a postmortem.

The decision question — "should we change the default?" — sits on top of two more fundamental defects: missing per-call configuration, and missing load-time validation. Reordering the work so the foundational fixes ship first means the default question stops being load-bearing.

## Solution

**Keep `m/44'/512'/0'` as the default for new wallets; add the legacy `m/44'/0'/0'` path as a first-class option for restoration; ship the foundational architectural fixes first.**

This is the same plan CraigD (Avian core dev) proposed independently in Discord, drawing on Avian's lived experience of the identical migration (coin type 175 → 921 for Avian/Ravencoin). The Avian wallet UI already implements the pattern and serves as a reference: a radio button under Advanced Options, defaulting to the spec-correct value, with the legacy option clearly labeled "use this for wallets created in [legacy app]." pyrxd will mirror the labeling: `512 - Radiant (Standard)` / `0 - Legacy Bitcoin-compatible`.

**The decision is supported by independent triangulation.** Three reviewers and one external ecosystem dev arrived at converging conclusions from non-overlapping vantage points:

- **Architecture review** argued that SDK defaults are read by tooling builders, not end users; spec correctness compounds while popularity drift does not; Bitcoin Cash precedent (the BCH ecosystem aligned to coin type 145 within roughly a year of the change) shows this kind of migration is achievable. Strongest argument: changing the default to `0'` would make pyrxd's default a public vote for the wrong path on the spec coordination question that PR #14 just took a public position on.
- **Security review** argued that the *manner* of any default change matters more than the value. Silent flips are postmortem-grade events. A wallet that previously received funds at the default path would now receive them at a different path, splitting the user across two derivation trees with no UI surface to reconcile them. Whatever default we ship, load-time validation against the persisted `coin_type` is non-negotiable.
- **Simplicity review** pushed back hardest on premature abstraction (the originally-proposed `--wallet-compat tangem|photonics|electrum-rxd` preset registry was rejected as "three lines of fiction wearing a trench coat" — `tangem` cannot import mnemonics, `electrum-rxd` was unverified, leaving `photonics` as the one real entry, which is just `m/44'/0'/0'`). A coin-type integer is sufficient.
- **CraigD (external)** confirmed the plan from inside an ecosystem that just lived through the same migration. His proposal — default new wallets to `512'`, keep `0'` as legacy support, label both clearly, scan both paths or let users override on import, recommend a phased migration — is now the working specification.

**The plan has three phases, sequenced so the architectural prerequisites ship before the user-visible decisions.** Phase 1 fixes the foundational defects: thread `derivation_path` (or `coin_type`) through `HdWallet.from_mnemonic` and `load_or_create` as a per-call kwarg, and add load-time validation that the persisted `coin_type` matches the active config (replacing silent-empty-wallet with an actionable error message). Phase 2 adds the user-facing surface: a `pyrxd setup --coin-type {512,0}` flag with help text mirroring the Avian labels, and either auto-scan-both-paths or explicit prompt during restoration. Phase 3 explicitly defers the preset registry until a second wallet is confirmed to differ — which may never happen, since coin-type integers cover every BIP44 wallet that will ever exist on this chain.

**The migration story for users with funds at either path is symmetric.** A user with Photonic-derived funds runs `pyrxd setup --coin-type 0` (or sets the env var) to access them, and is shown a banner suggesting they create a fresh `--coin-type 512` wallet and migrate funds at their own pace. A user with pyrxd-derived funds at `512'` from the week-long window between PR #14 and this work is unaffected (default does not change). No flag day, no forced migration, no version bump that breaks existing wallets.

**What CraigD's clarifying note settles for users worried about transaction-format risk:** "the coin type only affects which deterministic wallet path is used to discover addresses from a recovery phrase." This is a key-derivation question, not a chain-split or transaction-format question. Funds are recoverable from any wallet that knows the mnemonic and the path; the question is which wallet, by default, looks at which path. Stating this plainly in user-facing documentation removes the "is this a hard fork?" anxiety.

**What we explicitly rejected and why.** Runtime path detection (try multiple paths, pick the one with funds) was rejected as a chain-of-confusion attack surface for multi-account users and a way to hide the fragmentation problem rather than surface it. A configuration file as the primary mechanism was rejected as "a slower env var with worse precedence rules" — the env var stays, but per-call configuration is the missing primitive. Auto-mapping by mnemonic provenance was rejected because there is no signal in a mnemonic that identifies which wallet produced it. Versioned preset names (`photonics-2026-05`) were considered for security-sentinel-flagged drift risk and shelved with the rest of the preset registry under YAGNI; if Photonic later switches paths, that is a future decision with future evidence.

**Hazards documented but not fixed in Phase 1.** A red-team review (security-sentinel + data-integrity-guardian + adversarial general-purpose, 2026-05-03) surfaced two hazards that are real but cannot be fixed inside this PR alone:

- **NEW→OLD→NEW downgrade corruption.** A user who upgrades to Phase-1 pyrxd, saves a wallet at `coin_type=0`, then downgrades to a pre-this-PR pyrxd version and saves again will have the persisted JSON `coin_type` field overwritten to `512` (the old code's hardcoded behavior at save time) while their `_xprv` keys remain rooted at `m/44'/0'/...`. A subsequent re-upgrade and load with `coin_type=0` will then fail validation against the now-corrupted `512` JSON, locking the user out of the friendly recovery path. This is purely an old-code-side defect; the fix lives in versions of pyrxd we cannot retroactively change. **Mitigation:** document explicitly in user-facing release notes that downgrading is unsupported once Phase 1 ships, and recommend that production users pin their pyrxd version through the migration window.
- **Photonic compatibility is verified once, against one Photonic build, on one date.** On 2026-05-03 the canonical BIP39 mnemonic `abandon abandon ... about` was restored in Photonic Wallet; its Receive screen displayed `1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA`, which is exactly the value pyrxd's test suite locks in at `coin_type=0` — so the test is a real cross-wallet compatibility check today, not a regression-only guard. The hazard is *future drift*: Photonic publishes no versioned compatibility statement, and pyrxd has no mechanism to detect a path change in a future Photonic release (the preset registry that would have made this a tracked vocabulary was rejected as YAGNI). If Photonic ever ships a derivation-path change, pyrxd's `coin_type=0` advice will silently become wrong. **Mitigation:** Phase 2 work plan includes a quarterly re-verification task against `abandon abandon ... about`; a Photonic-version note belongs in user-facing CLI help text and release notes; if a drift is detected, ship a new value and document the date both addresses were valid.

## Lessons & Patterns

- **Spec-correct defaults can lose to popularity in the short run, but they compound in the long run.** A library's default is a vote on what the ecosystem should look like in five years, not a customer-service response to what is most popular today. Pick the long-run-correct value, document the short-run mismatch loudly, and ship the recovery path as a first-class option — not an undiscoverable env var.
- **A "fix" that solves the technical question without surveying the ecosystem can ship a worse failure mode.** PR #14 was right about the spec and silent about Photonic; one week later we discovered the change broke the most common restoration flow. The lesson is not that PR #14 was wrong (it was correct) — the lesson is that "is this spec-compliant?" and "does this match what users will actually do?" are independent questions and both must be asked before merging a change to a user-facing default.
- **The decision question often sits on top of foundational defects.** "Should we change the default?" was the visible question. "Is the default even per-call configurable?" and "Does load-time validation catch a bad config?" were the invisible prerequisites. Sequencing the architectural fixes first makes the policy question dramatically less load-bearing — once override is per-call and validation is loud, the cost of any default value being "wrong" for a given user collapses from "silent empty wallet" to "actionable error with the fix-it command in the message."
- **Empirical verification of an external system's behavior is cheap and decisive.** The entire architectural debate was unblocked by deriving one throwaway mnemonic in two wallets and comparing addresses. Total cost: about ten minutes. Total information gained: which path Photonic actually uses, with no ambiguity, no reading of obfuscated source code, no trust assumptions. When a question hinges on "what does this external system actually do?" — restore a throwaway seed and look. Don't reason about it.
- **A reference implementation from a sister ecosystem is worth more than a panel of internal opinions.** CraigD's Avian migration plan was concrete, tested in production, and already had a working UI. The internal review panel produced excellent analysis but converged toward the same answer that Avian had already shipped. When a similar ecosystem has solved a similar problem, find their reference implementation before designing your own — even if the internal review would have arrived at the same place, having the working precedent shortens the path from decision to ship and reduces the risk of an unforced error.
- **The override mechanism existing is not the same as it being usable.** `RXD_PY_SDK_BIP44_DERIVATION_PATH` had been in pyrxd since well before PR #14, parseable by anyone willing to read `constants.py`. It did not save users with Photonic funds because the env-var-only surface fails the discoverability test for non-expert users. Discoverability is part of the API. An undocumented escape hatch that requires source-reading is, in user-experience terms, equivalent to no escape hatch at all.
- **Registries of presets are forever-promises.** Adding `--wallet-compat photonics` would commit pyrxd to tracking Photonic's behavior across every future Photonic version. The simplicity reviewer's pushback was right: don't take on the maintenance promise unless there are at least two confirmed wallets that actually need distinct presets, and unless the integers themselves are insufficient. Coin-type integers are self-documenting once labeled (`512 - Radiant (Standard)`, `0 - Legacy Bitcoin-compatible`); preset names are not.
- **Sequencing matters more than scope when foundational defects are involved.** The original framing ("should we add `--wallet-compat`?") would have led to building user-facing surface on top of a broken architectural primitive. Reordering the work — kwarg plumbing first, load validation second, CLI surface third — means each phase builds on a solid foundation, and any phase that gets deprioritized still leaves the codebase better than before. This is the inverse of the more common "ship the user-visible feature first, fix the architecture later" pattern, which tends to leave the architecture permanently unfixed.
