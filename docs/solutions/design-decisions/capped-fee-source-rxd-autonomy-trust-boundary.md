---
title: "CappedFeeWalletSource: a structural spend ceiling is the trust boundary for autonomous RXD fee-paying"
category: design-decisions
component: gravity / watchtower / fee-source
tags:
  - fee-source
  - trust-boundary
  - autonomy
  - watchtower
  - capped-spend
  - structural-limit
  - build-now-arm-never
  - pre-audit
date: 2026-06-14
severity: medium
symptom: >
  Every future autonomous RXD action (an autonomous covenant claim/refund fired by the
  watchtower) needs a key that can pay a miner fee. The only fee source that existed was the
  UNCAPPED SshTrFeeSource, which carves a fresh fee UTXO from the operator's FULL wallet on
  every call — so the worst-case spend of an autonomous, possibly-buggy, possibly-compromised
  process is "the whole wallet". That is the wrong trust boundary to ever wire into a daemon.
root_cause: >
  A fee key wired into an autonomous loop is a standing authorisation to spend. The safety
  question an auditor asks is not "is the spend logic correct?" but "what is the MOST this key
  can spend if every software check is wrong?". With the uncapped source the answer is unbounded
  (wallet balance). The fix is to make the ceiling STRUCTURAL — enforced by the chain, not by a
  software counter a bug could skip.
---

# CappedFeeWalletSource — the structural ceiling for autonomous RXD fees

## The decision

Autonomous RXD fee-paying goes through **`CappedFeeWalletSource`**
(`pyrxd.gravity.capped_fee_source`), a `FeeUtxoSource` backed by a **fixed, pre-funded pool**
of small plain-RXD UTXOs. It can dispense **only the finite inventory it was constructed with**,
so the most it can ever spend is its funded balance. The uncapped `SshTrFeeSource` is for
**interactive, operator-confirmed** dust runs only and must **never** be wired into an
autonomous tower as a stopgap.

## Why the ceiling is *structural*, not just a check

The source holds **only the small pool wallet's key**, never the operator's main wallet. The
pool wallet has no other coins, so even if every software guard below were bypassed, the source
cannot spend more than the pool's on-chain balance — the chain enforces it. That is the load
bearing property: a software-only "stop at N photons" counter is one missed branch away from
failing open; an empty wallet is not.

Two **defense-in-depth** software guards sit on top:

- **`total_cap_photons`** — a cumulative ceiling, so the operator can authorise spend *below*
  the funded balance (fund 10 inputs, authorise 6 inputs' worth) and raise it only deliberately.
- **`max_per_input_photons`** (optional) — refuses construction if any pool UTXO is larger than a
  single fee should ever be, keeping the "a fee input is small" invariant structural rather than
  assumed.

## Dispense-once

`next_fee_input()` **commits** each UTXO (advances a cursor); a dispensed input is never handed
out again, even if the spend that consumed it is later abandoned. A dispensed-but-unused input is
a conservative loss of one small pool UTXO — strictly better than the alternative failure, which
is dispensing the same outpoint into two transactions and **double-spending the fee input**. When
the pool is empty or the cap is reached, it raises `FeePoolExhaustedError` (a `RxdSdkError`
subclass) and the caller must **fail closed** — page / refuse the autonomous action rather than
reach for a larger wallet.

## Build-now, arm-never (pre-audit posture)

The primitive is **built and tested now** so the trust boundary exists in code and can be
reasoned about by an auditor — but **no real pool key is wired into a running tower** until the
external security audit clears. Until then it is exercised only with throwaway pools in
`tests/test_capped_fee_source.py`. This mirrors the project rule that every value-bearing
autonomy item stays dormant-by-construction pre-audit (the v2 watchtower's keyless refund is the
same posture).

## What an auditor must still verify (residual for the auditor brief)

- The pool wallet is **genuinely isolated** from the operator's main funds (a separate key/seed,
  no shared change path) — the structural guarantee is only as good as that isolation.
- **Refill is a manual, audited operation**, never an automatic top-up from the main wallet (an
  auto-refill would re-introduce the unbounded ceiling the cap exists to remove).
- The caller (the autonomous spend path) **treats `FeePoolExhaustedError` as fail-closed** and
  has no fallback to an uncapped source.
- **The leg's type gate does not enforce "capped".** `RadiantCovenantLeg` accepts any
  `FeeUtxoSource` (a `runtime_checkable` Protocol that only checks a `next_fee_input` method
  exists by name), so the uncapped `SshTrFeeSource` passes the *same* gate as this class. "Autonomy
  uses the capped source" is therefore wiring discipline, not a type guarantee — the future
  autonomous wiring MUST assert the concrete `CappedFeeWalletSource` type (not just `FeeUtxoSource`)
  so a wiring mistake or refactor cannot silently restore the unbounded-spend source.

## See also

- `pyrxd.gravity.capped_fee_source.CappedFeeWalletSource` — the implementation + module docstring.
- `pyrxd.gravity.radiant_leg.FeeUtxoSource` — the `next_fee_input()` contract it satisfies.
- The watchtower's autonomy notes in `src/pyrxd/gravity/watch/README.md` (each autonomous action
  needs this fee-key custody seam).
