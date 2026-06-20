---
title: "The autonomous claim executor follows the as-is posture: arm-by-exception, consent not paternalism"
category: design-decisions
component: gravity / watchtower / claim-executor
tags:
  - atomic-swap
  - watchtower
  - autonomous-claim
  - hot-key
  - posture
  - as-is
  - capped-fee-source
  - consent
  - audit-gate
date: 2026-06-20
---

# The autonomous claim executor follows the as-is posture

## Context

0.9.0 deliberately aligned pyrxd's maturity posture to the rest of the Radiant ecosystem:
the library is **open-source software, provided as-is, and "does what you tell it," like running
a Radiant node.** Concretely, the library-wide `require_audit_cleared` /
`require_spv_sole_authority_cleared` gates were demoted to **advisory no-ops** — they no longer
hard-block mainnet/real-value use.

That left one component out of step: the **autonomous claim executor**
(`gravity/watch/claim_executor.py`). It is the single place pyrxd holds a *hot key* and acts
*unattended* — broadcasting a covenant claim on a `SAFE` reorg verdict while the operator is not in
the loop. It is therefore a conscious **exception** to the keyless-watchtower invariant, and its
own design comments still assumed the old hard gate ("a live leg only exists on an audit-cleared
network"), which the 0.9.0 no-op silently falsified.

## Decision

Make the executor **match the as-is posture, with the care its risk class warrants** — i.e.
*consent, not paternalism*. The rule of thumb: the library blocks **theft you did not consent to**;
it does **not** block **risk you knowingly take**.

1. **Cannot redirect the asset (structural, non-negotiable).** The claim is keyless: `output[0]`
   is pinned to the taker holder PKH, and the watchtower holds no value key — it only scrapes the
   maker's already-public preimage and pays the fee. A compromised *fee* key can burn dust fees /
   DoS, never steal the asset. This is the one hard guarantee, because it prevents non-consensual
   theft.

2. **Arm-by-exception (the affirmative "tell it").** On a value-bearing network the executor
   broadcasts nothing unless `enable_autonomous_mainnet_custody=True` (default off). This is the
   literal "does what you tell it" — the no-op'd audit gate no longer demands it, so the executor
   demands it explicitly for the one unattended-hot-key path. This is consent, not a cap: it bounds
   nothing the operator can do by hand.

3. **Value caps are defaults you raise with explicit per-value consent — not hard blocks.** The RXD
   autonomous-claim ceiling (`claim_dust_ceiling`, default 10 000 photons = dust) is an operator
   setting you *raise by stating the magnitude*. What stays unwaivable is that the **blunt**
   `accept_unbounded_reorg_risk` flag cannot cross whatever ceiling is configured (a 2026-06-14
   red-team fix: one boolean must never arm an arbitrary-value claim). So "non-dust" requires a
   conscious *number*, not a conscious *checkbox*.

4. **Capped fee source: recommended, not enforced.** `CappedFeeWalletSource` bounds a hot-fee-key
   compromise to a small pool. The leg accepts any `FeeUtxoSource` (it does **not** `isinstance`-gate
   the capped type) — forcing it would be the same paternalism shape as the gate 0.9.0 removed. The
   library hands you the safe tool and recommends it; it does not refuse your fee source. (Residual
   `CAPFEE-TYPE-GATE`, now `accepted` rather than `open`.)

## Why not the alternatives

- **Re-instate hard gates library-wide.** Contradicts the deliberate 0.9.0 posture and reintroduces
  the dev/testnet friction it removed.
- **Enforce the capped fee type (`isinstance` raise).** Paternalism — the library refusing your
  fee source — inconsistent with "does what you tell it"; and the blast radius it guards is
  fees-only, never the asset.
- **Leave the unwaivable hard cap + no arming opt-in.** Internally inconsistent: the executor would
  carry the as-is posture (advisory gates) *and* a hard rail (unwaivable cap) while lacking the one
  affirmative consent the no-op removed. (B) resolves that: caps become consented defaults; arming
  is the single required affirmative act.

## Consequences

- The doc record is corrected: `threat-model.md` no longer says "no ClaimExecutor in v1";
  `security-audit-scope.md` no longer certifies the demoted gates as fail-closed (`ASSUME-AS-IS-POSTURE`),
  and the live affirmative gate is `enable_autonomous_mainnet_custody`.
- An un-armed or un-wired tower still closes R1 via operator/taker liveness within `t_rxd`; an armed
  tower closes it autonomously within the consented value bound.
- **The external audit + a genuine two-party adversarial run remain the gates** before relying on
  autonomous custody for non-dust value. The as-is posture changes *who is responsible* for that
  decision (the operator, explicitly) — it does not claim the surface is audited.
