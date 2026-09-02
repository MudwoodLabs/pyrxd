---
title: "Capital-lockup griefing is an ACCEPTED liveness residual — do not add a bond"
category: design-decisions
component: gravity / cross-chain-swap
tags:
  - atomic-swap
  - cross-chain
  - htlc
  - griefing
  - denial-of-service
  - liveness
  - economics
  - residual-risk
  - threat-model
date: 2026-08-10
severity: medium
symptom: >
  A counterparty repeatedly opens swaps, lets the victim lock capital on-chain, then
  simply never locks their own leg. The victim's funds are immobilised for the full
  timelock and they pay two on-chain fees; the attacker pays nothing and never
  transacts. Every safety oracle reports success — nobody loses principal, the
  both-complete-XOR-both-refund invariant holds — so the attack is invisible to the
  entire adversarial test suite while being a real, repeatable cost to the victim.
---

# Capital-lockup griefing: accepted, not bonded

**Decision: ACCEPT the residual and document it. Do NOT add a bond or deposit.**
Revisit only on the trigger in §5.

## 1. The attack, and why it is structural

Verified against the shipped state machine, not inferred:

> **⚠ TWO PREMISES BELOW WERE CORRECTED IN SOURCE AND NOT HERE, and both point the asymmetry the
> other way. The conclusion — griefing is a liveness residual, not a bond problem — is unaffected,
> but the WHO and the HOW LONG are. Re-derive the cost asymmetry before quoting it.**

- **The MAKER locks first**, not the taker: `pre_btc_lock_check` refuses to fund until step 5 has
  read the maker's covenant off the Radiant chain (HZ-1, #392). This bullet said the taker locks
  first, quoting a state-machine comment that has since been corrected.
- **The taker's own refund is the SHORTER timelock**, not the longer. `assert_timelock_margin`
  enforces `t_rxd - t_btc >= margin` since #482 — the maker holds `p` and LOCKS the Radiant leg, so
  that leg carries the longer timeout. The old text called `t_btc - t_rxd >= margin` "correct and
  deliberate"; it is the layout in which the maker refunds its own leg and still claims the
  counter leg with `p`.

  So the party immobilised longest is now the **maker**, on the leg it locked — which is the
  opposite of the asymmetry this document built its griefing argument on.
- **The recourse works, and is slow.** `taker_refund_btc` is "valid from BTC_LOCKED (maker never
  locked, `t_btc` elapsed)". The taker is made whole; they simply cannot leave early.

So the cost table is:

| | attacker (malicious maker) | victim (honest taker) |
|---|---|---|
| on-chain transactions | **none** | fund + refund (2) |
| capital immobilised | **none** | full swap value, for `t_btc` |
| marginal cost to repeat | **~zero** | linear in swaps accepted |

The attacker's move is *inaction*. There is nothing to slash, nothing to observe on-chain, and no
protocol step they fail to perform — they never started one.

## 2. Why the test suite cannot see it

This is the part worth internalising. Every safety oracle in the adversarial matrix asks a
principal question: did anyone end with less than they started? Here, **nobody does.** The
invariant holds, the refund fires, the record reaches `ABORTED` cleanly. A griefing campaign and a
counterparty with flaky connectivity are *indistinguishable* to every check we have.

That is why it survived a red-team pass, a security panel, and an eight-reviewer fan-out without
being flagged as a defect: it is not a defect. It is a property of HTLC swaps in general, and
naming it is the only honest way to close it.

## 3. Why a bond is the wrong fix here

A bond or deposit is the textbook answer, and it is wrong for pyrxd *now*:

1. **It changes the protocol for everyone** to price a threat with **no observed instance**. Every
   honest swap would pay setup cost and UX friction to deter an attack nobody has run.
2. **A bond needs its own escrow, and escrow needs its own adjudication.** Who holds it? On which
   chain? Who decides the abort was malicious rather than a stalled node or a genuine reorg? Each
   answer is new consensus-adjacent surface on a stack whose existing surface is **explicitly
   unaudited**. Adding an unaudited mechanism to deter a liveness nuisance is a poor trade.
3. **It cannot distinguish malice from failure.** The honest counterparty whose node dies mid-swap
   is punished identically to the attacker. A bond that slashes on abort penalises exactly the
   users least able to absorb it.
4. **Cheaper mitigations exist that need no protocol change** (§4).

## 4. What to do instead

These are ordinary operational controls, available today, none of which touch the protocol:

- **Order the legs by trust.** The taker-locks-first ordering is a *default*, not a consensus rule.
  Against an untrusted counterparty, negotiate the maker locking first — the griefing cost then
  lands on the party who chose to grief.
- **Size `t_btc` deliberately.** The margin has a floor for safety, but everything above it is
  chosen. A longer-than-necessary `t_btc` buys nothing and directly lengthens the griefing window.
- **Keep counterparty state at the negotiation layer.** An allowlist or a simple abort-rate memory
  is trivially cheap and sits entirely outside the swap protocol.
- **Do not automate acceptance.** The RSWP orderbook makes accepting swaps programmatic; an
  operator auto-accepting from unknown counterparties converts a manual nuisance into an automated
  drain. That is the actual risk multiplier — not the attack itself.

## 5. The trigger to revisit

Accepting a residual is only honest with a named condition that reverses it. Revisit **when either**:

1. **An actual griefing incident occurs** — one observed campaign beats any amount of speculation
   about whether it will happen; or
2. **The orderbook carries untrusted counterparties at volume.** Griefing scales with automation.
   Today RSWP is experimental and swaps are operator-driven. If accepting an order becomes
   unattended and open to anyone, the cost asymmetry stops being theoretical and the mitigations in
   §4 stop being sufficient.

An external auditor flagging it as blocking is a third trigger, and would supersede this decision.

## 6. What is being accepted, stated plainly

**pyrxd's cross-chain swap stack defends SAFETY, not LIVENESS.** It will not let a counterparty
take your funds. It will not stop a counterparty from wasting your time and immobilising your
capital for the duration of a timelock at near-zero cost to themselves. Those are different
guarantees, and only the first is engineered for.

Anyone running swaps against untrusted counterparties should read that sentence as a design
constraint, not a bug report.

## See also

- `docs/threat-model.md` — S22 (this residual, registered).
- `docs/plans/2026-08-09-gap-closure-plan.md` §A3 — the plan item this closes.
- `docs/solutions/design-decisions/spv-oracle-swap-is-not-atomic-use-htlc.md` — why the HTLC
  binding exists at all; griefing is the residual left *after* one-sided loss was engineered out.
