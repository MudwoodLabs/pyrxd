---
title: "Inverting the HTLC timelock direction (#482 finding 1)"
type: design
date: 2026-08-30
status: DESIGN ONLY — no code changed. Needs the derivation checked against Herlihy before implementing.
related: "#482 (finding 1), #531 (merged), #529 (merged)"
---

# Inverting the HTLC timelock direction

## 0. Verified vs assumed

**Verified (read from source or measured):**

- `assert_timelock_margin` enforces `t_btc > t_rxd + margin` (`swap_coordinator.py:604`).
- `eth_absolute_to_rxd_relative_blocks` computes
  `budget_s = eth_timeout_unix_s - margin.total_s() - expected_rxd_lock_time_unix_s`
  (`eth_rxd_timelock.py:185`), i.e. `rxd_refund_opens = eth_timeout - margin`.
- `NegotiatedTerms.__post_init__` rejects `t_btc <= t_rxd` in the same unit as a cheap guard
  (`swap_state.py:425`).
- `CrossClockMargin`'s five components are ETH finality, ETH stall tolerance, RXD claim burial,
  RXD confirm slack, and rounding/skew (`eth_rxd_timelock.py:100-104`).
- #482 finding 1, from the 4th security round, independently reaches the same conclusion.

**Assumed / not yet verified:**

- That Herlihy (arXiv 1801.09515) says what I derive in §1. I have NOT read the paper in this
  session; the derivation is from the standard construction. **This is the load-bearing
  assumption and it should be checked before anyone writes code.**
- Exact wall-clock cost of the change in production (§4 gives the arithmetic, not a measurement).

## 1. The defect

The maker holds `p`, **locks** the RXD covenant, and **claims** the counter leg.

The invariant: *the leg the secret-holder CLAIMS must expire before the leg the secret-holder
LOCKED refunds.* Otherwise the secret-holder waits out their own refund, reclaims their asset,
and still claims the counter leg with the secret they never had to publish.

    needed:    counter_deadline + Δ  <  rxd_refund_opens
    enforced:  rxd_refund_opens      <  counter_deadline − margin

The enforced relation is the inverse, and it is off by `2 × margin`. In
`[rxd_refund_opens, counter_deadline]` — at least `margin` wide by construction, 7068 s on the
measured policy — the maker refunds the covenant while `p` is still secret, then claims the
counter leg. Both legs, deterministically. The taker cannot claim the covenant (no `p`) and
cannot refund the counter leg (its deadline is later). **The safety buffer is the attack window.**

Not a consequence of HZ-1: under the old lock order the maker still locked the shorter-refund leg
and claimed the longer one.

## 2. The insight that makes this cheap

**`CrossClockMargin`'s components are already correct for the fixed direction.** Every one of the
five budgets is time the TAKER needs, after the reveal, to claim RXD safely — ETH finality, stall
tolerance, claim burial, confirm slack, rounding. That is exactly `Δ` in §1.

Its own docstring states the correct rule:

> the RXD refund must NOT open until the taker has had a stall-tolerant window

The taker's window begins when the maker reveals, and the maker may reveal as late as
`counter_deadline`. So the RXD refund must not open until `counter_deadline + Δ`. The code
subtracts instead of adding.

The same correct instinct appears in the sizing note about `rxd_block_interval_s`: a fast RXD
chain is called the safety-critical direction because the refund would open *sooner*, cutting the
taker's post-reveal window. That reasoning only makes sense under the corrected ordering. **Parts
of this module reason correctly about the taker's post-reveal window while the top-level relation
enforces the opposite.**

So the fix is predominantly a sign change plus its consequences, not a new safety model.

## 3. Change set

| # | Site | Now | Becomes |
|---|---|---|---|
| 1 | `eth_absolute_to_rxd_relative_blocks` | `budget = eth_timeout − margin − lock_time` | `budget = eth_timeout + margin − lock_time` |
| 2 | `assert_timelock_margin` | `t_btc > t_rxd + margin` | `t_rxd > t_btc + margin` |
| 3 | `NegotiatedTerms.__post_init__` | rejects `t_btc <= t_rxd` | rejects `t_rxd <= t_btc` |
| 4 | `assert_covenant_confirms_before_eth_deadline` | covenant must not confirm LATE | covenant must not confirm EARLY (§5) |
| 5 | `MAKER_SECRET_TAKER_LOCKS_BTC_FIRST` | "t_BTC > t_RXD + margin … Radiant SHORTER" | inverted, with the reason |
| 6 | `swap_state.py:302-303` field comments | `t_btc` LONGER, `t_rxd` SHORTER | swapped |
| 7 | `eth_rxd_timelock.py:14, 80, 148` | "counter leg holds the LONGER deadline" | inverted |
| 8 | Runners' `--t-rxd-blocks` bounds | sized under the old relation | re-derived |

Sites 5–7 are prose, but #529 is the standing evidence that stale prose here manufactures wrong
findings — they are not optional.

## 4. Consequences

**`t_rxd` grows by roughly `2 × margin`.** It previously ended `margin` before the counter
deadline; it now ends `margin` after. On the measured policy that is ~14,136 s ≈ 3.9 h, ~47
Radiant blocks at the 300 s target.

**The maker's asset is locked longer.** That is the correct allocation: the maker holds the free
option today, so the maker should bear the lock. It is a liveness cost, not a safety one.

**BIP68 headroom is fine.** Even a full day of Radiant blocks is ~288, far under the 0xFFFF cap.
The cap tests noted in the mutation work stay relevant but are not a blocker.

**Gate 3b/6 gets easier, not harder.** A longer `t_rxd` means more room for
`burial + counter_reserve + elapsed`. The #531 fix is unaffected in direction.

**`ASSET_VULNERABLE` may become unreachable by this path.** Under the corrected ordering the
counter leg expires first, so the taker refunds it before the maker's RXD refund opens. The FSM
state should be re-examined rather than assumed still needed — but it also covers other paths, so
do not delete it on this argument alone.

## 5. The punctuality gate inverts

Today the risk is a covenant confirming LATE, because that shifts the RXD window right, past
`eth_timeout − margin`.

Corrected, the risk flips: `rxd_refund_opens = actual_confirm + t_rxd` must be **at least**
`eth_timeout + margin`, so a covenant confirming EARLIER than the sizing assumed cuts the taker's
window. `t_rxd` is committed in the covenant script before broadcast and cannot be resized after,
so the gate must re-verify against the ACTUAL confirmation time and refuse if the swap no longer
clears the bound — the maker refunds and restarts.

This is the site I am least confident about. It deserves its own derivation rather than a
mechanical sign flip.

## 6. Risks

- **A guard that refuses valid work is a bug.** Every changed bound needs a paired honest-path
  test proving a correctly-sized swap still negotiates. The runners' existing `--t-rxd-blocks`
  bands were computed under the old relation and will refuse until re-derived.
- **Re-attack the fix.** Every round of guard work in this corridor has introduced a defect in
  the fix itself. Budget an adversarial pass on the change, not just on the original.
- **Two corridors.** `assert_timelock_margin` serves BTC and the ETH path serves EVM. Change them
  as a set; a partial inversion is worse than neither.
- **Make the tests fail first.** The current suite encodes the OLD direction and will pass a
  wrong fix. Plant the inverted comparison and confirm the new tests fail before trusting them —
  three separate green tests this session were holding wrong beliefs in place (#505, #529, #531).

## 7. Test plan

1. A property test: for a swap sized by the converter, `rxd_refund_opens >= counter_deadline +
   margin.total_s()`. This is the invariant, stated once.
2. The theft scenario as an explicit adversarial test: maker refunds at `rxd_refund_opens` and
   then claims the counter leg — must be impossible because the counter leg has already expired.
3. Honest path at the boundary: equality passes.
4. A conversion round-trip across the six block intervals the existing sizing tests use.
5. Re-derive and assert the runners' `--t-rxd-blocks` valid range.

## 8. Recommendation

Do NOT ship this as a patch alongside other work. It changes a fund-safety invariant across two
corridors, and the acceptance of the current behaviour as a residual in #482 was made against a
note asserting the direction was already verified.

Sequence: check §1 against the paper → confirm §5 independently → implement §3 as one change with
§7's tests → adversarial pass on the result.
