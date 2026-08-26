---
title: "Six defects survived 9,700 green tests because they lived in scripts/, and a real-value mainnet swap found them in ninety minutes"
category: logic-errors
component: "`scripts/eth_swap_run.py`, `gravity/swap_coordinator.py`, `eth_wallet/multi_rpc.py`, `eth_wallet/htlc_leg.py`"
tags:
  - atomic-swap
  - cross-chain
  - htlc
  - erc20
  - timelock
  - resume
  - quorum
  - reachability
  - operator-tooling
  - test-coverage
  - mainnet
  - provenance
date: 2026-08-26
severity: high
status: solved
symptom: >
  The first real-value RXD↔USDT swap on Ethereum L1 refused six times before completing. Two
  refusals were operator sizing errors, four were latent defects. All six lived in code no test
  executes: an unsafe shipped default for the Radiant timelock, a `--resume` that silently minted a
  fresh swap instead of resuming, a quorum whose chain assertion aborted a live swap on one HTTP
  429, an error that reported "wrong/attacker contract" for a contract that was merely not yet
  finalized, and a run report that recorded ESTIMATED margins while the policy was MEASURED.
root_cause: >
  `scripts/` sits outside every automated gate — not in `testpaths`, not in the coverage target,
  not in the CI ruff scope, not in the mypy scope. The library beneath it was correct and tested;
  the executable path that operators actually run was neither. The two-interval timelock rule these
  defects turn on had been documented AND implemented in the library one day earlier, but its own
  decision to DERIVE the timelock in the runners was never carried out, so the rule existed
  everywhere except where it was used.
---

# Six defects that only a real-value run could reach

On 2026-08-26 the first RXD↔USDT atomic swap ran on Ethereum L1 with real value on both legs
(1.000000 USDT ↔ 1000 photons; both settled). It refused **six times** first. Every refusal fired
before value moved, which is the system working — but four of the six were defects, and the offline
suite was green at 9,700+ tests throughout.

This document exists because the *shared* cause is more valuable than any individual fix.

## 1. The shared cause: `scripts/` is outside every gate

Verified against `pyproject.toml` and `.github/workflows/lint.yml`:

| Gate | Scope | Reaches `scripts/`? |
|---|---|---|
| pytest / coverage | `testpaths = "tests"`, `--cov src` | **No** |
| `--cov-fail-under=85` | `--cov=pyrxd` | **No** — the floor is blind to it |
| CI ruff | `ruff check src tests examples` | **No** (fixed here) |
| mypy | `src/pyrxd/security/` + two glyph files | **No** |
| bandit | `-r src/` | **No** |
| pre-commit ruff | staged files | Yes — but only if the contributor installed the hook |

`scripts/eth_swap_run.py` is the **production entry point for the entire ETH↔RXD corridor**. It was
lint-clean by convention and untested by construction.

This has happened before, to this file. See
[`rxindexer-mainnet-rest-only-glyph-ref-gate-http-adapter.md`](../integration-issues/rxindexer-mainnet-rest-only-glyph-ref-gate-http-adapter.md)
— same script, same discovery mechanism, same class (a mechanism that was correct and unreachable).

### The HZ-1 precedent, which has had no citable home until now

When the taker-locks-first ordering was corrected (HZ-1, threat-model **S24**), the runners were not.
`tests/test_eth_swap_run_step_order.py` records the result in its own docstring:

> "The runner did the reverse for as long as HZ-1 has existed, and every run died at that gate.
> Nothing caught it: the runner is the production entry point for the ETH↔RXD corridor, **it is not
> driven by any test**, and exercising it by hand costs real mainnet value."

Three of five runners were unable to complete a swap for months — including both mainnet runners —
and it took a real-value run to notice. That finding lived only in a test file and two commits
(`4e43cf6`, `8fd364d`). It is the same root cause as everything below.

## 2. What broke

### 2.1 The timelock rule existed everywhere except where it was used

**This is the finding worth internalising, and it is not "we discovered a rule".**

[`sizing-t-rxd-the-two-directions-rule.md`](../design-decisions/sizing-t-rxd-the-two-directions-rule.md)
was written on **2026-08-25 — the day before this run** — and states the rule exactly: *dividing
wants the fast tail (p10), multiplying wants the slow tail; one field cannot serve both*. Its
decision 1 (split the interval by direction) shipped the same day.

Its **decision 3 did not**: *"Wire the safe-`t_rxd` sizer into the runners so `t_rxd` is DERIVED
rather than supplied."* Verified by grep: `eth_absolute_to_rxd_relative_blocks` — the function that
derives a safe `t_rxd` — has **zero production callers**. Its checker wrapper
`assert_t_rxd_fits_the_eth_deadline` is called from one script, and **not from the runner that
executed this swap**.

So `--t-rxd-blocks` stayed an operator flag with a **default of 60**, and nothing checked it. At the
measured p10 of 36 s that matures in **36 minutes**, against a cross-clock margin of **7068 s (~2 h)**
that the taker must sit through before it can claim — ETH finality, the stall budget, claim burial,
slack. The maker could have refunded the covenant while the taker was still, correctly, waiting.

That is threat-model **S20** ("taker offline/censored during `[reveal, t_rxd]`"), whose control list
opens with *"the cross-clock timelock margin sizes `t_rxd` to open strictly before the counter-leg
deadline minus the finality-stall-tolerant margin."* On this runner that control **was not in force**.

Two bounds, and they legitimately use different intervals:

```
lower = ceil(margin_total_s / fast)                        # 197 — divide by the p10 tail
upper = floor((eth_timeout - margin - confirm_wait) / nominal)  # 262 — multiply by the nominal
```

Sizing with one while the gate checks with the other inflated a projection **8×**: a `t_rxd` of 2203
— correct against the lower bound — projected the refund **7.6 days** out against a 22 h budget. The
coordinator caught it, **after the covenant was funded**, because nothing checked at parse time.

The upper bound must also reserve `max_covenant_confirm_wait_s`, because the gate anchors on the
covenant's **confirmation** time, not the run's start. A ~740 s fund-and-mine came straight out of
the budget and overshot by **607 s** — a second funded covenant, a second refusal.

> **The trap is documented inside the gate itself** (`eth_rxd_timelock.py`): the interval "cancels"
> only when the sizer and the gate use the *same* one. Read that docstring before touching either.

### 2.2 `--resume` did not resume

`_build_terms_and_covenant` called `os.urandom` for the preimage and both RXD keys unconditionally,
and `run_sepolia_dust` recomputed `eth_timeout` from the clock — an immutable of the deployed HTLC.
So `--resume` built a covenant with a **different hashlock** and silently abandoned the funded one.

Nothing detected it. The only thing that stopped the run was the `O_EXCL` create of the recovery
file failing afterwards — **accidental protection that would not have fired with a different
`--keys-out`.**

Separately, `SwapCoordinator` was always constructed at `NEGOTIATED` and the record sink's existing
`load_record()` was **never called**, so no state past the fund was resumable by any path.

Note what this sits next to:
[`nonce-pinning-makes-erc20-funding-idempotent.md`](../design-decisions/nonce-pinning-makes-erc20-funding-idempotent.md)
hardened *library-level* resume through seven rounds of guards — while the operator-level resume was
fiction.

### 2.3 A safety property implemented as a liveness requirement

`MultiSourceEthRpc.assert_chain` awaited every source with no `return_exceptions`, conflating "this
endpoint is on the wrong chain" with "this endpoint returned 429". One rate-limited public endpoint
**aborted `verify_funded` with real value already locked in the HTLC**.

A quorum spanning two chains is meaningless, so a wrong-chain answer must stay fatal. But an
endpoint that cannot be reached also cannot lie, and every identity read refuses on disagreement
anyway — so unreachable is now tolerated **above quorum**.

The fix had a second half that the first version missed: `min_agreeing` defaults to a true majority,
`max(2, n//2+1)`, so at **n=2 it is 2 and the tolerance is inert**. The runner was requiring two
endpoints — exactly the configuration that had just failed. It now requires **three**.

This corridor's own residual predicted the need:
[`usdc-corridor-is-issuer-trusted-not-trustless.md`](../design-decisions/usdc-corridor-is-issuer-trusted-not-trustless.md)
says *"the freeze read is single-source … multi-source quorum is the fix if this ever carries real
value."* This run was that trigger — and the quorum's first live use was a **false refusal**, not a
caught lie.

### 2.4 "Wrong/attacker contract" for a contract that was simply too new

`verify_funded` reads at the `finalized` checkpoint. `get_code` there returns `b""` for the ~13
minutes between deploy and finality — the ordinary state — and empty code fell into the mismatch
branch:

```
on-chain runtime logic != committed EthHtlc artifact (wrong/attacker contract)
```

On a live mainnet run that reads as *"you have been robbed"* when the truth is *"wait"*. **Empty is
not wrong**, and the two now diagnose separately.

Every fork test deploys and verifies where finality is instant, which is why no test saw it.

### 2.5 A measurement that drifted in the unsafe direction

The code cited Radiant p10 **43 s** from 2026-06-02. Re-measured 2026-08-26 over 720 blocks: **p10
36 s**, median 221 s, mean 296 s, p90 671 s, **max 2325 s**.

Reserves *divide* by this, so a stale-**high** value under-counts: sizing with 43 s against a real
36 s yields **16% fewer blocks** than the window holds. Both samples drifted the unsafe way — and
two samples is not a trend; say so.

### 2.6 Names that lie at the irreversible moment

The confirmation prompt before the maker's claim read:

```
maker_claims_btc: broadcast the ETH claim on SEPOLIA (reveals p)
```

Three misnomers in one sentence during an Ethereum **mainnet USDT** swap, at the single most
irreversible step in the protocol. `maker_claims_btc` and `btc_locked` are legacy FSM names and
staying is defensible — the state machine was built for BTC↔RXD and the EVM legs reuse it, which is
exactly why the ERC-20 leg needed **zero coordinator changes**. A hardcoded `SEPOLIA` while real
value moves is not defensible.

Related, same class: the `maker_stall_safety_window_blocks` floor error printed
`ceil(768/300)=22`, which does not reconcile — it had divided by the fast tail (768/36). And the run
**provenance record hardcoded `"is_measured": False`**, so the L1 run's own report claimed ESTIMATED
margins while its policy was MEASURED. A hardcoded field in the artifact that documents a run is not
a note; it is a false statement about what protected the money.

## 3. Prevention

### Landed with this document

- **`ruff check` now includes `scripts/`** in CI. One line; the tree was already clean because
  pre-commit reached it — so the guarantee no longer depends on each contributor's hook.
- **`tests/test_eth_swap_run_resume_identity.py`** — restoring reproduces the covenant byte-for-byte;
  *not* restoring produces a different one (the defect, as a test); a tampered preimage is refused;
  a mismatched parameter changes the SPK. Verified by planting the original defect and watching the
  two load-bearing assertions fail.
- **Argument-time bounds** for `t_rxd` (both directions, with the confirm-window reserve), a
  three-endpoint minimum for a real token leg, and provenance read from the policy rather than
  asserted.

### The pattern to copy for `scripts/`

`tests/test_eth_swap_run_erc20_wiring.py` is the model: `importlib`-load the runner, drive its
**real** `_args()` parser and its real factories against unreachable URLs so nothing touches a chain.
It has already caught a real defect. The runner's guards are pure `Namespace → SystemExit` functions;
there was never a technical obstacle to testing them.

A full cross-chain test is genuinely infeasible (two live chains, real value, a covenant SPK that
`sendtoaddress` cannot pay) — and a mock-token substitute was **deliberately rejected**: a mock
reproduces exactly the runtime behaviours someone remembered to write down, which are not the ones
that break.

### Still open

- **Derive `t_rxd` instead of flagging it** — the two-directions doc's decision 3, still unbuilt.
  Blocked on one unmade decision: the doc prescribes the **slow tail** for projections, the gate
  multiplies by the **nominal**, and there is no `rxd_block_interval_slow_s` field. Until sizer and
  gate agree by construction, a derived value could be refused by the gate it was derived to satisfy
  — the `#484` failure the doc itself warns about. Keep the guards alongside any derivation rather
  than deleting them.
- **`--cov scripts`** would make unexercised runner code visible, but it will drop the number below
  the 85% gate. The honest version is a separate, initially-low ratchet — not folding it into 85%.
- **`_SEPOLIA_CHAIN_ID` is still the default** for `--eth-chain-id`, so the wrong-network class is
  not structurally closed.
- **Measured constants still have no single home.** `tests/test_no_duplicate_consensus_constants.py`
  already enforces exactly this discipline for consensus constants, AST-based; extending it to
  measured ones is low-cost and would have caught the 43 s citations. An age-based CI failure would
  go red on a calendar rather than a defect — better as a runner warning at setup, where it reaches
  the person who can act.

## See also

- [`sizing-t-rxd-the-two-directions-rule.md`](../design-decisions/sizing-t-rxd-the-two-directions-rule.md) — the rule; decision 3 is what was missing.
- [`usdc-corridor-is-issuer-trusted-not-trustless.md`](../design-decisions/usdc-corridor-is-issuer-trusted-not-trustless.md) — predicted the quorum need.
- [`nonce-pinning-makes-erc20-funding-idempotent.md`](../design-decisions/nonce-pinning-makes-erc20-funding-idempotent.md) — library resume hardened while operator resume was fiction.
- [`griefing-is-a-liveness-residual-not-a-bond.md`](../design-decisions/griefing-is-a-liveness-residual-not-a-bond.md) — the sibling "tests structurally cannot see it" case. Its blind spot is *semantic* (the oracle asks the wrong question); this one is *positional* (the code is where no test looks).
- [`rxindexer-mainnet-rest-only-glyph-ref-gate-http-adapter.md`](../integration-issues/rxindexer-mainnet-rest-only-glyph-ref-gate-http-adapter.md) — same script, same discovery mechanism.
- [`glyph-mint-fee-ceiling-judged-one-rate-while-the-reveal-spent-another.md`](glyph-mint-fee-ceiling-judged-one-rate-while-the-reveal-spent-another.md) — a guard waived on the exact default path every caller takes.
- `docs/threat-model.md` — **S20** (the scenario 2.1 instantiates), **S21** (no RBF/CPFP on Radiant is *why* the taker's window must contain an unrepairable failure), **S24** (HZ-1), **S25** (the freeze residual that asked for the quorum).
