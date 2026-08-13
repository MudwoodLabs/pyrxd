# Mutation testing the consensus-critical and value-moving modules

Mutation testing measures **test quality**, not just line coverage: it mutates the source (e.g. flips
`!= 80` to `< 80`, `i - 1` to `i + 1`) and checks whether the suite *catches* each change. A **killed**
mutant means a test failed (good); a **survived** mutant means the line runs but no assertion pins its
behavior — a potential gap.

## Running it

```bash
poetry install --with dev   # brings in cosmic-ray
poetry run task mutate                    # default scope: spv (the original gate)
poetry run task mutate script             # script/ primitives
poetry run task mutate transaction        # transaction/ incl. the FORKID sighash preimage
poetry run task mutate dmint              # glyph/dmint/ covenant builders + DAA + parser

poetry run task mutate fee                # fee_sizing.py — the one fee-sizing rule
poetry run task mutate wallet             # wallet.py — the flat-key send/sweep builders
poetry run task mutate hdwallet           # hd/wallet.py — the BIP32/44 send/sweep builders
poetry run task mutate glyph              # glyph/ft.py + glyph/builder.py — token builders
poetry run task mutate swap               # gravity/htlc_spend.py + swap/rswp/orders.py
poetry run task mutate coordinator        # gravity/swap_coordinator.py — the swap state machine
poetry run task mutate network            # network/ — remote-response parsing + failover

poetry run task mutate consensus          # the original four groups
poetry run task mutate value              # the seven value-moving groups
poetry run task mutate all                # everything, sequentially (many hours)
```

This runs [`scripts/mutation_test.sh`](../../scripts/mutation_test.sh). It mutates
`src/pyrxd/<scope>/<file>.py` **in place** (the editable install picks it up), runs a scope-targeted
fast test command per mutant, and restores via `git`. It is an **occasional gate, not part of
`task ci`** (slow). Don't run concurrent git ops on `src/pyrxd` while it runs — when other
sessions/worktrees are active, run the whole thing in a detached worktree (see
`docs/solutions/integration-issues/task-ci-spurious-failures-from-concurrent-worktrees.md`).

Useful environment knobs:

- `MUTATION_SESSION_DIR=dir` — keep the cosmic-ray session `.sqlite` files for survivor triage
  (query them with `cr-report`, `cr-html`, or a `mutation_specs ⋈ work_results` join for diffs).
- `MUTATION_REPORT_DIR=dir` — where the per-group Markdown survivor lists land
  (default `.mutation-reports/`, gitignored).
- `MUTATION_MIN_KILL_PCT=N` — opt-in gate: exit non-zero below N% total kill rate.
- `MUTATION_RESUME=1` — keep an existing session and pick up where it stopped. `cosmic-ray exec`
  only runs jobs with no result yet, so a group killed at 90% resumes instead of restarting. Use it
  with `MUTATION_SESSION_DIR` and **only when the module has not changed since the session was
  created** — the session's mutation specs were derived from the source at `init` time, so resuming
  across an edit would score two different versions of the file under one number.

### Before it mutates anything

Three preflight checks run first, each for a failure mode that otherwise produces a confident,
meaningless number:

1. **Target sources must be clean.** Cleanup is `git checkout -- <files>`; with uncommitted work in
   a target file that is data loss, and the "baseline" would not be the committed code.
2. **`import pyrxd` must resolve to this checkout.** A shared virtualenv whose editable install
   points at a different clone (a `.pth` naming another repo root) would have cosmic-ray mutate files
   the tests never import — every mutant "survives" and a healthy module scores ~0% killed.
3. **The group's clean suite must be green.** cosmic-ray reads a non-zero exit as *mutant killed*, so
   a red or uncollectable test list scores **100% killed on every module**. That is the most
   flattering number the tool can produce and it is entirely fiction.

The run also restores on `INT`/`TERM`/`HUP`, not just `EXIT`: bash skips an `EXIT` trap when killed by
an untrapped signal, and a run killed mid-sweep used to leave a mutated source file in the tree
looking exactly like a hand edit.

### Parallelism

cosmic-ray's `local` distributor is serial, and two groups **cannot** share one checkout — the mutation
is a real edit to `src/pyrxd`, so a second group's tests would import the first group's mutant and
mis-score it. To use more cores, give each group its own clone and run one group per clone:

```bash
git clone --local --no-hardlinks . /tmp/lane-$g && cd /tmp/lane-$g && task mutate $g
```

That is how the baseline below was measured.

> Scope exclusions, on purpose: `spv/proof.py` / `spv/witness.py` (covered by the fuzz harness, ~30×
> slower per mutant), `__init__.py` re-export shims, `script/unlocking_template.py` (17-line ABC), and
> `glyph/dmint/__init__.py`. The whole-file scope for `glyph/dmint/miner.py` includes the mining
> dispatch loops; their kills come mostly from the DAA/preimage tests, not the multiprocessing paths.
> In `network`, `rxindexer.py` and `chaintracker.py` ARE in scope but score low by design
> (`rxindexer.py` killed 10%) — they are thin passthroughs with no decision in them, so their
> survivors are expected rather than actionable.

### Why `network` is in scope

The other four scopes protect arithmetic a *node* would eventually reject. `network` protects the
one place where nothing else will: consensus does not defend an SPV client against a server that
answers truthfully but about the wrong thing. Whether a lying ElectrumX / Esplora / Bitcoin Core
endpoint can move value rests entirely on `_guards.py` (fail-closed coercions), the
request↔response bindings in `electrumx.py` and `bitcoin.py`, `confirm.py`'s depth gate,
`tls_pin.py` + `registry.py` (which server, on which chain, under which pin) and `failover.py`
(which of those may be relaxed on a retry).

Two files that are part of the same trust boundary sit outside the group because they are not under
`network/`: `swap/rswp/node_rpc.py` and `gravity/watch/adapters.py`. Both were hand-mutated in the
2026-08 sweep (see below); a future scope extension should fold them in.

## Scopes and test commands

Each scope uses a fast targeted test list (defined in `mutation_test.sh`) so a full file sweep stays
tractable — the per-mutant cost is the test command's wall time. `tests/test_mutation_hardening.py`
(the survivor-killing assertions) leads every list so `-x` exits cheapest on the pinned mutants; the
property/differential suites (`test_preimage_differential.py`, `test_dmint_vector_derivations.py`)
close the transaction/dmint lists as the wide net.

Two constraints shape the value-group lists specifically:

- **Files from the same sub-package stay contiguous.** Splitting `tests/cli/*` across the arg list
  makes pytest 9.1.1 stop applying `tests/cli/conftest.py` to the later ones — the `runner` fixture
  disappears and 32 tests ERROR. Because cosmic-ray scores a non-zero exit as *killed*, that reads as
  a perfect score. This is a property of the suite, not of the harness: it reproduces with a plain
  `pytest a b c` invocation.
- **Group by the tests that decide, not by directory.** `wallet.py` and `hd/wallet.py` started as one
  group and their decisive suites turned out to be nearly disjoint, so each file's mutants were paying
  for the other file's tests — a ~15s clean suite where each half needs ~8s. They are two groups now.

## Baseline results — spv (2026-06)

| Module | Mutants | Killed | Survived | Killed |
|---|---|---|---|---|
| `pow.py` | 143 | 120 | 23 | 84% |
| `merkle.py` | 354 | 288 | 66 | 81% |
| `chain.py` | 132 | 78 | 54 | 59% |
| `payment.py` | 268 | 219 | 49 | 82% |

## Baseline + hardening results — script/, transaction/, glyph/dmint/ (2026-07)

The 2026-07 run measured each file with the PRE-hardening test lists (baseline), then every surviving
mutant was re-checked individually — its stored diff applied to a clean worktree and the UPDATED test
command run — to measure the post-hardening score without a second multi-hour sweep. A full re-run of
one scope (`script`) spot-checked that the per-survivor method matches a fresh sweep.

| Module | Mutants | Baseline killed | After hardening | Still surviving | …of which annotation-equivalent |
|---|---|---|---|---|---|
| `transaction/transaction.py` | 509 | 285 (56%) | 360 (71%) | 149 | 99 |
| `transaction/transaction_input.py` | 104 | 44 (42%) | 47 (45%) | 57 | 55 |
| `transaction/transaction_output.py` | 53 | 16 (30%) | 19 (36%) | 34 | 33 |
| `transaction/transaction_preimage.py` | 675 | 322 (48%) | **622 (92%)** | 53 | 0 |
| `script/script.py` | 299 | 172 (58%) | 207 (69%) | 92 | 33 |
| `script/timelock.py` | 257 | 249 (97%) | 253 (98%) | 4 | 0 |
| `script/type.py` | 340 | 241 (71%) | 272 (80%) | 68 | 55 |
| `glyph/dmint/builders.py` | 2197 | 2024 (92%) | **2179 (99%)** | 18 | 0 |
| `glyph/dmint/chain.py` | 1251 | 803 (64%) | 930 (74%) | 321 | 28 |
| `glyph/dmint/types.py` | 364 | 232 (64%) | 326 (90%) | 38 | 0 |
| `glyph/dmint/miner.py` | 1909 | 1430 (75%) | 1453 (76%) | 456 | 39 |

The annotation-equivalent column is a conservative lower bound (surviving `BitOr`-family mutants
whose diff touches only a signature/annotation line). Excluding just that class, the
annotation-adjusted post-hardening scores are e.g. transaction.py 88%, transaction_input 96%,
type.py 95%, transaction_output 95% — the honest view of files whose raw score is dragged by
`str | bytes | Reader`-style signatures.

**Spot-check:** a full fresh sweep of the `script` scope at the same commit reported 92 / 4 / 68
survivors for script.py / timelock.py / type.py — identical, file for file, to the per-survivor
re-check's prediction.

## Baseline results — value-moving modules (2026-08)

First measurement of the new scope, at commit `3115028` (module sources identical to `724fe92`).
Every module below ran to completion; the kill rate is over mutants that actually executed.

| Group | Module | Mutants | Killed | Survived | Killed | …annotation-equivalent | Wall time |
|---|---|---|---|---|---|---|---|
| `fee` | `fee_sizing.py` | 362 | 322 | 40 | **89%** | 0 | 16 min |
| `wallet` | `wallet.py` | 295 | 176 | 119 | 59% | 0 | 26 min |
| `hdwallet` | `hd/wallet.py` | 1201 | 776 | 425 | 65% | 132 | 89 min |
| `glyph` | `glyph/ft.py` | 453 | 318 | 135 | 70% | 77 | 13 min |
| `glyph` | `glyph/builder.py` | 736 | 177 | 559 | **24%** | 88 | 24 min |
| `swap` | `gravity/htlc_spend.py` | 277 | 205 | 72 | 74% | 22 | 7 min |
| `swap` | `swap/rswp/orders.py` | 529 | 282 | 247 | 53% | 143 | 15 min |
| `coordinator` | `gravity/swap_coordinator.py` | 1657 | 1162 | 495 | 70% | 187 | 42 min |
| `network` | `network/bitcoin.py` | 1288 | 840 | 448 | 65% | 77 | 47 min |
| `network` | `network/electrumx.py` | 557 | 301 | 256 | 54% | 110 | 26 min |
| `network` | `network/failover.py` | 251 | 118 | 133 | 47% | 88 | 8 min |
| `network` | `network/confirm.py` | 171 | 132 | 39 | 77% | 22 | 16 min |
| `network` | `network/registry.py` | 100 | 67 | 33 | 67% | 22 | 3 min |
| `network` | `network/rxindexer.py` | 95 | 10 | 85 | **10%** | 55 | 1 min |
| `network` | `network/tls_pin.py` | 93 | 76 | 17 | 81% | 11 | 2 min |
| `network` | `network/_guards.py` | 85 | 70 | 15 | 82% | 11 | 2 min |
| `network` | `network/chaintracker.py` | 21 | 17 | 4 | 80% | 0 | <1 min |
| **total** | | **8171** | **5049** | **3122** | **61%** | **1045** | **5 h 36 m** |

Per group, which is the unit a runner executes:

| Group | Mutants | Killed | Wall time |
|---|---|---|---|
| `fee` | 362 | 89% | 16 min |
| `wallet` | 295 | 59% | 26 min |
| `hdwallet` | 1201 | 65% | 89 min |
| `glyph` | 1189 | 42% | 37 min |
| `swap` | 806 | 60% | 22 min |
| `coordinator` | 1657 | 70% | 42 min |
| `network` | 2661 | 61% | 104 min |

**5 h 36 m serially; 1 h 44 m as wall clock** when each group gets its own runner, which is the
shape the scheduled workflow uses. That difference is the whole argument for one job per group.

> **Wall times are upper bounds, not clean measurements.** They were taken on a 32-core workstation
> running six to eight of these groups concurrently *and* an unrelated parallel mutation workload —
> load average 12-16 throughout. A single group run on an idle machine will be faster; a 2-core CI
> runner will be slower. Treat them as "what a group costs when the box is busy", which is the number
> that decides whether anyone can afford to run it.

Three results stand out, and none is a scheduling artifact:

- **`glyph/builder.py` kills 24% of its mutants** — the lowest score in the scope, on the largest
  module in it. Line coverage from the offline suite is 66%, so a third of the file never executes
  here; the regtest end-to-end suites cover those paths and they do not run in this lane. The honest
  reading is that this module's *offline* tests are close to a smoke test.
- **`wallet.py` kills 59% with zero annotation-equivalent survivors.** Unlike the other low scorers it
  has no annotation noise inflating the count: those 119 survivors are all real assertions nobody
  wrote, in the module that builds ordinary sends.
- **`network/rxindexer.py` kills 10%**, but 55 of its 85 survivors are annotations — the module is
  small and heavily typed. Adjusted, it is 30 genuine survivors out of 40 non-annotation mutants,
  which is still the weakest ratio in `network/` and the one to look at first.

For contrast, the small guard modules score well: `_guards.py` 82%, `tls_pin.py` 81%,
`chaintracker.py` 80%, `confirm.py` 77%. Test quality here is not uniformly low — it is low
specifically where the module is large and its coverage comes from regtest rather than unit tests.

## Reading the score — survivors are not all bugs

A large share of survivors are **equivalent mutants** that *cannot* be killed because they don't change
behavior. In this codebase they cluster into:

- **Type annotations** — `bytes | None` → `bytes - None`. Harmless: `from __future__ import annotations`
  makes annotations strings, never evaluated. This is the single largest class in every file (e.g. 33 of
  transaction.py's survivors sit on two `str | bytes | Reader` signatures).
- **Error-message f-strings** — `f"…offset {i - 1}"` → `{i + 1}`. Only the *text* of an exception
  message; no test asserts exact wording, and it shouldn't.
- **Interpreter-detail equivalents** — `==` → `is` on small interned ints / single-char strings /
  enum members; `x & (1<<31)` → `x // (1<<31)` inside a range-checked 32-bit domain; `<` → `!=` on a
  monotonically increasing loop counter.
- **Equivalent-for-valid-inputs** — e.g. `to_ef`'s `source_txid` branch (both branches produce the same
  bytes when `source_txid == source_transaction.txid()`, which construction guarantees), or comparison
  rewrites that only diverge for inputs outside the documented domain (`change_distribution` strings
  other than `"equal"`/`"random"`).
- **Outcome-equivalent guards** — `from_hex` length checks where `!=` vs `<` cannot differ because
  `Reader.read_bytes` never over-returns, and any fall-through still ends in the same `None` via the
  surrounding `suppress(Exception)`.

So the raw kill-rate **understates** real assertion quality. The value of the run is finding the
*genuine* gaps — branches that execute with no behavioral test.

## What the 2026-07 run found and closed

Survivor triage produced `tests/test_mutation_hardening.py` — every test there names the mutant class
it kills. The genuine gaps were real and some were consensus-adjacent:

- **`Transaction.txid()` byte order had no test.** The `hash()[::-1]` reversal could be deleted and the
  suite stayed green. Now pinned against a stdlib-only double-SHA256 re-derivation.
- **The FORKID preimage module was killable almost at will** (56%+ survival at baseline): the ref-scanner
  push-skip arithmetic, SIGHASH branch selection, and field assembly had only fixed-vector coverage.
  The spec-derived differential (`tests/test_preimage_differential.py`, anchored to the radiantjs golden
  vectors) now catches these, plus direct pins for the truncated-pushref guards the (deliberately
  well-formed) differential generator can't reach.
- **Script chunk parsing asserted nothing about chunk data** — push-boundary (75 B), PUSHDATA1/2/4
  dispatch, `from_asm` token handling ("-1" vs "0", push-size cliffs, unknown opcodes), `find_and_delete`
  retention, `__eq__` vs ordering.
- **Validation guards lacked boundary-exact tests** — dMint deploy params (`__post_init__` rules),
  CSV/CLTV ranges and the disable-bit ordering, BEEF version magic, `parse_script_offsets` skip
  arithmetic, minimal-push sign-bit padding (`0x90` → `90 00`).
- **dMint state re-derivation guards** — the script-number parser pinned to the encoding spec from both
  sides (parse + encode), and surgical corruption of valid contracts at documented layout offsets.

## What the 2026-08 run found (open — not yet closed)

The full survivor lists are in [`../reference/mutation-survivors/`](../reference/mutation-survivors/index.md),
one file per group, with file:line and the exact source change. These are the entries whose *meaning* is
worth stating up front, because in each case the guard is load-bearing and its removal is invisible:

- **The relay-floor comparison has no equality test.** `fee_sizing.required_fee` line 284,
  `if fee_rate < relay_floor_photons_per_byte()`, survives being rewritten to `<=`, `!=` and `is not`.
  Those differ from `<` only when `fee_rate == floor` — the single most common production value, and
  the case that decides whether a caller's sub-floor rate is honoured verbatim or raised.
- **`fee_never_below_relay_floor`'s rate arithmetic is never decisive.** Line 336's
  `size_bytes * fee_rate` survives `-`, `//`, `%`, `>>` and `&`: every test of this function lands on
  the `min_relay_fee` side of the `max()`. This is the "no opt-out" API documented for callers whose
  fee rate crosses a trust boundary.
- **Two exported consensus constants are unpinned.** `WITNESS_SCALE_FACTOR = 4` (BIP141, used by
  `bitcoin_virtual_size` and re-exported through `gravity/fee_policy.py`) survives becoming 3 or 5;
  `RADIANT_MIN_RELAY_PHOTONS_PER_KB` survives ±1. No test states either value.
- **HTLC unlocking-script size estimates are unpinned.** In `gravity/htlc_spend.py`, `lambda: 110`
  (P2PKH fee input) survives 109 and 111, and `lambda: len(selector) + 80` (covenant input) survives
  every binary-operator rewrite including `-`. These estimates are what the fee is sized from before
  the real signature exists. Radiant has neither RBF nor CPFP, so an under-estimate is the documented
  failure: rejected for `min relay fee not met`, holding its inputs until mempool expiry — on a claim,
  against a deadline. The same file's line 149 appends the sighash flag with `to_bytes(1, "little")`
  and survives a width of 2, which would emit a scriptSig consensus rejects; nothing asserts the bytes.
- **The cross-chain timelock ordering guard is not boundary-tested.** `swap_coordinator`'s
  `assert_timelock_margin` line 510, `if btc_blocks <= rxd_blocks`, survives rewriting, as does the
  margin comparison on line 514. The equal-timelock case is exactly the unsafe one.
- **Validation loops can be made to iterate zero times.** `ZeroIterationForLoop` survives on
  `swap_coordinator`'s `__post_init__` and `taker_refund_window_open` parameter-validation loops —
  every guard inside them is unexercised. `accept_flat_burial: bool = False` also survives flipping to
  `True` at all three of its declarations, a safety-posture default nothing pins.
- **RSWP order/asset binding guards survive.** In `swap/rswp/orders.py`, the checks that the offered
  UTXO belongs to the order (`give_source_tx.txid() != order.offered_txid`) and that the advertised
  token id and contract type match what is actually offered (`order.token_id != _pushed_token_id(give)`,
  `order.offered_type != _contract_type_of(give)`) all survive operator rewrites, as does
  `change = total_in - fee`. `tx.sign(bypass=True)` survives flipping to `False` in three builders.

Nothing here is a demonstrated exploit, and several may prove equivalent on inspection. What the run
establishes is narrower and still worth having: **these lines can be changed without any test
objecting**, in modules that decide how much value moves and to whom.

## Known remaining survivors (deferred)

- `spv/merkle.py` — the `i * 33` branch-index arithmetic needs a **multi-level** proof fixture;
  `spv/pow.py` chunked compare needs mined boundary headers; `spv/payment.py` needs boundary-exact
  transactions (unchanged from 2026-06).
- `transaction.py` BEEF **bump-combine** branches (`to_beef` path_index dedup/merge) need
  MerklePath-carrying fixtures; BEEF/EF are BSV interchange formats, not Radiant consensus surfaces, so
  these are documented rather than chased.
- `glyph/dmint/chain.py` async ElectrumX discovery flows and `glyph/dmint/miner.py` mining-dispatch
  loops — operational (not byte-consensus) paths whose remaining survivors are timing/IO-shaped; the
  regtest e2e suites cover them end-to-end.
- `glyph/builder.py`'s uncovered third — the offline suite never executes it, so those survivors say
  "not tested offline", which is already known from the 66% line coverage. Closing them means either
  offline fixtures for the builder paths or accepting that the regtest suites own them; that is a
  scope decision, not a triage one.

## Where this runs

Three places, deliberately, and **not** on the per-push path:

| Where | What | Why |
|---|---|---|
| `task mutate <group>` | on demand, locally | the loop you use while writing killer tests |
| [`Mutation (scheduled)`](https://github.com/MudwoodLabs/pyrxd/blob/main/.github/workflows/mutation.yml) | weekly, one parallel job per group | keeps the survivor list current without anyone remembering to run it |
| pre-release | `task mutate value` over the groups touching what shipped | the release checklist's slot for "did the new tests actually assert anything" |

The per-push gate is `ci.yml`, whose required checks must stay fast enough that people do not learn
to route around them; the measured cost here is **5 h 36 m of compute**, 16-104 minutes per group on
a loaded 32-core box. That is not a per-push shape at any budget. The scheduled lane is modelled on the existing
`Fuzz (scheduled)` workflow — Tuesday cron so it does not collide with Monday's fuzz run, forks
excluded from the schedule, manual `workflow_dispatch` retained.

One job per group, `fail-fast: false`. Groups **cannot** share a runner: cosmic-ray edits
`src/pyrxd` in place, so a second group's tests would import the first group's mutant and mis-score
it. Separate runners give each group its own checkout for free and make the wall clock the slowest
group rather than the sum. The repo is public, so these are free-tier minutes rather than a draw on
the private Actions pool.

The lane is **report-only** — no `MUTATION_MIN_KILL_PCT`. A third of the survivors in this scope are
equivalent mutants (1 045 of 3 122 are annotation-only by the conservative count), so a raw kill-rate
threshold would either sit below the real quality bar or fail the build on untriaged noise. Its
output is the uploaded survivor list; triage is the human step, and the tests it produces belong in
`tests/test_mutation_hardening.py`. Set a per-group threshold once that group's equivalent classes
have been triaged out — `fee` at 89% is the closest to ready.
