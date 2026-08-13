# Mutation testing the consensus-critical modules

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
poetry run task mutate keys               # key-material + operator-input guards
poetry run task mutate all                # everything, sequentially (hours)
```

This runs [`scripts/mutation_test.sh`](../../scripts/mutation_test.sh). It mutates
`src/pyrxd/<scope>/<file>.py` **in place** (the editable install picks it up), runs a scope-targeted
fast test command per mutant, and restores via `git` (a trap restores on any exit). It is an
**occasional gate, not part of `task ci`** (slow). Don't run concurrent git ops on `src/pyrxd` while it
runs — when other sessions/worktrees are active, run the whole thing in a detached worktree (see
`docs/solutions/integration-issues/task-ci-spurious-failures-from-concurrent-worktrees.md`).

Useful environment knobs:

- `MUTATION_SESSION_DIR=dir` — keep the cosmic-ray session `.sqlite` files for survivor triage
  (query them with `cr-report`, `cr-html`, or a `mutation_specs ⋈ work_results` join for diffs).
- `MUTATION_MIN_KILL_PCT=N` — opt-in gate: exit non-zero below N% total kill rate.

> Scope exclusions, on purpose: `spv/proof.py` / `spv/witness.py` (covered by the fuzz harness, ~30×
> slower per mutant), `__init__.py` re-export shims, `script/unlocking_template.py` (17-line ABC), and
> `glyph/dmint/__init__.py`. The whole-file scope for `glyph/dmint/miner.py` includes the mining
> dispatch loops; their kills come mostly from the DAA/preimage tests, not the multiprocessing paths.

## The `keys` scope (2026-08)

Every scope above mutates *arithmetic* — difficulty, Merkle paths, sighash preimages, covenant
bytes. None of them mutates the code standing between key material or operator input and a sink:
the redaction heuristic, the WIF/xprv decoders, the extended-key `__str__` overrides, the
xprv-in-a-descriptor refusal, the credential-file permission gate.

That gap mattered because those modules look the *most* tested by the usual measure.
`pyrxd.security` is held at 100% line and branch coverage — and 100% coverage says every line ran,
not that any assertion would notice if the line were wrong. A guard is a pure predicate over cheap
inputs: exercising it is nearly free, and asserting its *boundary* is a separate act that coverage
cannot distinguish from not asserting it.

The first sweep of `security/errors.py` bore that out. Excluding the annotation-equivalent class
below, the live mutants were all in guard predicates that every existing test walked through
without pinning:

| Mutant | Why it survived |
|---|---|
| `not t.isupper()` → `t.isupper()` | every test phrase came from a wordlist the SDK ships, which the *other* branch already catches |
| `t == t.lower()` → `t < t.lower()` | same |
| `len(value) > 8` → `> 9` (str, and again for bytes) | the documented "longer than 8 characters" threshold had no test at the value that distinguishes 8 from 9 |
| `except Exception:` stops catching | the "never raises" contract in a function called from `RxdSdkError.__init__` was documented, not tested |

Each is now pinned by a named test in `tests/security/test_key_material_never_echoed.py`, and each
was re-checked by re-planting the mutant.

Two more survivors turned up in the file-permission gates and are worth recording because neither
is about arithmetic:

- **`mode & 0o077` → `mode & 0o007`** in `cli_secrets.read_file_guarded` survived because the test
  that existed for it asserted only `0o644` — despite being *named* for the group case. A `0o640`
  secret file is readable by every account in the owner's group. Now parametrised per bit position.
- **Re-deriving the wallet file's mode from `path.stat()`** after reading it survived the
  swap-the-file test, because that test's swap lands later than the re-stat does. Timing tests pin
  timing; the structural property ("the verdict never consults the path") needed its own assertion.

### A methodology note that cost an hour

A hand-mutation harness that edits a file, runs pytest, then restores the original **must**
invalidate `__pycache__`. `0o077` → `0o007` is a same-length edit, so the restored file can keep the
same size and (at filesystem mtime granularity) the same timestamp — CPython then reuses the
mutated `.pyc` and every *subsequent* run silently executes the mutant. That produced four failures
in a file nobody had touched, against source that was provably correct on disk. `cosmic-ray` is not
affected (it re-inits per mutant), but any bespoke harness is. Set `PYTHONDONTWRITEBYTECODE=1` and
purge `__pycache__` between mutants.

## Scopes and test commands

Each scope uses a fast targeted test list (defined in `mutation_test.sh`) so a full file sweep stays
tractable — the per-mutant cost is the test command's wall time. `tests/test_mutation_hardening.py`
(the survivor-killing assertions) leads every list so `-x` exits cheapest on the pinned mutants; the
property/differential suites (`test_preimage_differential.py`, `test_dmint_vector_derivations.py`)
close the transaction/dmint lists as the wide net.

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
