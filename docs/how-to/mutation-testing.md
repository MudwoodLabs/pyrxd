# Mutation testing the SPV verifier

Mutation testing measures **test quality**, not just line coverage: it mutates the source (e.g. flips
`!= 80` to `< 80`, `i - 1` to `i + 1`) and checks whether the suite *catches* each change. A **killed**
mutant means a test failed (good); a **survived** mutant means the line runs but no assertion pins its
behavior — a potential gap.

## Running it

```bash
poetry install --with dev   # brings in cosmic-ray
poetry run task mutate
```

This runs [`scripts/mutation_test.sh`](../../scripts/mutation_test.sh) over the consensus-critical SPV
verification modules — `pow.py` (PoW/difficulty), `merkle.py` (proof), `chain.py` (header-chain link +
nBits pin), `payment.py` (output parse). It mutates `src/pyrxd/spv/<file>.py` **in place** (the editable
install picks it up), runs the SPV tests, and restores via `git` (a trap restores on any exit). It is an
**occasional gate, not part of `task ci`** (slow). Don't run concurrent git ops on `src/pyrxd/spv` while
it runs.

> The parser modules `proof.py` / `witness.py` are **excluded** here on purpose: they're covered by the
> fuzz harness (`tests/test_fuzz_spv_parsers.py`), and the full test command that covers them is ~30×
> slower per mutant. Mutation-testing the *verification arithmetic* is the high-value scope.

## Baseline results (2026-06)

| Module | Mutants | Killed | Survived | Killed |
|---|---|---|---|---|
| `pow.py` | 143 | 120 | 23 | 84% |
| `merkle.py` | 354 | 288 | 66 | 81% |
| `chain.py` | 132 | 78 | 54 | 59% |
| `payment.py` | 268 | 219 | 49 | 82% |

## Reading the score — survivors are not all bugs

A large share of survivors are **equivalent mutants** that *cannot* be killed because they don't change
behavior. In this codebase they cluster into:

- **Type annotations** — `bytes | None` → `bytes - None`. Harmless: `from __future__ import annotations`
  makes annotations strings, never evaluated.
- **Error-message f-strings** — `f"…header[{i - 1}]"` → `{i + 1}`. Only the *text* of an exception
  message; no test asserts the exact wording, and it shouldn't.
- **Unreachable invariants** — `pow.py`'s `if len(target_le) != 32` is dead by construction (the
  validated nBits exponent guarantees 32); it's deliberate defense kept out of `python -O`'s reach.
- **Redundant guards** — `chain.py`'s per-header `len(header) != 80` is masked by `verify_header_pow`'s
  own length check (defense in depth). Bypassing one still trips the other.

So the raw kill-rate **understates** real assertion quality. The value of the run is finding the
*genuine* gaps — branches that execute with no behavioral test.

## What the 2026-06 run found and closed

Mutation testing surfaced genuine, security-relevant gaps in **input validation**: the length guards and
the chain-link check executed, but no test fed an adversarial length or a broken link.
[`tests/test_spv_validation_hardening.py`](../../tests/test_spv_validation_hardening.py) closes them:

- `pow.py` / `chain.py` **length guards** — wrong-length header / chain-anchor / nBits inputs (using a
  real header ± a byte so a mutated guard falls through to a *different* error). Killed the
  `len(...) != N` → `< N` / `> N` mutants (pow survivors 25 → 23, chain 64 → 54).
- `chain.py` **link verification** — a valid 2-header consecutive chain (must pass) plus a broken link
  (reversed order, must raise), exercising the core `prevHash == hash(prev)` check that had no
  break-case test.

## Known remaining survivors (deferred)

Harder gaps that need crafted/mined fixtures — tracked for a follow-up, lower marginal value:

- `merkle.py` — the `i * 33` branch-index arithmetic survives because tests use only **single-level**
  (1-sibling) proofs; for `i = 0` every mutant operator collapses to 0. Needs a **multi-level** proof
  fixture.
- `pow.py` — the chunked `hash_be` vs `target_be` comparison and the `< 3` exponent boundary need
  headers with hashes/targets crafted to the chunk/boundary (effectively requires mining).
- `payment.py` — the size/offset guards need boundary-exact transactions (a tx exactly at `min_output_size`).
