---
title: Fuzzing strategy — graduated approach (hypothesis → atheris → OSS-Fuzz)
problem_type: design_decision
component: pyrxd (testing strategy, parser hardening)
status: planned
date_captured: 2026-05-06
tags: [fuzzing, testing, hypothesis, atheris, oss-fuzz, parsers, security]
---

## Context

The dmint V1 classifier gap (see
[`docs/solutions/logic-errors/dmint-v1-classifier-gap.md`](../logic-errors/dmint-v1-classifier-gap.md))
surfaced because pyrxd's parser tests round-tripped a synthetic builder
through the parser they were testing. That bug was *spec mismatch*, not
*memory corruption / hang / crash on adversarial input*. The next class
of parser bug — what fuzzing actually finds — is still latent in pyrxd's
attacker-facing parser surface:

- `Transaction.from_hex(bytes_from_electrumx_server)` — adversarial varints
- `DmintState.from_script(bytes_from_some_output)` — adversarial state pushes
- `decode_payload(cbor_bytes_from_attacker_reveal_tx)` — adversarial CBOR
- `extract_reveal_metadata(scriptsig_bytes)` — adversarial scriptSig push-data
- `GlyphRef.from_bytes` / `GlyphRef.from_contract_hex` — short-input edge cases

Every one of these takes attacker-controllable bytes and walks them. They
are exactly where fuzzing pays off.

## What was decided

A **graduated approach** rather than jumping straight to OSS-Fuzz. Three
stages, each independently valuable, increasing in setup cost:

### Stage 1 — `hypothesis` property tests (next session)

`hypothesis` is already in the dev dependencies (`hypothesis = "^6.98.0"` in
`pyproject.toml`). Property-based tests via `@hypothesis.given(binary())`
provide ~80% of the fuzzing value with ~zero new infrastructure. They run
inside the existing `pytest` invocation, surface failures as normal test
output, and seed-shrink any failing input down to the minimum reproducer.

**Targets and properties to assert:**

| Function | Property |
|---|---|
| `Transaction.from_hex(arbitrary_bytes)` | Never crashes; either returns `None` or a `Transaction` instance. If it returns a `Transaction`, calling `.serialize()` does not crash. |
| `DmintState.from_script(arbitrary_bytes)` | Never raises anything but `ValidationError` (defends the dispatcher contract). |
| `DmintState._from_v1_script(arbitrary_bytes)` | Same — only `ValidationError`. |
| `DmintState._from_v2_script(arbitrary_bytes)` | Same. |
| `GlyphRef.from_bytes(arbitrary_bytes)` | Never raises anything but `ValidationError`. |
| `GlyphRef.from_contract_hex(arbitrary_str)` | Never raises anything but `ValidationError`. |
| `decode_payload(arbitrary_bytes)` | Never raises anything but `ValidationError` or `cbor2.CBORDecodeError`; for inputs > 64 KB the size cap fires before any CBOR walk. |
| `extract_reveal_metadata(arbitrary_bytes)` | Never raises (returns `None` for unrecognised inputs — already documented invariant). |
| `is_ft_script(arbitrary_str_of_hex)` / `is_nft_script` / `is_dmint_contract_script` | Never raises; always returns `bool`. |

**Estimated cost:** ~50 LOC across `tests/property/test_parser_robustness.py`,
~1-2 hours of work, runs in the existing pytest invocation.

**Estimated value:** if any of these properties fail, that's a real
crash-on-adversarial-input bug. Hypothesis will minimise the failing input
to the smallest possible reproducer, making the fix and regression test
trivial.

### Stage 2 — `atheris` harnesses (when there's a free afternoon)

`atheris` is Google's `libFuzzer`-based fuzzer for Python. It instruments
imports for coverage feedback and runs at ~10k executions/sec on a single
core. Compared to hypothesis:

- Coverage-guided (mutates inputs that reached new branches)
- Higher throughput (orders of magnitude more inputs per second)
- Persists a corpus of "interesting" inputs across runs
- Catches subtle bugs hypothesis's random generation misses

**Targets:** the same parsers as Stage 1, but as standalone fuzz harnesses
under `fuzz/`. Each harness is ~10-30 lines:

```python
# fuzz/fuzz_transaction_parse.py
import sys
import struct
import atheris
with atheris.instrument_imports():
    from pyrxd.transaction.transaction import Transaction

def TestOneInput(data: bytes) -> None:
    try:
        tx = Transaction.from_hex(data)
        if tx is not None:
            tx.serialize()
    except (ValueError, IndexError, struct.error):
        pass  # documented failure modes
    # ANY OTHER exception is a bug.

atheris.Setup(sys.argv, TestOneInput)
atheris.Fuzz()
```

Run locally for hours/days; whenever a crash is found, atheris dumps the
offending bytes. Add the bytes to `tests/property/corpus/` as a regression
seed and fix the bug.

**Estimated cost:** ~1 day initial setup (4-5 harnesses, dev-dep on
`atheris`, optional seed corpus from real-mainnet fixtures).

### Stage 3 — OSS-Fuzz integration (when pyrxd hits a v1.0 / security milestone)

[OSS-Fuzz](https://github.com/google/oss-fuzz) is Google's free continuous
fuzzing service. After Stage 2 harnesses exist, submitting them to OSS-Fuzz
takes ~1 day (3 files: `build.sh`, `Dockerfile`, `project.yaml` in the
OSS-Fuzz monorepo). After that:

- Google runs the harnesses on their cluster, their CPUs, their bill
- 90-day responsible-disclosure window on findings
- Sanitizer-instrumented build catches memory errors and undefined behaviour
- Auto-bisects to the introducing commit
- Public coverage stats

**Why not skip straight to Stage 3:** common mistake. Going to OSS-Fuzz
before doing the cheap hypothesis wins floods you with shallow bugs that
were obvious in retrospect. Stage 1 squashes those in a few hours; OSS-Fuzz
then finds the deep bugs without noise.

## What was rejected

- **Going straight to OSS-Fuzz.** See above.
- **One mega-harness covering all parsers.** Hypothesis's
  `@hypothesis.given()` per-test-function model is the right granularity.
  One harness per parser keeps failures localized.
- **Custom mutators.** Both hypothesis and atheris generate inputs well
  enough for our parsers. Adding format-aware mutators is premature
  optimisation.
- **Fuzzing the CBOR codec itself.** `cbor2` is upstream and already
  fuzzed. Our exposure is the post-decode validation in
  `decode_payload` — that's what we test.

## Open questions for Stage 1 implementation

- **Where do the property tests live?** Recommend `tests/property/` to
  match the existing `tests/security/` (special-cased coverage gate)
  and `tests/cli/` (sub-package layout) conventions.
- **What's the failure budget?** Each property test should run for at
  least ~200 generated inputs by default; raise via
  `@settings(max_examples=...)` for the slow ones. Keep total runtime
  under 30s so the existing test suite doesn't balloon.
- **Should we ship the seed corpus?** Inline-as-bytes in the test file is
  the project norm (see `_RBG_DMINT_V1_HEX` in
  `tests/test_glyph.py::TestV1DmintParser`). A `tests/property/corpus/`
  directory would only matter for atheris later.

## Pointers for whoever picks this up

- Already in dev deps: `hypothesis = "^6.98.0"` (`pyproject.toml` line ~88)
- Existing hypothesis usage in pyrxd: search `tests/` for
  `@hypothesis.given` to see the project's idiom.
- Useful strategies for parser fuzzing:
  - `binary(min_size=0, max_size=10_000)` — general byte fuzzing
  - `binary(min_size=0, max_size=100)` — short-input edge cases
  - `text(alphabet="0123456789abcdef")` — hex-string parsers
  - `tuples(...)` to combine valid prefixes with random suffixes
- The corrective rule from
  [`docs/solutions/logic-errors/dmint-v1-classifier-gap.md`](../logic-errors/dmint-v1-classifier-gap.md)
  applies: synthetic round-trips aren't enough — the property test must
  also be exercised on real-mainnet bytes (use existing fixtures as
  hypothesis seeds via the `@example()` decorator).

## Related

- [`docs/solutions/logic-errors/dmint-v1-classifier-gap.md`](../logic-errors/dmint-v1-classifier-gap.md) —
  the bug that prompted thinking about fuzzing
- Conversation context (May 6, 2026): the inspect-tool series PR chain
  (#34-#43) hardened these parsers against many shapes of malformed
  input via threat-model-driven security review. Fuzzing is the next
  layer of the same defense.
