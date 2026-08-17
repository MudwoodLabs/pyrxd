---
title: "`ast.get_source_segment` rescans the whole file per node, so the 3.10 and 3.11 CI jobs ran 4-5x longer than 3.12"
date: 2026-08-16
problem_type: performance_issue
component: "tooling / ci (`test (3.10)`, `test (3.11)`) — `tests/test_no_duplicate_consensus_constants.py`"
symptoms:
  - "`test (3.10)` took 39.0 min and `test (3.11)` 34.2 min while `test (3.12)` took 8.2 min"
  - All three jobs ran the identical 9,158 tests — no version-gated skips, no extra parametrisation
  - Every PR waited ~35 minutes on two jobs after the one people watch had been green for half an hour
  - The gap grew with the size of the source tree, so it worsened quietly as the repo grew
severity: medium
status: solved
tags:
  - ci
  - python-version-matrix
  - ast
  - get-source-segment
  - quadratic
  - memoization
  - functools-cache
  - test-performance
  - measure-before-optimising
---

## Symptom

The three CI test jobs diverged by a factor of five on identical work:

| job | duration | tests run |
|---|---|---|
| `test (3.10)` | **39.0 min** | 9,158 |
| `test (3.11)` | **34.2 min** | 9,158 |
| `test (3.12)` | **8.2 min** | 9,158 |

Same commit, same suite, same counts (`9158 passed, 192 skipped, 1 xfailed` on all three). Every
pull request therefore sat for ~35 minutes after `test (3.12)` and `lint` had gone green.

It hid for months for a structural reason: **`test (3.12)` and `lint` are the required checks**
(CHANGELOG, the `integration.yml` split entry). The two slow jobs were advisory, so nobody was
blocked by them often enough to ask why. The 0.18.0 release cut is where it surfaced — the handoff
note for that release records the cut stalled "waiting on the last two CI jobs of PR #442
(`test (3.10)`, `test (3.11)`). Everything else was green: `test (3.12)` 7m43s".

## Root cause

`tests/test_no_duplicate_consensus_constants.py` asks, for every integer literal in the source
tree, **how that literal was written** — `0xd2` (a ref opcode, guarded) versus `210` (an ordinary
number). The AST does not carry that distinction, so each candidate node was resolved back to its
source text with `ast.get_source_segment(source, node)`.

**That function re-splits the entire file on every call.** In CPython 3.12 it passes a bound:

```python
lines = _splitlines_no_ff(source, maxlines=end_lineno+1)   # 3.12
```

so it stops splitting at the node's own line. In 3.10 and 3.11 `_splitlines_no_ff` takes no
`maxlines` argument and splits the whole source, every time. For a constant near the top of a
2,000-line module, 3.12 splits ~10 lines where 3.11 splits 2,000 — and the penalty scales with
file size, so it grew as the repo grew.

Measured over this repo's 198 source files / 255,437 AST nodes / 11,030 integer constants:

| operation | 3.12 | 3.11 | 3.10 |
|---|---|---|---|
| `ast.parse` (all files) | 0.19 s | 0.22 s | 0.19 s |
| `ast.walk` (all trees) | 0.07 s | 0.08 s | 0.08 s |
| **`ast.get_source_segment` per constant** | **6.8 s** | **46.7 s** | **71.3 s** |

Parsing and walking are the same speed on all three interpreters. **The entire version gap is one
stdlib helper** — which is what rules out "older Python is just slower" as an explanation.

The cost was then multiplied: the guards are parametrised (60 collected cases at the time of
writing, recorded as 88 in the code's own docstring), and each case re-read and re-parsed all 198
files.

## Genuinely ruled out

Recorded because each was plausible and each is worth *not* re-investigating next time.

- **Extra tests on older versions.** Ruled out by comparing pytest summary lines across the three
  jobs: `9158 passed, 192 skipped, 1 xfailed` on all three. Identical counts, so no
  `skipif(sys.version_info …)` asymmetry. A tree-wide grep for `version_info` in `src/` and
  `tests/` also returns nothing that changes *work* — only the documented `tomli` import fallback.
- **Coverage tracing core.** The theory was that 3.12 uses `sys.monitoring` (PEP 669) while
  3.10/3.11 fall back to `sys.settrace`. It does not: `[tool.coverage.run] branch = true` and
  coverage warns `Can't use core=sysmon: sys.monitoring can't measure branches in this version,
  using default core (no-sysmon)`. **All three versions use `CTracer`.** Measured on an ordinary
  subset, 3.11's coverage overhead (2.6x) is *lower* than 3.12's (3.2x).
- **Dependency install / cache.** Ruled out from the jobs API step timings: install was 0.3-0.4 min
  on every version; the divergence was entirely inside the "Tests + overall coverage" step
  (33.2 / 32.2 / 6.9 min).
- **A slow test unique to older versions.** Ruled out by `--durations=25` on both 3.11 (docker
  `python:3.11-slim`) and 3.12, same machine: the same two tests topped both lists, just 6.6x
  further apart.

## The fix

Merged as **PR #448** (`50a9c83`). Two changes, both in
`tests/test_no_duplicate_consensus_constants.py`.

**1. Split each source once, then slice.**

```python
#: The parser's line rule, which is NOT ``str.splitlines()``.
_LINE_END = re.compile(r"[^\r\n]*(?:\r\n|\r|\n)|[^\r\n]+\Z")           # :156

@functools.cache                                                        # :159
def _utf8_lines(source: str) -> tuple[bytes, ...]:
    return tuple(m[0].encode() for m in _LINE_END.finditer(source))

def _source_segment(source: str, node: ast.AST) -> str | None:          # :170
    ...
    if end_lineno != lineno:
        return ast.get_source_segment(source, node)   # rare; keep stdlib semantics
    return _utf8_lines(source)[lineno][col_offset:end_col_offset].decode()
```

Two details the replacement has to get right, and both are load-bearing:

- **The parser's line rule is not `str.splitlines()`.** Only `\r`, `\n` and `\r\n` end a line.
  `str.splitlines()` also breaks on form feed, vertical tab and U+2028 — any of which would shift
  every subsequent line number and slice the wrong text.
- **`col_offset` is a byte offset, not a character offset.** Lines are UTF-8 encoded before
  slicing. The stdlib does the same `.encode()[a:b].decode()` dance for the same reason; without
  it, any line containing a multi-byte character slices wrongly.

Multi-line nodes still defer to the stdlib. They are rare, and deferring keeps exact semantics for
the harder case instead of reimplementing it.

**2. Memoise the parse.**

```python
@functools.cache                                                        # :468
def _parse(source: str):
```

The trees are only ever read, never mutated, so sharing them across parametrised cases is safe.
This is the same remedy as the earlier CI fix in PR #140, which used `@functools.cache` on a
proof-of-work grind that three tests were repeating identically.

## Verification

**Correctness first — a faster answer that differs is worthless here.** Every guard in that file
decides whether a constant was written as hex or decimal from this string, so a wrong slice
silently turns a real consensus-constant violation into a pass.

`TestSourceSegmentMatchesTheStdlib` asserts equivalence with `ast.get_source_segment` across 12
sources chosen as the cases a hand-rolled splitter gets wrong — LF, CRLF, lone CR, no trailing
newline, form feed, vertical tab in a string, multi-byte characters before and on the literal's
line, multi-line and nested-multi-line nodes, blank leading lines, comment-then-constant — plus
every positioned node of a real module, and a node with no position info (must return `None`, not
raise). The file goes **160 → 174 tests**.

**The one file, same machine, before → after:**

| Python | before | after | |
|---|---|---|---|
| 3.12 | 32.3 s | 6.0 s | 5.4x |
| 3.11 | 183.9 s | 12.5 s | **14.7x** |
| 3.10 | 279.0 s | 16.9 s | **16.5x** |

**Real CI, before → after** (the numbers that motivated the work):

| job | before | after |
|---|---|---|
| `test (3.10)` | 39.0 min | **8.3 min** |
| `test (3.11)` | 34.2 min | **7.8 min** |
| `test (3.12)` | 8.2 min | **6.7 min** |

The matrix now finishes together instead of 3.12 waiting half an hour for the other two — roughly
**57 minutes of wall clock returned per CI run**. Full suite after the change: 9,175 passed.

## Prevention

The pattern to refuse in review: **an uncached helper that does whole-input work, called inside a
per-item loop, inside a parametrisation.** That is three multipliers stacked, and it reads as
normal code because the surrounding idiom in this file is exactly "AST for structure, source
spelling for intent".

A sweep of `src/`, `tests/`, `scripts/` and `examples/` after the fix found **`ast` is not imported
in production code at all** — this class of bug is test-only in this repo. The remaining risks are
structural rather than currently expensive, and all live in the tree-scanning guards:

1. **Any new `source`-taking helper in `test_no_duplicate_consensus_constants.py`** must bottom out
   in `_source_segment` (`:170`) or carry its own `@functools.cache`. Every existing `ast.walk` +
   whole-`source` call site now does; a new one that does its own splitting silently reopens the
   hole.
2. **`_strip_comments_and_docstrings` (`:192`) is the closest structural twin still uncached** —
   three whole-file `re.sub` calls, two using the backtracking-prone `(?:.|\n)*?`, invoked per file
   for each of 26 parametrised cases. Cheap today (1.04 s for the class on 3.12); a shape risk, not
   a current cost.
3. **`_python_files(root)` (`:131`) re-runs `rglob` + `sorted` for every case**, and
   `path.read_text()` re-reads and re-decodes every file per case — the parse and the split are
   cached *on the source string*, so the disk read is the missing final layer.
4. **`tests/test_consensus_parser_strictness.py:534` and `:627`** parse every file uncached. Single
   caller each, so harmless now — they become quadratic the moment either test is parametrised.
5. **`tests/test_residual_register_traceability.py:40`** does up to three `rglob` walks per
   unresolved token, unmemoised; it scales with register size × tree size.
6. **`tests/test_false_consensus_premises.py:318`** re-globs three roots for both `*.py` and `*.md`
   per parameter, unmemoised.

Two process guards, beyond the code:

- **Do not let advisory jobs rot.** This survived because only `test (3.12)` and `lint` are
  required. A job nobody is blocked by is a job nobody profiles. If the matrix exists, its cost
  should be looked at occasionally — the 3.10/3.11 legs exist for a real reason (`ci.yml` documents
  a genuine 3.10-only code path, the `tomli` backport in `cli/config.py`), so they are not
  decoration.
- **`--durations` before optimising.** Every wrong hypothesis above was cheap to kill with a
  measurement and would have been expensive to argue about.

## The transferable lesson

**When something is slow only on older Pythons and the test counts are identical, suspect a stdlib
function that got a version-specific optimisation — not the interpreter.**

The instinct is to blame the interpreter, and the interpreter is genuinely slower on 3.10 — by
roughly 1.2x, nowhere near the 4.7x observed. Measuring `ast.parse` and `ast.walk` separately and
finding them *identical* across versions is what turned a vague "old Python is slow" into a
one-function answer. The bisect that got there, in order, each step cheap:

1. **Step timings from the jobs API** — is it install, cache, or the tests? (It was the tests.)
2. **Compare pytest summary lines across versions** — same test count rules out version-gated work.
3. **Rule out the obvious environmental suspect** (here, the coverage core) by checking it rather
   than assuming it.
4. **`--durations` on both versions, same machine** — docker `python:3.11-slim` against local
   3.12. Two tests held 150 s of the 161 s gap.
5. **Microbenchmark the suspect stdlib calls in isolation**, which is where the 6.8 / 46.7 / 71.3
   split appeared and the answer became unambiguous.

## Still open

- **The equivalence oracle keeps one per-node `get_source_segment` sweep**
  (`test_it_matches_across_a_real_module`, `:1897`). That is deliberate — it is the test that
  proves the replacement matches the stdlib — and it is bounded to a single file: 1,075 positioned
  nodes in `src/pyrxd/constants.py`, measured at 0.16 s on 3.12 and **1.81 s on 3.10**. It is
  already inside the 16.9 s post-fix figure above. If that file grows substantially, cap the node
  count rather than dropping the oracle.
- **The uncached items 2-6 in Prevention are unfixed.** All measured cheap on 3.12 today; none
  measured on 3.10/3.11. They are listed so the next person finds them by reading rather than by
  waiting.
- **`CONTRIBUTING.md` still claims "full pytest suite, ~45 seconds" and "`task ci` … ~3-5 min".**
  Both predate this regression and the pre-push work; the latter was measured at 395 s. Stale
  claims, not yet corrected.

## See also

- [`../integration-issues/long-pre-push-hook-makes-git-push-to-github-fail-with-sigpipe.md`](../integration-issues/long-pre-push-hook-makes-git-push-to-github-fail-with-sigpipe.md)
  — the closest sibling, and the other half of the same week's CI-cost work: `task ci` measured at
  395 s exceeded GitHub's idle `git-receive-pack` timeout and killed pushes with exit 141. Same
  method — measure the thing, then cut it.
- [`../integration-issues/local-ci-parity-via-task-ci-and-pre-push-hook.md`](../integration-issues/local-ci-parity-via-task-ci-and-pre-push-hook.md)
  — the original local/CI parity decision, and where the `task ci` aggregate comes from.
- [`../../how-to/mutation-testing.md`](../../how-to/mutation-testing.md) — the repo's other
  measured-runtime budget (5 h 36 m serial, 1 h 44 m wall-clock), and the model for stating test
  cost honestly.
- [`../../concepts/architecture.md`](../../concepts/architecture.md) — `pyrxd/constants.py` as the
  single home for the consensus constants these guards defend, which is *why* the file scans the
  whole tree.
- `.github/workflows/ci.yml` — the matrix definition, and the in-file note explaining why 3.10 and
  3.11 are tested at all (a real 3.10-only `tomli` code path).
- `CHANGELOG.md` — the only record of the earlier CI-slowness fix, PR #140 ("halved the CI test job
  via header-grind memoization and dependency caching"). That fix addressed `test (3.12)`; this one
  addressed the other two legs. No solution doc was written for #140, which is part of why the
  second instance of the same remedy had to be rediscovered.
