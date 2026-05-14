---
title: "Ship the parallel pure-Python miner as pyrxd contrib"
type: feat
date: 2026-05-11
status: PROPOSED — targets 0.5.1 (NOT 0.5.0)
predecessor: docs/plans/2026-05-07-feat-dmint-v1-mint-and-reference-miner-plan.md
---

# Ship the parallel pure-Python miner as pyrxd contrib

## Overview

A 130-line `multiprocessing`-based pure-Python miner produced the live
mainnet PXD mint (txid `c9fdcd34…e530`, 2026-05-11). On the project
machine (i9-14900K, 32 cores) it sustains ~28 Mh/s aggregate and sweeps
the full V1 nonce space in ~2.5 minutes. The script currently lives at
`/tmp/parallel_python_miner.py` — outside the repo. This plan promotes
it into pyrxd as **contrib** (an officially-shipped, but explicitly
non-core, optional component) without expanding pyrxd's public API.

The 0.5.0 release ships **without** this miner. It is added in 0.5.1
once tests, docs, and the protocol contract are pinned.

## Problem statement

Three concrete pain points justify shipping the parallel miner:

1. **The serial `mine_solution()` is unusable on mainnet difficulty.**
   ≈1 Mh/s single-core × 2^32 floor ≈ 70 minutes for the lucky cases,
   hours for the unlucky ones. The plan-of-record (M1) said "for fast
   mining, install `glyph-miner`" — but `glyph-miner` is a third-party
   TypeScript/C++ binary that introduces silent-divergence risk.
2. **The `mine_solution_external()` protocol is shipped but
   undocumented externally.** It already lives at
   `src/pyrxd/glyph/dmint.py:880`. No reference implementation of the
   "other side" of that protocol exists inside the repo. Anyone wanting
   to write a custom miner today has to read pyrxd source and the
   already-shipped tests to figure out the JSON shape.
3. **Silent-divergence-with-the-verifier is the load-bearing risk for
   any miner.** The `glyph-miner` TypeScript codebase has its own
   midstate-precompute and BE byte-order assumptions; if either drifts
   from `verify_sha256d_solution`'s `hashlib` path, mined nonces pass
   the miner's local check, get embedded in a tx, and the network
   rejects them. A pure-Python miner that calls the **same** `hashlib`
   primitive as the verifier eliminates that class of bug by construction.

The miner already exists, has been validated on mainnet, and uses the
same `hashlib.sha256` path as pyrxd's verifier. The remaining work is
packaging, tests, docs, and protocol-stability commitments.

## Proposed Solution

### Location: `src/pyrxd/contrib/miner/`

New package directory:

```
src/pyrxd/contrib/
├── __init__.py            # docstring: "contrib — shipped but non-core"
└── miner/
    ├── __init__.py        # re-exports nothing publicly; namespace only
    ├── parallel.py        # the worker + mine() entry point
    ├── cli.py             # argparse + JSON-over-stdin/stdout main()
    └── protocol.py        # versioned dataclasses for the JSON shape
```

Rationale:
- **`src/pyrxd/contrib/`, not `scripts/` or `examples/`.** The miner is
  a redistributable component that should ship in the wheel and be
  invokable as a console script. `contrib/` signals shipped-but-non-core.
- **The `contrib` name has clear precedent** (Django, Bitcoin Core).
- **One sub-package, not files-at-package-root** — leaves room for
  future contrib pieces (e.g. a chain walker).

### Public API surface: zero new core exports

The miner is **not** importable from `pyrxd` or `pyrxd.glyph`.
Consumers reach it exactly two ways:

1. **As a subprocess** via `mine_solution_external(..., miner_argv=[
   sys.executable, "-m", "pyrxd.contrib.miner"])`.
2. **As a console script** via the `pyrxd-miner` entry point (added
   to `[project.scripts]` in `pyproject.toml`).

Code in `pyrxd.contrib.*` may be imported by adventurous users, but the
project makes **no semver promises** about that surface.

### Console script: `pyrxd-miner`

Add to `pyproject.toml`:

```toml
[project.scripts]
pyrxd        = "pyrxd.cli.main:run"
pyrxd-miner  = "pyrxd.contrib.miner.cli:main"   # new
```

Behavior:
- Reads one JSON object from stdin (the `mine_solution_external`
  request shape).
- Writes one JSON object to stdout on success.
- Exit code 0 on hit, 2 on nonce-space exhaustion, 1 on usage error.
- `--help` prints the protocol contract + version.
- `--workers N` overrides `os.cpu_count()`.
- `--quiet` suppresses any stderr progress messages.

### Protocol contract — pinned in 0.5.1

The `mine_solution_external` JSON shape is **already shipped** in 0.5.0
via the dmint.py docstring, but is not yet promoted to a versioned
contract. 0.5.1 freezes it.

#### Request (stdin, one line, UTF-8)

| Field           | Type   | Required | Description                              |
|-----------------|--------|----------|------------------------------------------|
| `preimage_hex`  | string | yes      | 64-byte preimage as 128 hex chars        |
| `target_hex`    | string | yes      | u64 BE target as 16 hex chars (no `0x`)  |
| `nonce_width`   | int    | yes      | 4 (V1) or 8 (V2)                         |
| `protocol`      | int    | no       | currently always 1; reject unknown       |

#### Response on hit (stdout, one line, UTF-8)

| Field           | Type   | Required | Description                              |
|-----------------|--------|----------|------------------------------------------|
| `nonce_hex`     | string | yes      | `nonce_width * 2` hex chars              |
| `attempts`      | int    | optional | best-effort metric; ≤ 2^40                |
| `elapsed_s`     | number | optional | finite ≥ 0; NaN/Inf rejected by pyrxd     |

#### Exit codes

| Code | Meaning                                                          |
|------|------------------------------------------------------------------|
| 0    | Solution written to stdout                                       |
| 1    | Usage error — bad JSON in, bad arguments, validation failed      |
| 2    | Nonce space exhausted (response is `{"exhausted": true}`)        |
| ≥128 | Killed by signal (parent timeout-fired SIGKILL)                  |

#### Exhaustion behavior — fix the `time.sleep(86400)` hack

The `/tmp` script currently sleeps 86400 seconds on exhaustion because
`mine_solution_external` treats `subprocess.TimeoutExpired` as
"no solution." That's a workaround for a real protocol gap.

**0.5.1 protocol addition**: on exhaustion, the miner writes
`{"exhausted": true}` to stdout and exits with code 2.
`mine_solution_external` is updated to recognise that response and
raise `MaxAttemptsError` immediately rather than waiting for the
parent timeout. Old miners that still sleep continue to work
(timeout path remains the fallback). This change is **additive to
the existing protocol**.

#### Protocol versioning

Embed `"protocol": 1` in the request. Reject unknown versions with
exit code 1. The 0.5.1 reference miner accepts requests without the
field (defaults to 1) for forward-compat.

### Cross-platform: default to `spawn`

The `/tmp` script relies on `multiprocessing`'s default start method,
which is `fork` on Linux and `spawn` on macOS 10.15+ / Windows. Mixing
those silently leads to "pickled closure" errors and inconsistent
worker startup.

**Fix in 0.5.1**: explicitly call `mp.set_start_method("spawn",
force=True)` before spawning workers, and refactor the `_worker`
function to take only picklable arguments (already true).

CI runs on Linux + macOS. Windows is marked best-effort (stretch).

### Dependencies: zero new ones

- `multiprocessing`, `hashlib`, `json`, `argparse` — all stdlib.

**Recommendation: bundle by default, do not gate behind extras.** Since
this is pure-Python with stdlib only, there's no install-time cost to
gate against. If a future contrib component does need heavy deps (e.g.
a SHA-NI ctypes shim), that one gets gated behind `pyrxd[fast-mining]`.

### Test plan

Three layers:

#### 1. Unit tests — `tests/contrib/test_miner_parallel.py`

- **`test_known_good_vector`** — pin at least 3 fixed (preimage, target,
  nonce) triples; mine once with the verifier, hardcode the result.
- **`test_mined_nonce_passes_verifier`** — call `mine()` against an
  easy synthetic target; pass the result to the production
  `verify_sha256d_solution`; assert pass. **The silent-divergence guard.**
- **`test_exhaustion_returns_protocol_signal`** — pin a target no nonce
  in `[0, 256)` satisfies; assert CLI exits 2 + writes
  `{"exhausted": true}` to stdout.
- **`test_workers_split_nonce_space`** — set `--workers 4`, verify
  each worker walks its stride correctly.
- **`test_spawn_start_method`** — assert `mp.get_start_method() ==
  "spawn"` after `mine()` runs.
- **`test_cli_round_trip`** — invoke `python -m pyrxd.contrib.miner`
  as a subprocess with a known-good request; assert the response
  parses and matches.

#### 2. Cross-validation test — `tests/contrib/test_miner_vs_verifier.py`

Property-style test:
- Generates 8 deterministic synthetic preimages.
- For each, sets a target loose enough that the parallel miner finds a
  hit in under 1 second.
- Mines via `pyrxd.contrib.miner.parallel.mine()`.
- Verifies the returned nonce via the **production**
  `verify_sha256d_solution`.

The **load-bearing test** — guarantees no divergence between miner and
verifier.

#### 3. End-to-end test — gated, opt-in

A `@pytest.mark.live_mainnet`-gated test that re-mines the PXD proof
vector (preimage from `c9fdcd34…e530`) and asserts the mined nonce
matches the one in the live tx. Strongest possible cross-check.

Captured-from-mainnet data lives in
`tests/contrib/fixtures/pxd_mint_preimage.json`.

### Docs plan

1. **`docs/concepts/parallel-mining.md`** — canonical reference.
   - Why pure-Python (silent-divergence avoidance).
   - The JSON protocol.
   - When to use vs `glyph-miner`.
   - Cross-platform notes.
   - Measured performance (cite PXD deploy numbers).
2. **`src/pyrxd/contrib/miner/README.md`** — one-pager: install, run,
   protocol spec, exit codes. Ships in the wheel.
3. **Cross-references** — `mine_solution_external` docstring points to
   the new module; `examples/dmint_claim_demo.py` adds
   `EXTERNAL_MINER="python -m pyrxd.contrib.miner"` recommendation;
   CHANGELOG 0.5.1 entry.

### Release sequence

**0.5.0** (current): ship as-is. No miner.

**0.5.1** (target ≤ 2 weeks after 0.5.0): add `pyrxd.contrib.miner`
package, `pyrxd-miner` console script, `{"exhausted": true}` protocol
extension, tests, docs. Patch release — no breaking API changes, no
public surface expansion.

**Do NOT** ship in 0.5.0 with an `_experimental_` prefix. Two reasons:
1. The "experimental" tag in a 0.5.0 release implies "may break in
   0.5.1," wrong message for a wire-format protocol.
2. Two weeks is the time to write the contract carefully, not the time
   to discover it's wrong.

### Future evolution

Headroom we leave in 0.5.1 for future variants:
1. `protocol: int` field (request) — additive future protocol changes.
2. Optional `algo` field — when/if BLAKE3 or K12 ships (V2).
3. Optional `start_nonce` / `end_nonce` fields — distributed mining.

We do NOT add #2 or #3 to the 0.5.1 contract. We add only the
`protocol` field and the `{"exhausted": true}` response.

## Acceptance Criteria

### Functional
- [ ] `python -m pyrxd.contrib.miner` accepts JSON request on stdin
      and writes JSON response on stdout per protocol.
- [ ] `pyrxd-miner` console script entry point works after install.
- [ ] `multiprocessing.set_start_method("spawn", force=True)` called
      before any worker spawn.
- [ ] Exhaustion writes `{"exhausted": true}` and exits 2.
- [ ] `mine_solution_external` recognises the exhaustion response and
      raises `MaxAttemptsError` immediately.
- [ ] Zero new public exports in `pyrxd.*` or `pyrxd.glyph.*`.

### Tests
- [ ] `tests/contrib/test_miner_parallel.py` — at least 6 tests.
- [ ] `tests/contrib/test_miner_vs_verifier.py` — 8 round-trip cases.
- [ ] `tests/contrib/fixtures/pxd_mint_preimage.json`.
- [ ] CI matrix: Linux + macOS. Windows skipped.
- [ ] No regressions in existing tests.

### Docs
- [ ] `docs/concepts/parallel-mining.md`.
- [ ] `src/pyrxd/contrib/miner/README.md` (ships in wheel).
- [ ] `mine_solution_external` docstring references new module.
- [ ] `examples/dmint_claim_demo.py` recommends bundled module.
- [ ] CHANGELOG 0.5.1 Added section.

### Protocol stability
- [ ] `docs/concepts/parallel-mining.md` declares request + response
      JSON shape as a wire contract — additive-only, versioned by
      `protocol` field.
- [ ] Unit tests pin each documented protocol field.

## Technical Considerations

### Architecture impacts
- New top-level subpackage `pyrxd.contrib.*` — "shipped but non-core."
- New console script `pyrxd-miner`.
- One additive protocol field, one additive response shape.
- No changes to `pyrxd.glyph.*` or the core dMint mint flow.

### Performance
Measured at deploy time (32-core i9-14900K): 28 Mh/s aggregate,
~900 Kh/s per core. Full V1 nonce space sweep ≤ 2.5 minutes. **31×
faster** than serial `mine_solution()`; speedup is parallelism, no
SIMD or assembly.

On a 4-core CI VM: ~20 minutes for a full V1 sweep — still acceptable.

### Security
- **No new attack surface.** Subprocess invocation is unchanged from
  0.5.0. Pointing it at the bundled miner is strictly safer than at an
  external binary (no `$PATH` resolution).
- **Worker isolation.** `spawn` start method, no inherited state.
- **Local re-verification is unchanged.** `mine_solution_external`
  still re-verifies every returned nonce via the production verifier.

### Cross-validation (the silent-divergence guard)
The bundled miner uses `hashlib.sha256` — the **same primitive** as
`verify_sha256d_solution`. The cross-validation test (test 2 above)
re-mines synthetic cases and runs the production verifier. If those
tests pass, the miner cannot embed a wrong nonce.

## Dependencies & Risks

- Python ≥ 3.10 — already minimum.
- `multiprocessing.set_start_method("spawn")` — stable since 3.4.

### Risks
- **`multiprocessing` overhead on tiny searches** — ~50-100ms startup
  per worker. Mitigation: `--workers 1` for tiny test cases.
- **Windows `spawn`-only quirk** — top-level `if __name__ == "__main__"`
  guard is required. Already present.
- **CI runtime impact** — ~30s for cross-validation. Acceptable.
- **Confusion vs `glyph-miner`** — docs explicitly state pure-Python is
  the default; `glyph-miner` is for V2-difficulty production mining
  with accepted divergence risk.

## Out of Scope

- A C miner / GPU miner — explicitly declined by user.
- SHA-NI ctypes shim — future PR, would get `pyrxd[fast-mining]`.
- Distributed mining — protocol headroom reserved, no implementation.
- Windows CI — stretch.
- Replacing `mine_solution()` core function — stays as slow-but-simple
  reference.
- Promoting `pyrxd.contrib.miner` to `pyrxd.*` public API — never.

## References

### Internal
- `/tmp/parallel_python_miner.py` — the source script (validated
  against PXD deploy 2026-05-11).
- `src/pyrxd/glyph/dmint.py:880` — `mine_solution_external`.
- `src/pyrxd/glyph/dmint.py:466` — `verify_sha256d_solution`.
- `docs/plans/2026-05-07-feat-dmint-v1-mint-and-reference-miner-plan.md`
  — M1 plan.
- `docs/plans/2026-05-11-first-real-v1-dmint-deploy.md` — PXD deploy.
- `examples/dmint_claim_demo.py:135` — `EXTERNAL_MINER` env var wiring.
- `tests/test_dmint_v1_mint.py:779` — `TestMineSolutionExternal` —
  template for new contrib tests.

### External
- the `glyph-miner` project — the
  fast-but-divergence-risk alternative.

### Files to be created
- `src/pyrxd/contrib/__init__.py`
- `src/pyrxd/contrib/miner/__init__.py`
- `src/pyrxd/contrib/miner/parallel.py`
- `src/pyrxd/contrib/miner/cli.py`
- `src/pyrxd/contrib/miner/protocol.py`
- `src/pyrxd/contrib/miner/README.md`
- `docs/concepts/parallel-mining.md`
- `tests/contrib/__init__.py`
- `tests/contrib/test_miner_parallel.py`
- `tests/contrib/test_miner_vs_verifier.py`
- `tests/contrib/fixtures/pxd_mint_preimage.json`

### Files to be modified
- `pyproject.toml` — `pyrxd-miner` console script + wheel includes.
- `src/pyrxd/glyph/dmint.py` — `mine_solution_external` recognises
  exhaustion response; docstring points to new module.
- `examples/dmint_claim_demo.py` — recommend bundled module.
- `CHANGELOG.md` — 0.5.1 Added section.
