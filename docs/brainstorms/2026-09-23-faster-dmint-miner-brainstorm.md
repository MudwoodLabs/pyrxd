# Brainstorm: a faster proof-of-work miner for dMint

**Date:** 2026-09-23
**Status:** Decided and built (see "Decision").
**Topic:** The nightly integration job's dMint suites grind real proof of work against a
regtest node and keep running out of time. Make the grinding faster instead of splitting the
job.

---

## Why

The `nightly — dMint (proof-of-work)` job in `.github/workflows/integration.yml` has
`timeout-minutes: 300` and runs its suites with `DMINT_MINE_TIMEOUT_S: "3600"`.

Of the **42** scheduled runs of that workflow created 2026-08-12 to 2026-09-22, the dMint job
was **cancelled at the limit 31 times** (300.2 to 301.5 minutes), **failed 8 times**, and
**passed 3 times**, taking 205.4, 260.4 and 274.0 minutes. Source: the Actions API
(`actions/workflows/integration.yml/runs?event=schedule`, then each run's jobs), queried
2026-09-23. One failure log was read (2026-09-19): a V2 grind hit its 3600 s ceiling,
`1 failed, 7 passed in 13759.74s`. The other seven failure logs were not read.

The work per grind cannot go down. A hit needs the digest's first four bytes to be zero and
the next eight, big-endian, below the target, so at difficulty 1 (the covenant's minimum, target
`2**63 - 1`) the mean is `2**96 / (2**63 - 1)`, about `2**33` = 8.59e9 attempts
(`estimate_attempts`, EXACT). Only the attempts per second can change.

No run before this one recorded the runner's hash rate: the suites ran with `-q` and no `-s`,
so the `[grind]` lines that print it were captured and never shown for a passing test.

## Measured baselines (this machine)

Machine: Intel Core i9-14900K, 24 cores / 32 threads, SHA extensions present
(`grep -o sha_ni /proc/cpuinfo` → `sha_ni`), CPython 3.12.3 with OpenSSL 3.0.13, a desktop
session running alongside (load average 2.3 before the first runs; the later three-run
comparison started at 6.2, most of it this work's own earlier runs decaying). Every rate below is a
MEASURED wall-clock rate over a sweep with target 1, which no digest meets (it would need 12 zero
bytes), so each run sweeps exactly the attempts it is given.

| grinder | runs (M hash/s) | how |
|---|---|---|
| `mine_solution`, sequential, in-process | 1.47, 1.44, 1.43 | `max_attempts=1_000_000`, caught `MaxAttemptsError` |
| `hashlib` SHA256d tight loop, 1 process | 1.89, 1.96, 1.95 | the parallel worker's inner loop, no IPC, 2M attempts |
| same, with `hashlib` `copy()` midstate | 2.15, 2.22, 2.21 | first block hashed once, `copy()` + `update(nonce)` per attempt |
| Python loop + nonce encode + concat, **no hashing** | 14.9, 15.3, 15.3 | the interpreter floor |
| bundled miner `mine()`, 1 worker | 1.66, 1.64, 1.60 | 3M nonces |
| bundled miner `mine()`, 8 workers | 11.4, 9.2 | 200M nonces |
| bundled miner `mine()`, 16 workers | 18.9, 18.2 | 200M nonces |
| bundled miner `mine()`, 24 workers | 24.6, 23.0 | 400M nonces |
| bundled miner `mine()`, 32 workers | 25.5, 24.6; later 25.3, 25.7, 25.4 | 400M, later 268M nonces |
| bundled miner start-up + teardown only | 0.056–0.076 s (1 worker), 0.154–0.158 s (32) | one nonce per worker |

An earlier measurement of 21.5–25.2 M hash/s (mean 24.1) over 19 grinds on this machine did not
record which miner or worker count produced it. The nightly suites' default is the bundled miner
with `os.cpu_count()` workers, 32 here, and the 32-worker rows above match it. That attribution
is INFERRED, not recorded.

## Where the time goes

At about 515 ns per attempt in one Python process:

- **About 65 ns is the interpreter** — the loop, `int.to_bytes`, the concatenation, the compare
  (the no-hashing row: 15 M/s).
- **About 450 ns is two `hashlib` round trips** — constructing two hash objects, two
  `digest()` calls, two `bytes` allocations. The hashing inside them is small: the same two
  SHA-256 compressions measured **78 ns** in C with the SHA extensions (below). So most of the
  per-attempt cost is object and call overhead, not SHA-256.
- **Midstate** (the first 64-byte block is the whole preimage and never changes) saves one of
  the three compressions. Through `hashlib.copy()` it bought **13%** (2.2 vs 1.95 M/s): the copy
  is itself an object allocation.
- **Process start-up** is 0.15 s per grind at 32 workers, against a mean grind of about 340 s at
  25 M/s. Not the problem.
- **Scaling**: 32 workers gave 25 M/s, about 15x one worker, on 24 physical cores of two kinds.

Conclusion: in Python the ceiling is the interpreter; the only large win is to leave it.

## Approaches

### A. Pure-Python: midstate plus fewer allocations

- **Expected speedup:** MEASURED ceiling +13% (the `copy()` midstate row). Even with free
  hashing the interpreter floor is 15 M/s per process, and real hashing cannot be free.
- **Verified by:** the existing suite; `hashlib` stays the primitive.
- **Cost / risk:** none; no new build step.
- **Runs:** everywhere.
- **Verdict:** rejected. The job already exceeds its limit on most nights, and 13% is not
  enough to change that.

### B. A small native grinder: C, midstate, SHA extensions, threads, standalone binary

- **Expected speedup:** MEASURED here, same session, three runs each: **313–318 M hash/s on 32
  threads vs 25.3–25.7** for the bundled miner (about 12x); **47.9–48.0 vs 5.4–6.8 at 4
  threads/workers** (about 8x); **12.6–12.7 vs 1.5–1.7 at 1** (about 8x). Without the SHA
  extensions its portable C path measured 3.2 M/s on one thread and 43.2 M/s on 32 (one run
  each), still ahead of Python.
- **Verified by:** differential tests against `hashlib` and `verify_sha256d_solution` (below),
  plus `mine_solution_external` re-checking every nonce it returns in production.
- **Cost:** one C file of 994 lines: 132 for the two SHA-256 compression functions, 132 for
  the per-attempt hash and the threaded sweep, 216 for the request reader, 75 for the
  self-test, the rest argument handling and output. No dependencies beyond libc and pthreads;
  built with `cc -O2 -pthread`. No new runtime dependency
  for `pip install pyrxd`: the source ships in the package, the binary is built where it runs.
- **Supply chain:** nothing new is downloaded. The SHA-256 code is written from FIPS 180-4 and
  the SHA-extension instruction set; its correctness rests on the tests, not on provenance.
- **Runs:** a developer's machine, the GitHub runner (built in the job), a user's
  `claim-dmint --miner-cmd`.

### C. A CPython extension module (C API or cffi)

- **Expected speedup:** the same kernel as B, minus a process start (about 0.15 s per grind,
  negligible).
- **Cost:** pyrxd's wheel is pure Python today. An extension means per-platform wheels
  (manylinux, macOS, Windows, each Python version) or a compiler at `pip install` time.
- **Verdict:** rejected. It breaks priority 2 (no new mandatory runtime dependency) or adds a
  wheel build matrix, for no speed B does not already have.

### D. A GPU miner

- **Expected speedup:** large on a GPU; not measured.
- **Verdict:** rejected for this goal. GitHub-hosted runners have no GPU, so it cannot touch the
  nightly job. A GPU miner that speaks the protocol would plug into `--miner-cmd` the same way
  B does; none was evaluated here.

### E. Reuse an audited SHA-256: OpenSSL's `SHA256_Transform`

- **Expected speedup:** MEASURED here, one thread pinned to one core, same attempt loop:
  OpenSSL 12.9–13.1 M attempts/s vs 12.7–13.0 for B's own SHA-extension code (the same, since
  OpenSSL also uses the SHA extensions), and with the SHA extensions masked off
  (`OPENSSL_ia32cap`) OpenSSL's assembly measured 4.8–4.9 M/s vs B's portable C at 3.0–3.4.
- **Cost:** needs OpenSSL headers to build and links libcrypto; `SHA256_Transform` is deprecated
  since OpenSSL 3.0.
- **Verdict:** not adopted. On CPUs with the SHA extensions it is no faster, and it would add a
  build dependency and a deprecated API. It stays the option to take if the portable path ever
  matters (a runner without the SHA extensions).

Not tried: interleaving two attempts per thread to hide the SHA instructions' latency. On this
CPU two hyperthreads per P-core already interleave, and it was not measured.

## Decision

**B**, against the stated priorities:

1. **Correct.** `mine_solution_external` re-verifies every returned nonce, so a wrong nonce
   from it cannot reach a transaction pyrxd builds. What the grinder could still do wrong is
   **miss** a solution, or report a range exhausted when it is not: that costs time, not
   safety. The tests are built around that.
2. **No new mandatory runtime dependency.** Source in the package, binary built where it runs,
   Python miner unchanged and still the default.
3. **Biggest measured speedup on the runner.** About 9.5x on the GitHub runner (28.9 vs
   2.9–3.1 M hash/s at 4 threads/workers; see "Measured after"), and about 8x at 4 threads
   here.
4. **Simple to build and review.** One file, one compiler command, no dependencies.

## Verification (as built)

`tests/contrib/test_native_grinder.py` builds the grinder with the shipped helper and checks it
against oracles that share none of its code:

- every digest equals `hashlib`'s, over 300-nonce ranges at the bottom, the top and a random
  point of each nonce space, both widths, both SHA-256 implementations;
- the set of hits over a 131,849-nonce range (two 65,536-nonce chunks plus 777) equals an
  exhaustive `hashlib` sweep, at 1, 3 and 8 threads, with a dense test-only target;
- real difficulty-1 solutions, found by the grinder and each accepted by
  `verify_sha256d_solution`, are returned at their exact nonce, and a range stopping one nonce
  short of each is reported exhausted;
- `target == value` is refused and `value + 1` accepted; a digest with four zero bytes and the
  sign bit set is refused even for a target above the ceiling;
- the request reader agrees with the Python one on 45 requests (15 accepted, 30 refused), and
  the 9 it deliberately refuses that Python accepts are pinned. A review pass found it had been
  more lenient than `json.loads` in fields nobody reads (`-`, `1.`, bytes outside ASCII); it
  was tightened so every difference is the grinder being stricter;
- `mine_solution_external` / `mine_solution_dispatch` accept its answers, receive its progress
  frames, map its exhaustion to `MaxAttemptsError`, and refuse BLAKE3/K12 before it starts;
- it exits when its parent is killed.

`tests/contrib/test_dmint_miner_selection.py` runs the nightly suites' own call through both the
fallback (bundled Python miner) and the grinder, against real solutions below nonce `2**22` that
are the only ones there for their preimages.

Planted defects, each run against the committed tests and then reverted by the inverse edit
on the same line (after each, `git status --porcelain` listed no changed tracked file):

| plant | result |
|---|---|
| nonce written big-endian | build refused: the self-test's midstate check failed |
| same, self-test verdict forced to "ok" | 26 failed |
| each 65,536-nonce chunk one nonce short | 17 failed |
| the requested range one nonce short | 17 failed |
| the value's two 32-bit words swapped | 9 failed (the dense-target sweeps do not see this; the real vectors do) |
| target above the ceiling not clamped | 2 failed |
| the last partial chunk dropped | 26 failed |
| request reader lets bytes outside ASCII through | 2 failed |
| request reader skips a number's fraction | 2 failed |

## Measured after

This machine: the B rows above (313–318 vs 25.3–25.7 M/s at 32).

GitHub runner, MEASURED on one `workflow_dispatch` of the integration workflow on this branch
(2026-09-23). The runner was `ubuntu-latest`: an Intel Xeon 6973P-C, 4 logical CPUs, with
the SHA extensions. The grinder's self-test picked them (`impl=shani`).

| | bundled Python miner, 4 workers | native grinder, 4 threads |
|---|---|---|
| `scripts/bench_dmint_miners.py`, two runs | 2.92, 3.14 M hash/s | 28.94, 28.93 M hash/s |
| every grind the suites ran (20 grinds) | — | 28.5–29.1 M hash/s |

The whole dMint job **passed**: 15 tests in 7,806.78 s, and 133.1 minutes from job start to
finish against the 300-minute limit. Its 20 grinds (18 at difficulty 1, 2 at difficulty 4)
are 26 difficulty-1 grinds' worth of expected work. That is 26 × 2**33 / 28.9e6 ≈ 129 minutes
of grinding at the mean, so this run's draw was close to average.

What that implies for the nightly job, PROJECTED from the measured runner rate, the EXACT
per-grind attempt distribution, and a fixed 3.9 minutes for everything else (2.9 minutes of
setup measured in this run, plus about a minute of non-grinding test time, which is assumed):
a Monte Carlo of 200,000 nights gives a mean of 133 minutes, p50 128, p90 179, p99 236, and
about 0.05% of nights over 300. That assumes every night gets a runner like this one; runner
hardware is not pinned and was measured once. At the Python miner's measured 3.03 M hash/s,
the same model gives a mean of about 1,230 minutes, and none of 20,000 simulated nights
finished inside 300. Today's 15 tests do not fit the limit on the Python miner at that rate.

The same three suites also passed on this machine with the grinder: V1 in 40 s, V2 and the
premine suite in 482 s, each in a throwaway regtest container with a unique name that was
removed afterwards.

## Open

- A runner without the SHA extensions would get the portable path (measured here at 3.2 M/s a
  thread). The build step prints whether the CPU has them, so it would show in the log.
- ARM machines get the portable path; the ARMv8 SHA-2 instructions are not used.
