# Parallel mining and the external-miner protocol

pyrxd ships two ways to mine a dMint contract: a slow but correct
in-process reference miner (`mine_solution`), and a fast subprocess
miner via `mine_solution_external`. The subprocess path is the
production-ready option, and pyrxd 0.5.1 added a bundled implementation
at `pyrxd.contrib.miner` so callers don't have to provide their own.

## The two miners

### `mine_solution` — slow but correct

In-process, single-threaded. Calls `verify_sha256d_solution` per
attempt — same code path the on-chain covenant ultimately mirrors.
Useful for tests, dev, and "I want to mine overnight without external
tooling." Not viable for production mining.

How long a sweep takes depends on the machine, so pyrxd measures rather
than assumes: run

```bash
pyrxd glyph dmint-estimate --difficulty 1 --workers 1
```

to get *your* single-core rate (MEASURED) alongside the attempt
distribution (EXACT) and the resulting ETA (PROJECTED). See
[Estimating time-to-mint](#estimating-time-to-mint) below.

### `mine_solution_external` — fast via subprocess

Reads from a user-supplied miner binary (or the bundled
`pyrxd.contrib.miner`) via a JSON-over-stdio protocol. Locally
re-verifies every nonce the external miner returns, so a buggy or
malicious miner can't ship a wrong nonce into your transaction.

## The wire protocol (v1)

Pinned in pyrxd 0.5.1. Future protocol changes are **additive only**,
gated by the optional `protocol` field. The miner reads one JSON
object from stdin and writes one JSON object to stdout.

### Request (stdin)

| Field          | Type   | Required | Description                              |
|----------------|--------|----------|------------------------------------------|
| `preimage_hex` | string | yes      | 64-byte preimage as 128 hex chars        |
| `target_hex`   | string | yes      | u64 BE target as 16 hex chars (no `0x`)  |
| `nonce_width`  | int    | yes      | 4 (V1 contracts) or 8 (V2)               |
| `protocol`     | int    | no       | Always 1 currently; reject unknown       |

### Response on hit (stdout)

| Field        | Type   | Required | Description                              |
|--------------|--------|----------|------------------------------------------|
| `nonce_hex`  | string | yes      | `nonce_width * 2` hex chars              |
| `attempts`   | int    | optional | Best-effort metric (≤ 2^40)              |
| `elapsed_s`  | number | optional | Finite, ≥ 0 (NaN/Inf rejected)           |

### Response on exhaustion (stdout)

```json
{"exhausted": true}
```

Exit code 2. `mine_solution_external` recognises this and raises
`MaxAttemptsError` immediately. A miner that doesn't know this
convention can still surface exhaustion by sleeping past the parent's
`timeout_s` — pyrxd will SIGKILL it and raise `MaxAttemptsError` via
the timeout path. Both behaviours are valid.

### Progress frames (stderr, optional — added after 0.13.0)

While it searches, a miner MAY write zero or more progress lines to
**stderr** — never stdout, never mixed with the response above:

```json
{"progress": {"attempts": 4200000, "elapsed_s": 1.7}}
```

This needed no `protocol` version bump — it's still `protocol: 1` —
because it is purely additive on both sides:

* stdout keeps carrying exactly one line, unchanged. Every consumer
  that only ever reads stdout (every consumer before this addition)
  sees no difference.
* An old miner that has never heard of progress frames writes nothing
  extra to stderr. Silence is valid: no progress is shown, exactly as
  before.
* A new miner talking to an old parent that still discards stderr
  outright is equally safe — the frames land in a stream nobody reads.

Pass `mine_solution_external(..., progress=callback)` to opt in on the
consumer side. Progress is a **display hint, not a trust boundary**: a
malformed or adversarial line is silently dropped (it can never be
parsed into anything that looks like a solution — the parser can only
ever produce an `(attempts, elapsed_s)` pair, and stdout is the only
channel the result parser reads), and stays bounded in memory no
matter how much or how fast a miner writes to stderr — see
`pyrxd.glyph.dmint.miner._ExternalMinerProgressReader` for the reader
that replaced the old `stderr=subprocess.DEVNULL` and keeps its same
flat-memory guarantee.

The bundled `pyrxd.contrib.miner` emits these frames by default
(`--quiet` suppresses them, same as the exhaustion message) — it is
the reference implementation of this extension as well as of the base
protocol.

### Exit codes

| Code | Meaning                                                  |
|------|----------------------------------------------------------|
| 0    | Solution found                                           |
| 1    | Usage/protocol error (stderr has details)                |
| 2    | Nonce space exhausted (stdout: `{"exhausted": true}`)    |
| ≥128 | Killed by signal (parent timeout-fired SIGKILL)          |

## The bundled miner: `pyrxd.contrib.miner`

A 32-core-friendly parallel pure-Python miner ships as
`pyrxd.contrib.miner` in 0.5.1. Two ways to invoke:

**As a console script:**

```bash
echo '{"preimage_hex":"...","target_hex":"7fffffffffffffff","nonce_width":4}' \
    | pyrxd-miner
```

**As a module from `mine_solution_external`:**

```python
import sys
from pyrxd.glyph.dmint import build_pow_preimage, mine_solution_external

pow_result = build_pow_preimage(txid_le, contract_ref, input_script, output_script)

result = mine_solution_external(
    preimage=pow_result.preimage,
    target=state.target,
    miner_argv=[sys.executable, "-m", "pyrxd.contrib.miner"],
    nonce_width=4,
)
# result.nonce is verified against pyrxd's internal SHA256d check.
```

### Performance

Numbers below are from one dated run on one machine. They are a data
point, not a spec — benchmark your own with `pyrxd glyph dmint-estimate`.

Measured against the canonical pyrxd PXD mint at txid
`c9fdcd3488f3e396bec3ce0b766bb8070963e7e75bb513b8820b6663e469e530`
(2026-05-11), on a 32-core i9-14900K:

- ~28 Mh/s aggregate
- ~900 Kh/s per core
- Full V1 nonce-space sweep (2^32 attempts): ~2.5 minutes
- First mainnet mint after the M1 scriptSig fix: 15.3 seconds total
  including network round-trips (lucky early hit, but consistent with
  the ~40% hit-per-sweep distribution at difficulty=1)

On a 4-core CI VM, a full sweep takes ~20 minutes. Still acceptable
for "deploy + first mints" workloads.

Note what those two lines already show: 28 Mh/s across 32 cores is
~875 Kh/s per core, not 32 × the single-core figure. Cross-core scaling
is sublinear, and pyrxd does not measure it — which is why every
aggregate rate the estimator prints is labelled PROJECTED.

## Estimating time-to-mint

`pyrxd glyph dmint-estimate` benchmarks this machine and turns a target
into an expected grind. It keeps three kinds of number apart, and so
should you:

- **MEASURED** — the single-core SHA256d rate, benchmarked on the same
  hash chain the workers run.
- **EXACT** — the hit probability and attempt counts. Closed form.
- **PROJECTED** — every ETA, plus the `single-core × workers` aggregate
  rate they divide by.

```bash
pyrxd glyph dmint-estimate --difficulty 1            # offline
pyrxd glyph dmint-estimate --contract <TXID>:<VOUT>  # against a live contract
pyrxd glyph dmint-estimate --difficulty 1 --json     # separate top-level keys
```

The same numbers stream to stderr while `pyrxd glyph claim-dmint` is
mining (`--no-progress` to silence), reporting the *observed* aggregate
rate — measured, not projected — and the remaining-time distribution.

### The arithmetic, and one formula to avoid

A digest is a hit iff its top 96 bits, read big-endian, are below the
target (the verifier's "four zero bytes plus an 8-byte value under the
target" is exactly that condition, because the target is always under
`2**64`). SHA-256 is uniform, so:

```text
p           = target / 2**96
E[attempts] = 2**96 / target
```

**`MAX_SHA256D_TARGET / target` is the difficulty multiplier, not an
attempt count.** It is low by a factor of ~`2**33`: at difficulty 1 it
says one expected attempt, where the true mean is ~8.59 billion. The
cross-check is the V1 reroll behaviour pyrxd already relies on — at
difficulty 1 a full 2^32 nonce sweep hits with probability
`1 - (1-p)**(2**32) ≈ 39%`, which is why V1 rerolls its OP_RETURN.

Because the process is geometric it is **memoryless**: attempts already
spent do not shorten what remains. That is why pyrxd reports a mean plus
p50/p90/p99 quantiles and never a countdown, and why the V1 reroll loop
does not perturb the estimate — chopping an i.i.d. hash stream into
2^32-nonce pieces leaves the total-attempts distribution unchanged.

### Live progress from your own code

`mine()` takes an optional `progress` callback. It is called with
`(attempts, elapsed_s)` from inside the worker-cleanup context, so an
exception raised in it (the supported way to impose a deadline) still
reaps every worker:

```python
from pyrxd.contrib.miner.parallel import MineParams, mine
from pyrxd.glyph.dmint import estimate_attempts, live_stats

est = estimate_attempts(target)

def on_progress(attempts: int, elapsed_s: float) -> None:
    s = live_stats(attempts, elapsed_s, est)
    print(f"{s.observed_hashes_per_second:,.0f} h/s, mean {s.remaining_mean_s:,.0f}s remaining")

result = mine(MineParams(...), progress=on_progress)
```

`pyrxd.glyph.dmint.mine_solution` accepts the same `progress` hook, and
so does `mine_solution_external` (added after 0.13.0 — see "Progress
frames" above):

```python
from pyrxd.glyph.dmint import mine_solution_external

result = mine_solution_external(
    preimage=preimage,
    target=target,
    miner_argv=[sys.executable, "-m", "pyrxd.contrib.miner"],
    nonce_width=4,
    progress=lambda attempts, elapsed: ...,   # called if the miner emits frames
)
```

An external miner that never emits a progress frame (the common case
for a third-party binary that predates this addition) simply means the
callback is never called — the grind still runs to completion or
timeout exactly as it would with `progress=None`.

### Why pure-Python and not C / GPU

The load-bearing risk for any miner is **silent divergence** with the
verifier. A miner that's byte-equivalent in the easy cases but drifts
on an edge case ships nonces the on-chain covenant rejects — same bug
class as the M1 scriptSig incident (see
`docs/solutions/logic-errors/dmint-v1-mint-scriptsig-divergence.md`).

`hashlib.sha256` is a thin wrapper around OpenSSL's C implementation —
the same primitive that `verify_sha256d_solution` uses. The parallel
miner builds on that. **By construction**, the miner can't compute
different bytes than the verifier on the same input.

A hand-rolled C miner (or a GPU implementation) has to re-implement the
midstate precompute, the byte-order conventions, and the
fixed-preimage-length padding. Any one of those drifting silently
produces nonces the network rejects. Until someone is willing to ship
+ maintain that miner with byte-equality tests against pyrxd's
verifier, the pure-Python option is the safer default.

### Cross-platform

The bundled miner explicitly requests `multiprocessing`'s `spawn`
start method via `get_context("spawn")` — works identically on Linux,
macOS, and Windows. CI runs Linux + macOS; Windows is best-effort.

## Writing a custom miner

A custom miner is a free-standing executable that satisfies the
protocol above. To validate yours against pyrxd's verifier:

```python
import json
import subprocess
import sys
from pyrxd.glyph.dmint import verify_sha256d_solution

preimage = bytes.fromhex("ab" * 64)
target = 0x7FFFFFFFFFFFFFFF
request = json.dumps({
    "preimage_hex": preimage.hex(),
    "target_hex": f"{target:016x}",
    "nonce_width": 4,
})

result = subprocess.run(
    ["/path/to/your/miner"],
    input=request.encode(),
    capture_output=True,
    timeout=600,
)
response = json.loads(result.stdout)
nonce = bytes.fromhex(response["nonce_hex"])

# This MUST pass. If it fails, your miner drifted.
assert verify_sha256d_solution(preimage, nonce, target, nonce_width=4), (
    "miner returned a nonce that pyrxd's verifier rejects — drift bug"
)
```

The bundled `pyrxd.contrib.miner` passes this test by construction
(it uses `hashlib.sha256` directly). Custom miners must keep passing
it after every change.

## Supply-chain safety

`mine_solution_external` runs whatever binary the caller points at —
including malicious binaries that intercept `$PATH`. Mitigations:

- Pass an absolute path (`["/usr/local/bin/glyph-miner", ...]`) rather
  than a bare name to bypass `$PATH` resolution.
- For the bundled miner: `[sys.executable, "-m", "pyrxd.contrib.miner"]`
  resolves through the pyrxd install, not `$PATH`. Reasonably safe.
- Local nonce re-verification (in `mine_solution_external`) defends
  against a malicious miner returning a *wrong* nonce. It does NOT
  defend against a malicious miner exfiltrating the preimage (which
  encodes the contract ref + funding-script hash) over the network.
