# Parallel mining and the external-miner protocol

pyrxd ships two ways to mine a dMint contract: a slow but correct
in-process reference miner (`mine_solution`), and a fast subprocess
miner via `mine_solution_external`. The subprocess path is the
production-ready option, and pyrxd 0.5.1 added a bundled implementation
at `pyrxd.contrib.miner` so callers don't have to provide their own.

## The two miners

### `mine_solution` — slow but correct

In-process, single-threaded. Calls `verify_sha256d_solution` per
attempt — same code path the on-chain covenant ultimately mirrors. At
~1 Mh/s on modern x86, a full V1 nonce-space sweep (2^32 attempts)
takes ~70 minutes. Useful for tests, dev, and "I want to mine overnight
without external tooling." Not viable for production mining.

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
