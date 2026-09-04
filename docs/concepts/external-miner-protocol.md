# External miner protocol: JSON-over-stdio subprocess contract

**Why this page exists:** pyrxd ships a pure-Python reference miner
([`mine_solution`](../../src/pyrxd/glyph/dmint/miner.py)) so the library is
self-contained and the verifier path is the same as the mining path —
no silent divergence between "what the miner accepts" and "what
on-chain validation enforces." That correctness comes at a cost: a
V1 mint needs ~8.59 billion SHA256d attempts on average even at
difficulty 1 (`2**96 / target` — see
[Estimating time-to-mint](parallel-mining.md#estimating-time-to-mint)),
and CPython's `hashlib` gets through them one core at a time. What that
is in wall clock depends on the machine; measure it with `pyrxd glyph
dmint-estimate` rather than assuming a rate. Anyone wanting to mine V1 dMint contracts in
production wants a faster miner — a parallel Python worker pool, a C
binary, a WebGPU shader. The shim that bridges pyrxd to those is
[`mine_solution_external`](../../src/pyrxd/glyph/dmint/miner.py): it spawns
a caller-supplied binary, hands it the search problem over JSON, and
**re-verifies the returned nonce locally** before letting it touch a
transaction. This page documents that wire protocol so you can wire
in your own miner.

---

## How callers invoke it

Two entry points:

1. **Direct API.** Pass an `argv` list to
   [`mine_solution_external`](../../src/pyrxd/glyph/dmint/miner.py):

   ```python
   from pyrxd.glyph.dmint import mine_solution_external, build_pow_preimage

   result = build_pow_preimage(txid_le, contract_ref, in_script, out_script)
   mined = mine_solution_external(
       preimage=result.preimage,
       target=target,
       miner_argv=["/usr/local/bin/glyph-miner", "--stdin"],
       nonce_width=4,        # 4 for V1, 8 for V2
       timeout_s=600.0,
   )
   nonce = mined.nonce
   ```

2. **Env-var wiring in the demo.** `examples/dmint_claim_demo.py`
   reads two environment variables:

   - `EXTERNAL_MINER` — argv string for the miner binary (parsed
     with `shlex.split`). When set, the demo's internal `_mine`
     helper calls `mine_solution_external` instead of the pure-Python
     `mine_solution`. When unset, the demo falls back to the slow
     reference miner.
   - `EXTERNAL_MINER_TIMEOUT_S` — hard timeout in seconds (default
     `600.0`, defined as `EXTERNAL_MINER_TIMEOUT_S` at
     [`src/pyrxd/glyph/dmint/miner.py`](../../src/pyrxd/glyph/dmint/miner.py)).
     On timeout the subprocess is killed and `MaxAttemptsError` is
     raised.

   Typical demo invocation:

   ```bash
   EXTERNAL_MINER=/usr/local/bin/glyph-miner \
   EXTERNAL_MINER_TIMEOUT_S=180 \
   MINER_WIF=... CONTRACT_TXID=... CONTRACT_VOUT=... \
       python examples/dmint_claim_demo.py
   ```

---

## The wire protocol

One request, one response, both single-shot. pyrxd spawns the binary
with `subprocess.run`, writes a single JSON object to its stdin, then
closes stdin and waits for the process to exit. The miner reads its
input, searches for a nonce, writes one JSON object to stdout, and
exits.

### Request — stdin (one JSON object, then EOF)

| Field          | Type   | Required | Meaning                                            |
|----------------|--------|----------|----------------------------------------------------|
| `preimage_hex` | string | yes      | 128 hex chars = the 64-byte SHA256d preimage       |
| `target_hex`   | string | yes      | 16 hex chars (no `0x`) = the u64 target            |
| `nonce_width`  | int    | yes      | `4` for V1 contracts, `8` for V2                   |

The exact request shape lives in
[`mine_solution_external`](../../src/pyrxd/glyph/dmint/miner.py):

```python
request = json.dumps({
    "preimage_hex": preimage.hex(),
    "target_hex":   f"{target:016x}",
    "nonce_width":  nonce_width,
})
```

### Response — stdout (one JSON object)

| Field        | Type           | Required | Notes                                             |
|--------------|----------------|----------|---------------------------------------------------|
| `nonce_hex`  | string         | **yes**  | `nonce_width * 2` hex chars                       |
| `attempts`   | int            | optional | Best-effort metric; pyrxd caps at `2**40`         |
| `elapsed_s`  | int / float    | optional | Must be finite and non-negative; NaN/Inf rejected |

pyrxd then checks:

- stdout decodes as UTF-8.
- stdout is no larger than **4096 bytes** (a miner that floods stdout
  with megabytes is treated as malformed).
- stdout parses as a JSON object.
- `nonce_hex` is present, a string, valid hex, and exactly
  `nonce_width` bytes long.

If any of those fail, pyrxd raises `ValidationError`. See
[the stdout-decoding block of `mine_solution_external`](../../src/pyrxd/glyph/dmint/miner.py)
for the exact decoding path.

### Exit codes

| Code           | Meaning                                                                |
|----------------|------------------------------------------------------------------------|
| `0`            | Solution written to stdout. pyrxd parses + re-verifies.                |
| non-zero       | Treated as failure — pyrxd raises `ValidationError` with the code.     |
| (timeout)      | Subprocess killed, pyrxd raises `MaxAttemptsError`.                    |

There is no separate "exhausted the nonce space" signal in 0.5.0 — a
miner that runs out of nonces either has to keep spinning until the
parent timeout fires, or exit non-zero (which surfaces as
`ValidationError`, not `MaxAttemptsError`). An additive
`{"exhausted": true}` response shape is planned for 0.5.1 — see the
"Forward reference" section below.

### Stderr

**Not a result channel, under either mode.** With no `progress` callback —
the default — pyrxd attaches `stderr=subprocess.DEVNULL` so a misbehaving
miner cannot OOM the parent by flooding stderr (see the comment at
[the `subprocess.run` call in `mine_solution_external`](../../src/pyrxd/glyph/dmint/miner.py)).
If you need to see what your miner is doing on that path, run it standalone
with the same JSON request and watch stderr there.

Pass a `progress` callback and stderr is *read* instead of discarded: a
background thread (`_ExternalMinerProgressReader`) parses progress frames
off it while the miner runs. The bounded-memory guarantee is preserved by
construction — only the single most recently parsed frame is retained, and
one physical line is capped — so a flood still cannot grow the parent. Either
way, stdout remains the only channel a result may arrive on.

---

## What the preimage actually is

The 64 bytes pyrxd hands the miner are the **canonical V1 mint
preimage** built by
[`build_pow_preimage`](../../src/pyrxd/glyph/dmint/miner.py): a fixed-layout
concatenation of the contract's previous txid, the contract ref, the
miner's input script hash, and the miner's output script hash. The
exact byte layout is pinned in
[`docs/solutions/logic-errors/dmint-v1-mint-scriptsig-divergence.md`](../solutions/logic-errors/dmint-v1-mint-scriptsig-divergence.md)
against a real mainnet snk-token mint.

To the miner, none of that structure is visible — it sees an opaque
64-byte blob. The miner's job is to find a 4-byte (V1) or 8-byte (V2)
little-endian nonce such that:

```
full = sha256(sha256(preimage || nonce))
full[0:4] == b'\x00\x00\x00\x00'  AND  int.from_bytes(full[4:12], 'big') < target
```

This is the exact check `verify_sha256d_solution` performs at
[`verify_sha256d_solution`](../../src/pyrxd/glyph/dmint/miner.py),
which `mine_solution_external` calls against every returned nonce
before declaring success. A nonce that fails this check raises
`ValidationError` regardless of what the miner claims, which is the
load-bearing safety property: a buggy or malicious miner cannot
embed a bad nonce into a transaction.

---

## The contract pyrxd promises the miner

- **The preimage is canonical.** The 64 bytes you receive are already
  wired to a specific 4-output mint transaction (per
  [`docs/concepts/dmint-v1-deploy.md`](dmint-v1-deploy.md) for the
  contract layout this feeds into). You do not need to know what's
  inside it.
- **Refs, OP_RETURN bytes, funding scripts, scriptSig assembly — none
  of that is your problem.** That work happens in pyrxd before and
  after your subprocess runs.
- **The target is final.** The 16-hex-char `target_hex` field is the
  exact u64 target that `verify_sha256d_solution` will check the
  nonce against. Do not rescale it, swap byte order, or interpret it
  as anything other than a positive 64-bit integer.

## What the miner must NOT do

- **Do not mutate the preimage.** The preimage encodes which contract
  slot you're mining for. Any byte drift produces a nonce that fails
  local re-verification (so it gets rejected before broadcast) or, in
  the worst case, a nonce that locally verifies but reflects a
  preimage the contract script doesn't recognise on chain. Treat the
  preimage as opaque.
- **Do not parallel-mine multiple contracts in one process.** One
  request = one preimage = one contract. The
  `mine_solution_external` JSON protocol carries no slot field; if
  you want to mine N contracts at once, run N child processes (or
  use pyrxd's planned `pyrxd.contrib.miner` parallel module).
- **Do not write anything but the response JSON to stdout.** Log
  lines, progress meters, startup banners — everything that is not
  the single response object must go to stderr (which pyrxd
  discards). A miner that prefixes its JSON with a banner line will
  fail JSON parsing or exceed the 4 KB stdout budget.

---

## Minimum-viable miner

A 20-line Python reference (functional, just slow) showing the wire
contract:

```python
import hashlib, json, sys

req = json.load(sys.stdin)
preimage = bytes.fromhex(req["preimage_hex"])
target   = int(req["target_hex"], 16)
width    = req["nonce_width"]

attempts = 0
for n in range(1 << (8 * width)):
    attempts += 1
    nonce = n.to_bytes(width, "little")
    full = hashlib.sha256(hashlib.sha256(preimage + nonce).digest()).digest()
    if full[:4] == b"\x00\x00\x00\x00" and int.from_bytes(full[4:12], "big") < target:
        json.dump({"nonce_hex": nonce.hex(), "attempts": attempts}, sys.stdout)
        sys.exit(0)
sys.exit(2)  # exhausted — pyrxd will surface this as ValidationError in 0.5.0
```

Drop this in a file, point `EXTERNAL_MINER` at
`python /path/to/that/file.py`, and the demo will use it. It won't be
faster than the bundled reference miner — the point is that the JSON
contract is small enough to fit on one screen.

---

## Forward reference: `pyrxd.contrib.miner`

A **stdlib-only parallel reference miner is planned for 0.5.1** and
will ship inside the wheel as `pyrxd.contrib.miner`, invokable as
`python -m pyrxd.contrib.miner` (or the `pyrxd-miner` console
script). It will be the same `hashlib.sha256` primitive as the
verifier — same source of truth, no silent-divergence risk — driven
by a `multiprocessing` worker pool. Measured throughput on a 32-core
i9-14900K during the project's first mainnet mint was ~28 Mh/s
aggregate, sweeping the full V1 nonce space in ≤ 2.5 minutes. The
full design lives at
[`docs/plans/2026-05-11-ship-parallel-miner-plan.md`](../plans/2026-05-11-ship-parallel-miner-plan.md).

**`pyrxd.contrib.miner` does not ship in 0.5.0.** Until 0.5.1 lands,
point `EXTERNAL_MINER` at your own miner binary (the canonical
example being the standalone `glyph-miner` C binary).

The 0.5.1 protocol freeze is **additive**: it adds an optional
`protocol: 1` field on the request and a `{"exhausted": true}`
response shape on the exit-code-2 path. Miners that follow the 0.5.0
contract documented above will continue to work without change.

Those throughput figures are one dated machine, not a spec. Benchmark
yours with `pyrxd glyph dmint-estimate`.

## Optional progress frames

This section previously said the protocol had none. It does: a miner MAY
write progress lines to **stderr** while it searches, one JSON object per
line —

```json
{"progress": {"attempts": 4200000, "elapsed_s": 1.7}}
```

— and pyrxd forwards each valid frame to the `progress` callback of
`mine_solution_external`. `pyrxd glyph claim-dmint` passes one, so an
external `--miner-cmd` that emits frames drives the same live hash-rate
and ETA display the in-process miners do. The wire format is specified in
[Parallel mining](parallel-mining.md).

**Emitting them is optional, and silence is valid.** A miner that has
never heard of progress frames writes nothing extra to stderr and works
exactly as before — the CLI says as much and points at
`pyrxd glyph dmint-estimate` for up-front numbers. Parsing is
best-effort and deliberately outside the trust boundary:
`_parse_external_progress_frame` returns `None` for anything that is not
exactly that shape with in-range values, never raises, and structurally
cannot return anything nonce-shaped. A malformed or adversarial stderr
line cannot abort an otherwise-successful grind, and it never reaches the
result-verification path.

stdout remains the sole result channel: the request → response contract
above is unchanged.

---

## Footguns the library guards against

1. **A buggy miner returning a nonce that doesn't satisfy the
   target.** Local re-verification calls the same
   `verify_sha256d_solution` the validator uses; a wrong nonce
   raises `ValidationError` rather than getting embedded in a tx the
   network would reject.
2. **A miner of wrong width.** A 4-byte miner answering an 8-byte
   request (or vice versa) is caught by an explicit length check
   before verification — `ValidationError` with both widths in the
   message.
3. **A miner flooding stdout.** Capped at 4096 bytes
   (`_EXTERNAL_MINER_MAX_STDOUT_BYTES`); the
   `subprocess.PIPE` buffer would otherwise fill, blocking the
   miner, and silently producing a timeout instead of a usable
   error.
4. **A miner flooding stderr.** Routed to `/dev/null` when no
   `progress` callback is given, so gigabyte-per-second stderr cannot
   OOM the parent. With a callback the stream is read instead, under a
   4096-byte-per-line cap and retaining only the most recent frame — the
   same flat-memory bound by a different route.
5. **NaN / Inf / negative `elapsed_s`.** `json.loads` accepts those
   constants by default; pyrxd checks `math.isfinite` and discards
   any miner-supplied metric that fails. Same for `attempts > 2**40`,
   to avoid log-aggregator overflow downstream.
6. **`$PATH` hijacking.** pyrxd does **not** pin or verify the miner
   binary. `miner_argv[0]` is resolved by the OS at exec time; a
   malicious binary earlier in `$PATH` can intercept calls. The local
   re-verification defends against a wrong nonce, but it cannot
   detect a miner that exfiltrates the preimage out-of-band over the
   network. Mitigations: invoke with an absolute path, verify
   checksums against the upstream release, run in a controlled
   environment. See the supply-chain warning in the
   [`mine_solution_external` docstring](../../src/pyrxd/glyph/dmint/miner.py)
   for the full discussion.
