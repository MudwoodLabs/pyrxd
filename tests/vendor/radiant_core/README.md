# Vendored Radiant Core consensus sources

Verbatim, unmodified copies of a handful of files from
[Radiant-Core/Radiant-Core](https://github.com/Radiant-Core/Radiant-Core), pinned at the tag and
commit recorded in `MANIFEST.json`. They are **test fixtures**, never imported or compiled — the
test suite parses them as text to derive consensus facts.

Distributed under the MIT license, as stated in the copyright header of each file.

## Why these are here

pyrxd re-implements Radiant consensus rules in Python. Every such re-implementation drifts unless
something mechanically pins it to the C++. Three ref-walking bugs reached `main` because four
walkers each spelled the ref-operand rule by hand and two spelled it wrong; the rule was *also*
hand-typed a fifth time in the test that was supposed to catch this, so the test agreed with the
bug.

`tests/test_consensus_opcode_parity.py` therefore derives the ground truth by **parsing these
files**, not by trusting a Python transcription of them:

| Fact | Derived from |
|---|---|
| opcode name → byte value | `enum opcodetype` in `script.h` |
| `MAX_OPCODE` | `FIRST_UNDEFINED_OP_VALUE - 1` in `script.h` |
| which opcodes carry a 36-byte immediate operand | the `GetScriptOp` operand branch in `script.cpp` |
| which of those land in an output's push-ref set | the `GetPushRefs` `foundPushRefs.insert` calls in `script.cpp` |
| when a script walk must fail rather than clamp | the `return false` guards in `GetScriptOp`, `script.cpp` |
| BIP68 `SEQUENCE_LOCKTIME_*` values | `class CTxIn` in `primitives_transaction.h` |
| how CSV consumes them (disable bit, mask, min tx version) | `CheckSequence` in `interpreter.cpp` |
| `SCRIPT_VERIFY_*` bit values | the flag enum in `script_flags.h` |
| which flags are mandatory vs standard | `MANDATORY_/STANDARD_SCRIPT_VERIFY_FLAGS` in `policy.h` |
| which flags a **block** is connected under, and `fRequireStandard` | `GetNextBlockScriptFlags` in `validation.cpp` |
| DER signature size bounds and the flags gating strict-DER / low-S | `IsValidDERSignatureEncoding` and its callers in `sigencoding.cpp` |

A hand-maintained Python table of the same facts would reintroduce exactly the transcription step
that produced the bugs.

Local filenames match upstream basenames except `primitives_transaction.h`, which is
`src/primitives/transaction.h` renamed so it cannot be confused with a pyrxd module; `MANIFEST.json`
records every `upstream_path` verbatim.

## Vendored, not fetched at test time

Deliberate. The parity test must run offline, hermetically, and identically on every machine and in
CI:

- **Fetching at test time makes CI depend on github.com.** A network blip becomes a red build with
  no code change, and rate limits make it worse on busy days. CI cost and flake budget are both
  real constraints here.
- **A test that skips when offline is worse than no test**, because it reports green while checking
  nothing. Vendoring means there is no skip path — the oracle is always present.
- **Pinning makes drift a reviewable event.** Upstream changing an opcode should surface as a diff
  in a pull request that a human reads, not as a test that silently starts asserting something new.

The cost is that the pin can go stale. That is handled explicitly rather than ignored:

- `scripts/refresh_radiant_core_vendor.py` re-fetches from upstream, rewrites these files and the
  manifest, and reports what changed. Run it when a new Radiant Core release lands.
- `tests/test_consensus_opcode_parity.py::test_vendored_sources_match_manifest_digest` fails if the
  vendored bytes stop matching the recorded sha256, so a local edit or a botched refresh cannot go
  unnoticed.
- `scripts/refresh_radiant_core_vendor.py --check` exits non-zero when upstream has moved. It needs
  network, so it is **not** part of the offline test suite. Its scheduled owner is the
  **`vendor-freshness` job in `.github/workflows/integration.yml`**, which runs nightly and on
  `workflow_dispatch`; there, a network failure is a job failure rather than a spurious PR red.
  By hand: `task check-vendor`.

## What the digest proves, and what it does not

The sha256 in `MANIFEST.json` proves these bytes are **self-consistent** — that nobody hand-edited
the oracle and that a refresh landed intact. It is not an authenticity proof: it is computed from
whatever GitHub served, so it attests to "what we fetched" and not to "what Radiant Core's
maintainers signed". Upstream does not publish signed source digests to check against; the
mitigation that actually exists is that the files are committed, so a change to them is a reviewable
diff in a pull request rather than a silent fetch.

It also does not prove these sources describe the node the integration lane runs. `MANIFEST.json`
pins the tag the SOURCE came from; `pyrxd.devnet.DEFAULT_RADIANT_VERSION` pins the release the
regtest image's BINARY is built from, and the two are bumped on different schedules — today the
source is at `v3.1.2` and the image at `v3.1.1`. That gap is fine only while the two releases share
these files, so `--check` verifies exactly that and fails if they ever diverge. (They are currently
byte-identical: `script.h` `3de78962…` and `script.cpp` `759ab524…` at both tags.) If they do
diverge, every parity assertion would be describing a different script interpreter than the one the
lane asks — bump the image, or pin the source to the image's tag.

## Refreshing

```bash
python scripts/refresh_radiant_core_vendor.py --tag v3.2.0
.venv/bin/pytest tests/test_consensus_opcode_parity.py
```

If the refresh makes the parity test fail, that is the oracle doing its job: upstream changed a
consensus fact and pyrxd has not caught up yet. Fix `src/pyrxd/constants.py`, do not edit the
vendored files.
