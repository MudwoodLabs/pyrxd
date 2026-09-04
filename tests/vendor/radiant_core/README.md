# Vendored Radiant Core consensus sources

Verbatim, unmodified copies of a handful of files from
[Radiant-Core/Radiant-Core](https://github.com/Radiant-Core/Radiant-Core), pinned at the tag and
commit recorded in `MANIFEST.json`. They are **test fixtures**, never imported or compiled — the
test suite parses them as text to derive consensus facts.

Distributed under the MIT license, as stated in the copyright header of each file.

## This pin is also the anchor for every Radiant-Core line citation in the repo

pyrxd's source comments, docs and tests cite Radiant Core by file and line
(`src/policy/policy.cpp:19-25`, `src/validation.cpp:271`, and so on). **Those line
numbers are at the tag recorded in `MANIFEST.json` — currently `v3.1.2`
(`45e0aa40d6ae022ba69439a58b706748b083a35b`)** — even for files not vendored here.
Cite that way in new comments: a bare line number with no version is unverifiable a
release later.

They were previously a mix of unanchored numbers and numbers at `main@afdf57b1`, which
put four citations several lines off the version this repo actually pins
(`init.cpp:1965`→`1995`, `feerate.cpp:51`→`95`, `miner.cpp:380`→`404`,
`validation.cpp:856`→`866`; also `validation.cpp:770`→`774` and `:778`→`779`). Every
underlying *fact* held at both revisions — only the line numbers had moved.

When `scripts/refresh_radiant_core_vendor.py` moves the pin, re-check the cited line
numbers along with the vendored bytes.

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
| the per-script stack-memory and opcode-cost budgets | `MAX_SCRIPT_STACK_MEMORY_USAGE` / `MAX_SCRIPT_OPCODE_COST` in `consensus.h` |
| the order refs are hashed into `hashOutputHashes` | `base_blob::Compare` and `operator<` in `uint256.h` |

A hand-maintained Python table of the same facts would reintroduce exactly the transcription step
that produced the bugs.

The last two entries were added because a citation is only evidence if the cited file is here.
`interpreter.cpp` enforces both script budgets and declares neither, so their *values* were
uncheckable; and `transaction_preimage.py` cited `src/primitives/transaction.h` for the ref sort
order, which holds the `std::set<uint288>` but does not define how it orders — that lives in
`uint256.h`, and getting it wrong made dMint contract-output signing fail about half the time.

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
  unnoticed. Its parameters come from `MANIFEST.json`, not from a list in the test — it was
  hand-listed as `["script.h", "script.cpp"]` while eight files were vendored, which is a check that
  passes vacuously on whatever was added after it was written. `test_every_vendored_file_is_digest_checked`
  and `test_the_refresh_script_covers_every_vendored_file` close the other two directions: a file on
  disk with no manifest entry, and a manifest entry the refresh script would never re-fetch.
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
byte-identical: `script.h` `3de78962…` and `script.cpp` `759ab524…` at both tags, and likewise the
two most recently added — `consensus.h` `c344ba58…` and `uint256.h` `e4cc8933…`, checked at `v3.1.1`
and `v3.1.2` when they were vendored.) If they do diverge, every parity assertion would be
describing a different script interpreter than the one the lane asks — bump the image, or pin the
source to the image's tag.

## Refreshing

```bash
python scripts/refresh_radiant_core_vendor.py --tag v3.2.0
.venv/bin/pytest tests/test_consensus_opcode_parity.py
```

If the refresh makes the parity test fail, that is the oracle doing its job: upstream changed a
consensus fact and pyrxd has not caught up yet. Fix `src/pyrxd/constants.py`, do not edit the
vendored files.
