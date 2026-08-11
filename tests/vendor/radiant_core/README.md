# Vendored Radiant Core consensus sources

Verbatim, unmodified copies of two files from
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

A hand-maintained Python table of the same facts would reintroduce exactly the transcription step
that produced the bugs.

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
  network, so it is **not** part of the offline test suite; run it on demand or from a scheduled
  job, where a network failure is a job failure rather than a spurious PR red.

## Refreshing

```bash
python scripts/refresh_radiant_core_vendor.py --tag v3.2.0
.venv/bin/pytest tests/test_consensus_opcode_parity.py
```

If the refresh makes the parity test fail, that is the oracle doing its job: upstream changed a
consensus fact and pyrxd has not caught up yet. Fix `src/pyrxd/constants.py`, do not edit the
vendored files.
