---
title: Counter-leg contract artifacts are pinned by digest, not by branch name
status: accepted
date: 2026-09-30
category: design-decisions
related_files:
  - tests/fixtures/EthHtlc.json (vendored artifact, _source now a 40-char sha)
  - tests/fixtures/Erc20Htlc.json (same)
  - tests/test_counter_leg_artifact_provenance.py (the digest pin)
  - src/pyrxd/eth_wallet/htlc_leg.py (load_artifact, _runtime_code_matches, verify_funded)
---

## TL;DR

pyrxd deploys `EthHtlc.sol` and `Erc20Htlc.sol` but does not build them. It vendors
the compiled artifacts, and until now those artifacts named their origin by BRANCH,
which is not a pin: a branch moves, and nothing here could tell whether the bytecode
being deployed came from the source it claimed.

They are now pinned by **digest**, against a manifest the producing repo generates
and re-verifies in its own CI.

## What was wrong

`tests/test_erc20_tokens.py` said it plainly:

> "The artifact is compiled in a DIFFERENT REPO (`MudwoodLabs/pyrxd-eth-htlc`), so
> nothing in this one would notice it drifting."

Measured 2026-09-30, it already had. `EthHtlc.json` claimed
`_source: eth-htlc-from-pyrxd-spike:contracts/EthHtlc.sol` and
`_compiler: forge/solc 0.8.24`, while that branch's own artifact was built by
py-solc-x and had different bytecode — 2512 against 4174 hex chars.

**Nothing was broken.** The ABI substance was identical, so no interface had drifted
and every test passed. What was absent was any way to demonstrate the correspondence
at all — and a claim nobody can check is the kind that is wrong for a long time
before anyone notices.

## What changed

- Both `_source` fields now read `MudwoodLabs/pyrxd-eth-htlc@<40-char sha>:contracts/artifacts/<C>.json`.
  This is the fix the 2026-09-16 pin sweep proposed for this exact finding.
- `tests/test_counter_leg_artifact_provenance.py` pins `sha256(runtime_bytecode)` for
  both contracts as **constants in the test**. A digest stored inside the artifact it
  describes proves nothing, because it travels with any substitution; held in the test,
  swapping the fixture fails a test.
- The producing repo grew `contracts/artifacts.manifest.json` plus a CI job that
  re-exports and compares on every push, so the upstream side of the correspondence
  is checked too.

## What this deliberately does NOT claim

The digest proves the artifact is the one recorded at that commit. It does **not**
prove the source at that commit is correct, and it does not extend
`_runtime_code_matches`, which still masks every committed-zero byte — a superset of
the immutable slots. The artifacts now carry `immutableReferences`, which is what the
slot-accurate compare named in that method's docstring requires; adopting it is still
a follow-up.

## Adopting a new upstream build

Update `UPSTREAM_COMMIT` and `EXPECTED_RUNTIME_SHA256` **together, in one commit**,
having read what changed between the two. The test failing is the intended
consequence of a fixture swap, not an obstacle to route around.

## Note on this adoption

The build adopted here is smaller than what it replaced — 1256 bytes of runtime code
against 2087 for `EthHtlc`, with an identical ABI — because the upstream Foundry
project enables the optimizer and whatever produced the previous artifact did not.
The full suite was run before and after the swap: **177 passed both times** across
every fixture-dependent test, so the change is a bytecode substitution with no
behavioural difference observed.
