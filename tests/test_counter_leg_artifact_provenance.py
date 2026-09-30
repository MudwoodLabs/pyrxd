"""The counter-leg contract artifacts are built in ANOTHER repo. Pin them here.

pyrxd deploys `EthHtlc.sol` and `Erc20Htlc.sol` but does not build them: it vendors
the compiled output into `tests/fixtures/`. `tests/test_erc20_tokens.py` already says
what that costs —

    "The artifact is compiled in a DIFFERENT REPO (MudwoodLabs/pyrxd-eth-htlc), so
     nothing in this one would notice it drifting."

It had already drifted, in a way nobody could evaluate. Before 2026-09-30 the
vendored `EthHtlc.json` claimed `_source: eth-htlc-from-pyrxd-spike:contracts/EthHtlc.sol`
and `_compiler: forge/solc 0.8.24`, while that branch's own artifact was built by
py-solc-x with different bytecode — 2512 vs 4174 hex chars. The ABI substance was
IDENTICAL, so nothing was broken; what was missing was any way to demonstrate that
the bytecode being deployed came from the source it named.

THE HASHES BELOW ARE THE DEMONSTRATION, and they are CONSTANTS here on purpose. A
digest stored inside the artifact it describes proves nothing — it travels with any
substitution. Pinning it in the test means swapping the fixture fails a test.

Upstream: MudwoodLabs/pyrxd-eth-htlc@41a70d75ebd8, whose
`contracts/artifacts.manifest.json` records these same values and whose CI re-exports
and compares on every push. To adopt a new upstream build, update the commit and the
digests together, in one commit, having read what changed.
"""

from __future__ import annotations

import hashlib
import json
import pathlib

import pytest

FIXTURES = pathlib.Path(__file__).parent / "fixtures"

UPSTREAM_COMMIT = "41a70d75ebd8ab75c5a68ebf5ed17ca46508fddc"

# sha256 of the RUNTIME code (`deployedBytecode`), which is what `verify_funded`
# compares against `eth_getCode`. Taken from the upstream manifest at the commit above.
EXPECTED_RUNTIME_SHA256 = {
    "EthHtlc": "dd201186f124a2718870ec2d32388963cea64fb7d4929fb98bc2681008de2d41",
    "Erc20Htlc": "6e4bb356f5a1a556b27296219c3e0022327990771ce5f850e9a58d2d5d6f82c4",
}

# What `EthHtlcContractLeg` calls. Erc20Htlc deliberately shares these signatures —
# `Erc20HtlcLeg` is a subclass, not a fork, and that only works while they match.
REQUIRED_FUNCTIONS = {
    ("claim", ("bytes32",)),
    ("refund", ()),
    ("hashlock", ()),
    ("claimant", ()),
    ("refundee", ()),
    ("timeout", ()),
}


def _artifact(name: str) -> dict:
    return json.loads((FIXTURES / f"{name}.json").read_text())


def _sig(entry: dict) -> tuple[str, tuple[str, ...]]:
    return (entry.get("name", ""), tuple(i["type"] for i in entry.get("inputs", [])))


@pytest.mark.parametrize("name", sorted(EXPECTED_RUNTIME_SHA256))
def test_vendored_runtime_code_matches_the_upstream_manifest(name: str) -> None:
    """THE pin. Fails if the fixture is replaced by a build we have not recorded."""
    art = _artifact(name)
    runtime = bytes.fromhex(art["runtime_bytecode"][2:])
    assert hashlib.sha256(runtime).hexdigest() == EXPECTED_RUNTIME_SHA256[name], (
        f"{name}.json is not the build recorded for "
        f"pyrxd-eth-htlc@{UPSTREAM_COMMIT[:12]}. If this is a deliberate upstream "
        f"adoption, update UPSTREAM_COMMIT and EXPECTED_RUNTIME_SHA256 together."
    )


@pytest.mark.parametrize("name", sorted(EXPECTED_RUNTIME_SHA256))
def test_vendored_artifact_carries_what_the_leg_requires(name: str) -> None:
    """The keys `_validate_artifact` enforces, checked here so a malformed vendored
    file fails in a test rather than at deploy time."""
    art = _artifact(name)
    for key in ("abi", "bytecode", "runtime_bytecode"):
        assert key in art, f"{name}.json is missing {key}"
    assert art["bytecode"].startswith("0x")
    assert art["runtime_bytecode"].startswith("0x")


@pytest.mark.parametrize("name", sorted(EXPECTED_RUNTIME_SHA256))
def test_vendored_abi_exposes_the_per_swap_interface(name: str) -> None:
    sigs = {_sig(e) for e in _artifact(name)["abi"] if e.get("type") == "function"}
    missing = REQUIRED_FUNCTIONS - sigs
    assert not missing, f"{name}.json ABI is missing {sorted(missing)}"


@pytest.mark.parametrize("name", sorted(EXPECTED_RUNTIME_SHA256))
def test_immutable_references_are_present(name: str) -> None:
    """`_runtime_code_matches` currently masks every committed-zero byte, a SUPERSET
    of the immutable slots. Its docstring names the slot-accurate compare as a
    follow-up that "requires the injected artifact to carry immutableReferences" —
    so this pins that the artifacts keep carrying them, which is what keeps that
    follow-up available."""
    imm = _artifact(name).get("immutableReferences")
    assert imm, f"{name}.json carries no immutableReferences"
    # EthHtlc has 4 immutables, Erc20Htlc adds token + amount.
    assert len(imm) == (4 if name == "EthHtlc" else 6), (
        f"{name}.json has {len(imm)} immutable slot groups; the contract's immutable "
        f"count changed, so verify_funded's read-back set may be stale"
    )


def test_the_two_artifacts_share_the_claim_refund_signatures() -> None:
    """`Erc20HtlcLeg` subclasses `EthHtlcContractLeg` and its module docstring says
    that "only works because Erc20Htlc.sol was deliberately given the same
    claim(bytes32) / refund() signatures". Pinned, because it is a cross-contract
    invariant that nothing else checks."""
    a = {_sig(e) for e in _artifact("EthHtlc")["abi"] if e.get("type") == "function"}
    b = {_sig(e) for e in _artifact("Erc20Htlc")["abi"] if e.get("type") == "function"}
    shared = {s for s in REQUIRED_FUNCTIONS}
    assert shared <= a and shared <= b, "the shared interface diverged"


def test_the_verifier_creation_pin_matches_the_vendored_artifact() -> None:
    """`swap_run_verify.py` carries its OWN hardcoded sha256 of the canonical EthHtlc
    creation bytecode, so the verifier can reject a look-alike contract that decodes
    honest constructor args yet pays the taker. That is a second copy of the same
    claim as the fixture, and two copies can disagree.

    They disagreed. Re-vendoring the artifact on 2026-09-30 invalidated the constant,
    and the only thing that noticed was `test_self_check_passes` — which failed with
    `assert 1 == 0` and a single `[FAIL]` line buried in ~40 lines of `[PASS]`. The
    guard worked; what was missing was anything tying the two values together.

    This ties them. Change the artifact without the constant and this fails
    immediately, naming both sides.
    """
    import re

    script = pathlib.Path(__file__).resolve().parent.parent / "scripts" / "swap_run_verify.py"
    m = re.search(r'_ETH_HTLC_CREATION_SHA256 = bytes\.fromhex\("([0-9a-f]{64})"\)', script.read_text())
    assert m, "could not find _ETH_HTLC_CREATION_SHA256 in swap_run_verify.py"
    pinned = m.group(1)

    creation = bytes.fromhex(_artifact("EthHtlc")["bytecode"][2:])
    actual = hashlib.sha256(creation).hexdigest()
    assert pinned == actual, (
        "swap_run_verify.py's _ETH_HTLC_CREATION_SHA256 does not match "
        f"tests/fixtures/EthHtlc.json:\n  pinned in script: {pinned}\n"
        f"  artifact says   : {actual}\n"
        "Both must be updated together when the artifact is re-vendored."
    )
