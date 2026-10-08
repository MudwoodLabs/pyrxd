"""Digest pins for the counter-leg contract artifacts, and where they come from.

``tests/fixtures/EthHtlc.json`` and ``tests/fixtures/Erc20Htlc.json`` are what a maker checks a
taker-deployed contract against, byte for byte (``EthHtlcContractLeg.verify_funded`` and the
slot-exact runtime compare, which reads ``immutableReferences`` and ``immutable_names``), in this
repo's swap runners (``scripts/eth_swap_run.py``, ``scripts/swap_run_verify.py``,
``scripts/eth_swap_grief_run.py``) and tests. The wheel ships no ETH artifact: an application using
the leg injects its own (``htlc_leg.py``). A change to these bytes changes the contract those
runners accept, so two runs on different builds would disagree about which contract is genuine.

The digests are CONSTANTS IN THIS FILE, never stored in the artifact: a digest that travels inside
the file it describes moves with any substitution and so proves nothing.

Provenance. The Solidity source is in this repo, in ``contracts/``, and the artifacts are built
from it by ``scripts/build_counter_leg_artifacts.py``: the official static solc 0.8.24 binary,
pinned by sha256, through standard JSON with the optimizer on (200 runs), evmVersion cancun,
``metadata.bytecodeHash`` ``"none"`` and the repo-relative path as the source unit name. The
``counter-leg-artifacts`` workflow runs the script with ``--check`` on every pull request and every
push to main; it rebuilds both artifacts and fails on any difference, so the source, the artifacts
and these pins cannot drift apart unnoticed.

* ``contracts/EthHtlc.sol`` is git blob ``fb823256``: blob ``2f8fea4a`` from
  ``MudwoodLabs/pyrxd-eth-htlc@726446c4070d:contracts/EthHtlc.sol`` with one comment changed (it
  cited a ``docs/plans/`` path that exists only in that repo), then hardened before the external
  audit: the constructor refuses a zero claimant or refundee (``ZeroAddress``), and ``claim()``
  checks ``Expired`` before ``BadPreimage``.
* ``contracts/Erc20Htlc.sol`` is git blob ``c1451092``: blob ``a0c9010f`` from
  ``MudwoodLabs/pyrxd-eth-htlc@7b7d005e9148:contracts/src/Erc20Htlc.sol``, hardened at the same
  time: ``refund()`` reverts ``NothingToRefund`` without settling when the balance is zero, and the
  pragma is pinned to ``0.8.24``.

Before this, both artifacts were built in that (private) repo: EthHtlc with the optimizer OFF
(2087 runtime bytes) and Erc20Htlc with it on, each with an IPFS metadata hash. #845 reproduced
both byte for byte; the build script's standard-JSON path, run with those old settings, reproduces
them byte for byte too. #846 then made the optimized build with no metadata hash canonical, and
the hardening above changed the logic of both contracts, so neither artifact matches an earlier
one: EthHtlc is 1215 runtime / 1548 creation bytes, Erc20Htlc 1856 / 2298. A contract deployed
from a previous artifact is not one these runners accept.

Adopting a different build is a deliberate act: change the source or the settings, run the script,
and update the constants below and ``scripts/swap_run_verify.py``'s creation pin TOGETHER, in one
commit that says why. A failure here is the intended consequence of a fixture change, not an
obstacle to route around.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest

from pyrxd.eth_wallet.htlc_leg import _validate_artifact

_ROOT = Path(__file__).resolve().parent.parent
_FIXTURES = Path(__file__).parent / "fixtures"
_SCRIPTS = str(Path(__file__).resolve().parent.parent / "scripts")


@dataclass(frozen=True)
class _Pin:
    source: str
    runtime_sha256: str
    creation_sha256: str
    abi_sha256: str
    layout_sha256: str  # immutableReferences + immutable_names, canonical JSON


_PINS: dict[str, _Pin] = {
    "EthHtlc.json": _Pin(
        source=(
            "contracts/EthHtlc.sol (git blob fb823256afd89182632a108857cab61c0d752e27), modified since it was "
            "copied from MudwoodLabs/pyrxd-eth-htlc@726446c4070d2e88e52598fe346f5445f63e116f:contracts/EthHtlc.sol "
            "(git blob 2f8fea4a53857965dc652a24d96349865070e835); changed: a comment: the plan it cites is "
            "named by the repo it lives in, not by a path absent here; the constructor refuses a zero claimant "
            "or refundee (ZeroAddress, as Erc20Htlc does); claim() checks Expired before BadPreimage, the order "
            "Erc20Htlc uses"
        ),
        runtime_sha256="2efa52047f84b343ae25450440864f51f586faeebf81dd057f977b236ffe8470",
        creation_sha256="16021fe7842f83350cdcf25742347449708e620d9cab25efd9b0c720695de415",
        abi_sha256="0fcfeff0ad9edcf2fd8dac3298f07259ff42d81d13c8bcb9c11c2031a2c793af",
        layout_sha256="7600fe56336a6f01143ee22e8c73095c417f6cb2d8d49948b7d52e30c4c5e358",
    ),
    "Erc20Htlc.json": _Pin(
        source=(
            "contracts/Erc20Htlc.sol (git blob c14510925b1ec5df61ac9ab29bde8ea72c73a670), modified since it was "
            "copied from MudwoodLabs/pyrxd-eth-htlc@7b7d005e9148a8ffd88b1a2e36b0e36450e0e40a:contracts/src/Erc20Htlc.sol "
            "(git blob a0c9010f0125e5ba9baba4970108a6b20b8405e9); changed: refund() reverts NothingToRefund, without "
            "settling, when the balance is zero; pragma pinned to 0.8.24 (was ^0.8.20); comments on the "
            "claim-error order and the sweep guard"
        ),
        runtime_sha256="38e445bf4c4ef93cc2aa820b022d5a3c39e7deb0ae2e97b89699333b577e4fb8",
        creation_sha256="2902ba9f380bec3548362999939342e3299280dc25db6e113b4c2416d2e0797d",
        abi_sha256="a7a0bc6de7b222dc125bb463f338593b830f12141dc7c6f91dee4c6ba7a35730",
        layout_sha256="c417e8b57d53f20e9bc8ceaa95a4f509e2c8cc960d88b4b55241985f5e0e898e",
    ),
}

#: ``<in-repo path> (git blob <id>), <copied unchanged from | modified since it was copied from> <origin>``.
_SOURCE_FORMAT = re.compile(
    r"^(contracts/\S+\.sol) \(git blob ([0-9a-f]{40})\), "
    r"(?:copied unchanged from|modified since it was copied from) MudwoodLabs/pyrxd-eth-htlc@[0-9a-f]{40}:\S+\.sol"
)


def _load(name: str) -> dict:
    return json.loads((_FIXTURES / name).read_text())


def _code_sha256(hex_code: str) -> str:
    return hashlib.sha256(bytes.fromhex(hex_code.removeprefix("0x"))).hexdigest()


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def test_every_vendored_contract_artifact_is_pinned() -> None:
    """The pinned set is DERIVED from the fixtures directory, both ways: a newly vendored contract
    artifact with no pin fails here, and so does a pin whose artifact has gone (a check that would
    otherwise stop running in silence)."""
    vendored = {p.name for p in _FIXTURES.glob("*.json") if "runtime_bytecode" in json.loads(p.read_text())}
    assert vendored, "found no contract artifacts at all; the derivation is broken, not the fixtures"
    assert vendored == set(_PINS)


@pytest.mark.parametrize("name", sorted(_PINS))
def test_runtime_bytecode_is_the_pinned_build(name: str) -> None:
    assert _code_sha256(_load(name)["runtime_bytecode"]) == _PINS[name].runtime_sha256


@pytest.mark.parametrize("name", sorted(_PINS))
def test_creation_bytecode_is_the_pinned_build(name: str) -> None:
    assert _code_sha256(_load(name)["bytecode"]) == _PINS[name].creation_sha256


@pytest.mark.parametrize("name", sorted(_PINS))
def test_abi_is_the_pinned_interface(name: str) -> None:
    assert _canonical_sha256(_load(name)["abi"]) == _PINS[name].abi_sha256


@pytest.mark.parametrize("name", sorted(_PINS))
def test_immutable_layout_is_present_and_pinned(name: str) -> None:
    """The slot-exact compare cannot run without ``immutableReferences`` and ``immutable_names``.
    Presence is checked by the leg's OWN constructor validation, then the layout is pinned: a wrong
    offset would mask the wrong 32 bytes, which the bytecode digests above cannot see."""
    art = _load(name)
    for key in ("immutableReferences", "immutable_names"):
        assert isinstance(art.get(key), dict), f"{name} lacks {key}"
        assert art[key], f"{name} has an empty {key}"
    _validate_artifact(art)
    layout = {"immutableReferences": art["immutableReferences"], "immutable_names": art["immutable_names"]}
    assert _canonical_sha256(layout) == _PINS[name].layout_sha256


@pytest.mark.parametrize("name", sorted(_PINS))
def test_source_field_names_the_in_repo_source_and_its_origin(name: str) -> None:
    """``_source`` is metadata nothing in pyrxd reads, but it is the claim a reader believes. Tie it
    to the pin so it cannot be edited to a different origin without editing this file too, and check
    the git blob it names against the file that is actually in ``contracts/`` (what
    ``git hash-object`` prints), so it cannot name a source that is no longer there."""
    source = _load(name)["_source"]
    match = _SOURCE_FORMAT.match(source)
    assert match, source
    assert source == _PINS[name].source
    path, blob = match.groups()
    data = (_ROOT / path).read_bytes()
    assert hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest() == blob, f"{path} is not git blob {blob}"


def test_the_verifier_creation_pin_is_the_vendored_ethhtlc() -> None:
    """``scripts/swap_run_verify.py`` hardcodes the EthHtlc creation digest so it can refuse a
    look-alike contract. That constant and the fixture are two copies of one claim; this ties both
    to the pin above, so neither can move alone."""
    if _SCRIPTS not in sys.path:
        sys.path.insert(0, _SCRIPTS)
    import swap_run_verify

    assert swap_run_verify._ETH_HTLC_CREATION_SHA256.hex() == _PINS["EthHtlc.json"].creation_sha256
