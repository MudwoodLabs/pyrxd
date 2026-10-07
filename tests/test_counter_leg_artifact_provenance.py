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

* ``contracts/EthHtlc.sol`` is git blob ``8cb90847``: blob ``2f8fea4a`` from
  ``MudwoodLabs/pyrxd-eth-htlc@726446c4070d:contracts/EthHtlc.sol`` with one comment changed (it
  cited a ``docs/plans/`` path that exists only in that repo). With no metadata hash, the bytecode
  is identical to the unmodified file's.
* ``contracts/Erc20Htlc.sol`` is git blob ``a0c9010f``, copied unchanged from
  ``MudwoodLabs/pyrxd-eth-htlc@7b7d005e9148:contracts/src/Erc20Htlc.sol``.

Before this, both artifacts were built in that (private) repo: EthHtlc with the optimizer OFF
(2087 runtime bytes) and Erc20Htlc with it on, each with an IPFS metadata hash. #845 reproduced
both byte for byte; the build script's standard-JSON path, run with those old settings, reproduces
them byte for byte too. With the current settings EthHtlc is 1215 runtime bytes. Erc20Htlc's
runtime is the previous one with only the trailing CBOR metadata changed (no IPFS hash), and its
creation code differs because it embeds that runtime. A contract deployed from a previous artifact
is not one these runners accept.

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
            "contracts/EthHtlc.sol (git blob 8cb90847a044aa49c2a022f97125faa37b64d146), modified since it was "
            "copied from MudwoodLabs/pyrxd-eth-htlc@726446c4070d2e88e52598fe346f5445f63e116f:contracts/EthHtlc.sol "
            "(git blob 2f8fea4a53857965dc652a24d96349865070e835); changed: one comment only: the plan it cites is "
            "named by the repo it lives in, not by a path absent here"
        ),
        runtime_sha256="491310059e93d547d1be46d0770b10e8c0e037280c728e67eca6963d180ae61e",
        creation_sha256="14929d5c58980ad93d446c22b55c48d8c71d040500b807ed84c83601142c10ec",
        abi_sha256="5207bac62c8ed4a5e2b742f11a60ef133550117df3dd3308ac6d4846744ebfb3",
        layout_sha256="3f7299d350e67f62bb5cc70287c815de479d29d1957e88ce5285fa73443b3dac",
    ),
    "Erc20Htlc.json": _Pin(
        source=(
            "contracts/Erc20Htlc.sol (git blob a0c9010f0125e5ba9baba4970108a6b20b8405e9), copied unchanged from "
            "MudwoodLabs/pyrxd-eth-htlc@7b7d005e9148a8ffd88b1a2e36b0e36450e0e40a:contracts/src/Erc20Htlc.sol"
        ),
        runtime_sha256="b08478b77d9391aa74f59c6ae249cf9f30db7e09e09c77595f0c5fca0d17d001",
        creation_sha256="f653ede1cd15dd28671f1571233ef27d8479e32d3690b253780aa3f683176043",
        abi_sha256="12bba2979f6b2dfe8eb624945906129ef547e9c5fd682e9b5aef1eb723d3d2d1",
        layout_sha256="2ce9d082c959ccd4ca1d077ac09a9291140db3fdc9560b52b3fa26150a3dac1c",
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
