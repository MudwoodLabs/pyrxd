"""Digest pins for the vendored counter-leg contract artifacts, and where they came from.

``tests/fixtures/EthHtlc.json`` and ``tests/fixtures/Erc20Htlc.json`` are what a maker checks a
taker-deployed contract against, byte for byte (``EthHtlcContractLeg.verify_funded`` and the
slot-exact runtime compare, which reads ``immutableReferences`` and ``immutable_names``), in this
repo's swap runners (``scripts/eth_swap_run.py``, ``scripts/swap_run_verify.py``,
``scripts/eth_swap_grief_run.py``) and tests. The wheel ships no ETH artifact: an application using
the leg injects its own (``htlc_leg.py``). They are compiled in a DIFFERENT repo,
``MudwoodLabs/pyrxd-eth-htlc``, so nothing here would otherwise notice one being swapped for a
different build. A change to these bytes changes the contract those runners accept, so two runs
on different builds would disagree about which contract is genuine.

The digests are CONSTANTS IN THIS FILE, never stored in the artifact: a digest that travels inside
the file it describes moves with any substitution and so proves nothing.

Provenance, established 2026-10-07 by rebuilding each contract and comparing every byte. The
CBOR metadata hash was NOT excluded: both artifacts match exactly, metadata included.

* ``EthHtlc.json``: built from ``pyrxd-eth-htlc@726446c4070d:contracts/EthHtlc.sol`` (git blob
  ``2f8fea4a``; the identical blob is ``contracts/src/EthHtlc.sol`` at ``41a70d75``). Running
  ``forge build --root . --contracts . --use 0.8.24`` in ``contracts/`` with no ``foundry.toml``
  (optimizer off, evmVersion cancun, source unit ``EthHtlc.sol``; ``--root .`` matters in a git
  checkout, where forge otherwise takes the git root as the project root and the bytes differ) reproduces runtime, creation code, ABI and
  ``immutableReferences`` exactly. So does plain ``solc 0.8.24`` standard JSON with those settings.
  It is NOT the ``EthHtlc.artifact.json`` committed at 726446c, which is an optimized build (1256
  runtime bytes against 2087 here).
* ``Erc20Htlc.json``: built from ``pyrxd-eth-htlc@7b7d005e9148:contracts/src/Erc20Htlc.sol``
  (blob ``a0c9010f``, unchanged since it was introduced at ``cc0ec485``). ``forge build`` in
  ``contracts/`` under that commit's ``foundry.toml`` (optimizer on, 200 runs, evmVersion cancun,
  remapping ``forge-std/=lib/forge-std/src/``) reproduces runtime, creation code and ABI exactly,
  and ``immutableReferences`` OFFSETS exactly. The reference IDS (40792...) were not reproduced:
  they are AST node ids, numbered across the whole project including ``lib/forge-std``, which that
  commit gitignored rather than pinned. Ids are not bytecode, and ``immutable_names`` is
  re-derived from the bytecode by ``test_eth_htlc_immutable_names.py``.

Re-running the reproduction needs read access to ``pyrxd-eth-htlc``. The settings above are
recorded in each artifact's ``_compiler``.

Adopting a different build is a deliberate act: update the artifact, the constants below and
``scripts/swap_run_verify.py``'s creation pin TOGETHER, in one commit that says why. A failure
here is the intended consequence of a fixture change, not an obstacle to route around.
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
        source="MudwoodLabs/pyrxd-eth-htlc@726446c4070d2e88e52598fe346f5445f63e116f:contracts/EthHtlc.sol",
        runtime_sha256="767a4ba6b2d2dc8daef4522e57e3953ab6aa140727ecb544b1ceccbdfc141aec",
        creation_sha256="81270a8375c83f51f1bd1812f36a31ef7b9b14e2bca8aea3287561d34d64b5ff",
        abi_sha256="dc6b1913270b335e3b0bd685c3960d37a65dd2a7850ddcc6705120b69b77816d",
        layout_sha256="92ca0e1abdfd3af909193bdb633599715c29b881b01ab4bc4aaaf16f23f0d87f",
    ),
    "Erc20Htlc.json": _Pin(
        source="MudwoodLabs/pyrxd-eth-htlc@7b7d005e9148a8ffd88b1a2e36b0e36450e0e40a:contracts/src/Erc20Htlc.sol",
        runtime_sha256="6994075523ab50f6a4080d9da5698b0a9f2bc27856abaf7124789d80602a0cd3",
        creation_sha256="d8c105102c2a47bd82a510b0b2b34de0c624f821f83ee68a93f148d145e83dff",
        abi_sha256="194b516d5f31dd2e102ec77fe3e5ed0cb04d4e39517afb0a880fbaf509edbb04",
        layout_sha256="42a29b388c41b572f8b743c699d8e14420237a60b02716f6604d9e61d3fba6a6",
    ),
}

_SOURCE_FORMAT = re.compile(r"^MudwoodLabs/pyrxd-eth-htlc@[0-9a-f]{40}:\S+\.sol$")


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
def test_source_field_names_the_reproducing_commit(name: str) -> None:
    """``_source`` is metadata nothing in pyrxd reads, but it is the claim a reader believes. Tie it
    to the pin so it cannot be edited to a different origin without editing this file too."""
    source = _load(name)["_source"]
    assert _SOURCE_FORMAT.match(source), source
    assert source == _PINS[name].source


def test_the_verifier_creation_pin_is_the_vendored_ethhtlc() -> None:
    """``scripts/swap_run_verify.py`` hardcodes the EthHtlc creation digest so it can refuse a
    look-alike contract. That constant and the fixture are two copies of one claim; this ties both
    to the pin above, so neither can move alone."""
    if _SCRIPTS not in sys.path:
        sys.path.insert(0, _SCRIPTS)
    import swap_run_verify

    assert swap_run_verify._ETH_HTLC_CREATION_SHA256.hex() == _PINS["EthHtlc.json"].creation_sha256
