"""A missing curve must withhold the verdict, not fail the decode.

`verify_attestation` imported `recover_public_key` from `pyrxd.keys`, which imports
`coincurve` at module top. The browser inspect page runs pyrxd under Pyodide and
installs only `micropip` and `pycryptodome`, so that import RAISES there — and it
raised straight out of the function. A HashMark output therefore did not classify
AT ALL in the browser: the per-output `try` in `_inspect_core` caught it and the row
became `type=error`.

A second path did the same thing and was mine: the `--network` plumbing reached for
`network.registry`, and importing `pyrxd.network` pulls in
`electrumx -> script.type -> keys -> coincurve`. In a module whose own docstring
calls itself a network-free core. The genesis map moved to `constants.py`, the
dependency-free bottom layer, with `registry` re-exporting it so there is still one
definition.

THE SPEC ALREADY SAID WHAT SHOULD HAPPEN. §6: "Decoding and attestation are
SEPARATE steps with separate outcomes. Decoding needs only these bytes; verifying a
v2 signature additionally needs secp256k1 … which a decoder in a dependency-free
library will not have. A record that decodes is well-formed, not yet believed."

So the outcome is `UNVERIFIABLE`: the digest, label and signer still reach the
reader and only the verdict is withheld, with the reason. Reporting
`INVALID_SIGNATURE` would be far worse — it would tell a reader a genuine mark's
claim does not hold, on the strength of a missing dependency.
"""

from __future__ import annotations

import importlib.abc
import sys

import pytest


class _BlockCoincurve(importlib.abc.MetaPathFinder):
    """Reproduce the browser: secp256k1 simply is not there."""

    def find_spec(self, name, path=None, target=None):
        if name == "coincurve" or name.startswith("coincurve."):
            raise ModuleNotFoundError("No module named 'coincurve'")
        return None


@pytest.fixture
def without_coincurve():
    blocker = _BlockCoincurve()
    sys.meta_path.insert(0, blocker)
    # Drop anything already imported that would satisfy the import from cache.
    saved = {n: m for n, m in sys.modules.items() if n == "pyrxd.keys" or n.startswith("coincurve")}
    for n in saved:
        del sys.modules[n]
    try:
        yield
    finally:
        sys.meta_path.remove(blocker)
        sys.modules.update(saved)


def _v2_script(label: bytes = b"contract.pdf") -> str:
    def push(b: bytes) -> bytes:
        return bytes([len(b)]) + b if len(b) <= 75 else b"\x4c" + bytes([len(b)]) + b

    return (
        b"\x6a"
        + push(b"HASHMARK")
        + push(bytes([2, 1]))
        + push(bytes(range(32)))
        + push(bytes(20))
        + push(bytes([31]) + bytes(64))
        + push(label)
    ).hex()


class TestTheRecordStillDecodes:
    def test_it_classifies_as_a_hashmark_not_an_error(self, without_coincurve) -> None:
        from pyrxd.glyph._inspect_core import _inspect_script

        assert _inspect_script(_v2_script())["type"] == "op_return-hashmark-v2"

    def test_the_digest_and_label_still_reach_the_reader(self, without_coincurve) -> None:
        """The half that needs no curve at all, and the half a reader most wants."""
        from pyrxd.glyph._inspect_core import _inspect_script

        hm = _inspect_script(_v2_script())["hashmark"]
        assert hm["digest"] == bytes(range(32)).hex()
        assert hm["label"] == "contract.pdf"

    def test_the_verdict_is_WITHHELD_not_negative(self, without_coincurve) -> None:
        """`invalid_signature` would say a genuine mark's claim does not hold, on the
        strength of a missing dependency. That is the wrong answer, not a cautious one."""
        from pyrxd.glyph._inspect_core import _inspect_script

        att = _inspect_script(_v2_script())["hashmark"]["attestation"]
        assert att["outcome"] == "unverifiable"
        assert "secp256k1" in att["detail"]


class TestTheNormalPathIsUnchanged:
    """With the curve present, nothing about the verdict changes."""

    def test_a_real_mainnet_record_still_verifies(self) -> None:
        from pyrxd.script.hashmark import AttestationOutcome, decode_hashmark, verify_attestation
        from tests.test_hashmark_mainnet_vectors import _V2_SIGNED

        assert verify_attestation(decode_hashmark(_V2_SIGNED)).outcome is AttestationOutcome.VALID

    def test_an_unsigned_v2_still_reports_invalid(self) -> None:
        from pyrxd.glyph._inspect_core import _inspect_script

        att = _inspect_script(_v2_script())["hashmark"]["attestation"]
        assert att["outcome"] == "invalid_signature", "with the curve present this is decidable"


class TestTheWithheldVerdictReachesAHuman:
    def test_the_CLI_says_NOT_CHECKED(self) -> None:
        """Falling through silently would leave a v2 record showing a signer and no
        word about its signature — which reads as "fine" far more than "unchecked"."""
        from pyrxd.cli.glyph_inspect import _op_return_payload_lines

        text = "\n".join(
            _op_return_payload_lines(
                {
                    "hashmark": {
                        "outcome": "ok",
                        "version": 2,
                        "algorithm": "sha256",
                        "digest": "cd" * 32,
                        "signer_hash160": "ab" * 20,
                        "attestation": {"outcome": "unverifiable", "detail": "secp256k1 unavailable"},
                    }
                }
            )
        )
        assert "NOT CHECKED" in text
        assert "not a verdict" in text


class TestTheInspectCoreStaysNetworkFree:
    def test_it_does_not_import_the_network_package(self) -> None:
        """The regression that made this worse. `pyrxd.network` pulls in coincurve,
        so any reach for it from the offline core breaks the browser."""
        import inspect as _i

        from pyrxd.glyph import _inspect_core

        source = _i.getsource(_inspect_core)
        assert "from ..network" not in source, "the inspect core must stay network-free"

    def test_the_genesis_map_has_exactly_one_definition(self) -> None:
        from pyrxd.constants import GENESIS_BLOCK_HASHES
        from pyrxd.network.registry import GENESIS_BLOCK_HASHES as REEXPORTED

        assert GENESIS_BLOCK_HASHES is REEXPORTED, "registry must re-export, not redefine"
