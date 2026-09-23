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
    """Reproduce the browser: secp256k1 simply is not there. ``attempts`` counts the imports
    that reached it — every one of them a full re-run of ``pyrxd/keys.py`` up to its import."""

    def __init__(self) -> None:
        self.attempts = 0

    def find_spec(self, name, path=None, target=None):
        if name == "coincurve" or name.startswith("coincurve."):
            self.attempts += 1
            raise ModuleNotFoundError("No module named 'coincurve'")
        return None


@pytest.fixture
def without_coincurve(monkeypatch):
    # `verify_attestation` remembers a failed curve import (it is attempted once per process),
    # so the memory is cleared here and restored by monkeypatch afterwards: a failure
    # remembered from inside this fixture must not outlive it.
    import pyrxd.script.hashmark as hashmark

    monkeypatch.setattr(hashmark, "_secp256k1_import_failure", None)
    blocker = _BlockCoincurve()
    sys.meta_path.insert(0, blocker)
    # Drop anything already imported that would satisfy the import from cache.
    saved = {n: m for n, m in sys.modules.items() if n == "pyrxd.keys" or n.startswith("coincurve")}
    for n in saved:
        del sys.modules[n]
    try:
        yield blocker
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


def _v1_record():
    from pyrxd.script.hashmark import decode_hashmark

    push = lambda b: bytes([len(b)]) + b  # noqa: E731
    record = decode_hashmark(b"\x6a" + push(b"HASHMARK") + push(bytes([1, 1])) + push(bytes(range(32))))
    assert record.ok and record.version == 1, "the premise: a readable v1 record"
    return record


class TestAnswersThatNeedNoCurveDoNotAskForOne:
    """With no backend and no coincurve — the page when the JavaScript curve fails to load —
    the curve was looked up BEFORE the record's own answer. Every v1 record re-attempted the
    import (a re-run of ``pyrxd/keys.py`` each time: 500 records took 2.61 s, measured by the
    review under Pyodide in Node) and came back NOT CHECKED, when its answer is NO SIGNATURE."""

    def test_a_v1_record_says_no_signature_and_never_asks_for_the_curve(self, without_coincurve) -> None:
        from pyrxd.glyph._inspect_core import _inspect_script
        from pyrxd.script.hashmark import AttestationOutcome, verify_attestation

        assert verify_attestation(_v1_record()).outcome is AttestationOutcome.NOT_ATTESTED
        row = _inspect_script((b"\x6a\x08HASHMARK\x02\x01\x01\x20" + b"\x07" * 32).hex(), attest=True)
        assert row["hashmark"]["attestation"]["status"] == "NO SIGNATURE"
        assert without_coincurve.attempts == 0

    def test_an_undecodable_record_is_answered_without_the_curve(self, without_coincurve) -> None:
        from pyrxd.script.hashmark import AttestationOutcome, HashMarkOutcome, HashMarkRecord, verify_attestation

        result = verify_attestation(HashMarkRecord(HashMarkOutcome.INVALID))
        assert result.outcome is AttestationOutcome.INVALID_SIGNATURE and result.detail == "record did not decode"
        assert without_coincurve.attempts == 0

    def test_a_failed_curve_import_is_attempted_once(self, without_coincurve) -> None:
        from pyrxd.script.hashmark import AttestationOutcome, decode_hashmark, verify_attestation

        record = decode_hashmark(bytes.fromhex(_v2_script()))
        results = [verify_attestation(record) for _ in range(5)]
        assert all(r.outcome is AttestationOutcome.UNVERIFIABLE for r in results)
        assert all("secp256k1" in (r.detail or "") for r in results), "every answer still says why"
        assert without_coincurve.attempts == 1, f"the import was attempted {without_coincurve.attempts} times"

    def test_a_registered_backend_is_used_and_the_import_is_never_attempted(self, without_coincurve) -> None:
        """The page's normal state: a curve from JavaScript. Coincurve is not even looked for."""
        from pyrxd.script.hashmark import (
            AttestationOutcome,
            RecoveryUnavailable,
            decode_hashmark,
            set_recovery_backend,
            verify_attestation,
        )

        calls = []

        def backend(*args):
            calls.append(args)
            raise RecoveryUnavailable("this test's backend does no arithmetic")

        from tests.test_hashmark_mainnet_vectors import _V2_SIGNED  # r and s in range: it reaches the curve

        set_recovery_backend(backend)
        try:
            result = verify_attestation(decode_hashmark(_V2_SIGNED))
        finally:
            set_recovery_backend(None)
        assert len(calls) == 1 and result.outcome is AttestationOutcome.UNVERIFIABLE
        assert "this test's backend does no arithmetic" in result.detail
        assert without_coincurve.attempts == 0


class TestTheHonestCurvesStillAnswer:
    def test_coincurve_still_verifies_a_v2_record_without_a_backend(self) -> None:
        """The CLI's path: no backend registered, coincurve present."""
        from pyrxd.script.hashmark import AttestationOutcome, decode_hashmark, recovery_backend, verify_attestation
        from tests.test_hashmark_mainnet_vectors import _V2_SIGNED

        assert recovery_backend() is None
        assert verify_attestation(decode_hashmark(_V2_SIGNED)).outcome is AttestationOutcome.VALID

    def test_a_registered_backend_still_decides_a_v2_record(self) -> None:
        """A backend that really recovers — coincurve's own, routed through the registry — is the
        one that answers, and a real signature verifies through it."""
        from pyrxd.keys import recover_public_key
        from pyrxd.script.hashmark import AttestationOutcome, decode_hashmark, set_recovery_backend, verify_attestation
        from tests.test_hashmark_mainnet_vectors import _V2_SIGNED

        calls = []

        def backend(message_hash, r, s, rec_id, compressed):
            calls.append(1)
            return recover_public_key(r + s + bytes([rec_id]), message_hash, hasher=None).serialize(
                compressed=compressed
            )

        set_recovery_backend(backend)
        try:
            outcome = verify_attestation(decode_hashmark(_V2_SIGNED)).outcome
        finally:
            set_recovery_backend(None)
        assert outcome is AttestationOutcome.VALID and calls == [1]
