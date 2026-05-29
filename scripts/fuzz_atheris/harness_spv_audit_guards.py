"""Atheris harness for the 2026-05-24 rigorous-audit guard helpers.

Targets the two NEW trust-boundary helpers added by the R1/R2 fixes:
  - ``spv.proof._max_input_scriptsig_len`` — walks attacker-supplied tx bytes
    to find the largest input scriptSig (R2 funding-tx guard).
  - ``gravity.ref_authenticity.verify_ref_authenticity`` — the fail-closed
    pre-payment REF-authenticity gate (R1).

Contract: each must ONLY raise ValidationError / SpvVerificationError on hostile
input — never leak IndexError / struct.error / OverflowError / etc. past its
trust boundary.

Run:
    python3 scripts/fuzz_atheris/harness_spv_audit_guards.py \\
        -atheris_runs=0 -max_total_time=3600 \\
        -artifact_prefix=logs/atheris-spv-audit-guards-
"""

from __future__ import annotations

import sys

import atheris

with atheris.instrument_imports(include=["pyrxd.spv", "pyrxd.gravity"]):
    from pyrxd.gravity.ref_authenticity import verify_ref_authenticity
    from pyrxd.security.errors import SpvVerificationError, ValidationError
    from pyrxd.spv.proof import _max_input_scriptsig_len

_OK = (ValidationError, SpvVerificationError)


class _FuzzIndexer:
    def __init__(self, fdp: atheris.FuzzedDataProvider) -> None:
        self._v = fdp.ConsumeBool()
        self._raise = fdp.ConsumeBool()

    def verify_ref(self, genesis_ref: bytes) -> bool:
        if self._raise:
            raise RuntimeError("indexer boom")
        return self._v


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    if fdp.ConsumeIntInRange(0, 1) == 0:
        raw = fdp.ConsumeBytes(fdp.remaining_bytes())
        try:
            _max_input_scriptsig_len(raw)
        except _OK:
            pass
        except Exception as e:
            raise AssertionError(f"_max_input_scriptsig_len leaked {type(e).__name__}: {e}") from e
    else:
        idx = _FuzzIndexer(fdp)
        variant = fdp.PickValueInList(["rxd", "ft", "nft", "bogus"])
        ref = fdp.ConsumeBytes(fdp.remaining_bytes())
        try:
            verify_ref_authenticity(idx, ref, asset_variant=variant)
        except _OK:
            pass
        except Exception as e:
            raise AssertionError(f"verify_ref_authenticity leaked {type(e).__name__}: {e}") from e


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
