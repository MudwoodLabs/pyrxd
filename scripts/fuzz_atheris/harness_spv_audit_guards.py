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

import asyncio
import sys

import atheris

with atheris.instrument_imports(include=["pyrxd.spv", "pyrxd.gravity"]):
    from pyrxd.gravity.ref_authenticity import ResolvedRef, verify_ref_authenticity
    from pyrxd.security.errors import SpvVerificationError, ValidationError
    from pyrxd.spv.proof import _max_input_scriptsig_len

_OK = (ValidationError, SpvVerificationError)

# The gate is `async def` (the indexer RPC is async), so drive it on one
# long-lived loop — `asyncio.run` per exec would dominate the fuzz budget.
_LOOP = asyncio.new_event_loop()


class _FuzzIndexer:
    """Fuzzer-driven ``RefAuthenticityIndexer`` covering every fail-closed branch.

    Modes mirror what a hostile/broken indexer can do: raise, report an unknown
    token, return a malformed non-``ResolvedRef`` object (the un-awaited-coroutine
    fail-open guard), or return a reveal whose fields are attacker-chosen.
    """

    def __init__(self, fdp: atheris.FuzzedDataProvider) -> None:
        self._mode = fdp.ConsumeIntInRange(0, 3)
        # Echoing the requested ref back satisfies binding (a) so the fuzzer can
        # reach bindings (b)-(e); without it every input dies at the first gate.
        self._echo = fdp.ConsumeBool()
        self._genesis = fdp.ConsumeBytes(36)
        self._marker = fdp.ConsumeBool()
        self._payload = fdp.ConsumeBytes(32)
        self._confs = fdp.ConsumeIntInRange(-5, 100)

    async def resolve_ref(self, genesis_ref: bytes) -> ResolvedRef | None:
        if self._mode == 0:
            raise RuntimeError("indexer boom")
        if self._mode == 1:
            return None
        if self._mode == 2:
            return object()  # type: ignore[return-value]  # malformed adapter
        return ResolvedRef(
            genesis_outpoint=genesis_ref if self._echo else self._genesis,
            has_gly_marker=self._marker,
            payload_hash=self._payload,
            confirmations=self._confs,
        )


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
        min_confs = fdp.ConsumeIntInRange(-2, 10)
        want_payload = fdp.ConsumeBool()
        expected_payload = fdp.ConsumeBytes(32) if want_payload else None
        ref = fdp.ConsumeBytes(fdp.remaining_bytes())
        try:
            _LOOP.run_until_complete(
                verify_ref_authenticity(
                    idx,
                    ref,
                    asset_variant=variant,
                    min_confirmations=min_confs,
                    expected_payload_hash=expected_payload,
                )
            )
        except _OK:
            pass
        except Exception as e:
            raise AssertionError(f"verify_ref_authenticity leaked {type(e).__name__}: {e}") from e


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
