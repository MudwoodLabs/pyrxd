"""Atheris harness for the SPV Merkle / PoW path (previously UNFUZZED).

These consume attacker-supplied SPV-proof components — a Merkle branch (list of
hex sibling hashes + a position), a header blob, and a txid string — and were
NOT covered by the prior fuzz sweep (which targeted the Glyph/dMint parsers and,
later, the tx byte-walkers).

Targets:
  - merkle.build_branch(merkle_be: list[str], pos: int)
  - merkle.compute_root(txid_be_hex: str, branch: bytes)
  - merkle.extract_merkle_root(header: bytes)
  - pow.verify_header_pow(header: bytes)

Contract: only ValidationError / SpvVerificationError may cross the boundary.
Anything else (ValueError from a bad bytes.fromhex, struct.error, IndexError,
OverflowError) is a leak — a finding.

Run:
    python3 scripts/fuzz_atheris/harness_spv_merkle_pow.py \\
        -atheris_runs=0 -max_total_time=3600 \\
        -artifact_prefix=logs/atheris-spv-merkle-pow-
"""

from __future__ import annotations

import sys

import atheris

with atheris.instrument_imports(include=["pyrxd.spv"]):
    from pyrxd.security.errors import SpvVerificationError, ValidationError
    from pyrxd.spv.merkle import build_branch, compute_root, extract_merkle_root
    from pyrxd.spv.pow import verify_header_pow

_OK = (ValidationError, SpvVerificationError)


def _guard(name: str, fn) -> None:
    try:
        fn()
    except _OK:
        pass
    except Exception as e:
        raise AssertionError(f"{name} leaked {type(e).__name__}: {e}") from e


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    choice = fdp.ConsumeIntInRange(0, 3)

    if choice == 0:
        n = fdp.ConsumeIntInRange(0, 40)
        merkle_be = [fdp.ConsumeUnicodeNoSurrogates(70) for _ in range(n)]
        pos = fdp.ConsumeInt(8)  # may be negative / huge
        _guard("build_branch", lambda: build_branch(merkle_be, pos))
    elif choice == 1:
        txid = fdp.ConsumeUnicodeNoSurrogates(80)
        branch = fdp.ConsumeBytes(fdp.remaining_bytes())
        _guard("compute_root", lambda: compute_root(txid, branch))
    elif choice == 2:
        header = fdp.ConsumeBytes(fdp.remaining_bytes())
        _guard("extract_merkle_root", lambda: extract_merkle_root(header))
    else:
        header = fdp.ConsumeBytes(fdp.remaining_bytes())
        _guard("verify_header_pow", lambda: verify_header_pow(header))


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
