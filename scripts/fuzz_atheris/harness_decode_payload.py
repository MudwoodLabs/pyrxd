"""Atheris coverage-guided fuzz harness for ``pyrxd.glyph.payload.decode_payload``.

Run:
    python3 scripts/fuzz_atheris/harness_decode_payload.py \\
        -atheris_runs=0 \\
        -max_total_time=3600 \\
        -artifact_prefix=logs/atheris-decode_payload-

Atheris instruments pyrxd.glyph.* on import and uses libFuzzer's coverage
feedback to guide input mutation toward unexplored code paths. Anything
the harness raises that isn't ``ValidationError`` will be reported as a
finding with a reproducer file dropped at ``artifact_prefix``.

This is independent of and complements ``tests/test_fuzz_parsers.py``:
Hypothesis is random + shrinking, atheris is coverage-guided.
"""

from __future__ import annotations

import sys

import atheris

# Instrument pyrxd's parser modules. Keep the surface narrow so we don't
# pay instrumentation cost on stdlib / cbor2 / etc.
with atheris.instrument_imports(include=["pyrxd.glyph"]):
    from pyrxd.glyph.payload import decode_payload
    from pyrxd.security.errors import ValidationError


def TestOneInput(data: bytes) -> None:
    try:
        decode_payload(data)
    except ValidationError:
        pass  # expected: parser converted a malformed input cleanly


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
