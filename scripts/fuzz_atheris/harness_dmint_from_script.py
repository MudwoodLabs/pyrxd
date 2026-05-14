"""Atheris harness for ``pyrxd.glyph.dmint.DmintState.from_script``.

The dMint state-script parser is a hand-written variable-length opcode
walker: it dispatches on per-byte opcodes, reads pushed lengths from the
stream, and decodes 36-byte ``GlyphRef`` blobs from inside the script.
Coverage-guided mutation is well-suited to finding edge cases (truncated
PUSHDATA, mismatched STATESEPARATOR, malformed ref-bytes) the random
Hypothesis fuzzer can take a long time to reach.

Run:
    python3 scripts/fuzz_atheris/harness_dmint_from_script.py \\
        -atheris_runs=0 \\
        -max_total_time=3600 \\
        -artifact_prefix=logs/atheris-dmint-
"""

from __future__ import annotations

import sys

import atheris

with atheris.instrument_imports(include=["pyrxd.glyph"]):
    from pyrxd.glyph.dmint import DmintState
    from pyrxd.security.errors import ValidationError


def TestOneInput(data: bytes) -> None:
    try:
        DmintState.from_script(data)
    except ValidationError:
        pass


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
