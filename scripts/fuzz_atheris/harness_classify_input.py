"""Atheris harness for ``pyrxd.glyph._inspect_core._classify_input``.

This is the very first thing the inspect tool runs against a user paste.
It must classify (txid / contract / outpoint / script) or raise
``ValidationError`` — never crash with a deeper exception type.

The fuzzer feeds a UTF-8-decoded string, since that's what the CLI
boundary deals in. Bytes that fail to decode are skipped.

Run:
    python3 scripts/fuzz_atheris/harness_classify_input.py \\
        -atheris_runs=0 \\
        -max_total_time=3600 \\
        -artifact_prefix=logs/atheris-classify-
"""

from __future__ import annotations

import sys

import atheris

with atheris.instrument_imports(include=["pyrxd.glyph"]):
    from pyrxd.glyph._inspect_core import _classify_input
    from pyrxd.security.errors import ValidationError


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    s = fdp.ConsumeUnicodeNoSurrogates(512)
    try:
        _classify_input(s)
    except ValidationError:
        pass


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
