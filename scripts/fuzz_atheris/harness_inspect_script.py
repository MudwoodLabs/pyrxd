"""Atheris harness for ``pyrxd.glyph._inspect_core._inspect_script``.

This is the dispatch the inspect tool runs when a user pastes a hex-
encoded locking script. It tries P2PKH, OP_RETURN, NFT, FT, mutable-NFT,
commit-NFT, commit-FT, and dMint classifiers in order. The whole chain
must surface failures as ``ValidationError`` only.

Atheris's ``FuzzedDataProvider`` is used to construct hex strings rather
than feeding raw bytes — the function expects hex input, so feeding it
arbitrary bytes mostly exercises the front-door hex check. We build a
hex string from the fuzzer's bytes so coverage feedback flows into the
deeper classifiers.

Run:
    python3 scripts/fuzz_atheris/harness_inspect_script.py \\
        -atheris_runs=0 \\
        -max_total_time=3600 \\
        -artifact_prefix=logs/atheris-inspect_script-
"""

from __future__ import annotations

import sys

import atheris

with atheris.instrument_imports(include=["pyrxd.glyph"]):
    from pyrxd.glyph._inspect_core import _inspect_script
    from pyrxd.security.errors import ValidationError


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    # Use the fuzzer's bytes as the hex source — every byte becomes 2 hex
    # chars, which keeps the hex even-length by construction so the
    # classifier reaches the deeper branches rather than failing on the
    # length-parity check.
    raw = fdp.ConsumeBytes(1024)
    hex_in = raw.hex()
    if not (50 <= len(hex_in) <= 20_000):
        return  # outside the inspector's accepted length window
    try:
        _inspect_script(hex_in)
    except ValidationError:
        pass  # expected: inspector rejected malformed hex at the boundary


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
