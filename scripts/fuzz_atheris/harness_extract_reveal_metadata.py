"""Atheris harness for ``GlyphInspector.extract_reveal_metadata``.

The reveal-metadata extractor walks an attacker-controlled scriptSig
push-data stream looking for the ``gly`` marker followed by CBOR. The
contract is "never raises" — any exception escaping is a bug because
the caller (``find_reveal_metadata`` and the inspect tool) does not
catch them at the call site.

Run:
    python3 scripts/fuzz_atheris/harness_extract_reveal_metadata.py \\
        -atheris_runs=0 \\
        -max_total_time=3600 \\
        -artifact_prefix=logs/atheris-reveal-
"""

from __future__ import annotations

import sys

import atheris

with atheris.instrument_imports(include=["pyrxd.glyph"]):
    from pyrxd.glyph.inspector import GlyphInspector


_inspector = GlyphInspector()


def TestOneInput(data: bytes) -> None:
    # No try/except: the contract says this never raises. Atheris will
    # report any uncaught exception as a finding.
    _inspector.extract_reveal_metadata(data)


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
