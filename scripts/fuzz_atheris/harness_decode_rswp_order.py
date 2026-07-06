"""Atheris harness for the RSWP order-advertisement decoder.

Targets the two attacker-facing entry points that walk a raw ``OP_RETURN``
byte string pulled straight off an ElectrumX/RXinDexer response
(``pyrxd.gravity.swap_order``, re-exported from ``pyrxd.swap.rswp``):

  - ``decode_rswp_order`` — the full advertisement decoder (magic, version,
    flags, token ids, outpoint, price_terms/signature tail-rule split).
    Contract: raise ``ValidationError`` on anything malformed, never a
    deeper exception type.
  - ``parse_price_terms_lenient`` — the ``price_terms`` blob reader
    (``MultiTxOutV1``, else Photonic's bare value/script fallback, else
    ``None``). Contract: NEVER raises — always returns a list or ``None``.

Complements the structured Hypothesis round-trip property in
``tests/test_rswp_wire.py::test_encode_decode_round_trip`` (which only
feeds the decoder bytes the encoder itself produced) and the arbitrary-
bytes robustness properties in ``tests/test_fuzz_parsers.py`` (Stage 1);
this harness is the coverage-guided Stage 2 complement over fully
adversarial, non-encoder-shaped byte strings.

Run:
    python3 scripts/fuzz_atheris/harness_decode_rswp_order.py \\
        -atheris_runs=0 -max_total_time=3600 \\
        -artifact_prefix=logs/atheris-decode_rswp_order-
"""

from __future__ import annotations

import sys

import atheris

with atheris.instrument_imports(include=["pyrxd.gravity", "pyrxd.swap"]):
    from pyrxd.gravity.swap_order import decode_rswp_order, parse_price_terms_lenient
    from pyrxd.security.errors import ValidationError


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    choice = fdp.ConsumeIntInRange(0, 1)
    blob = fdp.ConsumeBytes(fdp.remaining_bytes())
    if choice == 0:
        try:
            decode_rswp_order(blob)
        except ValidationError:
            pass  # expected: decoder rejected a malformed/non-RSWP frame cleanly
    else:
        # No try/except: parse_price_terms_lenient's documented contract is
        # "never raises" (MultiTxOutV1, else bare value/script, else None).
        parse_price_terms_lenient(blob)


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
