"""Atheris harness for the RSWP encoder <-> decoder round trip.

Structured fuzz (via ``atheris.FuzzedDataProvider``) of ``encode_rswp_order``
immediately followed by ``decode_rswp_order``: asserts the exact field-for-
field equality that ``tests/test_rswp_wire.py::test_encode_decode_round_trip``
checks with Hypothesis strategies, but driven by atheris's coverage feedback
(byte-level mutation toward PUSHDATA1 boundaries, the scriptnum sign-pad
boundary, offeredType 0/255, v2/v3 flag-bit edges, etc.) rather than random
sampling.

A mismatch here is a real interop bug: it would mean whatever pyrxd itself
encodes, pyrxd's own decoder — the canonical, Radiant-Core-following
implementation — cannot read back byte-for-byte.

Run:
    python3 scripts/fuzz_atheris/harness_rswp_round_trip.py \\
        -atheris_runs=0 -max_total_time=3600 \\
        -artifact_prefix=logs/atheris-rswp_round_trip-
"""

from __future__ import annotations

import sys

import atheris

with atheris.instrument_imports(include=["pyrxd.gravity", "pyrxd.swap", "pyrxd.glyph"]):
    from pyrxd.glyph.types import GlyphRef
    from pyrxd.gravity.swap_order import DemandedOutput, decode_rswp_order
    from pyrxd.security.types import Txid
    from pyrxd.swap.rswp import RXD_TOKEN_ID, encode_price_terms, encode_rswp_order, swap_token_id

# The node reads offeredUTXOIndex with a 4-byte CScriptNum — see
# encode_rswp_order's _MAX_ADVERTISABLE_VOUT (not re-exported, so pinned here
# too; a drift between the two would just make this harness under-fuzz, not
# false-fail, since encode_rswp_order re-checks the same bound).
_MAX_ADVERTISABLE_VOUT = 0x7FFFFFFF


def _consume_ref(fdp: atheris.FuzzedDataProvider) -> GlyphRef | None:
    if not fdp.ConsumeBool():
        return None
    txid_hex = fdp.ConsumeBytes(32).hex()
    if len(txid_hex) != 64:
        return None  # starved provider — not a case that can build a ref
    vout = fdp.ConsumeIntInRange(0, 0xFFFFFFFF)
    return GlyphRef(txid=Txid(txid_hex), vout=vout)


def _consume_outputs(fdp: atheris.FuzzedDataProvider) -> list[DemandedOutput]:
    n = fdp.ConsumeIntInRange(1, 5)
    outs = []
    for _ in range(n):
        value = fdp.ConsumeIntInRange(0, 0xFFFFFFFFFFFFFFFF)
        script = fdp.ConsumeBytes(fdp.ConsumeIntInRange(1, 200))
        if not script:
            script = b"\x51"  # keep the "non-empty script" invariant on a starved provider
        outs.append(DemandedOutput(value=value, script=script))
    return outs


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)

    offered_ref = _consume_ref(fdp)
    want_ref = _consume_ref(fdp)
    offered_type = fdp.ConsumeIntInRange(0, 255)
    offered_txid = fdp.ConsumeBytes(32).hex()
    if len(offered_txid) != 64:
        return  # starved provider — not a case that can build a valid frame
    offered_vout = fdp.ConsumeIntInRange(0, _MAX_ADVERTISABLE_VOUT)
    outputs = _consume_outputs(fdp)
    signature = fdp.ConsumeBytes(fdp.ConsumeIntInRange(1, 120))
    if not signature:
        signature = b"\x01"  # keep the "non-empty signature" invariant on a starved provider
    expiry_height = fdp.ConsumeIntInRange(1, 0xFFFFFFFF) if fdp.ConsumeBool() else None

    token_id = swap_token_id(offered_ref)
    want_token_id = None if want_ref is None else swap_token_id(want_ref)
    price_terms = encode_price_terms(outputs)

    script = encode_rswp_order(
        offered_type=offered_type,
        token_id=token_id,
        want_token_id=want_token_id,
        offered_txid=offered_txid,
        offered_vout=offered_vout,
        price_terms=price_terms,
        signature=signature,
        expiry_height=expiry_height,
    )
    order = decode_rswp_order(script)

    assert order.version == (3 if expiry_height is not None else 2)
    assert order.expiry_height == expiry_height
    assert order.offered_type == offered_type
    assert order.terms_type == 1
    # 32-byte ids travel byte-reversed on chain (display digest <-> pushed form).
    assert order.token_id == (token_id if token_id == RXD_TOKEN_ID else token_id[::-1])
    if want_token_id is None:
        assert order.want_token_id is None
    else:
        assert order.want_token_id == want_token_id[::-1]
    assert order.offered_txid == offered_txid
    assert order.offered_utxo_index == offered_vout
    assert order.price_terms == price_terms
    assert order.demanded_outputs == outputs
    assert order.signature == signature


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
