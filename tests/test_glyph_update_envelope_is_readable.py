"""pyrxd could not read a glyph UPDATE, so a repointed name inspected as its mint-time target.

A mutable Glyph is changed by publishing a second ``gly`` envelope carrying only the mutated
fields — no ``p``, no ``name``, no ``type``. ``decode_payload`` refuses that shape (``CBOR
payload missing 'p' field``) and is right to: ``p`` is what identifies a glyph payload. But
nothing else read it either, so every update on the chain was invisible.

MEASURED, not hypothesised. ``custodian-gate-x7f3.rxd`` on Radiant mainnet:

===========  ==================  ==========================================
height       transaction         ``attrs.target``
===========  ==================  ==========================================
458585       ``f644794b…`` mint  ``1CPfirXZahPrTb93QouwBfKDoz1ykfcBb7``
458591       ``315b4630…`` upd   ``14XmXG3dSBWZUukGT3xzS9zxpiZ53vgx1i``
458601       ``3c7b43df…`` upd   ``14XmXG3dSBWZUukGT3xzS9zxpiZ53vgx1i``
===========  ==================  ==========================================

Three of the four transactions in that chain carry the ``gly`` marker. Before this change the
inspect path rendered exactly one of them — the mint — and the two that MOVED where the name
points rendered blank. A reader that cannot see updates does not report an error; it reports
"nothing changed", which is the more confident answer and the wrong one.

The fixture is those four transactions' real bytes, run through ``_classify_raw_tx`` — the same
function the CLI calls — rather than through hand-built scriptSigs, because the defect lived in
the gap between what the chain publishes and what the parser accepted.
"""

from __future__ import annotations

import json
import pathlib

import cbor2
import pytest

from pyrxd.glyph._inspect_core import _classify_raw_tx
from pyrxd.glyph.inspector import GlyphInspector
from pyrxd.glyph.payload import GLY_MARKER, decode_payload, decode_update_payload
from pyrxd.security.errors import ValidationError

_FIXTURE = pathlib.Path(__file__).parent / "fixtures" / "wave_update_chain_mainnet.json"
_CHAIN = json.loads(_FIXTURE.read_text())
_TXS = {t["txid"][:8]: t for t in _CHAIN["transactions"]}

MINT = "f644794b"
UPDATE_1 = "315b4630"
TRANSFER = "2cee4847"
UPDATE_2 = "3c7b43df"

MINT_TARGET = "1CPfirXZahPrTb93QouwBfKDoz1ykfcBb7"
MOVED_TARGET = "14XmXG3dSBWZUukGT3xzS9zxpiZ53vgx1i"


def _inspect(short: str) -> dict:
    tx = _TXS[short]
    return _classify_raw_tx(tx["txid"], bytes.fromhex(tx["raw"]))


def _push(blob: bytes) -> bytes:
    """Minimal push encoding, for building scriptSigs by hand in the unit tests below."""
    if len(blob) < 0x4C:
        return bytes([len(blob)]) + blob
    return b"\x4c" + bytes([len(blob)]) + blob


# ---------------------------------------------------------------------------
# 1. The real chain, through the production entry point
# ---------------------------------------------------------------------------


def test_the_fixture_is_the_chain_it_claims_to_be() -> None:
    """Non-vacuity: if the fixture stops carrying four transactions at three heights, the
    tests below are asserting over something other than the defect they were written for."""
    assert len(_CHAIN["transactions"]) == 4
    assert sorted({t["height"] for t in _CHAIN["transactions"]}) == [458585, 458591, 458601]
    assert set(_TXS) == {MINT, UPDATE_1, TRANSFER, UPDATE_2}


def test_the_mint_still_reads_as_a_full_payload() -> None:
    """Regression guard. The update reader must not have disturbed the reveal path."""
    res = _inspect(MINT)
    assert res["metadata"] is not None
    assert res["metadata"]["name"] == "custodian-gate-x7f3.rxd"
    assert res["glyph_envelopes"] == [], "a full payload belongs in `metadata`, not here"


@pytest.mark.parametrize("short", [UPDATE_1, UPDATE_2])
def test_an_update_transaction_reports_the_new_target(short: str) -> None:
    """THE DEFECT. Both of these rendered as nothing at all."""
    res = _inspect(short)
    envelopes = res["glyph_envelopes"]
    assert len(envelopes) == 1, f"expected one update envelope, got {envelopes}"
    env = envelopes[0]
    assert env["kind"] == "update"
    assert env["fields"]["attrs"]["target"] == MOVED_TARGET


def test_the_moved_target_differs_from_the_mint_target() -> None:
    """The fixture must be able to EXPRESS the defect. If the name had been repointed to the
    address it already had, every assertion above would hold against a reader that ignores
    updates entirely — which is exactly the reader being replaced."""
    assert MOVED_TARGET != MINT_TARGET
    assert _inspect(MINT)["metadata"]["name"] == "custodian-gate-x7f3.rxd"


def test_a_transfer_carrying_no_envelope_reports_none() -> None:
    """The honest negative, and the reason `unreadable` is a separate kind: this transaction
    really does carry no glyph envelope, and it must be distinguishable from one that does and
    cannot be parsed."""
    assert _inspect(TRANSFER)["glyph_envelopes"] == []


# ---------------------------------------------------------------------------
# 2. Unreadable is not absent
# ---------------------------------------------------------------------------


def test_a_marker_followed_by_garbage_is_UNREADABLE_not_absent() -> None:
    """The property this whole design exists for.

    `extract_reveal_metadata` returns None both for "no glyph" and "a glyph I cannot read".
    Those are opposite facts, and collapsing them is what let a repointed name read as
    unchanged.
    """
    scriptsig = _push(GLY_MARKER) + _push(b"\xff\xff\xff not cbor")
    env = GlyphInspector().classify_glyph_scriptsig(scriptsig)
    assert env is not None
    assert env.kind == "unreadable"
    assert env.is_readable is False
    assert "not a payload" in env.reason and "not an update" in env.reason, (
        "both refusals must be reported: 'missing p' alone reads as 'this was an update', "
        "and 'not a map' alone reads as 'this was a payload'"
    )


def test_a_scriptsig_with_no_marker_is_None() -> None:
    """Genuinely nothing here — the case `unreadable` must not be confused with."""
    assert GlyphInspector().classify_glyph_scriptsig(_push(b"\x01" * 32) + _push(b"\x02" * 33)) is None


def test_a_marker_as_the_last_push_is_unreadable() -> None:
    env = GlyphInspector().classify_glyph_scriptsig(_push(GLY_MARKER))
    assert env is not None and env.kind == "unreadable"


def test_an_envelope_after_non_push_opcodes_is_still_found() -> None:
    """A MUT unlock ends in real opcodes — measured, `OP_1 OP_1 OP_0 OP_0`. The strict
    pure-push walker reports None for such a script, and reading that None as "no glyph" is
    what hid every update: the envelope is in the pushes that WERE read."""
    body = _push(GLY_MARKER) + _push(cbor2.dumps({"attrs": {"target": "T"}}))
    env = GlyphInspector().classify_glyph_scriptsig(body + b"\x51\x51\x00\x00")
    assert env is not None and env.kind == "update"
    assert env.fields == {"attrs": {"target": "T"}}


def test_the_strict_push_walker_still_refuses_a_non_push_script() -> None:
    """`_scriptsig_pushes` keeps its old contract — mint parsing depends on it."""
    assert GlyphInspector._scriptsig_pushes(_push(b"ab") + b"\x51") is None
    assert GlyphInspector._scriptsig_pushes(_push(b"ab")) == [b"ab"]


# ---------------------------------------------------------------------------
# 3. decode_update_payload's own refusals
# ---------------------------------------------------------------------------


def test_it_refuses_a_full_payload() -> None:
    """`p` is what identifies a glyph payload. An update reader that accepted `p` would make
    the two shapes interchangeable, and then every `p`-less blob on chain decodes as a token."""
    with pytest.raises(ValidationError, match="full glyph payload"):
        decode_update_payload(cbor2.dumps({"p": [2, 5, 11], "attrs": {}}))


@pytest.mark.parametrize(
    ("label", "blob"),
    [
        ("not a map", cbor2.dumps([1, 2, 3])),
        ("an empty map", cbor2.dumps({})),
        ("a non-string key", cbor2.dumps({1: "x"})),
        ("not CBOR at all", b"\xff\xff\xff\xff"),
    ],
)
def test_it_refuses_malformed_updates(label: str, blob: bytes) -> None:
    with pytest.raises(ValidationError):
        decode_update_payload(blob)


def test_a_non_string_key_is_refused_rather_than_coerced() -> None:
    """`str(1)` and the string "1" would collide. A fold that merged these onto mint state
    would let a writer overwrite a field it never named."""
    with pytest.raises(ValidationError, match="non-string key"):
        decode_update_payload(cbor2.dumps({1: "x", "attrs": {}}))


def test_the_two_decoders_refuse_each_other_s_input() -> None:
    """Stated as a pair so neither can quietly widen to accept both."""
    full = cbor2.dumps({"p": [2], "name": "n"})
    partial = cbor2.dumps({"attrs": {"target": "T"}})
    assert decode_payload(full).name == "n"
    assert decode_update_payload(partial) == {"attrs": {"target": "T"}}
    with pytest.raises(ValidationError):
        decode_update_payload(full)
    with pytest.raises(ValidationError):
        decode_payload(partial)


# ---------------------------------------------------------------------------
# 4. Display safety — the fields are attacker-authored
# ---------------------------------------------------------------------------


def test_update_keys_and_values_are_sanitised_for_display() -> None:
    """An update's KEYS are chosen by the publisher too, and land in terminal output beside
    verified facts. Sanitising only values leaves the injection in the key.

    ASSERTED ON THE STRUCTURE, NOT ON ITS JSON. A first version of this checked
    ``"\x1b" not in json.dumps(shown)`` and **passed against the planted defect**: `json.dumps`
    escapes control characters and non-ASCII to ``\u001b`` / ``\u202e``, so the literal
    characters are never in its output whether or not anything was sanitised. The serialiser was
    doing the work the assertion claimed to be testing — and the terminal, which is where the
    injection actually lands, does no such escaping.
    """
    hostile_key = "attrs\x1b[2K"
    hostile_val = "\x1b[31mnot-your-address\u202e"
    scriptsig = _push(GLY_MARKER) + _push(cbor2.dumps({hostile_key: {"target\u202e": hostile_val}}))
    env = GlyphInspector().classify_glyph_scriptsig(scriptsig)
    assert env is not None and env.kind == "update"

    from pyrxd.glyph._inspect_core import _sanitize_update_fields

    shown = _sanitize_update_fields(env.fields or {})

    def _every_string(obj):
        if isinstance(obj, dict):
            for k, v in obj.items():
                yield k
                yield from _every_string(v)
        else:
            yield str(obj)

    strings = list(_every_string(shown))
    assert strings, "the walker found no strings — it is not reaching the sanitised output"
    for s in strings:
        assert "\x1b" not in s, f"an ANSI escape survived sanitisation: {s!r}"
        assert "\u202e" not in s, f"a bidi override survived sanitisation: {s!r}"
    # And the hostile KEY specifically — the half the first version could not see.
    assert hostile_key not in shown, "the raw hostile key was carried through unsanitised"
