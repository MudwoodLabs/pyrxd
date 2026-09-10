"""#661 taught the classifier to read a glyph update, and stopped before anyone could see it.

`glyph_envelopes` was written into `_classify_raw_tx`'s result and read by NOTHING — three
references repo-wide, all of them the write. So `--output json` carried the update and the
DEFAULT terminal output, which is where people meet this tool, rendered the real mainnet
update `315b4630…` as::

    vout   0  type=unknown
    vout   1  type=mut
    vout   2  type=p2pkh

with no mention of the change and no sight of the new target. That is the same blindness the
PR's own subject line is about, one layer up: a production caller is necessary and not
sufficient, and the result has to reach a human.

The second half of this file covers `WaveAttrs`, which silently dropped `attrs.expires` —
measured, a real record round-tripped `[domain, expires, name, target, target_type]` back out
as `[domain, name, target, target_type]`. That is the field the merge rule for §7.6 form 2
turns on, so a fold built on this type would have lost it before the question was even asked.
"""

from __future__ import annotations

import json
import pathlib

import cbor2
import pytest

from pyrxd.cli.glyph_inspect import _render_txid_human
from pyrxd.glyph._inspect_core import _classify_raw_tx
from pyrxd.glyph.wave import WaveAttrs, build_wave_metadata
from pyrxd.security.errors import ValidationError

_FIXTURE = pathlib.Path(__file__).parent / "fixtures" / "wave_update_chain_mainnet.json"
_TXS = {t["txid"][:8]: t for t in json.loads(_FIXTURE.read_text())["transactions"]}

MINT, UPDATE_1, TRANSFER, UPDATE_2 = "f644794b", "315b4630", "2cee4847", "3c7b43df"
MOVED_TARGET = "14XmXG3dSBWZUukGT3xzS9zxpiZ53vgx1i"

#: A real mainnet record. Every key here was on chain.
REAL_ATTRS = {
    "name": "custodian-gate-x7f3",
    "domain": "rxd",
    "target": "1CPfirXZahPrTb93QouwBfKDoz1ykfcBb7",
    "target_type": "address",
    "expires": 1850743929,
}


def _human(short: str) -> str:
    tx = _TXS[short]
    return _render_txid_human(_classify_raw_tx(tx["txid"], bytes.fromhex(tx["raw"])))


# ---------------------------------------------------------------------------
# 1. The update must reach the terminal
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("short", [UPDATE_1, UPDATE_2])
def test_the_new_target_appears_in_default_human_output(short: str) -> None:
    """THE DEFECT. Both of these rendered without a trace of the change."""
    out = _human(short)
    assert MOVED_TARGET in out, f"the updated target is invisible in human output:\n{out}"
    assert "UPDATE" in out


def test_the_human_block_says_what_it_does_not_establish(short: str = UPDATE_1) -> None:
    """An update changes a GLYPH's fields. Whether that glyph is the name someone means is an
    index's answer, and the gap between those two is the whole of HashMark §7.6. The line must
    not read as 'company.rxd now points here'."""
    out = _human(short)
    assert "does NOT establish which" in out
    assert "nor who held that name when" in out


def test_a_full_payload_does_not_appear_as_an_envelope(short: str = MINT) -> None:
    """Payloads belong to the `metadata` block. Rendering the mint twice would be worse than
    not rendering it: the reader would see 'UPDATE' on a transaction that updates nothing."""
    out = _human(short)
    assert "Glyph envelopes carrying no full payload" not in out
    assert "custodian-gate-x7f3.rxd" in out, "the mint's own metadata block must still render"


def test_a_transfer_shows_no_envelope_block(short: str = TRANSFER) -> None:
    """The honest negative: this transaction really does carry no envelope."""
    assert "Glyph envelopes carrying no full payload" not in _human(TRANSFER)


def test_an_unreadable_envelope_is_named_in_human_output() -> None:
    """`unreadable` must be as visible as `update`. A reader that silently omits it reports
    'nothing was published here' when the truth is 'something was, and I could not read it'."""
    payload = {
        "txid": "ab" * 32,
        "byte_length": 10,
        "input_count": 1,
        "output_count": 0,
        "outputs": [],
        "metadata": None,
        "glyph_envelopes": [{"input_index": 0, "kind": "unreadable", "reason": "not a payload; not an update"}],
    }
    out = _render_txid_human(payload)
    assert "UNREADABLE" in out
    assert "not a payload; not an update" in out


# ---------------------------------------------------------------------------
# 2. WaveAttrs must not drop `expires`
# ---------------------------------------------------------------------------


def test_a_real_record_round_trips_losslessly() -> None:
    """It did not. `expires` went in and did not come out."""
    assert WaveAttrs.from_dict(REAL_ATTRS).to_dict() == REAL_ATTRS


def test_the_fixture_actually_carries_the_field_that_was_dropped() -> None:
    """Non-vacuity: without `expires` in REAL_ATTRS the test above passes on a type that still
    drops it."""
    assert "expires" in REAL_ATTRS


def test_a_mint_that_never_asked_for_expires_still_emits_four_keys() -> None:
    """Adding a field to a serialised type must not change the bytes pyrxd publishes for
    callers who never set it. `expires` is emitted only when present."""
    md = build_wave_metadata(qualified_name="alice.rxd", target="1" * 30)
    assert sorted(md.attrs) == ["domain", "name", "target", "target_type"]


@pytest.mark.parametrize("bad", [True, False, "soon", 1.5, [], {}])
def test_an_unusable_expires_is_refused_not_dropped(bad: object) -> None:
    """Refusing is the point: silently dropping it is the defect being fixed.

    `True` and `False` are in here deliberately — `isinstance(True, int)` is True in Python, so
    a bool would otherwise be carried as 1, a timestamp in 1970.
    """
    with pytest.raises(ValidationError, match="expires"):
        WaveAttrs.from_dict({**REAL_ATTRS, "expires": bad})


def test_a_record_with_no_expires_is_still_accepted() -> None:
    """4 of the 6 real update chains omit it. Requiring it would refuse most of the corpus."""
    without = {k: v for k, v in REAL_ATTRS.items() if k != "expires"}
    attrs = WaveAttrs.from_dict(without)
    assert attrs.expires is None
    assert attrs.to_dict() == without


def test_no_shipped_code_consumes_expires_as_an_expiry() -> None:
    """`expires` is carried so the round trip is lossless — NOT so anything can be concluded.

    Photonic's own source says the indexer is authoritative on renewals and that `attrs.expires`
    is "display-level": real expiry follows from treasury payments this type never sees. A plain
    integer field invites `if now > attrs.expires`, and that comparison would be wrong.

    Pinned as MEMBERSHIP rather than described in a docstring: today nothing reads it, and if
    that changes this fails and someone has to re-read why the field is not an answer. An AST
    scan, so the comment blocks explaining this are not themselves mistaken for a read.

    THE SCAN MATCHES THREE SPELLINGS, not one. It originally looked for `ast.Attribute` alone,
    which is the shape the DATACLASS uses — and `attrs` is a plain dict everywhere else, so the
    two ways a real consumer would actually reach the field, `attrs["expires"]` and
    `attrs.get("expires")`, both passed it silently. A guard written from one example generalises
    over the axis it was shown; this one was shown the attribute.
    """
    import ast

    root = pathlib.Path(__file__).resolve().parent.parent / "src" / "pyrxd"
    files = sorted(root.rglob("*.py"))
    assert len(files) > 50, f"the scan reached only {len(files)} modules — it is not reaching src/"

    readers = []
    for path in files:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))

        # EXEMPT BY SCOPE, NOT BY SPELLING. `WaveAttrs` parsing and serialising its own field is
        # not a caller drawing a conclusion from it. Scoping to the class body (derived from the
        # AST) rather than to `self.` covers `d["expires"]` and `d.get("expires")` inside
        # `from_dict`/`to_dict` too, which a `self.`-only exemption would have flagged.
        own = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and node.name == "WaveAttrs":
                own.update(id(sub) for sub in ast.walk(node))

        for node in ast.walk(tree):
            if (
                (isinstance(node, ast.Attribute) and node.attr == "expires")
                or (
                    isinstance(node, ast.Subscript)
                    and isinstance(node.slice, ast.Constant)
                    and node.slice.value == "expires"
                )
                or (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr in ("get", "pop", "setdefault")
                    and node.args
                    and isinstance(node.args[0], ast.Constant)
                    and node.args[0].value == "expires"
                )
            ):
                pass
            else:
                continue
            if id(node) in own:
                continue
            readers.append(f"{path.relative_to(root.parent.parent)}:{node.lineno}")

    assert not readers, (
        f"shipped code now reads `.expires`: {readers}. It is display-level, not an expiry — "
        "the indexer decides renewals from treasury payments. Re-read the note on WaveAttrs "
        "before treating this as an answer."
    )


def test_cbor_round_trip_through_the_wire_keeps_expires() -> None:
    """Through the transport that actually carries it, not just the dataclass."""
    blob = cbor2.dumps({"attrs": REAL_ATTRS})
    back = WaveAttrs.from_dict(cbor2.loads(blob)["attrs"])
    assert back.expires == REAL_ATTRS["expires"]
    assert back.to_dict() == REAL_ATTRS
