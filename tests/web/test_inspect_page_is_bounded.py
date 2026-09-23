"""One transaction cannot make /inspect/ do unbounded work, and what it leaves out it says.

Nothing bounds how many outputs or inputs a transaction carries — about 28,000 distinct signed
HashMark v2 records fit under the 4 MB cap — and /inspect/ classified and drew every one: a
curve recovery per record in JavaScript on the page's main thread, then (measured under Node's
stub DOM, not a browser) 1,013,995 elements and 28,166 file choosers. 88,884 inputs carrying a
bare ``gly`` marker drew 622,218 elements from the envelope list the same way.

Now the page draws at most ``MAX_ROWS_SHOWN`` rows from each list, passes the same number to the
classifier as its signature-checking limit (``TestEveryClassificationIsBounded`` in
``test_inspect_fetch_flow.py`` pins that the page really passes it), and states — in exact
counts taken from what the classifier said about each row it left out — what was not drawn and
what was not checked, with the command that shows everything.
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import shutil
import subprocess  # nosec B404 — fixed argv, no shell, repo-local script
import sys
from pathlib import Path

import pytest

# Every ``pyrxd`` import is LAZY — see the note in ``test_inspect_js_render_drift.py``.

_REPO_ROOT = Path(__file__).resolve().parents[2]
_HARNESS = _REPO_ROOT / "tests" / "web" / "inspect_render_harness.mjs"
_GLUE = _REPO_ROOT / "docs" / "inspect_static" / "inspect" / "glue.py"


def _require_node() -> str:
    node = shutil.which("node")
    if node is None:
        if os.environ.get("PYRXD_SKIP_JS_RENDER_GUARD") == "1":
            pytest.skip("node is missing and PYRXD_SKIP_JS_RENDER_GUARD=1 — the inspect page bound is UNGUARDED")
        pytest.fail("node is required to drive inspect.js (or set PYRXD_SKIP_JS_RENDER_GUARD=1)")
    return node


def _render(cases: dict) -> dict:
    proc = subprocess.run(  # nosec B603 — fixed argv, no shell, repo-local script
        [_require_node(), str(_HARNESS), "-"],
        input=json.dumps(cases),
        capture_output=True,
        text=True,
        check=False,
        cwd=str(_REPO_ROOT),
    )
    if proc.returncode != 0:
        pytest.fail(f"render harness failed (exit {proc.returncode}):\n{proc.stderr}")
    return json.loads(proc.stdout)


def _card(payload: dict) -> dict:
    return _render({"case": {"tx": payload}})["case"]


def _flat(text: str) -> str:
    return " ".join(text.split())


def _glue():
    spec = importlib.util.spec_from_file_location("pyrxd_inspect_glue_bounded", _GLUE)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["pyrxd_inspect_glue_bounded"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def limit() -> int:
    """``MAX_ROWS_SHOWN``, read from inspect.js through the harness rather than retyped here."""
    n = _render({})["__constants__"]["max_rows_shown"]
    assert isinstance(n, int), f"inspect.js exposes no MAX_ROWS_SHOWN (got {n!r})"
    return n


def _push(b: bytes) -> bytes:
    return bytes([len(b)]) + b


def _v1(i: int) -> bytes:
    return b"\x6a" + _push(b"HASHMARK") + _push(bytes([1, 1])) + _push(bytes([i % 256]) * 32)


_P2PKH = b"\x76\xa9\x14" + b"\x11" * 20 + b"\x88\xac"


def _signed(content: bytes) -> bytes:
    import hashlib

    from pyrxd.constants import genesis_hash_for
    from pyrxd.keys import PrivateKey
    from pyrxd.script.hashmark import encode_hashmark

    return encode_hashmark(hashlib.sha256(content).digest(), PrivateKey(), network_genesis=genesis_hash_for("mainnet"))


def _classified(*scripts: bytes, limit: int | None, inputs: list[bytes] | None = None) -> tuple[str, bytes, dict]:
    """A real transaction, classified by the page's own entry point with the page's limit — the
    exact payload inspect.js receives."""
    from pyrxd.script.script import Script
    from pyrxd.transaction.transaction import Transaction
    from pyrxd.transaction.transaction_input import TransactionInput
    from pyrxd.transaction.transaction_output import TransactionOutput

    tx = Transaction(tx_inputs=[], tx_outputs=[TransactionOutput(Script(s), 0) for s in scripts])
    ins = []
    for i, unlocking in enumerate(inputs or [b"\x00"]):
        inp = TransactionInput(source_txid=i.to_bytes(32, "big").hex(), source_output_index=0)
        inp.unlocking_script = Script(unlocking)
        ins.append(inp)
    tx.inputs = ins
    raw = tx.serialize()
    result = _glue().inspect_txid_with_raw(tx.txid(), raw.hex(), "", limit)
    assert result["ok"], result
    return tx.txid(), raw, result["payload"]


def _synthetic(template: dict, count: int) -> dict:
    """``count`` copies of one REAL classified row — the size of the transaction is the point,
    not the variety of its rows. Built in Python rather than signed 28,000 times."""
    return {
        "txid": "ab" * 32,
        "byte_length": 4_000_000,
        "input_count": 1,
        "output_count": count,
        "outputs": [{**template, "vout": i} for i in range(count)],
        "metadata": None,
        "metadata_inputs": [],
        "glyph_envelopes": [],
    }


@pytest.fixture(scope="module")
def v1_row(limit) -> dict:
    _t, _r, payload = _classified(_v1(0), limit=limit)
    row = payload["outputs"][0]
    assert row["hashmark"]["outcome"] == "ok"
    return row


# ─────────────────────────────────────────────────────── the page does not grow ──


class TestTheOutputListIsBounded:
    def test_the_limit_is_small_and_positive(self, limit) -> None:
        assert 1 <= limit <= 200

    def test_the_page_does_not_grow_with_the_transaction(self, limit, v1_row) -> None:
        """THE BOUND, at the size of the attack: 72,000 rows build exactly as much page as
        limit+1 rows do — the same elements, only different numbers in the text."""
        both = _render({"small": {"tx": _synthetic(v1_row, limit + 1)}, "huge": {"tx": _synthetic(v1_row, 72_000)}})
        small, huge = both["small"], both["huge"]
        assert huge["fetched_tx_card_elements"] == small["fetched_tx_card_elements"], "the page grew with the tx"
        assert huge["fetched_tx_card_file_inputs"] == limit == small["fetched_tx_card_file_inputs"]
        assert f"Outputs (the first {limit} of 72000)" in huge["fetched_tx_card"]
        assert f"{72_000 - limit} more outputs are in this transaction" in _flat(huge["fetched_tx_card"])

    def test_exactly_the_limit_is_all_drawn_and_nothing_says_otherwise(self, limit, v1_row) -> None:
        """The honest edge: nothing was left out, so nothing may say something was."""
        card = _card(_synthetic(v1_row, limit))
        assert card["fetched_tx_card_file_inputs"] == limit
        text = _flat(card["fetched_tx_card"])
        assert "Outputs (the first" not in text and "not shown here" not in text
        assert "pyrxd glyph inspect" not in text

    def test_one_past_the_limit_is_said_in_the_singular(self, limit, v1_row) -> None:
        text = _flat(_card(_synthetic(v1_row, limit + 1))["fetched_tx_card"])
        assert f"1 more output is in this transaction and is not shown here (vout {limit})." in text
        assert "It carries a HashMark record. What this page knows about its signature: 1 NO SIGNATURE." in text


# ─────────────────────────────────── what was left out, in the classifier's own words ──


class TestTheNoteSaysExactlyWhatWasLeftOut:
    def test_distinct_signed_records_past_the_limit_are_counted_as_not_checked(self, limit) -> None:
        txid, _r, payload = _classified(*(_signed(f"doc {i}".encode()) for i in range(limit + 5)), limit=limit)
        outcomes = [row["hashmark"]["attestation"]["outcome"] for row in payload["outputs"]]
        assert outcomes == ["valid"] * limit + ["not_checked_here"] * 5, "the premise: the classifier's own answer"
        card = _card(payload)
        text = _flat(card["fetched_tx_card"])
        assert card["fetched_tx_card_file_inputs"] == limit
        assert f"Outputs (the first {limit} of {limit + 5})" in text
        assert (
            f"5 more outputs are in this transaction and are not shown here (vout {limit} to {limit + 4}). "
            "By type: 5 op_return-hashmark-v2." in text
        )
        assert "They carry HashMark records. What this page knows about their signatures: 5 not checked here." in text
        assert "The 5 not checked here were past that, so nothing here says whether they verify" in text
        assert f"pyrxd glyph inspect {txid} --fetch" in text
        # ORDER: the heading before the first row, the note after the last one.
        assert text.index("Outputs (the first") < text.index("vout 0") < text.index("5 more outputs")

    def test_a_forgery_past_the_limit_is_not_checked_and_a_clean_copy_is_verified(self, limit) -> None:
        """The reviewer's case for /verify/, on this page. CLEAN: limit+1 copies of one genuine
        record. FORGED: limit copies and a forgery last. The page cannot know the forgery is forged
        without checking it — so it must SAY it did not check it, and the two pages must differ."""
        good = _signed(b"release 1.0\n")
        forged = bytearray(good)
        forged[20] ^= 0x01  # well-formed; the signature no longer holds
        _t, _r, clean = _classified(*([good] * (limit + 1)), limit=limit)
        _t, _r, dirty = _classified(*([good] * limit), bytes(forged), limit=limit)
        for payload in (clean, dirty):
            payload["txid"] = "ab" * 32  # so only the records differ
        both = _render({"clean": {"tx": clean}, "dirty": {"tx": dirty}})
        c, d = (_flat(both[k]["fetched_tx_card"]) for k in ("clean", "dirty"))
        assert c != d
        assert "What this page knows about its signature: 1 VERIFIED." in c and "could be among them" not in c
        assert "What this page knows about its signature: 1 not checked here." in d
        assert "The one not checked here was past that, so nothing here says whether it verifies" in d
        assert "a record that does not verify could be among them" in d

    def test_a_forgery_within_the_limit_is_drawn_in_the_error_colour(self, limit) -> None:
        good = _signed(b"release 1.0\n")
        forged = bytearray(good)
        forged[20] ^= 0x01
        _t, _r, payload = _classified(*([good] * 3), bytes(forged), *([good] * limit), limit=limit)
        card = _card(payload)
        assert "DOES NOT VERIFY" in card["fetched_tx_card"]
        assert any(c.split()[:2] == ["verdict", "verdict-bad"] for c in card["fetched_tx_card_classes"])

    def test_a_mixed_remainder_is_tallied_by_type_and_by_verdict(self, limit) -> None:
        """Only some of the rows left out are marks: the note says how many, and does not call
        the P2PKH rows marks."""
        scripts = [_P2PKH] * limit + [_v1(1), _P2PKH, _v1(2), _v1(3), _P2PKH]
        _t, _r, payload = _classified(*scripts, limit=limit)
        text = _flat(_card(payload)["fetched_tx_card"])
        assert "By type: 3 op_return-hashmark-v1, 2 p2pkh." in text
        assert "3 of them carry HashMark records. What this page knows about their signatures: 3 NO SIGNATURE." in text
        assert "not checked here" not in text, "a v1 record has no signature, and its NO SIGNATURE costs nothing"

    def test_a_remainder_of_many_types_names_twelve_and_counts_the_rest(self, limit, v1_row) -> None:
        """The tally of types is itself bounded: it names at most twelve and counts the rest,
        so the note cannot become the flood it reports."""
        payload = _synthetic(v1_row, limit)
        payload["outputs"] += [{"vout": limit + i, "type": f"kind-{i:02d}", "satoshis": 0} for i in range(13)]
        payload["output_count"] = len(payload["outputs"])
        text = _flat(_card(payload)["fetched_tx_card"])
        named = ", ".join(f"1 kind-{i:02d}" for i in range(12))
        assert f"By type: {named}, 1 more of 1 other kind." in text

    def test_a_remainder_with_no_marks_says_nothing_about_signatures(self, limit) -> None:
        _t, _r, payload = _classified(*([_P2PKH] * (limit + 2)), limit=limit)
        text = _flat(_card(payload)["fetched_tx_card"])
        assert "By type: 2 p2pkh." in text
        assert "HashMark" not in text.split("By type:", 1)[1]

    def test_the_command_the_note_gives_shows_every_output_with_every_signature_checked(
        self, limit, monkeypatch, tmp_path
    ) -> None:
        """The note's command, run as printed, through the real CLI."""
        import shlex

        from tests.test_hashmark_verify_one_record import _run

        txid, raw, payload = _classified(*(_signed(f"doc {i}".encode()) for i in range(limit + 3)), limit=limit)
        text = _flat(_card(payload)["fetched_tx_card"])
        match = re.search(r"(pyrxd glyph inspect \S+ --fetch)", text)
        assert match, "the note carries no command"
        argv = shlex.split(match.group(1))
        assert argv[:3] == ["pyrxd", "glyph", "inspect"] and argv[3] == txid
        r = _run(monkeypatch, {txid: raw}, argv[1:], tmp_path)
        assert r.exit_code == 0, r.output
        for vout in (0, limit, limit + 2):
            assert f"vout {vout:>3}" in r.output, f"vout {vout} is not in the command's output"
        assert r.output.count("signature VERIFIED") == limit + 3, (
            "the command a reader is sent to did not check every record"
        )
        assert "not checked here" not in r.output


# ─────────────────────────────────────── the inputs' lists are bounded the same way ──


class TestTheInputListsAreBounded:
    def test_envelopes_past_the_limit_are_counted_by_kind(self, limit) -> None:
        txid, _r, payload = _classified(b"\x6a" + b"\x00" * 30, limit=limit, inputs=[b"\x03gly"] * (limit + 3))
        assert len(payload["glyph_envelopes"]) == limit + 3, "the premise: every input carries an envelope"
        card = _card(payload)
        text = _flat(card["fetched_tx_card"])
        assert text.count("UNREADABLE — a 'gly' marker") == limit
        assert f"Glyph envelopes carrying no full payload ({limit + 3})" in text
        assert "3 more envelopes are not shown here: 3 UNREADABLE." in text
        assert f"pyrxd glyph inspect {txid} --fetch" in text

    def test_the_envelope_list_does_not_grow_with_the_transaction(self, limit) -> None:
        _t, _r, payload = _classified(b"\x6a" + b"\x00" * 30, limit=limit, inputs=[b"\x03gly"] * 2)
        env = payload["glyph_envelopes"][0]
        small = {**payload, "glyph_envelopes": [{**env, "input_index": i} for i in range(limit + 1)]}
        huge = {**payload, "glyph_envelopes": [{**env, "input_index": i} for i in range(88_884)]}
        both = _render({"small": {"tx": small}, "huge": {"tx": huge}})
        assert both["huge"]["fetched_tx_card_elements"] == both["small"]["fetched_tx_card_elements"]
        assert f"{88_884 - limit} more envelopes are not shown here" in _flat(both["huge"]["fetched_tx_card"])

    def test_exactly_the_limit_of_envelopes_says_nothing_is_missing(self, limit) -> None:
        _t, _r, payload = _classified(b"\x6a" + b"\x00" * 30, limit=limit, inputs=[b"\x03gly"] * limit)
        text = _flat(_card(payload)["fetched_tx_card"])
        assert text.count("UNREADABLE — a 'gly' marker") == limit
        assert "not shown here" not in text

    def test_other_glyphs_past_the_limit_are_counted(self, limit) -> None:
        rows = [{"input_index": i, "classification": "nft", "name": f"g{i}", "ticker": ""} for i in range(limit + 3)]
        payload = {
            "txid": "cd" * 32,
            "byte_length": 1,
            "input_count": limit + 3,
            "output_count": 0,
            "outputs": [],
            "metadata": {"input_index": 0, "protocol": [2], "name": "g0"},
            "metadata_inputs": rows,
            "glyph_envelopes": [],
        }
        text = _flat(_card(payload)["fetched_tx_card"])
        assert f"Other glyphs minted in this transaction ({limit + 2})" in text
        # The headline glyph (input 0) is not an "other" one: inputs 1..limit are listed, the rest counted.
        assert f"input {limit} " in text and f"input {limit + 1} " not in text
        assert f"The first {limit} are listed; 2 more are not shown here." in text
