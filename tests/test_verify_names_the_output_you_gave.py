"""``pyrxd verify <txid>:<n>`` and ``pyrxd verify <contract id>`` — #745.

Both forms NAME AN OUTPUT of a transaction. ``verify`` refused them with "that is not a
transaction id", about input that had one in it, and a fix hint that talked only about digests.
The /verify/ page accepts both (``docs/inspect_static/verify/verify.js``: ``transactionNamedBy``,
``namedByNote``, ``namedOutputNote``): it checks the transaction the pointer names and, before any
verdict, says whether the named output holds the record, holds something that is not a record
(and which output does), or does not exist. This file holds the command to the same answers.

Driven through the REAL top-level command. Only the ElectrumX transport is faked
(:class:`tests.test_hashmark_verify_cli._FakeServer`); every record is a real signed record over
a generated key, inside a real transaction whose txid is its own hash, read back by the real
classifier.

THE FIXTURE's quantities differ on purpose: the mark is at output 0 of a TWO-output transaction,
so ``:1`` is a real output that is not the mark, ``:2`` is exactly one past the end, and ``:7`` is
well past it. A one-output fixture would make "the named output" and "the record" the same thing
by construction, which is the conflation these sentences exist to separate.
"""

from __future__ import annotations

import hashlib
import json
import os

import pytest

from pyrxd.cli.hashmark_cmds import EXIT_VERDICT_DOES_NOT_HOLD
from pyrxd.glyph import _inspect_core
from pyrxd.keys import PrivateKey
from tests.test_hashmark_verify_cli import _FakeServer, _mark_script, _run, _tx_with

_CHANGE = b"\x76\xa9\x14" + bytes(range(20)) + b"\x88\xac"  # a P2PKH change output: not a record


def _contract(txid: str, vout: int) -> str:
    """The explorer's contract id: display-order txid, then the vout as 8 BIG-endian hex digits."""
    return f"{txid}{vout:08x}"


# (how the named output is written, how the command says it read it)
FORMS = [
    pytest.param(lambda txid, n: f"{txid}:{n}", "You gave an output reference, read as output", id="outpoint"),
    pytest.param(_contract, "You gave a contract id, which names output", id="contract"),
]


@pytest.fixture
def two_outputs(tmp_path):
    """A signed mark at output 0 and a change output at 1 — the ordinary shape of a mark."""
    content = b"the advisory, as published\n"
    target = tmp_path / "advisory.txt"
    target.write_bytes(content)
    txid, raw = _tx_with(_mark_script(content, PrivateKey(), label="advisory v1"), _CHANGE)
    return {"txid": txid, "raw": raw, "file": target, "server": _FakeServer({txid: raw})}


def _verify(monkeypatch, tmp_path, server, target: str, *extra: str):
    """``--json`` / ``--quiet`` go before the command (they are the CLI's); the rest after it."""
    top = [e for e in extra if e in ("--json", "--quiet")]
    own = [e for e in extra if e not in top]
    return _run(monkeypatch, server, [*top, "verify", target, *own, "--min-confirmations", "6"], tmp_path=tmp_path)


def _digest(fx: dict) -> str:
    return hashlib.sha256(fx["file"].read_bytes()).hexdigest()


def _flat(text: str) -> str:
    return " ".join(text.split())


def _said_before_the_verdict(output: str) -> str:
    head, sep, _ = output.partition("Mark: ")
    assert sep, f"no report was printed:\n{output}"
    return _flat(head)


# --------------------------------------------------------------------------- the bare txid


class TestTheBareTxidIsUnchanged:
    def test_it_says_nothing_about_a_named_output_and_its_json_has_no_such_key(
        self, monkeypatch, tmp_path, two_outputs
    ) -> None:
        r = _verify(monkeypatch, tmp_path, two_outputs["server"], two_outputs["txid"])
        assert r.exit_code == 0, r.output
        assert r.output.startswith("Mark: "), "a bare txid's report starts where it always did"
        assert "the one you named" not in r.output and "You gave" not in r.output

        j = _verify(monkeypatch, tmp_path, two_outputs["server"], two_outputs["txid"], "--json")
        assert j.exit_code == 0, j.output
        assert "named_by" not in json.loads(j.stdout)


# --------------------------------------------------------------------------- :0 / :1 / :7 / :<count>


@pytest.mark.parametrize(("spell", "gave"), FORMS)
class TestEachOutputYouCanName:
    def test_the_output_that_holds_the_mark(self, monkeypatch, tmp_path, two_outputs, spell, gave) -> None:
        txid = two_outputs["txid"]
        r = _verify(monkeypatch, tmp_path, two_outputs["server"], spell(txid, 0), "--digest", _digest(two_outputs))
        assert r.exit_code == 0, r.output
        said = _said_before_the_verdict(r.output)
        assert f"{gave} 0 of transaction {txid}." in said
        assert "that whole transaction was checked" in said
        assert "Output 0, the one you named, holds the HashMark record the verdict below is about." in said
        assert "NOT" not in said and "no output" not in said
        assert "VERDICT — holds" in r.output

    def test_a_change_output_is_not_the_mark_and_it_says_which_output_is(
        self, monkeypatch, tmp_path, two_outputs, spell, gave
    ) -> None:
        txid = two_outputs["txid"]
        r = _verify(monkeypatch, tmp_path, two_outputs["server"], spell(txid, 1))
        assert r.exit_code == 0, r.output
        said = _said_before_the_verdict(r.output)
        assert f"{gave} 1 of transaction {txid}." in said
        assert "Output 1, the one you named, is NOT a HashMark record, so the verdict below is not about it." in said
        assert "The transaction's HashMark record is in output 0, and the verdict below is about it." in said
        assert "holds the HashMark record" not in said
        # ...and what it says the verdict is about is what the verdict says it is about.
        assert "record:     vout 0" in r.output

    @pytest.mark.parametrize("n", [7, 2], ids=["well-past-the-end", "exactly-one-past-the-end"])
    def test_an_output_the_transaction_does_not_have(self, monkeypatch, tmp_path, two_outputs, spell, gave, n) -> None:
        txid = two_outputs["txid"]
        r = _verify(monkeypatch, tmp_path, two_outputs["server"], spell(txid, n))
        assert r.exit_code == 0, r.output
        said = _said_before_the_verdict(r.output)
        assert f"{gave} {n} of transaction {txid}." in said
        assert (
            f"That transaction has 2 outputs (numbered 0 to 1), so there is no output {n}: what you gave "
            "points at nothing in it." in said
        )
        assert "The transaction's HashMark record is in output 0, and the verdict below is about it." in said
        assert f"Output {n}, the one you named" not in said

    def test_the_json_carries_the_same_sentences_and_the_facts_under_them(
        self, monkeypatch, tmp_path, two_outputs, spell, gave
    ) -> None:
        txid = two_outputs["txid"]
        expected = {
            0: (True, True, True),
            1: (True, False, False),
            2: (False, False, False),
            7: (False, False, False),
        }
        for n, (exists, holds, about) in expected.items():
            human = _verify(monkeypatch, tmp_path, two_outputs["server"], spell(txid, n))
            j = _verify(monkeypatch, tmp_path, two_outputs["server"], spell(txid, n), "--json")
            assert j.exit_code == 0, j.output
            named = json.loads(j.stdout)["named_by"]
            assert (named["output_exists"], named["output_holds_record"], named["verdict_is_about_it"]) == (
                exists,
                holds,
                about,
            ), n
            assert (named["txid"], named["vout"]) == (txid, n)
            assert named["form"] == ("outpoint" if ":" in spell(txid, n) else "contract")
            # ONE source for both: the human lines ARE the JSON's sentences.
            assert _said_before_the_verdict(human.output) == _flat(" ".join(named["says"]))

    def test_naming_an_output_never_changes_the_verdict(self, monkeypatch, tmp_path, two_outputs, spell, gave) -> None:
        txid = two_outputs["txid"]
        bare = json.loads(_verify(monkeypatch, tmp_path, two_outputs["server"], txid, "--json").stdout)
        for n in (0, 1, 2, 7):
            named = json.loads(_verify(monkeypatch, tmp_path, two_outputs["server"], spell(txid, n), "--json").stdout)
            named.pop("named_by")
            assert named == bare, n

    def test_quiet_mode_keeps_one_token_and_still_says_it(
        self, monkeypatch, tmp_path, two_outputs, spell, gave
    ) -> None:
        r = _verify(monkeypatch, tmp_path, two_outputs["server"], spell(two_outputs["txid"], 7), "--quiet")
        assert r.exit_code == 0, r.output
        assert r.stdout.strip() == "HOLDS"
        assert "there is no output 7" in _flat(r.stderr)


# --------------------------------------------------------------------------- several records


class TestSeveralRecords:
    """The verdict is about ONE record. The named output can hold a record that is not it."""

    @pytest.fixture
    def two_marks(self, tmp_path):
        mine, theirs = b"my file\n", b"a different file\n"
        txid, raw = _tx_with(_mark_script(mine, PrivateKey()), _mark_script(theirs, PrivateKey()), _CHANGE)
        return {"txid": txid, "server": _FakeServer({txid: raw}), "digest": hashlib.sha256(mine).hexdigest()}

    def test_a_record_the_verdict_is_not_about(self, monkeypatch, tmp_path, two_marks) -> None:
        txid = two_marks["txid"]
        r = _verify(monkeypatch, tmp_path, two_marks["server"], f"{txid}:1", "--digest", two_marks["digest"])
        assert r.exit_code == 0, r.output
        said = _said_before_the_verdict(r.output)
        assert (
            "Output 1, the one you named, holds a HashMark record, but the verdict below is about the record at "
            'vout 0. Output 1\'s own record is listed below as "HashMark record at vout 1".' in said
        )
        assert "record:     vout 0" in r.output, "the verdict must be about the vout the sentence names"
        assert "HashMark record at vout 1:" in r.output, "the section the sentence points at must exist"

    def test_the_named_record_is_the_one_the_verdict_is_about(self, monkeypatch, tmp_path, two_marks) -> None:
        txid = two_marks["txid"]
        r = _verify(monkeypatch, tmp_path, two_marks["server"], f"{txid}:0", "--digest", two_marks["digest"])
        assert r.exit_code == 0, r.output
        assert "Output 0, the one you named, holds the HashMark record the verdict below is about." in (
            _said_before_the_verdict(r.output)
        )

    def test_not_a_record_says_how_many_there_are_and_which_one_the_verdict_is_about(
        self, monkeypatch, tmp_path, two_marks
    ) -> None:
        txid = two_marks["txid"]
        r = _verify(monkeypatch, tmp_path, two_marks["server"], f"{txid}:2", "--digest", two_marks["digest"])
        assert r.exit_code == 0, r.output
        said = _said_before_the_verdict(r.output)
        assert "Output 2, the one you named, is NOT a HashMark record" in said
        assert (
            "The transaction carries 2 HashMark records in other outputs; the verdict below is about the one at "
            "vout 0, and each is listed separately." in said
        )


class TestAForgedRecordBesideAGoodOne:
    """A record that does not verify fails the WHOLE transaction, and the verdict's signature line
    is then about THAT record while its other lines are about the witness. A sentence above the
    verdict saying "the verdict is about vout 0" would contradict the record line inside it."""

    @pytest.fixture
    def forged_at_1(self):
        good = _mark_script(b"honest\n", PrivateKey())
        forged = bytearray(_mark_script(b"honest\n", PrivateKey()))
        forged[20] ^= 0x01  # one digest bit: still well-formed, no longer verifies
        txid, raw = _tx_with(good, bytes(forged), _CHANGE)
        return {"txid": txid, "server": _FakeServer({txid: raw})}

    @pytest.mark.parametrize(
        ("n", "sentence"),
        [
            (
                0,
                "Output 0, the one you named, holds the HashMark record the verdict below is about, except its "
                "signature line, which is about the record at vout 1.",
            ),
            (
                1,
                "Output 1, the one you named, holds a HashMark record, but the verdict below is about the record at "
                "vout 0, except its signature line, which is about the record at vout 1.",
            ),
            (
                2,
                "The transaction carries 2 HashMark records in other outputs; the verdict below is about the one at "
                "vout 0, except its signature line, which is about the record at vout 1, and each is listed separately.",
            ),
        ],
    )
    def test_the_sentence_agrees_with_the_record_line(self, monkeypatch, tmp_path, forged_at_1, n, sentence) -> None:
        r = _verify(monkeypatch, tmp_path, forged_at_1["server"], f"{forged_at_1['txid']}:{n}")
        assert r.exit_code == EXIT_VERDICT_DOES_NOT_HOLD, r.output
        assert sentence in _said_before_the_verdict(r.output)
        # The record line inside the verdict says the same thing about the same two outputs.
        assert "record:     vout 0" in r.output
        assert "the signature line is about the record at vout 1" in _flat(r.output)


# --------------------------------------------------------------------------- unknown, not "not a record"


def test_an_output_the_classifier_could_not_read_is_not_called_a_non_record(monkeypatch, tmp_path, two_outputs) -> None:
    """A classifier crash becomes a ``type: "error"`` row. Whether that output is a record is
    UNKNOWN, and "is NOT a HashMark record" would be a claim nobody established."""
    real = _inspect_core._classify_script

    def crash_on_the_change(script_hex: str, **kw):
        if script_hex == _CHANGE.hex():
            raise RuntimeError("planted classifier crash")
        return real(script_hex, **kw)

    monkeypatch.setattr(_inspect_core, "_classify_script", crash_on_the_change)
    r = _verify(monkeypatch, tmp_path, two_outputs["server"], f"{two_outputs['txid']}:1")
    assert r.exit_code == 0, r.output
    said = _said_before_the_verdict(r.output)
    assert "Output 1, the one you named, could not be classified here, so this cannot say whether it is a" in said
    assert "is NOT a HashMark record" not in said

    j = _verify(monkeypatch, tmp_path, two_outputs["server"], f"{two_outputs['txid']}:1", "--json")
    assert json.loads(j.stdout)["named_by"]["output_holds_record"] is None


# --------------------------------------------------------------------------- no record at all


@pytest.mark.parametrize(("spell", "gave"), FORMS)
class TestATransactionWithNoMark:
    @pytest.fixture
    def no_mark(self):
        txid, raw = _tx_with(_CHANGE, b"\x76\xa9\x14" + os.urandom(20) + b"\x88\xac")
        return {"txid": txid, "server": _FakeServer({txid: raw})}

    def test_an_output_it_has(self, monkeypatch, tmp_path, no_mark, spell, gave) -> None:
        r = _verify(monkeypatch, tmp_path, no_mark["server"], spell(no_mark["txid"], 1))
        assert r.exit_code == 1, r.output
        flat = _flat(r.output)
        assert "no HashMark record in the transaction you named an output of" in flat
        assert f"{no_mark['txid']} has 2 output(s) and none of them decodes as a HashMark" in flat
        assert "output 1, the one you named, among them" in flat
        # Not the digest hint: an outpoint and a contract id are not the shape of a digest.
        assert "--digest" not in flat

    def test_an_output_it_does_not_have(self, monkeypatch, tmp_path, no_mark, spell, gave) -> None:
        r = _verify(monkeypatch, tmp_path, no_mark["server"], spell(no_mark["txid"], 2))
        assert r.exit_code == 1, r.output
        flat = _flat(r.output)
        assert "there is no output 2, the one you named: it has 2 outputs (numbered 0 to 1)" in flat
        assert "among them" not in flat


# --------------------------------------------------------------------------- refusals


class TestARefusalNamesTheTxidYouTyped:
    def test_an_unreadable_output_number_names_the_txid_before_it(self, monkeypatch, tmp_path, two_outputs) -> None:
        txid = two_outputs["txid"]
        r = _verify(monkeypatch, tmp_path, two_outputs["server"], f"{txid}:first")
        assert r.exit_code == 1, r.output
        flat = _flat(r.output)
        assert "that is not an output reference" in flat
        assert f"the part before ':' holds a transaction id, {txid}." in flat
        assert f"{txid}:0" in flat
        assert two_outputs["server"].calls == [], "refused before the network"

    @pytest.mark.parametrize("shape", ["{t}:0:1", "{t} :0"], ids=["two-colons", "space-before-the-colon"])
    def test_other_malformed_references_name_the_txid_too(self, monkeypatch, tmp_path, two_outputs, shape) -> None:
        txid = two_outputs["txid"]
        r = _verify(monkeypatch, tmp_path, two_outputs["server"], shape.format(t=txid))
        assert r.exit_code == 1, r.output
        assert "that is not an output reference" in _flat(r.output)
        assert f"holds a transaction id, {txid}." in _flat(r.output)

    def test_a_bad_txid_before_the_colon_is_not_called_one(self, monkeypatch, tmp_path, two_outputs) -> None:
        r = _verify(monkeypatch, tmp_path, two_outputs["server"], f"{two_outputs['txid'][:-1]}:0")
        assert r.exit_code == 1, r.output
        flat = _flat(r.output)
        assert "the part before ':' is not a transaction id" in flat
        assert "holds a transaction id" not in flat

    def test_the_plain_refusal_names_every_form_it_takes(self, monkeypatch, tmp_path, two_outputs) -> None:
        r = _verify(monkeypatch, tmp_path, two_outputs["server"], "not-a-txid")
        assert r.exit_code == 1, r.output
        flat = _flat(r.output)
        assert "that is not a transaction id" in flat
        assert "<txid>:<n>" in flat and "72-character contract id" in flat
        assert "--digest" in flat

    def test_the_min_confirmations_refusal_repeats_the_form_you_gave(self, monkeypatch, tmp_path, two_outputs) -> None:
        txid = two_outputs["txid"]
        for given, rerun in ((f"{txid.upper()}:1", f"{txid}:1"), (_contract(txid, 1).upper(), _contract(txid, 1))):
            r = _run(monkeypatch, two_outputs["server"], ["verify", given], tmp_path=tmp_path)
            assert r.exit_code == 1, r.output
            assert f"`pyrxd verify {rerun}`" in r.output


def test_a_verdict_that_does_not_hold_is_still_disclosed_first(monkeypatch, tmp_path, two_outputs) -> None:
    """The disclosure is not only for the happy path: a mismatch prints it too, then exits 5."""
    r = _verify(monkeypatch, tmp_path, two_outputs["server"], f"{two_outputs['txid']}:1", "--digest", "00" * 32)
    assert r.exit_code == EXIT_VERDICT_DOES_NOT_HOLD, r.output
    assert "Output 1, the one you named, is NOT a HashMark record" in _said_before_the_verdict(r.output)


def test_this_file_uses_the_fixture_it_says_it_does(two_outputs) -> None:
    """The docstring's claim about the fixture, checked: two outputs, the mark at 0."""
    from pyrxd.glyph._inspect_core import _classify_raw_tx

    payload = _classify_raw_tx(two_outputs["txid"], two_outputs["raw"])
    assert payload["output_count"] == 2
    assert [row["vout"] for row in payload["outputs"] if row.get("hashmark")] == [0]
