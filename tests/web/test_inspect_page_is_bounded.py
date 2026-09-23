"""One transaction cannot make /inspect/ carry, convert or draw unbounded lists, and what the
page leaves out it counts exactly and says.

Nothing bounds how many outputs or inputs a transaction carries — about 28,000 distinct signed
HashMark v2 records, or about 70,000 v1 records, fit under the 4 MB cap. The first version of this
limit cut only what the page DREW: the glue still classified every output in full, sanitised every
string in every row, and handed all of it to JavaScript, which converted it and stringified it into
the raw-JSON drawer. Measured by the review under Pyodide in Node (not a browser), one 3.8 MB
transaction of 69,900 v1 records took 81 s of main-thread time and 1.85 GB.

Now the classifier itself lists at most ``max_rows`` entries of each list the transaction produces
(``_classify_raw_tx``), and COUNTS the rest — the type of each output left out, and for a HashMark
record the word its panel would lead with — under a ``*_not_listed`` key beside the list. The page
passes ``MAX_ROWS_SHOWN`` as ``max_rows`` (pinned in ``test_inspect_fetch_flow.py``) and draws what
it is given. So:

* the PAYLOAD does not grow with the transaction (``TestThePayloadIsBounded``);
* the counts are the classifier's own — equal to a full classification of the same transaction,
  and typed by the same branches (``TestTheCountsAreTheClassifiersOwn``);
* the card and the JSON drawer say what was left out, and the command that shows all of it.
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import shutil
import subprocess  # nosec B404 — fixed argv, no shell, repo-local script
import sys
from collections import Counter
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
    if len(b) < 0x4C:
        return bytes([len(b)]) + b
    return b"\x4c" + bytes([len(b)]) + b


def _v1(i: int) -> bytes:
    return b"\x6a" + _push(b"HASHMARK") + _push(bytes([1, 1])) + _push(i.to_bytes(32, "big"))


def _v9(i: int) -> bytes:
    """A record from a version this build does not know: UNKNOWN VERSION, not a forgery."""
    return b"\x6a" + _push(b"HASHMARK") + _push(bytes([9, 1])) + _push(i.to_bytes(32, "big"))


def _p2pkh(i: int = 0x11) -> bytes:
    return b"\x76\xa9\x14" + i.to_bytes(20, "big") + b"\x88\xac"


def _signed(content: bytes) -> bytes:
    import hashlib

    from pyrxd.constants import genesis_hash_for
    from pyrxd.keys import PrivateKey
    from pyrxd.script.hashmark import encode_hashmark

    return encode_hashmark(hashlib.sha256(content).digest(), PrivateKey(), network_genesis=genesis_hash_for("mainnet"))


def _forged(record: bytes) -> bytes:
    """The same record with one byte of its digest flipped: it decodes, and does not verify."""
    b = bytearray(record)
    b[20] ^= 0x01
    return bytes(b)


_SIG = b"\x47" + b"\x00" * 71 + b"\x21" + b"\x02" * 33


def _tx(scripts, inputs: list[bytes] | None = None):
    from pyrxd.script.script import Script
    from pyrxd.transaction.transaction import Transaction
    from pyrxd.transaction.transaction_input import TransactionInput
    from pyrxd.transaction.transaction_output import TransactionOutput

    tx = Transaction(tx_inputs=[], tx_outputs=[TransactionOutput(Script(s, allow_malformed=True), 0) for s in scripts])
    ins = []
    for i, unlocking in enumerate(inputs or [b"\x00"]):
        inp = TransactionInput(source_txid=i.to_bytes(32, "big").hex(), source_output_index=0)
        inp.unlocking_script = Script(unlocking)
        ins.append(inp)
    tx.inputs = ins
    return tx


def _result(*scripts: bytes, limit: int, inputs: list[bytes] | None = None, bounded: bool = True) -> dict:
    """A real transaction through the page's own entry point with the page's arguments: the exact
    dict inspect.js receives. ``bounded=False`` is the same call without ``max_rows`` — the full
    classification a bounded one must agree with."""
    tx = _tx(scripts, inputs)
    result = _glue().inspect_txid_with_raw(tx.txid(), tx.serialize().hex(), limit, limit if bounded else None)
    assert result["ok"], result
    return result


def _classified(*scripts: bytes, limit: int, inputs: list[bytes] | None = None) -> dict:
    return _result(*scripts, limit=limit, inputs=inputs)["payload"]


def _envelope(name: str, **fields) -> bytes:
    from pyrxd.glyph.payload import build_reveal_scriptsig_suffix, encode_payload
    from pyrxd.glyph.types import GlyphMetadata, GlyphProtocol

    cbor, _ = encode_payload(GlyphMetadata(protocol=[GlyphProtocol.NFT], name=name, **fields))
    return _SIG + build_reveal_scriptsig_suffix(cbor)


def _word(hm: dict) -> str:
    from pyrxd.glyph._inspect_core import _hashmark_tally_word

    return _hashmark_tally_word(hm)


# ─────────────────────────────────────────────────── the payload does not grow ──


class TestThePayloadIsBounded:
    def test_the_limit_is_small_and_positive(self, limit) -> None:
        assert 1 <= limit <= 200

    def test_every_list_is_cut_and_counted(self, limit) -> None:
        """Outputs, envelopes and the other payloads of a reveal, each past the limit.

        The other payloads are read by the reveal reader, so they are listed (and counted) as
        other glyphs and NOT as envelopes. They used to be reported in ``glyph_envelopes`` too, as
        ``payload_unrendered`` — a payload "the reveal reader did not return" — which is how one
        input came to be described both ways. The envelope list here is the ``limit + 3`` bare
        markers alone."""
        inputs = [_envelope("head")] + [_envelope(f"g{i}") for i in range(limit + 2)] + [b"\x03gly"] * (limit + 3)
        payload = _classified(*([_p2pkh()] * (limit + 4)), limit=limit, inputs=inputs)
        assert len(payload["outputs"]) == limit and payload["outputs_not_listed"]["count"] == 4
        assert len(payload["glyph_envelopes"]) == limit
        assert {env["kind"] for env in payload["glyph_envelopes"]} == {"unreadable"}
        assert payload["glyph_envelopes_not_listed"] == {"count": 3, "by_kind": {"unreadable": 3}}
        assert len(payload["metadata_inputs"]) == limit + 1, "the headline plus the first `limit` others"
        assert payload["metadata_inputs_not_listed"] == {"count": 2}
        assert payload["metadata"]["of_n_payloads"] == limit + 3, "counted over every payload, not the listed ones"

    def test_the_payload_does_not_grow_with_the_transaction(self, limit) -> None:
        """THE BOUND, where the review measured it: what crosses into JavaScript. 3,000 outputs
        past the limit add a few digits, not 3,000 rows."""
        small = json.dumps(_result(*(_v1(i) for i in range(limit + 1)), limit=limit))
        huge = json.dumps(_result(*(_v1(i) for i in range(limit + 3000)), limit=limit))
        assert len(huge) - len(small) < 100, (len(small), len(huge))

    def test_only_the_listed_rows_are_classified_in_full(self, limit, monkeypatch) -> None:
        """The work, not only the payload: a row past the limit is never built. Counted on the
        function every listed row goes through, and the counter is checked to count."""
        from pyrxd.glyph import _inspect_core

        calls = []
        real = _inspect_core._inspect_script

        def counting(*a, **kw):
            calls.append(1)
            return real(*a, **kw)

        monkeypatch.setattr(_inspect_core, "_inspect_script", counting)
        _classified(*(_v1(i) for i in range(limit + 500)), limit=limit)
        assert len(calls) == limit, f"{len(calls)} full classifications for a limit of {limit}"
        calls.clear()
        _result(*(_v1(i) for i in range(limit + 5)), limit=limit, bounded=False)
        assert len(calls) == limit + 5, "without max_rows every row is classified in full, as the CLI needs"

    def test_the_cli_path_is_not_bounded(self, limit) -> None:
        """The honest neighbour: ``max_rows=None`` — every CLI path — lists everything and adds no
        count, so ``pyrxd glyph inspect --fetch`` stays the complete answer the page points at."""
        payload = _result(*(_v1(i) for i in range(limit + 7)), limit=limit, bounded=False)["payload"]
        assert len(payload["outputs"]) == limit + 7
        assert not [key for key in payload if key.endswith("_not_listed")]

    @pytest.mark.parametrize("bad", [-1, 1.5, "100", True])
    def test_the_glue_refuses_a_max_rows_that_is_not_a_whole_number(self, bad) -> None:
        tx = _tx([_p2pkh()])
        result = _glue().inspect_txid_with_raw(tx.txid(), tx.serialize().hex(), None, bad)
        assert result["ok"] is False and "max_rows" in result["error"]

    def test_the_glue_takes_a_javascript_whole_number(self, limit) -> None:
        tx = _tx([_p2pkh()] * 3)
        result = _glue().inspect_txid_with_raw(tx.txid(), tx.serialize().hex(), None, 2.0)
        assert result["ok"] and len(result["payload"]["outputs"]) == 2


# ─────────────────────────────────── the counts are what the classifier decided ──


def _mixed(limit: int) -> list[bytes]:
    """The review's mixed remainder, placed past the listing limit: records of an
    unknown version, a forgery, signed records within and past the CHECKING limit (which counts
    HashMark records, not rows), v1 records, repeated forgeries (byte copies of one already
    checked), more forgeries of the same statement that are NOT byte copies, and plain outputs."""
    forged = _forged(_signed(b"forge-me"))
    return (
        [_p2pkh(i) for i in range(limit)]
        + [_v9(i) for i in range(3)]
        + [forged]
        + [_signed(i.to_bytes(2, "big")) for i in range(limit)]
        + [_v1(i) for i in range(5)]
        + [forged, forged]
        + [_forged(_signed(b"forge-me")) for _ in range(3)]
        + [_signed(b"late-%d" % i) for i in range(4)]
        + [_p2pkh(999)]
    )


class TestTheCountsAreTheClassifiersOwn:
    def test_the_counts_equal_a_full_classification(self, limit) -> None:
        """EXACT: the bounded payload's counts equal the counts of the rows a full classification
        of the same transaction, with the same checking limit, gives past the listing limit."""
        scripts = _mixed(limit)
        assert len(scripts) > limit + 20, "the premise: a remainder worth counting"
        bounded = _classified(*scripts, limit=limit)
        full = _result(*scripts, limit=limit, bounded=False)["payload"]
        rest = full["outputs"][limit:]
        marks = [row["hashmark"] for row in rest if row.get("hashmark")]
        expected = {
            "count": len(rest),
            "first_vout": rest[0]["vout"],
            "last_vout": rest[-1]["vout"],
            "by_type": dict(Counter(row["type"] for row in rest)),
            "hashmark_by_status": dict(Counter(_word(hm) for hm in marks)),
            "not_checked_here": sum(1 for hm in marks if _word(hm) == "not checked here"),
        }
        assert bounded["outputs_not_listed"] == expected
        assert bounded["outputs"] == full["outputs"][:limit], "the listed rows are the full rows"
        # The premise: the remainder really is mixed, so equality above is not two empty tallies.
        assert {"DOES NOT VERIFY", "not checked here", "UNKNOWN VERSION", "NO SIGNATURE", "VERIFIED"} <= set(
            expected["hashmark_by_status"]
        )

    @pytest.mark.parametrize("attest", [True, False], ids=["checked", "past-the-checking-limit"])
    def test_a_summary_types_every_shape_as_the_full_classifier_does(self, attest) -> None:
        """ONE set of branches. A summary is the same `_classify_script` with work skipped, so its
        type must be the full type for every shape the classifier can name — the drift test's
        corpus, whose coverage of every emitted type that test derives from the source."""
        from pyrxd.glyph._inspect_core import _classify_script
        from tests.web.test_inspect_js_render_drift import _corpus

        extra = {
            "v9": _v9(7),
            "signed": _signed(b"s"),
            "forged": _forged(_signed(b"f")),
            "bare-marker": b"\x6a\x08HASHMARK",
        }
        compared = 0
        for name, script in {**_corpus(), **extra}.items():
            full = _classify_script(script.hex(), network="mainnet", attest=attest)
            summary = _classify_script(script.hex(), network="mainnet", attest=attest, summary=True)
            assert summary["type"] == full["type"], name
            assert ("hashmark" in summary) == ("hashmark" in full), name
            if "hashmark" in full:
                assert _word(summary["hashmark"]) == _word(full["hashmark"]), name
                compared += 1
        assert compared >= 5, f"only {compared} HashMark shapes compared — the word check is nearly vacuous"

    def test_the_word_is_the_one_the_panel_prints(self) -> None:
        """The counted word and the drawn panel cannot say different things about one record.
        The one deliberate difference: a record past the checking limit is drawn NOT CHECKED (the
        shared word for an unchecked signature) and counted "not checked here", so the count can
        say the page declined rather than that the curve failed."""
        from pyrxd.glyph._inspect_core import _inspect_script

        shapes = {
            "v1": (_v1(3), True),
            "v9": (_v9(3), True),
            "valid": (_signed(b"ok"), True),
            "forged": (_forged(_signed(b"no")), True),
            "past-the-limit": (_signed(b"later"), False),
        }
        rows = {name: _inspect_script(script.hex(), attest=attest) for name, (script, attest) in shapes.items()}
        rendered = _render({name: {"row": row} for name, row in rows.items()})
        for name, row in rows.items():
            word, text = _word(row["hashmark"]), rendered[name]["output_row"]
            if name == "past-the-limit":
                assert word == "not checked here" and "\nNOT CHECKED\n" in f"\n{text}\n"
            else:
                assert f"\n{word}\n" in f"\n{text}\n", f"{name}: the panel does not lead with {word!r}\n{text}"


# ─────────────────────────────────────── the card says exactly what was left out ──


class TestTheCardSaysExactlyWhatWasLeftOut:
    def test_the_page_does_not_grow_with_the_transaction(self, limit) -> None:
        """The same bound in the DOM: 3,000 more outputs build exactly as much page."""
        small = _classified(*(_v1(i) for i in range(limit + 1)), limit=limit)
        huge = _classified(*(_v1(i) for i in range(limit + 3000)), limit=limit)
        both = _render({"small": {"tx": small}, "huge": {"tx": huge}})
        assert both["huge"]["fetched_tx_card_elements"] == both["small"]["fetched_tx_card_elements"]
        assert both["huge"]["fetched_tx_card_file_inputs"] == limit == both["small"]["fetched_tx_card_file_inputs"]
        text = _flat(both["huge"]["fetched_tx_card"])
        assert f"Outputs (the first {limit} of {limit + 3000})" in text
        assert f"{3000} more outputs are in this transaction" in text

    def test_exactly_the_limit_is_all_drawn_and_nothing_says_otherwise(self, limit) -> None:
        """The honest edge: nothing was left out, so nothing may say something was."""
        payload = _classified(*(_v1(i) for i in range(limit)), limit=limit)
        assert not [key for key in payload if key.endswith("_not_listed")]
        card = _card(payload)
        assert card["fetched_tx_card_file_inputs"] == limit
        text = _flat(card["fetched_tx_card"])
        assert "Outputs (the first" not in text and "not shown here" not in text
        assert "pyrxd glyph inspect" not in text

    def test_one_past_the_limit_is_said_in_the_singular(self, limit) -> None:
        text = _flat(_card(_classified(*(_v1(i) for i in range(limit + 1)), limit=limit))["fetched_tx_card"])
        assert f"1 more output is in this transaction and is not shown here (vout {limit})." in text
        assert "It carries a HashMark record. What this page knows about its signature: 1 NO SIGNATURE." in text

    def test_distinct_signed_records_past_the_limit_are_counted_as_not_checked(self, limit) -> None:
        payload = _classified(*(_signed(f"doc {i}".encode()) for i in range(limit + 5)), limit=limit)
        assert [row["hashmark"]["attestation"]["outcome"] for row in payload["outputs"]] == ["valid"] * limit
        assert payload["outputs_not_listed"]["not_checked_here"] == 5, "the premise: the classifier's own answer"
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
        assert f"pyrxd glyph inspect {payload['txid']} --fetch" in text
        # ORDER: the heading before the first row, the note after the last one.
        assert text.index("Outputs (the first") < text.index("vout 0") < text.index("5 more outputs")

    def test_a_forgery_past_the_limit_is_not_checked_and_a_clean_copy_is_verified(self, limit) -> None:
        """CLEAN: limit+1 copies of one genuine record. FORGED: limit copies and a forgery last.
        The page cannot know the forgery is forged without checking it — so it must SAY it did not
        check it, and the two pages must differ."""
        good = _signed(b"release 1.0\n")
        clean = _classified(*([good] * (limit + 1)), limit=limit)
        dirty = _classified(*([good] * limit), _forged(good), limit=limit)
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
        payload = _classified(*([good] * 3), _forged(good), *([good] * limit), limit=limit)
        card = _card(payload)
        assert "DOES NOT VERIFY" in card["fetched_tx_card"]
        assert any(c.split()[:2] == ["verdict", "verdict-bad"] for c in card["fetched_tx_card_classes"])

    def test_a_mixed_remainder_is_tallied_by_type_and_by_verdict(self, limit) -> None:
        """Only some of the rows left out are marks: the note says how many, and does not call
        the P2PKH rows marks."""
        scripts = [_p2pkh()] * limit + [_v1(1), _p2pkh(), _v1(2), _v1(3), _p2pkh()]
        text = _flat(_card(_classified(*scripts, limit=limit))["fetched_tx_card"])
        assert "By type: 3 op_return-hashmark-v1, 2 p2pkh." in text
        assert "3 of them carry HashMark records. What this page knows about their signatures: 3 NO SIGNATURE." in text
        assert "not checked here" not in text, "a v1 record has no signature, and its NO SIGNATURE costs nothing"

    def test_the_review_mix_is_worded_from_the_classifiers_counts(self, limit) -> None:
        """The review's check: what the note says equals what the classifier
        decided about every row left out — computed here from a FULL classification."""
        scripts = _mixed(limit)
        text = _flat(_card(_classified(*scripts, limit=limit))["fetched_tx_card"])
        full = _result(*scripts, limit=limit, bounded=False)["payload"]["outputs"][limit:]
        truth = Counter(_word(row["hashmark"]) for row in full if row.get("hashmark"))
        said = re.search(r"What this page knows about (?:its|their) signatures?: ([^.]*)\.", text)
        assert said, text
        parsed = {w: int(n) for n, w in re.findall(r"(\d+) ([A-Za-z ]+?)(?:,|$)", said.group(1))}
        assert parsed == dict(truth)

    def test_a_remainder_of_many_types_names_twelve_and_counts_the_rest(self, limit) -> None:
        """The tally of types is itself bounded: it names at most twelve and counts the rest, so
        the note cannot become the flood it reports. Real shapes, from the drift corpus."""
        from tests.web.test_inspect_js_render_drift import _corpus

        shapes = list(_corpus().values())
        payload = _classified(*([_p2pkh()] * limit), *shapes, limit=limit)
        kinds = payload["outputs_not_listed"]["by_type"]
        assert len(kinds) > 12, f"the premise: more than twelve kinds past the limit, got {sorted(kinds)}"
        text = _flat(_card(payload)["fetched_tx_card"])
        rest = len(kinds) - 12
        assert re.search(rf"By type: (\d+ [a-z0-9_-]+, ){{12}}\d+ more of {rest} other kinds?\.", text), text

    def test_a_remainder_with_no_marks_says_nothing_about_signatures(self, limit) -> None:
        text = _flat(_card(_classified(*([_p2pkh()] * (limit + 2)), limit=limit))["fetched_tx_card"])
        assert "By type: 2 p2pkh." in text
        assert "HashMark" not in text.split("By type:", 1)[1]

    def test_the_command_the_note_gives_shows_every_output_with_every_signature_checked(
        self, limit, monkeypatch, tmp_path
    ) -> None:
        """The note's command, run as printed, through the real CLI."""
        import shlex

        from tests.test_hashmark_verify_one_record import _run

        tx = _tx([_signed(f"doc {i}".encode()) for i in range(limit + 3)])
        payload = _glue().inspect_txid_with_raw(tx.txid(), tx.serialize().hex(), limit, limit)["payload"]
        text = _flat(_card(payload)["fetched_tx_card"])
        match = re.search(r"(pyrxd glyph inspect \S+ --fetch)", text)
        assert match, "the note carries no command"
        argv = shlex.split(match.group(1))
        assert argv[:3] == ["pyrxd", "glyph", "inspect"] and argv[3] == tx.txid()
        r = _run(monkeypatch, {tx.txid(): tx.serialize()}, argv[1:], tmp_path)
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
        payload = _classified(b"\x6a" + b"\x00" * 30, limit=limit, inputs=[b"\x03gly"] * (limit + 3))
        assert len(payload["glyph_envelopes"]) == limit
        text = _flat(_card(payload)["fetched_tx_card"])
        assert text.count("UNREADABLE — a 'gly' marker") == limit
        assert f"Glyph envelopes carrying no full payload ({limit + 3})" in text
        assert "3 more envelopes are not shown here: 3 UNREADABLE." in text
        assert f"pyrxd glyph inspect {payload['txid']} --fetch" in text

    def test_the_envelope_list_does_not_grow_with_the_transaction(self, limit) -> None:
        small = _classified(b"\x6a" + b"\x00" * 30, limit=limit, inputs=[b"\x03gly"] * (limit + 1))
        huge = _classified(b"\x6a" + b"\x00" * 30, limit=limit, inputs=[b"\x03gly"] * (limit + 2000))
        both = _render({"small": {"tx": small}, "huge": {"tx": huge}})
        assert both["huge"]["fetched_tx_card_elements"] == both["small"]["fetched_tx_card_elements"]
        assert "2000 more envelopes are not shown here" in _flat(both["huge"]["fetched_tx_card"])

    def test_exactly_the_limit_of_envelopes_says_nothing_is_missing(self, limit) -> None:
        payload = _classified(b"\x6a" + b"\x00" * 30, limit=limit, inputs=[b"\x03gly"] * limit)
        assert "glyph_envelopes_not_listed" not in payload
        text = _flat(_card(payload)["fetched_tx_card"])
        assert text.count("UNREADABLE — a 'gly' marker") == limit
        assert "not shown here" not in text

    def test_other_glyphs_past_the_limit_are_counted(self, limit) -> None:
        inputs = [_envelope(f"g{i}") for i in range(limit + 3)]
        payload = _classified(b"\x6a" + b"\x00" * 30, limit=limit, inputs=inputs)
        text = _flat(_card(payload)["fetched_tx_card"])
        assert f"Other glyphs minted in this transaction ({limit + 2})" in text
        # The headline glyph (input 0) is not an "other" one: inputs 1..limit are listed, the rest counted.
        assert f"input {limit} " in text and f"input {limit + 1} " not in text
        assert f"The first {limit} are listed; 2 more are not shown here." in text


class TestTheRevealsOwnListsAreBounded:
    """A reveal's relationship claims and the delegate burns beside them. Both used to be drawn
    one row per entry, with nothing bounding how many a payload names — measured by the review, a
    258 KB payload of `in` claims drew 6,800 rows and 20,452 elements."""

    @staticmethod
    def _claims(n: int, *, burns: int = 0, limit: int) -> dict:
        from pyrxd.glyph.script import build_delegate_burn_script
        from pyrxd.glyph.types import GlyphRef

        refs = tuple(GlyphRef(txid=(i + 1).to_bytes(32, "big").hex(), vout=0) for i in range(n))
        outputs = [b"\x6a" + b"\x00" * 8] + [
            build_delegate_burn_script(GlyphRef(txid=(10_000 + i).to_bytes(32, "big").hex(), vout=1))
            for i in range(burns)
        ]
        return _classified(*outputs, limit=limit, inputs=[_envelope("many-claims", container_refs=refs)])

    def test_claims_past_the_limit_are_counted_in_their_own_verdict_words(self, limit) -> None:
        payload = self._claims(limit + 50, limit=limit)
        md = payload["metadata"]
        assert len(md["relationships"]) == limit
        assert md["relationships_not_listed"] == {
            "count": 50,
            "groups": [{"kind": "container", "ok": False, "basis": "none", "count": 50}],
        }
        text = _card(payload)["fetched_tx_card"]
        assert text.count("collection claim\n") == limit
        assert "50 more claims: 50 collection claim UNVERIFIED CLAIM (nothing in this tx authorises it)" in _flat(text)

    def test_the_claim_list_does_not_grow_with_the_payload(self, limit) -> None:
        both = _render(
            {
                "small": {"tx": self._claims(limit + 1, limit=limit)},
                "huge": {"tx": self._claims(limit + 400, limit=limit)},
            }
        )
        assert both["huge"]["fetched_tx_card_elements"] == both["small"]["fetched_tx_card_elements"]

    def test_exactly_the_limit_of_claims_says_nothing_is_missing(self, limit) -> None:
        payload = self._claims(limit, limit=limit)
        assert "relationships_not_listed" not in payload["metadata"]
        text = _card(payload)["fetched_tx_card"]
        assert text.count("collection claim\n") == limit and "claims not shown" not in text

    def test_burns_past_the_limit_are_counted_and_the_verdict_counts_them(self, limit) -> None:
        """ "Exactly one burn" is a fact about ALL of them: the verdict must not name the one
        listed burn as THE delegate when more were counted."""
        payload = self._claims(2, burns=limit + 5, limit=limit)
        md = payload["metadata"]
        assert len(md["delegate_burns"]) == limit and md["delegate_burns_not_listed"] == {"count": 5}
        text = _flat(_card(payload)["fetched_tx_card"])
        assert "… and 5 more not shown" in text
        assert "UNRESOLVED — this tx burned a delegate; fetch it to check" in text

    def test_one_burn_is_still_named(self, limit) -> None:
        """The honest neighbour: a single burn is named in the verdict, as before."""
        payload = self._claims(1, burns=1, limit=limit)
        (burn,) = payload["metadata"]["delegate_burns"]
        assert f"UNRESOLVED — this tx burned a delegate ({burn}); fetch it to check" in _flat(
            _card(payload)["fetched_tx_card"]
        )


# ─────────────────────────────────────────── the JSON drawer says what it holds ──


class TestTheJsonDrawerSaysItIsBounded:
    def test_a_cut_list_is_said_in_the_drawer_with_the_commands_for_all_of_it(self, limit) -> None:
        result = _result(*(_v1(i) for i in range(limit + 3000)), limit=limit)
        small = _result(*(_v1(i) for i in range(limit + 1)), limit=limit)
        both = _render({"huge": {"result": result}, "small": {"result": small}})
        text = _flat(both["huge"]["result_block"])
        txid = result["payload"]["txid"]
        assert "Show raw JSON (the lists are cut short)" in text
        assert f"it holds at most {limit} each of the transaction's outputs" in text
        assert f"For all of it: pyrxd glyph inspect {txid} --fetch" in text
        assert f"as JSON, pyrxd --json glyph inspect {txid} --fetch" in text
        # The drawer's JSON is the bounded payload: 3,000 more outputs add digits, not rows.
        assert both["huge"]["json_drawer_chars"] - both["small"]["json_drawer_chars"] < 100
        assert both["huge"]["result_block_elements"] == both["small"]["result_block_elements"]

    def test_a_list_that_was_not_cut_says_nothing_of_the_kind(self, limit) -> None:
        text = _flat(
            _render({"c": {"result": _result(*(_v1(i) for i in range(limit)), limit=limit)}})["c"]["result_block"]
        )
        assert "Show raw JSON" in text and "cut short" not in text and "bounded like the card" not in text

    def test_the_json_command_gives_every_output(self, limit, monkeypatch, tmp_path) -> None:
        """The drawer's command for the whole JSON, run as printed, through the real CLI."""
        import shlex

        from tests.test_hashmark_verify_one_record import _run

        tx = _tx([_v1(i) for i in range(limit + 4)])
        result = _glue().inspect_txid_with_raw(tx.txid(), tx.serialize().hex(), limit, limit)
        text = _flat(_render({"c": {"result": result}})["c"]["result_block"])
        match = re.search(r"(pyrxd --json glyph inspect \S+ --fetch)", text)
        assert match, text
        r = _run(monkeypatch, {tx.txid(): tx.serialize()}, shlex.split(match.group(1))[1:], tmp_path)
        assert r.exit_code == 0, r.output
        full = json.loads(r.output)
        assert len(full["outputs"]) == limit + 4 and not [k for k in full if k.endswith("_not_listed")]


# ─────────────────────────────────────── a small transaction is drawn as before ──


class TestASmallTransactionIsUnchanged:
    def test_the_bound_changes_nothing_under_the_limit(self, limit) -> None:
        """The honest path for every list at once: a reveal with outputs, other glyphs, an
        envelope, claims and a burn — each under the limit — is the same payload and the same
        page with ``max_rows`` as without it."""
        from pyrxd.glyph.script import build_delegate_burn_script
        from pyrxd.glyph.types import GlyphRef

        refs = tuple(GlyphRef(txid=(i + 1).to_bytes(32, "big").hex(), vout=0) for i in range(3))
        outputs = [_p2pkh(), _v1(1), _signed(b"x"), build_delegate_burn_script(GlyphRef(txid="77" * 32, vout=1))]
        inputs = [_envelope("head", container_refs=refs), _envelope("other"), b"\x03gly"]
        bounded = _result(*outputs, limit=limit, inputs=inputs)
        full = _result(*outputs, limit=limit, inputs=inputs, bounded=False)
        assert bounded == full
        rendered = _render({"b": {"result": bounded}, "f": {"result": full}})
        assert rendered["b"]["result_block"] == rendered["f"]["result_block"]
