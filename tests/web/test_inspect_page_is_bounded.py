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
        function every row goes through — a full classification is a call without ``summary`` —
        and the counter is checked to count."""
        from pyrxd.glyph import _inspect_core

        calls = []
        real = _inspect_core._classify_script

        def counting(*a, **kw):
            if not kw.get("summary"):
                calls.append(1)
            return real(*a, **kw)

        monkeypatch.setattr(_inspect_core, "_classify_script", counting)
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


# ─────────────────────── the shape banner describes the WHOLE transaction ──
#
# The banner above the rows (`_detectTxShape`) states counts, presence, absence and agreement:
# "creates N dMint contract UTXOs", "this one does not [carry a commit-nft]", "All N carry the
# same token_ref". It counted `payload.outputs`, which the classifier now cuts at the listing
# limit, so every one of those became a statement about the first 100 outputs. The classifier
# now sends `output_shape`, worked out over every output, whenever it cuts the list.


def _token(i: int):
    from pyrxd.glyph.types import GlyphRef

    return GlyphRef(txid=f"{i + 1:064x}", vout=0)


def _dmint(height: int = 0, *, token: int = 0, reward: int = 100_000, max_height: int = 1000) -> bytes:
    from pyrxd.glyph.dmint.builders import build_dmint_v1_contract_script
    from pyrxd.glyph.types import GlyphRef

    return build_dmint_v1_contract_script(
        height=height,
        contract_ref=GlyphRef(txid=os.urandom(32).hex(), vout=0),
        token_ref=_token(token),
        max_height=max_height,
        reward=reward,
        target=0x7FFFFFFFFFFFFF,
    )


def _commit(is_nft: bool) -> bytes:
    from pyrxd.glyph.script import build_commit_locking_script
    from pyrxd.security.types import Hex20

    return build_commit_locking_script(os.urandom(32), Hex20(b"\x22" * 20), is_nft=is_nft)


def _ft(i: int = 0) -> bytes:
    from pyrxd.glyph.script import build_ft_locking_script
    from pyrxd.security.types import Hex20

    return build_ft_locking_script(Hex20(i.to_bytes(20, "big")), _token(0))


def _mut() -> bytes:
    from pyrxd.glyph.script import build_mutable_nft_script

    return build_mutable_nft_script(_token(3), b"\x33" * 32)


def _banner(card_text: str) -> str:
    """The shape banner: the paragraph between the ``outputs`` count and the first heading."""
    lines = card_text.split("\n")
    after = lines[lines.index("outputs") + 2]
    return "" if after.startswith("Outputs") or after.startswith("Reveal metadata") else after


def _banners(scripts: list[bytes], limit: int, *, inputs: list[bytes] | None = None) -> tuple[str, str]:
    """(the banner the page draws, the banner for the same transaction listed WHOLE)."""
    bounded = _result(*scripts, limit=limit, inputs=inputs)["payload"]
    whole = _result(*scripts, limit=limit, inputs=inputs, bounded=False)["payload"]
    assert "outputs_not_listed" in bounded or len(scripts) <= limit
    both = _render({"bounded": {"tx": bounded}, "whole": {"tx": whole}})
    return _banner(both["bounded"]["fetched_tx_card"]), _banner(both["whole"]["fetched_tx_card"])


class TestTheShapeBannerDescribesTheWholeTransaction:
    def test_a_151_output_dmint_deploy_is_150_contracts(self, limit) -> None:
        """The review's first case: it read "creates 100 dMint contract UTXOs … × 100"."""
        assert limit < 150, "the premise: the deploy is wider than the listing limit"
        page, whole = _banners([_dmint() for _ in range(150)] + [_p2pkh()], limit)
        assert "creates 150 dMint contract UTXOs" in page
        assert "All 150 carry the same token_ref and agree on reward and max_height" in page
        assert "reward × max_height × 150" in page
        assert f"× {limit}." not in page and f"creates {limit} " not in page
        assert page == whole

    def test_a_deploy_commit_whose_commit_nft_is_past_the_limit_carries_one(self, limit) -> None:
        """The review's second case, laid out like the mainnet GLYPH deploy commit a443d9df…878b:
        commit-ft first, P2PKH ref-seeds, the commit-nft second to last, change last. It read
        "Most modern FT deploys also carry a commit-nft singleton; this one does not"."""
        scripts = [_commit(False)] + [_p2pkh(i) for i in range(118)] + [_commit(True), _p2pkh(999)]
        assert len(scripts) == 121 and scripts.index(scripts[-2]) > limit
        page, whole = _banners(scripts, limit)
        assert "This is a V1 dMint deploy commit" in page
        assert "the remaining 118 P2PKH outputs are 1-photon ref-seeds" in page
        assert "this one does not" not in page
        assert page == whole

    def test_an_ft_deploy_whose_commit_nft_is_past_the_limit_is_an_ft_deploy(self, limit) -> None:
        scripts = [_commit(False)] + [_ft(i) for i in range(limit + 5)] + [_commit(True), _p2pkh()]
        page, whole = _banners(scripts, limit)
        assert page.startswith("This is a Glyph FT deploy transaction") and "this one does not" not in page
        assert page == whole

    def test_a_commit_ft_with_no_commit_nft_anywhere_still_says_so(self, limit) -> None:
        """The honest neighbour of the case above: when the commit-nft really is absent from the
        whole transaction, the absence may be stated."""
        page, whole = _banners([_commit(False)] + [_ft(i) for i in range(limit + 5)] + [_p2pkh()], limit)
        assert "this one does not" in page
        assert page == whole

    @pytest.mark.parametrize("field", ["token", "reward", "max_height"])
    def test_a_disagreement_past_the_limit_is_seen(self, limit, field) -> None:
        """Agreement is a claim about EVERY contract: one that differs at vout 140 must stop it."""
        odd = {"token": {"token": 7}, "reward": {"reward": 250_000}, "max_height": {"max_height": 5}}[field]
        scripts = [_dmint(**(odd if i == 140 else {})) for i in range(150)] + [_p2pkh()]
        page, whole = _banners(scripts, limit)
        if field == "token":
            assert "They do NOT all carry the same token_ref" in page
        else:
            assert "All 150 carry the same token_ref, so claims race" in page
            assert "their reward / max_height are not all equal" in page
        assert "agree on reward and max_height" not in page
        assert page == whole

    def test_a_claim_with_no_ft_output_anywhere_says_so(self, limit) -> None:
        page, whole = _banners([_dmint(5)] + [_p2pkh(i) for i in range(limit + 50)], limit)
        assert "This is a dMint claim transaction (height 5 of 1000)" in page
        assert "This transaction has NO ft output" in page
        assert page == whole

    def test_a_claim_whose_ft_output_is_past_the_limit_does_not_say_there_is_none(self, limit) -> None:
        """Presence is known over the whole transaction; the POSITION is not, past the rows."""
        scripts = [_dmint(5)] + [_p2pkh(i) for i in range(limit + 29)] + [_ft()] + [_p2pkh(i) for i in range(20)]
        page, whole = _banners(scripts, limit)
        assert "NO ft output" not in page and "NO ft output" not in whole
        assert f"Only the first {limit} of this transaction's {len(scripts)} outputs are listed here" in page
        assert f"The freshly-minted FT is the ft output at vout {limit + 30}." in whole

    def test_a_small_transaction_gives_the_same_banner_whatever_the_limit(self) -> None:
        """The two derivations — the classifier's `output_shape` and the page's own count of
        complete rows — must say the same thing about one transaction. Every non-claim shape the
        banner knows, cut at every limit from 0 up to its size."""
        shapes = {
            "deploy-commit": [_commit(False), _p2pkh(1), _p2pkh(2), _commit(True), _p2pkh(3)],
            "ft-deploy": [_commit(False), _commit(True), _ft(), _p2pkh()],
            "commit-ft-only": [_commit(False), _ft(), _p2pkh()],
            "commit-nft-only": [_p2pkh(), _commit(True)],
            "dmint-one-token": [_dmint(), _dmint(), _dmint(), _p2pkh()],
            "dmint-mixed-refs": [_dmint(), _dmint(token=1), _dmint(), _p2pkh()],
            "dmint-mixed-terms": [_dmint(), _dmint(reward=7), _dmint(), _p2pkh()],
            "dmint-single": [_p2pkh(), _dmint()],
            "mut": [_p2pkh(), _mut()],
            "plain": [_p2pkh(1), _p2pkh(2)],
        }
        cases, expected = {}, {}
        for name, scripts in shapes.items():
            tx = _tx(scripts)
            for cut in [None, *range(len(scripts) + 1)]:
                result = _glue().inspect_txid_with_raw(tx.txid(), tx.serialize().hex(), None, cut)
                assert result["ok"], result
                cases[f"{name}/{cut}"] = {"tx": result["payload"]}
        rendered = _render(cases)
        for key in cases:
            expected.setdefault(key.split("/")[0], _banner(rendered[f"{key.split('/')[0]}/None"]["fetched_tx_card"]))
            assert _banner(rendered[key]["fetched_tx_card"]) == expected[key.split("/")[0]], key
        # Not vacuous: all but the plain shape draw a banner.
        assert sum(bool(b) for b in expected.values()) == len(shapes) - 1, expected


class TestTheOutputShapeIsEveryOutputs:
    """The classifier's half, exact: `output_shape` equals what the full rows of the same
    transaction give — counted by type, and for dMint rows by the banner's own agreement rule —
    on transactions drawn from a palette of real shapes, at random listing limits."""

    def test_it_equals_the_full_rows(self) -> None:
        import random

        rng = random.Random(720)
        palette = [
            lambda: _p2pkh(rng.randrange(5)),
            lambda: _commit(False),
            lambda: _commit(True),
            lambda: _ft(),
            lambda: _v1(rng.randrange(5)),
            lambda: b"\x6a\x04test",
            lambda: _dmint(rng.choice([0, 0, 3]), token=rng.randrange(2), reward=rng.choice([1, 1, 2])),
            lambda: _dmint(0, max_height=rng.choice([1000, 1000, 9])),
        ]
        compared = with_dmint = 0
        for _ in range(120):
            scripts = [rng.choice(palette)() for _ in range(rng.randint(1, 14))]
            cut = rng.randint(0, len(scripts) - 1)
            tx = _tx(scripts)
            bounded = _glue().inspect_txid_with_raw(tx.txid(), tx.serialize().hex(), None, cut)["payload"]
            rows = _glue().inspect_txid_with_raw(tx.txid(), tx.serialize().hex(), None, None)["payload"]["outputs"]
            dm = [r for r in rows if r["type"] == "dmint"]

            def agree(field, dm=dm):
                return all(r.get(field) is not None and r.get(field) == dm[0].get(field) for r in dm)

            expected: dict = {"by_type": dict(Counter(r["type"] for r in rows))}
            if dm:
                expected["dmint"] = {
                    "count": len(dm),
                    "first_vout": dm[0]["vout"],
                    "first_height": dm[0]["height"],
                    "first_max_height": dm[0]["max_height"],
                    "same_token_ref": agree("token_ref_outpoint"),
                    "same_reward": agree("reward"),
                    "same_max_height": agree("max_height"),
                }
                with_dmint += 1
            assert bounded["output_shape"] == expected
            listed = Counter(r["type"] for r in bounded["outputs"])
            assert dict(listed + Counter(bounded["outputs_not_listed"]["by_type"])) == expected["by_type"]
            compared += 1
        assert compared == 120 and with_dmint > 30, (compared, with_dmint)

    def test_nothing_cut_means_no_shape_and_the_cli_gets_none(self, limit) -> None:
        """Byte-identical for every caller whose list was not cut, and for the CLI, which passes
        no `max_rows`."""
        assert "output_shape" not in _classified(*([_p2pkh()] * limit), limit=limit)
        assert "output_shape" not in _result(*([_p2pkh()] * (limit + 9)), limit=limit, bounded=False)["payload"]

    def test_an_only_vout_listing_carries_no_shape(self) -> None:
        """One output enumerated says nothing about the rest, so no whole-transaction shape."""
        from pyrxd.glyph.inspect import classify_raw_tx

        tx = _tx([_dmint(5), _p2pkh(), _p2pkh()])
        payload = classify_raw_tx(tx.txid(), tx.serialize(), only_vout=1, max_rows=0)
        assert payload["outputs_not_listed"]["count"] == 1 and "output_shape" not in payload


_WIDE = (1 << 1100) + 12345  # 1,101 bits: past the width at which the payload carries text
_WIDE_2 = (1 << 1100) + 99999  # the same width, a different value


def _wide_dmint(reward: int) -> bytes:
    """A dMint contract whose reward is *reward*, however wide: `_dmint`'s script with its one
    reward push (100,000, pushed as ``03 a0 86 01``) replaced, and parsed back to check it."""
    from pyrxd.glyph.dmint import DmintState

    script, push = _dmint(), b"\x03\xa0\x86\x01"
    assert script.count(push) == 1
    raw = reward.to_bytes((reward.bit_length() + 8) // 8, "little")  # sign bit clear
    wide = script.replace(push, b"\x4c" + bytes([len(raw)]) + raw)
    assert DmintState.from_script(wide).reward == reward
    return wide


class TestAWideRewardIsComparedAsAnInteger:
    """The payload carries an integer wider than 1024 bits as the text "<oversized integer: N
    bits>". `_OutputShape` compared the LISTED rows after that replacement and the counted ones
    before it, so 150 contracts sharing one 1,101-bit reward read "not all equal" and two with
    different 1,101-bit rewards read "agree". Each case is drawn cut (the classifier's
    `output_shape`) and uncut (the page's own count of the rows, which sees only the text)."""

    _AGREE = "agree on reward and max_height"
    _DIFFER = "their reward / max_height are not all equal"
    _CANNOT = "This page cannot tell whether all"

    def test_one_wide_reward_past_the_limit_agrees_with_itself(self, limit) -> None:
        """Case A: listed rows and counted rows compared as the same integer."""
        page, whole = _banners([_wide_dmint(_WIDE) for _ in range(150)] + [_p2pkh()], limit)
        assert f"All 150 carry the same token_ref and {self._AGREE}" in page
        assert self._DIFFER not in page
        assert self._CANNOT in whole and self._AGREE not in whole and self._DIFFER not in whole

    def test_two_different_wide_rewards_within_the_limit_differ(self, limit) -> None:
        """Case B: both listed, both drawn as the same text, and different integers."""
        scripts = [_wide_dmint(_WIDE), _wide_dmint(_WIDE_2)] + [_p2pkh(i) for i in range(limit + 20)]
        bounded = _classified(*scripts, limit=limit)
        rewards = [row["reward"] for row in bounded["outputs"] if row["type"] == "dmint"]
        assert rewards == ["<oversized integer: 1101 bits>"] * 2, "the premise: the rows read alike"
        assert bounded["output_shape"]["dmint"]["same_reward"] is False
        page, _whole = _banners(scripts, limit)
        assert self._DIFFER in page and self._AGREE not in page

    @pytest.mark.parametrize(
        "rewards, words",
        [
            ((_WIDE, _WIDE_2), _CANNOT),  # the text is alike and the integers are not
            ((_WIDE, _WIDE), _CANNOT),  # the text is alike and so are the integers: still unknown here
            ((_WIDE, 100_000), _DIFFER),  # a number and the text are never one integer
            ((100_000, 100_000), _AGREE),  # the ordinary controls
            ((100_000, 5), _DIFFER),
        ],
        ids=["wide-different", "wide-equal", "wide-beside-ordinary", "ordinary-equal", "ordinary-different"],
    )
    def test_uncut_the_page_claims_only_what_it_can_compare(self, limit, rewards, words) -> None:
        scripts = [_wide_dmint(r) if r.bit_length() > 64 else _dmint(reward=r) for r in rewards] + [_p2pkh()]
        payload = _classified(*scripts, limit=limit)
        assert "output_shape" not in payload, "the premise: nothing cut, so the page counts the rows"
        page = _banner(_card(payload)["fetched_tx_card"])
        assert words in page, page
        assert [w for w in (self._AGREE, self._DIFFER, self._CANNOT) if w in page] == [words], page

    @pytest.mark.parametrize("reward", [100_000, 5], ids=["ordinary-equal", "ordinary-different"])
    def test_cut_ordinary_rewards_are_compared_as_before(self, limit, reward) -> None:
        scripts = [_dmint(reward=reward if i == 140 else 100_000) for i in range(150)] + [_p2pkh()]
        page, whole = _banners(scripts, limit)
        assert (self._AGREE if reward == 100_000 else self._DIFFER) in page and page == whole


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


def _update(fields: dict) -> bytes:
    """An input carrying a PARTIAL update envelope — no ``p``, only the fields being changed."""
    import cbor2

    from pyrxd.glyph.payload import build_reveal_scriptsig_suffix

    return _SIG + build_reveal_scriptsig_suffix(cbor2.dumps(fields))


class TestAnUpdatesFieldsAreBounded:
    """An update envelope's key set is the publisher's to choose, and the classifier used to send
    every field to the page, which draws at most 32 per level. Measured by the review under
    Pyodide in Node (not a browser): 16 inputs each carrying a 21,000-field update took 13.11 s and
    389 MB and made a 9.85M-character drawer, with nothing for `max_rows` to cut. A bounded call
    now sends each envelope's fields as the page draws them and counts the rest."""

    @staticmethod
    def _envelopes(fields: dict, limit: int, n: int = 1) -> tuple[dict, dict]:
        """(the page's payload, the same transaction unbounded) for *n* copies of an update."""
        inputs = [_update(fields)] * n
        bounded = _result(b"\x6a", limit=limit, inputs=inputs)["payload"]
        whole = _result(b"\x6a", limit=limit, inputs=inputs, bounded=False)["payload"]
        return bounded, whole

    def test_a_flood_of_fields_is_cut_to_what_is_drawn_and_counted_exactly(self, limit) -> None:
        fields = {f"k{i:05d}": i for i in range(3000)} | {
            "attrs": {"target": "1BoatSLRHtKNngkdXEeobR76b53LETtpyT"} | {f"a{i:05d}": i for i in range(3000)},
            "a-meta": {f"m{i:05d}": i for i in range(3000)},
        }
        bounded, whole = self._envelopes(fields, limit, n=4)
        for got, full in zip(bounded["glyph_envelopes"], whole["glyph_envelopes"], strict=True):
            kept = got["fields"]
            assert (
                len([k for k in kept if k != "attrs"]) == 32 and len(kept["attrs"]) == 33 and len(kept["a-meta"]) == 32
            )
            assert kept["attrs"]["target"] == full["fields"]["attrs"]["target"]
            assert got["fields_not_listed"] == {
                "count": len(full["fields"]) - 1 - 32,
                "within": {"attrs": len(full["fields"]["attrs"]) - 33, "a-meta": len(full["fields"]["a-meta"]) - 32},
            }
            for key, value in kept.items():  # what is sent is what the whole envelope says
                if isinstance(value, dict):
                    assert all(full["fields"][key][ik] == iv for ik, iv in value.items())
                else:
                    assert full["fields"][key] == value
        assert len(json.dumps(bounded)) * 20 < len(json.dumps(whole)), "the premise: the bound is what shrank it"

    def test_the_payload_does_not_grow_with_the_envelope(self, limit) -> None:
        small, _ = self._envelopes({f"k{i:05d}": i for i in range(100)}, limit)
        huge, _ = self._envelopes({f"k{i:05d}": i for i in range(20_000)}, limit)
        assert len(json.dumps(huge)) - len(json.dumps(small)) < 100

    def test_the_card_draws_what_it_would_have_drawn_from_the_whole_envelope(self, limit) -> None:
        """The same fields, the same values, the same counts.

        THE ORDER IS JAVASCRIPT'S. The page sorts keys by UTF-16 code unit; Python sorts by code
        point, and the two disagree once a key has a character past U+FFFF: "\U0001f600" (a
        surrogate pair, D83D DE00) sorts BEFORE "\uff01" in JavaScript and after it in Python.
        Twenty keys of each, cut at 32, keep a different set in each order — so a classifier
        picking by Python's order would send fields the page would not have drawn first. Each
        level is checked, and a random mix beside them."""
        import random

        rng = random.Random(5)
        alphabet = ["a", "b", "Z", "é", "\uff01", "\U0001f600", "\u4e2d", "1", "10", "2"]

        def key() -> str:
            return "".join(rng.choice(alphabet) for _ in range(rng.randint(1, 4)))

        def astral_and_bmp(tag: str) -> dict:
            return {f"{c}{tag}{i:02d}": f"{tag}{i}" for c in ("\U0001f600", "\uff01") for i in range(20)}

        fields = astral_and_bmp("t") | {
            "attrs": {"target": "t"} | astral_and_bmp("a"),
            "a-meta": astral_and_bmp("m"),
        }
        mixed = {key(): key() for _ in range(90)} | {"attrs": {key(): rng.randint(0, 9) for _ in range(90)}}
        for case in (fields, mixed):
            bounded, whole = self._envelopes(case, limit)
            assert bounded["glyph_envelopes"][0]["fields_not_listed"]["count"] > 0, "the premise: something was cut"
            both = _render({"b": {"tx": bounded}, "w": {"tx": whole}})
            assert both["b"]["fetched_tx_card"] == both["w"]["fetched_tx_card"]
        drawn = _render({"b": {"tx": self._envelopes(fields, limit)[0]}})["b"]["fetched_tx_card"]
        # The premise, on the page: the first 32 in JavaScript's order are all twenty astral keys
        # and then BMP ones — eleven at the top level, where "a-meta" sorts first and takes a
        # place, and twelve in `attrs`, where `target` is drawn on its own. (The map-valued field
        # is one line, capped at 200 characters, so it is checked by the equality above.)
        for tag, bmp_drawn in (("t", 11), ("a", 12)):
            assert all(f"{tag}{i}\n" in drawn for i in range(20)), tag
            assert f"\uff01{tag}{bmp_drawn - 1:02d}" in drawn and f"\uff01{tag}{bmp_drawn:02d}" not in drawn, tag

    def test_an_update_the_page_draws_whole_is_sent_whole(self, limit) -> None:
        """The honest path: nothing past the cap, nothing cut, and no count."""
        fields = {f"k{i}": i for i in range(32)} | {"attrs": {"target": "t"} | {f"a{i}": i for i in range(32)}}
        bounded, whole = self._envelopes(fields, limit)
        assert bounded == whole and "fields_not_listed" not in bounded["glyph_envelopes"][0]

    def test_a_map_valued_field_is_drawn_rather_than_as_object_object(self, limit) -> None:
        """A field whose value is a map was drawn as `String(value)`: "[object Object]"."""
        bounded, _ = self._envelopes({"meta": {"x": "1", "y": "2"}}, limit)
        text = _flat(_card(bounded)["fetched_tx_card"])
        assert "meta x=1, y=2" in text and "[object Object]" not in text


def _refs(carried: int, named: int) -> bytes:
    """One output naming *carried* distinct refs through 0xd0 and *named* through 0xd2 — the
    review's shape: a script's author chooses how many refs it names."""
    return b"".join(b"\xd0" + i.to_bytes(32, "little") + b"\x00" * 4 for i in range(carried)) + b"".join(
        b"\xd2" + (i + 10**6).to_bytes(32, "little") + b"\x00" * 4 for i in range(named)
    )


class TestAnOutputsRefsAreBounded:
    """One listed row carried every ref its script names: measured by the review, one 3.7 MB
    output naming 100,000 refs made a 22.6M-character drawer and 300,042 elements. A bounded
    call now sends at most 32 of each ref list, the ones the page draws, and counts the rest."""

    @staticmethod
    def _rows(carried: int, named: int, limit: int) -> tuple[dict, dict]:
        """(the page's row, the same output listed WHOLE) for one ref-heavy output."""
        scripts = [_refs(carried, named), _p2pkh()]
        bounded = _result(*scripts, limit=limit)["payload"]["outputs"][0]
        whole = _result(*scripts, limit=limit, bounded=False)["payload"]["outputs"][0]
        assert bounded["type"] == whole["type"] == "unknown"
        return bounded, whole

    def test_each_ref_list_is_cut_to_what_is_drawn_and_counted_exactly(self, limit) -> None:
        from pyrxd.glyph._inspect_core import _HUMAN_ENTRY_CAP

        bounded, whole = self._rows(100, 150, limit)
        assert len(whole["input_refs"]) == 100 and len(whole["referenced_refs"]) == 150, "the CLI keeps every ref"
        assert bounded["input_refs"] == whole["input_refs"][:_HUMAN_ENTRY_CAP]
        assert bounded["referenced_refs"] == whole["referenced_refs"][:_HUMAN_ENTRY_CAP]
        assert bounded["input_refs_not_listed"] == {"count": 100 - _HUMAN_ENTRY_CAP}
        assert bounded["referenced_refs_not_listed"] == {"count": 150 - _HUMAN_ENTRY_CAP}
        assert bounded["token_bearing"] is True, "decided over every ref, not the ones sent"
        text = _card(_classified(_refs(100, 150), _p2pkh(), limit=limit))["fetched_tx_card"]
        assert text.count("ref (0xd0)") == _HUMAN_ENTRY_CAP and text.count("ref (0xd2)") == _HUMAN_ENTRY_CAP
        assert f"… and {100 - _HUMAN_ENTRY_CAP} more TOKEN-BEARING refs not shown" in text
        assert f"… and {150 - _HUMAN_ENTRY_CAP} more named refs not shown" in text

    def test_the_page_does_not_grow_with_the_refs(self, limit) -> None:
        small = _result(_refs(40, 40), _p2pkh(), limit=limit)
        huge = _result(_refs(5_000, 5_000), _p2pkh(), limit=limit)

        def row_without_its_script(result: dict) -> dict:
            """The row less `hex` and `length`, which the script's own bytes bound, and nothing cuts."""
            return {k: v for k, v in result["payload"]["outputs"][0].items() if k not in ("hex", "length")}

        assert len(json.dumps(row_without_its_script(huge))) - len(json.dumps(row_without_its_script(small))) < 100
        both = _render({"small": {"result": small}, "huge": {"result": huge}})
        assert both["huge"]["result_block_elements"] == both["small"]["result_block_elements"]

    def test_a_row_the_page_draws_whole_is_sent_whole(self, limit) -> None:
        """The honest path: 32 of each is under the cap — nothing cut, no count, the same row."""
        bounded, whole = self._rows(32, 32, limit)
        assert bounded == whole and not [k for k in bounded if k.endswith("_not_listed")]

    def test_the_lists_cut_are_every_list_a_row_carries(self) -> None:
        """DERIVED: every shape the drift corpus holds (whose coverage of every type the classifier
        emits that test derives from the source), classified in full, and every list-valued field
        found at any depth of its row. A row gaining another list fails here rather than growing
        with the transaction."""
        from pyrxd.glyph._inspect_core import _ROW_LISTS, _classify_script
        from tests.web.test_inspect_js_render_drift import _corpus

        def lists(value) -> set[str]:
            found: set[str] = set()
            for key, inner in value.items() if isinstance(value, dict) else ():
                found |= {key} if isinstance(inner, (list, tuple)) else lists(inner)
            return found

        rows = [_classify_script(script.hex(), network="mainnet") for script in _corpus().values()]
        assert set().union(*(lists(row) for row in rows)) == set(_ROW_LISTS)
        assert sum(bool(row.get("input_refs")) for row in rows) >= 1, "the premise: a corpus row carries a ref"


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
