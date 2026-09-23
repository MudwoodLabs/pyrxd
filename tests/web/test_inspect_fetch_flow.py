"""/inspect/'s "Fetch from network" flow, end to end: what the page fetches, what it hands each
Python bridge, and what it then DRAWS.

``inspect_fetch_flow_harness.mjs`` runs the page's own ``onFetchTxid`` against a stub ElectrumX
server and records every argument it passes to the two bridges — the classifier
(``glue.inspect_txid_with_raw``) and the binding step (``glue.spent_output_binding``). Each bridge
answers from a canned list, and every canned answer here is computed by the REAL ``glue.py`` on
the arguments the page really passed: a first run records the binding step's arguments, the real
glue answers them, and a second run renders that answer after checking the page passed the same
arguments again. So the rendered text asserted on is what the page draws for the real answer —
not the harness's own "no canned result" error card, which is where every flow used to end.
``test_inspect_spent_tx_is_checked.py`` covers the Python half on its own.

Properties, each a defect this change fixes:

* **A server that answers with a different transaction is refused, on every fetch.** The page's
  second fetch — the commit a reveal spent — was checked by nothing, so a server could answer
  with a transaction of its own carrying a commit to the envelope on screen and the page printed
  ``bound``. The check now lives in ``fetchRawTxFromElectrumx``, which every raw fetch on both
  pages goes through.
* **A spent transaction the page could not get is SAID, not swallowed** — in the drawn
  ``payload binding`` row and its ``detail``, not "was not supplied".
* **The binding step does not classify the transaction again.** It used to be a second full
  ``inspect_txid_with_raw``; it is one ``spent_output_binding`` call.
* **A failed first fetch is advised by what failed.** A server that answered with a different
  transaction was reachable, and is not told to be checked for reachability.
* **The page passes its row limit as the classifier's checking limit AND its listing limit.**
"""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess  # nosec B404 — fixed argv, no shell, repo-local script
import sys
from pathlib import Path

import pytest

# Every ``pyrxd`` import is LAZY — see the note in ``test_inspect_js_render_drift.py``.

_REPO_ROOT = Path(__file__).resolve().parents[2]
_HARNESS = _REPO_ROOT / "tests" / "web" / "inspect_fetch_flow_harness.mjs"
_GLUE = _REPO_ROOT / "docs" / "inspect_static" / "inspect" / "glue.py"


def _require_node() -> str:
    node = shutil.which("node")
    if node is None:
        if os.environ.get("PYRXD_SKIP_JS_RENDER_GUARD") == "1":
            pytest.skip("node is missing and PYRXD_SKIP_JS_RENDER_GUARD=1 — the inspect fetch flow is UNGUARDED")
        pytest.fail("node is required to drive inspect.js's fetch flow (or set PYRXD_SKIP_JS_RENDER_GUARD=1)")
    return node


def _glue():
    spec = importlib.util.spec_from_file_location("pyrxd_inspect_glue_flow", _GLUE)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["pyrxd_inspect_glue_flow"] = module
    spec.loader.exec_module(module)
    return module


def _envelope(name: str) -> tuple[bytes, bytes]:
    from pyrxd.glyph.payload import build_reveal_scriptsig_suffix, encode_payload
    from pyrxd.glyph.types import GlyphMetadata, GlyphProtocol

    cbor, _ = encode_payload(GlyphMetadata(protocol=[GlyphProtocol.NFT], name=name))
    return build_reveal_scriptsig_suffix(cbor), cbor


def _tx(outputs, inputs):
    from pyrxd.script.script import Script
    from pyrxd.transaction.transaction import Transaction
    from pyrxd.transaction.transaction_input import TransactionInput
    from pyrxd.transaction.transaction_output import TransactionOutput

    tx = Transaction(tx_inputs=[], tx_outputs=[TransactionOutput(Script(s), v) for s, v in outputs])
    ins = []
    for source_txid, vout, unlocking in inputs:
        inp = TransactionInput(source_txid=source_txid, source_output_index=vout)
        inp.unlocking_script = Script(unlocking)
        ins.append(inp)
    tx.inputs = ins
    return tx


def _commit_for(cbor: bytes, amount: int = 1000):
    from pyrxd.glyph.script import build_commit_locking_script
    from pyrxd.hash import hash256
    from pyrxd.security.types import Hex20

    return _tx([(build_commit_locking_script(hash256(cbor), Hex20(os.urandom(20)), is_nft=True), amount)], [])


def _world(shown: str = "honest", committed: str | None = None):
    """(reveal, the real commit it spent, a FORGED commit to the envelope on screen)."""
    suffix, shown_cbor = _envelope(shown)
    _, committed_cbor = _envelope(committed if committed is not None else shown)
    commit = _commit_for(committed_cbor)
    unlocking = b"\x47" + b"\x00" * 71 + b"\x21" + b"\x02" * 33 + suffix
    reveal = _tx([(b"\x6a" + b"\x00" * 8, 0)], [(commit.txid(), 0, unlocking)])
    forged = _commit_for(shown_cbor, amount=999)
    assert forged.txid() != commit.txid()
    return reveal, commit, forged


@pytest.fixture(scope="module")
def limit() -> int:
    n = _flow("00" * 32, {}, [])["__constants__"]["max_rows_shown"]
    assert isinstance(n, int) and n > 0, f"inspect.js exposes no MAX_ROWS_SHOWN (got {n!r})"
    return n


def _first_pass(tx, limit: int) -> dict:
    """What the page's FIRST classification returns — the real one, computed by the real glue on
    the arguments the flow is asserted (below) to pass."""
    return _glue().inspect_txid_with_raw(tx.txid(), tx.serialize().hex(), limit, limit)


def _flow(txid: str, server: dict, glue_returns: list, binding_returns: list | None = None) -> dict:
    proc = subprocess.run(  # nosec B603 — fixed argv, no shell, repo-local script
        [_require_node(), str(_HARNESS)],
        input=json.dumps(
            {"txid": txid, "server": server, "glue_returns": glue_returns, "binding_returns": binding_returns or []}
        ),
        capture_output=True,
        text=True,
        check=False,
        cwd=str(_REPO_ROOT),
    )
    if proc.returncode != 0:
        pytest.fail(f"fetch-flow harness failed (exit {proc.returncode}):\n{proc.stderr}")
    return json.loads(proc.stdout)


def _run(reveal, server: dict, limit: int) -> dict:
    """The whole flow with REAL answers from both bridges, in two passes.

    Pass 1 records what the page hands the binding step. The real glue answers exactly that, and
    pass 2 runs again with the answer, asserting the page asked the same thing both times — so
    what pass 2 draws is the page's drawing of the real binding for the real arguments."""
    first = [_first_pass(reveal, limit)]
    recorded = _flow(reveal.txid(), server, first)
    answers = [_glue().spent_output_binding(*call) for call in recorded["binding_calls"]]
    flow = _flow(reveal.txid(), server, first, answers)
    assert flow["glue_calls"] == recorded["glue_calls"]
    assert flow["binding_calls"] == recorded["binding_calls"]
    assert "harness: no canned" not in flow["rendered"], "the flow ended on the harness's own error"
    flow["binding_answers"] = answers
    return flow


def _drawn_binding(flow: dict) -> tuple[str, str | None]:
    """The rendered ``payload binding`` row, and its ``payload binding detail`` row if any —
    read off the drawn card, one text node per line."""
    lines = flow["rendered"].split("\n")
    assert "payload binding" in lines, f"no payload binding row was drawn:\n{flow['rendered']}"
    value = lines[lines.index("payload binding") + 1]
    detail = lines[lines.index("payload binding detail") + 1] if "payload binding detail" in lines else None
    return value, detail


# ─────────────────────────────────── the second fetch is checked, and its failure is said ──


class TestTheSpentTransactionTheServerSends:
    def test_the_real_commit_reaches_the_binding_step_and_binds(self, limit) -> None:
        """The honest path, and the neighbour of every refusal below."""
        reveal, commit, _forged = _world()
        server = {reveal.txid(): {"hex": reveal.serialize().hex()}, commit.txid(): {"hex": commit.serialize().hex()}}
        flow = _run(reveal, server, limit)
        assert flow["requested"] == [reveal.txid(), commit.txid()]
        raw = reveal.serialize().hex()
        assert flow["glue_calls"] == [[reveal.txid(), raw, limit, limit]], "the transaction was classified twice"
        assert flow["binding_calls"] == [[reveal.txid(), raw, commit.serialize().hex(), ""]]
        assert flow["binding_answers"][0]["binding"]["state"] == "bound"
        assert _drawn_binding(flow) == ("bound — the spent commit committed to exactly this payload", None)

    def test_a_commit_to_a_different_payload_is_drawn_as_a_mismatch(self, limit) -> None:
        """The honest server, the dishonest reveal: the real commit committed to another payload."""
        reveal, commit, _forged = _world("EVIL", "real-token")
        server = {reveal.txid(): {"hex": reveal.serialize().hex()}, commit.txid(): {"hex": commit.serialize().hex()}}
        value, detail = _drawn_binding(_run(reveal, server, limit))
        assert value.startswith("mismatch — THE SPENT COMMIT COMMITTED TO A DIFFERENT PAYLOAD")
        assert detail is None

    @pytest.mark.parametrize("shown, committed", [("honest", None), ("EVIL", "real-token")])
    def test_a_server_answering_with_a_different_transaction_is_refused(self, limit, shown, committed) -> None:
        """The reviewer's case, through the page. Asked for the commit, the server answers with a
        transaction of its own committing to the envelope on screen. It used to reach the
        classifier and read ``bound`` — for the attack too, where the real commit committed to a
        different payload. Now the fetch refuses it and the page SAYS so, in the drawn row."""
        from pyrxd.glyph._inspect_core import SPENT_TX_NOT_OBTAINED

        reveal, commit, forged = _world(shown, committed)
        server = {reveal.txid(): {"hex": reveal.serialize().hex()}, commit.txid(): {"hex": forged.serialize().hex()}}
        flow = _run(reveal, server, limit)
        assert flow["requested"] == [reveal.txid(), commit.txid()]
        (call,) = flow["binding_calls"]
        assert call[2] == "", "the forged transaction reached the binding step"
        said = f"the server's answer is not the transaction asked for: it hashes to {forged.txid()}"
        assert call[3] == said
        value, detail = _drawn_binding(flow)
        assert value == f"unchecked — {SPENT_TX_NOT_OBTAINED}"
        assert detail == said
        assert "was not supplied" not in flow["rendered"]

    def test_a_server_that_refuses_the_commit_is_said_too(self, limit) -> None:
        from pyrxd.glyph._inspect_core import SPENT_TX_NOT_OBTAINED

        reveal, commit, _forged = _world()
        server = {reveal.txid(): {"hex": reveal.serialize().hex()}, commit.txid(): {"error": "daemon busy"}}
        flow = _run(reveal, server, limit)
        (call,) = flow["binding_calls"]
        assert call[2:] == ["", "server error: daemon busy"]
        assert _drawn_binding(flow) == (f"unchecked — {SPENT_TX_NOT_OBTAINED}", "server error: daemon busy")
        assert "was not supplied" not in flow["rendered"]

    def test_a_binding_step_that_answers_nothing_does_not_leave_was_not_supplied(self, limit) -> None:
        """The fallback for a binding step that returns an error: the first pass's "was not
        supplied" must not stand for a transaction the page asked for."""
        reveal, commit, _forged = _world()
        server = {reveal.txid(): {"hex": reveal.serialize().hex()}, commit.txid(): {"hex": commit.serialize().hex()}}
        flow = _flow(reveal.txid(), server, [_first_pass(reveal, limit)], [{"ok": False, "error": "boom"}])
        value, detail = _drawn_binding(flow)
        assert value.startswith("unchecked — ") and "was not supplied" not in value
        assert detail == "boom"


# ──────────────────────────────── the FIRST fetch is checked by the same function ──


class TestTheTransactionAskedForIsTheOneThatCameBack:
    def test_a_different_transaction_never_reaches_the_classifier(self, limit) -> None:
        reveal, commit, _forged = _world()
        flow = _flow(reveal.txid(), {reveal.txid(): {"hex": commit.serialize().hex()}}, [])
        assert flow["glue_calls"] == [] and flow["binding_calls"] == [], "a transaction nobody asked for was used"
        assert (
            f"fetch failed: the server's answer is not the transaction asked for: it hashes to {commit.txid()}"
            in (flow["rendered"])
        )

    def test_uppercase_hex_from_the_server_is_still_the_same_transaction(self, limit) -> None:
        """A guard that refuses valid work is a bug: hex case is not part of a transaction."""
        plain = _tx([(b"\x6a" + b"\x00" * 30, 0)], [("ab" * 32, 0, b"\x00")])
        flow = _flow(
            plain.txid(), {plain.txid(): {"hex": plain.serialize().hex().upper()}}, [_first_pass(plain, limit)]
        )
        assert len(flow["glue_calls"]) == 1

    @pytest.mark.parametrize(
        "reply, words",
        [("abc", "odd number of hex digits"), ("zz", "non-hex string"), ("", "empty string, not a transaction")],
        ids=["odd-length", "not-hex", "empty"],
    )
    def test_an_unusable_reply_is_named_for_what_is_wrong_with_it(self, limit, reply, words) -> None:
        flow = _flow("ab" * 32, {"ab" * 32: {"hex": reply}}, [])
        assert flow["glue_calls"] == []
        assert words in flow["rendered"]


class TestAFailedFirstFetchIsAdvisedByWhatFailed:
    """/verify/ branches on the wire's ``err.kind``; /inspect/ gave every failure the same
    "check that the server is reachable" advice — including a server that WAS reachable and
    answered with a different transaction."""

    @staticmethod
    def _hint(flow: dict) -> str:
        lines = flow["rendered"].split("\n")
        failed = next(i for i, line in enumerate(lines) if line.startswith("fetch failed: "))
        return lines[failed + 1]

    def test_a_different_transaction_is_not_blamed_on_reachability(self) -> None:
        reveal, commit, _forged = _world()
        hint = self._hint(_flow(reveal.txid(), {reveal.txid(): {"hex": commit.serialize().hex()}}, []))
        assert "reachable" not in hint
        assert "do not have that fingerprint" in hint and f"glyph inspect {reveal.txid()} --fetch" in hint

    def test_a_server_that_cannot_be_reached_is_told_to_be_checked(self) -> None:
        """The honest neighbour: the one kind the old advice was right for keeps it."""
        hint = self._hint(_flow("ab" * 32, {"ab" * 32: {"close": True}}, []))
        assert "could not be reached" in hint and "reachable" in hint

    # REAL error frames. The first three are aiorpcX 0.25.0's own (``aiorpcx/session.py``,
    # ``_throttled_request``; codes from ``aiorpcx/jsonrpc.py``), which every ElectrumX server
    # answers through; "not-found" is what the page's public endpoint was measured to send
    # (2026-09-23) for a txid it does not have, and "bad-request" what it sent for "zz".
    _TRANSIENT = {
        "server-busy": (-102, "server busy - request timed out"),
        "excessive-resource-usage": (-101, "excessive resource usage"),
        "internal-server-error": (-32603, "internal server error"),
    }
    _NOT_FOUND = (
        2,
        "daemon error: DaemonError({'code': -5, 'message': 'No such mempool or blockchain transaction. "
        "Use gettransaction for wallet transactions.'})",
    )

    def _refused(self, code, message) -> tuple[str, str]:
        """(the drawn error line, the drawn hint) for a refusal carrying this code and message."""
        entry = {"error": message} if code is None else {"error": message, "code": code}
        lines = _flow("ab" * 32, {"ab" * 32: entry}, [])["rendered"].split("\n")
        failed = next(i for i, line in enumerate(lines) if line.startswith("fetch failed: "))
        return lines[failed], lines[failed + 1]

    @pytest.mark.parametrize("case", sorted(_TRANSIENT))
    def test_a_busy_or_failing_server_is_not_called_a_wrong_number(self, case) -> None:
        """ "retrying will not change this answer" was the advice for EVERY refusal, and for these
        three retrying is the one thing that can."""
        error, hint = self._refused(*self._TRANSIENT[case])
        assert error == f"fetch failed: server error: {self._TRANSIENT[case][1]}"
        assert "declined to answer this time" in hint and "Try again in a moment" in hint
        assert "number" not in hint.split("CLI")[0], hint
        assert "will not change" not in hint and "commonest" not in hint

    def test_a_transaction_the_node_does_not_have_says_the_number_may_be_wrong(self) -> None:
        """The honest neighbour: the definitive answer still points at the number — and does not
        promise that retrying cannot help, since a transaction broadcast moments ago may not have
        reached the server's node yet."""
        error, hint = self._refused(*self._NOT_FOUND)
        assert "No such mempool or blockchain transaction" in error
        assert "no transaction with that number" in hint and "number may be wrong" in hint
        assert "may not have reached that node" in hint
        assert "will not change" not in hint and "commonest" not in hint and "reachable" not in hint

    def test_the_servers_default_refusal_is_the_real_not_found_frame(self) -> None:
        """The harness's own default (a txid not in its table) is that measured frame, so every
        flow above that ends on a refusal ends on the real one."""
        rendered = _flow("ab" * 32, {}, [])["rendered"]
        assert "fetch failed: server error: daemon error: DaemonError({'code': -5" in rendered
        assert "no transaction with that number" in rendered

    def test_a_malformed_request_says_asking_again_gets_the_same_answer(self) -> None:
        _error, hint = self._refused(1, "zz should be a transaction hash")
        assert "refused the request itself" in hint and "same answer" in hint

    @pytest.mark.parametrize("code, message", [(None, "daemon busy"), (-1, "something else"), (2, "daemon error: x")])
    def test_a_refusal_the_frame_does_not_explain_gets_advice_true_for_both(self, code, message) -> None:
        """No code, or a code the page does not know, or ElectrumX's daemon error wrapping
        something other than -5: the advice has to hold whether the transaction is missing or the
        server is not."""
        _error, hint = self._refused(code, message)
        assert "will not guess" in hint and "check the number" in hint and "try again later" in hint
        assert "will not change" not in hint and "declined to answer this time" not in hint

    def test_an_unreadable_reply_says_it_was_refused_rather_than_read(self) -> None:
        hint = self._hint(_flow("ab" * 32, {"ab" * 32: {"frame": "not json"}}, []))
        assert "shape a transaction has" in hint and "reachable" not in hint


# ──────────────────────────── the row limit is the checking limit AND the listing limit ──


class TestEveryClassificationIsBounded:
    def test_a_transaction_with_no_reveal_is_classified_once_with_the_limit(self, limit) -> None:
        plain = _tx([(b"\x6a" + b"\x00" * 30, 0)], [("ab" * 32, 0, b"\x00")])
        flow = _flow(plain.txid(), {plain.txid(): {"hex": plain.serialize().hex()}}, [_first_pass(plain, limit)])
        assert flow["requested"] == [plain.txid()], "a transaction with no reveal has no spent commit to fetch"
        assert flow["glue_calls"] == [[plain.txid(), plain.serialize().hex(), limit, limit]]
        assert flow["binding_calls"] == []

    def test_a_reveal_is_classified_once_and_its_binding_asked_for_once(self, limit) -> None:
        reveal, commit, _forged = _world()
        server = {reveal.txid(): {"hex": reveal.serialize().hex()}, commit.txid(): {"hex": commit.serialize().hex()}}
        flow = _run(reveal, server, limit)
        assert len(flow["glue_calls"]) == 1 and flow["glue_calls"][0][2:] == [limit, limit], flow["glue_calls"]
        assert len(flow["binding_calls"]) == 1
