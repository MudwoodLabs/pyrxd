"""/inspect/'s "Fetch from network" flow, end to end: what the page fetches, what it hands the
classifier, and what the classifier then says.

``inspect_fetch_flow_harness.mjs`` runs the page's own ``onFetchTxid`` against a stub ElectrumX
server and records every argument it passes to the classifier bridge. These tests REPLAY those
recorded arguments through the real ``glue.inspect_txid_with_raw`` — so what is asserted is the
verdict the real classifier gives for the arguments the real page passed, not for arguments a
test chose. ``test_inspect_spent_tx_is_checked.py`` covers the Python half on its own.

Three properties, each a defect this change fixes:

* **A server that answers with a different transaction is refused, on every fetch.** The page's
  second fetch — the commit a reveal spent — was checked by nothing, so a server could answer
  with a transaction of its own carrying a commit to the envelope on screen and the page printed
  ``bound``. The check now lives in ``fetchRawTxFromElectrumx``, which every raw fetch on both
  pages goes through.
* **A spent transaction the page could not get is SAID, not swallowed.** The refusal travels to
  Python as ``prev_fetch_error`` and becomes the verdict's ``detail``; the report no longer says
  the spent output "was not supplied" when the page asked for it.
* **The page passes its row limit as the signature-checking limit on every classification.**
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


def _flow(txid: str, server: dict, glue_returns: list) -> dict:
    proc = subprocess.run(  # nosec B603 — fixed argv, no shell, repo-local script
        [_require_node(), str(_HARNESS)],
        input=json.dumps({"txid": txid, "server": server, "glue_returns": glue_returns}),
        capture_output=True,
        text=True,
        check=False,
        cwd=str(_REPO_ROOT),
    )
    if proc.returncode != 0:
        pytest.fail(f"fetch-flow harness failed (exit {proc.returncode}):\n{proc.stderr}")
    return json.loads(proc.stdout)


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


def _first_pass(reveal, limit: int) -> dict:
    """What the page's FIRST classification returns — the real one, computed by the real glue on
    the arguments the flow is asserted (below) to pass."""
    return _glue().inspect_txid_with_raw(reveal.txid(), reveal.serialize().hex(), "", limit)


def _replay(call: list) -> dict:
    result = _glue().inspect_txid_with_raw(*call)
    assert result["ok"], result
    return result


def _run(reveal, server: dict, limit: int) -> dict:
    return _flow(reveal.txid(), server, [_first_pass(reveal, limit)])


# ─────────────────────────────────── the second fetch is checked, and its failure is said ──


class TestTheSpentTransactionTheServerSends:
    def test_the_real_commit_reaches_the_classifier_and_binds(self, limit) -> None:
        """The honest path, and the neighbour of every refusal below."""
        reveal, commit, _forged = _world()
        server = {reveal.txid(): {"hex": reveal.serialize().hex()}, commit.txid(): {"hex": commit.serialize().hex()}}
        flow = _run(reveal, server, limit)
        assert flow["requested"] == [reveal.txid(), commit.txid()]
        raw = reveal.serialize().hex()
        assert flow["glue_calls"] == [
            [reveal.txid(), raw, "", limit],
            [reveal.txid(), raw, commit.serialize().hex(), limit, ""],
        ]
        assert _replay(flow["glue_calls"][1])["payload"]["metadata"]["payload_binding"]["state"] == "bound"

    @pytest.mark.parametrize("shown, committed", [("honest", None), ("EVIL", "real-token")])
    def test_a_server_answering_with_a_different_transaction_is_refused(self, limit, shown, committed) -> None:
        """The reviewer's case, through the page. Asked for the commit, the server answers with a
        transaction of its own committing to the envelope on screen. It used to reach the
        classifier and read ``bound`` — for the attack too, where the real commit committed to a
        different payload. Now the fetch refuses it and the page says so."""
        reveal, commit, forged = _world(shown, committed)
        server = {reveal.txid(): {"hex": reveal.serialize().hex()}, commit.txid(): {"hex": forged.serialize().hex()}}
        flow = _run(reveal, server, limit)
        assert flow["requested"] == [reveal.txid(), commit.txid()]
        second = flow["glue_calls"][1]
        assert second[2] == "", "the forged transaction reached the classifier"
        assert second[4] == f"the server's answer is not the transaction asked for: it hashes to {forged.txid()}"

        binding = _replay(second)["payload"]["metadata"]["payload_binding"]
        assert binding["state"] == "unchecked"
        assert binding["reason"] == _glue()._SPENT_NOT_OBTAINED
        assert binding["detail"] == second[4]

    def test_a_server_that_refuses_the_commit_is_said_too(self, limit) -> None:
        reveal, commit, _forged = _world()
        server = {reveal.txid(): {"hex": reveal.serialize().hex()}, commit.txid(): {"error": "daemon busy"}}
        flow = _run(reveal, server, limit)
        second = flow["glue_calls"][1]
        assert second[2:] == ["", limit, "server error: daemon busy"]
        binding = _replay(second)["payload"]["metadata"]["payload_binding"]
        assert binding == {
            "state": "unchecked",
            "reason": _glue()._SPENT_NOT_OBTAINED,
            "detail": "server error: daemon busy",
        }
        assert "was not supplied" not in binding["reason"]


# ──────────────────────────────── the FIRST fetch is checked by the same function ──


class TestTheTransactionAskedForIsTheOneThatCameBack:
    def test_a_different_transaction_never_reaches_the_classifier(self, limit) -> None:
        reveal, commit, _forged = _world()
        flow = _flow(reveal.txid(), {reveal.txid(): {"hex": commit.serialize().hex()}}, [])
        assert flow["glue_calls"] == [], "the classifier was handed a transaction nobody asked for"
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


# ──────────────────────────────────── the row limit is the checking limit, on every call ──


class TestEveryClassificationIsBounded:
    def test_a_transaction_with_no_reveal_is_classified_once_with_the_limit(self, limit) -> None:
        plain = _tx([(b"\x6a" + b"\x00" * 30, 0)], [("ab" * 32, 0, b"\x00")])
        flow = _flow(plain.txid(), {plain.txid(): {"hex": plain.serialize().hex()}}, [_first_pass(plain, limit)])
        assert flow["requested"] == [plain.txid()], "a transaction with no reveal has no spent commit to fetch"
        assert flow["glue_calls"] == [[plain.txid(), plain.serialize().hex(), "", limit]]

    def test_every_call_the_page_makes_carries_the_limit(self, limit) -> None:
        reveal, commit, _forged = _world()
        server = {reveal.txid(): {"hex": reveal.serialize().hex()}, commit.txid(): {"hex": commit.serialize().hex()}}
        calls = _run(reveal, server, limit)["glue_calls"]
        assert len(calls) == 2 and all(call[3] == limit for call in calls), calls
