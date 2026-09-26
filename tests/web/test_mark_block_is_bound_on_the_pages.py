"""Both browser pages show the block whose header hashes to the block the node names — or none.

THE DEFECT. `/inspect/` and `/verify/` placed a mark in block ``tip - confirmations + 1``. The tip
is ElectrumX's INDEXED height and the confirmation count comes from its node, which gets each block
seconds before the index does, so in that window the number is one block LOW — on every server at
once (measured by the 0.25.0 panel; #744 fixed the CLI). The pages now bind the height through the
same ``resolve_mark_anchor(fetch_header=...)`` the CLI calls: ``glue.mark_anchor`` runs the rule and
asks for one header at a time (``needs_headers``), and ``resolveMarkAnchor`` in ``shared.js``
fetches each with ``blockchain.block.header`` and hands it back. JavaScript never picks a height.

WHAT RUNS. Each page's own entry point — ``onFetchTxid`` on /inspect/, ``onCheck`` on /verify/ —
loaded verbatim under Node, against a stub ElectrumX that serves a chain of synthetic headers. The
block-lookup bridge is the REAL ``glue.mark_anchor``, one Python subprocess per call
(``glue_subprocess_bridge.mjs``), so the loop across the bridge is exercised end to end rather than
replayed from canned answers. The transaction carries a real signed HashMark record.

THE CHAIN. The mark is in block ``H``; the node's tip is ``H + 9`` (ten confirmations). Every header
is ``synthetic_header(height)`` and the node's block hash for the transaction is
``block_hash_at(H)`` — the same fakes the CLI's binding tests use. "Index one behind" is modelled as
an operation on that truth: ``headers.subscribe`` reports ``H + 8`` and headers above it are refused.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess  # nosec B404 — fixed argv, no shell, repo-local script
import sys
from pathlib import Path

import pytest

from tests.test_mutable_chain_is_discovered_from_the_chain import block_hash_at, synthetic_header

_REPO_ROOT = Path(__file__).resolve().parents[2]
_INSPECT_HARNESS = _REPO_ROOT / "tests" / "web" / "inspect_fetch_flow_harness.mjs"
_VERIFY_HARNESS = _REPO_ROOT / "tests" / "web" / "verify_render_harness.mjs"

H = 460_572
NODE_TIP = H + 9
CONFIRMATIONS = NODE_TIP - H + 1


def _node() -> str:
    node = shutil.which("node")
    if node is None:
        if os.environ.get("PYRXD_SKIP_JS_RENDER_GUARD") == "1":
            pytest.skip("node is missing and PYRXD_SKIP_JS_RENDER_GUARD=1 — the pages' block binding is UNGUARDED")
        pytest.fail("node is required to drive the pages' block lookup (or set PYRXD_SKIP_JS_RENDER_GUARD=1)")
    return node


def _env() -> dict:
    """The harness's Python subprocess must import THIS tree's pyrxd, not an installed one."""
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(p for p in (str(_REPO_ROOT / "src"), env.get("PYTHONPATH", "")) if p)
    return env


def _headers(up_to: int) -> dict[str, str]:
    """What `blockchain.block.header` serves: every height from a little below the mark to ``up_to``."""
    return {str(h): synthetic_header(h).hex() for h in range(H - 5, up_to + 1)}


#: The three servers every case is built from.
HONEST = {"tip": NODE_TIP, "headers": _headers(NODE_TIP), "blockhash": block_hash_at(H)}
INDEX_BEHIND = {"tip": NODE_TIP - 1, "headers": _headers(NODE_TIP - 1), "blockhash": block_hash_at(H)}
INCONSISTENT = {"tip": NODE_TIP, "headers": _headers(NODE_TIP), "blockhash": "11" * 32}


def _header_requests(log: list) -> list[int]:
    return [params[0] for method, params in log if method == "blockchain.block.header"]


def bound_anchor(glue, txid: str, confirmations: int, tip: int) -> dict:
    """The anchor the pages end up with for an HONEST server whose index and node agree: the mark
    in block ``tip - confirmations + 1``, every header synthetic, the bridge's loop played to the
    end. For tests about something else that need a real, bound anchor to render — built by the
    real ``glue.mark_anchor``, never by hand."""
    height = tip - confirmations + 1
    verbose = json.dumps({"txid": txid, "confirmations": confirmations, "blockhash": block_hash_at(height)})
    fetched: dict = {"headers": {}, "errors": {}}
    for _ in range(8):
        answer = glue.mark_anchor(txid, verbose, tip, json.dumps(fetched))
        if not answer.get("needs_headers"):
            assert answer.get("resolved") and answer.get("header_bound"), answer
            return answer
        wanted = answer["needs_headers"][0]
        fetched["headers"][str(wanted)] = synthetic_header(wanted).hex()
    raise AssertionError("the bridge kept asking for headers")


# ─────────────────────────────────────────────────────────── /inspect/ ──


@pytest.fixture(scope="module")
def inspect_tx():
    """A real signed HashMark record in a transaction of its own, and the classifier's real answer
    for it — what /inspect/'s first fetch hands the page."""
    from tests.web.test_inspect_fetch_flow import _first_pass, _flow, _tx
    from tests.web.test_verify_page import _signed_script

    tx = _tx([(_signed_script(b"the advisory, as published\n"), 0)], [("ab" * 32, 0, b"\x00")])
    limit = _flow("00" * 32, {}, [])["__constants__"]["max_rows_shown"]
    first = _first_pass(tx, limit)
    assert any(row.get("hashmark") for row in first["payload"]["outputs"]), "the premise: a mark"
    return tx, first


def _inspect(inspect_tx, server: dict, **extra) -> dict:
    tx, first = inspect_tx
    spec = {
        "txid": tx.txid(),
        "server": {tx.txid(): {"hex": tx.serialize().hex()}},
        "glue_returns": [first],
        "binding_returns": [],
        "anchor_python": sys.executable,
        "confirmations": CONFIRMATIONS,
        **server,
        **extra,
    }
    proc = subprocess.run(  # nosec B603 — fixed argv, no shell, repo-local script
        [_node(), str(_INSPECT_HARNESS)],
        input=json.dumps(spec),
        capture_output=True,
        text=True,
        check=False,
        cwd=str(_REPO_ROOT),
        env=_env(),
        timeout=300,
    )
    if proc.returncode != 0:
        pytest.fail(f"inspect fetch-flow harness failed (exit {proc.returncode}):\n{proc.stderr[-3000:]}")
    return json.loads(proc.stdout)


class TestInspectShowsTheBoundBlock:
    def test_the_honest_path_shows_the_block_after_one_header(self, inspect_tx) -> None:
        out = _inspect(inspect_tx, HONEST)
        assert _header_requests(out["server_log"]) == [H], "the honest path needs exactly the one header"
        assert f"{H} — {CONFIRMATIONS} confirmation(s) deep" in out["rendered"]

    def test_a_node_one_block_ahead_of_its_index_shows_the_true_block(self, inspect_tx) -> None:
        """THE FINDING. The formula says H - 1; that header does not hash to the node's block hash,
        H's does, and H is what is drawn."""
        out = _inspect(inspect_tx, INDEX_BEHIND)
        assert _header_requests(out["server_log"]) == [H - 1, H], "the rule's order: the formula, then +1"
        assert f"{H} — {CONFIRMATIONS} confirmation(s) deep" in out["rendered"]
        assert f"{H - 1} — " not in out["rendered"], "the unbound, one-low block was drawn"

    def test_a_header_that_does_not_hash_to_the_block_is_refused_and_says_why(self, inspect_tx) -> None:
        out = _inspect(inspect_tx, INCONSISTENT)
        rendered = " ".join(out["rendered"].split())
        assert "not established — the server's index and its node disagree" in rendered
        assert "so no block number is shown" in rendered
        for height in range(H - 2, H + 3):
            assert f"{height} — " not in rendered, f"a block number ({height}) was drawn without a header binding it"

    def test_a_header_the_server_refuses_is_named_not_blamed_on_a_disagreement(self, inspect_tx) -> None:
        """ROUND 2. An HONEST chain, except the server refuses the header at the mark's own height.
        The other headers in the window are served and — honestly — do not match; that is not the
        server contradicting itself, and the page must not say it is. Paired with the true
        disagreement above, where every header is served."""
        headers = {k: v for k, v in HONEST["headers"].items() if k != str(H)}
        out = _inspect(inspect_tx, {**HONEST, "headers": headers})
        rendered = " ".join(out["rendered"].split())
        assert f"not established — the server did not serve the block headers at heights {H}," in rendered
        assert "disagree" not in rendered
        assert f"{H} — " not in rendered

    def test_clearing_during_the_header_fetch_draws_nothing_and_fetches_no_more(self, inspect_tx) -> None:
        """Requests: 1 the transaction, 2 and 3 the depth and the tip, 4 the first header. Clear
        lands during 4. Nothing is drawn — and no further header is fetched, nor the bridge asked
        again: the lookup itself checks for a reader who has moved on."""
        out = _inspect(inspect_tx, INDEX_BEHIND, interleave="clear", interleave_on_request=4)
        assert out["server_log"][3][0] == "blockchain.block.header", "the premise: request 4 is a header"
        assert out["rendered"] == ""
        assert _header_requests(out["server_log"]) == [H - 1], "the lookup went on fetching headers"
        assert len(out["anchor_calls"]) == 1, "the lookup went on asking the bridge"

    def test_a_bridge_that_asks_for_the_same_header_twice_is_stopped_not_looped(self, inspect_tx) -> None:
        """The page's own safety stop, reached through a bridge answering out of contract (canned,
        not the real glue): asked again for a header it already handed over, the page stops after
        ONE fetch and says the height could not be checked — no block number, no loop."""
        again = {"resolved": False, "needs_headers": [H], "reason": "the block's header has not been fetched yet"}
        out = _inspect(inspect_tx, HONEST, anchor_python=None, anchor_returns=[again] * 12)
        assert _header_requests(out["server_log"]) == [H], "the page fetched the same header more than once"
        assert len(out["anchor_calls"]) == 2
        rendered = " ".join(out["rendered"].split())
        assert "not established — the block's height could not be checked against the server's headers" in rendered

    @pytest.mark.parametrize(
        "bad",
        [synthetic_header(H).hex() + "00", "zz" * 80, 12345],
        ids=["one-byte-long", "not-hex", "not-a-string"],
    )
    def test_a_malformed_header_never_reaches_the_bridge_as_a_header(self, inspect_tx, bad) -> None:
        """UNTRUSTED SERVER INPUT, bounded where it arrives. The page refuses it and hands the
        bridge an ERROR for that height, never the header; the rule moves on and, finding no other
        header that matches, no block number is drawn."""
        server = {**HONEST, "headers": {**HONEST["headers"], str(H): bad}}
        out = _inspect(inspect_tx, server)
        for call in out["anchor_calls"]:
            fetched = json.loads(call[3]) if call[3] else {"headers": {}, "errors": {}}
            assert str(H) not in fetched["headers"], f"the page handed the bridge a malformed header: {call[3][:200]}"
        last = json.loads(out["anchor_calls"][-1][3])
        assert str(H) in last["errors"], "the refusal was not handed across as an error for that height"
        assert f"{H} — " not in out["rendered"]


# ──────────────────────────────────────────────────────────── /verify/ ──


@pytest.fixture(scope="module")
def verify_tx():
    from tests.web.test_verify_page import _signed_script, _tx_result

    txid, raw, fetched = _tx_result(_signed_script(b"the advisory, as published\n"), limit=50)
    return txid, raw.hex(), fetched


def _verify(verify_tx, server: dict, **extra) -> dict:
    txid, raw_hex, fetched = verify_tx
    case = {
        "text": txid,
        "raw": {txid: raw_hex},
        "run_returns": [],
        "fetch_returns": [fetched],
        "anchor_python": sys.executable,
        "confirmations": CONFIRMATIONS,
        **server,
        **extra,
    }
    proc = subprocess.run(  # nosec B603 — fixed argv, no shell, repo-local script
        [_node(), str(_VERIFY_HARNESS), "-"],
        input=json.dumps({"case": {"check": case}}),
        capture_output=True,
        text=True,
        check=False,
        cwd=str(_REPO_ROOT),
        env=_env(),
        timeout=300,
    )
    if proc.returncode != 0:
        pytest.fail(f"verify render harness failed (exit {proc.returncode}):\n{proc.stderr[-3000:]}")
    return json.loads(proc.stdout)["case"]


class TestVerifyShowsTheBoundBlock:
    def test_the_honest_path_shows_the_block_after_one_header(self, verify_tx) -> None:
        from pyrxd.glyph.mark_anchor import BOUND_CAVEAT

        out = _verify(verify_tx, HONEST)
        flat = " ".join(out["text"].split())
        assert _header_requests(out["requested"]) == [H]
        assert f"In block {H}, which has {CONFIRMATIONS} confirmations" in flat
        assert f"About that block number: {BOUND_CAVEAT}." in flat, "the bound caveat did not travel with it"

    def test_a_node_one_block_ahead_of_its_index_shows_the_true_block(self, verify_tx) -> None:
        out = _verify(verify_tx, INDEX_BEHIND)
        flat = " ".join(out["text"].split())
        assert _header_requests(out["requested"]) == [H - 1, H]
        assert f"In block {H}," in flat
        assert f"In block {H - 1}," not in flat, "the unbound, one-low block was shown"

    def test_a_header_that_does_not_hash_to_the_block_is_refused_and_says_why(self, verify_tx) -> None:
        out = _verify(verify_tx, INCONSISTENT)
        flat = " ".join(out["text"].split())
        assert "Not established — the server's index and its node disagree" in flat
        assert "so no block number is shown" in flat
        # The reason may name the RANGE of heights that was checked; what must not appear is any of
        # them presented as the mark's block — the sentence, or the "block" fact row.
        assert "In block" not in flat
        assert "block" not in out["text"].split("\n"), "a block fact row was drawn without a header binding it"

    def test_a_header_that_is_never_answered_is_named_not_blamed_on_a_disagreement(self, verify_tx) -> None:
        """ROUND 2, the reviewer's exact case: an honest chain whose request for the mark's own
        header is NEVER ANSWERED. The page's own 10 s timeout ends it (so this test takes that
        long); the other headers are served and honestly do not match. The page must name the
        height it did not get, not say the server disagrees with itself."""
        headers = {**HONEST["headers"], str(H): {"hang": True}}
        out = _verify(verify_tx, {**HONEST, "headers": headers})
        flat = " ".join(out["text"].split())
        assert _header_requests(out["requested"]) == [H, H + 1, H - 1, H + 2, H - 2], "the premise"
        assert f"Not established — the server did not serve the block headers at heights {H}," in flat
        assert "disagree" not in flat
        assert "In block" not in flat

    def test_clearing_during_the_header_fetch_draws_nothing_and_fetches_no_more(self, verify_tx) -> None:
        """Requests: 1 the transaction, 2 and 3 the depth and the tip, 4 the first header."""
        out = _verify(verify_tx, INDEX_BEHIND, interleave_clear_on_request=4)
        assert out["requested"][3][0] == "blockchain.block.header", "the premise: request 4 is a header"
        assert out["text"] == ""
        assert _header_requests(out["requested"]) == [H - 1], "the lookup went on fetching headers"
        assert len(out["calls"]["anchor"]) == 1, "the lookup went on asking the bridge"
