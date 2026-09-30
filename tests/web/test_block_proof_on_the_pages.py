"""The /verify/ and /inspect/ pages verify a HashMark's block, the way ``pyrxd verify`` does (#799 phase 3).

WHAT IS CHECKED, and against what:

* PARITY. The same server answers — the real replies two mainnet servers gave for two marks
  (``tests/fixtures/mark_block_fixtures_2026-09-30.json``) — go through the CLI's helper
  (``pyrxd.cli.glyph_inspect.verify_anchor_block``, over a real ``ElectrumXClient`` whose transport
  alone is faked) and through the page's bridge (``glue.verify_mark_block``, driven the way the page
  drives it). State, claim, reason and proved depth must be identical, and so must the whole
  display dict. Then the page's own JavaScript loop (``proveMarkBlock`` in ``shared.js``) drives the
  REAL glue in a subprocess, and the pages' own ``onCheck`` / ``onFetchTxid`` draw the result: the
  CLI's claim sentence must appear on screen verbatim, so a claim retyped in JavaScript fails here.
  MALFORMED replies too (a branch that is a string, a reply that is an array, header hex that is
  not hex or not the count served, a huge field nothing reads) go through the page's REAL loop and
  the CLI helper, and must reach the same state and the same reason.
* EVERY STATE ON SCREEN: VERIFIED at the checkpoint level and at the proof-of-work level, NOT
  VERIFIED with its reason (inclusion only), CONTRADICTED, a failed merkle fetch, and the "still
  checking" line — with no sentence on the screen contradicting another (#806's class).
* APPENDED, NEVER BLOCKING: the anchor is drawn before the proof starts, a failed or refused proof
  leaves it drawn with the reason, and a reader who moves on during the proof gets nothing redrawn.
* BOUNDS: the JavaScript loop's request cap stops a bridge that keeps asking, and is never below
  what the rule can ask for; glue refuses oversize or malformed inputs and never raises.

TEST CHECKPOINTS. The shipped checkpoints nearest the fixture marks are further away than the 17
captured headers reach, so, as in ``tests/test_verify_cli_block_verification.py``, the mainnet table
is replaced with one checkpoint made from a fixture header's own hash — in this process by
monkeypatch, and in a harness's glue subprocess through ``glue_subprocess_bridge.mjs``'s
``checkpoints`` option (a test-only seam; glue.py has none).
"""

from __future__ import annotations

import asyncio
import copy
import json
import math
import os
import shutil
import subprocess  # nosec B404 — fixed argv, no shell, repo-local script
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Any

import pytest

from pyrxd.cli import glyph_inspect
from pyrxd.glyph.mark_anchor import BOUND_CAVEAT, INCLUSION_ONLY_CAVEAT, MarkAnchor, mark_anchor_dict
from pyrxd.glyph.mark_block import MAX_HEADERS_FROM_CHECKPOINT, MAX_HEADERS_PER_REQUEST, plan_block_verification
from pyrxd.network.electrumx import _rpc_error
from pyrxd.spv import radiant_checkpoints
from tests.test_verify_cli_block_verification import (
    PYRXD,
    REFERENCE,
    Chain,
    _confs,
    _flip,
    _headers_reply,
    _renonced,
    _server,
)

_REPO_ROOT = Path(__file__).resolve().parents[2]
_GLUE_DIR = _REPO_ROOT / "docs" / "inspect_static" / "inspect"
_PROOF_HARNESS = _REPO_ROOT / "tests" / "web" / "block_proof_harness.mjs"
_VERIFY_HARNESS = _REPO_ROOT / "tests" / "web" / "verify_render_harness.mjs"
_INSPECT_FLOW_HARNESS = _REPO_ROOT / "tests" / "web" / "inspect_fetch_flow_harness.mjs"
_INSPECT_RENDER_HARNESS = _REPO_ROOT / "tests" / "web" / "inspect_render_harness.mjs"

C = Chain(REFERENCE)
P = Chain(PYRXD)


@pytest.fixture(scope="module")
def glue():
    """The page's own bridge module, imported the way the page imports it."""
    sys.path.insert(0, str(_GLUE_DIR))
    try:
        import glue as module

        yield module
    finally:
        sys.path.remove(str(_GLUE_DIR))
        sys.modules.pop("glue", None)


def _node() -> str:
    node = shutil.which("node")
    if node is None:
        if os.environ.get("PYRXD_SKIP_JS_RENDER_GUARD") == "1":
            pytest.skip("node is missing and PYRXD_SKIP_JS_RENDER_GUARD=1 — the pages' block proof is UNGUARDED")
        pytest.fail("node is required to drive the pages' block proof (or set PYRXD_SKIP_JS_RENDER_GUARD=1)")
    return node


def _env() -> dict:
    """The harness's Python subprocess must import THIS tree's pyrxd, not an installed one."""
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(p for p in (str(_REPO_ROOT / "src"), env.get("PYTHONPATH", "")) if p)
    return env


def _harness(path: Path, spec: Any, *args: str) -> dict:
    proc = subprocess.run(  # nosec B603 — fixed argv, no shell, repo-local script
        [_node(), str(path), *args],
        input=json.dumps(spec),
        capture_output=True,
        text=True,
        check=False,
        cwd=str(_REPO_ROOT),
        env=_env(),
        timeout=600,
    )
    if proc.returncode != 0:
        pytest.fail(f"{path.name} failed (exit {proc.returncode}):\n{proc.stderr[-3000:]}")
    return json.loads(proc.stdout)


def _flat(text: str) -> str:
    return " ".join(text.split())


def _checkpoints(chain: Chain, height: int) -> tuple[tuple[int, str], ...]:
    return ((height, chain.hash_at(height)),)


def _call(client, method: str, params) -> Any:
    return asyncio.run(client._call(method, list(params)))


# ── the page's side, driven as the page drives it ───────────────────────────────────────────


def page_anchor(glue, chain: Chain, client) -> dict:
    """``glue.mark_anchor``'s answer for *chain*, its header loop played out against *client*."""
    verbose = json.dumps(_call(client, "blockchain.transaction.get", [chain.txid, True]))
    tip = _call(client, "blockchain.headers.subscribe", [])["height"]
    fetched: dict = {"headers": {}, "errors": {}}
    for _ in range(8):
        answer = glue.mark_anchor(chain.txid, verbose, tip, json.dumps(fetched))
        if not answer.get("needs_headers"):
            assert answer.get("resolved") and answer.get("header_bound"), answer
            return answer
        h = answer["needs_headers"][0]
        try:
            fetched["headers"][str(h)] = _call(client, "blockchain.block.header", [h])
        except Exception as exc:
            fetched["errors"][str(h)] = str(exc)
    raise AssertionError("the anchor bridge kept asking for headers")


def page_proof(glue, chain: Chain, client, anchor: dict) -> tuple[dict, list]:
    """``glue.verify_mark_block``'s final answer, its request loop played out against *client* —
    every reply handed back RAW, as the page hands it; a refusal handed back as its message."""
    fetched: dict = {"replies": {}, "errors": {}}
    asked: list = []
    for _ in range(12):
        answer = glue.verify_mark_block(chain.txid, chain.raw.hex(), json.dumps(anchor), json.dumps(fetched))
        need = answer["needs"]
        if need is None:
            return answer, asked
        asked.append((need["method"], need["params"]))
        try:
            fetched["replies"][need["key"]] = _call(client, need["method"], need["params"])
        except Exception as exc:
            fetched["errors"][need["key"]] = str(exc)
    raise AssertionError("the proof bridge kept asking")


def page_target(glue, anchor: dict) -> int:
    """The depth the page AIMS for: the server's own count, at most ``_PROOF_TARGET_DEPTH``."""
    return min(anchor["confirmations"], glue._PROOF_TARGET_DEPTH)


def cli_proof(chain: Chain, client, anchor: dict, *, label: str, min_confirmations: int):
    """The CLI helper ``pyrxd verify`` calls, on the same anchor, from the same server.

    The CLI has one depth, REQUIRED (its ``--min-confirmations``); the page requires 1 and aims for
    :func:`page_target`. Asked to require the depth the page aims for, the CLI fetches the same
    requests, and wherever that depth is served it reaches the same outcome — which is what the
    parity tests compare. Where it is NOT served, the two differ by design (see
    ``test_a_server_serving_fewer_headers_than_it_reports_still_verifies``)."""
    return asyncio.run(
        glyph_inspect.verify_anchor_block(
            lambda: (client, label),
            txid=chain.txid,
            height=anchor["height"],
            blockhash=anchor["blockhash"],
            raw_tx=chain.raw,
            network="mainnet",
            min_confirmations=min_confirmations,
        )
    )


# ── the cases: (chain, checkpoint height or None for the shipped table, server overrides) ────


def _short(chain: Chain) -> dict:
    return {"blockchain.block.headers": lambda p: _headers_reply(chain.headers, p[0], 1)}


def _bad_sibling(chain: Chain) -> dict:
    bad = copy.deepcopy(chain.merkle)
    bad["merkle"][1] = _flip(bad["merkle"][1])
    return {"blockchain.transaction.get_merkle": lambda p: copy.deepcopy(bad)}


def _spliced(chain: Chain) -> dict:
    spliced = dict(chain.headers)
    spliced[chain.height + 3] = P.headers[P.height] if chain is not P else C.headers[C.height]
    return {"blockchain.block.headers": lambda p: _headers_reply(spliced, *p)}


def _reorg_named(chain: Chain) -> dict:
    """The anchor's replies name a re-nonced block at the mark's height; the proof serves the real
    chain. Every reply is honest for the moment it was given."""
    named = _renonced(chain.headers[chain.height])

    def verbose_or_raw(params: list) -> Any:
        _txid, verbose = params
        if not verbose:
            return chain.raw.hex()
        return {"txid": chain.txid, "confirmations": chain.tip - chain.height + 1, "blockhash": _hash(named)}

    def one_header(params: list) -> str:
        return (named if params[0] == chain.height else chain.headers[params[0]]).hex()

    return {"blockchain.transaction.get": verbose_or_raw, "blockchain.block.header": one_header}


def _hash(header: bytes) -> str:
    from pyrxd.hash import radiant_block_hash

    return radiant_block_hash(header)


CASES: dict[str, tuple[Chain, Any, dict, str]] = {
    "verified_checkpoint_reference": (C, "tip", {}, "VERIFIED"),
    "verified_checkpoint_pyrxd": (P, "tip", {}, "VERIFIED"),
    "verified_work_reference": (C, "start", {}, "VERIFIED"),
    "verified_work_pyrxd": (P, "start", {}, "VERIFIED"),
    "verified_after_a_reorganisation": (C, "tip", "reorg", "VERIFIED"),
    "inclusion_only_headers_served_short": (C, "tip", "short", "NOT VERIFIED"),
    "merkle_method_not_found": (
        C,
        "tip",
        {"blockchain.transaction.get_merkle": _rpc_error(-32601, "unknown method")},
        "NOT VERIFIED",
    ),
    "coinbase_method_not_found": (
        C,
        "tip",
        {"blockchain.transaction.id_from_pos": _rpc_error(-32601, "unknown method")},
        "NOT VERIFIED",
    ),
    "header_range_malformed": (
        C,
        "tip",
        {"blockchain.block.headers": lambda p: {"count": 3, "hex": "00" * 10, "max": 2016}},
        "NOT VERIFIED",
    ),
    "no_checkpoints_for_the_network": (C, "none", {}, "NOT VERIFIED"),
    "the_shipped_table_unpatched": (P, None, {}, "NOT VERIFIED"),
    "contradicted_flipped_sibling": (C, "tip", "bad_sibling", "CONTRADICTED"),
    "contradicted_spliced_header": (C, "tip", "spliced", "CONTRADICTED"),
}


def _setup(monkeypatch, case: str):
    chain, cp, override, state = CASES[case]
    if cp == "tip":
        monkeypatch.setitem(radiant_checkpoints.CHECKPOINTS, "mainnet", _checkpoints(chain, chain.tip))
    elif cp == "start":
        monkeypatch.setitem(radiant_checkpoints.CHECKPOINTS, "mainnet", _checkpoints(chain, chain.start))
    elif cp == "none":
        monkeypatch.setitem(radiant_checkpoints.CHECKPOINTS, "mainnet", ())
    if isinstance(override, str):
        override = {"short": _short, "bad_sibling": _bad_sibling, "spliced": _spliced, "reorg": _reorg_named}[override](
            chain
        )
    return chain, _server(chain, **override), state


def _page_verification(answer: dict) -> dict:
    anchor = answer["anchor"]
    assert anchor is not None, answer
    bv = dict(anchor["block_verification"])
    bv.pop("source")
    return bv


def _cli_verification(bv) -> dict:
    """The CLI's outcome as the page's JSON carries it: tuples as lists."""
    return json.loads(json.dumps(asdict(bv)))


# ════════════════════════════════════════════════════════════════════════════════════════════
# PARITY: the CLI helper and the page's bridge, on identical server answers
# ════════════════════════════════════════════════════════════════════════════════════════════


@pytest.mark.parametrize("case", list(CASES), ids=list(CASES))
def test_the_cli_and_the_page_reach_the_same_outcome(glue, monkeypatch, case: str) -> None:
    chain, client, state = _setup(monkeypatch, case)
    anchor = page_anchor(glue, chain, client)
    assert anchor["block_verification"] is None, "the premise: the anchor is drawn before any proof"
    page, _asked = page_proof(glue, chain, client, anchor)
    # The CLI names its endpoint by URL; the page names its one endpoint. Given the SAME label,
    # every sentence must be the same, byte for byte.
    cli, label = cli_proof(
        chain, client, anchor, label=glue._ANCHOR_SOURCE, min_confirmations=page_target(glue, anchor)
    )
    assert cli.state == state, cli.reason
    assert _page_verification(page) == _cli_verification(cli), "the page and the CLI disagree"
    for field in ("state", "claim", "reason", "verified_depth"):
        assert page["anchor"]["block_verification"][field] == getattr(cli, field), field
    if state == "CONTRADICTED":
        # No block number, as `pyrxd verify` reports none and exits 2 — and the same sentence.
        assert page["anchor"]["resolved"] is False
        from pyrxd.glyph.mark_block import NOTHING_AGAINST_THE_MARK, contradicted_sentence

        assert contradicted_sentence(anchor["height"], glue._ANCHOR_SOURCE, cli.reason) in page["anchor"]["reason"]
        assert NOTHING_AGAINST_THE_MARK in page["anchor"]["reason"]
        return
    # THE WHOLE DISPLAY DICT, not only the verdict: caveat, height_is_verified, the proved depth
    # and the block hash are `with_block_verification`'s on both surfaces.
    cli_shape = mark_anchor_dict(
        MarkAnchor(
            txid=chain.txid,
            height=anchor["height"],
            confirmations=anchor["confirmations"],
            min_confirmations=1,
            source=glue._ANCHOR_SOURCE,
            caveat=BOUND_CAVEAT,
            header_bound=True,
            blockhash=anchor["blockhash"],
        ),
        cli,
        verified_by=label,
    )
    for dropped in ("provisional", "deep_enough", "min_confirmations"):
        cli_shape.pop(dropped)
    shown = {k: v for k, v in page["anchor"].items() if k not in ("resolved", "txid", "no_depth_policy")}
    assert shown == json.loads(json.dumps(cli_shape))
    if state == "VERIFIED":
        assert page["anchor"]["caveat"] == cli.claim and page["anchor"]["height_is_verified"] is True
        assert page["anchor"]["verified_confirmations"] == cli.verified_depth


def test_the_page_asks_in_the_order_the_cli_fetches(glue, monkeypatch) -> None:
    """Merkle branch, coinbase branch, then each planned header range — and nothing twice."""
    chain, client, _ = _setup(monkeypatch, "verified_checkpoint_reference")
    anchor = page_anchor(glue, chain, client)
    _, asked = page_proof(glue, chain, client, anchor)
    plan = plan_block_verification(
        height=chain.height, min_confirmations=1, target_confirmations=page_target(glue, anchor)
    )
    assert asked == [
        ("blockchain.transaction.get_merkle", [chain.txid, chain.height]),
        ("blockchain.transaction.id_from_pos", [chain.height, 0, True]),
        *[("blockchain.block.headers", [s, n]) for s, n in plan.header_ranges],
    ]


def test_nothing_is_asked_when_nothing_could_verify(glue, monkeypatch) -> None:
    """No checkpoints for the network: the first answer is the outcome, with no request."""
    chain, client, _ = _setup(monkeypatch, "no_checkpoints_for_the_network")
    anchor = page_anchor(glue, chain, client)
    answer = glue.verify_mark_block(chain.txid, chain.raw.hex(), json.dumps(anchor), None)
    assert answer["needs"] is None
    assert "ships no checkpoints for this network" in answer["anchor"]["block_verification"]["reason"]
    assert answer["anchor"]["caveat"] == BOUND_CAVEAT


# ════════════════════════════════════════════════════════════════════════════════════════════
# THE DEPTH THE PAGE PROVES: it requires 1, and aims for min(the server's count, 6)
# ════════════════════════════════════════════════════════════════════════════════════════════


def _work_level(monkeypatch, chain: Chain) -> None:
    """The proof-of-work level — the checkpoint BELOW the mark — where depth is what is proved."""
    monkeypatch.setitem(radiant_checkpoints.CHECKPOINTS, "mainnet", _checkpoints(chain, chain.start))


@pytest.mark.parametrize("chain", [C, P], ids=["reference", "pyrxd"])
def test_a_server_reporting_170_gets_six_proved(glue, monkeypatch, chain: Chain) -> None:
    """The server's count is far past six: the page proves six — no fewer, and no more asked for."""
    _work_level(monkeypatch, chain)
    client = _server(chain, **_confs(chain, 170))
    anchor = page_anchor(glue, chain, client)
    assert anchor["confirmations"] == 170, "the premise"
    page, asked = page_proof(glue, chain, client, anchor)
    bv = page["anchor"]["block_verification"]
    assert bv["state"] == "VERIFIED" and bv["verified_depth"] == 6, bv
    assert page["anchor"]["verified_confirmations"] == 6 and page["anchor"]["confirmations"] == 170
    # The claim reports the depth proved: six headers a liar would have had to mine.
    assert f"it would have had to mine the 6 header(s) from block {chain.height} up" in bv["claim"]
    top = max(p[0] + p[1] - 1 for m, p in asked if m == "blockchain.block.headers")
    assert top == chain.height + 5, "the page asked for more (or fewer) headers than six deep"


def test_a_server_reporting_three_gets_three_proved_and_verified(glue, monkeypatch) -> None:
    """A server whose tip is three blocks up (it reports 3, and serves nothing above its tip): the
    page aims for three, proves three, and it is VERIFIED — never NOT VERIFIED for want of six.
    The CLI, asked to require the same three, reaches the identical outcome."""
    chain = P
    _work_level(monkeypatch, chain)
    upto = {h: b for h, b in chain.headers.items() if h <= chain.height + 2}
    over = {**_confs(chain, 3), "blockchain.block.headers": lambda p: _headers_reply(upto, *p)}
    anchor = page_anchor(glue, chain, _server(chain, **over))
    assert anchor["confirmations"] == 3, "the premise"
    page, _ = page_proof(glue, chain, _server(chain, **over), anchor)
    bv = page["anchor"]["block_verification"]
    assert bv["state"] == "VERIFIED" and bv["verified_depth"] == 3, bv
    assert page["anchor"]["height_is_verified"] is True and page["anchor"]["verified_confirmations"] == 3
    cli, _ = cli_proof(chain, _server(chain, **over), anchor, label=glue._ANCHOR_SOURCE, min_confirmations=3)
    assert _page_verification(page) == _cli_verification(cli)


def test_a_server_serving_fewer_headers_than_it_reports_still_verifies(glue, monkeypatch) -> None:
    """It reports 9 and serves headers only three deep. The page REQUIRES one, so it VERIFIES to
    the three it can prove. `pyrxd verify` is unchanged: its required floor is the user's
    ``--min-confirmations``, so at 6 the same answers are NOT VERIFIED with its own reason — and
    required at the three the page proved, it gives the page's outcome exactly."""
    chain = C
    _work_level(monkeypatch, chain)
    upto = {h: b for h, b in chain.headers.items() if h <= chain.height + 2}
    over = {"blockchain.block.headers": lambda p: _headers_reply(upto, *p)}
    anchor = page_anchor(glue, chain, _server(chain, **over))
    assert anchor["confirmations"] == 9, "the premise"
    page, _ = page_proof(glue, chain, _server(chain, **over), anchor)
    bv = page["anchor"]["block_verification"]
    assert bv["state"] == "VERIFIED" and bv["verified_depth"] == 3, bv
    six, _ = cli_proof(chain, _server(chain, **over), anchor, label=glue._ANCHOR_SOURCE, min_confirmations=6)
    assert six.state == "NOT VERIFIED" and six.reason == "only 3 of the 6 required blocks could be verified"
    three, _ = cli_proof(chain, _server(chain, **over), anchor, label=glue._ANCHOR_SOURCE, min_confirmations=3)
    assert _page_verification(page) == _cli_verification(three)


# ════════════════════════════════════════════════════════════════════════════════════════════
# The page's own JavaScript loop, driving the REAL glue in a subprocess
# ════════════════════════════════════════════════════════════════════════════════════════════


def _proof_table(chain: Chain, **over: Any) -> dict:
    table = {
        "merkle": copy.deepcopy(chain.merkle),
        "coinbase": copy.deepcopy(chain.coinbase),
        "headers": {str(h): b.hex() for h, b in chain.headers.items()},
    }
    table.update(over)
    return table


def _js_proof(glue, chain: Chain, checkpoint: int | None, proof: dict, anchor: dict | None = None) -> dict:
    anchor = anchor or page_anchor(glue, chain, _server(chain))
    spec = {
        "txid": chain.txid,
        "raw_hex": chain.raw.hex(),
        "anchor": anchor,
        "python": sys.executable,
        "checkpoints": None if checkpoint is None else [list(c) for c in _checkpoints(chain, checkpoint)],
        "proof": proof,
    }
    return _harness(_PROOF_HARNESS, spec)


@pytest.mark.parametrize(
    ("chain", "level"),
    [(C, "checkpoint"), (P, "work")],
    ids=["reference_checkpoint_level", "pyrxd_work_level"],
)
def test_the_js_loop_reaches_the_clis_verdict(glue, monkeypatch, chain: Chain, level: str) -> None:
    cp = chain.tip if level == "checkpoint" else chain.start
    out = _js_proof(glue, chain, cp, _proof_table(chain))
    monkeypatch.setitem(radiant_checkpoints.CHECKPOINTS, "mainnet", _checkpoints(chain, cp))
    anchor = page_anchor(glue, chain, _server(chain))
    cli, _ = cli_proof(
        chain, _server(chain), anchor, label=glue._ANCHOR_SOURCE, min_confirmations=page_target(glue, anchor)
    )
    got = out["answer"]["anchor"]
    assert cli.state == "VERIFIED" and got["block_verification"]["level"] == level
    bv = dict(got["block_verification"])
    bv.pop("source")
    assert bv == _cli_verification(cli)
    assert got["caveat"] == cli.claim
    methods = [m for m, _ in out["server_log"]]
    assert methods[:2] == ["blockchain.transaction.get_merkle", "blockchain.transaction.id_from_pos"]
    assert set(methods[2:]) == {"blockchain.block.headers"}
    assert "blockchain.transaction.get" not in methods, "the raw transaction is passed through, not fetched again"


def test_the_js_loop_carries_a_contradiction_as_no_block(glue) -> None:
    bad = copy.deepcopy(C.merkle)
    bad["merkle"][1] = _flip(bad["merkle"][1])
    out = _js_proof(glue, C, C.tip, _proof_table(C, merkle=bad))
    got = out["answer"]["anchor"]
    assert got["resolved"] is False and got["block_verification"]["state"] == "CONTRADICTED"
    assert "merkle inclusion failed" in got["reason"]


def test_a_server_refusing_the_merkle_method_leaves_the_block_with_the_reason(glue) -> None:
    out = _js_proof(glue, C, C.tip, _proof_table(C, merkle={"error": {"code": -32601, "message": "unknown method"}}))
    got = out["answer"]["anchor"]
    assert got["resolved"] is True and got["height"] == C.height
    assert got["block_verification"]["state"] == "NOT VERIFIED"
    assert got["block_verification"]["reason"].startswith(
        f"the transaction's merkle branch could not be fetched from {glue._ANCHOR_SOURCE}: "
    )
    assert got["caveat"] == BOUND_CAVEAT
    assert len(out["server_log"]) == 1, "nothing is fetched after the first failure"


#: MALFORMED REPLIES, each through the page's REAL JavaScript loop (`proveMarkBlock`) and the real
#: glue, and through the CLI helper over a real client: (what the page's table serves, what the
#: CLI's server serves — the same reply). The JavaScript judges no shape, so every refusal must be
#: Python's, in the CLI's words; and a field nothing reads, however large, must change nothing.
_PADDED = {**C.merkle, "padding": "x" * 1_100_000}
_MALFORMED: dict[str, tuple[dict, dict, str]] = {
    "merkle_branch_is_a_string": (
        {"merkle": {**C.merkle, "merkle": "deadbeef"}},
        {"blockchain.transaction.get_merkle": lambda p: {**C.merkle, "merkle": "deadbeef"}},
        "NOT VERIFIED",
    ),
    "merkle_reply_is_an_array": (
        {"merkle": [C.merkle]},
        {"blockchain.transaction.get_merkle": lambda p: [copy.deepcopy(C.merkle)]},
        "NOT VERIFIED",
    ),
    "coinbase_reply_is_an_array": (
        {"coinbase": [C.coinbase]},
        {"blockchain.transaction.id_from_pos": lambda p: [copy.deepcopy(C.coinbase)]},
        "NOT VERIFIED",
    ),
    "merkle_reply_has_no_pos": (
        {"merkle": {k: v for k, v in C.merkle.items() if k != "pos"}},
        {"blockchain.transaction.get_merkle": lambda p: {k: v for k, v in C.merkle.items() if k != "pos"}},
        "NOT VERIFIED",
    ),
    "header_hex_is_not_hex": (
        {"headers_reply": {"count": 2, "hex": "zz" * 160, "max": 2016}},
        {"blockchain.block.headers": lambda p: {"count": 2, "hex": "zz" * 160, "max": 2016}},
        "NOT VERIFIED",
    ),
    "header_hex_is_not_the_count_served": (
        {"headers_reply": {"count": 2, "hex": "00" * 80, "max": 2016}},
        {"blockchain.block.headers": lambda p: {"count": 2, "hex": "00" * 80, "max": 2016}},
        "NOT VERIFIED",
    ),
    "an_oversized_field_nothing_reads": (
        {"merkle": _PADDED},
        {"blockchain.transaction.get_merkle": lambda p: copy.deepcopy(_PADDED)},
        "VERIFIED",
    ),
}


@pytest.mark.parametrize("case", list(_MALFORMED), ids=list(_MALFORMED))
def test_a_malformed_reply_gets_the_same_state_and_reason_on_the_page_and_the_cli(glue, monkeypatch, case) -> None:
    table_over, server_over, state = _MALFORMED[case]
    out = _js_proof(glue, C, C.tip, _proof_table(C, **copy.deepcopy(table_over)))
    got = out["answer"]["anchor"]
    assert got is not None, out["answer"]
    monkeypatch.setitem(radiant_checkpoints.CHECKPOINTS, "mainnet", _checkpoints(C, C.tip))
    anchor = page_anchor(glue, C, _server(C))
    cli, _ = cli_proof(
        C,
        _server(C, **server_over),
        anchor,
        label=glue._ANCHOR_SOURCE,
        min_confirmations=page_target(glue, anchor),
    )
    assert cli.state == state, cli.reason
    bv = dict(got["block_verification"])
    bv.pop("source")
    assert bv == _cli_verification(cli), "the page and the CLI disagree"
    assert (got["block_verification"]["state"], got["block_verification"]["reason"]) == (cli.state, cli.reason)
    if state != "VERIFIED":
        # Python's reader wrote it, as `could_not_fetch` words it — not a JavaScript sentence.
        assert " could not be fetched from " in cli.reason, cli.reason
        assert ("Malformed" in cli.reason) or ("Unexpected response type" in cli.reason), cli.reason


def test_a_reply_over_the_pages_size_cap_is_refused_before_python_and_says_so(glue) -> None:
    """The one refusal the page writes itself is about SIZE, after the unread fields are dropped: a
    merkle branch of 600 hashes is larger than any honest one. It is a failed fetch with the page's
    reason — never a header, and never Python's "not in a shape it reads"."""
    huge = {**C.merkle, "merkle": ["ab" * 32] * 600}
    out = _js_proof(glue, C, C.tip, _proof_table(C, merkle=huge))
    bv = out["answer"]["anchor"]["block_verification"]
    assert bv["state"] == "NOT VERIFIED"
    assert bv["reason"].startswith(f"the transaction's merkle branch could not be fetched from {glue._ANCHOR_SOURCE}: ")
    assert "over the 16,384 this page accepts for it" in bv["reason"]


def test_the_js_loop_stops_at_its_cap_when_the_bridge_keeps_asking(glue) -> None:
    out = _harness(
        _PROOF_HARNESS,
        {
            "txid": C.txid,
            "raw_hex": C.raw.hex(),
            "anchor": page_anchor(glue, C, _server(C)),
            "bridge": "always_asks",
            "proof": _proof_table(C),
        },
    )
    cap = out["__constants__"]["max_block_proof_requests"]
    assert isinstance(cap, int) and cap > 0
    assert len(out["server_log"]) == cap, "the loop sent more (or fewer) requests than its cap"
    assert out["bridge_calls"] == cap + 1
    assert out["answer"]["anchor"] is None
    assert f"stopped after {cap} block-proof request(s)" in out["answer"]["reason"]


@pytest.mark.parametrize("answered", [True, False], ids=["replied", "refused"])
def test_the_js_loop_never_sends_the_same_request_twice(glue, answered: bool) -> None:
    """A bridge that asks again for a key it already has — as a reply, or as an error — is asking
    for something it cannot want. The loop stops after that ONE request, well below its cap, and
    says so; it does not send it again."""
    proof = _proof_table(C) if answered else _proof_table(C, merkle={"error": {"code": -32601, "message": "no"}})
    out = _harness(
        _PROOF_HARNESS,
        {
            "txid": C.txid,
            "raw_hex": C.raw.hex(),
            "anchor": page_anchor(glue, C, _server(C)),
            "bridge": "repeats",
            "proof": proof,
        },
    )
    assert out["__constants__"]["max_block_proof_requests"] > 1, "the premise: the cap alone would allow more"
    assert out["server_log"] == [["blockchain.transaction.get_merkle", [C.txid, C.height]]]
    assert out["bridge_calls"] == 2
    assert out["answer"]["anchor"] is None
    assert "stopped after 1 block-proof request(s)" in out["answer"]["reason"]


def test_the_cap_is_above_what_the_rule_can_ask_at_the_pages_floor(glue) -> None:
    """The cap only stops a runaway loop; it must never cut off an honest proof. At the page's
    floor the longest walk is MAX_HEADERS_FROM_CHECKPOINT + 1 headers either side of the newest
    checkpoint, in ranges of MAX_HEADERS_PER_REQUEST, plus the two merkle branches — checked against
    real plans over the SHIPPED table, at its extremes."""
    import re

    shared = (_GLUE_DIR / "shared.js").read_text(encoding="utf-8")
    match = re.search(r"const MAX_BLOCK_PROOF_REQUESTS = (\d+);", shared)
    assert match, "shared.js no longer declares MAX_BLOCK_PROOF_REQUESTS — this scan is broken"
    cap = int(match.group(1))
    worst = 2 + math.ceil((MAX_HEADERS_FROM_CHECKPOINT + 1) / MAX_HEADERS_PER_REQUEST)
    table = radiant_checkpoints.CHECKPOINTS["mainnet"]
    assert table, "non-vacuity: the shipped mainnet table is empty"
    newest = table[-1][0]
    heights = {
        newest,
        newest - 1,
        newest + 1,
        newest + MAX_HEADERS_FROM_CHECKPOINT,
        newest + MAX_HEADERS_FROM_CHECKPOINT - 1,
        table[0][0],
        table[-2][0] + 1,
    }
    seen = 0
    for h in heights:
        # The page requires its floor and AIMS for up to `_PROOF_TARGET_DEPTH`: the worst plan is
        # the one with the target, never smaller than without it.
        for target in (None, glue._PROOF_TARGET_DEPTH):
            plan = plan_block_verification(height=h, min_confirmations=glue._ANCHOR_FLOOR, target_confirmations=target)
            if plan.reason is None:
                seen = max(seen, 2 + len(plan.header_ranges))
                headers = sum(n for _, n in plan.header_ranges)
                assert headers <= MAX_HEADERS_FROM_CHECKPOINT + 1 + glue._PROOF_TARGET_DEPTH, (h, target, headers)
    assert seen, "non-vacuity: no height in the sample produced a plan"
    assert seen <= worst <= cap


def _js_constant(name: str) -> int:
    import re

    shared = (_GLUE_DIR / "shared.js").read_text(encoding="utf-8")
    match = re.search(rf"const {name} = ([\d_]+);", shared)
    assert match, f"shared.js no longer declares {name} — this scan is broken"
    return int(match.group(1).replace("_", ""))


def test_the_proof_json_cap_holds_the_worst_plan(glue) -> None:
    """``_MAX_PROOF_JSON_CHARS`` bounds what the page may hand across, and the page's per-reply
    caps (``proofReplyCap`` in shared.js) bound each reply it hands. For the longest plan the page
    can make, every reply AT its cap, plus an error for every key, must still fit — so a reply the
    page accepted can never trip glue's "not in a shape it reads" instead of Python's own reason."""
    branch_cap = _js_constant("MAX_PROOF_BRANCH_REPLY_CHARS")
    slack = _js_constant("PROOF_REPLY_SLACK_CHARS")
    newest = radiant_checkpoints.CHECKPOINTS["mainnet"][-1][0]
    plans = [
        plan_block_verification(
            height=h, min_confirmations=glue._ANCHOR_FLOOR, target_confirmations=glue._PROOF_TARGET_DEPTH
        )
        for h in (newest + MAX_HEADERS_FROM_CHECKPOINT, newest - 1, newest + 1)
    ]
    plans = [p for p in plans if p.reason is None]
    assert plans, "non-vacuity: no plan to measure"
    for plan in plans:
        at_cap = {"merkle": "x" * (branch_cap - 2), "coinbase": "x" * (branch_cap - 2)}
        for s, n in plan.header_ranges:
            at_cap[f"headers:{s}:{n}"] = "x" * (160 * n + slack - 2)
        errors = {key: "e" * 160 for key in at_cap}
        assert len(json.dumps({"replies": at_cap, "errors": errors})) < glue._MAX_PROOF_JSON_CHARS


# ════════════════════════════════════════════════════════════════════════════════════════════
# glue.verify_mark_block's own contract: bounded inputs, never raises
# ════════════════════════════════════════════════════════════════════════════════════════════


class TestTheBridgeIsBoundedAndTotal:
    def _anchor(self, glue) -> dict:
        return page_anchor(glue, C, _server(C))

    def test_an_anchor_that_is_not_resolved_is_not_verified(self, glue) -> None:
        out = glue.verify_mark_block(C.txid, C.raw.hex(), json.dumps({"resolved": False, "reason": "x"}), None)
        assert out == {"needs": None, "anchor": None, "reason": out["reason"]} and "not established" in out["reason"]

    @pytest.mark.parametrize(
        "mutate",
        [
            {"txid": "cd" * 32},
            {"height": -1},
            {"height": True},
            {"confirmations": 0},
            {"blockhash": "zz" * 32},
            {"blockhash": None},
            {"header_bound": False},
        ],
        ids=lambda m: next(iter(m)) + "=" + repr(next(iter(m.values())))[:12],
    )
    def test_an_anchor_whose_numbers_do_not_read_is_refused(self, glue, mutate) -> None:
        anchor = {**self._anchor(glue), **mutate}
        out = glue.verify_mark_block(C.txid, C.raw.hex(), json.dumps(anchor), None)
        assert out["needs"] is None and out["anchor"] is None and out["reason"]

    def test_the_anchor_is_rebuilt_from_its_numbers_not_its_sentences(self, glue, monkeypatch) -> None:
        """A caveat or source the page carried is never repeated: both come back as glue's own."""
        monkeypatch.setitem(radiant_checkpoints.CHECKPOINTS, "mainnet", ())
        anchor = {**self._anchor(glue), "caveat": "VERIFIED beyond doubt", "source": "trust me"}
        out = glue.verify_mark_block(C.txid, C.raw.hex(), json.dumps(anchor), None)
        assert out["anchor"]["caveat"] == BOUND_CAVEAT and out["anchor"]["source"] == glue._ANCHOR_SOURCE

    @pytest.mark.parametrize("bad", [None, 7, "not json", "[]", "x" * 20_000])
    def test_an_unreadable_anchor_json_is_refused(self, glue, bad) -> None:
        out = glue.verify_mark_block(C.txid, C.raw.hex(), bad, None)
        assert out["needs"] is None and out["anchor"] is None and out["reason"]

    @pytest.mark.parametrize("bad", [7, "not json", "[]", json.dumps({"replies": []}), "x" * 1_000_001])
    def test_an_unreadable_proof_json_is_refused(self, glue, bad) -> None:
        out = glue.verify_mark_block(C.txid, C.raw.hex(), json.dumps(self._anchor(glue)), bad)
        assert out["needs"] is None and out["anchor"] is None and out["reason"]

    @pytest.mark.parametrize("bad_txid", [None, "", "AB" * 32, "ab" * 31, 5])
    def test_a_bad_txid_is_refused(self, glue, bad_txid) -> None:
        out = glue.verify_mark_block(bad_txid, C.raw.hex(), json.dumps(self._anchor(glue)), None)
        assert out["needs"] is None and out["anchor"] is None

    @pytest.mark.parametrize("raw", [None, "", "abc", "zz" * 200, 12])
    def test_no_usable_raw_bytes_never_verifies(self, glue, monkeypatch, raw) -> None:
        monkeypatch.setitem(radiant_checkpoints.CHECKPOINTS, "mainnet", _checkpoints(C, C.tip))
        anchor = self._anchor(glue)
        fetched: dict = {"replies": {}, "errors": {}}
        for _ in range(8):
            out = glue.verify_mark_block(C.txid, raw, json.dumps(anchor), json.dumps(fetched))
            if out["needs"] is None:
                break
            fetched["replies"][out["needs"]["key"]] = _call(_server(C), out["needs"]["method"], out["needs"]["params"])
        bv = out["anchor"]["block_verification"]
        assert bv["state"] == "NOT VERIFIED" and out["anchor"]["height_is_verified"] is False

    def test_a_reply_under_a_key_the_plan_never_asked_for_is_ignored(self, glue, monkeypatch) -> None:
        monkeypatch.setitem(radiant_checkpoints.CHECKPOINTS, "mainnet", _checkpoints(C, C.tip))
        fetched = {"replies": {"headers:0:1": {"count": 1, "hex": "00" * 80}}, "errors": {"bogus": "x"}}
        out = glue.verify_mark_block(C.txid, C.raw.hex(), json.dumps(self._anchor(glue)), json.dumps(fetched))
        assert out["needs"]["key"] == "merkle"

    def test_a_long_server_error_is_capped_before_it_becomes_a_reason(self, glue, monkeypatch) -> None:
        monkeypatch.setitem(radiant_checkpoints.CHECKPOINTS, "mainnet", _checkpoints(C, C.tip))
        fetched = {"replies": {}, "errors": {"merkle": "e" * 5000 + "‮"}}
        out = glue.verify_mark_block(C.txid, C.raw.hex(), json.dumps(self._anchor(glue)), json.dumps(fetched))
        reason = out["anchor"]["block_verification"]["reason"]
        assert "‮" not in reason and len(reason) < 400

    def test_it_never_raises(self, glue, monkeypatch) -> None:
        def boom(**_):
            raise RuntimeError("pyrxd's own bug")

        import pyrxd.glyph.mark_block as mb

        monkeypatch.setattr(mb, "verify_with_fetched", boom)
        out = glue.verify_mark_block(C.txid, C.raw.hex(), json.dumps(self._anchor(glue)), None)
        assert out["needs"] is None and out["anchor"] is None and "could not be verified here" in out["reason"]

    def test_it_stays_synchronous(self, glue) -> None:
        """The page's bridge has no event loop to yield to (plan risk 8)."""
        import inspect as _i

        from pyrxd.glyph import mark_block

        for fn in (glue.verify_mark_block, mark_block.verify_with_fetched, mark_block.verify_mark_block):
            assert not _i.iscoroutinefunction(fn), fn.__name__


# ════════════════════════════════════════════════════════════════════════════════════════════
# ON SCREEN: /verify/, every state, from anchors the real glue produced
# ════════════════════════════════════════════════════════════════════════════════════════════


@pytest.fixture(scope="module")
def classified(glue) -> dict:
    """What /verify/'s classifier bridge hands the page for each real fixture transaction."""
    out = {}
    for chain in (C, P):
        result = glue.inspect_txid_with_raw(chain.txid, chain.raw.hex(), 50)
        assert result["ok"], result
        out[chain.txid] = result
    return out


def _anchor_for(glue, monkeypatch, case: str) -> tuple[Chain, dict, dict]:
    chain, client, _ = _setup(monkeypatch, case)
    anchor = page_anchor(glue, chain, client)
    answer, _ = page_proof(glue, chain, client, anchor)
    return chain, anchor, answer["anchor"]


def _verify_render(classified: dict, chain: Chain, anchor: dict, **extra) -> dict:
    result = copy.deepcopy(classified[chain.txid])
    result["payload"]["mark_anchor"] = anchor
    return _harness(_VERIFY_HARNESS, {"case": {"result": result, **extra}}, "-")["case"]


#: Sentences that say the mark's height is NOT verified. None may share a screen with VERIFIED.
_UNVERIFIED_SAYS = ("NOT verified", "pyrxd checks no", "nothing checks proof-of-work or merkle inclusion")


class TestTheVerifyPageShowsEachState:
    @pytest.mark.parametrize(
        "case", ["verified_checkpoint_reference", "verified_work_pyrxd"], ids=["checkpoint", "work"]
    )
    def test_verified_shows_the_pythons_claim_and_the_proved_depth(self, glue, classified, monkeypatch, case) -> None:
        chain, _drawn, settled = _anchor_for(glue, monkeypatch, case)
        claim = settled["block_verification"]["claim"]
        text = _flat(_verify_render(classified, chain, settled)["text"])
        assert f"Verified here: {_flat(claim)}" in text, "the claim is not Python's, whole"
        proved, reported = settled["verified_confirmations"], settled["confirmations"]
        assert f"at least {proved}" in text
        if proved != reported:
            assert f"(the server reports {reported})" in text, "the server's figure is not labelled as the server's"
        # #806's class on this screen: nothing beside VERIFIED says the height is not verified.
        for says in _UNVERIFIED_SAYS:
            assert says not in text, says
        assert "Not verified here" not in text
        # The depth note under two figures: it names which one the page proved, and how deep it
        # tries, and never calls the server's figure "the fact".
        note = _flat(settled["no_depth_policy"])
        assert note in text
        assert "the fact" not in text
        assert f"up to {glue._PROOF_TARGET_DEPTH} confirmations" in note and "the server's word" in note

    def test_inclusion_only_is_never_drawn_as_verified(self, glue, classified, monkeypatch) -> None:
        """The merkle branch passed, the height did not verify: the inclusion-only caveat and the
        reason — never the word VERIFIED (plan risk 2)."""
        chain, _, settled = _anchor_for(glue, monkeypatch, "inclusion_only_headers_served_short")
        assert dict(settled["block_verification"]["steps"])["merkle"] == "passed", "the premise"
        text = _flat(_verify_render(classified, chain, settled)["text"])
        assert f"About that block number: {_flat(INCLUSION_ONLY_CAVEAT)}." in text
        assert f"Not verified here: {_flat(settled['block_verification']['reason'])}." in text
        assert "Verified here:" not in text and "verified here" not in text.replace("Not verified here", "")

    def test_a_failed_merkle_fetch_keeps_the_block_with_the_reason(self, glue, classified, monkeypatch) -> None:
        chain, _, settled = _anchor_for(glue, monkeypatch, "merkle_method_not_found")
        text = _flat(_verify_render(classified, chain, settled)["text"])
        assert f"In block {chain.height}," in text
        assert f"About that block number: {_flat(BOUND_CAVEAT)}." in text
        assert "Not verified here: the transaction's merkle branch could not be fetched from" in text

    def test_a_contradiction_shows_no_block_number(self, glue, classified, monkeypatch) -> None:
        chain, _, settled = _anchor_for(glue, monkeypatch, "contradicted_flipped_sibling")
        text = _verify_render(classified, chain, settled)["text"]
        flat = _flat(text)
        assert "Not established — the block proof" in flat and "contradicts the height reported" in flat
        assert "In block" not in flat
        assert "block" not in text.split("\n"), "a block fact row was drawn under a contradicted proof"

    def test_while_the_proof_runs_the_page_says_so_under_the_servers_word(self, glue, classified, monkeypatch) -> None:
        chain, drawn, _ = _anchor_for(glue, monkeypatch, "verified_checkpoint_reference")
        text = _flat(_verify_render(classified, chain, drawn, view_anchor_pending=True)["text"])
        assert f"About that block number: {_flat(BOUND_CAVEAT)}." in text
        assert "Checking this block against the checkpoints pyrxd ships" in text
        assert "Verified here" not in text


# ════════════════════════════════════════════════════════════════════════════════════════════
# END TO END: each page's own entry point, the REAL glue on both bridges
# ════════════════════════════════════════════════════════════════════════════════════════════


def _verify_check(glue, classified: dict, chain: Chain, checkpoint: int, **extra) -> dict:
    case = {
        "text": chain.txid,
        "raw": {chain.txid: chain.raw.hex()},
        "run_returns": [],
        "fetch_returns": [classified[chain.txid]],
        "anchor_python": sys.executable,
        "verify_python": sys.executable,
        "checkpoints": [list(c) for c in _checkpoints(chain, checkpoint)],
        "confirmations": chain.tip - chain.height + 1,
        "tip": chain.tip,
        "blockhash": chain.hash_at(chain.height),
        "headers": {str(h): b.hex() for h, b in chain.headers.items()},
        "proof": _proof_table(chain),
        **extra,
    }
    return _harness(_VERIFY_HARNESS, {"case": {"check": case}}, "-")["case"]


class TestTheVerifyPageEndToEnd:
    def test_the_page_draws_the_same_claim_the_cli_prints(self, glue, classified, monkeypatch) -> None:
        """THE PARITY THAT A RETYPED STRING CANNOT PASS: the claim `pyrxd verify`'s helper makes for
        these server answers, found verbatim on the page `onCheck` drew."""
        out = _verify_check(glue, classified, P, P.start)
        monkeypatch.setitem(radiant_checkpoints.CHECKPOINTS, "mainnet", _checkpoints(P, P.start))
        anchor = page_anchor(glue, P, _server(P))
        cli, _ = cli_proof(
            P, _server(P), anchor, label=glue._ANCHOR_SOURCE, min_confirmations=page_target(glue, anchor)
        )
        assert cli.state == "VERIFIED"
        text = _flat(out["text"])
        assert f"Verified here: {_flat(cli.claim)}" in text
        assert f"at least {cli.verified_depth}" in text
        assert f"(the server reports {P.tip - P.height + 1})" in text
        for says in _UNVERIFIED_SAYS:
            assert says not in text, says
        # Drawn first, verified after: the anchor bridge finished before the proof bridge began.
        methods = [m for m, _ in out["requested"]]
        assert methods.index("blockchain.transaction.get_merkle") > methods.index("blockchain.block.header")
        assert len(out["calls"]["verify"]) >= 3

    def test_a_server_without_the_merkle_method_still_shows_the_block(self, glue, classified) -> None:
        proof = _proof_table(C, merkle={"error": {"code": -32601, "message": "unknown method"}})
        out = _verify_check(glue, classified, C, C.tip, proof=proof)
        text = _flat(out["text"])
        assert f"In block {C.height}," in text
        assert f"About that block number: {_flat(BOUND_CAVEAT)}." in text
        assert "Not verified here: the transaction's merkle branch could not be fetched from" in text

    def test_a_reader_who_moves_on_during_the_proof_gets_nothing_redrawn(self, glue, classified) -> None:
        """Requests: 1 the transaction, 2 and 3 the depth and the tip, 4 the mark's header, 5 the
        merkle branch — Start over is pressed as it arrives."""
        out = _verify_check(glue, classified, C, C.tip, interleave_clear_on_request=5)
        assert out["requested"][4][0] == "blockchain.transaction.get_merkle", "the premise"
        assert out["text"] == ""
        assert [m for m, _ in out["requested"]].count("blockchain.transaction.id_from_pos") == 0


def _inspect_flow(glue, chain: Chain, checkpoint: int, **extra) -> dict:
    first = glue.inspect_txid_with_raw(chain.txid, chain.raw.hex(), 50, 50)
    spec = {
        "txid": chain.txid,
        "server": {chain.txid: {"hex": chain.raw.hex()}},
        "glue_returns": [first],
        "binding_returns": [],
        "anchor_python": sys.executable,
        "verify_python": sys.executable,
        "checkpoints": [list(c) for c in _checkpoints(chain, checkpoint)],
        "confirmations": chain.tip - chain.height + 1,
        "tip": chain.tip,
        "blockhash": chain.hash_at(chain.height),
        "headers": {str(h): b.hex() for h, b in chain.headers.items()},
        "proof": _proof_table(chain),
        **extra,
    }
    return _harness(_INSPECT_FLOW_HARNESS, spec)


class TestTheInspectPage:
    def test_inspect_draws_the_same_claim_the_cli_prints(self, glue, monkeypatch) -> None:
        out = _inspect_flow(glue, C, C.tip)
        monkeypatch.setitem(radiant_checkpoints.CHECKPOINTS, "mainnet", _checkpoints(C, C.tip))
        anchor = page_anchor(glue, C, _server(C))
        cli, _ = cli_proof(
            C, _server(C), anchor, label=glue._ANCHOR_SOURCE, min_confirmations=page_target(glue, anchor)
        )
        text = _flat(out["rendered"])
        assert f"Verified: {_flat(cli.claim)}" in text
        assert f"{C.height} — VERIFIED, at least {cli.verified_depth} confirmation(s) verified" in text
        for says in _UNVERIFIED_SAYS:
            assert says not in text.split('"mark_anchor"')[0], says  # the card, above the JSON drawer
        # The JSON drawer is redrawn with the card: it carries the verified anchor, not the old one.
        assert '"height_is_verified": true' in out["rendered"]
        assert "block_proof_pending" not in out["rendered"]

    def test_inspect_at_the_work_level_shows_the_proved_depth_not_the_servers(self, glue, monkeypatch) -> None:
        """WHERE THE TWO DEPTHS DIFFER. At the checkpoint level the fixture's proved depth equals the
        server's count by construction (both 9), so a card printing the server's figure as the
        proved one would pass every test above. At the proof-of-work level the page proves six and
        the server reports nine: the card must print six as proved, and nine only as the server's."""
        out = _inspect_flow(glue, P, P.start)
        monkeypatch.setitem(radiant_checkpoints.CHECKPOINTS, "mainnet", _checkpoints(P, P.start))
        anchor = page_anchor(glue, P, _server(P))
        cli, _ = cli_proof(
            P, _server(P), anchor, label=glue._ANCHOR_SOURCE, min_confirmations=page_target(glue, anchor)
        )
        proved, reported = cli.verified_depth, P.tip - P.height + 1
        assert cli.state == "VERIFIED" and cli.level == "work" and proved != reported, "the premise"
        card = _flat(out["rendered"]).split('"mark_anchor"')[0]
        assert f"Verified: {_flat(cli.claim)}" in card
        assert (
            f"{P.height} — VERIFIED, at least {proved} confirmation(s) verified (the server reports {reported})"
        ) in card
        assert f"Depth: at least {proved} confirmation(s) verified here." in card
        assert f"at least {reported} confirmation(s) verified" not in card

    def test_inspect_keeps_the_block_when_the_merkle_fetch_fails(self, glue) -> None:
        proof = _proof_table(C, merkle={"error": {"code": -32601, "message": "unknown method"}})
        out = _inspect_flow(glue, C, C.tip, proof=proof)
        text = _flat(out["rendered"])
        assert f"{C.height} — {C.tip - C.height + 1} confirmation(s) deep" in text
        assert "Not verified here: the transaction's merkle branch could not be fetched from" in text

    def test_inspect_keeps_a_file_comparison_across_the_proofs_redraw(self, glue) -> None:
        """The reviewer's case: a file chosen just after the block is drawn — here as the merkle
        branch is requested (request 5) — and the proof landing after. The card is redrawn when it
        lands; the comparison's answer must still be on it, not lost with the old card."""
        out = _inspect_flow(glue, C, C.tip, choose_file={"on_request": 5, "hex": "00ff" * 8})
        assert out["server_log"][4][0] == "blockchain.transaction.get_merkle", "the premise"
        assert out["files_chosen"] == 1, "the premise: the drawn card had one file check"
        text = _flat(out["rendered"])
        assert f"{C.height} — VERIFIED" in text, "the premise: the proof landed and the card was redrawn"
        assert "DOES NOT MATCH" in text, "the file comparison did not survive the redraw"
        assert "Hashing chosen.bin" not in text, "the comparison never finished on the card shown"

    def test_inspect_a_reader_who_moves_on_during_the_proof_gets_no_redraw(self, glue) -> None:
        """The wait `proveMarkBlock` adds to `onFetchTxid`, interrupted: request 5 is the merkle
        branch (1 the transaction, 2-3 depth and tip, 4 the mark's header)."""
        out = _inspect_flow(glue, C, C.tip, interleave="clear", interleave_on_request=5)
        assert out["server_log"][4][0] == "blockchain.transaction.get_merkle", "the premise"
        assert out["rendered"] == ""
        assert [m for m, _ in out["server_log"]].count("blockchain.transaction.id_from_pos") == 0

    @pytest.mark.parametrize(
        ("case", "expect", "forbid"),
        [
            ("inclusion_only_headers_served_short", "Not verified here:", "VERIFIED, at least"),
            ("contradicted_flipped_sibling", "not established — the block proof", "confirmation(s) deep"),
        ],
        ids=["inclusion_only", "contradicted"],
    )
    def test_inspect_draws_each_other_state(self, glue, monkeypatch, case, expect, forbid) -> None:
        chain, _, settled = _anchor_for(glue, monkeypatch, case)
        result = copy.deepcopy(glue.inspect_txid_with_raw(chain.txid, chain.raw.hex(), 50, 50))
        result["payload"]["mark_anchor"] = settled
        text = _flat(_harness(_INSPECT_RENDER_HARNESS, {"case": {"result": result}}, "-")["case"]["result_block"])
        card = text.split('"mark_anchor"')[0]
        assert expect in card and forbid not in card
