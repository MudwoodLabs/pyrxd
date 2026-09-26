"""The mark's block is the block its header says, not what `tip - confirmations + 1` says.

THE FINDING (0.25.0 panel, round 2, M1, lane E, measured read-only on mainnet). ``resolve_mark_anchor``
derived the height as ``tip - confirmations + 1``. The tip is ElectrumX's ``headers.subscribe`` —
its INDEXED height — while ``confirmations`` passes through from its node, which gets each new
block seconds before the index does. In that window the formula is one block LOW, and it is low
on EVERY server at once, so the two-server rule could not see it: of 470 paired samples over
1,171 s, both shipped servers were one block low together in 7 (they passed corroboration) and
disagreed in 5. In 12 live runs of `verify --wave-name custodian-gate-x7f3.rxd`, run 11 printed
ESTABLISHED at "block 460571"; the block whose header hashes to the verbose `blockhash` is 460572.
It flips a form-2 verdict when a name update shares the mark's block (rename, then sign).

THE FIX, at the funnel. ``resolve_anchor_from`` — the one door every CLI anchor comes through —
passes ``fetch_header``, and ``resolve_mark_anchor`` then returns the height whose header hashes to
the verbose ``blockhash``, searching ``MAX_INDEX_LAG_BLOCKS`` either side of the formula (usually it
is low; round 3 added below, for a node behind its index), or raises ``AnchorBindingError``. A block
number no header confirmed is never printed.

The fakes here are the derived ``FakeChainServer``: every transaction real mainnet bytes, each
height's header a synthetic 80 bytes whose hash the fake reports as the verbose ``blockhash``. The
lag is modelled as an OPERATION on that truth — the index tip reported one block behind the node.
"""

from __future__ import annotations

import hashlib
import pathlib
import re
import sys

import pytest

from pyrxd.cli import glyph_inspect
from pyrxd.glyph.mark_anchor import (
    BOUND_CAVEAT,
    MAX_INDEX_LAG_BLOCKS,
    UNVERIFIED_CAVEAT,
    AnchorBindingError,
    resolve_mark_anchor,
)
from pyrxd.keys import PrivateKey
from pyrxd.security.errors import NetworkError
from tests.test_mutable_chain_is_discovered_from_the_chain import (
    HEIGHTS,
    MARK,
    MINT,
    MINT_TARGET,
    MOVED,
    UPDATE_A,
    block_hash_at,
    synthetic_header,
)
from tests.test_name_at_mark_reaches_the_cli import MOVED_H160, _payload, _run, _Server

SAME_BLOCK = HEIGHTS[UPDATE_A]  # 458591: the name moved to MOVED in this block, and the mark is in it too


class _IndexBehindNode(_Server):
    """Honest data; the ElectrumX INDEX tip trails the node that answers the verbose call."""

    def __init__(self, *, lag: int = 1, **kw) -> None:
        super().__init__(**kw)
        self.lag = lag

    async def get_tip_height(self) -> int:
        return self.tip - self.lag

    async def get_block_header(self, height) -> bytes:
        # ElectrumX serves headers only up to its OWN index tip, which is the lagging one.
        if int(height) > self.tip - self.lag:
            self.calls.append(("get_block_header", str(int(height))))
            raise NetworkError(f"height {int(height)} out of range")
        return await super().get_block_header(height)


def _pair(a_cls=_Server, b_cls=_Server, **kw):
    a = a_cls(indexer=False, mark_heights={MARK: SAME_BLOCK}, **kw)
    b = b_cls(indexer=True, mark_heights={MARK: SAME_BLOCK}, **kw)
    return a, "wss://a", b, "wss://b"


# ---------------------------------------------------------------------------
# Through the CLI: lane E's probe
# ---------------------------------------------------------------------------


def test_both_indexes_one_block_behind_still_place_the_mark_in_its_real_block(monkeypatch) -> None:
    """LANE E'S PROBE (`panel-e-744/tests/test_panel_e_744_index_lag.py`). Before: both servers
    'agreed' on 458590, form 2 folded the mint only, and the new key read NOT THE SIGNER with an
    empty reason. Now both bind to 458591 by the header, and the moved target is the answer."""
    nam = _run(monkeypatch, _payload(MOVED_H160), _pair(_IndexBehindNode, _IndexBehindNode))
    assert nam["form"] == 2, nam["degraded_reason"]
    assert nam["height"] == SAME_BLOCK
    assert nam["anchor"]["height"] == SAME_BLOCK, "the anchor itself — what `verify` prints — is the real block"
    assert nam["target_at_height"] == MOVED and nam["signer_is_target_at_height"] is True


def test_one_lagging_index_no_longer_makes_honest_servers_disagree(monkeypatch) -> None:
    """The other half of the measurement (5 of 470 samples): one server low, one not. That was a
    false degrade of an honest pair; bound, both place the mark in the same, real block."""
    nam = _run(monkeypatch, _payload(MOVED_H160), _pair(_IndexBehindNode, _Server))
    assert nam["form"] == 2, nam["degraded_reason"]
    assert {r["mark"] for r in nam["heights"]["by_source"]} == {SAME_BLOCK}


def test_in_sync_servers_are_unchanged(monkeypatch) -> None:
    nam = _run(monkeypatch, _payload(MOVED_H160), _pair())
    assert nam["form"] == 2 and nam["height"] == SAME_BLOCK and nam["target_at_height"] == MOVED


def test_the_anchor_that_reaches_verify_asked_for_the_header(monkeypatch) -> None:
    """Reachability: the binding runs on the production path, not only in the unit below."""
    a, la, b, lb = _pair(_IndexBehindNode, _IndexBehindNode)
    _run(monkeypatch, _payload(MOVED_H160), (a, la, b, lb))
    assert ("get_block_header", str(SAME_BLOCK - 1)) in a.calls, "the formula's height was checked"
    assert ("get_block_header", str(SAME_BLOCK)) in a.calls, "and the real one found by its header"


def test_the_printed_caveat_says_what_the_binding_is(monkeypatch) -> None:
    """The unbound caveat says the height was not checked against any header; for a bound anchor
    that sentence is false, so the bound one is printed — and it still says NOT verified."""
    nam = _run(monkeypatch, _payload(MOVED_H160), _pair())
    assert nam["anchor"]["caveat"] == BOUND_CAVEAT
    assert "NOT verified" in BOUND_CAVEAT and "checked only against the endpoint itself" in BOUND_CAVEAT


# ---------------------------------------------------------------------------
# The library: every branch of the binding
# ---------------------------------------------------------------------------


async def _resolve(*, confirmations: int, tip: int, verbose_extra=None, headers=None, bind=True):
    async def verbose(txid: str) -> dict:
        return {"txid": txid, "confirmations": confirmations, **(verbose_extra or {})}

    async def header(height: int) -> bytes:
        if headers is not None:
            return headers(height)
        return synthetic_header(height)

    return await resolve_mark_anchor(
        txid=MARK,
        fetch_verbose=verbose,
        source="endpoint",
        min_confirmations=6,
        tip_height=tip,
        fetch_header=header if bind else None,
    )


@pytest.mark.parametrize("lag", range(MAX_INDEX_LAG_BLOCKS + 1))
async def test_the_true_block_is_found_within_the_lag_window(lag) -> None:
    """The node's count says the mark is at 1000; the index tip is `lag` blocks behind."""
    node_tip, true_height = 1009, 1000
    anchor = await _resolve(
        confirmations=node_tip - true_height + 1,
        tip=node_tip - lag,
        verbose_extra={"blockhash": block_hash_at(true_height)},
    )
    assert anchor.height == true_height
    assert anchor.caveat == BOUND_CAVEAT
    assert anchor.confirmations == 10, "depth is the node's count, untouched by the binding"


@pytest.mark.parametrize("ahead", range(1, MAX_INDEX_LAG_BLOCKS + 1))
async def test_a_formula_that_comes_out_high_is_found_below_it(ahead) -> None:
    """Round 3 (lane E): the window is SYMMETRIC. When the node answering the verbose call is BEHIND
    the index (an ElectrumX failing over between nodes, or a reorg), its confirmation count is short
    and `tip - confirmations + 1` comes out HIGH. Searching only upward refused that honest endpoint;
    a match still has to hash to the block the node named, so looking lower costs nothing."""
    tip, true_height = 1009, 1000
    anchor = await _resolve(
        confirmations=tip - true_height + 1 - ahead,
        tip=tip,
        verbose_extra={"blockhash": block_hash_at(true_height)},
    )
    assert anchor.height == true_height and anchor.header_bound


@pytest.mark.parametrize("off", [MAX_INDEX_LAG_BLOCKS + 1, -(MAX_INDEX_LAG_BLOCKS + 1)])
async def test_beyond_the_window_either_way_it_refuses_rather_than_guessing(off) -> None:
    tip, true_height = 1009, 1000
    with pytest.raises(AnchorBindingError, match="is not its header at any height from"):
        await _resolve(
            confirmations=tip - true_height + 1 + off,
            tip=tip,
            verbose_extra={"blockhash": block_hash_at(true_height)},
        )


async def test_the_window_does_not_reach_below_the_genesis_block() -> None:
    """A mark in block 0 or 1 cannot have candidates at negative heights; they are skipped, not
    asked for."""
    asked: list[int] = []

    def header(height: int) -> bytes:
        asked.append(height)
        return synthetic_header(height)

    anchor = await _resolve(confirmations=10, tip=10, verbose_extra={"blockhash": block_hash_at(0)}, headers=header)
    assert anchor.height == 0, "derived height 1; the block is at 0, one below"
    assert min(asked) >= 0 and -1 not in asked, asked


async def test_a_confirmed_reply_with_no_block_hash_is_refused() -> None:
    with pytest.raises(NetworkError, match="no block hash to bind"):
        await _resolve(confirmations=10, tip=1009)
    with pytest.raises(NetworkError, match="no block hash to bind"):
        await _resolve(confirmations=10, tip=1009, verbose_extra={"blockhash": "zz" * 32})


async def test_a_header_the_endpoint_cannot_serve_is_refused_naming_it() -> None:
    """Every header unreadable: the search tries each candidate, then refuses, naming what failed.
    An `AnchorBindingError` — the endpoint answered — not a bare network failure."""

    def refuse(height: int) -> bytes:
        raise NetworkError("height out of range")

    with pytest.raises(AnchorBindingError, match="headers it could not serve") as caught:
        await _resolve(confirmations=10, tip=1009, verbose_extra={"blockhash": block_hash_at(1000)}, headers=refuse)
    assert "height out of range" in str(caught.value)


async def test_one_unreadable_header_does_not_stop_the_search() -> None:
    """Above the index's tip a header cannot be served; the match below it must still be found."""
    true_height = 1000

    def header(height: int) -> bytes:
        if height > true_height:
            raise NetworkError("height out of range")
        return synthetic_header(height)

    anchor = await _resolve(
        confirmations=9, tip=1009, verbose_extra={"blockhash": block_hash_at(true_height)}, headers=header
    )
    assert anchor.height == true_height


async def test_a_header_that_is_not_80_bytes_is_refused_not_hashed() -> None:
    with pytest.raises(AnchorBindingError, match="headers it could not serve"):
        await _resolve(
            confirmations=10, tip=1009, verbose_extra={"blockhash": block_hash_at(1000)}, headers=lambda h: b"\x00" * 79
        )


async def test_an_unmined_mark_needs_no_header() -> None:
    """Zero confirmations has no block to bind; nothing is fetched and nothing is claimed."""

    def never(height: int) -> bytes:
        raise AssertionError("a header was fetched for an unmined transaction")

    anchor = await _resolve(confirmations=0, tip=1009, headers=never)
    assert anchor.height is None


async def test_without_a_header_fetcher_the_library_is_still_the_formula() -> None:
    """What the bare library does when a caller passes no `fetch_header`: the arithmetic, one block
    low under lag, with the UNBOUND caveat. No shipped surface calls it that way any more — the
    CLI funnel binds (`test_the_cli_funnel_always_binds`) and so do the pages' glue
    (`test_the_pages_glue_binds`) — so this pins the library's contract for any future caller, and
    the unbound caveat that such a caller would have to show."""
    node_tip, true_height = 1009, 1000
    anchor = await _resolve(
        confirmations=node_tip - true_height + 1,
        tip=node_tip - 1,
        verbose_extra={"blockhash": block_hash_at(true_height)},
        bind=False,
    )
    assert anchor.height == true_height - 1
    assert anchor.caveat == UNVERIFIED_CAVEAT


def test_the_pages_glue_binds() -> None:
    """The flip of what this test used to pin ("the pages' glue does not bind yet"). The page
    bridge now calls `resolve_mark_anchor` WITH a header fetcher, and — executed, not only read —
    under the same lag the CLI tests model it lands on the true block, carrying the bound caveat.

    The bridge cannot fetch, so it answers `needs_headers` until the page has handed over the
    header the rule asks for next; the loop below plays the page's part against the fake chain's
    headers. `tests/web/test_mark_anchor_bridge.py` does the same with real mainnet headers, and the
    page harnesses drive the JavaScript side of the loop.
    """
    import inspect as _inspect
    import json

    glue_dir = pathlib.Path(__file__).resolve().parents[1] / "docs" / "inspect_static" / "inspect"
    sys.path.insert(0, str(glue_dir))
    try:
        import glue

        source = _inspect.getsource(glue.mark_anchor)
        node_tip, true_height, txid = 1009, 1000, "ab" * 32
        verbose = json.dumps(
            {"txid": txid, "confirmations": node_tip - true_height + 1, "blockhash": block_hash_at(true_height)}
        )
        fetched: dict = {"headers": {}, "errors": {}}
        answer: dict = {}
        for _ in range(2 * MAX_INDEX_LAG_BLOCKS + 2):
            answer = glue.mark_anchor(txid, verbose, node_tip - 1, json.dumps(fetched))
            if not answer.get("needs_headers"):
                break
            height = answer["needs_headers"][0]
            fetched["headers"][str(height)] = synthetic_header(height).hex()
    finally:
        sys.path.remove(str(glue_dir))
        sys.modules.pop("glue", None)
    assert "resolve_mark_anchor(" in source, "the premise: the page calls the library"
    assert "fetch_header=" in source, "the page bridge calls the library without a header fetcher"
    assert answer.get("resolved") is True, answer
    assert answer["height"] == true_height, "one block low: the formula, not the header"
    assert answer["caveat"] == BOUND_CAVEAT
    assert sorted(int(h) for h in fetched["headers"]) == [true_height - 1, true_height]


def test_the_cli_funnel_always_binds() -> None:
    """`resolve_anchor_from` is the one door; the header fetcher is passed unconditionally there."""
    import inspect as _inspect

    source = _inspect.getsource(glyph_inspect.resolve_anchor_from)
    assert "fetch_header=client.get_block_header" in source


def test_one_block_earlier_the_name_pointed_at_the_old_key() -> None:
    """Non-vacuity for the CLI probe above: at SAME_BLOCK - 1 the mint is in force and the update
    is not, so a height one low really changes the answer rather than landing on the same one."""
    assert HEIGHTS[MINT] <= SAME_BLOCK - 1 < HEIGHTS[UPDATE_A]
    assert MINT_TARGET != MOVED


# ---------------------------------------------------------------------------
# Round 3: no sentence on a bound verdict's screen may say the header was NOT checked
# ---------------------------------------------------------------------------

#: The CLASS, matched loosely rather than by one exact string (round 2's test pinned only
#: `UNVERIFIED_CAVEAT` verbatim, and `_corroborated_caveat` said the same false thing in other words
#: on the same screen — 0.25.0 panel, round 3). Each pattern stays inside one clause.
_NO_HEADER_CHECK = [
    re.compile(r"\bno\b[^.;:]{0,80}\bheader\b[^.;:]{0,80}\b(check|verif)", re.I),
    re.compile(r"\bnot\b[^.;:]{0,40}\bcheck\w*\b[^.;:]{0,40}\bheader", re.I),
    re.compile(r"\bno\b[^.;:]{0,40}\bheight\b[^.;:]{0,40}\bcheck\w*\b[^.;:]{0,40}\bheader", re.I),
]


def _claims_no_header_check(text: str) -> list[str]:
    flat = " ".join(text.split())
    return [m.group(0) for pat in _NO_HEADER_CHECK for m in pat.finditer(flat)]


def test_the_matcher_catches_every_spelling_this_class_has_shipped_in() -> None:
    """Non-vacuity: the three sentences this project has used for "no header was checked" all match.
    If the matcher stops seeing them, the tests below have stopped measuring."""
    shipped = [
        "and are NOT verified: pyrxd has no Radiant header, proof-of-work or merkle-inclusion check, so",
        UNVERIFIED_CAVEAT,
        "No height here was checked against a block header.",
    ]
    for sentence in shipped:
        assert _claims_no_header_check(sentence), sentence
    assert not _claims_no_header_check(BOUND_CAVEAT), "the bound caveat must not trip the matcher"


def _verify_output(monkeypatch, tmp_path, *extra: str) -> str:
    """The real `pyrxd verify --wave-name` over two agreeing servers that serve headers — a BOUND
    anchor and a form-2 ESTABLISHED verdict (the one-record suite's harness, unchanged)."""
    from tests.test_hashmark_verify_one_record import NAME, _address, _run, _signed, _tx

    key = PrivateKey()
    content = b"a press kit\n"
    txid, raw = _tx(_signed(content, key))
    digest = hashlib.sha256(content).hexdigest()
    args = [*extra, "verify", txid, "--digest", digest, "--wave-name", NAME, "--min-confirmations", "6"]
    r = _run(monkeypatch, {txid: raw}, args, tmp_path, name_target=_address(key))
    assert r.exit_code == 0, r.output
    return r.output


@pytest.mark.parametrize("mode", [[], ["--json"]], ids=["human", "json"])
def test_no_output_of_a_bound_verdict_says_the_header_was_not_checked(monkeypatch, tmp_path, mode) -> None:
    out = _verify_output(monkeypatch, tmp_path, *mode)
    assert "ESTABLISHED" in out, "the premise: a form-2 verdict on a bound anchor"
    assert not _claims_no_header_check(out), _claims_no_header_check(out)
    flat = " ".join(out.split())
    assert "checked against each endpoint's own block header" in flat
    assert "the step heights were not" in flat, "what the header check does NOT cover is said too"
    assert "Nothing checks proof-of-work or merkle inclusion" in flat


async def test_an_unbound_report_gets_the_weaker_sentence() -> None:
    """The caveat is true by construction: a caller whose reports do not say the mark was bound gets
    "No height here was checked against a block header" — never a claim nobody made."""
    from pyrxd.glyph.mark_anchor import MarkAnchor
    from pyrxd.glyph.wave_identity import HeightReport, judge_name_at_mark
    from tests.test_form2_step_heights_need_two_sources import TRUE, _walk

    walk = await _walk()
    anchor = MarkAnchor(txid=MARK, height=458595, confirmations=50, min_confirmations=6, source="node-A")
    reports = [HeightReport("node-A", 458595, TRUE), HeightReport("index-B", 458595, TRUE)]
    v = judge_name_at_mark(
        ref=walk.ref,
        name="custodian-gate-x7f3.rxd",
        binding_source="index-B",
        anchor=anchor,
        walk=walk,
        height_reports=reports,
    )
    assert v.form == 2 and "No height here was checked against a block header" in v.caveat
    bound = [HeightReport(r.source, r.mark_height, r.step_heights, mark_header_bound=True) for r in reports]
    v = judge_name_at_mark(
        ref=walk.ref,
        name="custodian-gate-x7f3.rxd",
        binding_source="index-B",
        anchor=anchor,
        walk=walk,
        height_reports=bound,
    )
    assert "checked against each endpoint's own block header" in v.caveat
    half = [bound[0], reports[1]]
    v = judge_name_at_mark(
        ref=walk.ref,
        name="custodian-gate-x7f3.rxd",
        binding_source="index-B",
        anchor=anchor,
        walk=walk,
        height_reports=half,
    )
    assert "No height here was checked against a block header" in v.caveat, "one unbound report is enough to say so"


# ---------------------------------------------------------------------------
# Round 3: a binding failure is not "unreachable"
# ---------------------------------------------------------------------------


def test_plain_verify_says_the_endpoint_answered_when_its_headers_disagree(monkeypatch, tmp_path) -> None:
    """The endpoint WAS reachable; its node named a block no nearby header hashes to. `verify` said
    "check that <url> is reachable", sending people to debug a connection that worked."""
    from tests.test_hashmark_verify_cli import TIP, _FakeServer, _mark_script, _tx_with
    from tests.test_hashmark_verify_cli import _run as _run_verify

    class _HeadersDisagree(_FakeServer):
        async def get_block_header(self, height) -> bytes:
            return synthetic_header(int(height) + 1000)  # never the block its node named

    txid, raw = _tx_with(_mark_script(b"a report\n", PrivateKey()))
    server = _HeadersDisagree({txid: raw})
    assert server.tip == TIP, "the premise: the fake's node and index agree on the tip"
    r = _run_verify(monkeypatch, server, ["verify", txid, "--min-confirmations", "6"], tmp_path=tmp_path)
    assert r.exit_code == 2, r.output
    flat = " ".join(r.output.split())
    assert "wss://only answered, but its index and its node disagree" in flat
    assert "--electrumx URL" in flat and "re-run" in flat
    assert "is reachable" not in flat


def test_an_unreachable_endpoint_is_still_reported_as_unreachable(monkeypatch, tmp_path) -> None:
    """The honest pair: a real network failure keeps the reachability advice."""
    from pyrxd.security.errors import NetworkError as _NetworkError
    from tests.test_hashmark_verify_cli import _FakeServer, _mark_script, _tx_with
    from tests.test_hashmark_verify_cli import _run as _run_verify

    class _Down(_FakeServer):
        async def get_tip_height(self) -> int:
            raise _NetworkError("connection refused")

    txid, raw = _tx_with(_mark_script(b"a report\n", PrivateKey()))
    r = _run_verify(monkeypatch, _Down({txid: raw}), ["verify", txid, "--min-confirmations", "6"], tmp_path=tmp_path)
    assert r.exit_code == 2, r.output
    assert "is reachable" in " ".join(r.output.split())


# ---------------------------------------------------------------------------
# Review round 2: "its index and its node disagree" only when every header arrived
# ---------------------------------------------------------------------------
#
# THE FALSE SENTENCE. The binding said the block "is not its header at any height from lo to hi …
# its index and its node disagree" even when some of those headers could not be read. On an HONEST
# chain whose header at the mark's own height is refused (or times out), the other headers not
# matching is exactly what honesty looks like — the missing one is the match — so the endpoint was
# accused of contradicting itself for a header it never sent. The browser pages had the same
# sentence and were fixed first; this is the CLI sibling. Each case below is paired with the true
# disagreement, where every header in the window is served and none matches.

_TRUE_HEIGHT, _NODE_TIP = 1000, 1009


def _refusing(refused: int):
    def header(height: int) -> bytes:
        if height == refused:
            raise NetworkError(f"height {height}: request timed out")
        return synthetic_header(height)

    return header


async def test_a_refused_header_on_an_honest_chain_is_named_not_called_a_disagreement() -> None:
    with pytest.raises(AnchorBindingError) as caught:
        await _resolve(
            confirmations=_NODE_TIP - _TRUE_HEIGHT + 1,
            tip=_NODE_TIP,
            verbose_extra={"blockhash": block_hash_at(_TRUE_HEIGHT)},
            headers=_refusing(_TRUE_HEIGHT),
        )
    exc = caught.value
    assert exc.unserved == (_TRUE_HEIGHT,) and not exc.disagrees
    assert sorted(exc.served) == [_TRUE_HEIGHT - 2, _TRUE_HEIGHT - 1, _TRUE_HEIGHT + 1, _TRUE_HEIGHT + 2]
    assert f"did not serve a usable header at heights {_TRUE_HEIGHT} " in str(exc)
    assert "request timed out" in str(exc), "what failed is still named"
    assert "disagree" not in str(exc)


async def test_every_header_served_and_none_matching_is_the_disagreement() -> None:
    """The pair: the whole window arrives and none of it is the node's block."""
    with pytest.raises(AnchorBindingError) as caught:
        await _resolve(
            confirmations=_NODE_TIP - _TRUE_HEIGHT + 1, tip=_NODE_TIP, verbose_extra={"blockhash": block_hash_at(2000)}
        )
    exc = caught.value
    assert exc.disagrees and exc.unserved == () and len(exc.served) == 2 * MAX_INDEX_LAG_BLOCKS + 1
    assert "its index and its node disagree" in str(exc)


def _verify_exit(monkeypatch, tmp_path, server_cls) -> str:
    from tests.test_hashmark_verify_cli import _mark_script, _tx_with
    from tests.test_hashmark_verify_cli import _run as _run_verify

    txid, raw = _tx_with(_mark_script(b"a report\n", PrivateKey()))
    r = _run_verify(
        monkeypatch, server_cls({txid: raw}), ["verify", txid, "--min-confirmations", "6"], tmp_path=tmp_path
    )
    assert r.exit_code == 2, r.output
    return " ".join(r.output.split())


def test_plain_verify_names_the_header_it_was_refused_rather_than_blaming_the_server(monkeypatch, tmp_path) -> None:
    """Through the real `verify` command: an honest fake whose header at the mark's own height is
    refused. The exit-2 advice names that height; it does not say the index and node disagree."""
    from tests.test_hashmark_verify_cli import _FakeServer

    class _RefusesTheMarksHeader(_FakeServer):
        async def get_block_header(self, height) -> bytes:
            if int(height) == self.tip - self.confirmations + 1:
                self.calls.append(("get_block_header", str(int(height))))
                raise NetworkError(f"height {int(height)}: request timed out")
            return await super().get_block_header(height)

    probe = _RefusesTheMarksHeader({})
    mark_height = probe.tip - probe.confirmations + 1
    flat = _verify_exit(monkeypatch, tmp_path, _RefusesTheMarksHeader)
    assert f"wss://only answered, but did not serve the block headers at heights {mark_height}," in flat
    assert "disagree" not in flat
    assert "is reachable" not in flat and "--electrumx URL" in flat


def test_plain_verify_still_says_disagree_when_every_header_arrived(monkeypatch, tmp_path) -> None:
    """The pair, stated with the attribute the advice now reads: all five served, none matching."""
    from tests.test_hashmark_verify_cli import _FakeServer

    class _HeadersDisagree(_FakeServer):
        async def get_block_header(self, height) -> bytes:
            return synthetic_header(int(height) + 1000)

    flat = _verify_exit(monkeypatch, tmp_path, _HeadersDisagree)
    assert "wss://only answered, but its index and its node disagree" in flat
    assert "did not serve" not in flat


def test_form_2_degrades_with_the_true_reason_for_each_failure(monkeypatch) -> None:
    """The form-2 path reports the anchor's failure in its degrade reason (the exception's own
    words). Both endpoints refuse the header at the mark's block: the reason names it and does not
    say "disagree". Paired: both serve every header and none is the node's block."""

    class _RefusesTheMarksHeader(_Server):
        async def get_block_header(self, height) -> bytes:
            if int(height) == SAME_BLOCK:
                raise NetworkError(f"height {int(height)}: request timed out")
            return await super().get_block_header(height)

    class _HeadersDisagree(_Server):
        async def get_block_header(self, height) -> bytes:
            return synthetic_header(int(height) + 100_000)

    refused = _run(monkeypatch, _payload(MOVED_H160), _pair(_RefusesTheMarksHeader, _RefusesTheMarksHeader))
    assert refused["resolved"] is False, refused
    assert f"did not serve a usable header at heights {SAME_BLOCK} " in refused["reason"]
    assert "disagree" not in refused["reason"]

    disagree = _run(monkeypatch, _payload(MOVED_H160), _pair(_HeadersDisagree, _HeadersDisagree))
    assert disagree["resolved"] is False, disagree
    assert "its index and its node disagree" in disagree["reason"]


def test_the_page_and_the_cli_tell_each_failure_the_same_way() -> None:
    """ONE classification. The page words its reason from the same exception attributes the CLI's
    advice reads — for a refused header and for a true disagreement, the two agree on which it is."""
    import inspect as _inspect

    glue_dir = pathlib.Path(__file__).resolve().parents[1] / "docs" / "inspect_static" / "inspect"
    sys.path.insert(0, str(glue_dir))
    try:
        import glue

        source = _inspect.getsource(glue._unbound_reason)
    finally:
        sys.path.remove(str(glue_dir))
        sys.modules.pop("glue", None)
    assert "exc.disagrees" in source and "exc.unserved" in source, "the page classifies the failure itself"
    cli = _inspect.getsource(sys.modules["pyrxd.cli.hashmark_cmds"])
    assert "exc.disagrees" in cli and "exc.unserved" in cli, "the CLI's advice classifies the failure itself"
