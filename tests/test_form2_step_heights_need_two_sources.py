"""§7.6 form 2: every block height the verdict compares must come from BOTH endpoints.

THE FINDING (0.25.0 pre-release panel, HIGH, two reviewers independently). Form 2 answers "what did
this name point at in the mark's block" by folding every update at or before that block. So the
answer is decided by HEIGHTS as much as by the binding: the mark's height, and each chain step's.
The rules that existed covered the binding (not from the anchor's server) and the tip proof (not
from the discovery server). The step heights came from the DISCOVERY server's
``blockchain.scripthash.get_history`` alone — and with the shipped endpoint order that is endpoint
A, which also supplies the mark's anchor. ONE server that reported ONE update's height a few blocks
late (still monotonic, still plausible) moved which target was in force at the mark and flipped
``pyrxd verify --wave-name`` to ESTABLISHED for a retired key. The module docstring said servers
could lie only about existence and spentness "and nothing else needs covering".

THE FIX. The tip server is asked, independently, where each walked step is
(``walk_discovered_chain`` → ``tip_heights``); the endpoint that did NOT supply the anchor is asked
where the mark is; and ``judge_name_at_mark`` takes one :class:`HeightReport` per endpoint and
refuses form 2 unless two DISTINCT sources agree on every height. Any disagreement, or a server
that cannot answer, degrades to form 1 naming it.

The CLI-level tests below are the panel's own probes (``panel-c/test_panelc_probe_heights.py``,
``panel-e/test_panel_e_step_heights.py``), driven through the real attach path with the lie
modelled as an OPERATION on the derived fake server's truth: every transaction is real mainnet
bytes, every history is derived from them, and only the one height is changed.
"""

from __future__ import annotations

import pytest

from pyrxd.base58 import base58check_decode
from pyrxd.cli import glyph_inspect, hashmark_cmds
from pyrxd.glyph.mark_anchor import MarkAnchor
from pyrxd.glyph.mutable_chain import walk_mutable_chain
from pyrxd.glyph.wave_identity import HeightReport, judge_name_at_mark
from pyrxd.security.errors import NetworkError
from tests.test_mutable_chain_is_discovered_from_the_chain import (
    HEIGHTS,
    MARK,
    MINT,
    MINT_TARGET,
    MOVED,
    RAW,
    UPDATE_A,
    UPDATE_B,
)
from tests.test_name_at_mark_reaches_the_cli import MOVED_H160, NAME, _ctx, _payload, _Server

RETIRED_H160 = base58check_decode(MINT_TARGET)[1:].hex()


class _HeightLiar(_Server):
    """Serves real bytes and real history MEMBERSHIP; lies only about the heights in ``lie``."""

    def __init__(self, *, lie: dict[str, int], **kw) -> None:
        super().__init__(**kw)
        self.lie = lie

    async def get_history(self, script_hash):
        return [
            {**e, "height": self.lie.get(e["tx_hash"], e["height"])} for e in await super().get_history(script_hash)
        ]


def _attach(monkeypatch: pytest.MonkeyPatch, pair, h160: str, *, name: str = NAME) -> dict:
    monkeypatch.setattr(glyph_inspect, "_endpoint_pair", lambda ctx: pair)
    payload = _payload(h160)
    glyph_inspect._attach_name_at_mark(_ctx(), payload, name=name, min_confirmations=6)
    return payload["outputs"][0]["hashmark"]["name_at_mark"]


# ---------------------------------------------------------------------------
# The panel's probes — each flipped the verdict before the fix
# ---------------------------------------------------------------------------


def test_the_discovery_server_alone_cannot_flip_the_verdict_by_one_step_height(monkeypatch) -> None:
    """PANEL C, shipped shape (indexer on B → binding B, anchor A, discovery A). Truth: the name
    moved to MOVED at 458591; a mark at 458595 signed by the RETIRED key is NOT the target. A
    reports UPDATE_A at 458599 instead — later than the mark — so the fold stops at the mint and
    the retired key reads as the target. Before the fix: form 2, ESTABLISHED."""
    a = _HeightLiar(indexer=False, mark_heights={MARK: 458595}, lie={UPDATE_A: 458599})
    b = _Server(indexer=True, mark_heights={MARK: 458595})
    nam = _attach(monkeypatch, (a, "wss://a", b, "wss://b"), RETIRED_H160)
    assert nam["resolved"] and nam["form"] == 1, nam
    assert nam["signer_is_target_at_height"] is None
    assert f"disagree about the block of chain step {UPDATE_A}" in nam["degraded_reason"]
    assert "'wss://a' says 458599" in nam["degraded_reason"] and "'wss://b' says 458591" in nam["degraded_reason"]
    assert hashmark_cmds._name_check({"name_at_mark": nam}, asked=True)[0] == "NOT ESTABLISHED"


def test_the_lie_is_caught_even_when_the_anchor_came_from_the_honest_server(monkeypatch) -> None:
    """PANEL C, binding on A: the anchor (the mark's height) then comes from the HONEST B — and A's
    step heights alone still flipped it, because the judge's only independence rule compared the
    binding with the anchor. The mark's height was never the lie."""
    a = _HeightLiar(indexer=True, mark_heights={MARK: 458595}, lie={UPDATE_A: 458599})
    b = _Server(indexer=False, mark_heights={MARK: 458595})
    nam = _attach(monkeypatch, (a, "wss://a", b, "wss://b"), RETIRED_H160)
    assert nam["anchor_source"] == "wss://b", "the premise: the anchor is from the honest server"
    assert nam["form"] == 1, nam
    assert UPDATE_A in nam["degraded_reason"]


def test_a_truthful_mark_height_and_one_early_step_height_cannot_flip_it(monkeypatch) -> None:
    """PANEL E. A tells the truth about the MARK (458586, before the move) and reports the update
    that moved the name (really 458591) at 458586. The printed height is the true one and the
    target is the post-move one — a signer holding the NEW key reads as ESTABLISHED at a block
    where the name still pointed at the old key."""
    a = _HeightLiar(indexer=False, mark_heights={MARK: 458586}, lie={UPDATE_A: 458586})
    b = _Server(indexer=True, mark_heights={MARK: 458586})
    nam = _attach(monkeypatch, (a, "wss://a", b, "wss://b"), MOVED_H160)
    assert nam["form"] == 1, nam
    assert nam["target_at_height"] is None
    state, _reason = hashmark_cmds._name_check({"name_at_mark": nam}, asked=True)
    assert state == "NOT ESTABLISHED" and state not in hashmark_cmds._CHECK_HOLDS


def test_the_anchor_server_alone_cannot_move_the_marks_block(monkeypatch) -> None:
    """The mark's height is the other half. Truth: the mark is at 458586 (before the move), so the
    NEW key is NOT the signer there. A (the anchor, with the shipped order) reports it at 458595
    — after the move — and alone made the new key ESTABLISHED. The binding server now places the
    mark too, and the two disagree."""
    a = _Server(indexer=False, mark_heights={MARK: 458595})
    b = _Server(indexer=True, mark_heights={MARK: 458586})
    nam = _attach(monkeypatch, (a, "wss://a", b, "wss://b"), MOVED_H160)
    assert nam["form"] == 1, nam
    assert "disagree about the mark's block" in nam["degraded_reason"]
    assert "'wss://a' says 458595" in nam["degraded_reason"] and "'wss://b' says 458586" in nam["degraded_reason"]


# ---------------------------------------------------------------------------
# The honest pairs — agreement still reaches form 2
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(("mark", "signer", "is_target"), [(458595, MOVED_H160, True), (458586, MOVED_H160, False)])
def test_two_agreeing_honest_servers_still_reach_form_2(monkeypatch, mark, signer, is_target) -> None:
    """A guard that refuses valid work is a bug. Two honest servers agree on every height, and form
    2 answers — both ways — with each server's own word carried in the JSON."""
    a = _Server(indexer=False, mark_heights={MARK: mark})
    b = _Server(indexer=True, mark_heights={MARK: mark})
    nam = _attach(monkeypatch, (a, "wss://a", b, "wss://b"), signer)
    assert nam["form"] == 2, nam["degraded_reason"]
    assert nam["signer_is_target_at_height"] is is_target
    heights = nam["heights"]
    assert heights["agreed_by"] == ["wss://a", "wss://b"]
    by = {r["source"]: r for r in heights["by_source"]}
    truth = {MINT: HEIGHTS[MINT], UPDATE_A: HEIGHTS[UPDATE_A], UPDATE_B: HEIGHTS[UPDATE_B]}
    assert by["wss://a"]["steps"] == truth and by["wss://b"]["steps"] == truth
    assert by["wss://a"]["mark"] == by["wss://b"]["mark"] == mark
    # NON-VACUITY: B's step heights were really B's answer, asked of B — not A's copied across.
    assert any(c[0] == "get_history" for c in b.calls), "the tip server was never asked for any history"


def test_an_unconfirmed_tip_update_on_both_servers_does_not_refuse_an_older_mark(monkeypatch) -> None:
    """Both servers leave UPDATE_B unplaced (unconfirmed): they AGREE, and a mark before UPDATE_A
    never needed its height. The agreement rule must not turn "both say unconfirmed" into a
    disagreement."""
    a = _Server(indexer=False, unconfirmed=frozenset({UPDATE_B}), mark_heights={MARK: 458588})
    b = _Server(indexer=True, unconfirmed=frozenset({UPDATE_B}), mark_heights={MARK: 458588})
    nam = _attach(monkeypatch, (a, "wss://a", b, "wss://b"), RETIRED_H160)
    assert nam["form"] == 2, nam["degraded_reason"]
    assert nam["signer_is_target_at_height"] is True


def test_a_server_that_places_a_step_the_other_does_not_disagrees(monkeypatch) -> None:
    """One says UPDATE_B is confirmed, the other says unconfirmed. That is a disagreement (one is
    behind the tip, or lying) even when the step is after the mark — ANY disagreement degrades."""
    a = _Server(indexer=False, mark_heights={MARK: 458588})
    b = _Server(indexer=True, unconfirmed=frozenset({UPDATE_B}), mark_heights={MARK: 458588})
    nam = _attach(monkeypatch, (a, "wss://a", b, "wss://b"), RETIRED_H160)
    assert nam["form"] == 1
    assert f"chain step {UPDATE_B}" in nam["degraded_reason"] and "not in a block" in nam["degraded_reason"]


class _NoVerbose(_Server):
    async def get_transaction_verbose(self, txid):
        raise NetworkError("verbose transactions unavailable")


def test_a_tip_server_that_cannot_report_heights_degrades_naming_it(monkeypatch) -> None:
    """No second word is not a second word that agrees. B's history fails AFTER the tip proof (its
    unspent set still answers), so the walk is complete and only the heights are missing."""

    class _HistoryFailsAfterTheWalk(_Server):
        async def get_history(self, script_hash):
            raise NetworkError("history refused")

    a = _Server(indexer=False, mark_heights={MARK: 458595})
    b = _HistoryFailsAfterTheWalk(indexer=True, mark_heights={MARK: 458595})
    nam = _attach(monkeypatch, (a, "wss://a", b, "wss://b"), MOVED_H160)
    assert nam["chain"]["complete"], "the premise: the walk itself completed"
    assert nam["form"] == 1
    assert "'wss://b' could not report the block heights" in nam["degraded_reason"]
    assert "history refused" in nam["degraded_reason"]


def test_a_second_server_that_cannot_place_the_mark_degrades_naming_it(monkeypatch) -> None:
    a = _Server(indexer=False, mark_heights={MARK: 458595})
    b = _NoVerbose(indexer=True, mark_heights={MARK: 458595})
    nam = _attach(monkeypatch, (a, "wss://a", b, "wss://b"), MOVED_H160)
    assert nam["form"] == 1
    assert "could not place the mark" in nam["degraded_reason"]
    assert nam["anchor"]["height"] == 458595, "the anchor itself (from A) is still reported"


def test_the_human_renderer_prints_the_disagreement_not_the_claim(monkeypatch) -> None:
    a = _HeightLiar(indexer=False, mark_heights={MARK: 458595}, lie={UPDATE_A: 458599})
    b = _Server(indexer=True, mark_heights={MARK: 458595})
    text = "\n".join(
        glyph_inspect._name_at_mark_lines(_attach(monkeypatch, (a, "wss://a", b, "wss://b"), RETIRED_H160))
    )
    assert "not established" in text and "disagree about the block of chain step" in text
    assert "IS that address" not in text


def test_the_form_2_caveat_says_what_the_agreement_covers_and_what_it_does_not(monkeypatch) -> None:
    a = _Server(indexer=False, mark_heights={MARK: 458595})
    b = _Server(indexer=True, mark_heights={MARK: 458595})
    nam = _attach(monkeypatch, (a, "wss://a", b, "wss://b"), MOVED_H160)
    text = " ".join("\n".join(glyph_inspect._name_at_mark_lines(nam)).split())
    assert "reported identically by 'wss://a' and 'wss://b'" in text
    assert "NOT verified" in text and "agree on the same lie" in text


# ---------------------------------------------------------------------------
# The judge, pure — the rule lives where the answer is decided
# ---------------------------------------------------------------------------


async def _walk():
    from pyrxd.transaction.transaction import Transaction

    async def fetch(txid: str):
        return Transaction.from_hex(RAW[txid])

    async def unspent(_t: str, _v: int) -> bool:
        return True

    return await walk_mutable_chain(
        mint_txid=MINT, candidates=list(RAW), fetch_tx=fetch, is_unspent=unspent, candidate_source="A", tip_source="B"
    )


def _anchor(height: int = 458595, source: str = "node-A") -> MarkAnchor:
    return MarkAnchor(txid=MARK, height=height, confirmations=50, min_confirmations=6, source=source)


def _judge(walk, reports, anchor=None):
    return judge_name_at_mark(
        ref=walk.ref, name=NAME, binding_source="index-B", anchor=anchor or _anchor(), walk=walk, height_reports=reports
    )


TRUE = {MINT: HEIGHTS[MINT], UPDATE_A: HEIGHTS[UPDATE_A], UPDATE_B: HEIGHTS[UPDATE_B]}


async def test_judge_two_agreeing_sources_answer() -> None:
    walk = await _walk()
    v = _judge(walk, [HeightReport("node-A", 458595, TRUE), HeightReport("index-B", 458595, TRUE)])
    assert v.form == 2 and v.target_at_height == MOVED
    assert v.height_sources == ("node-A", "index-B")
    assert "NOT verified" in v.caveat and "'node-A' and 'index-B'" in v.caveat


@pytest.mark.parametrize(
    "reports",
    [
        pytest.param([HeightReport("node-A", 458595, TRUE)], id="one-source"),
        pytest.param(
            [HeightReport("node-A", 458595, TRUE), HeightReport("node-A", 458595, TRUE)], id="one-label-twice"
        ),
        pytest.param([], id="no-source"),
    ],
)
async def test_judge_refuses_heights_from_fewer_than_two_sources(reports) -> None:
    """The case the finding is about, at its narrowest: every height from one endpoint. With A's
    word alone the lie below is undetectable, so one source must degrade even when it is honest."""
    walk = await _walk()
    v = _judge(walk, reports)
    assert v.form == 1 and v.target_at_height is None
    assert "every block height came from" in v.degraded_reason


async def test_judge_does_not_count_an_unlabelled_report_as_a_second_source() -> None:
    """An empty label beside a named one looked like two sources. It may be the same endpoint, so
    it is not independence — the walker already treats an unnamed source that way."""
    walk = await _walk()
    v = _judge(walk, [HeightReport("node-A", 458595, TRUE), HeightReport("", 458595, TRUE)])
    assert v.form == 1 and "carries no source label" in v.degraded_reason


async def test_judge_refuses_a_disagreement_on_any_step() -> None:
    walk = await _walk()
    for txid in (MINT, UPDATE_A, UPDATE_B):
        lie = {**TRUE, txid: TRUE[txid] + 1}
        v = _judge(walk, [HeightReport("node-A", 458595, lie), HeightReport("index-B", 458595, TRUE)])
        assert v.form == 1, txid
        assert f"chain step {txid}" in v.degraded_reason


async def test_judge_refuses_a_disagreement_about_the_mark() -> None:
    walk = await _walk()
    v = _judge(walk, [HeightReport("node-A", 458595, TRUE), HeightReport("index-B", 458586, TRUE)])
    assert v.form == 1 and "disagree about the mark's block" in v.degraded_reason
    v = _judge(walk, [HeightReport("node-A", 458595, TRUE), HeightReport("index-B", None, TRUE)])
    assert v.form == 1 and "'index-B' says not in a block" in v.degraded_reason


async def test_judge_refuses_a_report_that_carries_an_error() -> None:
    walk = await _walk()
    v = _judge(walk, [HeightReport("node-A", 458595, TRUE), HeightReport("index-B", 458595, TRUE, error="timeout")])
    assert v.form == 1 and "'index-B' could not report" in v.degraded_reason and "timeout" in v.degraded_reason


@pytest.mark.parametrize("bad", [True, -1, "458591", 1.5])
async def test_judge_validates_the_second_sources_heights_too(bad) -> None:
    walk = await _walk()
    v = _judge(walk, [HeightReport("node-A", 458595, TRUE), HeightReport("index-B", 458595, {**TRUE, UPDATE_A: bad})])
    assert v.form == 1 and "unusable block height" in v.degraded_reason
