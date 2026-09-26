"""A mutable glyph's spend chain can be discovered from the chain itself — and one server still isn't proof.

`walk_mutable_chain` verifies a candidate set it is handed; nothing in pyrxd produced one, so §7.6
form 2 was reachable only by a consumer with their own index. `discover_mutable_chain` follows the
mutable output's scripthash history hop by hop and hands the walker its candidates and heights.

THE FAKE SERVER IS DERIVED, NOT TYPED. `FakeChainServer` computes every scripthash history and
every unspent set from the fixture's real transaction bytes — outputs create history entries,
inputs create spender entries and mark outpoints spent. A hand-kept history could disagree with
the transactions it describes; this one cannot. Lies are modelled as OPERATIONS on the truth
(hide a transaction, inject an entry, mark one unconfirmed, corrupt a body), so each test says
exactly which lie it is about.

Everything runs on the real `custodian-gate-x7f3.rxd` bytes, whose live discovery was measured
2026-09-16 against two public servers (see the module docstring). The end-to-end test at the
bottom is the whole point: a form-2 verdict from chain-discovered candidates, no index anywhere.
"""

from __future__ import annotations

import json
import pathlib
from types import SimpleNamespace

import pytest

from pyrxd.glyph.mark_anchor import resolve_mark_anchor
from pyrxd.glyph.mutable_chain_discovery import (
    cached_fetcher,
    discover_mutable_chain,
    electrumx_tip_prover,
    walk_discovered_chain,
)
from pyrxd.glyph.wave_identity import HeightReport, judge_name_at_mark
from pyrxd.network.electrumx import script_hash_for_script
from pyrxd.security.errors import NetworkError, ValidationError
from pyrxd.transaction.transaction import Transaction

_FIX = pathlib.Path(__file__).parent / "fixtures" / "wave_update_chain_mainnet.json"
_DOC = json.loads(_FIX.read_text())
RAW = {t["txid"]: bytes.fromhex(t["raw"]) for t in _DOC["transactions"]}
HEIGHTS = {t["txid"]: int(t["height"]) for t in _DOC["transactions"]}

MINT = "f644794b3fb9ab8330b236debbe1989ce1034e5b2a8f8f2516e05f4e54f3cf31"
UPDATE_A = "315b46300bf160470edd1ee0171beb42306fe9c69ef53a324cb0607089b33192"
SIBLING = "2cee48475b8f3095478612840964d300caeb630a4ce8baecd37eae1344308e8b"
UPDATE_B = "3c7b43dffe74fe57bc233f5305589714ee54335f9b15e81cc7dde0861c2482be"
MINT_TARGET = "1CPfirXZahPrTb93QouwBfKDoz1ykfcBb7"
MOVED = "14XmXG3dSBWZUukGT3xzS9zxpiZ53vgx1i"
TIP_HEIGHT = 464826  # the live tip when discovery was measured
MARK = "ma" * 32


def _sh(sh) -> str:
    return sh if isinstance(sh, str) else bytes(sh).hex()


def _sh_of(txid: str, vout: int) -> str:
    tx = Transaction.from_hex(RAW[txid])
    return _sh(script_hash_for_script(bytes(tx.outputs[vout].locking_script.serialize())))


def _derived(txid: str, edit) -> tuple[str, bytes]:
    """A transaction DERIVED from a fixture one by a structural edit, re-serialized.

    Its txid is the hash of the bytes a `FakeChainServer(extra=...)` will serve, so the txid-bound
    fetch accepts it — which is the point: the lies below are about which transactions EXIST and
    what they spend, never about forged bytes. Nothing is typed by hand; the edit is one field.
    """
    tx = Transaction.from_hex(RAW[txid])
    edit(tx)
    raw = bytes(tx.serialize())
    derived = Transaction.from_hex(raw).txid()
    assert derived != txid, "the edit changed nothing"
    return derived, raw


class FakeChainServer:
    """ElectrumX as a function of the transactions it holds. See the module docstring."""

    def __init__(
        self,
        *,
        hide: frozenset[str] = frozenset(),
        unconfirmed: frozenset[str] = frozenset(),
        inject_history: dict[str, list[tuple[str, int]]] | None = None,
        corrupt: dict[str, bytes] | None = None,
        mark_heights: dict[str, int] | None = None,
        utxos_fail: bool = False,
        tip: int = TIP_HEIGHT,
        extra: dict[str, tuple[bytes, int]] | None = None,
        claim_unspent: dict[str, list[tuple[str, int]]] | None = None,
    ) -> None:
        # `extra`: transactions this server holds BESIDES the fixture — txid -> (raw, height).
        # Built by `_derived` from fixture bytes, so their txids are the hash of what is served
        # and `_fetch_bound` accepts them; their inputs and outputs enter the derived history and
        # spent set like any other. This is how a server that has indexed a conflicting or
        # non-mutable spend is modelled without typing a transaction by hand.
        # `claim_unspent`: scripthash -> outpoints this server ASSERTS are unspent under that
        # script, whatever the chain says. A lying tip server, and nothing else.
        self.raw = dict(RAW)
        self.heights = dict(HEIGHTS)
        for txid, (raw, height) in (extra or {}).items():
            self.raw[txid], self.heights[txid] = raw, height
        self.txs = {t: Transaction.from_hex(b) for t, b in self.raw.items()}
        self.hide, self.unconfirmed, self.tip = hide, unconfirmed, tip
        self.inject = inject_history or {}
        self.corrupt = corrupt or {}
        self.mark_heights = mark_heights or {}
        self.utxos_fail = utxos_fail
        self.claim_unspent = claim_unspent or {}
        self.calls: list[tuple[str, str]] = []
        self._history: dict[str, list[dict]] = {}
        self._spent: set[tuple[str, int]] = set()
        for txid, tx in self.txs.items():
            if txid in hide:
                continue  # a stale or lying server: the transaction is not in ITS index
            height = 0 if txid in unconfirmed else self.heights[txid]
            for out in tx.outputs:
                key = _sh(script_hash_for_script(bytes(out.locking_script.serialize())))
                self._history.setdefault(key, []).append({"tx_hash": txid, "height": height})
            for inp in tx.inputs:
                src = self.txs.get(inp.source_txid)
                if src is None:
                    continue
                self._spent.add((inp.source_txid, inp.source_output_index))
                key = _sh(
                    script_hash_for_script(bytes(src.outputs[inp.source_output_index].locking_script.serialize()))
                )
                self._history.setdefault(key, []).append({"tx_hash": txid, "height": height})

    async def get_transaction(self, txid) -> bytes:
        # Served even when hidden from history — a stale index still answers a direct fetch.
        key = str(txid).lower()
        self.calls.append(("get_transaction", key))
        return self.corrupt.get(key) or self.raw[key]

    async def get_history(self, script_hash) -> list[dict]:
        key = _sh(script_hash)
        self.calls.append(("get_history", key))
        extra = [{"tx_hash": t, "height": h} for t, h in self.inject.get(key, [])]
        return list(self._history.get(key, [])) + extra

    async def get_utxos(self, script_hash) -> list:
        key = _sh(script_hash)
        self.calls.append(("get_utxos", key))
        if self.utxos_fail:
            raise NetworkError("listunspent unavailable")
        out = []
        for entry in self._history.get(key, []):
            tx = self.txs[entry["tx_hash"]]
            for vout, o in enumerate(tx.outputs):
                same = _sh(script_hash_for_script(bytes(o.locking_script.serialize()))) == key
                if same and (entry["tx_hash"], vout) not in self._spent:
                    out.append(
                        SimpleNamespace(tx_hash=entry["tx_hash"], tx_pos=vout, value=o.satoshis, height=entry["height"])
                    )
        for txid, vout in self.claim_unspent.get(key, []):
            o = self.txs[txid].outputs[vout]
            out.append(SimpleNamespace(tx_hash=txid, tx_pos=vout, value=o.satoshis, height=self.heights[txid]))
        return out

    async def get_tip_height(self) -> int:
        return self.tip

    async def get_transaction_verbose(self, txid) -> dict:
        key = str(txid).lower()
        height = self.mark_heights.get(key) or self.heights.get(key)
        return {"txid": key, "confirmations": (self.tip - height + 1) if height else 0}


# ---------------------------------------------------------------------------
# Discovery on the honest path
# ---------------------------------------------------------------------------


async def test_discovery_finds_the_real_chain_and_only_it() -> None:
    """Both updates, no sibling, three hops of history — as measured live."""
    server = FakeChainServer()
    d = await discover_mutable_chain(server, MINT, source="A")

    assert set(d.candidates) == {UPDATE_A, UPDATE_B}
    assert SIBLING not in d.candidates, (
        "the sibling never touches the mutable output; scripthash history must not list it"
    )
    assert d.hops == 2
    assert d.heights == {MINT: 458585, UPDATE_A: 458591, UPDATE_B: 458601}
    assert not d.capped
    assert "tip" in d.stopped
    assert d.source == "A"


async def test_discovery_fetches_each_transaction_once() -> None:
    """Discovery and the walk share one cache; the live measurement was 6 fetches for 3 steps
    with a fresh cache per hop. A shared cache must not exceed one fetch per transaction."""
    server = FakeChainServer()
    fetch = cached_fetcher(server)
    await discover_mutable_chain(server, MINT, source="A", fetch_tx=fetch)
    fetched = [c for c in server.calls if c[0] == "get_transaction"]
    assert len(fetched) == len({c[1] for c in fetched}), fetched


async def test_two_servers_give_a_complete_walk() -> None:
    """The honest path end to end: discover on A, prove the tip on B."""
    result = await walk_discovered_chain(
        mint_txid=MINT,
        discovery_client=FakeChainServer(),
        tip_client=FakeChainServer(),
        discovery_source="A",
        tip_source="B",
    )
    walk = result.walk
    assert walk.complete, walk.reason
    assert [s.txid for s in walk.steps] == [MINT, UPDATE_A, UPDATE_B]
    assert (walk.tip_txid, walk.tip_vout) == (UPDATE_B, 1)
    assert walk.excluded == ()
    assert result.discovery.heights[UPDATE_B] == 458601


# ---------------------------------------------------------------------------
# One server is still not proof
# ---------------------------------------------------------------------------


async def test_one_server_for_both_halves_degrades_with_the_reason() -> None:
    """Chain-based discovery does not repeal the two-source rule: a history is still one
    server's claim about what exists. A single-server configuration (`--electrumx URL`, or a
    config naming one) lands here, and it must say why. (Not the shipped mainnet default, which
    this used to say — that ships two independent endpoints.)"""
    server = FakeChainServer()
    result = await walk_discovered_chain(
        mint_txid=MINT, discovery_client=server, tip_client=server, discovery_source="A", tip_source="A"
    )
    assert not result.walk.complete
    assert "same source" in result.walk.reason


async def test_a_stale_discovery_server_cannot_certify_its_own_truncation() -> None:
    """THE CASE THE RULE EXISTS FOR. Server A never indexed the last update, so its history
    ends at UPDATE_A and its own unspent set would happily say UPDATE_A:1 is live. Server B
    knows better. The walk must end incomplete, naming the unproved tip."""
    stale = FakeChainServer(hide=frozenset({UPDATE_B}))
    honest = FakeChainServer()
    result = await walk_discovered_chain(
        mint_txid=MINT, discovery_client=stale, tip_client=honest, discovery_source="A", tip_source="B"
    )
    assert [s.txid for s in result.walk.steps] == [MINT, UPDATE_A]
    assert not result.walk.complete
    assert f"{UPDATE_A}:1 is not proved unspent" in result.walk.reason
    # and the same stale server, asked to prove its own tip, WOULD have certified it:
    self_proved = await walk_discovered_chain(
        mint_txid=MINT, discovery_client=stale, tip_client=stale, discovery_source="A", tip_source="A-again"
    )
    assert self_proved.walk.tip_proved_unspent, "the stale server's own unspent set is consistent with its lie"


async def test_two_colluding_servers_are_the_residual_trust() -> None:
    """Pins the BOUNDARY, not a defect. Two endpoints that both omit the last update and are
    labelled as independent produce `complete=True` over a stale record. That is the trust
    this design accepts — 'two independent servers' — and it is written here so nobody reads
    `complete` as stronger than it is. If this ever fails, the boundary moved; update the docs."""
    a = FakeChainServer(hide=frozenset({UPDATE_B}))
    b = FakeChainServer(hide=frozenset({UPDATE_B}))
    result = await walk_discovered_chain(
        mint_txid=MINT, discovery_client=a, tip_client=b, discovery_source="A", tip_source="B"
    )
    assert result.walk.complete
    assert result.walk.tip_txid == UPDATE_A


# ---------------------------------------------------------------------------
# What discovery must not be fooled by
# ---------------------------------------------------------------------------


async def test_a_history_entry_that_does_not_spend_the_output_does_not_advance_the_walk() -> None:
    """ElectrumX lists every transaction that TOUCHES a script, including ones that merely pay
    to it. Discovery must advance only through a spender, or a paid-to-the-same-script decoy
    could redirect the chain. Modelled by injecting the sibling into the mint output's history."""
    server = FakeChainServer(inject_history={_sh_of(MINT, 1): [(SIBLING, 458591)]})
    d = await discover_mutable_chain(server, MINT, source="A")
    assert SIBLING in d.candidates, "it was in the history, so it is offered to the walker"
    assert d.hops == 2, "but it did not become a hop — the real spender did"
    walk = (
        await walk_discovered_chain(
            mint_txid=MINT, discovery_client=server, tip_client=FakeChainServer(), discovery_source="A", tip_source="B"
        )
    ).walk
    assert walk.complete
    assert walk.excluded == (SIBLING,), "the walker reports the decoy as not belonging to this token"


async def test_a_cap_that_truncates_the_candidate_set_cannot_prove_the_tip() -> None:
    """A padded history costs a fetch per entry. With one fetch allowed (the mint), discovery sees
    the mint's history NAME UPDATE_A and cannot examine it. It is not handed on — the walker
    fetches every candidate it is given, so a named-but-unexamined entry would be a fetch past the
    cap. The walker then stops at the mint, the honest tip server says MINT:1 is spent, and the
    verdict degrades instead of truncating quietly. `capped` is set so a reader knows WHY."""
    server = FakeChainServer()
    d = await discover_mutable_chain(server, MINT, source="A", max_fetches=1)
    assert d.capped
    assert "cap" in d.stopped
    assert d.candidates == (), "UPDATE_A was named, never fetched, and must not be handed on"
    server = FakeChainServer()  # fresh, so the fetch count below is this walk's alone
    result = await walk_discovered_chain(
        mint_txid=MINT,
        discovery_client=server,
        tip_client=FakeChainServer(),
        discovery_source="A",
        tip_source="B",
        max_fetches=1,
    )
    assert result.discovery.capped
    assert not result.walk.complete
    assert f"{MINT}:1 is not proved unspent" in result.walk.reason
    fetched = [c for c in server.calls if c[0] == "get_transaction"]
    assert len(fetched) == 1, f"one fetch allowed, {len(fetched)} made: {fetched}"


async def test_a_cap_hit_after_the_history_named_the_tip_bounds_the_walker_too() -> None:
    """THE CAP BOUNDS THE WHOLE WALK (0.25.0 panel, C-L1). This used to pass `complete=True`:
    with two fetches allowed, discovery stopped before fetching UPDATE_B, but UPDATE_A's history
    had NAMED it, so the name went into the candidate set and the walker fetched it anyway —
    which is exactly how a padded history made 3,002 fetches against a cap of 256. Discovery now
    hands on only what it examined, so the walk ends at UPDATE_A, the honest tip server says
    UPDATE_A:1 is spent, and the verdict degrades. That refuses a whole chain only when discovery
    ran out of budget — i.e. when a history was padded past `max_fetches`, never on an honest
    chain, where each hop costs one fetch (see the honest-path tests above)."""
    server = FakeChainServer()
    result = await walk_discovered_chain(
        mint_txid=MINT,
        discovery_client=server,
        tip_client=FakeChainServer(),
        discovery_source="A",
        tip_source="B",
        max_fetches=2,
    )
    assert result.discovery.capped
    assert result.discovery.candidates == (UPDATE_A,), "UPDATE_B was named, never fetched"
    assert not result.walk.complete
    assert f"{UPDATE_A}:1 is not proved unspent" in result.walk.reason
    fetched = {c[1] for c in server.calls if c[0] == "get_transaction"}
    assert fetched == {MINT, UPDATE_A}, fetched


async def test_an_unconfirmed_step_has_no_height_rather_than_height_zero() -> None:
    """ElectrumX reports 0 / -1 for a mempool transaction. Stored as a height, that would place
    the step at the genesis block — definitely before any mark. It must be absent instead."""
    server = FakeChainServer(unconfirmed=frozenset({UPDATE_B}))
    d = await discover_mutable_chain(server, MINT, source="A")
    assert UPDATE_B in d.candidates
    assert UPDATE_B not in d.heights
    assert d.heights[UPDATE_A] == 458591


async def test_a_server_returning_the_wrong_transaction_is_an_error_not_a_chain_end() -> None:
    """Bytes that do not hash to the txid asked for are a lying or broken server. Swallowing
    that into 'no spender' would let the same server end a chain early on purpose."""
    server = FakeChainServer(corrupt={UPDATE_A: RAW[UPDATE_B]})
    with pytest.raises(ValidationError, match="hash != requested"):
        await discover_mutable_chain(server, MINT, source="A")


async def test_a_non_mutable_mint_is_reported_not_walked() -> None:
    """The sibling has no mutable output. Discovery from it has nothing to follow and says so;
    the walker then reports the same thing in its own words."""
    server = FakeChainServer()
    d = await discover_mutable_chain(server, SIBLING, source="A")
    assert d.candidates == () and d.hops == 0
    assert "no mutable output" in d.stopped
    result = await walk_discovered_chain(
        mint_txid=SIBLING, discovery_client=server, tip_client=FakeChainServer(), discovery_source="A", tip_source="B"
    )
    assert not result.walk.complete
    assert "not a mutable glyph mint" in result.walk.reason


async def test_a_tip_server_that_cannot_answer_is_reported_as_cannot_say() -> None:
    """`None` from the prover is neither spent nor unspent; the walk says the source could not
    say, which is a different fact from 'spent' and must render differently."""
    server = FakeChainServer()
    prover = electrumx_tip_prover(FakeChainServer(utxos_fail=True), fetch_tx=cached_fetcher(server))
    assert await prover(UPDATE_B, 1) is None
    result = await walk_discovered_chain(
        mint_txid=MINT,
        discovery_client=server,
        tip_client=FakeChainServer(utxos_fail=True),
        discovery_source="A",
        tip_source="B",
    )
    assert not result.walk.complete
    assert "could not say" in result.walk.reason


async def test_the_tip_prover_answers_about_the_outpoint_not_the_script() -> None:
    """Every mutable output in a chain carries the same ref but a DIFFERENT payload hash, so the
    scripts differ per step — but the prover must still check the specific outpoint, not
    'anything unspent under this script'."""
    server = FakeChainServer()
    prover = electrumx_tip_prover(server, fetch_tx=cached_fetcher(server))
    assert await prover(UPDATE_B, 1) is True
    assert await prover(UPDATE_A, 1) is False
    assert await prover(MINT, 1) is False


async def test_max_fetches_must_be_a_positive_int() -> None:
    server = FakeChainServer()
    for bad in (0, -1, True, "5"):
        with pytest.raises(ValidationError):
            await discover_mutable_chain(server, MINT, source="A", max_fetches=bad)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# The whole point: form 2 from chain-discovered candidates, no index anywhere
# ---------------------------------------------------------------------------


async def _verdict_at(mark_height: int):
    discovery_server = FakeChainServer(mark_heights={MARK: mark_height})
    tip_server = FakeChainServer(mark_heights={MARK: mark_height})
    result = await walk_discovered_chain(
        mint_txid=MINT, discovery_client=discovery_server, tip_client=tip_server, discovery_source="A", tip_source="B"
    )
    anchors = {}
    for label, server in (("A", discovery_server), ("B", tip_server)):
        anchors[label] = await resolve_mark_anchor(
            txid=MARK,
            fetch_verbose=server.get_transaction_verbose,
            source=label,
            min_confirmations=6,
            tip_height=await server.get_tip_height(),
        )
    # EACH SERVER'S OWN WORD: A's step heights are what discovery read from A's histories, B's are
    # what B reported when asked separately (`tip_heights`). No height here is typed by hand.
    assert result.tip_heights == result.discovery.heights, "two honest servers must agree, or form 2 is unreachable"
    return judge_name_at_mark(
        ref=result.walk.ref,
        name="custodian-gate-x7f3.rxd",
        binding_source="operator",  # the name→glyph binding is the caller's; here it is asserted, not verified
        anchor=anchors["B"],
        walk=result.walk,
        height_reports=[
            HeightReport(source="A", mark_height=anchors["A"].height, step_heights=result.discovery.heights),
            HeightReport(source="B", mark_height=anchors["B"].height, step_heights=result.tip_heights),
        ],
    )


async def test_form_2_fires_from_chain_discovered_candidates() -> None:
    """The eras a present-tense lookup conflates, told apart with nothing but two ElectrumX
    servers and the chain. This is what the CLI could not do before discovery existed."""
    before = await _verdict_at(458586)
    after = await _verdict_at(458595)
    assert before.form == 2 and before.target_at_height == MINT_TARGET, before.degraded_reason
    assert after.form == 2 and after.target_at_height == MOVED, after.degraded_reason
    assert before.binding_verified is False, "discovery proves the CHAIN; it says nothing about the name→glyph binding"


async def test_a_mark_before_the_mint_degrades_with_the_reason() -> None:
    v = await _verdict_at(458580)
    assert v.form == 1
    assert "did not exist when the mark was made" in v.degraded_reason


# ---------------------------------------------------------------------------
# Mutant killers. cosmic-ray on main@86c276f (2026-09-16) left 49 non-annotation survivors in
# this module; the ones below are the verdict-relevant ones. Each docstring names the mutant and
# what a hostile server could have done under it. Scenarios are derived from the fixture bytes:
# `_derived` edits one field of a real transaction, `inject_history`/`claim_unspent` are the
# server's lies about the truth the fixture defines.
# ---------------------------------------------------------------------------


async def test_a_spender_must_spend_this_outpoint_not_another_output_of_the_same_transaction() -> None:
    """Kills line 216 `and` -> `or`, `source_output_index == cur_vout` -> `>=` and `<=`.

    The sibling spends UPDATE_A:0 and UPDATE_A:2 — the SAME transaction as the mutable output
    UPDATE_A:1, other outputs. Listed in UPDATE_A:1's history by a padding server, it matches the
    txid half of the check and the vout half on either side of 1 (0 <= 1, 2 >= 1). Under any of
    the three rewrites it becomes a second claimant, discovery stops at hop 1 reporting an
    ambiguity that does not exist, and the verdict degrades on a chain that is whole — one
    injected history entry silences a name."""
    server = FakeChainServer(inject_history={_sh_of(UPDATE_A, 1): [(SIBLING, 458591)]})
    d = await discover_mutable_chain(server, MINT, source="A")
    assert d.hops == 2
    assert "claim to spend" not in d.stopped and "tip" in d.stopped
    assert set(d.candidates) == {UPDATE_A, UPDATE_B, SIBLING}
    walk = (
        await walk_discovered_chain(
            mint_txid=MINT, discovery_client=server, tip_client=FakeChainServer(), discovery_source="A", tip_source="B"
        )
    ).walk
    assert walk.complete and walk.tip_txid == UPDATE_B
    assert walk.excluded == (SIBLING,)


async def test_a_spender_must_spend_this_outpoint_not_the_same_index_of_another_transaction() -> None:
    """Kills line 216 `and` -> `or`, `source_txid == cur_txid` -> `>=`, `<=` and `is not`.

    UPDATE_B spends 315b4630:1 and 60562394:1 — index 1, the mutable output's index, of OTHER
    transactions. Listed in MINT:1's history it matches the vout half; its `315b…` sorts below
    the mint's `f644…` so it also passes a `<=` on the txid, and `is not` passes for every
    string. The mint itself spends 78e25bdc:1, which sorts ABOVE UPDATE_A's `315b…`; listed in
    UPDATE_A:1's history it passes a `>=`. Under each rewrite a padded history manufactures a
    second claimant and the walk stops early on a chain that is whole."""
    server = FakeChainServer(
        inject_history={_sh_of(MINT, 1): [(UPDATE_B, 458601)], _sh_of(UPDATE_A, 1): [(MINT, 458585)]}
    )
    d = await discover_mutable_chain(server, MINT, source="A")
    assert d.hops == 2
    assert "claim to spend" not in d.stopped and "tip" in d.stopped
    assert set(d.candidates) == {UPDATE_A, UPDATE_B}, "the mint is never a candidate for its own chain"


async def test_a_server_that_hides_the_real_update_and_offers_a_later_one_gets_a_dead_end() -> None:
    """Kills line 216 `and` -> `or` from the other side: the direction that shortens a chain.

    Hide UPDATE_A from MINT:1's history and list UPDATE_B there instead. UPDATE_B carries the
    ref's mutable output and has an input at index 1 — so under `or` discovery follows it as the
    spender of MINT:1, hops once, and hands the walker a chain that skips the update in the
    middle. The honest answer is that nothing in that history spends MINT:1: the server has
    presented a dead end, and the walker will find no link for UPDATE_B either."""
    server = FakeChainServer(hide=frozenset({UPDATE_A}), inject_history={_sh_of(MINT, 1): [(UPDATE_B, 458601)]})
    d = await discover_mutable_chain(server, MINT, source="A")
    assert d.hops == 0
    assert "no spender" in d.stopped
    assert d.candidates == (UPDATE_B,)
    result = await walk_discovered_chain(
        mint_txid=MINT, discovery_client=server, tip_client=FakeChainServer(), discovery_source="A", tip_source="B"
    )
    assert not result.walk.complete
    assert [s.txid for s in result.walk.steps] == [MINT]


async def test_two_claimed_spenders_stop_discovery_naming_the_ambiguity() -> None:
    """Kills line 226 `len(spenders) > 1` -> `> 2` and `< 1`, and line 231 `break` -> `continue`.

    A second transaction with UPDATE_A's inputs — UPDATE_A re-serialized with its locktime moved,
    so a different txid over the same outpoints — is a conflicting spend of MINT:1 that
    consensus forbids and an index can still hold (a reorg read mid-flight, or an invented one).
    Under `> 2` / `< 1` discovery would pick `spenders[0]` and walk on as if the conflict were
    not there, so a server that ORDERS its history could choose which of two claimants becomes
    the chain. Under `continue` it would loop on the same history until the fetch cap and report
    a cap instead of the ambiguity. The honest answer is to stop, say `2 … claim to spend`, and
    let the walker degrade — which it does, in its own words."""
    double_txid, double_raw = _derived(UPDATE_A, lambda tx: setattr(tx, "locktime", tx.locktime + 1))
    assert Transaction.from_hex(double_raw).inputs[1].source_txid == MINT
    server = FakeChainServer(extra={double_txid: (double_raw, 458592)})
    d = await discover_mutable_chain(server, MINT, source="A")
    assert d.hops == 0
    assert not d.capped
    assert d.stopped == f"2 transactions in history claim to spend {MINT}:1"
    assert set(d.candidates) == {UPDATE_A, double_txid}
    assert d.fetches == 3, "the mint and the two claimants — not a loop to the fetch cap"
    result = await walk_discovered_chain(
        mint_txid=MINT, discovery_client=server, tip_client=FakeChainServer(), discovery_source="A", tip_source="B"
    )
    assert not result.walk.complete
    assert "claim to spend" in result.walk.reason


async def test_a_spender_that_carries_no_mutable_output_ends_the_chain_there() -> None:
    """Kills line 236 `break` -> `continue`.

    The sibling, with its first input's index moved from 0 to 1, spends UPDATE_A:1 — the mutable
    output — into two ordinary outputs: the singleton is gone. With UPDATE_B hidden, that is the
    only spender the server knows. Discovery must report the end and stop; under `continue` it
    would re-read the same history until the fetch cap and report a cap over a prefix, which the
    walker reads as "cannot prove the tip" rather than "the token was spent out"."""
    burn_txid, burn_raw = _derived(SIBLING, lambda tx: setattr(tx.inputs[0], "source_output_index", 1))
    burn = Transaction.from_hex(burn_raw)
    assert (burn.inputs[0].source_txid, burn.inputs[0].source_output_index) == (UPDATE_A, 1)
    server = FakeChainServer(hide=frozenset({UPDATE_B}), extra={burn_txid: (burn_raw, 458601)})
    d = await discover_mutable_chain(server, MINT, source="A")
    assert d.hops == 1
    assert not d.capped
    assert d.stopped.startswith(f"{burn_txid} spends the mutable output and carries none for")
    assert d.candidates == (UPDATE_A, burn_txid)
    assert d.fetches == 3


async def test_the_hop_cap_stops_at_exactly_max_steps() -> None:
    """Kills line 198 `hops >= max_steps` -> `>` and line 200 `break` -> `continue`.

    With one hop allowed the walk follows MINT:1 to UPDATE_A:1, reads that output's history (so
    UPDATE_B is still offered as a candidate) and stops. `>` would take a second hop past the
    cap; `continue` would never leave the loop. With zero hops the mint's own history is read and
    nothing is followed."""
    d = await discover_mutable_chain(FakeChainServer(), MINT, source="A", max_steps=1)
    assert d.hops == 1
    assert d.stopped == "stopped at the 1-hop cap — the chain may continue"
    # UPDATE_B is NAMED in UPDATE_A:1's history but never examined at the cap, so it is not
    # handed on (a named-but-unfetched candidate is a fetch the walker would make past the cap).
    assert d.candidates == (UPDATE_A,)
    assert d.heights[UPDATE_B] == 458601, "its height was still read — the history WAS asked for"
    d0 = await discover_mutable_chain(FakeChainServer(), MINT, source="A", max_steps=0)
    assert (d0.hops, d0.candidates) == (0, ())


async def test_a_non_mutable_mint_is_not_reported_as_capped() -> None:
    """Kills line 173 `capped=False` -> `True`. `capped` means "the candidate set is a prefix
    because the fetch budget ran out". A mint with nothing to follow spent one fetch; reporting
    it capped would tell a reader there was more to find."""
    d = await discover_mutable_chain(FakeChainServer(), SIBLING, source="A")
    assert d.capped is False
    assert d.fetches == 1


async def test_a_substituted_transaction_is_refused_whichever_way_its_hash_sorts() -> None:
    """Kills line 84 `tx.txid() != str(wanted)` -> `>`.

    The existing refusal test serves UPDATE_B's bytes for UPDATE_A: the hash `3c7b…` sorts ABOVE
    the requested `315b…`, so an ordering comparison still refuses it. Serve UPDATE_A's bytes
    for UPDATE_B and the hash sorts BELOW — under `>` the substitution is accepted, UPDATE_A's
    inputs do not spend UPDATE_A:1, and the chain "ends" at UPDATE_A. A server could then roll
    a name back one step for half of all txid pairs, silently."""
    server = FakeChainServer(corrupt={UPDATE_B: RAW[UPDATE_A]})
    with pytest.raises(ValidationError, match="hash != requested"):
        await discover_mutable_chain(server, MINT, source="A")


async def test_minus_one_is_not_a_height_and_one_is() -> None:
    """Kills line 193 `height > 0` -> `!= 0` and `> 1`.

    ElectrumX reports -1 (not only 0) for a mempool transaction whose parent is also unconfirmed.
    Stored, -1 would place the update BEFORE THE GENESIS BLOCK — before any mark — so a
    present-tense record would be certified as the state at every past height. Height 1 is a
    real height and is kept; the boundary is exactly `> 0`."""
    unconfirmed = FakeChainServer(hide=frozenset({UPDATE_B}), inject_history={_sh_of(UPDATE_A, 1): [(UPDATE_B, -1)]})
    d = await discover_mutable_chain(unconfirmed, MINT, source="A")
    assert d.hops == 2, "the entry is still followed; only its height is unknown"
    assert UPDATE_B in d.candidates and UPDATE_B not in d.heights

    early = FakeChainServer(hide=frozenset({UPDATE_B}), inject_history={_sh_of(UPDATE_A, 1): [(UPDATE_B, 1)]})
    assert (await discover_mutable_chain(early, MINT, source="A")).heights[UPDATE_B] == 1


async def test_candidate_membership_does_not_depend_on_how_a_txid_sorts() -> None:
    """Kills line 195 `txid != mint_txid` -> `<`.

    Every update in the fixture happens to sort below the mint's `f644…`, so on this chain the
    rewrite is invisible — but txids are hashes, so on mainnet half of all updates sort above
    their mint and `<` would drop them from the candidate set. Start discovery from UPDATE_A,
    whose successor `3c7b…` sorts above its `315b…`: the successor must still be offered."""
    d = await discover_mutable_chain(FakeChainServer(), UPDATE_A, source="A")
    assert UPDATE_B > UPDATE_A, "the fixture no longer has a successor sorting above its start; pick another"
    assert d.candidates == (UPDATE_B,)
    assert d.hops == 1


async def test_the_tip_prover_refuses_an_unspent_claim_that_matches_only_half_the_outpoint() -> None:
    """Kills line 274 `and` -> `or`, `tx_hash == want` -> `>=`, `<=`, `is not`, and
    `tx_pos == vout` -> `>=`, `<=`.

    THE FORM-2 CASE. A tip server that asserts, under UPDATE_A:1's script, that UPDATE_A:0 or
    UPDATE_A:2 (same txid, other index) or UPDATE_B:1 / MINT:1 / SIBLING:1 (same index, other
    txid — `3c7b…` and `f644…` sort above `315b…`, `2cee…` below) is unspent. None of those is
    UPDATE_A:1. Under any rewrite the prover answers True, the walker takes UPDATE_A:1 as the
    proved tip, and a stale discovery server that omitted UPDATE_B gets its truncation certified
    `complete` — a name's OLD target, reported as current, with an empty reason.

    (Planting `<=` found the first draft of this list had no claim sorting BELOW UPDATE_A with
    index 1 — the docstring said MINT was it, and MINT sorts above. SIBLING:1 is the one.)"""
    sh = _sh_of(UPDATE_A, 1)
    liar = FakeChainServer(claim_unspent={sh: [(UPDATE_A, 0), (UPDATE_A, 2), (UPDATE_B, 1), (MINT, 1), (SIBLING, 1)]})
    assert UPDATE_B > UPDATE_A and MINT > UPDATE_A and SIBLING < UPDATE_A, "the claims must straddle UPDATE_A"
    prover = electrumx_tip_prover(liar, fetch_tx=cached_fetcher(FakeChainServer()))
    assert await prover(UPDATE_A, 1) is False
    assert await prover(UPDATE_B, 1) is True, "the honest tip is still proved"

    result = await walk_discovered_chain(
        mint_txid=MINT,
        discovery_client=FakeChainServer(hide=frozenset({UPDATE_B})),
        tip_client=liar,
        discovery_source="A",
        tip_source="B",
    )
    assert not result.walk.complete
    assert f"{UPDATE_A}:1 is not proved unspent" in result.walk.reason


def test_the_fetch_cap_is_the_trackers_cap_on_purpose() -> None:
    """Kills line 63 `MAX_DISCOVERY_FETCHES = 256` -> 255 / 257.

    The constant's own comment says it follows `swap/rswp/tracker.py`'s `_MAX_HISTORY_FETCHES`:
    the same bound on the same attack (a padded history that costs a fetch per entry). Pinning
    the two together is the reason 256 is 256; if one moves, decide about both."""
    from pyrxd.glyph.mutable_chain_discovery import MAX_DISCOVERY_FETCHES
    from pyrxd.swap.rswp.tracker import _MAX_HISTORY_FETCHES

    assert MAX_DISCOVERY_FETCHES == _MAX_HISTORY_FETCHES == 256


async def test_discovery_results_are_frozen() -> None:
    """Kills lines 106 and 279 `frozen=True` -> `False`. A `ChainDiscovery` is handed to the
    walker and its heights to the judge; a `DiscoveredWalk` carries both verdict inputs to the
    CLI. Evidence that can be edited between its producer and its consumers is not evidence."""
    import dataclasses

    result = await walk_discovered_chain(
        mint_txid=MINT,
        discovery_client=FakeChainServer(),
        tip_client=FakeChainServer(),
        discovery_source="A",
        tip_source="B",
    )
    with pytest.raises(dataclasses.FrozenInstanceError):
        result.discovery.capped = True  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        result.walk = None  # type: ignore[misc]


# ---------------------------------------------------------------------------
# The fetch cap bounds what a hostile history can cost (0.25.0 panel, C-L1)
# ---------------------------------------------------------------------------


def _padding(n: int) -> dict[str, tuple[bytes, int]]:
    """``n`` REAL transactions a padding server can list: the sibling re-serialized with its
    locktime moved, so each has its own txid, passes the txid-bound fetch, and spends nothing
    this chain cares about. Derived, not typed — the panel's own construction."""
    out = {}
    for i in range(n):
        txid, raw = _derived(SIBLING, lambda tx, i=i: setattr(tx, "locktime", 1_000_000 + i))
        out[txid] = (raw, 458590)
    return out


@pytest.mark.parametrize(("padding", "cap"), [(40, 8), (300, 256)])
async def test_the_fetch_cap_bounds_every_fetch_the_walk_makes(padding: int, cap: int) -> None:
    """THE PANEL'S PROBE (``panel-c/test_panelc_probe_cap.py``): a history padded with real,
    txid-bound non-spenders. Discovery stopped at the cap — and then handed EVERY named entry to
    the walker, which fetched them all: 302 fetches at 300 padding, 3,002 at 3,000, against a cap
    of 256. The cap now bounds the discovery server's transaction fetches for the whole walk."""
    pad = _padding(padding)
    a = FakeChainServer(extra=pad, inject_history={_sh_of(MINT, 1): [(t, 458590) for t in pad]})
    result = await walk_discovered_chain(
        mint_txid=MINT,
        discovery_client=a,
        tip_client=FakeChainServer(),
        discovery_source="A",
        tip_source="B",
        max_fetches=cap,
    )
    fetched = [c for c in a.calls if c[0] == "get_transaction"]
    assert result.discovery.capped, "the premise: the padding is past the cap"
    assert len(fetched) <= cap, f"{len(fetched)} fetches against a cap of {cap}"
    assert not result.walk.complete, "a capped discovery cannot prove the tip"


async def test_a_history_that_repeats_one_entry_costs_one_fetch() -> None:
    """The budget counts DISTINCT transactions. A history naming the sibling five thousand times
    cost five thousand "fetches" (all served from cache), hit the cap, and silenced a name whose
    chain is whole — a guard refusing valid work, triggered by a free repetition."""
    a = FakeChainServer(inject_history={_sh_of(MINT, 1): [(SIBLING, 458591)] * 5000})
    result = await walk_discovered_chain(
        mint_txid=MINT, discovery_client=a, tip_client=FakeChainServer(), discovery_source="A", tip_source="B"
    )
    assert not result.discovery.capped
    assert result.discovery.fetches == 4, "the mint, UPDATE_A, the sibling (once) and UPDATE_B"
    assert result.walk.complete and result.walk.tip_txid == UPDATE_B, result.walk.reason
    assert result.walk.excluded == (SIBLING,)


async def test_candidate_bookkeeping_is_linear_in_what_a_server_sends() -> None:
    """Membership was `txid not in candidates` on a LIST, once per history entry: quadratic in a
    number the server chooses. Measured by the panel: 10k / 20k / 40k entries → 0.2 / 0.9 / 4.6 s.
    Here 40,000 never-fetched entries (one fetch allowed, so none is examined) must be read in well
    under a second; the quadratic version takes seconds. The bound is loose on purpose — this is
    an order-of-growth check, not a benchmark."""
    import time

    entries = [(f"{i:064x}", 458590) for i in range(40_000)]
    a = FakeChainServer(inject_history={_sh_of(MINT, 1): entries})
    started = time.perf_counter()
    d = await discover_mutable_chain(a, MINT, source="A", max_fetches=1)
    elapsed = time.perf_counter() - started
    assert d.capped and len(d.heights) >= 40_000, "the premise: every entry was read"
    assert elapsed < 1.0, f"40,000 history entries took {elapsed:.2f}s"
