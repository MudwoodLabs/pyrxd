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
from pyrxd.glyph.wave_identity import judge_name_at_mark
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
    ) -> None:
        self.txs = {t: Transaction.from_hex(b) for t, b in RAW.items()}
        self.hide, self.unconfirmed, self.tip = hide, unconfirmed, tip
        self.inject = inject_history or {}
        self.corrupt = corrupt or {}
        self.mark_heights = mark_heights or {}
        self.utxos_fail = utxos_fail
        self.calls: list[tuple[str, str]] = []
        self._history: dict[str, list[dict]] = {}
        self._spent: set[tuple[str, int]] = set()
        for txid, tx in self.txs.items():
            if txid in hide:
                continue  # a stale or lying server: the transaction is not in ITS index
            height = 0 if txid in unconfirmed else HEIGHTS[txid]
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
        return self.corrupt.get(key) or RAW[key]

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
        return out

    async def get_tip_height(self) -> int:
        return self.tip

    async def get_transaction_verbose(self, txid) -> dict:
        key = str(txid).lower()
        height = self.mark_heights.get(key) or HEIGHTS.get(key)
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
    server's claim about what exists. The shipped default config is a single server, so this
    is the degrade most users will see, and it must say why."""
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
    """A padded history costs a fetch per entry. With one fetch allowed, discovery sees the
    mint's history name UPDATE_A and can go no further — UPDATE_B is never seen. The walker
    then stops at UPDATE_A:1, the honest tip server says it is spent, and the verdict degrades
    instead of truncating quietly. `capped` is set so a reader knows WHY the set is short."""
    server = FakeChainServer()
    d = await discover_mutable_chain(server, MINT, source="A", max_fetches=1)
    assert d.capped
    assert "cap" in d.stopped
    assert d.candidates == (UPDATE_A,), "UPDATE_B was beyond the cap and must not appear"
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
    assert f"{UPDATE_A}:1 is not proved unspent" in result.walk.reason


async def test_a_cap_hit_after_the_history_already_named_the_tip_still_walks_completely() -> None:
    """`capped` is about discovery EFFORT, not about truth. With two fetches allowed, discovery
    stops before fetching UPDATE_B — but UPDATE_A's history had already named it, so the walker,
    which verifies every link itself, reaches and proves the real tip. `complete=True` is correct
    here; `capped=True` still reports honestly that discovery did not finish on its own."""
    result = await walk_discovered_chain(
        mint_txid=MINT,
        discovery_client=FakeChainServer(),
        tip_client=FakeChainServer(),
        discovery_source="A",
        tip_source="B",
        max_fetches=2,
    )
    assert result.discovery.capped
    assert UPDATE_B in result.discovery.candidates
    assert result.walk.complete and result.walk.tip_txid == UPDATE_B


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
    discovery_server = FakeChainServer()
    tip_server = FakeChainServer(mark_heights={MARK: mark_height})
    result = await walk_discovered_chain(
        mint_txid=MINT, discovery_client=discovery_server, tip_client=tip_server, discovery_source="A", tip_source="B"
    )
    anchor = await resolve_mark_anchor(
        txid=MARK,
        fetch_verbose=tip_server.get_transaction_verbose,
        source="B",
        min_confirmations=6,
        tip_height=await tip_server.get_tip_height(),
    )
    return judge_name_at_mark(
        ref=result.walk.ref,
        binding_source="operator",  # the name→glyph binding is the caller's; here it is asserted, not verified
        anchor=anchor,
        walk=result.walk,
        step_heights=result.discovery.heights,
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
