"""#850 PR 3: the swap record carries what the later disposition PRs read (design §2.9, §4).

* ``role``: which side wrote the record. The coordinator's role lived only on its config, so a
  restarted process could not tell, and a record could be driven by the other party's coordinator.
* The token push's nonce and hash survive the fund. ``with_counter_lock`` cleared them and
  ``to_dict`` wrote them only inside the pending-deploy block, so a funded record lost the one
  handle that says which transaction moved the tokens (design §2.7).
* The push HASH reaches the record in production. ``EthLeg.fund`` never passed ``on_push_hash`` to
  the token leg, so ``pending_push_tx_hash`` was written only by tests (#850 item 4).
* ``schema_version`` is read. A record from a newer pyrxd is refused rather than read with its new
  fields dropped, and the watchtower pages each record it cannot read, by name.
"""

from __future__ import annotations

import asyncio
import dataclasses
import json

import pytest

from pyrxd.gravity.eth_leg import EthLeg
from pyrxd.gravity.record_sink import JsonFileRecordSink
from pyrxd.gravity.swap_coordinator import CoordinatorConfig, MarginPolicy, SwapCoordinator
from pyrxd.gravity.swap_state import (
    SWAP_RECORD_SCHEMA_VERSION,
    RecordFromNewerPyrxd,
    RecordRole,
    SwapRecord,
    SwapRole,
    SwapState,
)
from pyrxd.gravity.watch import Intent, Observations
from pyrxd.gravity.watch.adapters import JsonDirRecordStore
from pyrxd.security.errors import ValidationError
from tests.test_deployed_contract_is_durable_before_funding import _AMOUNT, _FUND_TIMEOUT, _USDC, _leg
from tests.test_swap_coordinator import (
    _NOW,
    FakeBtcLeg,
    FakeEthLeg,
    FakeIndexer,
    FakeRadiantLeg,
    FakeSeenStore,
    _coordinator,
    _eth_coord_full,
    _eth_terms,
    _final,
    _terms,
    generate_secret,
)
from tests.test_swap_record_erc20_migration import _erc20_locator, _token_terms
from tests.test_watch_reconciler import FakeAlerter, FakeObserver, _reconciler

_PUSH_HASH = "0x" + "ab" * 32


# --------------------------------------------------------------------------- the record itself


def test_role_round_trips_and_writes_the_current_schema_version() -> None:
    for role in RecordRole:
        rec = SwapRecord(state=SwapState.NEGOTIATED, terms=_terms(), role=role)
        d = json.loads(json.dumps(rec.to_dict()))
        assert d["role"] == role.value and d["schema_version"] == SWAP_RECORD_SCHEMA_VERSION
        assert SwapRecord.from_dict(d) == rec


def test_a_record_without_any_new_field_keeps_its_pre_0_27_wire_form() -> None:
    """Honest path for older readers: no role and no stray push writes exactly what 0.26 wrote."""
    btc = SwapRecord(state=SwapState.NEGOTIATED, terms=_terms()).to_dict()
    assert "role" not in btc and "schema_version" not in btc
    eth = SwapRecord(state=SwapState.NEGOTIATED, terms=_token_terms()).with_counter_lock(_erc20_locator()).to_dict()
    assert "role" not in eth and eth["schema_version"] == 2


def test_an_unknown_role_is_refused_on_read() -> None:
    d = SwapRecord(state=SwapState.NEGOTIATED, terms=_terms(), role=RecordRole.TAKER).to_dict()
    d["role"] = "auditor"
    with pytest.raises(ValidationError, match="unknown swap record role"):
        SwapRecord.from_dict(d)


def test_a_record_from_a_newer_pyrxd_is_refused_not_read() -> None:
    d = SwapRecord(state=SwapState.NEGOTIATED, terms=_terms(), role=RecordRole.TAKER).to_dict()
    d["schema_version"] = SWAP_RECORD_SCHEMA_VERSION + 1
    d["counter_refund_tx_hash"] = "0x" + "cd" * 32  # a field this version would silently drop
    with pytest.raises(RecordFromNewerPyrxd, match="newer than this pyrxd reads"):
        SwapRecord.from_dict(d)


@pytest.mark.parametrize("version", [1, 2, SWAP_RECORD_SCHEMA_VERSION])
def test_every_version_up_to_this_one_still_reads(version: int) -> None:
    d = SwapRecord(state=SwapState.NEGOTIATED, terms=_terms()).to_dict()
    d["schema_version"] = version
    assert SwapRecord.from_dict(d).state is SwapState.NEGOTIATED


@pytest.mark.parametrize("bad", ["3", 0, -1, True, 2.0])
def test_a_malformed_schema_version_is_refused(bad: object) -> None:
    d = SwapRecord(state=SwapState.NEGOTIATED, terms=_terms()).to_dict()
    d["schema_version"] = bad
    with pytest.raises(ValidationError, match="schema_version"):
        SwapRecord.from_dict(d)


def test_attaching_the_locator_keeps_the_push_and_the_role() -> None:
    rec = SwapRecord(
        state=SwapState.NEGOTIATED,
        terms=_token_terms(),
        pending_counter_contract="0x" + "77" * 20,
        pending_counter_deploy_tx="0x" + "de" * 32,
        pending_push_nonce=7,
        pending_push_tx_hash=_PUSH_HASH,
        role=RecordRole.TAKER,
    ).with_counter_lock(_erc20_locator())
    assert rec.pending_counter_contract is None and rec.pending_counter_deploy_tx is None
    assert (rec.pending_push_nonce, rec.pending_push_tx_hash, rec.role) == (7, _PUSH_HASH, RecordRole.TAKER)
    back = SwapRecord.from_dict(json.loads(json.dumps(rec.to_dict())))
    assert back == rec, "the funded record lost the push across a write and a read"


# --------------------------------------------------------------------------- the coordinator


async def test_the_role_reaches_the_record_on_disk_through_a_fund(tmp_path) -> None:
    """Production entry point: a TAKER coordinator funds, and the record it persists names it."""
    _p, h = generate_secret()
    terms = _terms(hashlock=h)
    coord = _coordinator(terms=terms, btc_leg=FakeBtcLeg(), radiant_leg=FakeRadiantLeg(), role=SwapRole.TAKER)
    sink = JsonFileRecordSink(tmp_path / "swap.json")
    coord._persist = sink
    await coord.taker_funds_btc(terms)
    on_disk = sink.load_record()
    assert on_disk.state is SwapState.BTC_LOCKED and on_disk.role is RecordRole.TAKER


@pytest.mark.parametrize("role", [None, SwapRole.MAKER, SwapRole.TAKER])
def test_a_record_from_before_0_27_is_stamped_with_the_configured_role(role) -> None:
    coord = SwapCoordinator(
        record=SwapRecord(state=SwapState.NEGOTIATED, terms=_terms()),
        btc_leg=FakeBtcLeg(),
        radiant_leg=FakeRadiantLeg(),
        indexer=FakeIndexer(),
        seen_store=FakeSeenStore(),
        config=CoordinatorConfig(margin_policy=MarginPolicy.estimated(), maker_stall_safety_window_blocks=6, role=role),
    )
    assert coord.record.role is RecordRole.of(role)


@pytest.mark.parametrize(
    ("written", "configured"),
    [(RecordRole.MAKER, SwapRole.TAKER), (RecordRole.TAKER, SwapRole.MAKER), (RecordRole.NONE, SwapRole.TAKER)],
)
def test_a_coordinator_of_another_role_refuses_the_record(written, configured) -> None:
    with pytest.raises(ValidationError, match="written by a .*-role coordinator"):
        SwapCoordinator(
            record=SwapRecord(state=SwapState.BOTH_LOCKED, terms=_terms(), role=written),
            btc_leg=FakeBtcLeg(),
            radiant_leg=FakeRadiantLeg(),
            indexer=FakeIndexer(),
            seen_store=FakeSeenStore(),
            config=CoordinatorConfig(
                margin_policy=MarginPolicy.estimated(), maker_stall_safety_window_blocks=6, role=configured
            ),
        )


class _PushingEthLeg(FakeEthLeg):
    """FakeEthLeg plus the token leg's push-hash report, made between signing and sending."""

    def __init__(self, **kw) -> None:
        super().__init__(**kw)
        self.events: list[str] = []
        self.persisted_hash_before_send: str | None = None

    async def fund(self, terms, *, on_push_hash=None, push_tx_hash=None, **kw):
        self.push_tx_hash_seen = push_tx_hash
        if on_push_hash is not None:
            await on_push_hash(7, _PUSH_HASH)
        self.events.append("push-sent")
        return await super().fund(terms, **kw)


async def test_the_coordinator_persists_the_push_hash_before_the_push_is_sent() -> None:
    secret, h = generate_secret()
    terms = _eth_terms(hashlock=h)
    leg = _PushingEthLeg(preimage=secret, verdict=_final())
    coord = _eth_coord_full(terms=terms, eth_leg=leg, role=SwapRole.TAKER)
    sent_at: list[int] = []
    real = coord._persist

    async def _persist(record):
        sent_at.append(len(leg.events))
        await real(record)

    coord._persist = _persist
    rec = await coord.taker_funds_btc(terms, now_unix_s=_NOW)
    with_hash = [i for i, r in enumerate(coord.persisted) if r.pending_push_tx_hash == _PUSH_HASH]
    assert with_hash, "the push hash was never persisted"
    assert sent_at[with_hash[0]] == 0, "the hash was persisted only after the push was sent"
    assert rec.pending_push_tx_hash == _PUSH_HASH and rec.pending_push_nonce == 7
    assert coord.persisted[-1].pending_push_tx_hash == _PUSH_HASH, "the funded record dropped it"


def test_the_shipped_eth_leg_forwards_the_push_hash_to_the_token_leg() -> None:
    """Reachability, through the shipped EthLeg and the shipped Erc20HtlcLeg: before #850 PR 3
    ``EthLeg.fund`` did not pass ``on_push_hash``, so the token leg's hook had no production caller.
    The token leg reports the hash from ``on_signed``, between signing and sending."""
    order: list[str] = []
    token_leg = _leg(order=order)
    plain_send = token_leg._sign_and_send

    async def _send(*a, on_signed=None, **k):
        if on_signed is not None and order and order[-1] == "deployed":
            await on_signed(_PUSH_HASH)
        out = await plain_send(*a, **k)
        if not order or order[-1] != "tokens-pushed":
            order.append("deployed")
        return out

    token_leg._sign_and_send = _send

    async def _verified(locator, **_k):
        order.append("verified")

    token_leg.verify_funded = _verified
    eth_leg = EthLeg(
        contract_leg=token_leg,
        network="anvil",
        claim_to="0x" + "44" * 20,
        refund_to="0x" + "55" * 20,
        eth_timeout_unix_s=_FUND_TIMEOUT,
    )
    terms = dataclasses.replace(
        _token_terms(), token_address=_USDC.address, eth_timeout_unix_s=_FUND_TIMEOUT, value_amount=_AMOUNT
    )
    reported: list[tuple[int, str]] = []

    async def _on_push_hash(nonce: int, tx_hash: str) -> None:
        reported.append((nonce, tx_hash))
        order.append("hash-recorded")

    async def _noop(*_a) -> None:
        return None

    asyncio.run(eth_leg.fund(terms, on_deploy=_noop, on_push_nonce=_noop, on_push_hash=_on_push_hash))
    assert reported and reported[0][1] == _PUSH_HASH, f"the token leg never reported the push hash: {order}"
    assert order.index("hash-recorded") < order.index("tokens-pushed"), order


# --------------------------------------------------------------------------- the watchtower


def _write(dirpath, name: str, record: SwapRecord, **override) -> None:
    d = record.to_dict()
    d.update(override)
    (dirpath / f"{name}.json").write_text(json.dumps(d))


async def test_the_tower_pages_each_unreadable_record_by_name_and_watches_the_rest(tmp_path) -> None:
    live = SwapRecord(state=SwapState.BTC_LOCKED, terms=_terms(), role=RecordRole.TAKER)
    _write(tmp_path, "ok", live)
    _write(tmp_path, "newer", live, schema_version=SWAP_RECORD_SCHEMA_VERSION + 1)
    (tmp_path / "corrupt.json").write_text("{not json")
    alerter = FakeAlerter()
    observer = FakeObserver({"ok": Observations(maker_has_claimed_btc=False, now_rxd_height=100)})
    results = await _reconciler(JsonDirRecordStore(tmp_path), observer, alerter).tick()
    by_id = {r.swap_id: r for r in results}
    assert by_id["newer"].decision.intent is Intent.PAGE_SQUEEZED
    assert "newer pyrxd" in by_id["newer"].decision.reason and "NOT being watched" in by_id["newer"].decision.reason
    assert by_id["corrupt"].decision.intent is Intent.PAGE_SQUEEZED
    assert ("newer", Intent.PAGE_SQUEEZED) in alerter.pages and ("corrupt", Intent.PAGE_SQUEEZED) in alerter.pages
    assert "ok" in by_id, "the readable record was not watched"


async def test_a_store_with_only_readable_records_pages_nothing_extra(tmp_path) -> None:
    _write(tmp_path, "ok", SwapRecord(state=SwapState.BTC_LOCKED, terms=_terms()))
    alerter = FakeAlerter()
    observer = FakeObserver({"ok": Observations(maker_has_claimed_btc=False, now_rxd_height=100)})
    results = await _reconciler(JsonDirRecordStore(tmp_path), observer, alerter).tick()
    assert [r.swap_id for r in results] == ["ok"]
    assert all(swap_id == "ok" for swap_id, _ in alerter.pages)


# --------------------------------------------------------------------------- review round 1


def _shipped_token_eth_leg(order: list[str]):
    """The shipped ``EthLeg`` over the shipped ``Erc20HtlcLeg`` (fake RPC), whose send reports the
    push hash through ``on_signed`` as the real one does, and whose ``fund`` arguments are kept."""
    token_leg = _leg(order=order)
    plain_send = token_leg._sign_and_send

    async def _send(*a, on_signed=None, **k):
        if on_signed is not None and order and order[-1] == "deployed":
            await on_signed(_PUSH_HASH)
        out = await plain_send(*a, **k)
        if not order or order[-1] != "tokens-pushed":
            order.append("deployed")
        return out

    token_leg._sign_and_send = _send

    async def _verified(locator, **_k):
        order.append("verified")

    token_leg.verify_funded = _verified
    seen: dict = {}
    real_fund = token_leg.fund

    async def _fund(**kw):
        seen.update(kw)
        return await real_fund(**kw)

    token_leg.fund = _fund
    leg = EthLeg(
        contract_leg=token_leg,
        network="regtest",
        claim_to="0x" + "44" * 20,
        refund_to="0x" + "55" * 20,
        eth_timeout_unix_s=_FUND_TIMEOUT,
    )
    return leg, seen


def _token_coordinator(leg, record=None, persist=None):
    """A TAKER coordinator over *leg*, with the pre-lock gate and the asset re-check stood in. They
    are not the subject here (they read the Radiant chain) and are covered on their own."""
    _s, h = generate_secret()
    terms = dataclasses.replace(
        _eth_terms(hashlock=h), token_address=_USDC.address, eth_timeout_unix_s=_FUND_TIMEOUT, value_amount=_AMOUNT
    )
    import contextlib

    coord = _eth_coord_full(terms=terms, eth_leg=leg, role=SwapRole.TAKER, fund_lock=contextlib.nullcontext)
    if record is not None:
        coord.record = coord._adopted(dataclasses.replace(record, terms=terms))
        coord.seen_store.reserve(terms.hashlock)  # a pending deploy means this swap won the reserve
    if persist is not None:
        coord._persist = persist
    from pyrxd.gravity.swap_coordinator import PreBtcLockGate

    async def _gate(*_a, **_k):
        return PreBtcLockGate(ok=True, reason="stood in")

    async def _asset(*_a, **_k):
        return ("cd" * 32 + ":0", 1_000, 0)

    coord.pre_btc_lock_check = _gate
    coord.taker_verify_asset_funding = _asset
    coord._judge_remaining_window = lambda *_a, **_k: None
    return coord, terms


async def test_the_push_hash_reaches_the_record_through_the_shipped_eth_leg(tmp_path) -> None:
    """Both halves joined: coordinator -> ``_accepted_kwargs`` -> shipped ``EthLeg`` -> shipped token
    leg. Planting ``_accepted_kwargs`` to return nothing for ``EthLeg`` passed every test before."""
    order: list[str] = []
    leg, _seen = _shipped_token_eth_leg(order)
    sink = JsonFileRecordSink(tmp_path / "swap.json")
    coord, terms = _token_coordinator(leg, persist=sink)
    await coord.taker_funds_btc(terms, now_unix_s=_FUND_TIMEOUT - 40_000)
    on_disk = sink.load_record()
    assert on_disk.state is SwapState.BTC_LOCKED
    assert on_disk.pending_push_tx_hash == _PUSH_HASH, f"the shipped path never recorded the push hash: {order}"
    assert on_disk.role is RecordRole.TAKER


async def test_a_resume_hands_the_recorded_push_hash_back_to_the_token_leg(tmp_path) -> None:
    """The resume half: the persisted hash reaches the token leg, which is what lets it read its own
    still-pending push and replace it rather than refuse (``erc20_leg`` replace-own-push)."""
    order: list[str] = []
    leg, seen = _shipped_token_eth_leg(order)
    pending = SwapRecord(
        state=SwapState.NEGOTIATED,
        terms=_token_terms(),
        pending_counter_contract="0x" + "77" * 20,
        pending_counter_deploy_tx="0x" + "de" * 32,
        pending_push_nonce=9,
        pending_push_tx_hash=_PUSH_HASH,
    )
    coord, terms = _token_coordinator(leg, record=pending)
    try:
        await coord.taker_funds_btc(terms, now_unix_s=_FUND_TIMEOUT - 40_000)
    except Exception as exc:  # the fake chain holds no such contract; only the handoff matters
        assert seen, f"the fund failed before reaching the token leg: {exc}"
    assert seen.get("push_tx_hash") == _PUSH_HASH and seen.get("push_nonce") == 9, seen


async def test_resume_interrupted_fund_checks_and_stamps_the_role(tmp_path) -> None:
    """``resume_interrupted_fund`` adopts the record from its sink; it skipped the constructor's
    check, so another side's record was driven and a pre-0.27 one was persisted with no role."""
    sink = JsonFileRecordSink(tmp_path / "swap.json")
    base = SwapRecord(
        state=SwapState.NEGOTIATED,
        terms=_token_terms(),
        pending_counter_contract="0x" + "77" * 20,
        pending_counter_deploy_tx="0x" + "de" * 32,
    )
    order: list[str] = []
    leg, _seen = _shipped_token_eth_leg(order)
    coord, terms = _token_coordinator(leg)
    await sink(dataclasses.replace(base, terms=terms, role=RecordRole.MAKER))
    with pytest.raises(ValidationError, match="written by a maker-role coordinator"):
        await coord.resume_interrupted_fund(terms, sink=sink, now_unix_s=_FUND_TIMEOUT - 40_000)

    (tmp_path / "swap.json").unlink()
    await sink(dataclasses.replace(base, terms=terms))  # a pre-0.27 record: no role
    coord2, _t = _token_coordinator(leg)
    try:
        await coord2.resume_interrupted_fund(terms, sink=sink, now_unix_s=_FUND_TIMEOUT - 40_000)
    except Exception:
        pass  # the fake chain may refuse the resume; what was adopted is the subject
    assert coord2.record.role is RecordRole.TAKER


async def test_the_sink_keeps_a_persisted_role_and_refuses_another(tmp_path) -> None:
    sink = JsonFileRecordSink(tmp_path / "swap.json")
    terms = _terms()
    await sink(SwapRecord(state=SwapState.NEGOTIATED, terms=terms, role=RecordRole.TAKER))
    await sink(SwapRecord(state=SwapState.BTC_LOCKED, terms=terms))  # built outside a coordinator
    assert sink.load_record().role is RecordRole.TAKER, "a role-less write dropped the persisted role"
    with pytest.raises(ValidationError, match="written by the taker side"):
        await sink(SwapRecord(state=SwapState.BTC_LOCKED, terms=terms, role=RecordRole.MAKER))
    await sink(SwapRecord(state=SwapState.BOTH_LOCKED, terms=terms, role=RecordRole.TAKER))  # honest path
    assert sink.load_record().state is SwapState.BOTH_LOCKED
