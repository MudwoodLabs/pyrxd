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
        push_signer=leg.signer_address(),
    )
    coord, terms = _token_coordinator(leg, record=pending)
    try:
        await coord.taker_funds_btc(terms, now_unix_s=_FUND_TIMEOUT - 40_000)
    except Exception as exc:  # the fake chain holds no such contract; only the handoff matters
        assert seen, f"the fund failed before reaching the token leg: {exc}"
    assert seen.get("push_tx_hash") == _PUSH_HASH and seen.get("push_nonce") == 9, seen


async def test_the_push_key_reaches_the_record_with_the_push_nonce(tmp_path) -> None:
    """#850 PR 7a: the push nonce is a count of one key; the record names the key, from the shipped
    ``EthLeg``, in the same write as the nonce, before the push."""
    order: list[str] = []
    leg, _seen = _shipped_token_eth_leg(order)
    sink = JsonFileRecordSink(tmp_path / "swap.json")
    persisted: list[SwapRecord] = []

    async def _persist(record):
        persisted.append(record)
        await sink(record)

    coord, terms = _token_coordinator(leg, persist=_persist)
    await coord.taker_funds_btc(terms, now_unix_s=_FUND_TIMEOUT - 40_000)
    first_nonce = next(r for r in persisted if r.pending_push_nonce is not None)
    assert first_nonce.push_signer == leg.signer_address()
    assert leg.signer_address() == leg._leg._account_address().lower()
    assert sink.load_record().push_signer == leg.signer_address()


def _pending_push(signer: str) -> SwapRecord:
    return SwapRecord(
        state=SwapState.NEGOTIATED,
        terms=_token_terms(),
        pending_counter_contract="0x" + "77" * 20,
        pending_counter_deploy_tx="0x" + "de" * 32,
        pending_push_nonce=9,
        pending_push_tx_hash=_PUSH_HASH,
        push_signer=signer,
    )


async def test_a_resume_with_another_key_than_the_push_is_refused(tmp_path) -> None:
    """A push pinned at key A's nonce 9 is not stopped by key B's nonce 9: a resume with B would push
    again and leave A's push free to land. Refused before the token leg is reached."""
    order: list[str] = []
    leg, seen = _shipped_token_eth_leg(order)
    coord, terms = _token_coordinator(leg, record=_pending_push("0x" + "ab" * 20))
    with pytest.raises(ValidationError, match="resume with the key that signed the push"):
        await coord.taker_funds_btc(terms, now_unix_s=_FUND_TIMEOUT - 40_000)
    assert seen == {} and coord.record.state is SwapState.NEGOTIATED


async def test_a_resumed_record_without_a_push_key_does_not_adopt_the_resuming_one(tmp_path) -> None:
    """Re-review of #850 PR 7a: a record from before the key was kept (a 0.26.x pin) resumed with
    whatever key this leg has. Stamping that key from the push-hash write would make it the key whose
    count ends the record, unproven. Only a nonce this process chose names its key."""
    order: list[str] = []
    leg, _seen = _shipped_token_eth_leg(order)
    old = dataclasses.replace(_pending_push(leg.signer_address()), push_signer=None)
    persisted: list[SwapRecord] = []

    async def _persist(record):
        persisted.append(record)

    coord, terms = _token_coordinator(leg, record=old, persist=_persist)
    proofs: list[tuple[str, str]] = []

    async def _created(address, deploy_tx_hash):  # this key's CREATE address at the deploy's nonce
        proofs.append((address, deploy_tx_hash))
        return True

    leg.created_by_this_key = _created

    async def _fund(**kw):  # the resume reports its push hash at the pinned nonce, then stops
        await kw["on_push_hash"](kw["push_nonce"], _PUSH_HASH)
        raise RuntimeError("stop after the push hash")

    leg._leg.fund = _fund
    with pytest.raises(RuntimeError, match="stop after the push hash"):
        await coord.taker_funds_btc(terms, now_unix_s=_FUND_TIMEOUT - 40_000)
    assert any(r.pending_push_tx_hash == _PUSH_HASH for r in persisted), "the push hash write never ran"
    assert {r.push_signer for r in persisted} == {None}
    assert proofs == [(old.pending_counter_contract, old.pending_counter_deploy_tx)]


@pytest.mark.parametrize("prover", ["another key deployed it", "the leg cannot say", "the record names no contract"])
async def test_a_record_without_a_push_key_is_not_resumed_by_a_key_that_did_not_deploy(tmp_path, prover) -> None:
    """Re-review of #850 PR 7a, round 2: the push was pinned at nonce 9 before the record named its
    key. A key that cannot be shown to have deployed the contract would push at ITS nonce 9 and leave
    the first push free to land. Refused before the token leg is reached; the honest pair is the test
    above, where the deploy proof holds. A record with the nonce and no contract has nothing to prove
    the deploy against, so it is refused even by a leg whose proof would say yes."""
    order: list[str] = []
    leg, seen = _shipped_token_eth_leg(order)
    old = dataclasses.replace(_pending_push(leg.signer_address()), push_signer=None)
    if prover == "the record names no contract":
        old = dataclasses.replace(
            old, pending_counter_contract=None, pending_counter_deploy_tx=None, pending_push_tx_hash=None
        )
    coord, terms = _token_coordinator(leg, record=old)
    if prover == "the record names no contract":
        from tests.test_swap_coordinator import FakeSeenStore

        coord.seen_store = FakeSeenStore()  # a store that lost H: one that holds it refuses at the reserve

        async def _yes(address, deploy_tx_hash):
            return True

        leg.created_by_this_key = _yes
    elif prover == "another key deployed it":

        async def _created(address, deploy_tx_hash):
            return False

        leg.created_by_this_key = _created
    else:
        leg.created_by_this_key = None
    with pytest.raises(ValidationError, match="resume with the key that deployed it"):
        await coord.taker_funds_btc(terms, now_unix_s=_FUND_TIMEOUT - 40_000)
    assert seen == {} and coord.record.state is SwapState.NEGOTIATED


async def test_a_resume_with_a_leg_that_does_not_say_its_key_is_refused(tmp_path) -> None:
    order: list[str] = []
    leg, seen = _shipped_token_eth_leg(order)
    coord, terms = _token_coordinator(leg, record=_pending_push(leg.signer_address()))
    leg.signer_address = None  # a leg written before signer_address
    with pytest.raises(ValidationError, match="resume with the key that signed the push"):
        await coord.taker_funds_btc(terms, now_unix_s=_FUND_TIMEOUT - 40_000)
    assert seen == {}


async def test_HONEST_a_resume_with_the_push_key_reaches_the_token_leg(tmp_path) -> None:
    order: list[str] = []
    leg, seen = _shipped_token_eth_leg(order)
    coord, terms = _token_coordinator(leg, record=_pending_push(leg.signer_address()))
    try:
        await coord.taker_funds_btc(terms, now_unix_s=_FUND_TIMEOUT - 40_000)
    except Exception as exc:  # the fake chain holds no such contract; only the handoff matters
        assert seen, f"the fund failed before reaching the token leg: {exc}"
    assert seen.get("push_nonce") == 9, seen


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


# --------------------------------------------------------------------------- Mythos review round


async def test_the_sink_keeps_a_hand_edited_role_that_has_no_schema_version(tmp_path) -> None:
    """A record naming a role but no version was only possible by hand, and crashed the sink with a
    bare KeyError on the next role-less write (Mythos L1)."""
    sink = JsonFileRecordSink(tmp_path / "swap.json")
    terms = _terms()
    await sink(SwapRecord(state=SwapState.NEGOTIATED, terms=terms, role=RecordRole.TAKER))
    raw = json.loads((tmp_path / "swap.json").read_text())
    del raw["schema_version"]
    (tmp_path / "swap.json").write_text(json.dumps(raw))
    await sink(SwapRecord(state=SwapState.BTC_LOCKED, terms=terms))
    on_disk = json.loads((tmp_path / "swap.json").read_text())
    assert on_disk["role"] == "taker" and on_disk["schema_version"] == SWAP_RECORD_SCHEMA_VERSION


def test_a_single_operator_record_refused_by_a_two_host_runner_names_the_runner_to_use() -> None:
    """The two-host runners accept only --role maker|taker, so "run it with --role none" could not be
    followed (Mythos L2)."""
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
    from _dust_swap_shared import _refuse_another_roles_record

    record = SwapRecord(state=SwapState.BTC_LOCKED, terms=_terms(), role=RecordRole.NONE)
    with pytest.raises(SystemExit) as raised:
        _refuse_another_roles_record(record, role="taker", path="swap.json")
    msg = str(raised.value)
    assert "single-operator run" in msg and "--role none" not in msg, msg
    with pytest.raises(SystemExit, match="Run it with --role maker"):
        _refuse_another_roles_record(dataclasses.replace(record, role=RecordRole.MAKER), role="taker", path="swap.json")


async def test_the_deploy_proof_is_this_keys_create_address_at_the_deploys_nonce(tmp_path) -> None:
    """``EthLeg.created_by_this_key``: only the deploy's nonce comes from the endpoint, and the CREATE
    derivation checks it. Another key's contract, or a read that fails, proves nothing."""
    from pyrxd.eth_wallet.erc20_leg import _create_address

    leg, _seen = _shipped_token_eth_leg([])
    ours = _create_address(leg.signer_address(), 5)
    answers: dict[str, object] = {"0x" + "de" * 32: {"nonce": 5}, "0x" + "df" * 32: {"nonce": True}}

    async def _get_transaction(tx_hash):
        if tx_hash not in answers:
            raise ConnectionError("endpoint down")
        return answers[tx_hash]

    leg._leg._rpc.get_transaction = _get_transaction
    assert await leg.created_by_this_key(ours, "0x" + "de" * 32) is True
    assert await leg.created_by_this_key(ours.lower(), "0x" + "de" * 32) is True
    assert await leg.created_by_this_key("0x" + "77" * 20, "0x" + "de" * 32) is False
    at_one = _create_address(leg.signer_address(), 1)  # where a bool read as the integer 1 would point
    assert await leg.created_by_this_key(at_one, "0x" + "df" * 32) is False  # a bool is not a nonce
    assert await leg.created_by_this_key(ours, "0x" + "e0" * 32) is False
