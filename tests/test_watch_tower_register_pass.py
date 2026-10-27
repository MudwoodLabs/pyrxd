"""Fixes for the whole-component Mythos pass over the watchtower (register run on e6fb4b2).

* F1: the drain renamed the inbox away, so the runbook's ``echo ... >> $ACKS`` recreated it under the
  operator's umask (0644 by default) and the owner-only gate refused it: every ACK was dropped.
* F2: an ACK written while the page channel was down never took the swap off the escalation count.
* F3: one blind (-1) heartbeat used up the escalation monitor's only edge, so real un-ACKed pages
  after it never escalated.
* F5: a record named outside the ACK grammar (a space, ``+``, non-ASCII, over 128 characters) gave
  pages that could never be ACKed.
* F6: a CRITICAL that never went out counted toward escalation but could not be ACKed.
* Test gaps the pass's mutant matrix left alive (A04, A14, A18, A24, R03, D07, D15, D31). F4 is in
  ``tests/test_watchtower_dust_run_harness.py``.

Every refusal has its honest twin.
"""

from __future__ import annotations

import dataclasses
import os

import pytest

from pyrxd.btc_wallet.taproot import TimeUnit
from pyrxd.gravity.swap_state import RecordRole
from pyrxd.gravity.watch.alerts import DedupAlerter, FileAckInbox
from pyrxd.gravity.watch.decide import (
    SITUATION_CLAIM_RACE,
    SITUATION_MAKER_REFUND_T_RXD_MATURED,
    Decision,
    Intent,
)
from tests.test_watch_btc_refund_pages_through_the_alerter import T_RXD_OPENS, _at
from tests.test_watch_btc_spender_classification import BURIAL, _Tower
from tests.test_watch_escalation import TOWER_TS, RecordingChannel, make_monitor, write_beat

SWAP = "swap-1"
RACE = Decision(Intent.PAGE_SQUEEZED, reason="maker revealed p", situation=SITUATION_CLAIM_RACE)
RACE_KEY = "page_squeezed:claim_race"

posix_only = pytest.mark.skipif(os.name != "posix", reason="file modes are POSIX")


class _Channel:
    def __init__(self) -> None:
        self.sent: list = []
        self.down = False

    async def send(self, page) -> None:
        if self.down:
            raise ConnectionError("channel down")
        self.sent.append(page)


def _append_as_operator(path, line: str, umask: int) -> None:
    """What ``echo "<line>" >> path`` does in a shell with this umask."""
    old = os.umask(umask)
    try:
        with open(path, "a") as f:
            f.write(line + "\n")
    finally:
        os.umask(old)


# --------------------------------------------------------------------------- F1: the inbox keeps its mode


@posix_only
@pytest.mark.parametrize("umask", [0o022, 0o002], ids=["umask-022", "umask-002"])
def test_an_ack_appended_after_a_drain_under_a_default_umask_is_read(tmp_path, umask):
    path = tmp_path / "acks"
    _append_as_operator(path, "first", 0o077)  # created as the runbook's install -m 600 does
    inbox = FileAckInbox(path)
    assert inbox.drain() == ["first"]
    _append_as_operator(path, f"{SWAP} {RACE_KEY}", umask)
    assert inbox.drain() == [f"{SWAP} {RACE_KEY}"], "the ACK was refused: the drain left no inbox to append to"


@posix_only
def test_a_missing_inbox_is_created_owner_only(tmp_path):
    path = tmp_path / "acks"
    inbox = FileAckInbox(path)
    assert inbox.drain() == []
    assert path.stat().st_mode & 0o777 == 0o600
    _append_as_operator(path, SWAP, 0o022)
    assert inbox.drain() == [SWAP]


@posix_only
def test_an_inbox_others_can_write_is_still_refused(tmp_path):
    """The honest twin: the gate is unchanged. A group-writable inbox is refused, and the next
    one, put back owner-only, works."""
    path = tmp_path / "acks"
    path.write_text(f"{SWAP}\n")
    path.chmod(0o620)
    inbox = FileAckInbox(path)
    assert inbox.drain() == [], "a group-writable inbox was read"
    assert path.stat().st_mode & 0o777 == 0o600
    _append_as_operator(path, SWAP, 0o022)
    assert inbox.drain() == [SWAP]


@posix_only
def test_the_inbox_is_not_recreated_through_a_symlink(tmp_path):
    """A link planted at the inbox path between the claim and the re-create is not followed: the
    re-create leaves it alone, and the next drain claims and refuses it."""
    target = tmp_path / "elsewhere"
    path = tmp_path / "acks"
    inbox = FileAckInbox(path)
    path.symlink_to(target)
    inbox._recreate()  # the instant after a claim, with the link already there
    assert not target.exists(), "the re-create followed a planted link"
    assert inbox.drain() == []
    assert not target.exists() and path.is_file() and not path.is_symlink()


# --------------------------------------------------------------------------- F2 and F6: ACKs of undelivered pages


async def test_an_ack_written_while_the_channel_is_down_clears_escalation():
    """F2: the claim race paged, the channel went down, the re-page failed, the operator ACKed it."""
    ch = _Channel()
    alerter = DedupAlerter(channel=ch)
    await alerter.handle(SWAP, RACE)
    ch.down = True
    with pytest.raises(ConnectionError):
        await alerter.handle(SWAP, RACE)  # the re-page
    assert alerter.unacked_critical_count() == 1
    assert alerter.ack(SWAP, RACE_KEY) is True
    for _ in range(5):
        await alerter.handle(SWAP, RACE)  # ACKed: no re-page is attempted
    assert alerter.unacked_critical_count() == 0, "the ACK did not take the swap off the escalation count"


async def test_an_unacked_page_still_counts_while_the_channel_is_down():
    """The honest twin: without the ACK the swap keeps counting through the outage."""
    ch = _Channel()
    alerter = DedupAlerter(channel=ch)
    await alerter.handle(SWAP, RACE)
    ch.down = True
    for _ in range(5):
        with pytest.raises(ConnectionError):
            await alerter.handle(SWAP, RACE)
        assert alerter.unacked_critical_count() == 1


@pytest.mark.parametrize("key", [RACE_KEY, None], ids=["keyed", "bare"])
async def test_a_critical_that_never_went_out_can_be_acked(key):
    """F6: the escalation page tells the operator to ACK; a page whose first send failed could not be."""
    ch = _Channel()
    alerter = DedupAlerter(channel=ch)
    ch.down = True
    with pytest.raises(ConnectionError):
        await alerter.handle(SWAP, RACE)
    assert alerter.unacked_critical_count() == 1
    assert alerter.ack(SWAP, key) is True
    assert alerter.unacked_critical_count() == 0


async def test_an_undelivered_page_is_not_acked_by_a_key_it_does_not_have():
    """The honest twin: only the undelivered page's own key (or an unambiguous bare id) ACKs it."""
    ch = _Channel()
    alerter = DedupAlerter(channel=ch)
    ch.down = True
    with pytest.raises(ConnectionError):
        await alerter.handle(SWAP, RACE)
    assert alerter.ack(SWAP, "page_squeezed:reconcile_error") is False
    assert alerter.unacked_critical_count() == 1


# --------------------------------------------------------------------------- F3: a blind beat and the escalation edge


async def _beats(monitor, hb, counts, start, step=30.0):
    verdicts = []
    for i, n in enumerate(counts):
        ts = start + i * step
        write_beat(hb, ts=ts, unacked=n)
        verdicts.append(await monitor.check(now=ts))
    return verdicts


async def test_one_blind_beat_does_not_use_up_the_escalation_of_real_pages(tmp_path):
    """F3: a -1 count escalated once and set the episode's only edge, so 40 minutes of real
    un-ACKed pages after it escalated nothing."""
    hb = tmp_path / "hb.json"
    channel = RecordingChannel()
    monitor = make_monitor(hb, channel, escalate_after_s=900.0)
    verdicts = await _beats(monitor, hb, [-1] + [2] * 80, TOWER_TS)
    assert verdicts[0].escalated is True, "the honest twin: blind still escalates at once"
    later = [i for i, v in enumerate(verdicts) if v.escalated and i > 0]
    assert later, "real un-ACKed pages never escalated after one blind beat"
    assert later[0] * 30.0 >= 900.0, "the real escalation did not wait for the threshold"
    assert len(channel.pages) == 2


async def test_a_blind_count_that_persists_escalates_once(tmp_path):
    """The honest twin: a count that stays blind pages once per episode, not every beat."""
    hb = tmp_path / "hb.json"
    channel = RecordingChannel()
    monitor = make_monitor(hb, channel, escalate_after_s=900.0)
    await _beats(monitor, hb, [-1] * 20, TOWER_TS)
    assert len(channel.pages) == 1


async def test_a_blind_episode_that_ends_at_zero_pages_the_recovery(tmp_path):
    hb = tmp_path / "hb.json"
    channel = RecordingChannel()
    monitor = make_monitor(hb, channel, escalate_after_s=900.0)
    verdicts = await _beats(monitor, hb, [-1, 0], TOWER_TS)
    assert verdicts[1].recovered is True
    assert not monitor.state.blind_fired and not monitor.state.fired


# --------------------------------------------------------------------------- F5: a record name the inbox cannot carry


@posix_only
@pytest.mark.parametrize("swap_id", ["my swap", "swap+1", "sw@p", "échange", "a" * 129])
async def test_a_page_for_a_record_named_outside_the_ack_grammar_can_be_acked(tmp_path, swap_id):
    """F5: the store names a swap by its file stem and accepts any name; the page printed that name
    on its ack: line, and the inbox dropped the line as malformed, so the page could never be ACKed."""
    from pyrxd.gravity.watch.run import apply_acks

    ch = _Channel()
    alerter = DedupAlerter(channel=ch)
    await alerter.handle(swap_id, RACE)
    ack_line = ch.sent[0].message.rsplit("ack: ", 1)[1]
    path = tmp_path / "acks"
    inbox = FileAckInbox(path)
    inbox.drain()
    _append_as_operator(path, ack_line, 0o077)
    apply_acks(alerter, inbox.drain())
    assert alerter.unacked_critical_count() == 0, f"the printed ack line {ack_line!r} did not ACK the page"


async def test_an_ackable_record_name_is_printed_as_it_is():
    """The honest twin: an ordinary swap id is printed unchanged, and its alias ACKs nothing else."""
    ch = _Channel()
    alerter = DedupAlerter(channel=ch)
    await alerter.handle(SWAP, RACE)
    assert ch.sent[0].message.endswith(f"ack: {SWAP} {RACE_KEY}")
    await alerter.handle("other swap", RACE)
    assert alerter.ack("id-" + "0" * 32, RACE_KEY) is False
    assert alerter.unacked_critical_count() == 2


# --------------------------------------------------------------------------- test gaps from the pass's mutant matrix


async def test_a_keyed_ack_of_a_warn_does_not_pre_ack_its_later_critical():
    """A04: a keyed ACK names a CRITICAL page. A WARN situation that turns urgent must still count."""
    ch = _Channel()
    alerter = DedupAlerter(channel=ch)
    due = Decision(Intent.PAGE_REFUND, reason="refund due", situation="btc_refund_due")
    urgent = Decision(Intent.PAGE_REFUND, reason="refund now", situation="btc_refund_due", urgent=True)
    await alerter.handle(SWAP, due)
    assert alerter.ack(SWAP, "page_refund:btc_refund_due") is False, "a WARN was ACKed"
    await alerter.handle(SWAP, urgent)
    assert alerter.unacked_critical_count() == 1
    assert alerter.ack(SWAP, "page_refund:btc_refund_due") is True, "the honest twin: the CRITICAL ACKs"
    assert alerter.unacked_critical_count() == 0


async def test_a_retired_swap_id_reused_does_not_inherit_the_old_ack():
    """A14: RETIRE rebuilds the swap's state, so a later swap with the same id is paged afresh."""
    ch = _Channel()
    alerter = DedupAlerter(channel=ch)
    await alerter.handle(SWAP, RACE)
    assert alerter.ack(SWAP, RACE_KEY) is True
    await alerter.handle(SWAP, Decision(Intent.RETIRE, reason="done"))
    await alerter.handle(SWAP, RACE)
    assert alerter.unacked_critical_count() == 1, "the reused id inherited the old swap's ACK"
    assert len([p for p in ch.sent if p.intent is Intent.PAGE_SQUEEZED]) == 2


@posix_only
@pytest.mark.parametrize("mode", [0o660, 0o640, 0o604], ids=["group-writable", "group-readable", "other-readable"])
def test_an_inbox_others_can_read_or_write_is_refused(tmp_path, mode):
    """A18: the gate is owner-only; a group mode was never tried."""
    path = tmp_path / "acks"
    path.write_text(f"{SWAP}\n")
    path.chmod(mode)
    assert FileAckInbox(path).drain() == []


def test_an_inbox_over_the_bound_keeps_only_whole_lines(tmp_path):
    """A24: the cut at max_bytes can land mid-id, and a half id must not be ACKed."""
    path = tmp_path / "acks"
    inbox = FileAckInbox(path, max_bytes=20)
    inbox.drain()
    _append_as_operator(path, "swap-aaaa", 0o077)
    _append_as_operator(path, "swap-bbbbbbbbbbbbbbbbbbbb", 0o077)
    assert inbox.drain() == ["swap-aaaa"]


async def test_the_reconcile_page_reaches_the_operator(tmp_path):
    """R03: RECONCILE ("run reconcile_counter_leg") was asserted on decide() only, never on what the
    reconciler routes to the alerter."""
    w = _Tower(tmp_path)
    w.chain.submit(w.chain.refund_tx())
    w.chain.mine(BURIAL)
    ch = _Channel()
    (result,) = await w.reconciler(alerter=DedupAlerter(channel=ch)).tick()
    assert result.decision.intent is Intent.RECONCILE
    assert [p.intent for p in ch.sent] == [Intent.RECONCILE], "the RECONCILE page never reached the channel"


@pytest.mark.parametrize("covenant", [True, False], ids=["covenant-seen", "never-locked"])
@pytest.mark.parametrize("unit", [TimeUnit.BLOCKS, TimeUnit.SECONDS])
async def test_the_autonomous_refund_arms_only_on_a_block_count_lock(tmp_path, covenant, unit):
    """D07: no test ran decide() with t_btc in seconds. A confirmation count proves nothing about an
    MTP lock, so the refund must not arm on it; the honest twin (blocks) arms."""
    w = _Tower(tmp_path, covenant=covenant)
    record = w.record()
    t_btc = dataclasses.replace(record.terms.t_btc, unit=unit)
    w.write(dataclasses.replace(record, terms=dataclasses.replace(record.terms, t_btc=t_btc)))
    d = await w.decide()
    assert d.autonomous_btc_refund is (unit is TimeUnit.BLOCKS), d.reason


async def test_a_never_locked_refund_does_not_arm_on_a_read_below_quorum(tmp_path):
    """D15: the below-quorum test covered the covenant-seen branch only."""
    w = _Tower(tmp_path, covenant=False)
    w.sources[0].spender_reads_fail = True
    w.sources[1].spender_reads_fail = True
    d = await w.decide()
    assert d.intent is Intent.PAGE_REFUND, "the page still goes out"
    assert d.autonomous_btc_refund is False


@pytest.mark.parametrize("past", [-1, 0, 1])
async def test_the_makers_t_rxd_matured_page_starts_at_t_rxd(tmp_path, past):
    """D31: the maker's "t_rxd has matured" page at exactly the height the covenant refund opens."""
    w = _Tower(tmp_path, role=RecordRole.MAKER)
    _at(w, T_RXD_OPENS + past)
    d = await w.decide()
    assert (d.situation == SITUATION_MAKER_REFUND_T_RXD_MATURED) is (past >= 0), d.reason
