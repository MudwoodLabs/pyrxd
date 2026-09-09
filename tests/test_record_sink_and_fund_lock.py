"""The two things that make the ERC-20 fund path safe in production rather than in principle.

Both exist because of a defect, not a wish. The record sink exists because not one shipped runner
injected a persist hook, so the durable deploy handle never reached disk and every recoverability
guarantee in the coordinator was inert. The fund lock exists because `reserve(H)` was the only
mutual exclusion in the funding path, and resuming an interrupted fund deliberately skips it.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import multiprocessing as mp
import time
from pathlib import Path

import pytest

from pyrxd.gravity.record_sink import FileFundLock, JsonFileRecordSink
from pyrxd.security.errors import NetworkError, ValidationError


class _Rec:
    def __init__(self, payload: dict) -> None:
        self._p = payload

    def to_dict(self) -> dict:
        return self._p


class TestTheRecordSinkWritesAtomically:
    def test_it_round_trips_a_record(self, tmp_path: Path) -> None:
        sink = JsonFileRecordSink(tmp_path / "swap.json")
        payload = {"state": "negotiated", "pending_counter_contract": "0x" + "ab" * 20}
        asyncio.run(sink(_Rec(payload)))
        assert sink.load() == payload

    def test_it_leaves_no_temporary_files_behind(self, tmp_path: Path) -> None:
        """A stray tmp file beside the record is how a later reader picks up a half-written one."""
        sink = JsonFileRecordSink(tmp_path / "swap.json")
        for i in range(5):
            asyncio.run(sink(_Rec({"n": i})))
        assert sorted(p.name for p in tmp_path.iterdir()) == ["swap.json"]

    def test_the_file_is_not_world_readable(self, tmp_path: Path) -> None:
        sink = JsonFileRecordSink(tmp_path / "swap.json")
        asyncio.run(sink(_Rec({"n": 1})))
        assert oct(sink.path.stat().st_mode)[-3:] == "600"

    def test_a_rewrite_never_leaves_a_TRUNCATED_file(self, tmp_path: Path) -> None:
        """The property `os.replace` buys: a reader either sees the whole old record or the whole
        new one. Writing in place would let a crash mid-write leave a file that parses as nothing
        while looking like it should — worse than no record, because the address is gone."""
        sink = JsonFileRecordSink(tmp_path / "swap.json")
        asyncio.run(sink(_Rec({"pending_counter_contract": "0x" + "11" * 20})))
        big = {"pending_counter_contract": "0x" + "22" * 20, "pad": "x" * 100_000}
        asyncio.run(sink(_Rec(big)))
        assert json.loads(sink.path.read_text())["pending_counter_contract"] == "0x" + "22" * 20

    def test_an_unwritable_location_RAISES_rather_than_silently_dropping(self, tmp_path: Path) -> None:
        """The whole failure being fixed is a persist that silently does nothing. If the record
        cannot be written the caller must find out, because the coordinator awaits this before
        letting value move."""
        sink = JsonFileRecordSink(tmp_path / "swap.json")
        tmp_path.chmod(0o500)
        try:
            with pytest.raises(NetworkError):
                asyncio.run(sink(_Rec({"n": 1})))
        finally:
            tmp_path.chmod(0o700)


def _hold_lock(path: str, ready, done) -> None:
    lock = FileFundLock(path)
    with lock():
        ready.set()
        done.wait(10)


class TestTheFundLockIsExclusive:
    def test_a_second_holder_in_the_SAME_process_is_refused(self, tmp_path: Path) -> None:
        lock = FileFundLock(tmp_path / "swap")
        with lock():
            with pytest.raises(ValidationError, match="already funding"):
                with lock():
                    pass

    def test_a_second_holder_in_ANOTHER_PROCESS_is_refused(self, tmp_path: Path) -> None:
        """The case that matters: the double-fund needs two PROCESSES (a supervisor restart racing
        a lingering worker, or an operator retrying twice). An in-process-only lock would not have
        closed it."""
        ctx = mp.get_context("spawn")
        ready, done = ctx.Event(), ctx.Event()
        p = ctx.Process(target=_hold_lock, args=(str(tmp_path / "swap"), ready, done))
        p.start()
        try:
            assert ready.wait(10), "helper process never acquired the lock"
            with pytest.raises(ValidationError, match="already funding"):
                with FileFundLock(tmp_path / "swap")():
                    pass
        finally:
            done.set()
            p.join(10)

    def test_the_lock_is_RELEASED_on_exit_so_a_later_resume_can_take_it(self, tmp_path: Path) -> None:
        """A resume that could only ever run once would be useless — the whole point is recovering
        from an interruption, which may itself be interrupted."""
        lock = FileFundLock(tmp_path / "swap")
        for _ in range(3):
            with lock():
                pass

    def test_a_CRASHED_holder_does_not_deadlock_the_swap(self, tmp_path: Path) -> None:
        """Why flock and not a lease: the kernel drops it when the process dies. A lease would
        leave the swap locked for its duration by exactly the crash a resume exists to recover
        from."""
        ctx = mp.get_context("spawn")
        ready, done = ctx.Event(), ctx.Event()
        p = ctx.Process(target=_hold_lock, args=(str(tmp_path / "swap"), ready, done))
        p.start()
        assert ready.wait(10)
        p.kill()  # SIGKILL — no cleanup runs
        p.join(10)
        deadline = time.time() + 10
        while time.time() < deadline:
            try:
                with FileFundLock(tmp_path / "swap")():
                    return
            except ValidationError:
                time.sleep(0.05)
        pytest.fail("the lock outlived the process that held it")


class TestLoadingBackIsFailClosed:
    """The read side. The durable handle was WRITTEN for a whole release before anything read it
    back, so the recoverability it promised did not exist — and a load path is only worth adding if
    it refuses bad input, because it runs on a crash-restart, when disk state is least trustworthy.
    """

    def _rec(self):
        from pyrxd.gravity.swap_state import SwapRecord, SwapState
        from tests.test_swap_coordinator import _eth_terms

        return SwapRecord(
            state=SwapState.NEGOTIATED,
            # 1_800_000_000 was ~3 years past the shared fixture clock; `_eth_terms` now SIZES t_rxd
            # from the deadline (#482), so that asks for ~333k blocks and trips the BIP68 16-bit cap.
            terms=_eth_terms(hashlock=b"\x33" * 32, eth_timeout_unix_s=1_700_040_000),
            pending_counter_contract="0x" + "ab" * 20,
            pending_counter_deploy_tx="0x" + "cd" * 32,
            pending_push_nonce=41,
        )

    def test_a_written_record_round_trips_as_a_SwapRecord(self, tmp_path: Path) -> None:
        """THE property the write side was missing. Not a dict — the real type, so `__post_init__`
        runs and the pending handle is validated on the way back in."""
        sink = JsonFileRecordSink(tmp_path / "swap.json")
        rec = self._rec()
        asyncio.run(sink(rec))
        back = sink.load_record()
        assert back is not None
        assert back.pending_counter_contract == rec.pending_counter_contract
        assert back.pending_counter_deploy_tx == rec.pending_counter_deploy_tx
        assert back.pending_push_nonce == 41, "the nonce pin did not survive the round trip"

    def test_an_absent_record_is_None_not_an_error(self, tmp_path: Path) -> None:
        assert JsonFileRecordSink(tmp_path / "nope.json").load_record() is None

    @pytest.mark.parametrize(
        ("label", "body"),
        [
            ("a torn write", '{"state": "negotiated", "ter'),
            ("an empty file", ""),
            ("whitespace only", "   \n"),
            ("a JSON array", "[1, 2, 3]"),
            ("a JSON scalar", '"negotiated"'),
        ],
    )
    def test_an_unreadable_record_RAISES_rather_than_reading_as_absent(
        self, tmp_path: Path, label: str, body: str
    ) -> None:
        """The dangerous failure is not an exception — it is a corrupt record decoding as "no swap
        here", because the operator then re-runs from scratch while a contract holds real value."""
        p = tmp_path / "swap.json"
        p.write_text(body)
        sink = JsonFileRecordSink(p)
        with pytest.raises(ValidationError):
            sink.load_record()

    def test_a_record_with_HALF_a_pending_handle_is_refused_on_load(self, tmp_path: Path) -> None:
        """The both-or-neither invariant must bind on the way IN, not only at construction — a
        hand-edited or partially-migrated file is exactly how half a handle reaches a resume, and
        half a handle cannot rebuild a locator."""
        sink = JsonFileRecordSink(tmp_path / "swap.json")
        asyncio.run(sink(self._rec()))
        d = json.loads(sink.path.read_text())
        del d["pending_counter_deploy_tx"]
        sink.path.write_text(json.dumps(d))
        with pytest.raises(ValidationError, match="must be set together"):
            sink.load_record()


class TestItRefusesToClobberADifferentSwap:
    """`os.replace` is unconditional, and the record path derives from `--keys-out` — per RUN.

    So re-running with a `--keys-out` that already has a record silently replaced it, and the
    record it replaced may reference a contract that still holds value: the pending counter
    contract address and the funded locator live nowhere else. Until now the only obstacle was
    incidental, the KEYS file's `O_EXCL` — and the runbook tells operators to delete that file
    after sweep, which removes the accident and leaves the record unprotected (#504 item 3).

    Keyed on the HASHLOCK rather than on existence, because this sink is called repeatedly as one
    swap advances. A guard that refused any existing file would break every update after the
    first, which is the failure this project treats as a bug in its own right — so the same-swap
    path is asserted here just as hard as the refusal.
    """

    def _rec(self, hashlock: bytes, *, nonce: int = 41):
        from pyrxd.gravity.swap_state import SwapRecord, SwapState
        from tests.test_swap_coordinator import _eth_terms

        return SwapRecord(
            state=SwapState.NEGOTIATED,
            terms=_eth_terms(hashlock=hashlock, eth_timeout_unix_s=1_700_040_000),
            pending_counter_contract="0x" + "ab" * 20,
            pending_counter_deploy_tx="0x" + "cd" * 32,
            pending_push_nonce=nonce,
        )

    def test_the_same_swap_may_be_written_repeatedly(self, tmp_path: Path) -> None:
        """THE honest path. One swap persists many times as its state advances."""
        sink = JsonFileRecordSink(tmp_path / "swap.json")
        for nonce in (41, 42, 43):
            asyncio.run(sink(self._rec(b"\x33" * 32, nonce=nonce)))
        back = sink.load_record()
        assert back is not None and back.pending_push_nonce == 43, "later updates must land"

    def test_a_first_write_to_a_fresh_path_is_allowed(self, tmp_path: Path) -> None:
        sink = JsonFileRecordSink(tmp_path / "fresh.json")
        asyncio.run(sink(self._rec(b"\x44" * 32)))
        assert sink.load_record() is not None

    def test_a_different_swap_is_refused(self, tmp_path: Path) -> None:
        """The clobber. Two swaps, one `--keys-out`."""
        sink = JsonFileRecordSink(tmp_path / "swap.json")
        asyncio.run(sink(self._rec(b"\x33" * 32)))
        with pytest.raises(ValidationError) as exc:
            asyncio.run(sink(self._rec(b"\x55" * 32)))
        assert "DIFFERENT swap" in str(exc.value)

    def test_the_refusal_names_both_swaps_and_the_path(self, tmp_path: Path) -> None:
        """Operator-facing. A refusal that does not say WHICH record it protected, or where it
        is, sends someone hunting — and the tempting next move is to delete the file."""
        sink = JsonFileRecordSink(tmp_path / "swap.json")
        asyncio.run(sink(self._rec(b"\x33" * 32)))
        with pytest.raises(ValidationError) as exc:
            asyncio.run(sink(self._rec(b"\x55" * 32)))
        msg = str(exc.value)
        assert "swap.json" in msg
        assert ("33" * 8) in msg and ("55" * 8) in msg, "both hashlocks must be identifiable"
        assert "--keys-out" in msg, "the message must name the flag an operator can change"

    def test_the_existing_record_survives_the_refusal(self, tmp_path: Path) -> None:
        """A refusal that had already truncated the file would be worse than the clobber."""
        sink = JsonFileRecordSink(tmp_path / "swap.json")
        asyncio.run(sink(self._rec(b"\x33" * 32, nonce=41)))
        with contextlib.suppress(ValidationError):
            asyncio.run(sink(self._rec(b"\x55" * 32, nonce=99)))
        back = sink.load_record()
        assert back is not None
        assert back.pending_push_nonce == 41, "the protected record was modified anyway"
        assert back.terms.hashlock == b"\x33" * 32

    def test_a_torn_existing_record_is_refused_rather_than_overwritten(self, tmp_path: Path) -> None:
        """`load()` already fails closed on a torn file; routing the write through it means a
        record that cannot be READ cannot be silently replaced either."""
        path = tmp_path / "swap.json"
        path.write_text('{"state": "negotiated", "ter')
        with pytest.raises(ValidationError):
            asyncio.run(JsonFileRecordSink(path)(self._rec(b"\x33" * 32)))
        assert path.read_text() == '{"state": "negotiated", "ter', "the torn file was overwritten"
