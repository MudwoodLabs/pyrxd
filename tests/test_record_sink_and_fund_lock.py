"""The two things that make the ERC-20 fund path safe in production rather than in principle.

Both exist because of a defect, not a wish. The record sink exists because not one shipped runner
injected a persist hook, so the durable deploy handle never reached disk and every recoverability
guarantee in the coordinator was inert. The fund lock exists because `reserve(H)` was the only
mutual exclusion in the funding path, and resuming an interrupted fund deliberately skips it.
"""

from __future__ import annotations

import asyncio
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
