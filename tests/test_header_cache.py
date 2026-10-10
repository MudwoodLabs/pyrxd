"""The verified-header cache (#826): the store, ``pyrxd headers sync``, and ``pyrxd verify`` with it.

REAL HEADERS. Every header here is a real mainnet header: the 17 linked headers around block
460,572 that two shipped servers served identically on 2026-09-30
(``tests/fixtures/mark_block_fixtures_2026-09-30.json``), with the HashMark in block 460,572 and its
merkle data. As in the verify tests, the shipped checkpoint table is replaced by ONE checkpoint
made from a fixture header's own hash, so the cache's whole life — sync, store, verify — runs on
17 real headers instead of the thousands the shipped table would need.

THE PRODUCTION ENTRY POINTS. ``pyrxd headers sync`` and ``pyrxd verify`` run through ``CliRunner``
against real :class:`~pyrxd.network.electrumx.ElectrumXClient` objects whose JSON-RPC transport
alone is faked, so every reply crosses the client's own parsing. Sync's operators are injected at
:func:`pyrxd.cli.headers_cmds.operator_sources`; how that function groups configured endpoints
into operators is tested on its own, against a real config.

THE FLOOR TESTS NEED A SMALL DIVISOR. Real Radiant headers 17 blocks apart differ in work by a few
percent, never 16x, so the default ``FLOOR_WORK_DIVISOR`` cannot separate "the floor rests on the
shipped checkpoint" from "the floor rests on the cached anchor" with real data. Those tests set the
divisor to 1 (or an exact Fraction just above 1), which leaves the rule under test (WHICH work the
floor is taken from) unchanged and makes the two answers differ on real headers. There is ONE
divisor, ``mark_block.FLOOR_WORK_DIVISOR``, which the cache reads at call time too, so a test sets
it for the cache and the verifier alike, as production has it.
"""

from __future__ import annotations

import copy
import json
import os
from collections.abc import Sequence
from fractions import Fraction
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from pyrxd.cli import glyph_inspect, header_store, headers_cmds
from pyrxd.cli.context import CliContext
from pyrxd.cli.main import cli
from pyrxd.glyph import header_cache, mark_block
from pyrxd.glyph.header_cache import (
    CACHE_MIN_DEPTH,
    HeaderCacheRefusal,
    VerifiedHeaders,
    agreed_headers,
    decode_store,
    encode_store,
    extend_verified_headers,
    start_verified_headers,
    verify_header_chain,
)
from pyrxd.glyph.mark_block import MAX_HEADERS_FROM_CHECKPOINT, plan_block_verification
from pyrxd.hash import radiant_block_hash
from pyrxd.network.electrumx import ElectrumXClient
from pyrxd.security.errors import NetworkError, ValidationError
from pyrxd.spv import radiant_checkpoints
from pyrxd.spv.radiant import radiant_header_work

ROOT = Path(__file__).resolve().parent.parent
_FIX = json.loads((ROOT / "tests/fixtures/mark_block_fixtures_2026-09-30.json").read_text(encoding="utf-8"))["fixtures"]
TXID = "a1a86ab4503901af4df3d092fcf668b07c03c5cd89240fe918ae70e02e045916"  # block 460,572
FX = _FIX[TXID]
RAW = bytes.fromhex(FX["headers_hex"])
START = FX["headers_start"]  # 460,564
HEADERS = {START + i: RAW[i * 80 : (i + 1) * 80] for i in range(len(RAW) // 80)}
TOP = max(HEADERS)  # 460,580
MARK_H = FX["merkle"]["block_height"]  # 460,572
LABEL = "wss://fixture.invalid/"

#: The second real mark (pyrxd's own, block 468,521) and its 17 headers, for the one floor test
#: whose work pattern only that stretch has.
TXID2 = "aa66b04662aa5514ed7d0027ff3cbd608d73f3e2b92d4129d810eb576bc0c86e"
FX2 = _FIX[TXID2]
_RAW2 = bytes.fromhex(FX2["headers_hex"])
HEADERS2 = {FX2["headers_start"] + i: _RAW2[i * 80 : (i + 1) * 80] for i in range(len(_RAW2) // 80)}
#: Both stretches by height (they do not overlap).
BY_HEIGHT = {**HEADERS, **HEADERS2}


def _hash(h: int) -> str:
    return radiant_block_hash(BY_HEIGHT[h])


def _table(cp: int) -> tuple[tuple[int, str], ...]:
    return ((cp, _hash(cp)),)


def _chain(cp: int, top: int) -> VerifiedHeaders:
    chain = start_verified_headers("mainnet", BY_HEIGHT[cp], table=_table(cp))
    if top > cp:
        chain, stopped = extend_verified_headers(chain, [BY_HEIGHT[h] for h in range(cp + 1, top + 1)])
        assert stopped is None
    assert chain.top == top
    return chain


def _patch_table(monkeypatch, cp: int) -> None:
    monkeypatch.setitem(radiant_checkpoints.CHECKPOINTS, "mainnet", _table(cp))


def _renonced(header: bytes) -> bytes:
    moved = bytearray(header)
    moved[76] ^= 1
    return bytes(moved)


def test_the_fixture_is_what_these_tests_lean_on() -> None:
    """Non-vacuity: 17 consecutive linked real headers, the mark in the middle, the work spread the
    floor tests use (460,566 carries the most work; 460,576 more than 460,575)."""
    assert (START, MARK_H, TOP) == (460564, 460572, 460580)
    for h in range(START + 1, TOP + 1):
        assert HEADERS[h][4:36][::-1].hex() == _hash(h - 1)
    work = {h: radiant_header_work(HEADERS[h]) for h in HEADERS}
    assert max(work, key=work.get) == 460566
    assert work[460575] < work[460576] < work[460566]
    assert mark_block.FLOOR_WORK_DIVISOR == 16
    assert type(mark_block.FLOOR_WORK_DIVISOR) is int, "an int: a float floor is inexact (see _floor_of)"


def test_the_floor_divisor_has_one_source(monkeypatch) -> None:
    """The cache and the verifier read ONE divisor, ``mark_block.FLOOR_WORK_DIVISOR``, at call time.
    A copy imported by value let tests set the cache's to 1 while the verifier's stayed 16, a
    combination production cannot have."""
    assert not hasattr(header_cache, "FLOOR_WORK_DIVISOR"), "no second copy for a test to set apart"
    w = radiant_header_work(HEADERS[START])
    assert _chain(START, START).floor_work == w // 16
    monkeypatch.setattr(mark_block, "FLOOR_WORK_DIVISOR", 1)
    assert _chain(START, START).floor_work == w, "the cache's floor follows mark_block's divisor"


# ── the pure core ───────────────────────────────────────────────────────────────────────────


def test_a_verified_headers_object_cannot_be_built_by_hand() -> None:
    with pytest.raises(ValidationError, match="built only by"):
        VerifiedHeaders("mainnet", START, _hash(START), (HEADERS[START],), (_hash(START),), 1)


def test_a_verified_headers_object_cannot_be_derived_with_replace() -> None:
    """``dataclasses.replace`` re-runs ``__init__`` with the original's seal; each seal admits one
    construction, so a derived (unchecked) chain is refused."""
    import dataclasses

    chain = _chain(START, 460570)
    with pytest.raises(ValidationError, match="built only by"):
        dataclasses.replace(chain, headers=(*chain.headers, HEADERS[460575]))
    with pytest.raises(ValidationError, match="built only by"):
        dataclasses.replace(chain, floor_work=1)


def test_the_floor_is_the_checkpoints_and_does_not_move_with_the_cache() -> None:
    cp = 460566
    chain = _chain(cp, TOP)
    assert chain.floor_work == radiant_header_work(HEADERS[cp]) // 16
    # Re-read from the same headers, it is the same, whatever the cache's newest header carries.
    again, why = verify_header_chain("mainnet", cp, list(chain.headers), table=_table(cp))
    assert why is None and again is not None and again.floor_work == chain.floor_work
    assert radiant_header_work(chain.headers[-1]) < radiant_header_work(chain.headers[0])


def test_agreed_headers_needs_two_operators_and_byte_identical_replies() -> None:
    got = [HEADERS[h] for h in range(START, START + 3)]
    assert agreed_headers({"operator:a": got, "operator:b": list(got)}, START, 3) == got
    with pytest.raises(HeaderCacheRefusal, match="at least 2 different operators, got 1"):
        agreed_headers({"operator:a": got}, START, 3)
    other = [got[0], _renonced(got[1]), got[2]]
    with pytest.raises(HeaderCacheRefusal, match=f"disagree on the header at block {START + 1}"):
        agreed_headers({"operator:a": got, "operator:b": other}, START, 3)
    with pytest.raises(HeaderCacheRefusal, match="served 2 of the 3"):
        agreed_headers({"operator:a": got, "operator:b": got[:2]}, START, 3)


def test_extending_refuses_a_lie_and_stops_at_the_floor() -> None:
    chain = _chain(START, 460567)
    # A broken link: the header at 460,569 served where 460,568 belongs.
    with pytest.raises(HeaderCacheRefusal, match="does not link"):
        extend_verified_headers(chain, [HEADERS[460569]])
    # A failed proof-of-work: 460,568 with another nonce (it still names 460,567 as its parent).
    with pytest.raises(HeaderCacheRefusal, match="fails its own proof-of-work"):
        extend_verified_headers(chain, [_renonced(HEADERS[460568])])
    # Honest: it extends.
    longer, stopped = extend_verified_headers(chain, [HEADERS[460568], HEADERS[460569]])
    assert stopped is None and longer.top == 460569


# ── the store ───────────────────────────────────────────────────────────────────────────────


def test_a_saved_store_reads_back_verified(tmp_path) -> None:
    chain = _chain(START, TOP)
    path = tmp_path / "mainnet.bin"
    header_store.save(chain, table=_table(START), record={"from": START + 1, "to": TOP}, path=path)
    got = header_store.load("mainnet", _table(START), path=path)
    assert got.chain is not None and got.chain.headers == chain.headers and got.note is None
    assert got.syncs == ({"from": START + 1, "to": TOP},)
    assert not any(p.name.endswith(".tmp") for p in tmp_path.iterdir()), "no temporary file is left"


def _corruptions() -> dict[str, Any]:
    chain = _chain(START, TOP)
    good = encode_store(chain)
    body_at = good.index(chain.headers[0])

    def reencode(headers: list[bytes]) -> bytes:
        # A WELL-FORMED store (valid checksum) whose headers do not verify.
        meta, _ = decode_store(good)
        import hashlib

        blob = json.dumps(meta, sort_keys=True, separators=(",", ":")).encode()
        body = b"pyrxd-header-cache\n" + len(blob).to_bytes(4, "big") + blob + b"".join(headers)
        return body + hashlib.sha256(body).digest()

    flipped = bytearray(good)
    flipped[body_at + 80 * 5 + 40] ^= 1
    headers = list(chain.headers)
    swapped = [*headers[:5], _renonced(headers[5]), *headers[6:]]
    return {
        "a_flipped_byte": bytes(flipped),
        "truncated": good[:-100],
        "empty_file": b"",
        "garbage": os.urandom(4000),
        "valid_checksum_but_a_header_fails_its_proof_of_work": reencode(swapped),
        "valid_checksum_but_a_link_is_broken": reencode(headers[:5] + headers[6:7] + headers[5:6] + headers[7:]),
    }


@pytest.mark.parametrize("case", list(_corruptions()), ids=list(_corruptions()))
def test_a_damaged_store_is_empty_never_trusted(tmp_path, case: str) -> None:
    path = tmp_path / "mainnet.bin"
    path.write_bytes(_corruptions()[case])
    got = header_store.load("mainnet", _table(START), path=path)
    assert got.chain is None and got.untrusted
    assert "treated as empty" in (got.note or "")


def test_a_store_for_another_network_or_another_checkpoint_is_not_used(tmp_path) -> None:
    path = tmp_path / "mainnet.bin"
    header_store.save(_chain(START, TOP), table=_table(START), path=path)
    assert header_store.load("testnet", _table(START), path=path).chain is None
    assert header_store.load("mainnet", _table(460570), path=path).chain is None, "not at a shipped checkpoint"
    # Honest pair: a newer shipped checkpoint the store reaches is honoured (the store is rebased on it).
    newer = ((START, _hash(START)), (460570, _hash(460570)))
    rebased = header_store.load("mainnet", newer, path=path).chain
    assert rebased is not None and (rebased.base_height, rebased.top) == (460570, TOP)


def test_a_store_that_ends_below_the_newest_checkpoint_is_stale(tmp_path) -> None:
    path = tmp_path / "mainnet.bin"
    header_store.save(_chain(START, 460570), table=_table(START), path=path)
    got = header_store.load("mainnet", ((START, _hash(START)), (460575, _hash(460575))), path=path)
    assert got.chain is None and got.stale and not got.untrusted
    assert (
        "behind this pyrxd's newest checkpoint (460575)" in (got.note or "")
        and "stale and was not checked further" in got.note
    )


def test_a_write_that_fails_leaves_the_old_store_whole(tmp_path, monkeypatch) -> None:
    path = tmp_path / "mainnet.bin"
    header_store.save(_chain(START, 460570), table=_table(START), path=path)
    before = path.read_bytes()

    def boom(src, dst):  # the rename never happens: the crash a temp file + os.replace guards against
        raise OSError("disk full")

    monkeypatch.setattr(header_store.os, "replace", boom)
    with pytest.raises(OSError):
        header_store.save(_chain(START, TOP), table=_table(START), path=path)
    assert path.read_bytes() == before
    assert not any(p.name.endswith(".tmp") for p in tmp_path.iterdir()), "the temporary file is removed"


_KILLED_SAVE = """
import os, signal, sys
from pathlib import Path
from pyrxd.cli import header_store
from pyrxd.glyph.header_cache import start_verified_headers

path, cp, cp_hash, header = Path(sys.argv[1]), int(sys.argv[2]), sys.argv[3], bytes.fromhex(sys.argv[4])
chain = start_verified_headers("mainnet", header, table=((cp, cp_hash),))
header_store.os.replace = lambda src, dst: os.kill(os.getpid(), signal.SIGKILL)  # killed before the rename
header_store.save(chain, table=((cp, cp_hash),), path=path)
"""


def test_a_save_cleans_up_the_temporary_file_a_killed_save_left(tmp_path) -> None:
    """A save SIGKILLed between its fsync and its os.replace leaves its temporary file (no
    ``finally`` runs). The next save of the same store removes it, under the lock, and touches no
    other file. The orphan here is made by a real save in a real process killed at that point, so
    its name is the one save() really uses."""
    import signal
    import subprocess
    import sys

    path = tmp_path / "mainnet.bin"
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
    args = [str(path), str(START), _hash(START), HEADERS[START].hex()]
    done = subprocess.run([sys.executable, "-c", _KILLED_SAVE, *args], env=env, timeout=60, check=False)
    assert done.returncode == -signal.SIGKILL, done
    orphans = [p.name for p in tmp_path.iterdir() if p.name.endswith(".tmp")]
    assert len(orphans) == 1 and orphans[0].startswith(".mainnet.bin.") and not path.exists(), orphans
    # Files that are not this store's temporary files are left alone.
    others = [".testnet.bin.1.deadbeef.tmp", ".mainnet.bin.notes.tmp", "mainnet.bin.1.deadbeef.tmp"]
    for name in others:
        (tmp_path / name).write_bytes(b"x")
    header_store.save(_chain(START, TOP), table=_table(START), path=path)
    left = sorted(p.name for p in tmp_path.iterdir() if p.name.endswith(".tmp"))
    assert left == sorted(others), left
    assert header_store.load("mainnet", _table(START), path=path).chain.top == TOP  # type: ignore[union-attr]


def test_two_saves_at_once_cannot_shorten_the_store(tmp_path) -> None:
    """The append-only check and the replace happen under one lock. Interleaving, made
    deterministic: this test holds the lock while a save of a SHORTER chain starts (it read nothing
    yet), then writes a longer store itself, as a second sync would, and releases the lock. The
    first save then checks against the longer store and refuses; without the lock it would have
    checked the old one and shortened the store."""
    import fcntl
    import threading

    path = tmp_path / "mainnet.bin"
    header_store.save(_chain(START, 460570), table=_table(START), path=path)
    errors: list[BaseException] = []

    def shorter() -> None:
        try:
            header_store.save(_chain(START, 460575), table=_table(START), path=path)
        except BaseException as exc:
            errors.append(exc)

    fd = os.open(header_store.lock_path(path), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        t = threading.Thread(target=shorter)
        t.start()
        t.join(0.5)
        assert t.is_alive(), "the save waits for the lock"
        path.write_bytes(encode_store(_chain(START, TOP)))  # the other sync's write, under the lock
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)
    t.join(10)
    assert not t.is_alive()
    assert errors and isinstance(errors[0], header_store.AppendOnlyRefusal)
    assert "already reaches block 460580" in str(errors[0])
    assert header_store.load("mainnet", _table(START), path=path).chain.top == TOP  # type: ignore[union-attr]


def test_the_store_is_append_only(tmp_path) -> None:
    path = tmp_path / "mainnet.bin"
    header_store.save(_chain(START, 460575), table=_table(START), path=path)
    with pytest.raises(header_store.AppendOnlyRefusal, match="already reaches block 460575"):
        header_store.save(_chain(START, 460570), table=_table(START), path=path)
    assert header_store.load("mainnet", _table(START), path=path).chain.top == 460575  # type: ignore[union-attr]
    header_store.save(_chain(START, TOP), table=_table(START), path=path)  # honest: extending
    assert header_store.load("mainnet", _table(START), path=path).chain.top == TOP  # type: ignore[union-attr]


# ── pyrxd headers sync ──────────────────────────────────────────────────────────────────────


def _headers_reply(headers: dict[int, bytes], start: int, count: int) -> dict:
    out = []
    h = start
    while h in headers and len(out) < count:
        out.append(headers[h])
        h += 1
    return {"count": len(out), "hex": b"".join(out).hex(), "max": 2016}


def _operator(tip: int, headers: dict[int, bytes] | None = None, *, fail: str | None = None) -> ElectrumXClient:
    """A real client whose transport serves *headers* and reports *tip*."""
    served = dict(HEADERS if headers is None else headers)
    client = ElectrumXClient([LABEL])

    async def _call(method: str, params: list) -> Any:
        if fail and method in fail:
            raise NetworkError("the operator is down")
        if method == "blockchain.headers.subscribe":
            return {"height": tip, "hex": served[max(served)].hex()}
        if method == "blockchain.block.headers":
            return _headers_reply(served, *params)
        if method == "blockchain.block.header":
            return served[params[0]].hex()
        raise AssertionError(f"unexpected RPC {method}")

    async def _connected() -> None:
        return None

    client._call = _call  # type: ignore[method-assign]
    client._ensure_connected = _connected  # type: ignore[method-assign]
    return client


def _sync(monkeypatch, tmp_path, operators: dict[str, ElectrumXClient], *, json_out: bool = True):
    sources = [headers_cmds.OperatorSource(k, c) for k, c in operators.items()]
    monkeypatch.setattr(headers_cmds, "operator_sources", lambda ctx: sources)
    head = ["--wallet", str(tmp_path / "w.dat"), "--config", str(tmp_path / "c.toml")]
    r = CliRunner().invoke(cli, [*head, *(["--json"] if json_out else []), "headers", "sync"])
    return r, (json.loads(r.output) if json_out and r.output.strip().startswith("{") else None)


def _cached(cp: int) -> VerifiedHeaders | None:
    return header_store.load("mainnet", _table(cp)).chain


DEEP = TOP + CACHE_MIN_DEPTH  # a tip that puts every fixture header exactly 288 or more below it


def test_two_operators_agreeing_extend_the_cache(monkeypatch, tmp_path) -> None:
    _patch_table(monkeypatch, START)
    r, out = _sync(monkeypatch, tmp_path, {"operator:a": _operator(DEEP), "operator:b": _operator(DEEP + 5)})
    assert r.exit_code == 0, r.output
    assert out["state"] == "synced" and out["added"] == TOP - START
    assert (out["cached_from"], out["cached_to"], out["lowest_tip"]) == (START, TOP, DEEP)
    assert out["operators"] == ["operator:a", "operator:b"]
    assert out["verify_reach"] == TOP + MAX_HEADERS_FROM_CHECKPOINT
    cached = _cached(START)
    assert cached is not None and cached.headers == tuple(HEADERS[h] for h in range(START, TOP + 1))
    # Again: nothing new, nothing rewritten.
    r2, out2 = _sync(monkeypatch, tmp_path, {"operator:a": _operator(DEEP), "operator:b": _operator(DEEP)})
    assert r2.exit_code == 0 and out2["state"] == "up to date" and out2["added"] == 0


def test_one_operator_is_refused_and_nothing_is_written(monkeypatch, tmp_path) -> None:
    _patch_table(monkeypatch, START)
    for json_out in (True, False):
        r, out = _sync(monkeypatch, tmp_path, {"operator:a": _operator(DEEP)}, json_out=json_out)
        assert r.exit_code == 2, r.output
        assert "need at least 2 different operators" in " ".join(r.output.split())
        if out:
            assert out["state"] == "refused" and out["added"] == 0
    assert _cached(START) is None


def test_an_unreachable_second_operator_is_refused(monkeypatch, tmp_path) -> None:
    _patch_table(monkeypatch, START)
    down = _operator(DEEP, fail="blockchain.headers.subscribe")
    r, out = _sync(monkeypatch, tmp_path, {"operator:a": _operator(DEEP), "operator:b": down})
    assert r.exit_code == 2 and out["state"] == "refused"
    assert "operator:b" in out["unreachable"] and "reached 1 (operator:a) of 2" in out["reason"]
    assert _cached(START) is None


def test_headers_shallower_than_288_below_the_lowest_tip_are_not_cached(monkeypatch, tmp_path) -> None:
    _patch_table(monkeypatch, START)
    # The LOWEST tip decides: one operator a block short leaves the top header 287 deep.
    r, out = _sync(monkeypatch, tmp_path, {"operator:a": _operator(DEEP + 50), "operator:b": _operator(DEEP - 1)})
    assert r.exit_code == 0, r.output
    assert out["cached_to"] == TOP - 1 and out["lowest_tip"] == DEEP - 1
    # Honest pair: at exactly 288 deep it is cached.
    r, out = _sync(monkeypatch, tmp_path, {"operator:a": _operator(DEEP), "operator:b": _operator(DEEP)})
    assert out["cached_to"] == TOP and out["added"] == 1


def test_nothing_deep_enough_is_up_to_date_not_an_error(monkeypatch, tmp_path) -> None:
    _patch_table(monkeypatch, START)
    r, out = _sync(monkeypatch, tmp_path, {"operator:a": _operator(START + 100), "operator:b": _operator(START + 100)})
    assert r.exit_code == 0 and out["state"] == "up to date" and out["added"] == 0
    assert "at least 288 blocks below the lowest tip" in out["reason"]
    assert _cached(START) is None


def _lie(at: int, header: bytes) -> dict[int, bytes]:
    served = dict(HEADERS)
    served[at] = header
    return served


@pytest.mark.parametrize(
    ("case", "served", "why"),
    [
        ("a_broken_link", _lie(460570, HEADERS[460571]), "does not link"),
        ("a_failed_proof_of_work", _lie(460570, _renonced(HEADERS[460570])), "fails its own proof-of-work"),
    ],
)
def test_a_lie_both_operators_serve_is_refused(monkeypatch, tmp_path, case: str, served, why: str) -> None:
    """Byte-identical agreement is not enough: what they agree on must link and carry its work."""
    _patch_table(monkeypatch, START)
    r, out = _sync(
        monkeypatch, tmp_path, {"operator:a": _operator(DEEP, served), "operator:b": _operator(DEEP, served)}
    )
    assert r.exit_code == 2 and out["state"] == "refused" and why in out["reason"]
    assert _cached(START) is None, "nothing is written, not even the agreed headers below the lie"


def test_operators_that_disagree_are_refused(monkeypatch, tmp_path) -> None:
    _patch_table(monkeypatch, START)
    other = _lie(460575, _renonced(HEADERS[460575]))
    r, out = _sync(monkeypatch, tmp_path, {"operator:a": _operator(DEEP), "operator:b": _operator(DEEP, other)})
    assert r.exit_code == 2 and out["state"] == "refused"
    assert "disagree on the header at block 460575" in out["reason"]
    assert _cached(START) is None


def test_a_header_below_the_floor_ends_the_sync_and_keeps_what_is_under_it(monkeypatch, tmp_path) -> None:
    """An honest difficulty drop is not a lie: the agreed headers below it are cached, and why it
    stopped is said. (Divisor 1: see the module docstring.) 460,575's work is the floor; 460,576
    and 460,577 carry more, 460,578 less."""
    monkeypatch.setattr(mark_block, "FLOOR_WORK_DIVISOR", 1)
    _patch_table(monkeypatch, 460575)
    r, out = _sync(monkeypatch, tmp_path, {"operator:a": _operator(DEEP), "operator:b": _operator(DEEP)})
    assert r.exit_code == 6, r.output
    assert out["state"] == "stopped" and out["cached_to"] == 460577 and out["added"] == 2
    assert "the header at 460578 carries less work than the floor" in out["stopped"]
    assert _cached(460575).top == 460577, "the headers below the stop are written"  # type: ignore[union-attr]


# ── a sync spanning more than one request ───────────────────────────────────────────────────


def test_a_lie_in_the_second_request_writes_nothing(monkeypatch, tmp_path) -> None:
    _patch_table(monkeypatch, START)
    monkeypatch.setattr(headers_cmds, "MAX_HEADERS_PER_REQUEST", 4)
    served = _lie(460570, _renonced(HEADERS[460570]))  # the 6th header: in the second request
    ops = {"operator:a": _operator(DEEP, served), "operator:b": _operator(DEEP, served)}
    r, out = _sync(monkeypatch, tmp_path, ops)
    assert r.exit_code == 2 and out["state"] == "refused" and "fails its own proof-of-work" in out["reason"]
    assert _cached(START) is None, "the first request's agreed headers are not written either"
    # Honest pair: the same requests from honest servers cache everything.
    r, out = _sync(monkeypatch, tmp_path, {"operator:a": _operator(DEEP), "operator:b": _operator(DEEP)})
    assert r.exit_code == 0 and out["cached_to"] == TOP


def test_a_floor_stop_in_the_second_request_keeps_the_first(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(mark_block, "FLOOR_WORK_DIVISOR", 1)
    monkeypatch.setattr(headers_cmds, "MAX_HEADERS_PER_REQUEST", 2)
    _patch_table(monkeypatch, 460575)
    r, out = _sync(monkeypatch, tmp_path, {"operator:a": _operator(DEEP), "operator:b": _operator(DEEP)})
    assert r.exit_code == 6 and out["state"] == "stopped" and out["cached_to"] == 460577
    assert _cached(460575).top == 460577  # type: ignore[union-attr]


def test_two_servers_of_one_operator_are_one_operator(tmp_path) -> None:
    """The grouping is the one every source count uses: radiant4people's two servers are one
    operator, so a config naming only them cannot sync. A second operator makes two."""
    from pyrxd.cli import config as cfg_mod

    def sources(servers: list[str]) -> list[str]:
        path = tmp_path / "c.toml"
        path.write_text("electrumx_servers = [" + ", ".join(f'"{u}"' for u in servers) + "]\n", encoding="utf-8")
        cfg = cfg_mod.load(path).for_network("mainnet")
        return [s.key for s in headers_cmds.operator_sources(CliContext(config=cfg, network="mainnet"))]

    r4p = ["wss://electrumx.radiant4people.com:50022/", "wss://electrumx2.radiant4people.com:50022/"]
    assert sources(r4p) == ["operator:radiant4people"]
    assert sources([*r4p, "wss://electrumx.radiantcore.org/"]) == ["operator:radiant4people", "operator:radiantcore"]


def test_status_calls_a_store_behind_the_checkpoint_stale_not_untrusted(monkeypatch, tmp_path) -> None:
    """An ordinary upgrade moves the shipped checkpoint past the cache's top."""
    _patch_table(monkeypatch, START)
    _store(START, 460570)
    monkeypatch.setitem(radiant_checkpoints.CHECKPOINTS, "mainnet", ((START, _hash(START)), (460575, _hash(460575))))
    head = ["--wallet", str(tmp_path / "w.dat"), "--config", str(tmp_path / "c.toml")]
    out = json.loads(CliRunner().invoke(cli, [*head, "--json", "headers", "status"]).output)
    assert out["state"] == "stale" and "stale" in out["note"]
    human = CliRunner().invoke(cli, [*head, "headers", "status"]).output
    assert "STALE" in human and "UNTRUSTED" not in human and "does not verify" not in human
    # And the next sync rebuilds it from the newer checkpoint.
    r, synced = _sync(monkeypatch, tmp_path, {"operator:a": _operator(DEEP), "operator:b": _operator(DEEP)})
    assert r.exit_code == 0 and synced["cached_from"] == 460575 and synced["cached_to"] == TOP


def test_status_sanitises_what_the_store_says(monkeypatch, tmp_path) -> None:
    """The sync records are text from a file: a terminal escape in them never reaches the terminal."""
    _patch_table(monkeypatch, START)
    evil = "\x1b]8;;http://x.invalid\x07click\x1b]8;;\x07"
    header_store.save(
        _chain(START, TOP),
        table=_table(START),
        record={"utc": evil, "from": evil, "to": 1, "operators": [evil, "operator:b"]},
    )
    head = ["--wallet", str(tmp_path / "w.dat"), "--config", str(tmp_path / "c.toml")]
    human = CliRunner().invoke(cli, [*head, "headers", "status"]).output
    assert "last sync:" in human and "\x1b" not in human and "\x07" not in human
    raw = header_store.store_path("mainnet").read_bytes()
    meta, headers = decode_store(raw)
    meta["network"] = evil
    import hashlib

    blob = json.dumps(meta, sort_keys=True, separators=(",", ":")).encode()
    body = b"pyrxd-header-cache\n" + len(blob).to_bytes(4, "big") + blob + b"".join(headers)
    header_store.store_path("mainnet").write_bytes(body + hashlib.sha256(body).digest())
    human = CliRunner().invoke(cli, [*head, "headers", "status"]).output
    assert "is for" in human and "\x1b" not in human


def test_status_reports_the_cache(monkeypatch, tmp_path) -> None:
    _patch_table(monkeypatch, START)
    head = ["--wallet", str(tmp_path / "w.dat"), "--config", str(tmp_path / "c.toml"), "--json"]
    out = json.loads(CliRunner().invoke(cli, [*head, "headers", "status"]).output)
    assert out["state"] == "empty" and out["verify_reach"] == START + MAX_HEADERS_FROM_CHECKPOINT
    _sync(monkeypatch, tmp_path, {"operator:a": _operator(DEEP), "operator:b": _operator(DEEP)})
    out = json.loads(CliRunner().invoke(cli, [*head, "headers", "status"]).output)
    assert out["state"] == "ready" and out["cached_to"] == TOP
    assert out["last_sync"]["operators"] == ["operator:a", "operator:b"]
    header_store.store_path("mainnet").write_bytes(b"not a store")
    out = json.loads(CliRunner().invoke(cli, [*head, "headers", "status"]).output)
    assert out["state"] == "untrusted" and "treated as empty" in out["note"]


# ── pyrxd verify, with and without the cache ────────────────────────────────────────────────


def _mark_server(txid: str = TXID, headers: dict[int, bytes] | None = None) -> ElectrumXClient:
    """A real client serving one fixture mark and its 17 headers (the tip is the top one)."""
    fx = _FIX[txid]
    own = HEADERS if txid == TXID else HEADERS2
    served = dict(own if headers is None else headers)
    top, mark_h = max(own), fx["merkle"]["block_height"]
    client = ElectrumXClient([LABEL])

    async def _call(method: str, params: list) -> Any:
        if method == "blockchain.transaction.get":
            asked, verbose = params
            assert asked == txid
            if not verbose:
                return fx["raw_tx"]
            return {"txid": txid, "confirmations": top - mark_h + 1, "blockhash": _hash(mark_h)}
        if method == "blockchain.headers.subscribe":
            return {"height": top, "hex": own[top].hex()}
        if method == "blockchain.block.header":
            return own[params[0]].hex()
        if method == "blockchain.transaction.get_merkle":
            return copy.deepcopy(fx["merkle"])
        if method == "blockchain.transaction.id_from_pos":
            return copy.deepcopy(fx["coinbase_merkle"])
        if method == "blockchain.block.headers":
            return _headers_reply(served, *params)
        raise AssertionError(f"unexpected RPC {method}")

    async def _connected() -> None:
        return None

    client._call = _call  # type: ignore[method-assign]
    client._ensure_connected = _connected  # type: ignore[method-assign]
    return client


def _verify(monkeypatch, tmp_path, server=None, *, conf: int = 6, json_out: bool = True, txid: str = TXID):
    server = server or _mark_server(txid)
    monkeypatch.setattr(CliContext, "make_client", lambda self: server)
    monkeypatch.setattr(glyph_inspect, "_endpoint_pair", lambda ctx: (server, LABEL, server, LABEL))
    head = ["--wallet", str(tmp_path / "w.dat"), "--config", str(tmp_path / "c.toml")]
    args = [*head, *(["--json"] if json_out else []), "verify", txid, "--min-confirmations", str(conf)]
    return CliRunner().invoke(cli, args)


def _store(cp: int, top: int) -> None:
    header_store.save(_chain(cp, top), table=_table(cp))


def _flat(text: str) -> str:
    return " ".join(text.split())


def test_with_no_cache_verify_is_exactly_as_before(monkeypatch, tmp_path) -> None:
    _patch_table(monkeypatch, START)
    out = json.loads(_verify(monkeypatch, tmp_path).output)
    bv = out["mark_anchor"]["block_verification"]
    assert bv["state"] == "VERIFIED" and bv["level"] == "work" and bv["checkpoint_height"] == START
    assert bv["cached_anchor_height"] is None
    assert "a checkpoint shipped with pyrxd, through 8 header(s)" in bv["claim"]
    assert "cache" not in bv["claim"] and "cache" not in out["checks"]["block"]["reason"]
    # A damaged store is the same as none.
    header_store.store_path("mainnet").write_bytes(b"pyrxd-header-cache\n" + os.urandom(200))
    again = json.loads(_verify(monkeypatch, tmp_path).output)
    assert again["mark_anchor"]["block_verification"] == bv
    assert again["checks"] == out["checks"]


def test_a_cache_below_the_needed_range_changes_nothing(monkeypatch, tmp_path) -> None:
    """A cache that ends below the mark is used as the anchor only up to its top; one that does
    not reach above the shipped checkpoint at all is not used."""
    _patch_table(monkeypatch, TOP)  # the mark is BELOW the checkpoint: no cache can matter
    before = json.loads(_verify(monkeypatch, tmp_path).output)
    _store(TOP, TOP)
    after = json.loads(_verify(monkeypatch, tmp_path).output)
    assert after["mark_anchor"]["block_verification"] == before["mark_anchor"]["block_verification"]


def test_verify_links_from_the_newest_cached_header_and_says_so(monkeypatch, tmp_path) -> None:
    _patch_table(monkeypatch, START)
    _store(START, 460570)
    r = _verify(monkeypatch, tmp_path)
    assert r.exit_code == 0, r.output
    out = json.loads(r.output)
    bv = out["mark_anchor"]["block_verification"]
    assert bv["state"] == "VERIFIED", bv["reason"]
    assert bv["level"] == "work"
    assert (bv["cached_anchor_height"], bv["cached_anchor_hash"]) == (460570, _hash(460570))
    assert bv["checkpoint_height"] == START, "the checkpoint named is the SHIPPED one"
    claim = bv["claim"]
    assert "linked hash by hash to block 460570, a header in pyrxd's verified-header cache" in claim
    assert "through 2 header(s), each meeting its own proof-of-work target" in claim
    assert f"linked hash by hash to block {START}, a checkpoint shipped with pyrxd" in claim
    reason = out["checks"]["block"]["reason"]
    assert f"cached header 460570 (pyrxd's verified-header cache, first linked to pyrxd checkpoint {START})" in reason
    # The floor rests on the greater of the checkpoint's work and the anchor's.
    floor = max(radiant_header_work(HEADERS[START]), radiant_header_work(HEADERS[460570])) // 16
    assert bv["floor_work_log2"] == floor.bit_length() - 1


def test_a_mark_inside_the_cache_is_linked_to_a_cached_header(monkeypatch, tmp_path) -> None:
    _patch_table(monkeypatch, START)
    _store(START, TOP)
    out = json.loads(_verify(monkeypatch, tmp_path).output)
    bv = out["mark_anchor"]["block_verification"]
    assert bv["state"] == "VERIFIED", bv["reason"]
    assert bv["level"] == "checkpoint" and bv["cached_anchor_height"] == MARK_H + 5
    assert bv["verified_depth"] == 6 and dict(bv["steps"])["proof_of_work"] == "not run"
    assert "The height rests on that cache and that checkpoint, not on any server." in bv["claim"]
    reason = out["checks"]["block"]["reason"]
    assert f"linked hash by hash to cached header {MARK_H + 5}" in reason and f"checkpoint {START}" in reason


def test_a_mark_below_the_checkpoint_counts_its_depth_through_the_cache(monkeypatch, tmp_path) -> None:
    """The mark is linked to the SHIPPED checkpoint above it; only its depth runs on into the cache.
    The claim and the summary name the shipped checkpoint as the anchor, and say the depth used the
    cache."""
    _patch_table(monkeypatch, 460575)
    _store(460575, TOP)
    out = json.loads(_verify(monkeypatch, tmp_path).output)
    bv = out["mark_anchor"]["block_verification"]
    assert bv["state"] == "VERIFIED", bv["reason"]
    assert bv["level"] == "checkpoint" and bv["checkpoint_height"] == 460575
    assert bv["cached_anchor_height"] == MARK_H + 5 and bv["verified_depth"] == 6
    assert "linked hash by hash to block 460575, a checkpoint shipped with pyrxd" in bv["claim"]
    assert f"cache on this machine, which links checkpoint 460575 to block {MARK_H + 5}" in bv["claim"]
    reason = out["checks"]["block"]["reason"]
    assert "linked hash by hash to pyrxd checkpoint 460575" in reason
    assert f"depth counted on through the cached headers from block {MARK_H + 5}" in reason
    # Honest pair: without the cache, 6 confirmations need headers above the checkpoint, fetched
    # and checked for work; it verifies too, and names no cache.
    header_store.store_path("mainnet").unlink()
    bv = json.loads(_verify(monkeypatch, tmp_path).output)["mark_anchor"]["block_verification"]
    assert bv["state"] == "VERIFIED" and bv["cached_anchor_height"] is None and "cache" not in bv["claim"]


def test_the_human_report_prints_the_cached_claim_whole(monkeypatch, tmp_path) -> None:
    _patch_table(monkeypatch, START)
    _store(START, 460570)
    claim = json.loads(_verify(monkeypatch, tmp_path).output)["mark_anchor"]["caveat"]
    r = _verify(monkeypatch, tmp_path, json_out=False)
    assert r.exit_code == 0, r.output
    assert _flat(f"VERIFIED: {claim}") in _flat(r.output), "the claim is printed whole, never cut"


# ── A CACHE ON AN ABANDONED BRANCH: never CONTRADICTED ──────────────────────────────────────
#
# THE SYNTHETIC FORK. A cache left on a branch Radiant abandoned (a reorganisation deeper than its
# 288-block margin) holds a header whose proof-of-work is genuine but which the live chain no longer
# contains. No such header can be mined for a test, so the fork's tip is real block 460,570 with
# another nonce (same parent, another hash), and the CACHE's proof-of-work check alone is told to
# accept that one header, as it would accept a genuinely mined one. The SERVER's headers are the
# real chain, checked by the verifier's own, unpatched proof-of-work.

FORK_H = 460570
FORK = _renonced(HEADERS[FORK_H])


def _accept_the_fork(monkeypatch) -> None:
    real = header_cache.verify_radiant_header_pow

    def pow_(header: bytes, **kw: Any) -> str:
        return radiant_block_hash(header) if header == FORK else real(header, **kw)

    monkeypatch.setattr(header_cache, "verify_radiant_header_pow", pow_)


def _store_fork(monkeypatch) -> None:
    _accept_the_fork(monkeypatch)
    chain = _chain(START, FORK_H - 1)
    chain, stopped = extend_verified_headers(chain, [FORK])
    assert stopped is None and chain.hash_at(FORK_H) != _hash(FORK_H)
    header_store.save(chain, table=_table(START))
    assert _cached(START).top == FORK_H  # type: ignore[union-attr]


def test_a_cache_on_an_abandoned_branch_is_not_verified_never_contradicted(monkeypatch) -> None:
    """At the verifier: the server's chain disagrees with the CACHE, not with anything shipped or
    with the mark's proof, so the answer is NOT VERIFIED, naming the cached height and the fix.
    (The verifier's own proof-of-work check is not the patched one.)"""
    _accept_the_fork(monkeypatch)
    chain, _ = extend_verified_headers(_chain(START, FORK_H - 1), [FORK])
    v = mark_block.verify_mark_block(
        txid=TXID,
        raw_tx=bytes.fromhex(FX["raw_tx"]),
        height=MARK_H,
        merkle=FX["merkle"],
        coinbase_merkle=FX["coinbase_merkle"],
        headers=HEADERS,
        min_confirmations=6,
        checkpoints=_table(START),
        header_cache=chain,
    )
    assert v.state == mark_block.NOT_VERIFIED, v.reason
    assert v.cached_anchor_height == FORK_H and v.cache_disagreement
    assert f"the header served at {FORK_H} is not the one pyrxd's verified-header cache holds" in v.reason
    assert "`pyrxd headers sync --reset`" in v.reason


def test_verify_falls_back_to_the_shipped_checkpoint_when_the_cache_disagrees(monkeypatch, tmp_path) -> None:
    _patch_table(monkeypatch, START)
    _store_fork(monkeypatch)
    r = _verify(monkeypatch, tmp_path)
    assert r.exit_code == 0, r.output
    out = json.loads(r.output)
    bv = out["mark_anchor"]["block_verification"]
    assert bv["state"] == "VERIFIED", bv["reason"]
    assert bv["cached_anchor_height"] is None and bv["checkpoint_height"] == START and bv["level"] == "work"
    assert f"cache disagreed with the server at block {FORK_H}" in bv["claim"]
    assert "linked from the shipped checkpoint instead" in bv["claim"] and "--reset" in bv["claim"]
    assert bv["cache_disagreement"] and out["checks"]["block"]["state"] == "VERIFIED"
    # Honest pair: the same mark with the real chain cached verifies FROM the cache, no note.
    header_store.save(_chain(START, FORK_H), table=_table(START), reset=True)
    bv = json.loads(_verify(monkeypatch, tmp_path).output)["mark_anchor"]["block_verification"]
    assert bv["state"] == "VERIFIED" and bv["cached_anchor_height"] == FORK_H and bv["cache_disagreement"] is None


def test_a_server_that_also_contradicts_the_shipped_checkpoint_is_still_contradicted(monkeypatch, tmp_path) -> None:
    """The fallback does not launder a lie: a header that fails its own proof-of-work on the walk from
    the SHIPPED checkpoint is CONTRADICTED, as it is with no cache at all."""
    _patch_table(monkeypatch, START)
    _store(START, FORK_H)
    served = dict(HEADERS)
    served[FORK_H] = _renonced(HEADERS[FORK_H])
    r = _verify(monkeypatch, tmp_path, _mark_server(headers=served))
    assert r.exit_code == 2, r.output
    assert f"the header at {FORK_H} fails its own proof-of-work" in _flat(r.output)


def test_sync_names_the_reset_when_the_cache_is_on_another_branch(monkeypatch, tmp_path) -> None:
    _patch_table(monkeypatch, START)
    _store_fork(monkeypatch)
    ops = {"operator:a": _operator(DEEP), "operator:b": _operator(DEEP)}
    r, out = _sync(monkeypatch, tmp_path, ops)
    assert r.exit_code == 2 and out["state"] == "refused"
    assert f"does not continue from the newest cached header (block {FORK_H})" in out["reason"]
    assert "`pyrxd headers sync --reset`" in out["reason"]
    # A reset that cannot reach two operators writes nothing: the old cache is untouched.
    head = ["--wallet", str(tmp_path / "w.dat"), "--config", str(tmp_path / "c.toml"), "--json"]
    one = [headers_cmds.OperatorSource("operator:a", _operator(DEEP))]
    monkeypatch.setattr(headers_cmds, "operator_sources", lambda ctx: one)
    r = CliRunner().invoke(cli, [*head, "headers", "sync", "--reset"])
    assert r.exit_code == 2 and _cached(START).hash_at(FORK_H) != _hash(FORK_H)  # type: ignore[union-attr]
    # Honest path: the reset with two operators rebuilds the cache on the live chain.
    two = [headers_cmds.OperatorSource(k, _operator(DEEP)) for k in ("operator:a", "operator:b")]
    monkeypatch.setattr(headers_cmds, "operator_sources", lambda ctx: two)
    r = CliRunner().invoke(cli, [*head, "headers", "sync", "--reset"])
    out = json.loads(r.output)
    assert r.exit_code == 0 and out["state"] == "synced" and out["reset"] is True and out["cached_to"] == TOP
    assert _cached(START).headers == tuple(HEADERS[h] for h in range(START, TOP + 1))  # type: ignore[union-attr]


# ── THE SYNC FLOOR: raise-only, from headers already cached ─────────────────────────────────
#
# Real headers of pyrxd's mark stretch, divisor 1 (module docstring). Checkpoint 468,524 carries
# the least work of 468,524..468,526; 468,527 carries more than the checkpoint and less than the
# median of those three. A sync floor resting on the checkpoint alone accepts 468,527; one raised
# to the median of the headers ALREADY cached refuses it.

CP2 = 468524


def _sync2(monkeypatch, tmp_path, stop: int):
    tip = stop + CACHE_MIN_DEPTH
    return _sync(
        monkeypatch, tmp_path, {"operator:a": _operator(tip, HEADERS2), "operator:b": _operator(tip, HEADERS2)}
    )


def test_the_sync_floor_rises_with_the_cached_median(monkeypatch, tmp_path) -> None:
    w = {h: radiant_header_work(HEADERS2[h]) for h in range(CP2, CP2 + 4)}
    assert w[CP2] < w[CP2 + 3] < sorted([w[CP2], w[CP2 + 1], w[CP2 + 2]])[1], "the work pattern this test needs"
    monkeypatch.setattr(mark_block, "FLOOR_WORK_DIVISOR", 1)
    _patch_table(monkeypatch, CP2)
    r, out = _sync2(monkeypatch, tmp_path, CP2 + 2)
    assert r.exit_code == 0 and out["cached_to"] == CP2 + 2
    r, out = _sync2(monkeypatch, tmp_path, CP2 + 5)
    assert r.exit_code == 6, r.output
    assert out["state"] == "stopped" and out["added"] == 0 and out["cached_to"] == CP2 + 2
    assert f"the header at {CP2 + 3} carries less work than the floor" in out["stopped"]
    assert "recent cached median" in out["stopped"]
    assert f"this sync's floor was {out['floor_work']}" in out["stopped"]
    # THE ADVICE IS COMPUTED: nothing was added, so a re-run's floor is the same (exact integers),
    # and the checkpoint's floor admits 468,527, so `--reset` is what gets past it.
    assert out["advice"] == "reset" and out["next_floor_work"] == out["floor_work"]
    assert out["stopped_at"] == CP2 + 3 and out["stopped_work"] == radiant_header_work(HEADERS2[CP2 + 3])
    assert "A plain re-run would stop here again" in out["stopped"]
    assert "`pyrxd headers sync --reset` gets past it" in out["stopped"]
    # And it is true: a re-run stops at the same header with the same exact floor...
    r, again = _sync2(monkeypatch, tmp_path, CP2 + 5)
    assert r.exit_code == 6 and again["state"] == "stopped" and again["cached_to"] == CP2 + 2
    assert again["floor_work"] == out["floor_work"]
    # What the reason offers does get past it: a reset holds its first sync to the checkpoint's work.
    tip = CP2 + 5 + CACHE_MIN_DEPTH
    two = [headers_cmds.OperatorSource(k, _operator(tip, HEADERS2)) for k in ("operator:a", "operator:b")]
    monkeypatch.setattr(headers_cmds, "operator_sources", lambda ctx: two)
    head = ["--wallet", str(tmp_path / "w.dat"), "--config", str(tmp_path / "c.toml"), "--json"]
    r = CliRunner().invoke(cli, [*head, "headers", "sync", "--reset"])
    assert r.exit_code == 0 and json.loads(r.output)["cached_to"] == CP2 + 5


def test_advice_rerun_when_the_added_headers_move_the_floor(monkeypatch, tmp_path) -> None:
    """The re-run branch. The headers a stopped sync adds move the median, so a plain re-run can pass
    the header the first sync stopped at. Real headers 460,564..460,569 with a divisor of 1.0065, exact (a
    test-scale ratio; see the module docstring): the cache holds 460,564..460,566; a sync adds
    460,567 and stops at 460,568; the next floor (computed exactly, not as a power of two) admits it."""
    monkeypatch.setattr(mark_block, "FLOOR_WORK_DIVISOR", Fraction(10065, 10000))
    _patch_table(monkeypatch, START)
    ops = lambda stop: {k: _operator(stop + CACHE_MIN_DEPTH) for k in ("operator:a", "operator:b")}  # noqa: E731
    r, out = _sync(monkeypatch, tmp_path, ops(START + 2))
    assert r.exit_code == 0 and out["cached_to"] == START + 2
    r, out = _sync(monkeypatch, tmp_path, ops(TOP))
    assert r.exit_code == 6 and out["state"] == "stopped" and out["stopped_at"] == 460568, out
    assert out["added"] == 1 and out["advice"] == "rerun"
    assert out["next_floor_work"] < out["floor_work"] and out["stopped_work"] >= out["next_floor_work"]
    assert "Re-run `pyrxd headers sync`" in out["stopped"] and "--reset" not in out["stopped"]
    # And it is true: the plain re-run gets past 460,568.
    r, again = _sync(monkeypatch, tmp_path, ops(TOP))
    assert again["cached_to"] >= 460569, again


def test_advice_upgrade_when_nothing_this_release_can_use_admits_the_header(monkeypatch, tmp_path) -> None:
    """The upgrade branch. Divisor 1, checkpoint 460,566 (the most work of the stretch): 460,567 is
    below the checkpoint's own floor, so neither a re-run nor a reset can cache it."""
    monkeypatch.setattr(mark_block, "FLOOR_WORK_DIVISOR", 1)
    _patch_table(monkeypatch, 460566)
    r, out = _sync(monkeypatch, tmp_path, {"operator:a": _operator(DEEP), "operator:b": _operator(DEEP)})
    assert r.exit_code == 6 and out["state"] == "stopped" and out["advice"] == "upgrade"
    assert out["stopped_at"] == 460567 and out["stopped_work"] < out["floor_work"]
    assert "Only a newer pyrxd release can get past this header" in out["stopped"]
    assert "gets past it" not in out["stopped"] and "Re-run" not in out["stopped"]
    # And it is true: a reset stops at the same header.
    head = ["--wallet", str(tmp_path / "w.dat"), "--config", str(tmp_path / "c.toml"), "--json"]
    two = [headers_cmds.OperatorSource(k, _operator(DEEP)) for k in ("operator:a", "operator:b")]
    monkeypatch.setattr(headers_cmds, "operator_sources", lambda ctx: two)
    reset = json.loads(CliRunner().invoke(cli, [*head, "headers", "sync", "--reset"]).output)
    assert reset["state"] == "stopped" and reset["stopped_at"] == 460567 and reset["advice"] == "upgrade"


# ── a reset never destroys a longer good cache ──────────────────────────────────────────────


def _reset(monkeypatch, tmp_path, tip: int, headers: dict[int, bytes] | None = None):
    head = ["--wallet", str(tmp_path / "w.dat"), "--config", str(tmp_path / "c.toml"), "--json"]
    two = [headers_cmds.OperatorSource(k, _operator(tip, headers)) for k in ("operator:a", "operator:b")]
    monkeypatch.setattr(headers_cmds, "operator_sources", lambda ctx: two)
    r = CliRunner().invoke(cli, [*head, "headers", "sync", "--reset"])
    return r, json.loads(r.output)


def test_a_stopped_reset_keeps_the_existing_cache(monkeypatch, tmp_path) -> None:
    """The review's case: a store reaching 460,580, and a reset whose floor stops it at 460,567. The
    reset is not saved: the file on disk is byte for byte what it was. (With divisor 1 the store's
    own re-read sees only 460,566 of it, which is what the message reports; the file is untouched.)"""
    _patch_table(monkeypatch, 460566)
    _store(460566, TOP)
    before = header_store.store_path("mainnet").read_bytes()
    monkeypatch.setattr(mark_block, "FLOOR_WORK_DIVISOR", 1)
    r, out = _reset(monkeypatch, tmp_path, DEEP)
    assert r.exit_code == 6 and out["state"] == "stopped" and out["added"] == 0
    assert "was kept unchanged" in out["stopped"]
    assert header_store.store_path("mainnet").read_bytes() == before
    monkeypatch.setattr(mark_block, "FLOOR_WORK_DIVISOR", 16)
    assert _cached(460566).top == TOP  # type: ignore[union-attr]


def test_a_reset_that_agrees_and_ends_lower_keeps_the_existing_cache(monkeypatch, tmp_path) -> None:
    _patch_table(monkeypatch, START)
    _store(START, TOP)
    r, out = _reset(monkeypatch, tmp_path, 460570 + CACHE_MIN_DEPTH)
    assert r.exit_code == 0 and out["state"] == "up to date" and "the existing cache was kept" in out["reason"]
    assert out["cached_to"] == TOP and _cached(START).top == TOP  # type: ignore[union-attr]
    # Honest pair: a reset that reaches AT LEAST the top (here it ends exactly AT it, with the same
    # headers) replaces it.
    r, out = _reset(monkeypatch, tmp_path, DEEP)
    assert r.exit_code == 0 and out["state"] == "synced" and out["cached_to"] == TOP


def test_a_reset_refused_by_the_operators_keeps_the_existing_cache(monkeypatch, tmp_path) -> None:
    """Operators that serve a lie (here, a failed proof-of-work) refuse the reset; nothing is written."""
    _patch_table(monkeypatch, START)
    _store(START, TOP)
    r, out = _reset(monkeypatch, tmp_path, DEEP, _lie(460570, _renonced(HEADERS[460570])))
    assert r.exit_code == 2 and out["state"] == "refused"
    assert _cached(START).headers == tuple(HEADERS[h] for h in range(START, TOP + 1))  # type: ignore[union-attr]


def test_a_write_refusal_and_a_write_failure_say_different_things(monkeypatch, tmp_path) -> None:
    _patch_table(monkeypatch, START)
    ops = {"operator:a": _operator(DEEP), "operator:b": _operator(DEEP)}

    def raced(*a, **kw):
        raise header_store.AppendOnlyRefusal("the cache on disk already reaches block 460590, past this sync's 460580")

    monkeypatch.setattr(header_store, "save", raced)
    head = ["--wallet", str(tmp_path / "w.dat"), "--config", str(tmp_path / "c.toml")]
    sources = [headers_cmds.OperatorSource(k, c) for k, c in ops.items()]
    monkeypatch.setattr(headers_cmds, "operator_sources", lambda ctx: sources)
    r = CliRunner().invoke(cli, [*head, "headers", "sync"])
    assert r.exit_code == 1 and "another `pyrxd headers sync` wrote the cache" in _flat(r.output)
    assert "writable" not in r.output

    def full(*a, **kw):
        raise OSError("No space left on device")

    monkeypatch.setattr(header_store, "save", full)
    sources = [headers_cmds.OperatorSource(k, _operator(DEEP)) for k in ops]
    monkeypatch.setattr(headers_cmds, "operator_sources", lambda ctx: sources)
    r = CliRunner().invoke(cli, [*head, "headers", "sync"])
    assert r.exit_code == 1 and "is writable and has free space" in _flat(r.output)
    assert "another `pyrxd headers sync`" not in r.output


def test_sync_records_accumulate_on_disk(tmp_path) -> None:
    """Each save appends its record to the records read from the file under the lock."""
    path = tmp_path / "mainnet.bin"
    header_store.save(_chain(START, 460570), table=_table(START), record={"to": 460570}, path=path)
    header_store.save(_chain(START, TOP), table=_table(START), record={"to": TOP}, path=path)
    assert header_store.load("mainnet", _table(START), path=path).syncs == ({"to": 460570}, {"to": TOP})


def test_a_sync_does_not_raise_its_own_bar_one_header_per_request(monkeypatch, tmp_path) -> None:
    """The bar is fixed once per SYNC, not per request: with one header per request, recomputing it
    per request would take the median of 468,524..468,526 and refuse 468,527."""
    monkeypatch.setattr(mark_block, "FLOOR_WORK_DIVISOR", 1)
    monkeypatch.setattr(headers_cmds, "MAX_HEADERS_PER_REQUEST", 1)
    _patch_table(monkeypatch, CP2)
    r, out = _sync2(monkeypatch, tmp_path, CP2 + 5)
    assert r.exit_code == 0 and out["cached_to"] == CP2 + 5 and out["stopped"] is None


def test_a_sync_does_not_raise_its_own_bar(monkeypatch, tmp_path) -> None:
    """Honest pair: the same headers in ONE sync are held to the bar set before it began (the
    checkpoint's, as nothing else was cached), so 468,527 is cached."""
    monkeypatch.setattr(mark_block, "FLOOR_WORK_DIVISOR", 1)
    _patch_table(monkeypatch, CP2)
    r, out = _sync2(monkeypatch, tmp_path, CP2 + 5)
    assert r.exit_code == 0 and out["cached_to"] == CP2 + 5 and out["stopped"] is None


def test_the_raised_sync_floor_passes_honest_headers_at_the_real_divisor(monkeypatch, tmp_path) -> None:
    _patch_table(monkeypatch, CP2)
    _sync2(monkeypatch, tmp_path, CP2 + 2)
    r, out = _sync2(monkeypatch, tmp_path, CP2 + 5)
    assert r.exit_code == 0 and out["cached_to"] == CP2 + 5 and out["stopped"] is None


def test_the_sync_floor_is_never_below_the_checkpoints() -> None:
    chain = _chain(460566, TOP)  # every cached header carries less work than the checkpoint
    assert header_cache.sync_floor(chain) == chain.floor_work == radiant_header_work(HEADERS[460566]) // 16
    with pytest.raises(ValidationError, match="never be below"):
        extend_verified_headers(chain, [], floor=chain.floor_work - 1)


def test_the_cap_is_measured_from_the_cached_anchor() -> None:
    """The same 4,032 headers, counted from the newest cached header instead of the checkpoint."""
    table, cache = _table(START), _chain(START, TOP)
    far = START + MAX_HEADERS_FROM_CHECKPOINT + 3  # 3 past the checkpoint's reach (min_confirmations 1)
    alone = plan_block_verification(height=far, min_confirmations=1, checkpoints=table)
    assert alone.reason is not None and "needs a newer pyrxd" in alone.reason
    cached = plan_block_verification(height=far, min_confirmations=1, checkpoints=table, header_cache=cache)
    assert cached.reason is None and cached.header_ranges[0][0] == TOP
    beyond = TOP + MAX_HEADERS_FROM_CHECKPOINT + 1
    past = plan_block_verification(height=beyond, min_confirmations=1, checkpoints=table, header_cache=cache)
    assert past.reason is not None and "run `pyrxd headers sync`" in past.reason
    assert f"past the newest header in pyrxd's verified-header cache ({TOP})" in past.reason


def test_a_cache_built_against_another_table_is_a_programming_error() -> None:
    with pytest.raises(ValidationError, match="different newest checkpoint"):
        plan_block_verification(
            height=MARK_H, min_confirmations=1, checkpoints=_table(460570), header_cache=_chain(START, TOP)
        )


# ── THE FLOOR: never lowered by headers the cache supplied ──────────────────────────────────
#
# Checkpoint 460,566 carries the most work of the 17 headers; the cache holds 460,566..460,574.
# The mark (460,572) with 6 confirmations needs 460,575..460,577 above the cached anchor (460,574).
# ONE divisor, read by the cache and the verifier alike (a cache held to a looser divisor than the
# verifier is a combination production cannot have): 1.033, exact. Every cached header meets the
# checkpoint's floor under it, so the store is whole; 460,575 does not, though it meets the floor a
# rule resting on the cached anchor ALONE would set.

_ANCHOR_D = Fraction(1033, 1000)


def test_a_cached_anchor_does_not_lower_the_floor(monkeypatch, tmp_path) -> None:
    w = {h: radiant_header_work(HEADERS[h]) for h in range(460566, 460578)}
    cp_floor, anchor_floor = int(w[460566] // _ANCHOR_D), int(w[460574] // _ANCHOR_D)
    assert all(w[h] >= cp_floor for h in range(460567, 460575)), "the cache can hold 460,567..460,574"
    assert anchor_floor <= w[460575] < cp_floor, "the anchor-only floor would admit 460,575; the rule's does not"
    monkeypatch.setattr(mark_block, "FLOOR_WORK_DIVISOR", _ANCHOR_D)
    _patch_table(monkeypatch, 460566)
    _store(460566, 460574)
    assert _cached(460566).top == 460574, "the store re-reads whole under the same divisor"  # type: ignore[union-attr]
    out = json.loads(_verify(monkeypatch, tmp_path).output)
    bv = out["mark_anchor"]["block_verification"]
    assert bv["cached_anchor_height"] == 460574
    assert bv["state"] == "NOT VERIFIED", bv["claim"]
    assert dict(bv["steps"])["floor"] == "failed"
    assert "the header at 460575 carries less work than the floor" in bv["reason"]
    assert "the greater of checkpoint 460566's and cached header 460574's" in bv["reason"]
    assert out["mark_anchor"]["height_is_verified"] is False
    # Honest pair: at the shipped divisor the same store verifies from the same cached anchor.
    monkeypatch.setattr(mark_block, "FLOOR_WORK_DIVISOR", 16)
    bv = json.loads(_verify(monkeypatch, tmp_path).output)["mark_anchor"]["block_verification"]
    assert bv["state"] == "VERIFIED" and bv["cached_anchor_height"] == 460574, bv["reason"]


def test_the_same_cached_anchor_verifies_at_the_real_floor(monkeypatch, tmp_path) -> None:
    """Honest pair: at the shipped divisor the same chain verifies from the same cached anchor."""
    _patch_table(monkeypatch, 460566)
    _store(460566, 460575)
    bv = json.loads(_verify(monkeypatch, tmp_path).output)["mark_anchor"]["block_verification"]
    assert bv["state"] == "VERIFIED", bv["reason"]
    assert bv["cached_anchor_height"] == 460575 and bv["checkpoint_height"] == 460566


def test_a_cached_anchor_with_more_work_raises_the_floor(monkeypatch, tmp_path) -> None:
    """The other direction is allowed, and pinned: a cached anchor carrying MORE work than the
    checkpoint raises the bar. pyrxd's own mark (468,521) with 7 confirmations needs up to 468,527.
    Checkpoint 468,524; the cache holds 468,524..468,525, which carries more work; 468,526 carries
    more than both, and 468,527 more than the checkpoint and less than the cached anchor. With
    divisor 1, a floor resting on the checkpoint alone would pass 468,527; this one refuses it."""
    w = {h: radiant_header_work(HEADERS2[h]) for h in (468524, 468525, 468526, 468527)}
    assert w[468524] < w[468527] < w[468525] < w[468526], "the work pattern this test needs"
    monkeypatch.setattr(mark_block, "FLOOR_WORK_DIVISOR", 1)  # one source: the cache's and the verifier's
    _patch_table(monkeypatch, 468524)
    _store(468524, 468525)
    bv = json.loads(_verify(monkeypatch, tmp_path, conf=7, txid=TXID2).output)["mark_anchor"]["block_verification"]
    assert bv["cached_anchor_height"] == 468525
    assert bv["state"] == "NOT VERIFIED" and "the header at 468527 carries less work than the floor" in bv["reason"]
    # Honest pair: at the shipped divisor it verifies, from the same cached anchor.
    monkeypatch.setattr(mark_block, "FLOOR_WORK_DIVISOR", 16)
    bv = json.loads(_verify(monkeypatch, tmp_path, conf=7, txid=TXID2).output)["mark_anchor"]["block_verification"]
    assert bv["state"] == "VERIFIED", bv["reason"]
    assert bv["cached_anchor_height"] == 468525


def _steering_server() -> ElectrumXClient:
    """pyrxd's mark served honestly, EXCEPT that the header range starting at the cached anchor
    (468,525) begins with that block re-nonced: just enough to make the cache disagree."""
    server = _mark_server(TXID2)
    honest = server._call
    asked: list[tuple[int, int]] = []

    async def steer(method: str, params: list) -> Any:
        reply = await honest(method, params)
        if method == "blockchain.block.headers":
            asked.append((params[0], params[1]))
            if params[0] == 468525:
                first = bytes.fromhex(reply["hex"][:160])
                reply = dict(reply, hex=_renonced(first).hex() + reply["hex"][160:])
        return reply

    server._call = steer  # type: ignore[method-assign]
    server.asked = asked  # type: ignore[attr-defined]
    return server


def test_a_server_cannot_switch_the_cache_off_to_get_a_lower_floor(monkeypatch, tmp_path) -> None:
    """Regression (hostile review A1): a server that makes the cache disagree must not get the
    fallback's checkpoint-only floor where an honest server is held to the cached anchor's.
    Setup as in the test above: an honest server gets NOT VERIFIED (468,527 below the floor)."""
    monkeypatch.setattr(mark_block, "FLOOR_WORK_DIVISOR", 1)  # one source: the cache's and the verifier's
    _patch_table(monkeypatch, 468524)
    _store(468524, 468525)
    honest = json.loads(_verify(monkeypatch, tmp_path, conf=7, txid=TXID2).output)["mark_anchor"]
    assert honest["block_verification"]["state"] == "NOT VERIFIED"
    server = _steering_server()
    r = _verify(monkeypatch, tmp_path, server, conf=7, txid=TXID2)
    bv = json.loads(r.output)["mark_anchor"]["block_verification"]
    assert (468525, 3) in server.asked and (468524, 4) in server.asked, "the fallback walk did run"  # type: ignore[attr-defined]
    assert bv["cache_disagreement"], "the cache did disagree"
    assert bv["state"] == "NOT VERIFIED", bv["claim"]
    assert "the header at 468527 carries less work than the floor" in bv["reason"]
    assert "cached header 468525's, which this walk did not anchor at" in bv["reason"]
    # Honest pair: at the shipped divisor the steered fallback still verifies, from the checkpoint.
    monkeypatch.setattr(mark_block, "FLOOR_WORK_DIVISOR", 16)
    bv = json.loads(_verify(monkeypatch, tmp_path, _steering_server(), conf=7, txid=TXID2).output)["mark_anchor"][
        "block_verification"
    ]
    assert bv["state"] == "VERIFIED" and bv["cache_disagreement"] and bv["cached_anchor_height"] is None


def test_a_float_divisor_is_refused() -> None:
    """``int(W // 16.0)`` is inexact on real work; the floor refuses a float divisor outright."""
    mp = pytest.MonkeyPatch()
    try:
        mp.setattr(mark_block, "FLOOR_WORK_DIVISOR", 16.0)
        with pytest.raises(ValidationError, match="positive int"):
            header_cache.sync_floor(_chain(START, START))
    finally:
        mp.undo()
    w = radiant_header_work(HEADERS[START])
    assert header_cache._floor_of(w) == w // 16


def test_following_the_advice_never_loops(monkeypatch, tmp_path) -> None:
    """The review's advice loop: checkpoint 460,564, divisor 1.004 (exact), cache to 460,566. A sync
    stops at 460,567 and advises `--reset`; the reset passes 460,567 and stops at 460,568, and is
    SAVED, because it agrees with the cache and extends it; its advice is then computed from that
    saved cache. Following every piece of advice ends, and no step repeats."""
    monkeypatch.setattr(mark_block, "FLOOR_WORK_DIVISOR", Fraction(1004, 1000))
    _patch_table(monkeypatch, START)
    ops = lambda stop: {k: _operator(stop + CACHE_MIN_DEPTH) for k in ("operator:a", "operator:b")}  # noqa: E731
    _, out = _sync(monkeypatch, tmp_path, ops(START + 2))
    assert out["cached_to"] == START + 2
    _, out = _sync(monkeypatch, tmp_path, ops(TOP))
    assert (out["stopped_at"], out["advice"]) == (460567, "reset"), out
    seen, steps = set(), []
    for _ in range(6):
        if out["advice"] == "reset":
            _, out = _reset(monkeypatch, tmp_path, DEEP)
        elif out["advice"] == "rerun":
            _, out = _sync(monkeypatch, tmp_path, ops(TOP))
        else:
            break
        step = (out["state"], out["stopped_at"], out["advice"], out["cached_to"])
        assert step not in seen, f"the advice loops: {[*steps, step]}"
        seen.add(step)
        steps.append(step)
    assert steps[0] == ("stopped", 460568, "upgrade", 460567), steps
    assert _cached(START).top == 460567, "the stopped reset was saved: it extends the cache"  # type: ignore[union-attr]
    # And the upgrade advice holds: a plain sync stops at 460,568 again.
    _, out = _sync(monkeypatch, tmp_path, ops(TOP))
    assert (out["stopped_at"], out["advice"]) == (460568, "upgrade"), out


def test_a_failed_save_withdraws_the_advice(monkeypatch, tmp_path) -> None:
    """A stopped sync that added headers but could not write them gives no advice: its premise
    (the cache it would have left) is not on disk."""
    monkeypatch.setattr(mark_block, "FLOOR_WORK_DIVISOR", Fraction(10065, 10000))
    _patch_table(monkeypatch, START)
    ops = lambda stop: {k: _operator(stop + CACHE_MIN_DEPTH) for k in ("operator:a", "operator:b")}  # noqa: E731
    _sync(monkeypatch, tmp_path, ops(START + 2))

    def full(*a, **kw):
        raise OSError("No space left on device")

    monkeypatch.setattr(header_store, "save", full)
    r, out = _sync(monkeypatch, tmp_path, ops(TOP))
    assert r.exit_code == 1 and out["state"] == "refused"
    assert out["advice"] is None and out["next_floor_work"] is None
    assert "Re-run" not in (out["stopped"] or "") and out["cached_to"] == START + 2


# ── the fork clause of the reset rule ───────────────────────────────────────────────────────
#
# A store on another branch from 460,568 up: real 460,564..460,567, then three headers that link to
# each other but not to the real chain (460,568 re-nonced; 460,569 and 460,570 re-pointed at the one
# below). Only the CACHE's proof-of-work check is told to accept those three, as for FORK above.


def _fork_branch() -> list[bytes]:
    f1 = _renonced(HEADERS[460568])
    f2 = bytearray(HEADERS[460569])
    f2[4:36] = bytes.fromhex(radiant_block_hash(f1))[::-1]
    f3 = bytearray(HEADERS[460570])
    f3[4:36] = bytes.fromhex(radiant_block_hash(bytes(f2)))[::-1]
    return [f1, bytes(f2), bytes(f3)]


def _store_long_fork(monkeypatch) -> None:
    branch = _fork_branch()
    real = header_cache.verify_radiant_header_pow
    monkeypatch.setattr(
        header_cache,
        "verify_radiant_header_pow",
        lambda h, **kw: radiant_block_hash(h) if h in branch else real(h, **kw),
    )
    chain, stopped = extend_verified_headers(_chain(START, 460567), branch)
    assert stopped is None and chain.top == 460570
    header_store.save(chain, table=_table(START))


def test_a_completed_reset_that_disagrees_replaces_a_longer_store(monkeypatch, tmp_path) -> None:
    """The fork clause: the rebuild ends at 460,569, BELOW the store's top (460,570), but disagrees
    with it at 460,568, so it replaces it."""
    _patch_table(monkeypatch, START)
    _store_long_fork(monkeypatch)
    r, out = _reset(monkeypatch, tmp_path, 460569 + CACHE_MIN_DEPTH)
    assert r.exit_code == 0 and out["state"] == "synced", out
    assert _cached(START).headers == tuple(HEADERS[h] for h in range(START, 460570))  # type: ignore[union-attr]


def test_a_completed_reset_that_agrees_and_is_shorter_does_not_replace(monkeypatch, tmp_path) -> None:
    """The inverse: the same shape of rebuild (ending below the store's top) that AGREES with it
    keeps it; only disagreement licenses replacing a longer store."""
    _patch_table(monkeypatch, START)
    _store(START, 460570)
    before = header_store.store_path("mainnet").read_bytes()
    r, out = _reset(monkeypatch, tmp_path, 460569 + CACHE_MIN_DEPTH)
    assert r.exit_code == 0 and out["state"] == "up to date" and "kept" in out["reason"]
    assert header_store.store_path("mainnet").read_bytes() == before


def test_a_stopped_reset_that_disagrees_and_reaches_past_the_top_replaces_the_store(monkeypatch, tmp_path) -> None:
    """A store on an abandoned branch (real 460,564..460,567, then two branch headers to 460,569),
    and a reset that stops at 460,571, past the store's top: it is written, though it disagrees,
    so the user is not left on the abandoned branch. Divisor 1.015 (exact), so the reset's floor
    (the checkpoint's alone) admits 460,570 and not 460,571."""
    monkeypatch.setattr(mark_block, "FLOOR_WORK_DIVISOR", Fraction(1015, 1000))
    _patch_table(monkeypatch, START)
    branch = _fork_branch()[:2]
    real = header_cache.verify_radiant_header_pow
    monkeypatch.setattr(
        header_cache,
        "verify_radiant_header_pow",
        lambda h, **kw: radiant_block_hash(h) if h in branch else real(h, **kw),
    )
    chain, stopped = extend_verified_headers(_chain(START, 460567), branch)
    assert stopped is None and chain.top == 460569
    header_store.save(chain, table=_table(START))
    r, out = _reset(monkeypatch, tmp_path, DEEP)
    assert r.exit_code == 6 and out["state"] == "stopped" and out["stopped_at"] == 460571, out
    assert out["cached_to"] == 460570 and "kept unchanged" not in out["stopped"]
    assert out["advice"] in ("rerun", "reset", "upgrade") and out["next_floor_work"] is not None
    saved = header_store.load("mainnet", _table(START))
    assert saved.chain.headers == tuple(HEADERS[h] for h in range(START, 460571))  # type: ignore[union-attr]
    assert saved.syncs[-1].get("reset") is True, "the record of a written stopped reset keeps the flag"


def _branch_chain(monkeypatch) -> VerifiedHeaders:
    """A verified chain START..460,570 on the branch of :func:`_fork_branch` (it leaves the real
    chain at 460,568). Only the cache's proof-of-work check is told to accept the branch headers."""
    branch = _fork_branch()
    real = header_cache.verify_radiant_header_pow
    monkeypatch.setattr(
        header_cache,
        "verify_radiant_header_pow",
        lambda h, **kw: radiant_block_hash(h) if h in branch else real(h, **kw),
    )
    chain, stopped = extend_verified_headers(_chain(START, 460567), branch)
    assert stopped is None and chain.top == 460570 and chain.header_at(460568) != HEADERS[460568]
    return chain


def test_a_plain_save_of_another_branch_is_refused_and_the_store_is_unchanged(monkeypatch, tmp_path) -> None:
    """The append-only rule's "different header" clause, on its own: the branch chain reaches PAST
    the store's top (460,569 -> 460,570), so only that clause can refuse it."""
    path = tmp_path / "mainnet.bin"
    header_store.save(_chain(START, 460569), table=_table(START), record={"to": 460569}, path=path)
    before = path.read_bytes()
    branch = _branch_chain(monkeypatch)
    assert branch.top > 460569, "longer than the store: the shorter-chain clause cannot be what refuses it"
    with pytest.raises(header_store.AppendOnlyRefusal, match="holds a different header at block 460568"):
        header_store.save(branch, table=_table(START), record={"to": 460570}, path=path)
    assert path.read_bytes() == before, "the store is byte for byte what it was"
    # The reset path, per the module docstring: a completed rebuild that disagrees replaces it.
    header_store.save(branch, table=_table(START), record={"to": 460570, "reset": True}, path=path, reset=True)
    got = header_store.load("mainnet", _table(START), path=path)
    assert got.chain is not None and got.chain.headers == branch.headers
    assert got.syncs == ({"to": 460569}, {"to": 460570, "reset": True})


def test_a_reset_save_keeps_a_store_it_would_only_shorten(tmp_path) -> None:
    """``save(reset=True)``'s two ResetKeptExisting cases, at the store: a rebuild that AGREES and
    ends below the top, and a STOPPED rebuild (``past_top_only``) that does not reach past it. Each
    leaves the file byte for byte unchanged; a rebuild reaching at least the top is written."""
    path = tmp_path / "mainnet.bin"
    header_store.save(_chain(START, 460575), table=_table(START), path=path)
    before = path.read_bytes()
    with pytest.raises(header_store.ResetKeptExisting, match="agrees with the existing cache"):
        header_store.save(_chain(START, 460570), table=_table(START), path=path, reset=True)
    assert path.read_bytes() == before
    with pytest.raises(header_store.ResetKeptExisting, match="not past the existing cache's top"):
        header_store.save(_chain(START, 460575), table=_table(START), path=path, reset=True, past_top_only=True)
    assert path.read_bytes() == before
    # Honest pair: a stopped rebuild reaching past the top is written.
    header_store.save(_chain(START, TOP), table=_table(START), path=path, reset=True, past_top_only=True)
    assert header_store.load("mainnet", _table(START), path=path).chain.top == TOP  # type: ignore[union-attr]


# ── a store whose metadata is hostile JSON ───────────────────────────────────────────────────


def _store_bytes(blob: bytes, headers: Sequence[bytes] = ()) -> bytes:
    """Store bytes with *blob* as the metadata and a CORRECT checksum: past every shape check that
    runs before the metadata is parsed."""
    import hashlib

    body = b"pyrxd-header-cache\n" + len(blob).to_bytes(4, "big") + blob + b"".join(headers)
    return body + hashlib.sha256(body).digest()


def _deep_metadata() -> dict[str, bytes]:
    deep = "[" * 100_000 + "]" * 100_000
    good, _ = decode_store(encode_store(_chain(START, TOP)))
    within = json.dumps({**good, "syncs": ["@"]}, sort_keys=True).replace('"@"', deep)
    # Shallow enough to parse, and still deeper than any record pyrxd writes (records are flat).
    shallow = json.dumps({**good, "syncs": [{"x": "@"}]}, sort_keys=True).replace('"@"', "[" * 40 + "]" * 40)
    return {
        "the_whole_metadata": deep.encode(),
        "inside_the_sync_records": within.encode(),
        "nested_deeper_than_any_record_pyrxd_writes": shallow.encode(),
    }


@pytest.mark.parametrize("case", list(_deep_metadata()), ids=list(_deep_metadata()))
def test_deeply_nested_metadata_is_a_damaged_store_not_a_crash(monkeypatch, tmp_path, case: str) -> None:
    """A valid checksum over metadata nested 100,000 deep made ``json.loads`` raise RecursionError
    through ``load()``, crashing ``pyrxd verify`` and ``pyrxd headers status``/``sync``, and
    ``sync --reset`` could not repair it. It is a damaged store: treated as empty, and replaced."""
    headers = [HEADERS[h] for h in range(START, TOP + 1)]
    data = _store_bytes(_deep_metadata()[case], headers)
    with pytest.raises(header_cache.HeaderStoreCorrupt):
        decode_store(data)
    _patch_table(monkeypatch, START)
    path = header_store.store_path("mainnet")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    got = header_store.load("mainnet", _table(START))
    assert got.chain is None and got.untrusted and "is damaged" in (got.note or "")
    head = ["--wallet", str(tmp_path / "w.dat"), "--config", str(tmp_path / "c.toml")]
    status = CliRunner().invoke(cli, [*head, "--json", "headers", "status"])
    assert status.exit_code == 0, status.output
    assert json.loads(status.output)["state"] == "untrusted"
    human = CliRunner().invoke(cli, [*head, "headers", "status"])
    assert human.exit_code == 0 and "UNTRUSTED" in human.output, human.output
    # `pyrxd verify` runs as with no cache.
    bv = json.loads(_verify(monkeypatch, tmp_path).output)["mark_anchor"]["block_verification"]
    assert bv["state"] == "VERIFIED" and bv["cached_anchor_height"] is None
    # And `pyrxd headers sync --reset` replaces it.
    r, out = _reset(monkeypatch, tmp_path, DEEP)
    assert r.exit_code == 0 and out["state"] == "synced" and out["cached_to"] == TOP, out
    assert _cached(START).headers == tuple(headers)  # type: ignore[union-attr]
