"""``pyrxd.glyph.mark_block``: verifying a HashMark's block from real data, and refusing lies.

REAL DATA. Both marks are real mainnet transactions — Craig's at block 460,572
(``a1a86ab4…5916``) and pyrxd's at 468,521 (``aa66b046…c86e``) — with the merkle replies, raw
transactions and 17 linked headers around each, saved verbatim from both shipped ElectrumX servers
(which returned identical data): ``tests/fixtures/mark_block_fixtures_2026-09-30.json``.

TEST CHECKPOINTS. Most tests inject a checkpoint table through ``checkpoints=`` built from a
fixture header's own hash, so they exercise both levels on 17 headers rather than on the ~1,100
and ~2,800 the shipped table would need. The shipped table is exercised by the tests that pass
``checkpoints=None`` (its default path, its over-cap refusal, a network it has no entries for).
With the shipped table, both marks were verified live on 2026-09-30 against both servers — that
run is not repeatable offline and is recorded in the PR, not here.

THE LYING SERVER. Each lie is a well-formed reply a hostile endpoint could send. The cheapest
forgery — a block MINED at trivial difficulty that moves the mark to another height — uses a header
mined for this file (nBits ``1d7fffff``, the easiest target ``Nbits`` accepts: about 2^25 expected
hashes, under a second on a desktop) on top of real block 460,580. Its proof-of-work is genuine;
only the floor stops it.
"""

from __future__ import annotations

import hashlib
import inspect
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from pyrxd.glyph import mark_block
from pyrxd.glyph.mark_block import (
    CONTRADICTED,
    FLOOR_WORK_DIVISOR,
    MAX_HEADERS_FROM_CHECKPOINT,
    NOT_VERIFIED,
    VERIFIED,
    BlockVerification,
    plan_block_verification,
    verify_mark_block,
)
from pyrxd.hash import radiant_block_hash
from pyrxd.security.errors import ValidationError
from pyrxd.spv.radiant import TxMerkleBranch, radiant_header_work, verify_radiant_header_pow
from pyrxd.spv.radiant_checkpoints import CHECKPOINTS

ROOT = Path(__file__).resolve().parent.parent
_FIX = json.loads((ROOT / "tests/fixtures/mark_block_fixtures_2026-09-30.json").read_text(encoding="utf-8"))["fixtures"]

CRAIG = "a1a86ab4503901af4df3d092fcf668b07c03c5cd89240fe918ae70e02e045916"
PYRXD = "aa66b04662aa5514ed7d0027ff3cbd608d73f3e2b92d4129d810eb576bc0c86e"


def _d256(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


class Mark:
    """One real fixture: its tx, merkle reply and headers, plus helpers to build calls."""

    def __init__(self, txid: str) -> None:
        fx = _FIX[txid]
        self.txid = txid
        self.raw_tx = bytes.fromhex(fx["raw_tx"])
        self.merkle = dict(fx["merkle"])
        self.height = fx["merkle"]["block_height"]
        raw = bytes.fromhex(fx["headers_hex"])
        self.start = fx["headers_start"]
        self.headers = {self.start + i: raw[i * 80 : (i + 1) * 80] for i in range(len(raw) // 80)}
        self.top = max(self.headers)

    def cp(self, h: int) -> list[tuple[int, str]]:
        return [(h, radiant_block_hash(self.headers[h]))]

    def run(self, checkpoints: Any, **over: Any) -> BlockVerification:
        kw: dict[str, Any] = {
            "txid": self.txid,
            "raw_tx": self.raw_tx,
            "height": self.height,
            "merkle": self.merkle,
            "headers": self.headers,
            "min_confirmations": 1,
            "blockhash": radiant_block_hash(self.headers[self.height]),
            "checkpoints": checkpoints,
        }
        kw.update(over)
        return verify_mark_block(**kw)


MARKS = {"craig_460572": Mark(CRAIG), "pyrxd_468521": Mark(PYRXD)}
BOTH = pytest.mark.parametrize("m", list(MARKS.values()), ids=list(MARKS))
C = MARKS["craig_460572"]


def _step(v: BlockVerification, name: str) -> str:
    return dict(v.steps)[name]


# ── honest paths ─────────────────────────────────────────────────────────────────────────────


def test_both_real_marks_are_here() -> None:
    assert (MARKS["craig_460572"].height, MARKS["pyrxd_468521"].height) == (460572, 468521)
    for m in MARKS.values():
        assert m.top - m.height == 8 and m.height - m.start == 8


@BOTH
def test_at_or_below_a_checkpoint_the_block_is_verified_by_linkage(m: Mark) -> None:
    v = m.run(m.cp(m.top))
    assert v.state == VERIFIED, v.reason
    assert v.level == "checkpoint"
    assert v.linked_headers == 9
    assert v.checkpoint_height == m.top
    assert v.blockhash == radiant_block_hash(m.headers[m.height])
    assert f"linked hash by hash to block {m.top}" in (v.claim or "")
    assert "rests on that checkpoint, not on any server" in (v.claim or "")
    assert _step(v, "proof_of_work") == "not run", "no PoW is claimed at this level"
    assert _step(v, "merkle") == _step(v, "linkage") == _step(v, "blockhash") == "passed"


@BOTH
def test_a_block_that_is_itself_a_checkpoint_links_to_itself(m: Mark) -> None:
    v = m.run(m.cp(m.height))
    assert v.state == VERIFIED and v.linked_headers == 1


@BOTH
def test_above_the_newest_checkpoint_the_block_is_verified_by_work(m: Mark) -> None:
    v = m.run(m.cp(m.start))
    assert v.state == VERIFIED, v.reason
    assert v.level == "work"
    assert v.checkpoint_height == m.start
    floor = radiant_header_work(m.headers[m.start]) // FLOOR_WORK_DIVISOR
    assert v.floor_work_log2 == floor.bit_length() - 1
    assert "through 8 header(s)" in (v.claim or "")
    assert "does not check that they are Radiant's most-work chain" in (v.claim or "")
    assert _step(v, "proof_of_work") == _step(v, "floor") == "passed"


@BOTH
def test_burial_above_the_mark_is_linked_and_counted(m: Mark) -> None:
    v = m.run(m.cp(m.start), min_confirmations=9)
    assert v.state == VERIFIED and v.verified_depth == 9 and v.linked_headers == 17


def test_a_merkle_branch_object_and_a_raw_reply_are_the_same_input() -> None:
    assert C.run(C.cp(C.top), merkle=TxMerkleBranch.from_electrumx(C.merkle)) == C.run(C.cp(C.top))


def test_the_endpoint_naming_no_blockhash_skips_only_that_step() -> None:
    v = C.run(C.cp(C.top), blockhash=None)
    assert v.state == VERIFIED and _step(v, "blockhash") == "not run"


def test_an_odd_level_duplicate_sibling_is_accepted() -> None:
    """Pitfall 5 must NOT be "fixed": the last tx of an odd-width level is paired with itself.

    A three-transaction block; the mark is the third, so its level-0 sibling IS its own txid.
    The header is synthetic and unmined, so the test anchors a checkpoint to its own hash (the
    checkpoint level needs no proof-of-work).
    """
    cb, t1, mark = b"\x01" * 100, b"\x02" * 100, C.raw_tx
    l0 = [_d256(cb), _d256(t1), _d256(mark)]
    left = _d256(l0[0] + l0[1])
    right = _d256(l0[2] + l0[2])
    root = _d256(left + right)
    header = b"\x00\x00\x00\x20" + b"\x11" * 32 + root + b"\x00" * 4 + bytes.fromhex("31aa001a") + b"\x00" * 4
    merkle = {"block_height": 1000, "merkle": [l0[2][::-1].hex(), left[::-1].hex()], "pos": 2}
    assert merkle["merkle"][0] == C.txid, "the sibling is the mark itself"
    v = verify_mark_block(
        txid=C.txid,
        raw_tx=mark,
        height=1000,
        merkle=merkle,
        headers={1000: header},
        min_confirmations=1,
        checkpoints=[(1000, radiant_block_hash(header))],
    )
    assert v.state == VERIFIED, v.reason


# ── the lying server ─────────────────────────────────────────────────────────────────────────


def test_a_real_header_served_at_the_wrong_height_is_contradicted() -> None:
    """The endpoint names the real block, claims it is one lower, and serves the real header
    there. The merkle proof and the blockhash both pass — which is why inclusion alone is not
    verification — and linkage places that header at 460,572, not 460,571."""
    lie = dict(C.headers)
    lie[460571] = C.headers[460572]
    v = C.run(C.cp(C.top), height=460571, merkle={**C.merkle, "block_height": 460571}, headers=lie)
    assert v.state == CONTRADICTED
    assert _step(v, "merkle") == _step(v, "blockhash") == "passed"
    assert _step(v, "linkage") == "failed"


def test_the_whole_chain_shifted_down_one_is_contradicted() -> None:
    shifted = {h - 1: hdr for h, hdr in C.headers.items()}
    shifted[C.top] = C.headers[C.top]  # the checkpoint's own header is still served honestly
    v = C.run(C.cp(C.top), height=460571, merkle={**C.merkle, "block_height": 460571}, headers=shifted)
    assert v.state == CONTRADICTED and "does not link" in (v.reason or "")


def test_a_spliced_header_breaks_the_link() -> None:
    lie = dict(C.headers)
    lie[460576] = MARKS["pyrxd_468521"].headers[468515]
    v = C.run(C.cp(C.top), headers=lie)
    assert v.state == CONTRADICTED and "the header at 460576 does not link" in (v.reason or "")


def test_a_chain_that_does_not_reach_the_checkpoint_hash_is_contradicted() -> None:
    v = C.run([(C.top, "00" * 32)])
    assert v.state == CONTRADICTED and "not pyrxd's checkpoint" in (v.reason or "")


@pytest.mark.parametrize(
    "mutate",
    [
        lambda r: {**r, "merkle": [r["merkle"][0][:-2] + "00", *r["merkle"][1:]]},
        lambda r: {**r, "pos": 5},
        lambda r: {**r, "merkle": r["merkle"][:-1], "pos": r["pos"] % 8},
        lambda r: {**r, "merkle": list(reversed(r["merkle"]))},
    ],
    ids=["flipped_sibling", "pos_4_to_5", "truncated_branch", "reordered_branch"],
)
def test_a_wrong_merkle_branch_is_contradicted(mutate: Any) -> None:
    v = C.run(C.cp(C.top), merkle=mutate(C.merkle))
    assert v.state == CONTRADICTED and _step(v, "merkle") == "failed"


def test_a_merkle_branch_for_another_block_is_contradicted() -> None:
    v = C.run(C.cp(C.top), merkle={**C.merkle, "block_height": 460573})
    assert v.state == CONTRADICTED and "for block 460573" in (v.reason or "")


def test_a_header_other_than_the_one_the_endpoint_named_is_contradicted() -> None:
    v = C.run(C.cp(C.top), blockhash=radiant_block_hash(C.headers[460571]))
    assert v.state == CONTRADICTED and _step(v, "blockhash") == "failed"


@pytest.mark.parametrize(
    "raw",
    [b"\x00" * 64, C.raw_tx[:-1], MARKS["pyrxd_468521"].raw_tx],
    ids=["64_bytes", "truncated", "a_different_tx"],
)
def test_a_raw_tx_that_is_not_the_mark_is_contradicted(raw: bytes) -> None:
    assert C.run(C.cp(C.top), raw_tx=raw).state == CONTRADICTED


def test_a_header_with_bad_pow_above_the_checkpoint_is_contradicted() -> None:
    lie = dict(C.headers)
    h = bytearray(lie[460575])
    h[79] ^= 0x01
    lie[460575] = bytes(h)
    v = C.run(C.cp(C.start), headers=lie, min_confirmations=5)
    assert v.state == CONTRADICTED
    assert _step(v, "proof_of_work") == "failed" and "460575" in (v.reason or "")


# The mined forgery: real block 460,580 as the checkpoint, then ONE cheap block on top of it that
# contains the real mark, so an endpoint can claim the mark is at 460,581.
_MINED_COINBASE = bytes.fromhex(
    "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0d0365070700"
    "000000000000000000ffffffff0100f2052a010000001976a914111111111111111111111111111111111111111188ac"
    "00000000"
)
_MINED_HEADER = bytes.fromhex(
    "0000002031c1b00e932262cdb79cae0bf1b7858e4b9deea88a31e8b861000000000000009ec81346e48cd566ad4232"
    "b77b74ab9a21b5611e8d7dffbd59a3bc941f97674a60ea966affff7f1d98ef3b03"
)


def _forged(**over: Any) -> BlockVerification:
    headers = {460580: C.headers[460580], 460581: over.pop("header", _MINED_HEADER)}
    merkle = {"block_height": 460581, "merkle": [_d256(_MINED_COINBASE)[::-1].hex()], "pos": 1}
    return C.run(C.cp(460580), height=460581, merkle=merkle, headers=headers, blockhash=None, **over)


def test_the_mined_forgery_is_real_proof_of_work_on_the_real_chain() -> None:
    """Premise check: without this the low-work test below could pass for the wrong reason."""
    assert verify_radiant_header_pow(_MINED_HEADER).startswith("000000")
    assert _MINED_HEADER[4:36][::-1].hex() == radiant_block_hash(C.headers[460580])
    assert radiant_header_work(_MINED_HEADER).bit_length() - 1 == 25


def test_a_cheaply_mined_block_fails_the_floor() -> None:
    """The attack the floor exists for. Everything else passes: inclusion, linkage, genuine PoW."""
    v = _forged()
    assert v.state == NOT_VERIFIED
    assert _step(v, "merkle") == _step(v, "proof_of_work") == "passed"
    assert _step(v, "floor") == "failed"
    assert "less work than the floor" in (v.reason or "")


def test_the_same_forgery_unmined_is_contradicted() -> None:
    h = bytearray(_MINED_HEADER)
    h[76] ^= 0x01
    assert _forged(header=bytes(h)).state == CONTRADICTED


# ── nothing proved either way ────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("over", "reason"),
    [
        ({"merkle": None}, "no merkle branch"),
        ({"merkle": "deadbeef"}, "malformed"),
        ({"merkle": {"block_height": 460572, "pos": 4}}, "malformed"),
        ({"merkle": {"block_height": 460572, "merkle": [], "pos": 0}}, "coinbase"),
        ({"merkle": {**C.merkle, "pos": 0}}, "coinbase"),
        ({"merkle": {**C.merkle, "pos": 16}}, "malformed"),
        ({"raw_tx": None}, "no raw transaction"),
        ({"headers": None}, "no headers"),
        ({"headers": {}}, "not available"),
        ({"headers": {**C.headers, 460576: C.headers[460576][:79]}}, "not an 80-byte header"),
        ({"headers": {**C.headers, 460576: C.headers[460576].hex()}}, "not an 80-byte header"),
        ({"headers": {h: x for h, x in C.headers.items() if h != 460578}}, "460578 was not available"),
        ({"height": None}, "no usable block height"),
        ({"height": "460572"}, "no usable block height"),
        ({"height": -1}, "no usable block height"),
        ({"txid": None}, "no usable txid"),
    ],
    ids=lambda x: x if isinstance(x, str) else None,
)
def test_missing_or_unreadable_data_is_not_verified(over: dict, reason: str) -> None:
    v = C.run(C.cp(C.top), **over)
    assert v.state == NOT_VERIFIED
    assert reason in (v.reason or "")


def test_a_network_with_no_checkpoints_is_not_verified() -> None:
    v = C.run(None, network="regtest")
    assert v.state == NOT_VERIFIED and "ships no checkpoints" in (v.reason or "")


def test_the_shipped_table_is_the_default_and_asks_for_its_full_range() -> None:
    """``checkpoints=None`` reaches the shipped table. The fixture carries 17 of the 1,093
    headers it needs, so the answer is NOT VERIFIED naming the first one missing."""
    newest = CHECKPOINTS["mainnet"][-1][0]
    assert C.height < newest
    v = C.run(None)
    assert v.state == NOT_VERIFIED
    assert f"{C.top + 1} was not available" in (v.reason or "")
    assert plan_block_verification(height=C.height, min_confirmations=1).header_ranges == ((460572, 1093),)


def test_past_the_cap_it_needs_a_newer_pyrxd() -> None:
    newest = CHECKPOINTS["mainnet"][-1][0]
    ok = plan_block_verification(height=newest + MAX_HEADERS_FROM_CHECKPOINT, min_confirmations=1)
    assert ok.reason is None and ok.level == "work"
    assert sum(n for _, n in ok.header_ranges) == MAX_HEADERS_FROM_CHECKPOINT + 1
    assert all(n <= 2016 for _, n in ok.header_ranges)
    over = plan_block_verification(height=newest + MAX_HEADERS_FROM_CHECKPOINT + 1, min_confirmations=1)
    assert over.header_ranges == () and "needs a newer pyrxd" in (over.reason or "")
    burial = plan_block_verification(height=newest + MAX_HEADERS_FROM_CHECKPOINT, min_confirmations=2)
    assert "needs a newer pyrxd" in (burial.reason or "")
    v = C.run(None, height=newest + MAX_HEADERS_FROM_CHECKPOINT + 1)
    assert v.state == NOT_VERIFIED and "needs a newer pyrxd" in (v.reason or "")


def test_a_checkpoint_too_far_above_is_not_verified() -> None:
    v = C.run([(C.height + MAX_HEADERS_FROM_CHECKPOINT + 1, "00" * 32)])
    assert v.state == NOT_VERIFIED and "no checkpoint within" in (v.reason or "")


def test_a_burial_shortfall_is_not_verified_with_the_depth_reached() -> None:
    v = C.run(C.cp(C.start), min_confirmations=10)
    assert v.state == NOT_VERIFIED and v.verified_depth == 9
    assert "only 9 of the 10" in (v.reason or "")


# ── contract ─────────────────────────────────────────────────────────────────────────────────


def test_it_is_synchronous() -> None:
    """The browser bridge drives it with no event loop."""
    assert not inspect.iscoroutinefunction(verify_mark_block)


@pytest.mark.parametrize("bad", [0, -1, True, None, 1.0])
def test_a_bad_min_confirmations_is_a_caller_error(bad: Any) -> None:
    with pytest.raises(ValidationError):
        C.run(C.cp(C.top), min_confirmations=bad)


@pytest.mark.parametrize(
    "table",
    [[(2, "aa" * 32), (1, "bb" * 32)], [(1, "AA" * 32)], [(1,)], [("1", "aa" * 32)]],
    ids=["descending", "uppercase", "short", "str_height"],
)
def test_a_malformed_checkpoint_table_is_a_caller_error(table: Any) -> None:
    with pytest.raises(ValidationError):
        C.run(table)


def test_importing_it_pulls_no_browser_incompatible_dependency() -> None:
    code = (
        "import sys, pyrxd.glyph.mark_block\n"
        "bad = sorted(m for m in sys.modules if m.split('.')[0] in "
        "('websockets', 'aiohttp', 'coincurve', 'Cryptodome'))\n"
        "print(bad)"
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True)
    assert out.stdout.strip() == "[]"


# ── never raises on server data (property) ───────────────────────────────────────────────────

_ANY_JSON = st.recursive(
    st.none() | st.booleans() | st.integers() | st.floats() | st.text(max_size=70) | st.binary(max_size=90),
    lambda inner: st.lists(inner, max_size=4) | st.dictionaries(st.text(max_size=12), inner, max_size=4),
    max_leaves=12,
)
_SPAN = sorted(h for h in C.headers if C.height <= h <= C.top)


@st.composite
def _mutated(draw: Any) -> dict[str, Any]:
    kw: dict[str, Any] = {
        "merkle": dict(C.merkle),
        "headers": dict(C.headers),
        "raw_tx": C.raw_tx,
        "height": C.height,
        "blockhash": radiant_block_hash(C.headers[C.height]),
    }
    # One or two mutations, headers weighted up: with more, nearly every case stopped at the first
    # (merkle) check and the header-walking code was rarely reached. The bit-flip property below
    # covers the linkage walk exhaustively over its own axis.
    kinds = ["merkle_field", "merkle", "header", "header", "header", "drop_header", "raw_tx", "height", "blockhash"]
    for _ in range(draw(st.integers(1, 2))):
        what = draw(st.sampled_from(kinds))
        if what == "merkle_field":
            kw["merkle"] = dict(kw["merkle"]) if isinstance(kw["merkle"], dict) else {}
            kw["merkle"][draw(st.sampled_from(["block_height", "merkle", "pos"]))] = draw(_ANY_JSON)
        elif what == "merkle":
            kw["merkle"] = draw(_ANY_JSON)
        elif what == "header":
            kw["headers"][draw(st.sampled_from(_SPAN))] = draw(st.binary(min_size=0, max_size=100) | _ANY_JSON)
        elif what == "drop_header":
            kw["headers"].pop(draw(st.sampled_from(_SPAN)), None)
        elif what == "raw_tx":
            kw["raw_tx"] = draw(st.binary(max_size=400) | _ANY_JSON)
        elif what == "height":
            kw["height"] = draw(st.integers(-5, 2**40) | _ANY_JSON)
        else:
            kw["blockhash"] = draw(st.text(max_size=70) | _ANY_JSON)
    return kw


@settings(max_examples=300, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(_mutated())
def test_mutated_server_data_never_raises_and_never_verifies_another_height(kw: dict[str, Any]) -> None:
    v = C.run(C.cp(C.top), **kw)
    assert isinstance(v, BlockVerification)
    assert v.state in (VERIFIED, NOT_VERIFIED, CONTRADICTED)
    assert not (v.reason or "").startswith(mark_block._INTERNAL), v.reason
    if v.state == VERIFIED:
        assert v.height == C.height
        assert v.blockhash == radiant_block_hash(C.headers[C.height])
        assert v.reason is None and v.claim
    else:
        assert v.reason and v.claim is None


@settings(max_examples=200, deadline=None)
@given(st.sampled_from(_SPAN), st.integers(0, 80 * 8 - 1))
def test_any_single_bit_flipped_in_the_linked_span_is_not_verified(height: int, bit: int) -> None:
    headers = dict(C.headers)
    h = bytearray(headers[height])
    h[bit // 8] ^= 1 << (bit % 8)
    headers[height] = bytes(h)
    v = C.run(C.cp(C.top), headers=headers)
    assert v.state != VERIFIED
