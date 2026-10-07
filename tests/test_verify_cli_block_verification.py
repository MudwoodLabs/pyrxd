"""``pyrxd verify`` verifies the mark's block — driven through the real click command.

THE ENTRY POINT IS THE PRODUCTION ONE. Every test here runs ``pyrxd verify`` through
``CliRunner`` against a REAL :class:`~pyrxd.network.electrumx.ElectrumXClient` whose JSON-RPC
transport alone is faked (``_call``), so every reply crosses the client's own parsing and
validation exactly as a server's would. The replies are the real ones two mainnet servers gave
for two HashMarks (``tests/fixtures/mark_block_fixtures_2026-09-30.json``): the raw
transactions (each a real signed v2 record the classifier reads), their merkle branches, each
block's coinbase branch, and 17 linked headers around each block.

TEST CHECKPOINTS. The shipped table's checkpoints nearest these marks are ~1,100 and ~2,800
blocks away, further than 17 headers reach. So most tests replace the mainnet table with ONE
checkpoint made from a fixture header's own hash (``_checkpoint``), which exercises both levels —
linkage to a checkpoint above the mark, and proof-of-work from one below it — on real headers.
The shipped table itself is used, unpatched, in the degrade test for a mark it cannot reach.

WHAT IS NOT PROVED HERE: what the pages draw (``tests/web/test_block_proof_on_the_pages.py``
checks that, against these same fixture replies), or that a live server answers these RPCs this
way today (the fixture was captured 2026-09-30).
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from pyrxd.cli import glyph_inspect
from pyrxd.cli.context import CliContext
from pyrxd.cli.glyph_inspect import resolve_anchor_from
from pyrxd.cli.main import cli
from pyrxd.glyph.mark_anchor import BOUND_CAVEAT, INCLUSION_ONLY_CAVEAT, mark_anchor_dict
from pyrxd.hash import radiant_block_hash
from pyrxd.network.electrumx import ElectrumXClient, _rpc_error
from pyrxd.security.errors import NetworkError
from pyrxd.spv import radiant_checkpoints

ROOT = Path(__file__).resolve().parent.parent
_FIX = json.loads((ROOT / "tests/fixtures/mark_block_fixtures_2026-09-30.json").read_text(encoding="utf-8"))["fixtures"]

REFERENCE = "a1a86ab4503901af4df3d092fcf668b07c03c5cd89240fe918ae70e02e045916"  # block 460,572
PYRXD = "aa66b04662aa5514ed7d0027ff3cbd608d73f3e2b92d4129d810eb576bc0c86e"  # block 468,521
LABEL = "wss://fixture.invalid/"

_BLOCK_RPCS = {"blockchain.transaction.get_merkle", "blockchain.transaction.id_from_pos", "blockchain.block.headers"}


class Chain:
    """One real mark and the 17 real headers around its block. The tip is the top one."""

    def __init__(self, txid: str) -> None:
        fx = _FIX[txid]
        self.txid = txid
        self.raw = bytes.fromhex(fx["raw_tx"])
        self.merkle = fx["merkle"]
        self.coinbase = fx["coinbase_merkle"]
        self.height = fx["merkle"]["block_height"]
        raw = bytes.fromhex(fx["headers_hex"])
        self.start = fx["headers_start"]
        self.headers = {self.start + i: raw[i * 80 : (i + 1) * 80] for i in range(len(raw) // 80)}
        self.tip = max(self.headers)

    def hash_at(self, h: int) -> str:
        return radiant_block_hash(self.headers[h])


def _server(chain: Chain, **override: Any) -> ElectrumXClient:
    """A real client; only its transport answers from the fixture.

    ``override`` maps a JSON-RPC method to a replacement: an exception instance is raised, a
    callable is called with ``params`` and its result returned.
    """
    client = ElectrumXClient([LABEL])
    calls: list[tuple[str, list]] = []

    async def _call(method: str, params: list) -> Any:
        calls.append((method, list(params)))
        if method in override:
            got = override[method]
            if isinstance(got, BaseException):
                raise got
            return got(params)
        if method == "blockchain.transaction.get":
            txid, verbose = params
            assert txid == chain.txid, "the fake only knows its own transaction"
            if not verbose:
                return chain.raw.hex()
            return {
                "txid": chain.txid,
                "confirmations": chain.tip - chain.height + 1,
                "blockhash": chain.hash_at(chain.height),
            }
        if method == "blockchain.headers.subscribe":
            return {"height": chain.tip, "hex": chain.headers[chain.tip].hex()}
        if method == "blockchain.block.header":
            h = params[0]
            if h not in chain.headers:
                raise NetworkError(f"height {h} out of range")
            return chain.headers[h].hex()
        if method == "blockchain.transaction.get_merkle":
            return copy.deepcopy(chain.merkle)
        if method == "blockchain.transaction.id_from_pos":
            assert params == [chain.height, 0, True]
            return copy.deepcopy(chain.coinbase)
        if method == "blockchain.block.headers":
            return _headers_reply(chain.headers, *params)
        raise AssertionError(f"unexpected RPC {method}")

    async def _connected() -> None:
        return None

    client._call = _call  # type: ignore[method-assign]
    client._ensure_connected = _connected  # type: ignore[method-assign]
    client.calls = calls  # type: ignore[attr-defined]
    return client


def _headers_reply(headers: dict[int, bytes], start: int, count: int) -> dict:
    """What ElectrumX sends: the consecutive headers it has from ``start``, at most ``count``."""
    out = []
    h = start
    while h in headers and len(out) < count:
        out.append(headers[h])
        h += 1
    return {"count": len(out), "hex": b"".join(out).hex(), "max": 2016}


def _renonced(header: bytes, byte: int = 76) -> bytes:
    """The same block with another nonce: the same merkle root (so the same transactions), a
    different hash — what a reorganisation that re-mines the transaction at the same height leaves."""
    moved = bytearray(header)
    moved[byte] ^= 1
    return bytes(moved)


def _reorg(chain: Chain, *, named: bytes, served: bytes | None = None) -> dict[str, Any]:
    """Overrides for a block at the mark's height that CHANGED between the endpoint's replies.

    The anchor's replies (verbose ``blockhash``, and the single header it binds to) name the block
    ``named``; the proof's header ranges serve ``served`` at that height (default: the real one,
    which links to the rest of the chain). Every reply is internally honest for the moment it
    was given."""
    ranges = dict(chain.headers)
    if served is not None:
        ranges[chain.height] = served

    def verbose_or_raw(params: list) -> Any:
        txid, verbose = params
        assert txid == chain.txid
        if not verbose:
            return chain.raw.hex()
        return {
            "txid": chain.txid,
            "confirmations": chain.tip - chain.height + 1,
            "blockhash": radiant_block_hash(named),
        }

    def one_header(params: list) -> str:
        if params[0] == chain.height:
            return named.hex()
        if params[0] not in chain.headers:
            raise NetworkError(f"height {params[0]} out of range")
        return chain.headers[params[0]].hex()

    return {
        "blockchain.transaction.get": verbose_or_raw,
        "blockchain.block.header": one_header,
        "blockchain.block.headers": lambda p: _headers_reply(ranges, *p),
    }


def _checkpoint(monkeypatch, chain: Chain, height: int) -> None:
    """Replace the shipped mainnet table with one checkpoint: the real header at ``height``."""
    monkeypatch.setitem(radiant_checkpoints.CHECKPOINTS, "mainnet", ((height, chain.hash_at(height)),))


def _run(monkeypatch, tmp_path, server: ElectrumXClient, *args: str, json_out: bool = True):
    monkeypatch.setattr(CliContext, "make_client", lambda self: server)
    monkeypatch.setattr(glyph_inspect, "_endpoint_pair", lambda ctx: (server, LABEL, server, LABEL))
    head = ["--wallet", str(tmp_path / "w.dat"), "--config", str(tmp_path / "c.toml")]
    return CliRunner().invoke(cli, [*head, *(["--json"] if json_out else []), "verify", *args])


def _verify(monkeypatch, tmp_path, chain: Chain, server=None, *, conf: int = 6, json_out: bool = True):
    server = server or _server(chain)
    r = _run(monkeypatch, tmp_path, server, chain.txid, "--min-confirmations", str(conf), json_out=json_out)
    return r, server


def _flat(text: str) -> str:
    return " ".join(text.split())


C = Chain(REFERENCE)
BOTH = pytest.mark.parametrize("chain", [Chain(REFERENCE), Chain(PYRXD)], ids=["reference_460572", "pyrxd_468521"])


def test_both_real_marks_are_here_and_nine_deep() -> None:
    """Non-vacuity: the fixture carries what every test below leans on."""
    for chain in (Chain(REFERENCE), Chain(PYRXD)):
        assert chain.tip - chain.height == 8 and chain.height - chain.start == 8
        assert len(chain.raw) > 64


# ── VERIFIED ────────────────────────────────────────────────────────────────────────────────


@BOTH
def test_a_block_below_a_checkpoint_is_verified(monkeypatch, tmp_path, chain: Chain) -> None:
    _checkpoint(monkeypatch, chain, chain.tip)
    r, server = _verify(monkeypatch, tmp_path, chain)
    assert r.exit_code == 0, r.output
    out = json.loads(r.output)
    anchor = out["mark_anchor"]
    bv = anchor["block_verification"]
    assert bv["state"] == "VERIFIED", bv["reason"]
    assert bv["level"] == "checkpoint" and bv["checkpoint_height"] == chain.tip
    assert bv["source"] == LABEL
    assert anchor["height"] == chain.height and anchor["height_is_verified"] is True
    assert anchor["blockhash"] == chain.hash_at(chain.height)
    assert anchor["caveat"] == bv["claim"] and "rests on that checkpoint, not on any server" in bv["claim"]
    assert out["checks"]["block"]["state"] == "VERIFIED"
    assert f"linked hash by hash to pyrxd checkpoint {chain.tip}" in out["checks"]["block"]["reason"]
    assert out["verdict_holds"] is True
    # THE RAW TRANSACTION IS NOT FETCHED AGAIN: one non-verbose `blockchain.transaction.get`,
    # the classifier's, and the verifier checked those same bytes.
    raw_gets = [c for c in server.calls if c == ("blockchain.transaction.get", [chain.txid, False])]
    assert len(raw_gets) == 1
    assert {m for m, _ in server.calls} >= _BLOCK_RPCS


@BOTH
def test_a_block_above_the_newest_checkpoint_is_verified_by_work(monkeypatch, tmp_path, chain: Chain) -> None:
    _checkpoint(monkeypatch, chain, chain.start)
    r, _ = _verify(monkeypatch, tmp_path, chain)
    assert r.exit_code == 0, r.output
    out = json.loads(r.output)
    bv = out["mark_anchor"]["block_verification"]
    assert bv["state"] == "VERIFIED", bv["reason"]
    assert bv["level"] == "work" and bv["checkpoint_height"] == chain.start
    assert dict(bv["steps"])["proof_of_work"] == "passed"
    assert out["checks"]["block"]["state"] == "VERIFIED"
    assert f"at least 2^{bv['floor_work_log2']}" in out["checks"]["block"]["reason"]


def test_the_human_report_prints_the_claim_whole_and_not_the_endpoint_caveat(monkeypatch, tmp_path) -> None:
    for level_cp in (C.tip, C.start):  # both claims, the long proof-of-work one included
        _checkpoint(monkeypatch, C, level_cp)
        r, _ = _verify(monkeypatch, tmp_path, C, json_out=False)
        assert r.exit_code == 0, r.output
        claim = json.loads(_verify(monkeypatch, tmp_path, C)[0].output)["mark_anchor"]["caveat"]
        flat = _flat(r.output)
        assert "block: VERIFIED" in flat
        assert _flat(f"VERIFIED: {claim}") in flat, "the claim is printed whole, never cut"
        assert _flat(BOUND_CAVEAT) not in flat
        assert "not verified:" not in flat
        assert f"(block proof asked of: {LABEL})" in r.output


def test_the_longest_claim_is_printed_whole(monkeypatch, tmp_path) -> None:
    """The proof-of-work claim with the different-name sentence: the longest a claim gets."""
    _checkpoint(monkeypatch, C, C.start)
    override = _reorg(C, named=_renonced(C.headers[C.height]))
    r, _ = _verify(monkeypatch, tmp_path, C, _server(C, **override), json_out=False)
    assert r.exit_code == 0, r.output
    claim = json.loads(_verify(monkeypatch, tmp_path, C, _server(C, **override))[0].output)["mark_anchor"]["caveat"]
    assert "proof-of-work" in claim and "had named a different block" in claim
    assert _flat(f"VERIFIED: {claim}") in _flat(r.output), "the claim is printed whole, never cut"


# ── degrades: CONFIRMED, the endpoint's word, with the reason; the verdict still holds ──────


def _degrades() -> dict[str, Any]:
    return {
        "merkle_method_not_found": (
            {"blockchain.transaction.get_merkle": _rpc_error(-32601, "unknown method")},
            "the transaction's merkle branch could not be fetched",
        ),
        "coinbase_method_not_found": (
            {"blockchain.transaction.id_from_pos": _rpc_error(-32601, "unknown method")},
            "the block's coinbase merkle branch could not be fetched",
        ),
        "header_range_times_out": (
            {"blockchain.block.headers": NetworkError("ElectrumX request timed out")},
            "could not be fetched",
        ),
        "header_range_malformed": (
            {"blockchain.block.headers": lambda p: {"count": 3, "hex": "00" * 10, "max": 2016}},
            "could not be fetched",
        ),
    }


@pytest.mark.parametrize("case", list(_degrades()), ids=list(_degrades()))
def test_a_server_that_cannot_serve_the_proof_degrades_to_confirmed(monkeypatch, tmp_path, case: str) -> None:
    override, why = _degrades()[case]
    _checkpoint(monkeypatch, C, C.tip)
    r, _ = _verify(monkeypatch, tmp_path, C, _server(C, **override))
    assert r.exit_code == 0, r.output  # never a refusal of a valid mark
    out = json.loads(r.output)
    anchor = out["mark_anchor"]
    assert anchor["block_verification"]["state"] == "NOT VERIFIED"
    assert why in anchor["block_verification"]["reason"] and LABEL in anchor["block_verification"]["reason"]
    assert anchor["height_is_verified"] is False
    assert anchor["caveat"] == BOUND_CAVEAT, "nothing was checked, so the endpoint's-word caveat is true"
    assert out["checks"]["block"]["state"] == "CONFIRMED"
    assert "endpoint's word; not verified:" in out["checks"]["block"]["reason"]
    assert out["verdict_holds"] is True


def test_headers_served_short_leave_inclusion_checked_and_the_height_unverified(monkeypatch, tmp_path) -> None:
    """The server serves the mark's own header and stops (as near its tip): the merkle branch IS
    checked and passes, and the linkage cannot finish. Inclusion alone fixes no height (plan
    risk 2), so this is CONFIRMED — and the caveat must not say "pyrxd checks no merkle
    inclusion", because here it did."""
    _checkpoint(monkeypatch, C, C.tip)
    short = {"blockchain.block.headers": lambda p: _headers_reply(C.headers, p[0], 1)}
    r, _ = _verify(monkeypatch, tmp_path, C, _server(C, **short))
    assert r.exit_code == 0, r.output
    anchor = json.loads(r.output)["mark_anchor"]
    bv = anchor["block_verification"]
    assert bv["state"] == "NOT VERIFIED" and dict(bv["steps"])["merkle"] == "passed"
    assert f"the header at height {C.height + 1} was not available" in bv["reason"]
    assert anchor["height_is_verified"] is False
    assert anchor["caveat"] == INCLUSION_ONLY_CAVEAT
    assert json.loads(r.output)["checks"]["block"]["state"] == "CONFIRMED"


def test_a_network_with_no_checkpoints_asks_for_nothing(monkeypatch, tmp_path) -> None:
    monkeypatch.setitem(radiant_checkpoints.CHECKPOINTS, "mainnet", ())
    r, server = _verify(monkeypatch, tmp_path, C)
    assert r.exit_code == 0, r.output
    out = json.loads(r.output)
    assert out["mark_anchor"]["block_verification"]["state"] == "NOT VERIFIED"
    assert "ships no checkpoints for this network" in out["mark_anchor"]["block_verification"]["reason"]
    assert out["checks"]["block"]["state"] == "CONFIRMED"
    assert not {m for m, _ in server.calls} & _BLOCK_RPCS, "no proof was fetched that could not be used"


def test_regtest_ships_no_checkpoints_so_its_block_stays_confirmed(monkeypatch, tmp_path) -> None:
    """The real regtest table (empty), not a patched one. The record is signed for mainnet, so
    the signature check is not what this asserts; the block check and the RPCs are."""
    assert radiant_checkpoints.CHECKPOINTS["regtest"] == ()
    server = _server(C)
    monkeypatch.setattr(CliContext, "make_client", lambda self: server)
    monkeypatch.setattr(glyph_inspect, "_endpoint_pair", lambda ctx: (server, LABEL, server, LABEL))
    head = ["--wallet", str(tmp_path / "w.dat"), "--config", str(tmp_path / "c.toml"), "--network", "regtest"]
    r = CliRunner().invoke(cli, [*head, "--json", "verify", C.txid, "--min-confirmations", "6"])
    assert r.exit_code in (0, 5), r.output
    out = json.loads(r.output)
    assert out["network"] == "regtest"
    assert out["checks"]["block"]["state"] == "CONFIRMED"
    assert "ships no checkpoints" in out["mark_anchor"]["block_verification"]["reason"]
    assert not {m for m, _ in server.calls} & _BLOCK_RPCS


def test_a_mark_whose_headers_reach_no_shipped_checkpoint_is_confirmed_with_the_reason(monkeypatch, tmp_path) -> None:
    """The SHIPPED table, unpatched. None of these 17 headers is a shipped checkpoint, so they
    cannot link the mark to one, whichever side of the newest checkpoint the mark falls on. The
    server's short header range is what stops verification, honestly, and the verdict stands."""
    chain = Chain(PYRXD)
    shipped = {h for h, _ in radiant_checkpoints.CHECKPOINTS["mainnet"]}
    assert shipped and not shipped & set(chain.headers)
    r, _ = _verify(monkeypatch, tmp_path, chain)
    assert r.exit_code == 0, r.output
    out = json.loads(r.output)
    assert out["mark_anchor"]["block_verification"]["state"] == "NOT VERIFIED"
    assert out["checks"]["block"]["state"] == "CONFIRMED"


# ── CONTRADICTED: exit 2, with the reason; the mark is not called invalid ──────────────────


def _flip(hex64: str) -> str:
    return ("0" if hex64[0] != "0" else "1") + hex64[1:]


def _contradictions() -> dict[str, dict]:
    bad_merkle = copy.deepcopy(C.merkle)
    bad_merkle["merkle"][1] = _flip(bad_merkle["merkle"][1])
    spliced = dict(C.headers)
    other = Chain(PYRXD)
    spliced[C.height + 3] = other.headers[other.height]  # a real header, on another chain
    return {
        "a_flipped_merkle_sibling": {"blockchain.transaction.get_merkle": lambda p: copy.deepcopy(bad_merkle)},
        "a_header_spliced_between_the_mark_and_the_checkpoint": {
            "blockchain.block.headers": lambda p: _headers_reply(spliced, *p)
        },
    }


@pytest.mark.parametrize("case", list(_contradictions()), ids=list(_contradictions()))
def test_a_proof_that_contradicts_the_height_exits_2_with_its_reason(monkeypatch, tmp_path, case: str) -> None:
    _checkpoint(monkeypatch, C, C.tip)
    for json_out in (True, False):
        r, _ = _verify(monkeypatch, tmp_path, C, _server(C, **_contradictions()[case]), json_out=json_out)
        assert r.exit_code == 2, r.output
        text = _flat(r.output)
        assert "could not establish which block the mark is in" in text
        assert "contradicts the height reported for the mark" in text and LABEL in text
        assert "says nothing against the mark itself" in text
        assert "VERDICT" not in text and '"verdict_holds"' not in text, "no verdict is printed over it"
        assert "invalid" not in text.lower().replace("invalid/", "")


def test_the_contradiction_reason_names_what_failed(monkeypatch, tmp_path) -> None:
    _checkpoint(monkeypatch, C, C.tip)
    r, _ = _verify(monkeypatch, tmp_path, C, _server(C, **_contradictions()["a_flipped_merkle_sibling"]))
    assert "merkle inclusion failed" in r.output
    r, _ = _verify(
        monkeypatch,
        tmp_path,
        C,
        _server(C, **_contradictions()["a_header_spliced_between_the_mark_and_the_checkpoint"]),
    )
    assert f"the header at {C.height + 3} does not link to the header served at {C.height + 2}" in _flat(r.output)


def _bad_pow_at(headers: dict[int, bytes], h: int) -> dict[int, bytes]:
    """The real headers, with the one at *h* altered so it hashes above its own nBits target."""
    lie = dict(headers)
    moved = bytearray(lie[h])
    moved[79] ^= 0x01
    lie[h] = bytes(moved)
    return lie


def test_a_header_failing_its_own_proof_of_work_exits_2(monkeypatch, tmp_path) -> None:
    """The review's case: the server reports nine, and the header at 468,523 — three deep — hashes
    above its own target. Required six deep, that is a lie in the server's own proof: exit 2. (The
    pages, which require one and aim for six, say the same: ``tests/web/test_block_proof_on_the_pages.py``.)"""
    chain = Chain(PYRXD)
    _checkpoint(monkeypatch, chain, chain.start)
    lie = _bad_pow_at(chain.headers, chain.height + 2)
    r, _ = _verify(
        monkeypatch, tmp_path, chain, _server(chain, **{"blockchain.block.headers": lambda p: _headers_reply(lie, *p)})
    )
    assert r.exit_code == 2, r.output
    assert "the header at 468523 fails its own proof-of-work" in _flat(r.output)


def test_the_json_reports_the_floor_on_a_proof_that_fails_above_the_checkpoint(monkeypatch, tmp_path) -> None:
    """``floor_work_log2`` is known before any header above the checkpoint is checked, so a proof
    failing among them still carries it in ``--json`` — here the header mined for
    ``tests/test_mark_block_verification.py`` on top of the real 460,580, below the floor, ten deep."""
    from pyrxd.glyph.mark_block import FLOOR_WORK_DIVISOR
    from pyrxd.spv.radiant import radiant_header_work
    from tests.test_mark_block_verification import _MINED_HEADER

    _checkpoint(monkeypatch, C, C.start)
    served = {**C.headers, C.tip + 1: _MINED_HEADER}
    over = {**_confs(C, 10), "blockchain.block.headers": lambda p: _headers_reply(served, *p)}
    r, _ = _verify(monkeypatch, tmp_path, C, _server(C, **over), conf=10)
    bv = json.loads(r.output)["mark_anchor"]["block_verification"]
    assert bv["state"] == "NOT VERIFIED" and dict(bv["steps"])["floor"] == "failed", bv
    floor = radiant_header_work(C.headers[C.start]) // FLOOR_WORK_DIVISOR
    assert bv["floor_work_log2"] == floor.bit_length() - 1 == 52


# ── a reorganisation between the anchor's reply and the proof's ────────────────────────────


def test_a_block_replaced_between_the_anchor_and_the_proof_is_verified_as_the_block_proved(
    monkeypatch, tmp_path
) -> None:
    """HONEST: the endpoint named block A at the mark's height, then the chain reorganised and
    the transaction was re-mined at the same height in block B, which the proof's headers carry.
    B's proof holds — inclusion, linkage to the checkpoint — so this is VERIFIED, exit 0, and
    what is reported is B, the block proved, never the stale name. It used to exit 2."""
    _checkpoint(monkeypatch, C, C.tip)
    stale = _renonced(C.headers[C.height])
    for json_out in (True, False):
        r, _ = _verify(monkeypatch, tmp_path, C, _server(C, **_reorg(C, named=stale)), json_out=json_out)
        assert r.exit_code == 0, r.output
        if not json_out:
            flat = _flat(r.output)
            assert "block: VERIFIED" in flat
            assert f"had named a different block for the transaction ({radiant_block_hash(stale)})" in flat
            assert f"the block proved is {C.hash_at(C.height)}" in flat
            continue
        out = json.loads(r.output)
        anchor = out["mark_anchor"]
        bv = anchor["block_verification"]
        assert bv["state"] == "VERIFIED", bv["reason"]
        assert dict(bv["steps"])["blockhash"] == "differs"
        assert anchor["blockhash"] == bv["blockhash"] == C.hash_at(C.height), "the proven hash, not the stale one"
        assert bv["named_blockhash"] == radiant_block_hash(stale)
        assert anchor["height_is_verified"] is True and out["checks"]["block"]["state"] == "VERIFIED"


def test_the_block_the_endpoint_named_reaches_the_verifier(monkeypatch, tmp_path) -> None:
    """WHAT THE BLOCKHASH STEP IS FOR, pinned at the production entry point. It no longer refuses
    anything (a stale name alone is not a contradiction); it is how the reader learns that the
    block the endpoint NAMED is not the block PROVED. So the anchor's name must reach the
    verifier: when it matches, the step passes and nothing is noted; when it differs, the JSON
    carries the name, labelled, beside the proved hash, and the summary says so. Dropping the name
    on the way (``blockhash=None``) turns both into "not run" and silence — which this catches."""
    _checkpoint(monkeypatch, C, C.tip)
    honest = json.loads(_verify(monkeypatch, tmp_path, C)[0].output)
    bv = honest["mark_anchor"]["block_verification"]
    assert dict(bv["steps"])["blockhash"] == "passed", "the endpoint's name was checked against the header"
    assert bv["named_blockhash"] is None
    assert "named a different block" not in honest["checks"]["block"]["reason"]

    stale = _renonced(C.headers[C.height])
    moved = json.loads(_verify(monkeypatch, tmp_path, C, _server(C, **_reorg(C, named=stale)))[0].output)
    bv = moved["mark_anchor"]["block_verification"]
    assert dict(bv["steps"])["blockhash"] == "differs"
    assert bv["named_blockhash"] == radiant_block_hash(stale)
    assert moved["mark_anchor"]["blockhash"] == C.hash_at(C.height), "the anchor reports the block proved"
    assert (
        f"the endpoint had named a different block, the block proved is {C.hash_at(C.height)}"
        in (moved["checks"]["block"]["reason"])
    )


def test_a_different_name_with_a_header_that_does_not_link_still_exits_2(monkeypatch, tmp_path) -> None:
    """The pair of the test above: the endpoint names one block, and the header its range serves
    at that height is a THIRD one, not on the checkpoint's chain. The proof fails — linkage — so
    this is CONTRADICTED and exits 2, as it did before; the different name is in the reason."""
    _checkpoint(monkeypatch, C, C.tip)
    override = _reorg(C, named=_renonced(C.headers[C.height], 77), served=_renonced(C.headers[C.height], 76))
    r, _ = _verify(monkeypatch, tmp_path, C, _server(C, **override))
    assert r.exit_code == 2, r.output
    text = _flat(r.output)
    assert f"the header at {C.height + 1} does not link to the header served at {C.height}" in text
    assert "also named a different block" in text


def test_an_inherited_anchor_from_before_a_reorganisation_is_verified_as_the_block_proved(
    monkeypatch, tmp_path
) -> None:
    """An inherited anchor that did not come with a verification (the name lookup here is a stub
    that verifies nothing, so this is ``_with_verified_block``'s fallback) is verified with the
    proof of ``_endpoint_pair``'s first endpoint — here another server than the one that gave the
    anchor. Their views of the block at the mark's height can differ honestly; the proof decides,
    and the block it proved is the one reported."""
    _checkpoint(monkeypatch, C, C.tip)
    stale = _renonced(C.headers[C.height])
    server = _server(C)
    other = _server(C, **_reorg(C, named=stale))

    async def _name_at_mark(ctx, *, name, mark_txid, min_confirmations, signer_hash160, **_verify_block):
        async with other:
            anchor = await resolve_anchor_from(
                other, "wss://other.invalid/", mark_txid=mark_txid, min_confirmations=min_confirmations
            )
        return {"resolved": True, "name": name, "anchor": mark_anchor_dict(anchor), "reason": "test"}

    monkeypatch.setattr(glyph_inspect, "_name_at_mark", _name_at_mark)
    r = _run(monkeypatch, tmp_path, server, C.txid, "--min-confirmations", "6", "--wave-name", "alice.rxd")
    out = json.loads(r.output)
    # Not 2: the block did not stop it. (5 is the stubbed name judgement, NOT ESTABLISHED.)
    assert r.exit_code != 2 and out["verdict_failed_checks"] == ["name: NOT ESTABLISHED"], r.output
    anchor = out["mark_anchor"]
    assert anchor["source"] == "wss://other.invalid/"
    assert anchor["block_verification"]["state"] == "VERIFIED"
    assert anchor["blockhash"] == C.hash_at(C.height)
    assert anchor["block_verification"]["named_blockhash"] == radiant_block_hash(stale)
    # The stub's own anchor is untouched: still the other endpoint's word, naming what it named.
    # (The real lookup verifies its anchor itself: see the `--wave-name` tests below.)
    assert out["records"][0]["name_at_mark"]["anchor"]["blockhash"] == radiant_block_hash(stale)


# ── every path: the JSON keys, and the two halves of the human report agree ────────────────


def _confs(chain: Chain, n: int) -> dict[str, Any]:
    """Overrides for an endpoint that REPORTS ``n`` confirmations (and a tip to match), while the
    headers it serves are the real ones — nine of them from the mark's block up."""

    def verbose_or_raw(params: list) -> Any:
        txid, verbose = params
        assert txid == chain.txid
        if not verbose:
            return chain.raw.hex()
        return {"txid": chain.txid, "confirmations": n, "blockhash": chain.hash_at(chain.height)}

    return {
        "blockchain.transaction.get": verbose_or_raw,
        "blockchain.headers.subscribe": lambda p: {
            "height": chain.height + n - 1,
            "hex": chain.headers[chain.tip].hex(),
        },
    }


_NO_MERKLE = {"blockchain.transaction.get_merkle": _rpc_error(-32601, "x")}


def _paths() -> dict[str, tuple[int, dict, str]]:
    """Every path ``checks.block`` can take here: (checkpoint height or -1 for none, overrides, state)."""
    return {
        "verified_checkpoint": (C.tip, {}, "VERIFIED"),
        "verified_work": (C.start, {}, "VERIFIED"),
        "verified_after_a_reorganisation": (C.tip, _reorg(C, named=_renonced(C.headers[C.height])), "VERIFIED"),
        # The endpoint's number is a claim either way; the proved depth (9) is what counts.
        "verified_while_the_endpoint_reports_fewer_than_the_floor": (C.tip, _confs(C, 3), "VERIFIED"),
        "verified_while_the_endpoint_reports_a_million": (C.tip, _confs(C, 1_000_000), "VERIFIED"),
        "merkle_method_not_found": (C.tip, _NO_MERKLE, "CONFIRMED"),
        "header_range_times_out": (
            C.tip,
            {"blockchain.block.headers": NetworkError("ElectrumX request timed out")},
            "CONFIRMED",
        ),
        "headers_short": (
            C.tip,
            {"blockchain.block.headers": lambda p: _headers_reply(C.headers, p[0], 1)},
            "CONFIRMED",
        ),
        "no_checkpoints": (-1, {}, "CONFIRMED"),
        "provisional_and_not_verified": (C.tip, {**_confs(C, 3), **_NO_MERKLE}, "PROVISIONAL"),
    }


def _setup(monkeypatch, case: str) -> ElectrumXClient:
    cp, override, _state = _paths()[case]
    if cp < 0:
        monkeypatch.setitem(radiant_checkpoints.CHECKPOINTS, "mainnet", ())
    else:
        _checkpoint(monkeypatch, C, cp)
    return _server(C, **override)


def _exit_for(state: str) -> int:
    return 5 if state == "PROVISIONAL" else 0


@pytest.mark.parametrize("case", list(_paths()), ids=list(_paths()))
def test_the_json_carries_the_whole_verification_on_every_path(monkeypatch, tmp_path, case: str) -> None:
    state = _paths()[case][2]
    r, _ = _verify(monkeypatch, tmp_path, C, _setup(monkeypatch, case))
    assert r.exit_code == _exit_for(state), r.output
    out = json.loads(r.output)
    anchor = out["mark_anchor"]
    bv = anchor["block_verification"]
    fields = {"state", "claim", "reason", "height", "blockhash", "level", "checkpoint_height", "checkpoint_hash"}
    fields |= {"linked_headers", "floor_work_log2", "verified_depth", "steps", "source", "named_blockhash"}
    assert fields <= set(bv), fields - set(bv)
    assert {"blockhash", "height_is_verified", "confirmations", "verified_confirmations"} <= set(anchor)
    verified = bv["state"] == "VERIFIED"
    assert verified is (state == "VERIFIED")
    assert anchor["height_is_verified"] is verified
    assert out["checks"]["block"]["state"] == state
    assert (bv["claim"] is not None) is verified and (bv["reason"] is None) is verified
    # TWO DEPTHS, NAMED APART: `confirmations` is the endpoint's, `verified_confirmations` the proof's.
    assert anchor["verified_confirmations"] == (bv["verified_depth"] if verified else None)
    assert anchor["provisional"] is (state == "PROVISIONAL")
    assert anchor["deep_enough"] is (state != "PROVISIONAL")
    assert out["verdict_holds"] is (state != "PROVISIONAL")


def _halves(output: str) -> tuple[str, str]:
    """The human report's summary ``block:`` line, and the whole detail block under it."""
    lines = output.splitlines()
    summary = next(ln for ln in lines if ln.strip().startswith("block:") and "VERDICT" not in ln)
    start = next(i for i, ln in enumerate(lines) if ln.startswith("  block:        "))
    end = next(i for i in range(start, len(lines)) if "(source:" in lines[i])
    return _flat(summary), _flat(" ".join(lines[start : end + 1]))


@pytest.mark.parametrize("case", list(_paths()), ids=list(_paths()))
def test_the_summary_the_detail_and_the_json_agree_on_every_path(monkeypatch, tmp_path, case: str) -> None:
    """Two elements on one screen describing the same quantity must agree — with each other and
    with the JSON — on the state, the depth, and whose depth it is."""
    state = _paths()[case][2]
    out = json.loads(_verify(monkeypatch, tmp_path, C, _setup(monkeypatch, case))[0].output)
    r, _ = _verify(monkeypatch, tmp_path, C, _setup(monkeypatch, case), json_out=False)
    assert r.exit_code == _exit_for(state), r.output
    summary, detail = _halves(r.output)
    anchor, bv = out["mark_anchor"], out["mark_anchor"]["block_verification"]
    endpoint = anchor["confirmations"]
    assert f" {state} " in f" {summary} "
    assert ("PROVISIONAL — below the floor you set" in detail) is (state == "PROVISIONAL")
    if state == "VERIFIED":
        proved = anchor["verified_confirmations"]
        assert proved == bv["verified_depth"] >= anchor["min_confirmations"]
        assert "VERIFIED:" in detail and "not verified:" not in detail + summary
        said = f"at least {proved} confirmation(s) verified"
        assert said in summary and said in detail
        if proved != endpoint:
            assert f"the endpoint reports {endpoint}" in summary and f"the endpoint reports {endpoint}" in detail
            assert f" {endpoint} confirmation(s)" not in f" {summary} {detail}", "the endpoint's figure, unlabelled"
        else:
            assert "the endpoint reports" not in summary + detail
    else:
        assert anchor["verified_confirmations"] is None
        assert "VERIFIED:" not in detail and "verified)" not in summary
        assert f"{endpoint} confirmation(s)" in summary and f"{endpoint} confirmation(s)" in detail
        # The same reason, in both halves (the summary may be cut at 200 characters).
        assert f"not verified: {bv['reason']}"[:60] in summary
        assert _flat(f"not verified: {bv['reason']}") in detail


# ── the inherited branch: form 2's anchor crosses the same verification ────────────────────


def test_an_anchor_inherited_from_the_name_lookup_is_verified_too(monkeypatch, tmp_path) -> None:
    """``_verify_anchor`` has two branches — its own lookup, and the anchor inherited from a
    resolved ``--wave-name`` lookup (so the block comes from the endpoint that did NOT supply the
    name binding). Both must cross the verification. The inherited anchor here is built by the
    real ``resolve_anchor_from`` against the fixture, labelled as the OTHER endpoint; the name
    lookup is replaced by a stub that verifies nothing, so this pins the FALLBACK: an inherited
    anchor that arrives without a verification is verified by ``_with_verified_block``. (The real
    lookup verifies its own anchor, and that outcome is reported as it is: the ``--wave-name``
    tests below.)"""
    _checkpoint(monkeypatch, C, C.tip)
    server = _server(C)
    other = _server(C)

    async def _name_at_mark(ctx, *, name, mark_txid, min_confirmations, signer_hash160, **_verify_block):
        async with other:
            anchor = await resolve_anchor_from(
                other, "wss://other.invalid/", mark_txid=mark_txid, min_confirmations=min_confirmations
            )
        return {"resolved": True, "name": name, "anchor": mark_anchor_dict(anchor), "reason": "test"}

    monkeypatch.setattr(glyph_inspect, "_name_at_mark", _name_at_mark)
    r = _run(monkeypatch, tmp_path, server, C.txid, "--min-confirmations", "6", "--wave-name", "alice.rxd")
    out = json.loads(r.output)
    anchor = out["mark_anchor"]
    assert anchor["source"] == "wss://other.invalid/", "the anchor was inherited, not looked up again"
    assert anchor["block_verification"]["state"] == "VERIFIED"
    assert anchor["block_verification"]["source"] == LABEL
    assert out["checks"]["block"]["state"] == "VERIFIED"
    # THE STUB'S ANCHOR IS NOT VERIFIED — it made none — and the reported one is a copy: the
    # verification is applied to `mark_anchor`, not written back into the record.
    own = out["records"][0]["name_at_mark"]["anchor"]
    assert own["block_verification"] is None and own["caveat"] == BOUND_CAVEAT and own["height_is_verified"] is False


# ── --wave-name: the name judgement reads the SAME proof as the block check ─────────────────
#
# Through the REAL `_name_at_mark` and `judge_name_at_mark`: two fixture servers (real
# `ElectrumXClient`s, only `_call` faked) of two distinct operators, B running the indexer
# extension. Only the name's chain WALK is faked — a complete walk whose mint names the label and
# whose target is the mark's own signer, placed 100 blocks before the mark by both servers — as
# `tests/test_hashmark_verify_one_record.py` does, because forging a mainnet name's chain is not
# the point. B answers the binding, so the anchor, and the proof of its block, are A's.

A_URL, B_URL = "wss://a.invalid/", "wss://b.invalid/"
WAVE_LABEL = "alice"
MINT = "ab" * 32


def _signer_address(chain: Chain) -> str:
    from pyrxd.base58 import base58check_encode
    from pyrxd.constants import NETWORK_ADDRESS_PREFIX_DICT, Network

    payload = glyph_inspect._classify_raw_tx(chain.txid, chain.raw, network="mainnet")
    (h160,) = {row["hashmark"]["attestation"]["recovered_hash160"] for row in payload["outputs"] if row.get("hashmark")}
    return base58check_encode(NETWORK_ADDRESS_PREFIX_DICT[Network.MAINNET] + bytes.fromhex(h160))


def _name_walk(monkeypatch, chain: Chain) -> None:
    import cbor2

    from pyrxd.glyph import mutable_chain_discovery as mcd
    from pyrxd.glyph.mutable_chain import ChainStep, MutableChainWalk

    target = _signer_address(chain)
    placed = chain.height - 100

    async def walk(*, mint_txid, discovery_source, tip_source, **_):
        attrs = {"name": WAVE_LABEL, "domain": "rxd", "target": target}
        step = ChainStep(
            txid=mint_txid,
            mut_vout=1,
            kind="mint",
            attrs={"target": target},
            envelope_cbor=cbor2.dumps({"p": [2, 5, 11], "name": f"{WAVE_LABEL}.rxd", "attrs": attrs}),
        )
        w = MutableChainWalk(
            ref=f"{mint_txid}:1",
            steps=(step,),
            tip_txid=mint_txid,
            tip_vout=1,
            tip_proved_unspent=True,
            complete=discovery_source != tip_source,
        )
        d = mcd.ChainDiscovery(
            mint_txid=mint_txid,
            candidates=(),
            heights={mint_txid: placed},
            hops=0,
            fetches=1,
            capped=False,
            stopped="tip",
            source=discovery_source,
        )
        return mcd.DiscoveredWalk(walk=w, discovery=d, tip_heights={mint_txid: placed})

    monkeypatch.setattr(mcd, "walk_discovered_chain", walk)


def _indexer(chain: Chain) -> ElectrumXClient:
    """B: an honest fixture server that also answers ``wave.resolve`` for the label."""
    target = _signer_address(chain)

    def resolve(params: list) -> Any:
        return {"name": WAVE_LABEL, "ref": f"{MINT}_0", "target": target} if params == [WAVE_LABEL] else None

    return _server(chain, **{"wave.resolve": resolve})


def _run_name(monkeypatch, tmp_path, a: ElectrumXClient, b: ElectrumXClient, *, json_out: bool = True):
    _name_walk(monkeypatch, C)
    monkeypatch.setattr(CliContext, "make_client", lambda self: a)
    monkeypatch.setattr(glyph_inspect, "_endpoint_pair", lambda ctx: (a, A_URL, b, B_URL))
    head = ["--wallet", str(tmp_path / "w.dat"), "--config", str(tmp_path / "c.toml")]
    args = ["verify", C.txid, "--min-confirmations", "6", "--wave-name", f"{WAVE_LABEL}.rxd"]
    return CliRunner().invoke(cli, [*head, *(["--json"] if json_out else []), *args])


def _name_detail(output: str) -> str:
    lines = output.splitlines()
    start = next(i for i, ln in enumerate(lines) if "at the mark's block" in ln)
    end = next((i for i in range(start + 1, len(lines)) if not lines[i].startswith("      ")), len(lines))
    return _flat(" ".join(lines[start:end]))


@pytest.mark.parametrize("case", list(_paths()), ids=list(_paths()))
def test_under_wave_name_the_name_the_block_and_the_json_agree_on_every_path(monkeypatch, tmp_path, case) -> None:
    """Every block path, with ``--wave-name``: the name judgement's depth test and the block check
    read ONE verification, so "too shallow" beside "at or past the floor" (or the reverse) cannot
    be printed. Under VERIFIED the proved depth decides both; otherwise the endpoint's figure
    decides both, exactly as without the proof."""
    state = _paths()[case][2]
    out = json.loads(_run_name(monkeypatch, tmp_path, _setup(monkeypatch, case), _indexer(C)).output)
    r = _run_name(monkeypatch, tmp_path, _setup(monkeypatch, case), _indexer(C), json_out=False)
    assert r.exit_code == _exit_for(state), r.output
    anchor, nam = out["mark_anchor"], out["records"][0]["name_at_mark"]
    assert out["checks"]["block"]["state"] == state
    # ONE anchor: the block check reports the very dict the name judgement produced.
    assert anchor == nam["anchor"]
    assert anchor["source"] == A_URL and nam["binding_source"] == B_URL
    shallow = state == "PROVISIONAL"
    assert nam["provisional"] is anchor["provisional"] is shallow
    if shallow:
        assert out["checks"]["name"]["state"] == "NOT ESTABLISHED"
        # The endpoint's figure, the same one the block line prints as the endpoint's word.
        said = f"the mark is {anchor['confirmations']} confirmations deep, below the 6 required — too shallow"
        assert said in out["checks"]["name"]["reason"]
    else:
        assert out["checks"]["name"]["state"] == "ESTABLISHED", out["checks"]["name"]["reason"]
        assert "too shallow" not in r.output
    detail = _name_detail(r.output)
    proved, endpoint = anchor["verified_confirmations"], anchor["confirmations"]
    note = f"at least {proved} confirmation(s) verified; the endpoint reports {endpoint}"
    assert (note in detail) is (state == "VERIFIED" and proved != endpoint), detail
    summary, block_detail = _halves(r.output)
    if state == "VERIFIED" and proved != endpoint:
        # The same two numbers, each labelled the same way, as the block's own line.
        assert f"at least {proved} confirmation(s) verified" in block_detail
        assert f"the endpoint reports {endpoint}" in block_detail and f"the endpoint reports {endpoint}" in summary


def test_the_reviewers_scenario_an_endpoint_a_block_behind_the_floor(monkeypatch, tmp_path) -> None:
    """HONEST: A's index reports 5 confirmations against a floor of 6; its proof shows the block 9
    deep. The name was judged "5 confirmations deep ... too shallow" beside ``block: VERIFIED ...
    at least 9``, exit 5. Now the name is judged by the proved depth too: ESTABLISHED, exit 0, and
    the name's line says whose depth it used."""
    _checkpoint(monkeypatch, C, C.tip)
    a = _server(C, **_confs(C, 5))
    out = json.loads(_run_name(monkeypatch, tmp_path, a, _indexer(C)).output)
    assert out["verdict_holds"] is True, out["verdict_failed_checks"]
    assert out["checks"]["name"]["state"] == "ESTABLISHED"
    assert out["checks"]["block"]["state"] == "VERIFIED"
    nam = out["records"][0]["name_at_mark"]
    assert nam["form"] == 2 and nam["provisional"] is False
    assert nam["anchor"]["verified_confirmations"] == 9 and nam["anchor"]["confirmations"] == 5
    assert out["mark_anchor"]["provisional"] is nam["anchor"]["provisional"] is False
    r = _run_name(monkeypatch, tmp_path, _server(C, **_confs(C, 5)), _indexer(C), json_out=False)
    assert r.exit_code == 0, r.output
    assert "too shallow" not in r.output
    assert "at least 9 confirmation(s) verified; the endpoint reports 5" in _name_detail(r.output)


def test_a_proof_shallower_than_the_floor_leaves_the_name_too_shallow(monkeypatch, tmp_path) -> None:
    """The pair of the test above: the proof can only RAISE the depth to proved. Here it links and
    carries the work, but the server serves headers only 4 deep against a floor of 6 — NOT
    VERIFIED — so the endpoint's 5 decides both checks, as before: too shallow, PROVISIONAL, exit 5."""
    _checkpoint(monkeypatch, C, C.start)  # the proof-of-work level, so depth is what fails
    short = {h: b for h, b in C.headers.items() if h <= C.height + 3}
    a = _server(C, **_confs(C, 5), **{"blockchain.block.headers": lambda p: _headers_reply(short, *p)})
    r = _run_name(monkeypatch, tmp_path, a, _indexer(C))
    assert r.exit_code == 5, r.output
    out = json.loads(r.output)
    bv = out["mark_anchor"]["block_verification"]
    assert bv["state"] == "NOT VERIFIED" and bv["verified_depth"] == 4 < 6, bv
    assert out["mark_anchor"]["verified_confirmations"] is None
    assert out["checks"]["block"]["state"] == "PROVISIONAL"
    assert out["checks"]["name"]["state"] == "NOT ESTABLISHED"
    assert "the mark is 5 confirmations deep, below the 6 required" in out["checks"]["name"]["reason"]
    assert out["records"][0]["name_at_mark"]["provisional"] is True


def test_a_block_that_does_not_verify_leaves_the_name_on_the_endpoints_figure(monkeypatch, tmp_path) -> None:
    """NOT VERIFIED (a server without the merkle method): the name judgement is exactly what it was
    before any proof existed — the endpoint's 3 is too shallow, with the unchanged sentence."""
    _checkpoint(monkeypatch, C, C.tip)
    a = _server(C, **_confs(C, 3), **_NO_MERKLE)
    out = json.loads(_run_name(monkeypatch, tmp_path, a, _indexer(C)).output)
    assert out["checks"]["block"]["state"] == "PROVISIONAL"
    assert out["checks"]["name"]["reason"] == (
        "the mark is 3 confirmations deep, below the 6 required — too shallow to build a claim on"
    )


@pytest.mark.parametrize("case", list(_contradictions()), ids=list(_contradictions()))
def test_under_wave_name_a_contradicting_proof_still_exits_2(monkeypatch, tmp_path, case: str) -> None:
    """The verification made in the name lookup is reported, not repeated — and it crosses the
    same CONTRADICTED refusal as one made by ``_verify_anchor``."""
    _checkpoint(monkeypatch, C, C.tip)
    r = _run_name(monkeypatch, tmp_path, _server(C, **_contradictions()[case]), _indexer(C))
    assert r.exit_code == 2, r.output
    text = _flat(r.output)
    assert "contradicts the height reported for the mark" in text and A_URL in text


def test_under_wave_name_the_block_is_proved_once(monkeypatch, tmp_path) -> None:
    """ONE proof, so the name and the block cannot be judged from two: the merkle branch is fetched
    once across both endpoints, from the one that gave the anchor."""
    _checkpoint(monkeypatch, C, C.tip)
    a, b = _server(C), _indexer(C)
    r = _run_name(monkeypatch, tmp_path, a, b)
    assert r.exit_code == 0, r.output
    merkles = [c for s in (a, b) for c in s.calls if c[0] == "blockchain.transaction.get_merkle"]
    assert len(merkles) == 1 and any(c[0] == "blockchain.transaction.get_merkle" for c in a.calls)
    assert json.loads(r.output)["mark_anchor"]["block_verification"]["source"] == A_URL


def test_a_proved_depth_can_only_lift_a_shallow_mark_never_sink_a_deep_one_below_the_floor() -> None:
    """`MarkAnchor.provisional` is the one depth test the judge and the dict both derive from. A
    proved depth is set only from a VERIFIED outcome that reaches the floor (`proven_depth`), so it
    lifts the endpoint's 5 to proved; a VERIFIED-looking outcome below the floor, or one about
    another height, sets nothing. An anchor built by hand with a proved depth below the floor is
    provisional whatever the endpoint reports — and the judge says whose number it was."""
    from dataclasses import replace

    from pyrxd.glyph.mark_anchor import MarkAnchor, proven_depth, with_proven_depth
    from pyrxd.glyph.mark_block import NOT_VERIFIED, VERIFIED, BlockVerification
    from pyrxd.glyph.wave_identity import judge_name_at_mark

    shallow = MarkAnchor(txid=C.txid, height=C.height, confirmations=5, min_confirmations=6, source=A_URL)
    proof = BlockVerification(state=VERIFIED, claim="c", reason=None, height=C.height, verified_depth=9)
    assert shallow.provisional and not with_proven_depth(shallow, proof).provisional
    for no in (
        replace(proof, verified_depth=5),  # below the floor
        replace(proof, height=C.height + 1),  # another height
        replace(proof, state=NOT_VERIFIED, claim=None, reason="r"),
        None,
    ):
        assert proven_depth(no, height=C.height, min_confirmations=6) is None
        assert with_proven_depth(shallow, no).provisional
    by_hand = replace(shallow, confirmations=100, verified_confirmations=4)
    assert by_hand.provisional
    verdict = judge_name_at_mark(
        ref="00" * 36, name="alice.rxd", binding_source=B_URL, anchor=by_hand, walk=None, height_reports=[]
    )
    assert verdict.form == 1 and verdict.provisional
    assert "proved only 4 confirmations deep (the endpoint reports 100), below the 6 required" in (
        verdict.degraded_reason
    )


@pytest.mark.parametrize("wave_name", [False, True], ids=["own_lookup", "wave_name"])
@pytest.mark.parametrize("reorganised", [False, True], ids=["honest", "reorganised"])
def test_header_bound_names_the_block_the_endpoint_named(monkeypatch, tmp_path, wave_name, reorganised) -> None:
    """WHAT ``header_bound: true`` IS ABOUT, pinned. It says the endpoint's height was checked
    against the endpoint's own single header (``blockchain.block.header``) — the block it NAMED.
    After a reorganisation the anchor's ``blockhash`` is the block PROVED, a different one, so the
    header that binding checked is ``block_verification.named_blockhash``; ``blockhash`` is it only
    when ``named_blockhash`` is null. Checked against the header the endpoint really served."""
    _checkpoint(monkeypatch, C, C.tip)
    single = _renonced(C.headers[C.height]) if reorganised else C.headers[C.height]
    override = _reorg(C, named=single) if reorganised else {}
    a = _server(C, **override)
    if wave_name:
        r = _run_name(monkeypatch, tmp_path, a, _indexer(C))
    else:
        r, _ = _verify(monkeypatch, tmp_path, C, a)
    assert r.exit_code == 0, r.output
    anchor = json.loads(r.output)["mark_anchor"]
    bv = anchor["block_verification"]
    assert ["blockchain.block.header", [C.height]] in [[m, p] for m, p in a.calls], "the binding read that header"
    assert anchor["header_bound"] is True and bv["state"] == "VERIFIED"
    bound_to = bv["named_blockhash"] or anchor["blockhash"]
    assert bound_to == radiant_block_hash(single)
    assert anchor["blockhash"] == C.hash_at(C.height)
    assert (bv["named_blockhash"] is not None) is reorganised
    assert (anchor["blockhash"] == radiant_block_hash(single)) is not reorganised


# ── #806: the name's form-2 caveat and the block line agree, on one screen ─────────────────────
#
# The name section's caveat carried "block heights — the mark's and every chain step's — ... are
# NOT verified ... Nothing checks proof-of-work or merkle inclusion" beside `block: VERIFIED ...
# merkle inclusion proved`. Its sentence about the MARK's height now follows the one predicate the
# block line follows; its sentences about the chain STEPS' heights stay the endpoints' word.


def _unverified_form2_caveat(nam: dict) -> str:
    from pyrxd.glyph.wave_identity import _corroborated_caveat

    return _corroborated_caveat(nam["heights"]["agreed_by"], mark_header_bound=True)


_SHORT_HEADERS = {"blockchain.block.headers": lambda p: _headers_reply(C.headers, p[0], 1)}


@pytest.mark.parametrize("state", ["VERIFIED", "NOT VERIFIED", "INCLUSION ONLY"])
def test_806_the_name_caveat_and_the_block_line_agree_under_verify(monkeypatch, tmp_path, state: str) -> None:
    """``INCLUSION ONLY``: the headers are served short, so the merkle branch is checked and PASSES
    while the height does not verify. The block line then says the branch leads to the header
    served (``INCLUSION_ONLY_CAVEAT``), and the name's caveat must not say nothing checks merkle
    inclusion beside it."""
    _checkpoint(monkeypatch, C, C.tip)

    def a() -> ElectrumXClient:
        if state == "VERIFIED":
            return _server(C)
        return _server(C, **(_SHORT_HEADERS if state == "INCLUSION ONLY" else _NO_MERKLE))

    r = _run_name(monkeypatch, tmp_path, a(), _indexer(C), json_out=False)
    assert r.exit_code == 0, r.output
    out = json.loads(_run_name(monkeypatch, tmp_path, a(), _indexer(C)).output)
    nam = out["records"][0]["name_at_mark"]
    assert nam["form"] == 2 and out["checks"]["name"]["state"] == "ESTABLISHED", "the premise: a form-2 caveat"
    bv = out["mark_anchor"]["block_verification"]
    assert bv["state"] == ("NOT VERIFIED" if state == "INCLUSION ONLY" else state), "the premise: the block's state"
    assert (dict(bv["steps"]).get("merkle") == "passed") is (state != "NOT VERIFIED"), "the premise: the merkle step"
    text = _flat(r.output)
    caveat = _flat(nam["caveat"])
    assert f"({caveat})" in text, "the name's caveat is not on the screen the block line is on"
    if state == "VERIFIED":
        assert "block: VERIFIED" in text
        assert "The mark's height is also VERIFIED by pyrxd" in caveat
        assert "The chain steps' heights are NOT verified" in caveat, "the step heights are still the endpoints' word"
        # Nothing on the screen says the MARK's height is unverified.
        assert "and are NOT verified" not in caveat
        assert "Nothing checks proof-of-work or merkle inclusion" not in text
        assert "pyrxd checks no" not in text
    elif state == "INCLUSION ONLY":
        assert "block: CONFIRMED" in text and "not verified:" in text
        # The block line and the name's caveat say the SAME thing about the mark's height: the
        # one constant, whole, in both.
        assert out["mark_anchor"]["caveat"] == INCLUSION_ONLY_CAVEAT
        assert _flat(INCLUSION_ONLY_CAVEAT) in caveat
        assert text.count(_flat(INCLUSION_ONLY_CAVEAT)) >= 2, "the block line and the name's caveat"
        assert "Nothing checks proof-of-work or merkle inclusion" not in text
        assert "pyrxd checks no" not in text
        assert "VERIFIED by pyrxd" not in text
        assert "chain steps' proof-of-work or merkle inclusion" in caveat, "the steps are still unchecked"
    else:
        assert "block: CONFIRMED" in text and "not verified:" in text
        assert caveat == _flat(_unverified_form2_caveat(nam)), "the unverified caveat changed"
        assert "VERIFIED by pyrxd" not in text


def test_806_glyph_inspect_keeps_the_unverified_caveat_because_it_verifies_nothing(monkeypatch, tmp_path) -> None:
    """``glyph inspect --wave-name`` does not verify the block (only ``pyrxd verify`` does), so its
    name caveat must still say the mark's height is not verified — and nothing on its screen may
    say otherwise. The shared wording must not leak the verified sentence here."""
    _checkpoint(monkeypatch, C, C.tip)
    _name_walk(monkeypatch, C)
    a, b = _server(C), _indexer(C)
    monkeypatch.setattr(CliContext, "make_client", lambda self: a)
    monkeypatch.setattr(glyph_inspect, "_endpoint_pair", lambda ctx: (a, A_URL, b, B_URL))
    head = ["--wallet", str(tmp_path / "w.dat"), "--config", str(tmp_path / "c.toml")]
    args = ["glyph", "inspect", C.txid, "--fetch", "--wave-name", f"{WAVE_LABEL}.rxd", "--min-confirmations", "6"]
    r = CliRunner().invoke(cli, [*head, *args])
    assert r.exit_code == 0, r.output
    rj = CliRunner().invoke(cli, [*head, "--json", *args])
    payload = json.loads(rj.output)
    (nam,) = [row["hashmark"]["name_at_mark"] for row in payload["outputs"] if row.get("hashmark")]
    assert nam["form"] == 2, "the premise: a form-2 caveat"
    assert nam["anchor"]["block_verification"] is None, "the premise: glyph inspect verified nothing"
    text = _flat(r.output)
    assert f"({_flat(_unverified_form2_caveat(nam))})" in text
    assert "VERIFIED by pyrxd" not in text
    assert not {m for s in (a, b) for m, _ in s.calls} & _BLOCK_RPCS


def test_806_a_degraded_name_verdict_carries_the_marks_own_caveat() -> None:
    """A form-2 verdict that DEGRADES hands the anchor's caveat on as its own (``--json``'s
    ``name_at_mark.caveat``). ``with_proven_depth`` gives it the caveat the block line has: the
    claim when proved, the inclusion-only caveat when the branch passed but the height did not
    verify, and the endpoint's-word caveat otherwise."""
    from pyrxd.glyph.mark_anchor import MarkAnchor, with_proven_depth
    from pyrxd.glyph.mark_block import BlockVerification
    from pyrxd.glyph.wave_identity import judge_name_at_mark

    base = MarkAnchor(
        txid=C.txid,
        height=C.height,
        confirmations=9,
        min_confirmations=6,
        source="wss://one.invalid/",
        caveat=BOUND_CAVEAT,
        header_bound=True,
        blockhash=C.hash_at(C.height),
    )
    proved = BlockVerification(
        state="VERIFIED",
        claim="THE CLAIM.",
        reason=None,
        height=C.height,
        verified_depth=9,
        steps=(("merkle", "passed"),),
    )
    inclusion = BlockVerification(
        state="NOT VERIFIED", claim=None, reason="r", height=C.height, steps=(("merkle", "passed"),)
    )
    nothing = BlockVerification(state="NOT VERIFIED", claim=None, reason="r", height=C.height)
    for verification, caveat in ((proved, "THE CLAIM."), (inclusion, INCLUSION_ONLY_CAVEAT), (nothing, BOUND_CAVEAT)):
        anchor = with_proven_depth(base, verification)
        assert anchor.caveat == caveat
        # One source for both the binding and the block: the judge degrades on its second rule.
        verdict = judge_name_at_mark(
            ref="ab" * 32 + ":1",
            name="alice.rxd",
            binding_source=anchor.source,
            anchor=anchor,
            walk=None,  # type: ignore[arg-type]  # never reached: the verdict degrades first
            height_reports=[],
        )
        assert verdict.form == 1 and verdict.caveat == caveat
