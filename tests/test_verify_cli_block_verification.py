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

WHAT IS NOT PROVED HERE: that the pages verify anything (phase 3 of #799), or that a live server
answers these RPCs this way today (the fixture was captured 2026-09-30).
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


def test_a_mark_past_the_shipped_tables_reach_is_confirmed_with_the_reason(monkeypatch, tmp_path) -> None:
    """The SHIPPED table, unpatched. Block 468,521 is ~2,800 past its newest checkpoint (465,696),
    and these 17 headers do not reach back to it — so the server's short header range is what
    stops verification, honestly, and the verdict stands."""
    chain = Chain(PYRXD)
    assert radiant_checkpoints.CHECKPOINTS["mainnet"][-1][0] < chain.start
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


# ── every path: the JSON keys, and the two halves of the human report agree ────────────────


def _paths() -> dict[str, tuple[int, dict]]:
    return {
        "verified_checkpoint": (C.tip, {}),
        "verified_work": (C.start, {}),
        "merkle_method_not_found": (C.tip, {"blockchain.transaction.get_merkle": _rpc_error(-32601, "x")}),
        "header_range_times_out": (C.tip, {"blockchain.block.headers": NetworkError("ElectrumX request timed out")}),
        "headers_short": (C.tip, {"blockchain.block.headers": lambda p: _headers_reply(C.headers, p[0], 1)}),
        "no_checkpoints": (-1, {}),
    }


def _setup(monkeypatch, case: str) -> ElectrumXClient:
    cp, override = _paths()[case]
    if cp < 0:
        monkeypatch.setitem(radiant_checkpoints.CHECKPOINTS, "mainnet", ())
    else:
        _checkpoint(monkeypatch, C, cp)
    return _server(C, **override)


@pytest.mark.parametrize("case", list(_paths()), ids=list(_paths()))
def test_the_json_carries_the_whole_verification_on_every_path(monkeypatch, tmp_path, case: str) -> None:
    r, _ = _verify(monkeypatch, tmp_path, C, _setup(monkeypatch, case))
    assert r.exit_code == 0, r.output
    out = json.loads(r.output)
    anchor = out["mark_anchor"]
    bv = anchor["block_verification"]
    fields = {"state", "claim", "reason", "height", "blockhash", "level", "checkpoint_height", "checkpoint_hash"}
    fields |= {"linked_headers", "floor_work_log2", "verified_depth", "steps", "source"}
    assert fields <= set(bv), fields - set(bv)
    assert "blockhash" in anchor and "height_is_verified" in anchor
    verified = bv["state"] == "VERIFIED"
    assert verified is case.startswith("verified_")
    assert anchor["height_is_verified"] is verified
    assert (out["checks"]["block"]["state"] == "VERIFIED") is verified
    assert (bv["claim"] is not None) is verified and (bv["reason"] is None) is verified
    # The form-2-free record copy is untouched: nothing but the verify anchor was verified.
    assert out["verdict_holds"] is True


@pytest.mark.parametrize("case", list(_paths()), ids=list(_paths()))
def test_the_summary_and_the_detail_agree_on_every_path(monkeypatch, tmp_path, case: str) -> None:
    """Two elements on one screen describing the same quantity must agree after the change."""
    server = _setup(monkeypatch, case)
    r, _ = _verify(monkeypatch, tmp_path, C, server, json_out=False)
    assert r.exit_code == 0, r.output
    summary = next(ln for ln in r.output.splitlines() if ln.strip().startswith("block:") and "VERDICT" not in ln)
    detail_start = next(i for i, ln in enumerate(r.output.splitlines()) if ln.startswith("  block:        "))
    detail = _flat(" ".join(r.output.splitlines()[detail_start : detail_start + 14]))
    if case.startswith("verified_"):
        assert " VERIFIED " in f" {summary} " and "VERIFIED:" in detail
        assert "not verified:" not in detail and "not verified:" not in summary
    else:
        assert " CONFIRMED " in f" {summary} " and "VERIFIED:" not in detail
        # The same reason, in both halves (the summary may be cut at 200 characters).
        reason = json.loads(_verify(monkeypatch, tmp_path, C, _setup(monkeypatch, case))[0].output)["mark_anchor"][
            "block_verification"
        ]["reason"]
        assert f"not verified: {reason}"[:60] in _flat(summary)
        assert _flat(f"not verified: {reason}") in detail


# ── the inherited branch: form 2's anchor crosses the same verification ────────────────────


def test_an_anchor_inherited_from_the_name_lookup_is_verified_too(monkeypatch, tmp_path) -> None:
    """``_verify_anchor`` has two branches — its own lookup, and the anchor inherited from a
    resolved ``--wave-name`` lookup (so the block comes from the endpoint that did NOT supply the
    name binding). Both must cross the verification. The inherited anchor here is built by the
    real ``resolve_anchor_from`` against the fixture, labelled as the OTHER endpoint; the name
    judgement is replaced, since forging a mainnet name's chain is not the point."""
    _checkpoint(monkeypatch, C, C.tip)
    server = _server(C)
    other = _server(C)

    async def _name_at_mark(ctx, *, name, mark_txid, min_confirmations, signer_hash160):
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
    # FORM 2'S OWN ANCHOR IS NOT VERIFIED: its caveat is unchanged (plan risk 9).
    own = out["records"][0]["name_at_mark"]["anchor"]
    assert own["block_verification"] is None and own["caveat"] == BOUND_CAVEAT and own["height_is_verified"] is False
