"""``ElectrumXClient.get_block_headers`` and ``get_transaction_id_from_pos`` — what the block
verifier in ``pyrxd verify`` fetches, refused when malformed and accepted when honest.

Each refusal is paired with the honest reply it was derived from, so a refusal cannot pass because
the client refuses everything. The honest replies are the real ones two mainnet servers gave
(``tests/fixtures/mark_block_fixtures_2026-09-30.json``): 17 consecutive headers around each of
two HashMarks, and each block's coinbase branch (``id_from_pos(height, 0, true)``).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from pyrxd.network.electrumx import MAX_BLOCK_HEADERS_PER_CALL, ElectrumXClient
from pyrxd.network.failover import FailoverElectrumXClient
from pyrxd.security.errors import NetworkError, ValidationError
from pyrxd.security.types import BlockHeight

_FIX = json.loads(
    (Path(__file__).resolve().parent.parent / "fixtures" / "mark_block_fixtures_2026-09-30.json").read_text(
        encoding="utf-8"
    )
)["fixtures"]
_FX = _FIX["a1a86ab4503901af4df3d092fcf668b07c03c5cd89240fe918ae70e02e045916"]
_START = _FX["headers_start"]
_HEX = _FX["headers_hex"]
_N = len(_HEX) // 160


def _client_answering(reply: Any) -> ElectrumXClient:
    client = ElectrumXClient(["wss://electrum.invalid:50002"])
    calls: list[tuple[str, list]] = []

    async def _call(method: str, params: list) -> Any:
        calls.append((method, params))
        return reply

    client._call = _call  # type: ignore[method-assign]
    client.calls = calls  # type: ignore[attr-defined]
    return client


def _honest(count: int = _N) -> dict:
    return {"count": count, "hex": _HEX[: 160 * count], "max": 2016}


# ── get_block_headers: honest ───────────────────────────────────────────────────────────────


async def test_the_real_reply_is_split_into_its_80_byte_headers() -> None:
    assert _N == 17, "premise: the fixture carries 17 headers"
    client = _client_answering(_honest())
    got = await client.get_block_headers(BlockHeight(_START), _N)
    raw = bytes.fromhex(_HEX)
    assert got == [raw[i * 80 : (i + 1) * 80] for i in range(_N)]
    assert client.calls == [("blockchain.block.headers", [_START, _N])]  # type: ignore[attr-defined]


async def test_fewer_headers_than_asked_is_honest_near_the_tip() -> None:
    """A range that runs past the server's tip comes back short. That is an answer, not a lie."""
    got = await _client_answering(_honest(5)).get_block_headers(BlockHeight(_START), 2016)
    assert len(got) == 5 and all(len(h) == 80 for h in got)


async def test_an_empty_range_past_the_tip_is_an_empty_list() -> None:
    assert await _client_answering({"count": 0, "hex": "", "max": 2016}).get_block_headers(BlockHeight(_START), 3) == []


async def test_uppercase_hex_is_accepted() -> None:
    reply = _honest(2)
    reply["hex"] = reply["hex"].upper()
    got = await _client_answering(reply).get_block_headers(BlockHeight(_START), 2)
    assert got == [bytes.fromhex(_HEX[:160]), bytes.fromhex(_HEX[160:320])]


# ── get_block_headers: refused ──────────────────────────────────────────────────────────────


def _malformed() -> list[tuple[str, Any]]:
    good = _honest(4)
    return [
        ("not_an_object", _HEX[:640]),
        ("count_missing", {"hex": good["hex"], "max": 2016}),
        ("count_not_an_int", {**good, "count": "4"}),
        ("count_a_bool", {**good, "count": True}),
        ("count_fractional", {**good, "count": 4.5}),
        ("count_infinite", {**good, "count": float("inf")}),
        ("count_negative", {**good, "count": -1}),
        ("count_more_than_asked", {"count": 5, "hex": _HEX[:800], "max": 2016}),
        ("hex_missing", {"count": 4, "max": 2016}),
        ("hex_not_a_string", {"count": 4, "hex": list(bytes.fromhex(good["hex"])), "max": 2016}),
        ("hex_one_header_short", {"count": 4, "hex": _HEX[:480], "max": 2016}),
        ("hex_one_char_long", {"count": 4, "hex": good["hex"] + "0", "max": 2016}),
        ("hex_not_hex", {"count": 4, "hex": "zz" + good["hex"][2:], "max": 2016}),
        # `bytes.fromhex` skips whitespace, so a same-length string with a space would decode short.
        ("hex_with_whitespace", {"count": 4, "hex": " " + good["hex"][1:], "max": 2016}),
    ]


@pytest.mark.parametrize(("case", "reply"), _malformed(), ids=[c for c, _ in _malformed()])
async def test_a_malformed_reply_is_refused(case: str, reply: Any) -> None:
    with pytest.raises(NetworkError):
        await _client_answering(reply).get_block_headers(BlockHeight(_START), 4)


async def test_the_refusals_are_of_replies_one_edit_from_an_honest_one() -> None:
    """The pair to the refusals: the reply they were all derived from IS accepted."""
    assert len(await _client_answering(_honest(4)).get_block_headers(BlockHeight(_START), 4)) == 4


@pytest.mark.parametrize("count", [0, -1, MAX_BLOCK_HEADERS_PER_CALL + 1, True, 1.0])
async def test_an_out_of_range_count_is_refused_before_anything_is_sent(count: Any) -> None:
    client = _client_answering(_honest())
    with pytest.raises(ValidationError):
        await client.get_block_headers(BlockHeight(_START), count)
    assert client.calls == []  # type: ignore[attr-defined]


async def test_the_largest_count_a_server_serves_is_allowed() -> None:
    client = _client_answering(_honest())
    assert len(await client.get_block_headers(BlockHeight(_START), MAX_BLOCK_HEADERS_PER_CALL)) == _N
    assert MAX_BLOCK_HEADERS_PER_CALL == 2016


# ── get_transaction_id_from_pos ─────────────────────────────────────────────────────────────


@pytest.mark.parametrize("fx", list(_FIX.values()), ids=[t[:8] for t in _FIX])
async def test_the_real_coinbase_reply_is_returned_validated(fx: dict) -> None:
    height = fx["merkle"]["block_height"]
    client = _client_answering(fx["coinbase_merkle"])
    got = await client.get_transaction_id_from_pos(BlockHeight(height), 0)
    assert got == {"tx_hash": fx["coinbase_merkle"]["tx_hash"], "merkle": fx["coinbase_merkle"]["merkle"]}
    assert client.calls == [("blockchain.transaction.id_from_pos", [height, 0, True])]  # type: ignore[attr-defined]


def _bad_coinbase() -> list[tuple[str, Any]]:
    good = _FX["coinbase_merkle"]
    return [
        ("not_an_object", good["tx_hash"]),
        ("tx_hash_missing", {"merkle": good["merkle"]}),
        ("tx_hash_short", {**good, "tx_hash": good["tx_hash"][:62]}),
        ("merkle_missing", {"tx_hash": good["tx_hash"]}),
        ("merkle_a_string", {**good, "merkle": "".join(good["merkle"])}),
        ("merkle_entry_short", {**good, "merkle": [good["merkle"][0][:62], *good["merkle"][1:]]}),
        ("merkle_too_deep", {**good, "merkle": [good["merkle"][0]] * 33}),
    ]


@pytest.mark.parametrize(("case", "reply"), _bad_coinbase(), ids=[c for c, _ in _bad_coinbase()])
async def test_a_malformed_id_from_pos_reply_is_refused(case: str, reply: Any) -> None:
    with pytest.raises(NetworkError):
        await _client_answering(reply).get_transaction_id_from_pos(BlockHeight(460572), 0)


async def test_a_32_level_coinbase_branch_is_the_deepest_accepted() -> None:
    good = _FX["coinbase_merkle"]
    got = await _client_answering({**good, "merkle": [good["merkle"][0]] * 32}).get_transaction_id_from_pos(
        BlockHeight(460572), 0
    )
    assert len(got["merkle"]) == 32


# ── the failover wrapper forwards both ──────────────────────────────────────────────────────


async def test_the_failover_client_forwards_both_new_methods() -> None:
    """`pyrxd verify` reaches ElectrumX through `FailoverElectrumXClient`; a method it does not
    forward is an AttributeError that the verification reports as NOT VERIFIED — silently, forever."""
    inner_headers = _client_answering(_honest())
    inner_coinbase = _client_answering(_FX["coinbase_merkle"])
    fo = FailoverElectrumXClient.__new__(FailoverElectrumXClient)
    ran: list[str] = []
    inner = {"get_block_headers": inner_headers, "get_transaction_id_from_pos": inner_coinbase}

    async def _run(description: str, op: Any, **_: Any) -> Any:
        ran.append(description)
        return await op(inner[description])

    fo._run = _run  # type: ignore[method-assign]
    assert len(await fo.get_block_headers(BlockHeight(_START), _N)) == _N
    cb = await fo.get_transaction_id_from_pos(BlockHeight(460572), 0)
    assert cb["tx_hash"] == _FX["coinbase_merkle"]["tx_hash"]
    assert ran == ["get_block_headers", "get_transaction_id_from_pos"]
