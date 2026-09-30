"""``get_transaction_merkle`` against the REAL replies two mainnet servers gave for two HashMarks.

Through 0.25.1 this method raised on every real multi-level proof: it put every sibling of every
level into BUMP level 0. Measured 2026-09-29/30, read-only, on both shipped servers
(``wss://electrumx.radiant4people.com:50022/`` and ``wss://electrumx.radiantcore.org/``, which
returned identical data):

* ``a1a86ab4…5916`` (block 460,572, pos 4, depth 4) raised
  ``Could not construct MerklePath: Missing hash for index 3 at height 0``;
* ``aa66b046…c86e`` (block 468,521, pos 7, depth 5) raised
  ``Could not construct MerklePath: Duplicate offset: 1, at height: 0``.

No test caught it because the only tests fed it one-sibling branches, where "every level in level
0" and "one level per depth" are the same thing. These replies are what the servers actually sent,
saved verbatim in ``tests/fixtures/mark_block_fixtures_2026-09-30.json``, and each is checked
against the merkle root of the block header the same servers served for that height — a root the
fix did not compute, so agreeing with it is not the code agreeing with itself.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from pyrxd.network.electrumx import ElectrumXClient
from pyrxd.network.failover import FailoverElectrumXClient
from pyrxd.security.errors import NetworkError
from pyrxd.security.types import BlockHeight, Txid
from pyrxd.spv.radiant import TxMerkleBranch

_FIXTURES = json.loads(
    (Path(__file__).resolve().parent.parent / "fixtures" / "mark_block_fixtures_2026-09-30.json").read_text(
        encoding="utf-8"
    )
)["fixtures"]


def _cases() -> list[tuple[str, dict[str, Any]]]:
    return sorted(_FIXTURES.items())


def _header_at(fx: dict[str, Any], height: int) -> bytes:
    raw = bytes.fromhex(fx["headers_hex"])
    i = height - fx["headers_start"]
    assert i >= 0 and (i + 1) * 80 <= len(raw), "fixture does not carry that height"
    return raw[i * 80 : (i + 1) * 80]


def _client_answering(reply: Any) -> ElectrumXClient:
    client = ElectrumXClient(["wss://electrum.invalid:50002"])
    calls: list[tuple[str, list]] = []

    async def _call(method: str, params: list) -> Any:
        calls.append((method, params))
        return reply

    client._call = _call  # type: ignore[method-assign]
    client.calls = calls  # type: ignore[attr-defined]
    return client


def test_both_real_fixtures_are_present_and_multi_level() -> None:
    """Non-vacuity, and the property that hid the bug: depth > 1 on both."""
    assert {txid[:8] for txid in _FIXTURES} == {"a1a86ab4", "aa66b046"}
    for fx in _FIXTURES.values():
        assert len(fx["merkle"]["merkle"]) >= 4
        assert fx["merkle"]["pos"] not in (0, 1)


@pytest.mark.parametrize(("txid", "fx"), _cases(), ids=[t[:8] for t, _ in _cases()])
async def test_the_real_reply_builds_a_path_whose_root_is_the_real_headers_root(txid: str, fx: dict) -> None:
    height = fx["merkle"]["block_height"]
    client = _client_answering(fx["merkle"])

    path = await client.get_transaction_merkle(Txid(txid), BlockHeight(height))

    header = _header_at(fx, height)
    assert path.compute_root(txid) == header[36:68][::-1].hex()
    assert path.block_height == height
    assert len(path.path) == len(fx["merkle"]["merkle"]), "one BUMP level per tree depth"
    assert client.calls == [("blockchain.transaction.get_merkle", [txid, height])]


@pytest.mark.parametrize(("txid", "fx"), _cases(), ids=[t[:8] for t, _ in _cases()])
async def test_the_bump_round_trips_through_its_binary_form(txid: str, fx: dict) -> None:
    """A BUMP that only works in memory is not a BUMP: serialise it and read it back."""
    from pyrxd.merkle_path import MerklePath

    path = await _client_answering(fx["merkle"]).get_transaction_merkle(
        Txid(txid), BlockHeight(fx["merkle"]["block_height"])
    )
    again = MerklePath.from_hex(path.to_hex())
    assert again.compute_root(txid) == path.compute_root(txid)


@pytest.mark.parametrize(("txid", "fx"), _cases(), ids=[t[:8] for t, _ in _cases()])
async def test_the_branch_method_returns_the_reply_verbatim_and_validated(txid: str, fx: dict) -> None:
    height = fx["merkle"]["block_height"]
    branch = await _client_answering(fx["merkle"]).get_transaction_merkle_branch(Txid(txid), BlockHeight(height))
    assert branch == TxMerkleBranch(block_height=height, branch=tuple(fx["merkle"]["merkle"]), pos=fx["merkle"]["pos"])


@pytest.mark.parametrize(("txid", "fx"), _cases(), ids=[t[:8] for t, _ in _cases()])
async def test_a_flipped_sibling_changes_the_root(txid: str, fx: dict) -> None:
    """The root match above is not a tautology: the same code on a one-nibble-wrong reply misses."""
    height = fx["merkle"]["block_height"]
    reply = json.loads(json.dumps(fx["merkle"]))
    s = reply["merkle"][2]
    reply["merkle"][2] = ("0" if s[0] != "0" else "1") + s[1:]
    path = await _client_answering(reply).get_transaction_merkle(Txid(txid), BlockHeight(height))
    assert path.compute_root(txid) != _header_at(fx, height)[36:68][::-1].hex()


@pytest.mark.parametrize("pos_offset", [0, 1], ids=["pos_eq_2_pow_depth", "beyond"])
async def test_a_pos_that_aliases_another_leaf_is_refused(pos_offset: int) -> None:
    """``pos >= 2**depth`` names no leaf of a tree that deep — it aliases a smaller pos."""
    txid, fx = _cases()[0]
    reply = dict(fx["merkle"])
    reply["pos"] = 2 ** len(reply["merkle"]) + pos_offset
    with pytest.raises(NetworkError, match="Malformed merkle"):
        await _client_answering(reply).get_transaction_merkle_branch(Txid(txid), BlockHeight(reply["block_height"]))


async def test_the_failover_client_forwards_the_branch_method() -> None:
    """The failover wrapper is the only production holder of this method; it must forward the new one."""
    txid, fx = _cases()[0]
    inner = _client_answering(fx["merkle"])
    fo = FailoverElectrumXClient.__new__(FailoverElectrumXClient)

    async def _run(description: str, op: Any, **_: Any) -> Any:
        return await op(inner)

    fo._run = _run  # type: ignore[method-assign]
    got = await fo.get_transaction_merkle_branch(Txid(txid), BlockHeight(fx["merkle"]["block_height"]))
    assert got.pos == fx["merkle"]["pos"]
    path = await fo.get_transaction_merkle(Txid(txid), BlockHeight(fx["merkle"]["block_height"]))
    assert path.compute_root(txid) == _header_at(fx, fx["merkle"]["block_height"])[36:68][::-1].hex()


# Block 1 of Radiant mainnet holds ONE transaction, its coinbase. Captured 2026-09-30, read-only,
# from both shipped servers (identical), and the maintainer's node (``getblock <hash> 1``) agreed:
# one tx, ``2b1bfc07…ac8c``, and a merkle root equal to it.
_BLOCK1_TXID = "2b1bfc071d1d120b9592bdd45e50484ebba63943f565aebde9cbb6c250f8ac8c"
_BLOCK1_REPLY = {"block_height": 1, "merkle": [], "pos": 0}
_BLOCK1_HEADER = bytes.fromhex(
    "00000020b43f004e6f7a1f7e439ea50c6c2aac60b6ffb376688de28b5dedd865000000008cacf850c2b6cbe9bdae65f5"
    "4339a6bb4e48505ed4bd92950b121d1d07fc1b2bd933b162ffff001d29e973a3"
)


async def test_a_single_transaction_block_gives_a_path_whose_root_is_the_txid() -> None:
    """The branch is empty and the root equals the txid. Through this PR's first fix it raised
    ``Could not construct MerklePath: Missing hash for index 0 at height 0``."""
    from pyrxd.merkle_path import MerklePath

    assert _BLOCK1_HEADER[36:68][::-1].hex() == _BLOCK1_TXID, "premise: the real header's root is the txid"
    path = await _client_answering(_BLOCK1_REPLY).get_transaction_merkle(Txid(_BLOCK1_TXID), BlockHeight(1))
    assert path.compute_root(_BLOCK1_TXID) == _BLOCK1_HEADER[36:68][::-1].hex()
    assert MerklePath.from_hex(path.to_hex()).compute_root(_BLOCK1_TXID) == _BLOCK1_TXID


def test_a_lone_leaf_that_is_not_at_offset_zero_is_still_refused() -> None:
    """The single-transaction case is offset 0 only; a lone leaf elsewhere is a proof missing its
    sibling, not a one-transaction block."""
    from pyrxd.merkle_path import MerklePath

    with pytest.raises(ValueError, match="Missing hash for index 1 at height 0"):
        MerklePath(1, [[{"offset": 1, "hash_str": _BLOCK1_TXID, "txid": True}]])
