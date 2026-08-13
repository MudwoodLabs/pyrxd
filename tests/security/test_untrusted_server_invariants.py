"""A response must be bound to the request that asked for it — and to nothing else.

Sibling of :mod:`tests.security.test_hostile_server_responses`. That file sweeps the
*shape* of a field: can a server put something un-interpretable in it and have the SDK
act on it anyway. This file asks the other question, the one a well-formed response can
still fail: **is this the answer to the question we asked?**

A lying server's cheapest move is not to fabricate a field. It is to return a completely
truthful answer to a *different* question — another transaction's confirmation depth,
another block's Merkle proof, another output's amount, its own idea of what txid it just
broadcast. Every one of those is a valid document that no type check, range check or
fail-closed ``except`` tuple will ever reject. Only a binding will.

The four invariants asserted here, in the order the audit named them:

1. **A response is bound to the request that asked for it.** Every read that has an echo
   to bind (``txid``, ``block_height``) must bind it, and must refuse a *missing* echo as
   hard as a mismatched one — "I cannot check" is not "it passed".
2. **An ambiguous answer fails closed.** Where several sources are consulted, two
   different values each reaching the quorum is not a result to pick from.
3. **A value-bearing read cannot be satisfied by a minority of hostile sources.**
   Quorum must be about how many sources AGREE, never about where they sit in a list.
4. **Failover does not silently relax the security of the endpoint it moves to.**

Each invariant is tested in BOTH directions. A guard that refuses a legitimate server
answer costs funds too — during a timelock race it costs them faster — so every refusal
test is paired with an honest response that must still be accepted.

Offline: every server here is a local double. No socket is opened.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from pyrxd.gravity.watch.adapters import MultiSourceRxdChainSource
from pyrxd.network.bitcoin import (
    BitcoinCoreFundingReader,
    BitcoinCoreRpcSource,
    BlockstreamSource,
    MempoolSpaceBroadcaster,
    MempoolSpaceFundingReader,
    MempoolSpaceSource,
    MultiSourceBtcDataSource,
)
from pyrxd.network.confirm import wait_for_confirmation
from pyrxd.network.electrumx import ElectrumXClient
from pyrxd.network.registry import Endpoint, NetworkProfile
from pyrxd.network.tls_pin import normalize_pin
from pyrxd.security.errors import NetworkError, ValidationError
from pyrxd.security.types import BlockHeight, Txid

# ── shared fixtures ───────────────────────────────────────────────────────────

#: A minimal, parseable, non-segwit transaction and the txid it actually hashes to.
#: Derived, never hand-written: a fixture whose hex does not hash to its txid is not a
#: response an honest server can produce, so it would test the binding against itself.
REAL_TX = (
    bytes.fromhex("02000000")
    + b"\x01"
    + b"\x00" * 32
    + b"\x00\x00\x00\x00"
    + b"\x00"
    + b"\xff\xff\xff\xff"
    + b"\x01"
    + b"\x00" * 8
    + b"\x19"
    + b"\x76\xa9\x14"
    + b"\x00" * 20
    + b"\x88\xac"
    + bytes.fromhex("00000000")
)
REAL_TXID = hashlib.sha256(hashlib.sha256(REAL_TX).digest()).digest()[::-1].hex()

#: A different, equally real transaction — what a hostile server answers WITH.
OTHER_TX = REAL_TX[:4] + b"\x01" + b"\x11" * 32 + REAL_TX[37:]
OTHER_TXID = hashlib.sha256(hashlib.sha256(OTHER_TX).digest()).digest()[::-1].hex()


def http_response(status: int, body: bytes, content_type: str = "application/json"):
    resp = AsyncMock()
    resp.status = status
    resp.content_type = content_type
    resp.read = AsyncMock(return_value=body)
    resp.__aenter__ = AsyncMock(return_value=resp)
    resp.__aexit__ = AsyncMock(return_value=None)
    return resp


def http_session(bodies: list):
    """A session whose successive ``.get()`` calls yield ``bodies`` in order."""
    session = MagicMock()
    session.closed = False
    session.get = MagicMock(side_effect=[b if not isinstance(b, bytes) else http_response(200, b) for b in bodies])
    return session


def jbytes(obj: Any) -> bytes:
    return json.dumps(obj).encode()


def esplora_source(cls, bodies: list):
    source = cls()
    source._session = http_session(bodies)
    return source


def esplora_reader(bodies: list) -> MempoolSpaceFundingReader:
    reader = MempoolSpaceFundingReader()
    reader._http._session = http_session(bodies)
    return reader


def core_reader(*results: Any) -> BitcoinCoreFundingReader:
    """A ``BitcoinCoreFundingReader`` whose RPC answers ``results`` in order (last repeats)."""
    seq = list(results)

    async def _rpc(method: str, params: list) -> Any:
        return seq.pop(0) if len(seq) > 1 else seq[0]

    return BitcoinCoreFundingReader(_rpc)


def ws_yielding(*payloads: dict):
    """A websocket double that yields each payload once, then blocks like a real socket."""
    ws = AsyncMock()
    ws.send = AsyncMock(return_value=None)
    queue = [json.dumps(p) for p in payloads]

    async def _recv(*_a, **_kw):
        if queue:
            return queue.pop(0)
        await asyncio.Event().wait()
        return None  # pragma: no cover - unreachable

    ws.recv = _recv
    ws.close = AsyncMock(return_value=None)
    return ws


def patch_connect(ws):
    async def _connected(*_a, **_kw):
        return ws

    return patch("pyrxd.network.electrumx.websockets.connect", side_effect=_connected)


# ══════════════════════════════════════════════════════════════════════════════
# 1. A response is bound to the request that asked for it
# ══════════════════════════════════════════════════════════════════════════════
#
# ── ElectrumX: the verbose transaction read ───────────────────────────────────
#
# `get_transaction` recomputes hash256(raw) and has done since the Glyph-scanner fix.
# `get_transaction_verbose` — the read EVERY confirmation gate in the SDK is built on
# (wait_for_confirmation, RadiantCovenantLeg.confirmations, ElectrumRxdChainSource) —
# had no binding of any kind. A server could answer with a different, deeply-buried
# transaction's body and satisfy the depth threshold without fabricating a field.


@pytest.mark.parametrize(
    ("label", "echoed"),
    [
        ("another_txid", OTHER_TXID),
        ("missing", None),
        ("empty", ""),
        ("not_a_string", 12),
        ("truncated", REAL_TXID[:32]),
    ],
)
async def test_electrumx_verbose_refuses_a_body_that_is_not_about_the_requested_tx(label, echoed) -> None:
    body = {"confirmations": 4242, "blockhash": "00" * 32}
    if echoed is not None:
        body["txid"] = echoed
    ws = ws_yielding({"id": 1, "result": body})
    with patch_connect(ws):
        async with ElectrumXClient(["wss://example.com"]) as client:
            with pytest.raises(NetworkError, match="does not identify the requested txid"):
                await client.get_transaction_verbose(Txid(REAL_TXID))


async def test_electrumx_verbose_still_accepts_the_transaction_it_asked_for() -> None:
    """The honest direction: a well-formed body for the requested tx must pass through."""
    body = {"txid": REAL_TXID, "confirmations": 3, "blockhash": "00" * 32, "hex": REAL_TX.hex()}
    ws = ws_yielding({"id": 1, "result": body})
    with patch_connect(ws):
        async with ElectrumXClient(["wss://example.com"]) as client:
            result = await client.get_transaction_verbose(Txid(REAL_TXID))
    assert result["confirmations"] == 3


async def test_electrumx_verbose_accepts_an_uppercase_echo() -> None:
    """A server that echoes the id in a different case is honest, not hostile."""
    body = {"txid": REAL_TXID.upper(), "confirmations": 1}
    ws = ws_yielding({"id": 1, "result": body})
    with patch_connect(ws):
        async with ElectrumXClient(["wss://example.com"]) as client:
            assert (await client.get_transaction_verbose(Txid(REAL_TXID)))["confirmations"] == 1


async def test_confirmation_gate_cannot_be_satisfied_by_a_substituted_transaction() -> None:
    """The end the binding exists for.

    ``wait_for_confirmation`` swallows a ``NetworkError`` per poll and keeps waiting, so a
    substituted deep transaction must not merely be *noticed* — it must fail to satisfy the
    threshold at all. Before the binding, one substituted body returned "confirmed" for a
    transaction that was not mined; the mint path proceeds on that answer.
    """
    ws = ws_yielding({"id": 1, "result": {"txid": OTHER_TXID, "confirmations": 999}})
    with patch_connect(ws):
        async with ElectrumXClient(["wss://example.com"]) as client:
            with pytest.raises(NetworkError):
                await wait_for_confirmation(
                    client,
                    Txid(REAL_TXID),
                    min_confirmations=1,
                    sleep=AsyncMock(),
                    clock=iter([0.0, 1.0, 10_000.0]).__next__,
                    max_iterations=1,
                )


# ── Esplora: the Merkle proof must be for the block we asked about ────────────


@pytest.mark.parametrize("cls", [MempoolSpaceSource, BlockstreamSource], ids=lambda c: c.__name__)
@pytest.mark.parametrize(
    ("label", "proved"),
    [("one_below", 99), ("one_above", 101), ("far_off", 5), ("missing", None)],
)
async def test_esplora_merkle_proof_refuses_a_proof_for_a_different_block(cls, label, proved) -> None:
    body: dict[str, Any] = {"merkle": ["ab" * 32], "pos": 3}
    if proved is not None:
        body["block_height"] = proved
    source = esplora_source(cls, [jbytes(body)])
    with pytest.raises(NetworkError):
        await source.get_merkle_proof(Txid(REAL_TXID), BlockHeight(100))


@pytest.mark.parametrize("cls", [MempoolSpaceSource, BlockstreamSource], ids=lambda c: c.__name__)
async def test_esplora_merkle_proof_accepts_the_requested_block(cls) -> None:
    source = esplora_source(cls, [jbytes({"block_height": 100, "merkle": ["ab" * 32], "pos": 3})])
    branch, pos = await source.get_merkle_proof(Txid(REAL_TXID), BlockHeight(100))
    assert pos == 3
    assert branch == ["ab" * 32]


# ── Bitcoin Core: the verbose object behind BOTH funding reads ────────────────


async def test_core_funding_reader_confirmations_refuses_another_transactions_body() -> None:
    reader = core_reader({"txid": OTHER_TXID, "confirmations": 4242})
    with pytest.raises(NetworkError, match="does not identify the requested transaction"):
        await reader.confirmations(REAL_TXID)


async def test_core_funding_reader_amount_refuses_another_transactions_body() -> None:
    reader = core_reader({"txid": OTHER_TXID, "confirmations": 99, "vout": [{"value": 21.0}]})
    with pytest.raises(NetworkError, match="does not identify the requested transaction"):
        await reader.read_output_amount_sats(REAL_TXID, 0, min_confirmations=1)


async def test_core_source_tx_block_height_refuses_another_transactions_body() -> None:
    source = BitcoinCoreRpcSource("http://node.invalid:8332/", "u", "p")

    async def _rpc(_m: str, _p: list) -> Any:
        return {"txid": OTHER_TXID, "blockheight": 700_000}

    source._rpc = _rpc  # type: ignore[method-assign]
    with pytest.raises(NetworkError, match="does not identify the requested transaction"):
        await source.get_tx_block_height(Txid(REAL_TXID))


async def test_core_funding_reader_accepts_its_own_transaction() -> None:
    """Honest direction: the node's real answer for the tx we asked about still works."""
    reader = core_reader({"txid": REAL_TXID, "confirmations": 7, "vout": [{"value": 0.001}]})
    assert await reader.confirmations(REAL_TXID) == 7
    assert await reader.read_output_amount_sats(REAL_TXID, 0, min_confirmations=1) == 100_000


# ── the funded amount must be bound to the OUTPOINT, not just the tx ──────────
#
# audit B7 fixed `data["vout"][-1]`'s silent wrap in `get_tx_output_script_type` on all
# three sources, and in `read_confirmed_unspent_output`. It missed both
# `read_output_amount_sats` implementations — the read a maker's counter-funding gate
# uses to decide whether the BTC it is about to lock against is really there.


async def test_esplora_funding_reader_refuses_a_negative_vout() -> None:
    reader = esplora_reader(
        [
            jbytes({"confirmed": True, "block_height": 100}),
            b"105",
            jbytes({"txid": REAL_TXID, "vout": [{"value": 1_000}, {"value": 999_999}]}),
        ]
    )
    with pytest.raises(ValidationError, match="non-negative"):
        await reader.read_output_amount_sats(REAL_TXID, -1, min_confirmations=1)


async def test_esplora_funding_reader_reads_the_named_output() -> None:
    reader = esplora_reader(
        [
            jbytes({"confirmed": True, "block_height": 100}),
            b"105",
            jbytes({"txid": REAL_TXID, "vout": [{"value": 1_000}, {"value": 999_999}]}),
        ]
    )
    assert await reader.read_output_amount_sats(REAL_TXID, 1, min_confirmations=1) == 999_999


async def test_core_funding_reader_refuses_a_negative_vout() -> None:
    reader = core_reader({"txid": REAL_TXID, "confirmations": 9, "vout": [{"value": 0.001}, {"value": 21.0}]})
    with pytest.raises(ValidationError, match="non-negative"):
        await reader.read_output_amount_sats(REAL_TXID, -1, min_confirmations=1)


# ── the broadcaster's echoed txid is a claim, not evidence ────────────────────


def broadcaster_posting(status: int, body: bytes) -> MempoolSpaceBroadcaster:
    b = MempoolSpaceBroadcaster()
    session = MagicMock()
    session.closed = False
    session.post = MagicMock(return_value=http_response(status, body, "text/plain"))
    b._http._session = session
    return b


async def test_broadcaster_refuses_an_echoed_txid_that_is_not_the_bytes_it_posted() -> None:
    """``claim()`` and ``refund()`` return this value UNBOUND to their caller.

    An endpoint that answers 200 with someone else's id — or that never relayed anything —
    had the operator record and watch a transaction that does not exist, while believing the
    leg was broadcast. ``fund()`` survived only because it re-binds one layer up.
    """
    b = broadcaster_posting(200, OTHER_TXID.encode())
    with pytest.raises(NetworkError, match="fail-closed"):
        await b.broadcast(REAL_TX)


async def test_broadcaster_returns_the_locally_derived_txid_on_success() -> None:
    b = broadcaster_posting(200, REAL_TXID.encode())
    assert await b.broadcast(REAL_TX) == REAL_TXID


async def test_broadcaster_still_treats_already_present_as_success() -> None:
    """Honest direction: idempotent re-broadcast keeps working, with a LOCAL txid."""
    b = broadcaster_posting(400, b"txn-already-known")
    assert await b.broadcast(REAL_TX) == REAL_TXID


# ── the raw-bytes binding that no test could detect the removal of ────────────
#
# `_verify_raw_matches_txid` (audit F-004) is applied at four call sites. Neutering its
# comparison to `if False:` left the entire suite green — the guard was correct and
# nothing could tell if it went away. These pin all four.


async def test_esplora_get_raw_tx_refuses_bytes_that_are_a_different_transaction() -> None:
    for cls in (MempoolSpaceSource, BlockstreamSource):
        source = esplora_source(
            cls,
            [
                jbytes({"confirmed": True, "block_height": 100}),
                b"105",
                http_response(200, OTHER_TX.hex().encode(), "text/plain"),
            ],
        )
        with pytest.raises(NetworkError, match="do not match the requested txid"):
            await source.get_raw_tx(Txid(REAL_TXID), min_confirmations=1)


async def test_core_get_raw_tx_refuses_bytes_that_are_a_different_transaction() -> None:
    source = BitcoinCoreRpcSource("http://node.invalid:8332/", "u", "p")

    async def _rpc(_m: str, _p: list) -> Any:
        # A node that echoes the requested id but serves someone else's bytes: the echo
        # check passes, so ONLY the hash binding can catch this.
        return {"txid": REAL_TXID, "confirmations": 9, "hex": OTHER_TX.hex()}

    source._rpc = _rpc  # type: ignore[method-assign]
    with pytest.raises(NetworkError, match="do not match the requested txid"):
        await source.get_raw_tx(Txid(REAL_TXID), min_confirmations=1)


async def test_multisource_get_raw_tx_refuses_agreed_bytes_for_a_different_transaction() -> None:
    """Quorum agreement is not identity: N sources agreeing on the WRONG tx is still wrong."""
    s1, s2 = MagicMock(), MagicMock()
    for s in (s1, s2):
        s.get_raw_tx = AsyncMock(return_value=OTHER_TX)
    multi = MultiSourceBtcDataSource([s1, s2], quorum=2)
    with pytest.raises(NetworkError, match="do not match the requested txid"):
        await multi.get_raw_tx(Txid(REAL_TXID))


async def test_get_raw_tx_accepts_the_transaction_it_asked_for() -> None:
    """Honest direction, all four sites."""
    source = esplora_source(
        MempoolSpaceSource,
        [
            jbytes({"confirmed": True, "block_height": 100}),
            b"105",
            http_response(200, REAL_TX.hex().encode(), "text/plain"),
        ],
    )
    assert bytes(await source.get_raw_tx(Txid(REAL_TXID), min_confirmations=1)) == REAL_TX

    s1, s2 = MagicMock(), MagicMock()
    for s in (s1, s2):
        s.get_raw_tx = AsyncMock(return_value=REAL_TX)
    assert bytes(await MultiSourceBtcDataSource([s1, s2], quorum=2).get_raw_tx(Txid(REAL_TXID))) == REAL_TX


# ── the JSON-RPC id is the only thing correlating a response to a call ────────


async def test_electrumx_reader_does_not_dispatch_a_boolean_id_to_request_one() -> None:
    """``isinstance(True, int)`` is True and ``hash(True) == hash(1)``.

    So a server message carrying ``"id": true`` popped the future for request id **1** — the
    first RPC of every connection, which is the genesis read ``assert_chain`` is built on.
    The call must time out instead of accepting an answer that was never correlated.
    """
    ws = ws_yielding({"id": True, "result": {"height": 999_999}})
    with patch_connect(ws):
        async with ElectrumXClient(["wss://example.com"], timeout=0.05) as client:
            with pytest.raises(NetworkError, match="timed out"):
                await client.get_tip_height()


async def test_electrumx_reader_still_dispatches_a_real_integer_id() -> None:
    ws = ws_yielding({"id": 1, "result": {"height": 840_000}})
    with patch_connect(ws):
        async with ElectrumXClient(["wss://example.com"], timeout=1.0) as client:
            assert int(await client.get_tip_height()) == 840_000


# ── an unbounded frame is not a response ─────────────────────────────────────


@pytest.mark.parametrize("as_bytes", [False, True], ids=["text_frame", "binary_frame"])
async def test_electrumx_reader_refuses_an_oversized_frame(as_bytes: bool) -> None:
    """The 10 MB cap is checked before ``json.loads``, on BOTH frame types, and neither
    branch had a test.

    A server that answers one RPC with an arbitrarily large frame otherwise gets that whole
    frame decoded and parsed in the client's process — and it is a *read*, so the cost lands
    on any wallet that merely queries a balance. Over the cap the connection is dropped and
    every in-flight call fails; it must not be parsed and must not hang.
    """
    ws = AsyncMock()
    ws.send = AsyncMock(return_value=None)
    oversized: Any = b"a" * (10 * 1024 * 1024 + 1) if as_bytes else "a" * (10 * 1024 * 1024 + 1)
    frames = [oversized]

    async def _recv(*_a, **_kw):
        if frames:
            return frames.pop(0)
        await asyncio.Event().wait()
        return None  # pragma: no cover - unreachable

    ws.recv = _recv
    ws.close = AsyncMock(return_value=None)
    with patch_connect(ws):
        async with ElectrumXClient(["wss://example.com"], timeout=5.0) as client:
            with pytest.raises(NetworkError, match="exceeds maximum allowed size"):
                await client.get_tip_height()


# ── a block header is 80 bytes or it is not a block header ───────────────────


@pytest.mark.parametrize("nbytes", [0, 40, 79, 81, 160], ids=lambda n: f"{n}b")
async def test_electrumx_get_block_header_refuses_a_wrong_length_header(nbytes: int) -> None:
    """The header this returns is hashed into a chain identity and an SPV link."""
    ws = ws_yielding({"id": 1, "result": ("aa" * nbytes)})
    with patch_connect(ws):
        async with ElectrumXClient(["wss://example.com"]) as client:
            with pytest.raises(NetworkError, match="80 bytes"):
                await client.get_block_header(BlockHeight(0))


async def test_electrumx_get_block_header_accepts_eighty_bytes() -> None:
    ws = ws_yielding({"id": 1, "result": "aa" * 80})
    with patch_connect(ws):
        async with ElectrumXClient(["wss://example.com"]) as client:
            assert await client.get_block_header(BlockHeight(0)) == bytes.fromhex("aa" * 80)


# ── an output the source cannot describe is not an output ────────────────────


async def test_esplora_confirmed_unspent_output_refuses_an_empty_script() -> None:
    """The maker's counter-funding gate compares this scriptPubKey to the HTLC's.

    Handing it ``b""`` and a negative value is not a funding output; it is a source that
    could not answer, dressed as one that could.
    """
    reader = esplora_reader(
        [
            jbytes({"confirmed": True, "block_height": 100}),
            b"105",
            jbytes({"txid": REAL_TXID, "vout": [{"scriptpubkey": "", "value": 1_000}]}),
        ]
    )
    with pytest.raises(NetworkError, match="empty scriptPubKey or negative value"):
        await reader.read_confirmed_unspent_output(REAL_TXID, 0)


async def test_esplora_confirmed_unspent_output_refuses_a_negative_value() -> None:
    reader = esplora_reader(
        [
            jbytes({"confirmed": True, "block_height": 100}),
            b"105",
            jbytes({"txid": REAL_TXID, "vout": [{"scriptpubkey": "0014" + "11" * 20, "value": -1}]}),
        ]
    )
    with pytest.raises(NetworkError, match="empty scriptPubKey or negative value"):
        await reader.read_confirmed_unspent_output(REAL_TXID, 0)


async def test_esplora_confirmed_unspent_output_accepts_a_real_live_output() -> None:
    reader = esplora_reader(
        [
            jbytes({"confirmed": True, "block_height": 100}),
            b"105",
            jbytes({"txid": REAL_TXID, "vout": [{"scriptpubkey": "0014" + "11" * 20, "value": 1_000}]}),
            jbytes({"spent": False}),
        ]
    )
    spk, value = await reader.read_confirmed_unspent_output(REAL_TXID, 0)
    assert spk == bytes.fromhex("0014" + "11" * 20)
    assert value == 1_000


# ══════════════════════════════════════════════════════════════════════════════
# 2 + 3. An ambiguous answer fails closed; a minority cannot satisfy the quorum
# ══════════════════════════════════════════════════════════════════════════════


def fake_source(**answers) -> MagicMock:
    source = MagicMock()
    for name, value in answers.items():
        setattr(source, name, AsyncMock(return_value=value))
    return source


async def test_quorum_is_about_agreement_not_list_position() -> None:
    """Two colluding sources listed FIRST beat three honest ones listed after them.

    ``_require_quorum`` returned the first group in insertion order that reached the quorum,
    and insertion order is source order. With ``quorum=2`` a hostile pair at the head of the
    list therefore decided the answer while three honest sources disagreed in silence.
    """
    hostile = [fake_source(get_tx_block_height=BlockHeight(1)) for _ in range(2)]
    honest = [fake_source(get_tx_block_height=BlockHeight(800_000)) for _ in range(3)]
    multi = MultiSourceBtcDataSource([*hostile, *honest], quorum=2)
    with pytest.raises(NetworkError, match="Sources disagree"):
        await multi.get_tx_block_height(Txid(REAL_TXID))


async def test_quorum_refuses_an_even_split() -> None:
    a = [fake_source(get_block_hash=b"\xaa" * 32) for _ in range(2)]
    b = [fake_source(get_block_hash=b"\xbb" * 32) for _ in range(2)]
    multi = MultiSourceBtcDataSource([*a, *b], quorum=2)
    with pytest.raises(NetworkError, match="Sources disagree"):
        await multi.get_block_hash(BlockHeight(100))


async def test_quorum_accepts_a_single_agreeing_group_with_a_dissenter() -> None:
    """Honest direction: one odd source out must not deny service to a real quorum."""
    honest = [fake_source(get_tx_block_height=BlockHeight(800_000)) for _ in range(3)]
    odd = fake_source(get_tx_block_height=BlockHeight(1))
    multi = MultiSourceBtcDataSource([*honest, odd], quorum=3)
    assert int(await multi.get_tx_block_height(Txid(REAL_TXID))) == 800_000


async def test_quorum_accepts_unanimous_sources() -> None:
    sources = [fake_source(get_tip_height=BlockHeight(840_000)) for _ in range(3)]
    assert int(await MultiSourceBtcDataSource(sources, quorum=2).get_tip_height()) == 840_000


@pytest.mark.parametrize("quorum", [0, -1, True, 1.5, "2"], ids=["zero", "negative", "bool", "float", "str"])
def test_multisource_refuses_a_quorum_that_cannot_corroborate(quorum) -> None:
    """A 0/negative quorum makes ``len(group) >= quorum`` vacuous — the first source wins.

    Both sibling quorum readers already refuse it; this one silently accepted corroboration
    switched off by a typo.
    """
    with pytest.raises(ValidationError, match="quorum must be an int >= 1"):
        MultiSourceBtcDataSource([fake_source(), fake_source()], quorum=quorum)


async def test_rxd_corroboration_cannot_be_claimed_over_a_single_source() -> None:
    """``MultiSourceRxdChainSource.corroborated`` is what the ChainObserver reads to justify
    ``rxd_corroborated=True``. One source, or ``quorum=1``, is not corroboration however the
    wiring asks for it."""
    one = MultiSourceRxdChainSource([fake_source()], quorum=1)
    assert one.corroborated is False
    two_but_quorum_one = MultiSourceRxdChainSource([fake_source(), fake_source()], quorum=1)
    assert two_but_quorum_one.corroborated is False
    genuine = MultiSourceRxdChainSource([fake_source(), fake_source()], quorum=2)
    assert genuine.corroborated is True


# ══════════════════════════════════════════════════════════════════════════════
# 4. Failover does not silently relax the security of the endpoint it moves to
# ══════════════════════════════════════════════════════════════════════════════

#: Real 32-byte SHA-256-shaped digests, base64'd — a pin is a hard 32-byte commitment, so a
#: hand-shortened string is not a pin the module could ever have been given.
_PIN_BODY_A = base64.b64encode(bytes([0xAA]) * 32).decode("ascii")
_PIN_BODY_B = base64.b64encode(bytes([0xBB]) * 32).decode("ascii")
PIN_A = normalize_pin(_PIN_BODY_A)
PIN_B = normalize_pin(_PIN_BODY_B)


def test_profile_refuses_to_mix_pinned_and_unpinned_endpoints() -> None:
    """One transport error and failover runs UNPINNED, with no error and no warning.

    The operator configured a pin, the client reports pinning as enabled, and the connection
    that actually carries the wallet's traffic is not pinned at all.
    """
    with pytest.raises(ValidationError, match="mixes TLS-pinned and unpinned"):
        NetworkProfile(
            network="mainnet",
            endpoints=(
                Endpoint(url="wss://a.example/", spki_pins=(PIN_A,)),
                Endpoint(url="wss://b.example/"),
            ),
            genesis_hash=None,
        )


def test_profile_refuses_to_mix_tls_and_plaintext_endpoints() -> None:
    with pytest.raises(ValidationError, match="mixes TLS and plaintext"):
        NetworkProfile(
            network="regtest",
            endpoints=(
                Endpoint(url="wss://a.example/"),
                Endpoint(url="ws://127.0.0.1:50022/", allow_insecure=True),
            ),
            genesis_hash=None,
        )


def test_profile_accepts_a_uniformly_pinned_set() -> None:
    """Honest direction: one pin LIST may cover several servers — that is the documented way
    to make a rotation deployable and to pin a failover set."""
    profile = NetworkProfile(
        network="mainnet",
        endpoints=(
            Endpoint(url="wss://a.example/", spki_pins=(PIN_A, PIN_B)),
            Endpoint(url="wss://b.example/", spki_pins=(PIN_A, PIN_B)),
        ),
        genesis_hash=None,
    )
    assert len(profile.endpoints) == 2


def test_profile_accepts_a_uniformly_unpinned_set() -> None:
    """Pinning is opt-in; a profile with no pins anywhere is the documented default."""
    profile = NetworkProfile.build("mainnet", ["wss://a.example/", "wss://b.example/"])
    assert len(profile.endpoints) == 2


def test_profile_accepts_a_uniformly_plaintext_set() -> None:
    """A local regtest pair is not a downgrade — there is nothing to downgrade FROM."""
    profile = NetworkProfile.build("regtest", ["ws://127.0.0.1:50022/", "ws://127.0.0.1:50023/"], allow_insecure=True)
    assert len(profile.endpoints) == 2


def test_profile_accepts_a_single_pinned_endpoint() -> None:
    """Nothing to fail over to, so nothing to relax."""
    profile = NetworkProfile(
        network="mainnet",
        endpoints=(Endpoint(url="wss://a.example/", spki_pins=(PIN_A,)),),
        genesis_hash=None,
    )
    assert profile.endpoints[0].spki_pins == (PIN_A,)


# ── a mistyped pin must not normalise to a DIFFERENT, valid-looking pin ──────


@pytest.mark.parametrize("junk", ["!", " ", "\n", "\t", "*"], ids=["bang", "space", "newline", "tab", "star"])
def test_normalize_pin_refuses_a_pin_with_non_base64_characters(junk: str) -> None:
    """``b64decode`` without ``validate=True`` silently DISCARDS characters outside the
    alphabet.

    Each string here is a real 44-char pin with one junk character INSERTED, so a lenient
    decode drops the junk, gets exactly 32 bytes back, and normalises to a well-formed pin —
    for the wrong key, silently. The operator sees a configured pin, gets a permanent
    connection refusal, and has no way to tell it from an attack. ``validate=True`` is what
    turns that into a message at wiring time.
    """
    typo = _PIN_BODY_A[:21] + junk + _PIN_BODY_A[21:]
    assert len(base64.b64decode(typo)) == 32  # a lenient decode WOULD accept it
    with pytest.raises(ValidationError, match="standard base64"):
        normalize_pin(typo)


def test_normalize_pin_accepts_the_documented_forms() -> None:
    """Honest direction: prefixed, bare, and whitespace-padded all normalise to one value."""
    assert (
        normalize_pin(_PIN_BODY_A)
        == normalize_pin("sha256/" + _PIN_BODY_A)
        == normalize_pin("  " + _PIN_BODY_A + "  ")
        == PIN_A
    )
