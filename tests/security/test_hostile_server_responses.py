"""Every external response is attacker-influenced: sweep the hostile shape space.

The bug this suite exists to make unreachable
---------------------------------------------
``MempoolSpaceFundingReader.read_confirmed_unspent_output`` read liveness with
``bool(spend.get("spent", True))``. The ``True`` default covers only a *missing* key, so
a **present-but-falsy** value — ``{"spent": null}``, what a broken or hostile
Esplora-shaped server emits for "no data" — evaluated falsy and was read as UNSPENT. A
maker's counter-funding gate would then lock its own asset against BTC that had already
been swept. The tests supplied only well-formed responses, so nothing saw it.

The generalisation
------------------
A boundary read is not "parsing"; it is a **decision to act on someone else's number**.
So this file does not test examples, it tests a *shape space*: every value-bearing field
at every reachable boundary (Esplora HTTP, Bitcoin Core JSON-RPC, ElectrumX WebSocket) is
swept with :data:`HOSTILE_SCALARS` — missing, present-but-falsy, wrong type, negative,
non-integral, the JSON non-standard literals ``Infinity`` / ``-Infinity`` / ``NaN``,
and absurd magnitudes.

The contract asserted everywhere is one sentence:

    A value-bearing read either returns a correct, well-typed value, or raises an
    ``RxdSdkError``. It never returns a value derived from an un-interpretable field,
    and it never escapes as a bare ``OverflowError`` / ``TypeError`` / ``ValueError`` /
    ``ArithmeticError``.

The second half of that is not pedantry. Every caller on a value-moving path guards with
``except NetworkError``; ``json.loads`` accepts ``Infinity``, and ``int(float("inf"))``
raises ``OverflowError``, which is not a ``NetworkError`` and was absent from every
fail-closed ``except`` tuple in the network layer. Such a read escaped as a bare
traceback *past* the handler that existed to contain it.

Offline: every server here is a local double. No socket is opened.
"""

from __future__ import annotations

import hashlib
import json
import math
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from pyrxd.network.bitcoin import (
    BitcoinCoreFundingReader,
    BitcoinCoreRpcSource,
    BlockstreamSource,
    MempoolSpaceFundingReader,
    MempoolSpaceSource,
)
from pyrxd.network.electrumx import ElectrumXClient
from pyrxd.security.errors import RxdSdkError
from pyrxd.security.types import BlockHeight, Txid

# ── the shape space ───────────────────────────────────────────────────────────


class _Missing:
    """Sentinel: the key is absent from the response entirely."""

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "<missing>"


MISSING = _Missing()

#: The hostile shapes a JSON field can take. Named so a parametrised failure
#: identifies the shape without needing the value printed back.
HOSTILE_SCALARS: list[tuple[str, Any]] = [
    ("missing", MISSING),
    ("null", None),
    ("false", False),
    ("true", True),
    ("zero", 0),
    ("empty_string", ""),
    ("empty_list", []),
    ("empty_dict", {}),
    ("numeric_string", "12"),
    ("word_string", "twelve"),
    ("negative", -1),
    ("non_integral_float", 1.9),
    ("infinity", float("inf")),
    ("negative_infinity", float("-inf")),
    ("nan", float("nan")),
    ("absurd_magnitude", 2**80),
    ("list_of_number", [12]),
    ("dict_wrapper", {"value": 12}),
]

#: Shapes that a *boolean* liveness/confirmation flag can take and still be a lie.
#: ``"false"`` is the sharp one: a non-empty string is truthy in Python, so a naive
#: ``if flag:`` reads the literal text "false" as TRUE.
HOSTILE_BOOLEANS: list[tuple[str, Any]] = [
    ("missing", MISSING),
    ("null", None),
    ("zero", 0),
    ("one", 1),
    ("empty_string", ""),
    ("string_false", "false"),
    ("string_true", "true"),
    ("empty_list", []),
    ("empty_dict", {}),
    ("nan", float("nan")),
]


def with_field(base: dict, key: str, value: Any) -> dict:
    """``base`` with ``key`` set to ``value`` — or removed when ``value`` is MISSING."""
    out = dict(base)
    if isinstance(value, _Missing):
        out.pop(key, None)
    else:
        out[key] = value
    return out


#: Exceptions that mean "the boundary leaked its internal failure mode". Any of these
#: escaping a boundary read is the defect: the caller guards with ``except NetworkError``.
LEAKED_EXCEPTIONS = (OverflowError, TypeError, ValueError, ArithmeticError, AttributeError, IndexError, KeyError)


async def assert_fail_closed(coro, *, label: str) -> None:
    """The read must refuse via an ``RxdSdkError``, not return and not leak a raw error.

    ``Base58Error`` and friends are ``RxdSdkError`` *and* ``ValueError``; the SDK-family
    check is applied first so those count as a proper refusal.
    """
    try:
        result = await coro
    except RxdSdkError:
        return  # the documented, catchable refusal
    except LEAKED_EXCEPTIONS as exc:
        pytest.fail(
            f"{label}: leaked {type(exc).__name__} past the trust boundary — callers on the "
            f"value-moving path guard with `except NetworkError`, so this escapes as a bare traceback"
        )
    pytest.fail(f"{label}: FAIL-OPEN — returned {result!r} instead of refusing an un-interpretable response")


def is_finite_number(value: Any) -> bool:
    """True for a real, finite, integral number (not a bool)."""
    if isinstance(value, (bool, _Missing)):
        return False
    if isinstance(value, int):
        return True
    if isinstance(value, float):
        return math.isfinite(value) and value.is_integer()
    return False


def is_acceptable(value: Any) -> bool:
    """True only for the shapes a boundary is *allowed* to accept: a real, finite,
    non-negative, integral number of plausible magnitude.

    ``2**80`` is excluded wherever the SDK has a *principled* ceiling to check against —
    ``Satoshis.MAX`` (the chain's hard supply bound) for an amount, ``BlockHeight``'s
    sanity ceiling for a height. It is deliberately NOT excluded for confirmation depths,
    output indices and Merkle leaf positions: there is no principled ceiling for those,
    and inventing one would be a number this suite made up rather than a rule the chain
    imposes. A huge depth is not more of a lie than a merely large one — the defence
    against a lying depth is the quorum reader, not a magnitude check."""
    return is_finite_number(value) and 0 <= value < 2**32


def is_uncapped_ok(value: Any) -> bool:
    """:func:`is_acceptable`, plus the absurd magnitudes on fields with no principled cap."""
    return is_finite_number(value) and value >= 0


# ── Esplora (mempool.space / blockstream.info) HTTP doubles ───────────────────

_VALID_RAW = (
    bytes.fromhex("02000000")  # version
    + b"\x01"  # 1 input
    + b"\x00" * 32  # prevout txid
    + b"\x00\x00\x00\x00"  # prevout vout
    + b"\x00"  # empty scriptSig
    + b"\xff\xff\xff\xff"  # sequence
    + b"\x01"  # 1 output
    + b"\x00" * 8  # value 0
    + b"\x19"  # script len 25
    + b"\x76\xa9\x14"
    + b"\x00" * 20
    + b"\x88\xac"  # P2PKH (keeps the tx > 64 bytes, RawTx's floor)
    + bytes.fromhex("00000000")  # locktime
)
VALID_TXID = hashlib.sha256(hashlib.sha256(_VALID_RAW).digest()).digest()[::-1].hex()
OTHER_TXID = "ff" * 32


def http_response(status: int, body: bytes, content_type: str = "application/json"):
    """A mock ``aiohttp`` response usable as an async context manager."""
    resp = AsyncMock()
    resp.status = status
    resp.content_type = content_type
    resp.read = AsyncMock(return_value=body)
    resp.__aenter__ = AsyncMock(return_value=resp)
    resp.__aexit__ = AsyncMock(return_value=None)
    return resp


def http_session(bodies: list):
    """A mock session whose successive ``.get()`` calls yield ``bodies`` in order.

    Each entry is either raw ``bytes`` (200 / JSON) or an already-built response.
    """
    session = MagicMock()
    session.closed = False
    responses = [b if not isinstance(b, bytes) else http_response(200, b) for b in bodies]
    session.get = MagicMock(side_effect=responses)
    return session


def esplora_source(cls, bodies: list):
    """An Esplora-shaped ``BtcDataSource`` wired to a scripted session."""
    source = cls()
    source._session = http_session(bodies)
    return source


def esplora_reader(bodies: list) -> MempoolSpaceFundingReader:
    """A ``MempoolSpaceFundingReader`` wired to a scripted session."""
    reader = MempoolSpaceFundingReader()
    reader._http._session = http_session(bodies)
    return reader


def jbytes(obj: Any) -> bytes:
    """JSON-encode, keeping the non-standard ``Infinity`` / ``NaN`` literals a real
    server (or a proxy) can emit — ``json.loads`` accepts them by default."""
    return json.dumps(obj).encode()


ESPLORA_SOURCES = [MempoolSpaceSource, BlockstreamSource]


# ── Esplora: /tx/{txid}/status → block_height ─────────────────────────────────


@pytest.mark.parametrize("cls", ESPLORA_SOURCES, ids=lambda c: c.__name__)
@pytest.mark.parametrize(("shape", "value"), HOSTILE_SCALARS, ids=[s for s, _ in HOSTILE_SCALARS])
async def test_get_tx_block_height_fails_closed_on_hostile_block_height(cls, shape: str, value: Any) -> None:
    """``get_tx_block_height`` must refuse any block_height it cannot interpret.

    Catches: an ``Infinity`` height escaping as ``OverflowError`` (absent from the
    ``(TypeError, ValueError, ValidationError)`` tuple), and a non-integral or
    stringly-typed height being silently coerced into a real height.
    """
    status = with_field({"confirmed": True, "block_height": 100}, "block_height", value)
    source = esplora_source(cls, [jbytes(status)])
    coro = source.get_tx_block_height(Txid(VALID_TXID))

    if is_acceptable(value):
        assert int(await coro) == int(value)
        return
    await assert_fail_closed(coro, label=f"{cls.__name__}.get_tx_block_height[{shape}]")


@pytest.mark.parametrize("cls", ESPLORA_SOURCES, ids=lambda c: c.__name__)
@pytest.mark.parametrize(("shape", "value"), HOSTILE_SCALARS, ids=[s for s, _ in HOSTILE_SCALARS])
async def test_get_raw_tx_conf_gate_fails_closed_on_hostile_block_height(cls, shape: str, value: Any) -> None:
    """The ``get_raw_tx`` confirmation gate computes ``tip - block_height + 1``.

    That arithmetic ran on a raw ``int(block_height)`` with **no** ``try`` around it, so a
    ``"block_height": "twelve"`` escaped as ``ValueError`` and ``Infinity`` as
    ``OverflowError`` — straight past the ``except NetworkError`` that every caller on the
    SPV/gravity finalize path uses. The gate must refuse instead.
    """
    status = with_field({"confirmed": True, "block_height": 100}, "block_height", value)
    source = esplora_source(cls, [jbytes(status), http_response(200, b"840000", "text/plain")])
    coro = source.get_raw_tx(Txid(VALID_TXID), min_confirmations=6)
    # Every shape here is either un-interpretable or yields a depth far below 6, so the
    # only correct outcome is a refusal (InsufficientConfirmationsError is an RxdSdkError).
    await assert_fail_closed(coro, label=f"{cls.__name__}.get_raw_tx[block_height={shape}]")


@pytest.mark.parametrize("cls", ESPLORA_SOURCES, ids=lambda c: c.__name__)
@pytest.mark.parametrize(("shape", "value"), HOSTILE_BOOLEANS, ids=[s for s, _ in HOSTILE_BOOLEANS])
async def test_get_raw_tx_requires_a_real_confirmed_boolean(cls, shape: str, value: Any) -> None:
    """``confirmed`` is the same shape of flag as the ``spent`` field that caused the bug.

    ``if not confirmed:`` is a truthiness test, so the STRING ``"false"`` — non-empty,
    therefore truthy — read as CONFIRMED. The height is set 6 deep so nothing else can
    refuse for us: only a real ``confirmed is True`` may let this through.
    """
    status = with_field({"confirmed": True, "block_height": 839995}, "confirmed", value)
    source = esplora_source(
        cls,
        [jbytes(status), http_response(200, b"840000", "text/plain"), http_response(200, _VALID_RAW.hex().encode())],
    )
    coro = source.get_raw_tx(Txid(VALID_TXID), min_confirmations=6)
    await assert_fail_closed(coro, label=f"{cls.__name__}.get_raw_tx[confirmed={shape}]")


# ── Esplora: /tx/{txid}/merkle-proof ──────────────────────────────────────────


@pytest.mark.parametrize("cls", ESPLORA_SOURCES, ids=lambda c: c.__name__)
@pytest.mark.parametrize(("shape", "value"), HOSTILE_SCALARS, ids=[s for s, _ in HOSTILE_SCALARS])
async def test_get_merkle_proof_fails_closed_on_hostile_pos(cls, shape: str, value: Any) -> None:
    """The leaf position drives every direction bit of the Merkle branch.

    A negative ``pos`` was returned verbatim, and ``Infinity`` escaped as ``OverflowError``.
    The SPV verifier downstream does reject both — but a boundary that hands a caller a
    negative leaf index has already failed to fail closed, and the ``OverflowError`` never
    reaches the verifier at all.
    """
    body = with_field({"merkle": ["ab" * 32], "pos": 3}, "pos", value)
    source = esplora_source(cls, [jbytes(body)])
    coro = source.get_merkle_proof(Txid(VALID_TXID), BlockHeight(100))

    if is_uncapped_ok(value):
        _, pos = await coro
        assert pos == int(value)
        return
    await assert_fail_closed(coro, label=f"{cls.__name__}.get_merkle_proof[pos={shape}]")


@pytest.mark.parametrize("cls", ESPLORA_SOURCES, ids=lambda c: c.__name__)
@pytest.mark.parametrize(
    "merkle",
    ["deadbeef", {"0": "ab" * 32}, [None], [123], ["zz" * 32], ["ab" * 31], 7, None],
    ids=["string", "dict", "list_of_null", "list_of_int", "non_hex", "short_hash", "int", "null"],
)
async def test_get_merkle_proof_fails_closed_on_hostile_branch(cls, merkle: Any) -> None:
    """``data["merkle"]`` was returned with no type check at all.

    A JSON string passes straight through as the "branch": iterating ``"deadbeef"`` yields
    eight one-character "hashes". A boundary must not hand its caller a type-confused proof.
    """
    source = esplora_source(cls, [jbytes({"merkle": merkle, "pos": 3})])
    await assert_fail_closed(
        source.get_merkle_proof(Txid(VALID_TXID), BlockHeight(100)),
        label=f"{cls.__name__}.get_merkle_proof[merkle={type(merkle).__name__}]",
    )


# ── Esplora: /tx/{txid} → the response must be about the tx we asked for ──────


@pytest.mark.parametrize("cls", ESPLORA_SOURCES, ids=lambda c: c.__name__)
@pytest.mark.parametrize(
    ("shape", "echoed"),
    [("other_txid", OTHER_TXID), ("missing", MISSING), ("null", None), ("empty", ""), ("number", 7)],
)
async def test_get_tx_output_script_type_binds_the_response_to_the_request(cls, shape: str, echoed: Any) -> None:
    """A ``/tx/{txid}`` body that is not about the requested tx must be refused.

    ``_assert_tx_identity`` already exists in this module and guards the funding-reader
    reads, but ``get_tx_output_script_type`` never called it: a single malicious or MITM'd
    source could answer with ANOTHER transaction's outputs, and the caller would bind the
    wrong output's script type to the outpoint it is about to act on.
    """
    body = with_field({"txid": VALID_TXID, "vout": [{"scriptpubkey_type": "v1_p2tr"}]}, "txid", echoed)
    source = esplora_source(cls, [jbytes(body)])
    await assert_fail_closed(
        source.get_tx_output_script_type(Txid(VALID_TXID), 0),
        label=f"{cls.__name__}.get_tx_output_script_type[txid={shape}]",
    )


@pytest.mark.parametrize("cls", ESPLORA_SOURCES, ids=lambda c: c.__name__)
@pytest.mark.parametrize("index", [-1, -2, True, 1.5, "0"], ids=["neg1", "neg2", "bool", "float", "string"])
async def test_get_tx_output_script_type_rejects_a_non_index(cls, index: Any) -> None:
    """A negative output index silently WRAPS in Python: ``vout[-1]`` is the last output.

    So ``get_tx_output_script_type(txid, -1)`` reported the script type of a different
    output than the one named, with no error. An output index must be a real non-negative
    ``int``.
    """
    body = {
        "txid": VALID_TXID,
        "vout": [{"scriptpubkey_type": "p2pkh"}, {"scriptpubkey_type": "v1_p2tr"}],
    }
    source = esplora_source(cls, [jbytes(body)])
    await assert_fail_closed(
        source.get_tx_output_script_type(Txid(VALID_TXID), index),
        label=f"{cls.__name__}.get_tx_output_script_type[index={index!r}]",
    )


# ── Esplora funding reader: /address/{addr}/utxo ──────────────────────────────


@pytest.mark.parametrize("field", ["vout", "value"])
@pytest.mark.parametrize(("shape", "value"), HOSTILE_SCALARS, ids=[s for s, _ in HOSTILE_SCALARS])
async def test_list_address_utxos_fails_closed_on_hostile_amounts(field: str, shape: str, value: Any) -> None:
    """UTXO discovery is how the operator picks the outpoint to hand the BTC leg.

    A negative ``value``/``vout`` was returned verbatim, ``1234.99`` was silently truncated
    to ``1234``, and ``Infinity`` escaped as ``OverflowError`` (absent from the
    ``(KeyError, TypeError, ValueError, ValidationError)`` tuple).
    """
    entry = with_field(
        {"txid": VALID_TXID, "vout": 0, "value": 5000, "status": {"confirmed": True, "block_height": 5}},
        field,
        value,
    )
    reader = esplora_reader([jbytes([entry])])
    coro = reader.list_address_utxos("bc1qexample")

    ok = is_acceptable(value) if field == "value" else is_uncapped_ok(value)
    if ok:
        got = await coro
        assert got[0][{"vout": "vout", "value": "value_sats"}[field]] == int(value)
        return
    await assert_fail_closed(coro, label=f"list_address_utxos[{field}={shape}]")


@pytest.mark.parametrize(("shape", "value"), HOSTILE_BOOLEANS, ids=[s for s, _ in HOSTILE_BOOLEANS])
async def test_funding_reader_confirmations_requires_a_real_confirmed_boolean(shape: str, value: Any) -> None:
    """``MempoolSpaceFundingReader.confirmations`` is the reorg gate's depth oracle.

    ``if not status.get("confirmed", False)`` is a truthiness test, so the NON-EMPTY string
    ``"false"`` read as CONFIRMED — the same shape as the ``spent`` bug in the sibling read
    two methods down. The height is set so a spoofed "confirmed" would otherwise yield a
    healthy depth, and the honest falsy answers must still read as depth 0 rather than raise.
    """
    status = with_field({"confirmed": True, "block_height": 100}, "confirmed", value)
    reader = esplora_reader([jbytes(status), http_response(200, b"140", "text/plain")])
    coro = reader.confirmations(VALID_TXID)

    if value is False or isinstance(value, _Missing):
        assert await coro == 0  # an honest "not confirmed yet" is depth 0, not an error
        return
    await assert_fail_closed(coro, label=f"MempoolSpaceFundingReader.confirmations[confirmed={shape}]")


# ── Bitcoin Core JSON-RPC ─────────────────────────────────────────────────────


def core_source(result: Any) -> BitcoinCoreRpcSource:
    """A ``BitcoinCoreRpcSource`` whose RPC always answers ``result``."""
    source = BitcoinCoreRpcSource("http://node.invalid:8332/", "user", "pass")

    async def _rpc(method: str, params: list) -> Any:
        return result

    source._rpc = _rpc  # type: ignore[method-assign]
    return source


def core_reader(result: Any) -> BitcoinCoreFundingReader:
    """A ``BitcoinCoreFundingReader`` whose RPC always answers ``result``."""

    async def _rpc(method: str, params: list) -> Any:
        return result

    return BitcoinCoreFundingReader(_rpc)


@pytest.mark.parametrize(("shape", "value"), HOSTILE_SCALARS, ids=[s for s, _ in HOSTILE_SCALARS])
async def test_core_get_raw_tx_fails_closed_on_hostile_confirmations(shape: str, value: Any) -> None:
    """``confs < min_confirmations`` ran on a completely unvalidated field.

    ``{"confirmations": null}`` and ``{"confirmations": "12"}`` raised ``TypeError``
    comparing to an int, and — the fail-OPEN — ``{"confirmations": Infinity}`` compared
    False and the transaction was accepted as sufficiently buried, which is the whole
    point of the gate.
    """
    data = with_field({"confirmations": 0, "hex": _VALID_RAW.hex(), "txid": VALID_TXID}, "confirmations", value)
    coro = core_source(data).get_raw_tx(Txid(VALID_TXID), min_confirmations=6)

    if is_uncapped_ok(value) and value >= 6:
        assert bytes(await coro) == _VALID_RAW
        return
    await assert_fail_closed(coro, label=f"BitcoinCoreRpcSource.get_raw_tx[confirmations={shape}]")


@pytest.mark.parametrize(("shape", "value"), HOSTILE_SCALARS, ids=[s for s, _ in HOSTILE_SCALARS])
async def test_core_funding_reader_confirmations_fails_closed(shape: str, value: Any) -> None:
    """``confs = int(confs)`` had no guard at all — every non-numeric shape escaped raw.

    A MISSING key is the one legitimate falsy answer (Bitcoin Core omits
    ``confirmations`` for a mempool tx), and must read as depth 0 — never as confirmed.
    """
    data = with_field({"confirmations": 3, "hex": _VALID_RAW.hex()}, "confirmations", value)
    coro = core_reader(data).confirmations(VALID_TXID)

    if isinstance(value, _Missing) or value is None:
        assert await coro == 0  # unconfirmed / unknown -> 0, the gate's >= N fails closed
        return
    if is_finite_number(value):
        assert await coro == max(0, int(value))
        return
    await assert_fail_closed(coro, label=f"BitcoinCoreFundingReader.confirmations[{shape}]")


@pytest.mark.parametrize(
    ("shape", "value"),
    [
        ("infinity", float("inf")),
        ("nan", float("nan")),
        ("word_string", "twelve"),
        ("null", None),
        ("list", [1]),
        ("dict", {}),
        ("negative", -1),
    ],
)
async def test_core_gettxout_fails_closed_on_hostile_value(shape: str, value: Any) -> None:
    """``_btc_to_sats`` runs ``Decimal(str(v))``, which raises ``decimal.InvalidOperation``.

    That is an ``ArithmeticError``, not a ``ValueError`` and certainly not a
    ``NetworkError`` — so a garbage ``value`` from ``gettxout`` escaped the maker's
    counter-funding gate as a bare traceback. ``Infinity`` reached ``int(Decimal("Infinity"))``
    (``OverflowError``) and ``NaN`` reached ``int(Decimal("NaN"))`` (``ValueError``).
    """
    res = {"scriptPubKey": {"hex": "0014" + "11" * 20}, "value": value}
    await assert_fail_closed(
        core_reader(res).read_confirmed_unspent_output(VALID_TXID, 0),
        label=f"BitcoinCoreFundingReader.read_confirmed_unspent_output[value={shape}]",
    )


# ── ElectrumX WebSocket JSON-RPC ──────────────────────────────────────────────


def electrum_client(result: Any) -> ElectrumXClient:
    """An ``ElectrumXClient`` whose every RPC answers ``result``. No socket is opened."""
    client = ElectrumXClient(["wss://electrum.invalid:50002"])

    async def _call(method: str, params: list) -> Any:
        return result

    client._call = _call  # type: ignore[method-assign]
    return client


@pytest.mark.parametrize(("shape", "value"), HOSTILE_SCALARS, ids=[s for s, _ in HOSTILE_SCALARS])
async def test_electrumx_tip_height_fails_closed(shape: str, value: Any) -> None:
    """``blockchain.headers.subscribe`` → ``height``. ``Infinity`` escaped as ``OverflowError``
    and ``1.9`` was silently truncated to a height of 1."""
    result = with_field({"height": 100}, "height", value)
    coro = electrum_client(result).get_tip_height()

    if is_acceptable(value):
        assert int(await coro) == int(value)
        return
    await assert_fail_closed(coro, label=f"ElectrumX.get_tip_height[{shape}]")


@pytest.mark.parametrize("field", ["confirmed", "unconfirmed"])
@pytest.mark.parametrize(("shape", "value"), HOSTILE_SCALARS, ids=[s for s, _ in HOSTILE_SCALARS])
async def test_electrumx_get_balance_fails_closed(field: str, shape: str, value: Any) -> None:
    """A balance is a value-bearing read: it gates whether a caller believes it can spend."""
    result = with_field({"confirmed": 1000, "unconfirmed": 0}, field, value)
    coro = electrum_client(result).get_balance(b"\x11" * 32)

    if is_acceptable(value):
        confirmed, unconfirmed = await coro
        assert int({"confirmed": confirmed, "unconfirmed": unconfirmed}[field]) == int(value)
        return
    await assert_fail_closed(coro, label=f"ElectrumX.get_balance[{field}={shape}]")


@pytest.mark.parametrize("field", ["tx_pos", "value", "height"])
@pytest.mark.parametrize(("shape", "value"), HOSTILE_SCALARS, ids=[s for s, _ in HOSTILE_SCALARS])
async def test_electrumx_get_utxos_fails_closed(field: str, shape: str, value: Any) -> None:
    """``listunspent`` feeds coin selection directly.

    A ``UtxoRecord`` with ``value=-5`` / ``tx_pos=-1`` was returned verbatim; ``1.9`` was
    truncated to ``1``; ``Infinity`` escaped as ``OverflowError``. ``_make_input`` does
    reject a non-positive value further down, which is why this is a boundary hardening
    rather than a live loss — but the boundary is where an un-interpretable number stops.
    """
    entry = with_field({"tx_hash": VALID_TXID, "tx_pos": 0, "value": 5000, "height": 12}, field, value)
    coro = electrum_client([entry]).get_utxos(b"\x11" * 32)

    ok = is_acceptable(value) if field == "value" else is_uncapped_ok(value)
    if ok:
        got = await coro
        assert getattr(got[0], field) == int(value)
        return
    await assert_fail_closed(coro, label=f"ElectrumX.get_utxos[{field}={shape}]")


@pytest.mark.parametrize(
    ("shape", "tx_hash"),
    [("null", None), ("number", 7), ("list", ["ab" * 32]), ("short_hex", "ab"), ("non_hex", "zz" * 32)],
)
async def test_electrumx_get_utxos_requires_a_real_txid(shape: str, tx_hash: Any) -> None:
    """``tx_hash`` was assigned with no validation whatsoever.

    ``UtxoRecord.tx_hash`` is documented as "transaction id in hex"; a ``None`` propagated
    into the outpoint of a transaction the wallet was about to sign.
    """
    entry = {"tx_hash": tx_hash, "tx_pos": 0, "value": 5000, "height": 12}
    await assert_fail_closed(
        electrum_client([entry]).get_utxos(b"\x11" * 32),
        label=f"ElectrumX.get_utxos[tx_hash={shape}]",
    )


@pytest.mark.parametrize(("shape", "value"), HOSTILE_SCALARS, ids=[s for s, _ in HOSTILE_SCALARS])
async def test_electrumx_get_merkle_fails_closed_on_hostile_pos(shape: str, value: Any) -> None:
    """``blockchain.transaction.get_merkle`` → ``pos``, the leaf index of the proof."""
    result = with_field({"block_height": 100, "merkle": ["ab" * 32], "pos": 3}, "pos", value)
    coro = electrum_client(result).get_transaction_merkle(Txid(VALID_TXID), BlockHeight(100))

    if is_uncapped_ok(value):
        assert await coro is not None
        return
    await assert_fail_closed(coro, label=f"ElectrumX.get_transaction_merkle[pos={shape}]")


@pytest.mark.parametrize(
    "merkle",
    ["deadbeef", {"0": "ab" * 32}, [None], [123], ["zz" * 32], 7, None],
    ids=["string", "dict", "list_of_null", "list_of_int", "non_hex", "int", "null"],
)
async def test_electrumx_get_merkle_fails_closed_on_hostile_branch(merkle: Any) -> None:
    """The sibling list must be a list of 32-byte hex hashes — nothing else."""
    result = {"block_height": 100, "merkle": merkle, "pos": 3}
    await assert_fail_closed(
        electrum_client(result).get_transaction_merkle(Txid(VALID_TXID), BlockHeight(100)),
        label=f"ElectrumX.get_transaction_merkle[merkle={type(merkle).__name__}]",
    )


@pytest.mark.parametrize(("shape", "value"), HOSTILE_SCALARS, ids=[s for s, _ in HOSTILE_SCALARS])
async def test_electrumx_get_history_fails_closed(shape: str, value: Any) -> None:
    """History drives HD gap-limit discovery: an entry it cannot read must not be invented.

    ``height`` is the one field where a negative value is legitimate — ElectrumX reports
    ``0`` or ``-1`` for unconfirmed — so only the un-interpretable shapes must refuse.
    """
    entry = with_field({"tx_hash": VALID_TXID, "height": 12}, "height", value)
    coro = electrum_client([entry]).get_history(b"\x11" * 32)

    if is_finite_number(value):
        assert (await coro)[0]["height"] == int(value)
        return
    await assert_fail_closed(coro, label=f"ElectrumX.get_history[height={shape}]")


# ── answering a DIFFERENT question than the one asked ─────────────────────────
#
# The sweep above varies the SHAPE of a field. These two vary its VALUE, and they are
# a different bug class: the response is perfectly well-formed, internally consistent,
# and describes a real object — just not the one that was requested. Both guards were
# invisible to mutation testing (``if False:`` left the whole suite green) precisely
# because every test above hands back a value that already matches what it asked for.


#: A second well-formed transaction, differing from ``_VALID_RAW`` only in nLockTime.
#: Both parse; only the hash tells them apart, which is the entire point.
_OTHER_VALID_RAW = _VALID_RAW[:-4] + bytes.fromhex("01000000")
OTHER_VALID_TXID = hashlib.sha256(hashlib.sha256(_OTHER_VALID_RAW).digest()).digest()[::-1].hex()


async def test_electrumx_get_transaction_refuses_a_transaction_that_is_not_the_one_asked_for() -> None:
    """A server may answer ``blockchain.transaction.get`` with ANY transaction.

    ``swap.resolve.fetch_transaction`` and ``failover._holds_tx`` re-derive the id
    themselves; ``glyph/scanner.py`` did not, so a hostile server could hand it a
    transaction of its choosing and have the token metadata parsed out of that. The
    substituted transaction here is not malformed in any way — it is a valid
    transaction, it simply is not the requested one, so nothing but the hash binding
    can reject it.
    """
    assert OTHER_VALID_TXID != VALID_TXID, "the two fixtures must differ, or this proves nothing"

    client = electrum_client(_OTHER_VALID_RAW.hex())
    with pytest.raises(RxdSdkError, match="not the requested txid"):
        await client.get_transaction(Txid(VALID_TXID))


async def test_electrumx_get_transaction_still_accepts_the_transaction_it_asked_for() -> None:
    """The binding must not be a blanket refusal — the honest answer still passes."""
    got = await electrum_client(_VALID_RAW.hex()).get_transaction(Txid(VALID_TXID))
    assert bytes(got) == _VALID_RAW


@pytest.mark.parametrize("proved_height", [99, 101, 0, 999_999], ids=["one_below", "one_above", "genesis", "far"])
async def test_electrumx_get_merkle_refuses_a_proof_for_a_different_block(proved_height: int) -> None:
    """ElectrumX echoes ``block_height``; unbound, the SERVER picks which block it proves.

    Inclusion in *some* block is not the claim being made — the caller asked whether
    the transaction is in block N, and a proof for block M answers a question it did
    not ask. Every other test in this file requests height 100 and is handed 100 back,
    so the echo was never actually checked against the request.
    """
    result = {"block_height": proved_height, "merkle": ["ab" * 32], "pos": 3}
    with pytest.raises(RxdSdkError, match="not the requested"):
        await electrum_client(result).get_transaction_merkle(Txid(VALID_TXID), BlockHeight(100))


async def test_electrumx_get_merkle_still_accepts_a_proof_for_the_requested_block() -> None:
    """The height binding must not reject the honest answer."""
    result = {"block_height": 100, "merkle": ["ab" * 32], "pos": 3}
    assert await electrum_client(result).get_transaction_merkle(Txid(VALID_TXID), BlockHeight(100)) is not None


# ── the watchtower's claim-detection outspend: the un-fixed twin of the bug ───


class _FakeAiohttpResponse:
    """Minimal aiohttp-response double for the watchtower's ``session.get(...)`` usage."""

    def __init__(self, payload: Any) -> None:
        self._payload = payload

    async def __aenter__(self) -> _FakeAiohttpResponse:
        return self

    async def __aexit__(self, *exc: object) -> None:
        return None

    def raise_for_status(self) -> None:
        return None

    async def json(self) -> Any:
        return self._payload


class _FakeAiohttpSession:
    def __init__(self, payload: Any) -> None:
        self._payload = payload
        self.requested: list[str] = []

    def get(self, url: str, **_: Any) -> _FakeAiohttpResponse:
        self.requested.append(url)
        return _FakeAiohttpResponse(self._payload)


@pytest.mark.parametrize(
    ("shape", "payload"),
    [
        ("null", {"spent": None}),
        ("missing", {}),
        ("zero", {"spent": 0}),
        ("empty_string", {"spent": ""}),
        ("empty_list", {"spent": []}),
        ("empty_dict", {"spent": {}}),
        ("string_false", {"spent": "false"}),
        ("string_true", {"spent": "true"}),
        ("one", {"spent": 1}),
        ("not_a_dict", ["spent"]),
        ("nan", {"spent": float("nan")}),
    ],
)
async def test_watchtower_outspend_refuses_a_non_boolean_spent(shape: str, payload: Any) -> None:
    """THE lead regression. ``mempool_space_outspend`` read ``bool(data.get("spent"))``.

    This is the same defect as the fixed ``bool(spend.get("spent", True))`` one layer down in
    ``network/bitcoin.py``, pointing the other way: every present-but-falsy shape read as NOT
    SPENT. And a NOT-SPENT answer is a **successful** read, not an exception, so it never
    reaches ``OutspendBtcClaimSource.claim_status``'s "every source failed" fail-closed
    branch — the multi-source fan-out cannot rescue it. The consequence is that the maker's
    on-chain claim goes undetected and ``PAGE_CLAIM`` is silently suppressed, which this
    module's own docstring names as the forbidden failure for an alert-only tower.

    Refusing makes the source *fail*, so it drops out of the fan-out and a tower blind across
    every source pages instead of reporting "not claimed".
    """
    from pyrxd.gravity.watch.adapters import mempool_space_outspend

    session = _FakeAiohttpSession(payload)
    await assert_fail_closed(
        mempool_space_outspend(session, "https://esplora.invalid", VALID_TXID, 0),
        label=f"mempool_space_outspend[spent={shape}]",
    )


async def test_watchtower_outspend_reports_a_real_spend() -> None:
    """The honest path must still work: a real ``true`` with a real txid detects the claim."""
    from pyrxd.gravity.watch.adapters import mempool_space_outspend

    session = _FakeAiohttpSession({"spent": True, "txid": OTHER_TXID})
    spent, spender = await mempool_space_outspend(session, "https://esplora.invalid", VALID_TXID, 0)
    assert (spent, spender) == (True, OTHER_TXID)

    session = _FakeAiohttpSession({"spent": False})
    assert await mempool_space_outspend(session, "https://esplora.invalid", VALID_TXID, 0) == (False, None)


@pytest.mark.parametrize(
    ("shape", "spender"),
    [
        ("path_traversal", "../" + "a" * 61),
        ("query_string", "?x=" + "a" * 61),
        ("fragment", "#" + "a" * 63),
        ("slashes", "a" * 32 + "/" + "b" * 31),
        ("non_hex", "z" * 64),
        ("wrong_length", "ab" * 40),
        ("not_a_string", 12),
    ],
)
async def test_watchtower_outspend_rejects_a_non_txid_spender(shape: str, spender: Any) -> None:
    """The spender id was length-checked but never charset-checked.

    ``mempool_space_tx_hex`` interpolates it UNQUOTED into ``/api/tx/{txid}/hex``, so a
    64-character value containing ``/``, ``?`` or ``#`` is a path-injection primitive
    pointed at whichever Esplora host the tower trusts.
    """
    from pyrxd.gravity.watch.adapters import mempool_space_outspend

    session = _FakeAiohttpSession({"spent": True, "txid": spender})
    spent, resolved = await mempool_space_outspend(session, "https://esplora.invalid", VALID_TXID, 0)
    assert spent is True
    assert resolved is None, "a non-txid spender must be dropped, never used to build a URL"


# ── the RSWP orderbook's liveness gate ────────────────────────────────────────


@pytest.mark.parametrize(
    ("shape", "result"),
    [
        ("empty_dict", {}),
        ("no_script_pubkey", {"value": 1}),
        ("empty_script_hex", {"scriptPubKey": {"hex": ""}, "value": 1}),
        ("script_not_a_dict", {"scriptPubKey": "0014aa", "value": 1}),
        ("no_value", {"scriptPubKey": {"hex": "0014" + "11" * 20}}),
    ],
)
async def test_node_rpc_is_unspent_requires_a_describable_output(shape: str, result: Any) -> None:
    """``is_unspent`` was ``isinstance(out, dict)`` — a bare ``{}`` read as LIVE.

    This is the ``fillable`` gate of the RSWP orderbook. A response that cannot describe the
    output it claims exists is not evidence that the output exists.
    ``BitcoinCoreFundingReader.read_confirmed_unspent_output`` has always required a non-empty
    ``scriptPubKey.hex`` and a ``value``; this sibling did not.
    """
    from pyrxd.swap.rswp.node_rpc import NodeRpcSource

    source = NodeRpcSource("http://node.invalid:7332")

    async def _call(method: str, params: list) -> Any:
        return result

    source._call = _call  # type: ignore[method-assign]
    assert await source.is_unspent(VALID_TXID, 0) is False


async def test_node_rpc_is_unspent_accepts_a_real_gettxout() -> None:
    """The honest path: a full gettxout result still reads as live."""
    from pyrxd.swap.rswp.node_rpc import NodeRpcSource

    source = NodeRpcSource("http://node.invalid:7332")

    async def _call(method: str, params: list) -> Any:
        return {"scriptPubKey": {"hex": "76a914" + "11" * 20 + "88ac"}, "value": 0.5}

    source._call = _call  # type: ignore[method-assign]
    assert await source.is_unspent(VALID_TXID, 0) is True


# ── the Radiant covenant leg's confirmation gate ──────────────────────────────


@pytest.mark.parametrize(("shape", "value"), HOSTILE_SCALARS, ids=[s for s, _ in HOSTILE_SCALARS])
async def test_radiant_leg_confirmations_fails_closed(shape: str, value: Any) -> None:
    """``int(info.get("confirmations", 0) or 0)`` — the RXD leg's own depth oracle.

    A stringly-typed ``"12"`` coerced straight into a depth, and a JSON ``Infinity`` raised
    ``OverflowError`` — not a ``NetworkError``, so it escaped every handler on a value-moving
    path. Present-but-falsy correctly reads as depth 0 (the ``or 0``), which is the
    fail-closed direction and is preserved.
    """
    from pyrxd.gravity.radiant_leg import RadiantChainIO

    info = with_field({"confirmations": 3}, "confirmations", value)

    class _Client:
        async def get_transaction_verbose(self, txid: str) -> Any:
            return info

    leg = RadiantChainIO.__new__(RadiantChainIO)
    leg._client = _Client()
    coro = leg.confirmations(VALID_TXID)

    if isinstance(value, _Missing) or not value:  # missing / null / 0 / "" / [] / {} / False
        assert await coro == 0
        return
    if is_finite_number(value):
        assert await coro == max(0, int(value))
        return
    await assert_fail_closed(coro, label=f"RadiantChainIO.confirmations[{shape}]")
