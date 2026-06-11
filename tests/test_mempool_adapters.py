"""Unit tests for the mempool.space value-moving adapters (P-TRANSPORT).

The BtcLeg's mainnet broadcaster + funding reader. Mocked HTTP — no network. Focus:
the fail-closed paths (the panel's MUST-not-cut), idempotent broadcast, and the
Protocol conformance the leg relies on.
"""

from __future__ import annotations

# A real mainnet segwit tx (the spike's P2TR HTLC claim) + its txid — so the
# broadcaster's local txid derivation has a real round-trip.
import json as _json
from pathlib import Path as _Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from pyrxd.btc_wallet.htlc_leg import BtcBroadcaster, BtcFundingReader
from pyrxd.network.bitcoin import (
    MempoolSpaceBroadcaster,
    MempoolSpaceFundingReader,
    _MempoolHttpClient,
)
from pyrxd.security.errors import InsufficientConfirmationsError, NetworkError, ValidationError

_SPIKE = _Path(__file__).resolve().parent.parent / "docs" / "brainstorms" / "gravity-ref-spike"


def _claim_vec():
    p = _SPIKE / ".live_swap_nft.json"
    if not p.exists():
        pytest.skip("mainnet golden vector not present")
    d = _json.loads(p.read_text())
    return bytes.fromhex(d["btc_claim_tx_hex"]), d["btc_claim_txid"]


def _post_resp(status: int, body: str) -> MagicMock:
    resp = MagicMock()
    resp.status = status
    resp.content_type = "text/plain"
    resp.read = AsyncMock(return_value=body.encode())
    resp.__aenter__ = AsyncMock(return_value=resp)
    resp.__aexit__ = AsyncMock(return_value=False)
    return resp


def _session_posting(resp: MagicMock) -> MagicMock:
    s = MagicMock()
    s.post = MagicMock(return_value=resp)
    return s


# --------------------------------------------------------------------------- Protocol conformance


def test_adapters_satisfy_leg_protocols():
    assert isinstance(MempoolSpaceBroadcaster(), BtcBroadcaster)
    assert isinstance(MempoolSpaceFundingReader(), BtcFundingReader)


# --------------------------------------------------------------------------- broadcaster


async def test_broadcast_success_returns_node_txid():
    raw, txid = _claim_vec()
    b = MempoolSpaceBroadcaster()
    b._http.session = AsyncMock(return_value=_session_posting(_post_resp(200, txid)))
    assert await b.broadcast(raw) == txid


async def test_broadcast_idempotent_already_known_derives_txid_locally():
    raw, txid = _claim_vec()
    b = MempoolSpaceBroadcaster()
    b._http.session = AsyncMock(return_value=_session_posting(_post_resp(400, "sendrawtransaction: txn-already-known")))
    # Idempotent: derives the canonical txid locally from raw -> matches the real txid.
    assert await b.broadcast(raw) == txid


async def test_broadcast_present_phrases_are_idempotent_success():
    # LOW-R4: the specific "already present" phrases each derive the txid locally (no-op re-broadcast).
    raw, txid = _claim_vec()
    for body in (
        "sendrawtransaction: txn-already-known",
        "Transaction already in block chain",
        "txn-already-in-mempool: already in mempool",
    ):
        b = MempoolSpaceBroadcaster()
        b._http.session = AsyncMock(return_value=_session_posting(_post_resp(400, body)))
        assert await b.broadcast(raw) == txid, body


async def test_broadcast_already_spent_conflict_is_fail_closed():
    # LOW-R4: a rejection containing the bare word "already" but meaning a DOUBLE-SPEND/conflict
    # (the counterparty spent the HTLC output first) must NOT be misread as idempotent success —
    # else broadcast() would return a txid for a tx that never landed. Fail-closed.
    raw, _ = _claim_vec()
    for body in (
        "bad-txns-inputs-missingorspent",
        "sendrawtransaction: inputs already spent by another transaction",
        "txn-mempool-conflict",
    ):
        b = MempoolSpaceBroadcaster()
        b._http.session = AsyncMock(return_value=_session_posting(_post_resp(400, body)))
        with pytest.raises(NetworkError, match="broadcast rejected"):
            await b.broadcast(raw)


async def test_broadcast_rejects_empty():
    b = MempoolSpaceBroadcaster()
    with pytest.raises(ValidationError, match="non-empty bytes"):
        await b.broadcast(b"")


async def test_broadcast_real_error_fail_closed():
    raw, _ = _claim_vec()
    b = MempoolSpaceBroadcaster()
    b._http.session = AsyncMock(
        return_value=_session_posting(_post_resp(400, "non-mandatory-script-verify-flag (...)"))
    )
    with pytest.raises(NetworkError, match="broadcast rejected"):
        await b.broadcast(raw)


async def test_broadcast_non_txid_success_body_fail_closed():
    raw, _ = _claim_vec()
    b = MempoolSpaceBroadcaster()
    b._http.session = AsyncMock(return_value=_session_posting(_post_resp(200, "not-a-txid")))
    with pytest.raises(NetworkError, match="non-txid body"):
        await b.broadcast(raw)


# --------------------------------------------------------------------------- funding reader: confirmations


async def test_confirmations_confirmed():
    r = MempoolSpaceFundingReader()
    r._http.tx_status = AsyncMock(return_value={"confirmed": True, "block_height": 800_000})
    r._http.tip_height = AsyncMock(return_value=800_005)
    assert await r.confirmations("ab" * 32) == 6  # 800005 - 800000 + 1


async def test_confirmations_unconfirmed_is_zero():
    r = MempoolSpaceFundingReader()
    r._http.tx_status = AsyncMock(return_value={"confirmed": False, "block_height": None})
    assert await r.confirmations("ab" * 32) == 0  # fail-closed: unconfirmed -> 0, never "assume"


async def test_confirmations_missing_height_is_zero():
    r = MempoolSpaceFundingReader()
    r._http.tx_status = AsyncMock(return_value={"confirmed": True})  # no block_height
    assert await r.confirmations("ab" * 32) == 0


async def test_confirmations_block_above_tip_fails_closed_f005():
    # F-005: a tx cannot be in a block above the tip — an inverted/garbage response is a
    # confused/lying source and must fail-closed LOUD, not silently compute a depth.
    r = MempoolSpaceFundingReader()
    r._http.tx_status = AsyncMock(return_value={"confirmed": True, "block_height": 800_010})
    r._http.tip_height = AsyncMock(return_value=800_005)  # block_height > tip
    with pytest.raises(NetworkError, match="inconsistent confirmation data"):
        await r.confirmations("ab" * 32)


async def test_confirmations_block_height_below_one_fails_closed_f005():
    r = MempoolSpaceFundingReader()
    r._http.tx_status = AsyncMock(return_value={"confirmed": True, "block_height": 0})
    r._http.tip_height = AsyncMock(return_value=800_005)
    with pytest.raises(NetworkError, match="inconsistent confirmation data"):
        await r.confirmations("ab" * 32)


# --------------------------------------------------------------------------- funding reader: amount read-back


async def test_read_output_amount_above_min_confs():
    r = MempoolSpaceFundingReader()
    r._http.tx_status = AsyncMock(return_value={"confirmed": True, "block_height": 800_000})
    r._http.tip_height = AsyncMock(return_value=800_010)
    r._http.tx_json = AsyncMock(return_value={"vout": [{"value": 100_000}, {"value": 5}]})
    assert await r.read_output_amount_sats("ab" * 32, 0, min_confirmations=6) == 100_000


async def test_read_output_amount_below_min_confs_fail_closed():
    r = MempoolSpaceFundingReader()
    r._http.tx_status = AsyncMock(return_value={"confirmed": True, "block_height": 800_000})
    r._http.tip_height = AsyncMock(return_value=800_001)  # only 2 confs
    with pytest.raises(InsufficientConfirmationsError) as ei:
        await r.read_output_amount_sats("ab" * 32, 0, min_confirmations=6)
    assert ei.value.have == 2
    assert ei.value.required == 6


async def test_read_output_amount_bad_vout_fail_closed():
    r = MempoolSpaceFundingReader()
    r._http.tx_status = AsyncMock(return_value={"confirmed": True, "block_height": 800_000})
    r._http.tip_height = AsyncMock(return_value=800_010)
    r._http.tx_json = AsyncMock(return_value={"vout": [{"value": 100_000}]})
    with pytest.raises(NetworkError, match="could not read output value"):
        await r.read_output_amount_sats("ab" * 32, 5, min_confirmations=1)  # vout 5 OOB


# --------------------------------------------------------------------------- txid_of (local)


async def test_txid_of_derives_locally():
    raw, txid = _claim_vec()
    assert await MempoolSpaceFundingReader().txid_of(raw) == txid


# --------------------------------------------------------------------------- list_address_utxos


async def test_list_address_utxos_parses():
    r = MempoolSpaceFundingReader()
    r._http.session = AsyncMock()  # not used directly; patch _get_json via the helper
    # Patch the JSON fetch the method performs.
    import pyrxd.network.bitcoin as mod

    async def fake_get_json(_s, _url):
        return [
            {"txid": "ab" * 32, "vout": 0, "value": 50_000, "status": {"confirmed": True, "block_height": 800_000}},
            {"txid": "cd" * 32, "vout": 2, "value": 9, "status": {"confirmed": False}},
        ]

    orig = mod._get_json
    mod._get_json = fake_get_json
    try:
        utxos = await r.list_address_utxos("bc1qexample")
    finally:
        mod._get_json = orig
    assert utxos[0] == {"txid": "ab" * 32, "vout": 0, "value_sats": 50_000, "confirmed": True, "height": 800_000}
    assert utxos[1]["confirmed"] is False and utxos[1]["height"] is None


async def test_list_address_utxos_rejects_empty_address():
    with pytest.raises(ValidationError, match="non-empty string"):
        await MempoolSpaceFundingReader().list_address_utxos("")


# --------------------------------------------------------------------------- shared client url join


def test_http_client_url_join_preserves_api_path():
    # __init__ adds a trailing slash, so a relative part joins UNDER the api base —
    # the /signet/api/ path segment is preserved (important: signet base URL must not
    # be truncated, or a signet tx would hit the mainnet endpoint).
    c = _MempoolHttpClient(base_url="https://mempool.space/signet/api")
    assert c.url("tx") == "https://mempool.space/signet/api/tx"
    assert c.url("blocks/tip/height") == "https://mempool.space/signet/api/blocks/tip/height"
    # Mainnet default likewise preserves /api/.
    assert _MempoolHttpClient().url("tx") == "https://mempool.space/api/tx"


# --------------------------------------------------------------------------- _MempoolHttpClient raw HTTP


def _get_resp(status: int, body: bytes, content_type: str = "text/plain") -> MagicMock:
    resp = MagicMock()
    resp.status = status
    resp.content_type = content_type
    resp.read = AsyncMock(return_value=body)
    resp.__aenter__ = AsyncMock(return_value=resp)
    resp.__aexit__ = AsyncMock(return_value=False)
    return resp


def _session_getting(resp: MagicMock) -> MagicMock:
    s = MagicMock()
    s.get = MagicMock(return_value=resp)
    return s


async def test_http_client_session_lifecycle():
    c = _MempoolHttpClient()
    s1 = await c.session()
    s2 = await c.session()
    assert s1 is s2  # reused
    await c.close()  # closes + clears
    await c.close()  # idempotent (no session)


async def test_http_client_tip_height_parses_and_fail_closed():
    c = _MempoolHttpClient()
    c.session = AsyncMock(return_value=_session_getting(_get_resp(200, b"800123")))
    assert await c.tip_height() == 800_123
    # non-200 -> fail-closed
    c.session = AsyncMock(return_value=_session_getting(_get_resp(500, b"")))
    with pytest.raises(NetworkError, match="tip height"):
        await c.tip_height()
    # non-numeric body -> fail-closed
    c.session = AsyncMock(return_value=_session_getting(_get_resp(200, b"notanumber")))
    with pytest.raises(NetworkError):
        await c.tip_height()


async def test_http_client_tx_status_and_json_require_dict():
    c = _MempoolHttpClient()
    c.session = AsyncMock(return_value=_session_getting(_get_resp(200, b'["not","a","dict"]', "application/json")))
    with pytest.raises(NetworkError, match="tx status"):
        await c.tx_status("ab" * 32)
    c.session = AsyncMock(return_value=_session_getting(_get_resp(200, b'["x"]', "application/json")))
    with pytest.raises(NetworkError, match="tx json"):
        await c.tx_json("ab" * 32)


async def test_broadcast_http_clienterror_fail_closed():
    import aiohttp

    raw, _ = _claim_vec()
    b = MempoolSpaceBroadcaster()
    bad_session = MagicMock()
    bad_session.post = MagicMock(side_effect=aiohttp.ClientError("boom"))
    b._http.session = AsyncMock(return_value=bad_session)
    with pytest.raises(NetworkError, match="broadcast HTTP request failed"):
        await b.broadcast(raw)


async def test_list_address_utxos_non_list_fail_closed():
    r = MempoolSpaceFundingReader()
    import pyrxd.network.bitcoin as mod

    async def fake_get_json(_s, _url):
        return {"not": "a list"}

    orig = mod._get_json
    mod._get_json = fake_get_json
    try:
        with pytest.raises(NetworkError, match="unexpected address utxo"):
            await r.list_address_utxos("bc1qx")
    finally:
        mod._get_json = orig


async def test_list_address_utxos_malformed_entry_fail_closed():
    r = MempoolSpaceFundingReader()
    import pyrxd.network.bitcoin as mod

    async def fake_get_json(_s, _url):
        return [{"txid": "ab" * 32}]  # missing vout/value

    orig = mod._get_json
    mod._get_json = fake_get_json
    try:
        with pytest.raises(NetworkError, match="malformed address utxo"):
            await r.list_address_utxos("bc1qx")
    finally:
        mod._get_json = orig


async def test_reader_close_is_idempotent():
    r = MempoolSpaceFundingReader()
    await r.close()
    await r.close()


async def test_http_client_tx_status_and_json_happy_path():
    c = _MempoolHttpClient()
    c.session = AsyncMock(
        return_value=_session_getting(_get_resp(200, b'{"confirmed": true, "block_height": 1}', "application/json"))
    )
    assert (await c.tx_status("ab" * 32))["confirmed"] is True
    c.session = AsyncMock(
        return_value=_session_getting(_get_resp(200, b'{"vout": [{"value": 7}]}', "application/json"))
    )
    assert (await c.tx_json("ab" * 32))["vout"][0]["value"] == 7
