"""Tests for the watchtower transports (``gravity.watch.adapters``)."""

from __future__ import annotations

import hashlib
import json
import logging
import os

import pytest

from pyrxd.btc_wallet import taproot as t
from pyrxd.gravity.swap_state import NegotiatedTerms, SwapRecord, SwapState
from pyrxd.gravity.watch import (
    CallbackAlertChannel,
    ElectrumRxdChainSource,
    JsonDirRecordStore,
    LoggingAlertChannel,
    OutspendBtcClaimSource,
    Page,
    Severity,
    mempool_space_outspend,
)
from pyrxd.security.errors import NetworkError, ValidationError


def _xonly() -> bytes:
    import coincurve

    return coincurve.PublicKeyXOnly.from_secret(os.urandom(32)).format()


def _terms() -> NegotiatedTerms:
    return NegotiatedTerms(
        hashlock=hashlib.sha256(os.urandom(32)).digest(),
        btc_sats=100_000,
        radiant_amount=1_000,
        t_btc=t.Timelock(144, t.TimeUnit.BLOCKS),
        t_rxd=t.Timelock(72, t.TimeUnit.BLOCKS),
        asset_variant="ft",
        genesis_ref=b"\xaa" * 36,
        taker_dest_hash=b"\x11" * 32,
        maker_dest_hash=b"\x22" * 32,
        btc_claim_pubkey_xonly=_xonly(),
        btc_refund_pubkey_xonly=_xonly(),
    )


# --- JsonDirRecordStore ---------------------------------------------------


async def test_record_store_lists_only_active(tmp_path):
    (tmp_path / "active.json").write_text(json.dumps(SwapRecord(state=SwapState.BOTH_LOCKED, terms=_terms()).to_dict()))
    (tmp_path / "done.json").write_text(json.dumps(SwapRecord(state=SwapState.COMPLETED, terms=_terms()).to_dict()))
    (tmp_path / "garbage.json").write_text("{not valid json")

    active = await JsonDirRecordStore(tmp_path).list_active()
    assert [swap_id for swap_id, _ in active] == ["active"]  # terminal + garbage skipped
    assert active[0][1].state is SwapState.BOTH_LOCKED


async def test_record_store_missing_dir_raises(tmp_path):
    # red-team MEDIUM: a missing/typo'd/unmounted records dir must NOT read as a healthy 0-swap
    # tick — it RAISES so the reconciler pages "watching nothing" instead of looking healthy.
    with pytest.raises(NetworkError, match="does not exist"):
        await JsonDirRecordStore(tmp_path / "nope").list_active()


async def test_record_store_all_unreadable_raises(tmp_path):
    # Files present but EVERY one unreadable => blind, not "0 active" => raise.
    (tmp_path / "a.json").write_text("{ not json")
    (tmp_path / "b.json").write_text("also not json")
    with pytest.raises(NetworkError, match="unreadable"):
        await JsonDirRecordStore(tmp_path).list_active()


async def test_record_store_empty_existing_dir_is_ok(tmp_path):
    # A genuinely empty existing dir is healthy (0 swaps), not an error.
    assert await JsonDirRecordStore(tmp_path).list_active() == []


# --- ElectrumRxdChainSource -----------------------------------------------


class FakeRxdClient:
    def __init__(self, tip, verbose=None, raise_verbose=False):
        self._tip = tip
        self._verbose = verbose if verbose is not None else {}
        self._raise = raise_verbose

    async def get_tip_height(self):
        return self._tip

    async def get_transaction_verbose(self, txid):
        if self._raise:
            raise RuntimeError("tx not found")
        return self._verbose


async def test_rxd_source_tip_and_confs():
    src = ElectrumRxdChainSource(FakeRxdClient(200, {"confirmations": 5}))
    assert await src.tip_height() == 200
    assert await src.covenant_confirmations("ab" * 32 + ":0") == 5


@pytest.mark.parametrize("verbose", [{}, {"confirmations": 0}])
async def test_rxd_source_unmined_yields_none(verbose):
    src = ElectrumRxdChainSource(FakeRxdClient(200, verbose))
    assert await src.covenant_confirmations("ab" * 32 + ":0") is None


async def test_rxd_source_lookup_error_yields_none():
    src = ElectrumRxdChainSource(FakeRxdClient(200, raise_verbose=True))
    assert await src.covenant_confirmations("ab" * 32 + ":0") is None


# --- OutspendBtcClaimSource -----------------------------------------------


class FakeReader:
    def __init__(self, confs):
        self._c = confs

    async def confirmations(self, txid):
        return self._c


async def test_claim_source_spent():
    async def outspend(txid, vout):
        return True, "ef" * 32

    src = OutspendBtcClaimSource(outspend_fn=outspend, funding_reader=FakeReader(7))
    status = await src.claim_status("cd" * 32, 1)
    assert status.claimed is True
    assert status.claim_txid == "ef" * 32
    assert await src.confirmations("ef" * 32) == 7


async def test_claim_source_unspent():
    async def outspend(txid, vout):
        return False, None

    src = OutspendBtcClaimSource(outspend_fn=outspend, funding_reader=FakeReader(0))
    status = await src.claim_status("cd" * 32, 1)
    assert status.claimed is False
    assert status.claim_txid is None


async def _unspent(txid, vout):
    return False, None


async def _spent(txid, vout):
    return True, "ef" * 32


async def _boom(txid, vout):
    raise RuntimeError("esplora 503")


async def test_claim_source_multi_any_spent_detects():
    # red-team #2: detection fails TOWARD paging — ANY source seeing the outpoint spent → claimed,
    # so a single lagging/lying source can no longer suppress the claim page.
    src = OutspendBtcClaimSource(outspend_fns=[_unspent, _spent], funding_reader=FakeReader(7))
    status = await src.claim_status("cd" * 32, 1)
    assert status.claimed is True and status.claim_txid == "ef" * 32


async def test_claim_source_multi_all_unspent_is_unspent():
    src = OutspendBtcClaimSource(outspend_fns=[_unspent, _unspent], funding_reader=FakeReader(0))
    assert (await src.claim_status("cd" * 32, 1)).claimed is False


async def test_claim_source_one_source_down_other_decides():
    # One source erroring must not blind detection; the surviving source decides.
    src = OutspendBtcClaimSource(outspend_fns=[_boom, _spent], funding_reader=FakeReader(7))
    assert (await src.claim_status("cd" * 32, 1)).claimed is True


async def test_claim_source_all_sources_down_fails_closed():
    # red-team #2: EVERY detection source failing → blind → fail CLOSED (raise), never silent unspent.
    src = OutspendBtcClaimSource(outspend_fns=[_boom, _boom], funding_reader=FakeReader(0))
    with pytest.raises(NetworkError, match="claim-detection source"):
        await src.claim_status("cd" * 32, 1)


# --- mempool_space_outspend -----------------------------------------------


class _FakeResp:
    def __init__(self, data):
        self._data = data

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    def raise_for_status(self):
        pass

    async def json(self):
        return self._data


class _FakeSession:
    def __init__(self, data):
        self._data = data
        self.urls: list[str] = []

    def get(self, url, timeout=None):  # timeout: the per-request ClientTimeout the adapter now sets
        self.urls.append(url)
        self.last_timeout = timeout
        return _FakeResp(self._data)


async def test_mempool_outspend_spent():
    sess = _FakeSession({"spent": True, "txid": "ef" * 32, "vin": 0})
    spent, spender = await mempool_space_outspend(sess, "https://mempool.space/", "cd" * 32, 1)
    assert spent is True
    assert spender == "ef" * 32
    assert sess.urls == [f"https://mempool.space/api/tx/{'cd' * 32}/outspend/1"]


async def test_mempool_outspend_unspent():
    spent, spender = await mempool_space_outspend(_FakeSession({"spent": False}), "https://mempool.space", "cd" * 32, 0)
    assert (spent, spender) == (False, None)


async def test_mempool_outspend_sets_per_request_timeout():
    # red-team #8: an explicit per-request timeout is passed (not aiohttp's 300s session default).
    sess = _FakeSession({"spent": False})
    await mempool_space_outspend(sess, "https://m", "cd" * 32, 0, timeout_s=7.0)
    assert sess.last_timeout is not None


async def test_mempool_outspend_bad_spender_txid_dropped():
    spent, spender = await mempool_space_outspend(
        _FakeSession({"spent": True, "txid": "short"}), "https://m", "cd" * 32, 0
    )
    assert spent is True
    assert spender is None  # malformed txid not trusted


# --- alert channels -------------------------------------------------------


def _page(sev=Severity.CRITICAL) -> Page:
    return Page(
        "s1",
        intent=None,
        severity=sev,
        message="hello",
        recommended_action=None,
        deadline_rxd_height=None,
        low_corroboration=False,
    )


async def test_logging_alert_channel(caplog):
    with caplog.at_level(logging.ERROR, logger="pyrxd.watchtower.alerts"):
        await LoggingAlertChannel().send(_page(Severity.CRITICAL))
    assert any("hello" in r.message for r in caplog.records)


async def test_callback_alert_channel():
    seen = []

    async def sink(page):
        seen.append(page)

    await CallbackAlertChannel(sink).send(_page())
    assert len(seen) == 1


def test_callback_alert_channel_rejects_non_callable():
    with pytest.raises(ValidationError):
        CallbackAlertChannel(send_fn="nope")
