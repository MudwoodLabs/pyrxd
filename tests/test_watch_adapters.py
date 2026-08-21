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
    MempoolClaimBytesSource,
    OutspendBtcClaimSource,
    Page,
    Severity,
    mempool_space_outspend,
    mempool_space_tx_hex,
)
from pyrxd.gravity.watch.claim_executor import ClaimBytesSource
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


async def test_record_store_excludes_executor_sidecars(tmp_path):
    # The refund blob + the claim covenant-context sidecars live beside the records and are NOT
    # SwapRecords; they must NOT be globbed as records (else they'd spam "unreadable" warnings and
    # could trip the all-unreadable "watching nothing" page — and their stem isn't the swap_id).
    (tmp_path / "s1.json").write_text(json.dumps(SwapRecord(state=SwapState.SECRET_REVEALED, terms=_terms()).to_dict()))
    (tmp_path / "s1.refund.json").write_text('{"version": 1, "swap_id": "s1", "raw_tx": "00"}')
    (tmp_path / "s1.claim.json").write_text('{"version": 1, "swap_id": "s1", "taker_pkh": "11", "maker_pkh": "22"}')
    active = await JsonDirRecordStore(tmp_path).list_active()
    assert [swap_id for swap_id, _ in active] == ["s1"]  # only the real record; sidecars ignored


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


# --- mempool_space_tx_hex / MempoolClaimBytesSource -----------------------


class _FakeHexResp:
    def __init__(self, text="", status=200):
        self._text, self.status = text, status

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    def raise_for_status(self):
        if self.status >= 400:
            raise NetworkError(f"http {self.status}")

    async def text(self):
        return self._text


class _FakeHexSession:
    def __init__(self, resp):
        self._resp, self.urls = resp, []

    def get(self, url, timeout=None):
        self.urls.append(url)
        return self._resp


async def test_tx_hex_returns_bytes():
    raw = b"\x01\x02\x03\xab"
    sess = _FakeHexSession(_FakeHexResp(raw.hex()))
    out = await mempool_space_tx_hex(sess, "https://mempool.space/", "cd" * 32)
    assert out == raw
    assert sess.urls == [f"https://mempool.space/api/tx/{'cd' * 32}/hex"]


async def test_tx_hex_404_returns_none():
    out = await mempool_space_tx_hex(_FakeHexSession(_FakeHexResp("", status=404)), "https://m", "cd" * 32)
    assert out is None  # not yet indexed/mined → None, never garbage bytes


async def test_tx_hex_unparseable_returns_none():
    out = await mempool_space_tx_hex(_FakeHexSession(_FakeHexResp("not hex!!")), "https://m", "cd" * 32)
    assert out is None


async def test_claim_bytes_source_satisfies_protocol_and_delegates():
    src = MempoolClaimBytesSource(_FakeHexSession(_FakeHexResp((b"\xde\xad").hex())), "https://m")
    assert isinstance(src, ClaimBytesSource)  # structural Protocol conformance
    assert await src.claim_tx_bytes("ab" * 32) == b"\xde\xad"


def test_claim_bytes_source_validates_base_url():
    with pytest.raises(ValidationError):
        MempoolClaimBytesSource(_FakeHexSession(_FakeHexResp()), "")


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


class _FakeRnsTransport:
    """Stands in for the RNS layer. The channel takes its transport injected, exactly as
    WebhookAlertChannel takes a session, so none of these tests need `rns` installed."""

    def __init__(self, fail: Exception | None = None):
        self.sent: list[tuple[bytes, bytes]] = []
        self._fail = fail

    def send(self, destination: bytes, payload: bytes) -> None:
        if self._fail is not None:
            raise self._fail
        self.sent.append((destination, payload))


class _AsyncRnsTransport(_FakeRnsTransport):
    async def send(self, destination: bytes, payload: bytes) -> None:  # type: ignore[override]
        super().send(destination, payload)


def _reticulum_page(message: str = "claim now", *, swap_id: str = "swap-7", corr: bool = False):
    from pyrxd.gravity.watch.alerts import Page, Severity
    from pyrxd.gravity.watch.decide import Intent

    return Page(
        swap_id=swap_id,
        intent=Intent.PAGE_CLAIM,
        severity=Severity.CRITICAL,
        message=message,
        recommended_action="taker_scrape_and_claim_asset",
        deadline_rxd_height=172,
        low_corroboration=corr,
    )


class TestReticulumAlertChannelFitsTheWire:
    """Reticulum drops a packet that exceeds its payload — it is not "mostly delivered".

    A realistic CRITICAL page serialises to 381 bytes under the webhook's own encoding,
    against a 465-byte ceiling. It fits, with under 100 bytes of headroom, which is
    exactly the kind of margin that holds in testing and fails on the one page that
    matters. So the channel guarantees fit rather than assuming it.
    """

    from pyrxd.gravity.watch.adapters import RETICULUM_MAX_PAYLOAD as _MAX

    @pytest.mark.parametrize("length", [0, 1, 100, 400, 465, 466, 4000, 100_000])
    def test_every_message_length_fits(self, length: int) -> None:
        from pyrxd.gravity.watch.adapters import ReticulumAlertChannel

        ch = ReticulumAlertChannel("ab" * 16, transport=_FakeRnsTransport())
        payload = ch.encode(_reticulum_page("X" * length))
        assert len(payload) <= self._MAX, f"{length}-char message produced {len(payload)} bytes"

    def test_the_actionable_fields_survive_truncation(self) -> None:
        """What an operator needs at 3am is which swap, how bad, what to run and by when.
        The prose is the compressible part, so it is what gets dropped."""
        from pyrxd.gravity.watch.adapters import ReticulumAlertChannel

        ch = ReticulumAlertChannel("ab" * 16, transport=_FakeRnsTransport())
        decoded = json.loads(ch.encode(_reticulum_page("X" * 4000, corr=True)))
        assert decoded["s"] == "swap-7"
        assert decoded["v"] == "critical"
        assert decoded["d"] == 172
        assert decoded["a"] == "taker_scrape_and_claim_asset"
        assert decoded["c"] == 1
        assert decoded["m"].endswith("..."), "a silently clipped instruction reads as a complete one"

    def test_a_page_that_cannot_fit_without_the_message_is_refused(self) -> None:
        """Better a loud failure than a page with the deadline truncated away."""
        from pyrxd.gravity.watch.adapters import ReticulumAlertChannel

        ch = ReticulumAlertChannel("ab" * 16, transport=_FakeRnsTransport(), max_payload=40)
        with pytest.raises(ValidationError, match="does not fit"):
            ch.encode(_reticulum_page("anything"))

    def test_the_compact_form_is_materially_smaller_than_the_webhook_form(self) -> None:
        """The reason this encoding exists at all."""
        from pyrxd.gravity.watch.adapters import ReticulumAlertChannel, page_to_dict

        page = _reticulum_page(
            "swap-2026-08-21-btc-rxd-0007: BTC HTLC claim is live and the counter-leg "
            "refund window opens at RXD height 172 — run `pyrxd swap claim` now",
            swap_id="swap-2026-08-21-btc-rxd-0007",
        )
        webhook = len(json.dumps(page_to_dict(page), separators=(",", ":")).encode())
        compact = len(ReticulumAlertChannel("ab" * 16, transport=_FakeRnsTransport()).encode(page))
        assert compact < webhook, f"compact {compact} is not smaller than webhook {webhook}"


class TestReticulumAlertChannelWiring:
    @pytest.mark.parametrize("bad", ["ab" * 8, b"\x01" * 15, b"\x01" * 17, "zz" * 16, 42])
    def test_a_destination_that_is_not_16_bytes_is_refused(self, bad) -> None:
        from pyrxd.gravity.watch.adapters import ReticulumAlertChannel

        with pytest.raises((ValidationError, ValueError)):
            ReticulumAlertChannel(bad, transport=_FakeRnsTransport())

    def test_a_transport_without_send_is_refused(self) -> None:
        from pyrxd.gravity.watch.adapters import ReticulumAlertChannel

        with pytest.raises(ValidationError, match="send"):
            ReticulumAlertChannel("ab" * 16, transport=object())

    @pytest.mark.parametrize("transport_cls", [_FakeRnsTransport, _AsyncRnsTransport])
    async def test_it_sends_over_either_a_sync_or_async_transport(self, transport_cls) -> None:
        """`rns` is synchronous; a future LXMF-backed transport would not be. Supporting
        both keeps that swap from becoming a redesign."""
        from pyrxd.gravity.watch.adapters import ReticulumAlertChannel

        t = transport_cls()
        await ReticulumAlertChannel("ab" * 16, transport=t).send(_reticulum_page())
        assert len(t.sent) == 1
        dest, payload = t.sent[0]
        assert dest == bytes.fromhex("ab" * 16)
        assert json.loads(payload)["s"] == "swap-7"

    async def test_a_transport_failure_propagates_so_the_page_is_retried(self) -> None:
        """DedupAlerter records dedup state only after send returns. Swallowing here would
        mark an undelivered page as sent."""
        from pyrxd.gravity.watch.adapters import ReticulumAlertChannel

        ch = ReticulumAlertChannel("ab" * 16, transport=_FakeRnsTransport(fail=NetworkError("radio down")))
        with pytest.raises(NetworkError, match="radio down"):
            await ch.send(_reticulum_page())


class TestReticulumFailureDoesNotSilenceTheOtherChannels:
    """The whole point of the spike: adding a second path must not make the first one
    worse. A dead LoRa link has to be strictly additive."""

    async def test_the_webhook_still_fires_when_reticulum_is_down(self) -> None:
        from pyrxd.gravity.watch.adapters import CompositeAlertChannel, ReticulumAlertChannel

        class _Recording:
            def __init__(self):
                self.sent = []

            async def send(self, page):
                self.sent.append(page)

        webhook = _Recording()
        dead = ReticulumAlertChannel("ab" * 16, transport=_FakeRnsTransport(fail=NetworkError("no radio")))
        composite = CompositeAlertChannel(dead, webhook)

        # Composite raises so DedupAlerter retries the page it could not fully deliver...
        with pytest.raises(NetworkError):
            await composite.send(_reticulum_page())
        # ...but the working channel was still attempted and delivered.
        assert len(webhook.sent) == 1, "a dead Reticulum link swallowed the webhook page"


class TestTheOptionalExtraStaysOptional:
    """`rns` carries a custom non-OSI licence with field-of-use restrictions. It must
    never reach anyone who did not ask for it — and the way that silently stops being
    true is a stray top-level import."""

    def test_pyrxd_imports_and_the_channel_works_without_rns(self) -> None:
        """Run it in a fresh interpreter where RNS is unimportable.

        The first version asserted ``"RNS" not in sys.modules``, which is a GLOBAL
        condition any other test file may legitimately violate — and one does: the
        integration module calls ``importorskip("RNS")`` at import time, so collecting it
        put RNS in ``sys.modules`` and this failed for a reason that had nothing to do with
        the property. The claim is "pyrxd works when rns is ABSENT", and only an isolated
        interpreter with the import actually blocked can test that.
        """
        import subprocess
        import sys

        snippet = (
            "import sys\n"
            "class _Block:\n"
            "    def find_module(self, name, path=None):\n"
            "        return self if name.split('.')[0] in ('RNS', 'rns') else None\n"
            "    def load_module(self, name):\n"
            "        raise ImportError('blocked for test')\n"
            "    def find_spec(self, name, path=None, target=None):\n"
            "        if name.split('.')[0] in ('RNS', 'rns'):\n"
            "            raise ImportError('blocked for test')\n"
            "        return None\n"
            "sys.meta_path.insert(0, _Block())\n"
            "from pyrxd.gravity.watch.adapters import ReticulumAlertChannel\n"
            "from pyrxd.gravity.watch.alerts import Page, Severity\n"
            "from pyrxd.gravity.watch.decide import Intent\n"
            "class T:\n"
            "    def send(self, d, p): pass\n"
            "pg = Page('s', Intent.PAGE_CLAIM, Severity.CRITICAL, 'm', 'a', 1, False)\n"
            "assert ReticulumAlertChannel('ab'*16, transport=T()).encode(pg)\n"
            "print('OK')\n"
        )
        proc = subprocess.run([sys.executable, "-c", snippet], capture_output=True, text=True, timeout=60)
        assert proc.returncode == 0, f"pyrxd failed with rns unavailable:\n{proc.stderr[-2000:]}"
        assert "OK" in proc.stdout

    def test_nothing_outside_the_transport_adapter_references_rns(self) -> None:
        """One containment point. If a second module starts importing it, the extra has
        stopped being optional in practice even if pyproject still says otherwise."""
        import ast
        import pathlib

        offenders = []
        for path in pathlib.Path("src/pyrxd").rglob("*.py"):
            for node in ast.walk(ast.parse(path.read_text())):
                names = []
                if isinstance(node, ast.Import):
                    names = [a.name for a in node.names]
                elif isinstance(node, ast.ImportFrom):
                    names = [node.module or ""]
                if any(n.split(".")[0] in {"RNS", "rns", "LXMF"} for n in names):
                    offenders.append(f"{path}:{node.lineno}")
        stray = [o for o in offenders if not o.startswith("src/pyrxd/gravity/watch/adapters.py:")]
        assert not stray, f"rns/LXMF imported outside the transport adapter: {stray}"
        assert offenders, "the detector found nothing at all — it has stopped detecting"

    def test_it_is_declared_as_an_extra_and_not_a_core_dependency(self) -> None:
        import tomllib

        with open("pyproject.toml", "rb") as fh:
            cfg = tomllib.load(fh)
        core = " ".join(cfg["project"]["dependencies"])
        assert "rns" not in core.split(), "rns leaked into core dependencies"
        assert "reticulum" in cfg["project"].get("optional-dependencies", {})
