"""The two-endpoint plumbing of §7.6 form 2, tested with servers that DISAGREE.

THE GAP (0.25.0 pre-release panel, H-M1). Every source rule in form 2 compares LABELS, and the
labels are only worth anything if each one names the server that really answered. The tests that
drove the CLI could not see which server answered: ``_pair()`` built two IDENTICAL fakes, the
one-record verify suite replaced the walk outright, and the single-endpoint test patched
``_endpoint_pair`` itself. So three plants survived the whole suite:

* the tip proof taken from the DISCOVERY client (``tip_client=client_b`` → ``client_a``);
* the anchor taken from the BINDING server, still labelled as the other one;
* one configured endpoint handed out under TWO labels by the real ``_endpoint_pair``.

Each is invisible when both servers say the same thing. So every test here gives the two servers
DIFFERENT answers — one stale, one reporting another block — and asserts both the verdict and
which server was asked what (every fake records its calls). The last class runs the REAL
``_endpoint_pair`` on a real ``--electrumx URL`` configuration.
"""

from __future__ import annotations

import hashlib
import json

from pyrxd.base58 import base58check_decode
from pyrxd.cli import config as cfg_mod
from pyrxd.cli import glyph_inspect
from pyrxd.cli.context import CliContext
from pyrxd.keys import PrivateKey
from tests.test_hashmark_verify_one_record import (
    NAME as VICTIM_NAME,
)
from tests.test_hashmark_verify_one_record import (
    _address,
    _fake_walk,
    _invoke,
    _signed,
    _tx,
)
from tests.test_hashmark_verify_one_record import (
    _Server as _MarkServer,
)
from tests.test_mutable_chain_is_discovered_from_the_chain import (
    MARK,
    MINT,
    MOVED,
    UPDATE_A,
    UPDATE_B,
    _sh_of,
)
from tests.test_name_at_mark_reaches_the_cli import NAME, _ctx, _payload, _Server

MOVED_H160 = base58check_decode(MOVED)[1:].hex()


class _Recording(_Server):
    """A derived fake that also records the two calls `FakeChainServer` does not: the anchor's."""

    async def get_transaction_verbose(self, txid):
        self.calls.append(("get_transaction_verbose", str(txid).lower()))
        return await super().get_transaction_verbose(txid)

    async def get_tip_height(self):
        self.calls.append(("get_tip_height", ""))
        return await super().get_tip_height()


class _LyingHistoryHeights(_Recording):
    def __init__(self, *, lie: dict[str, int], **kw) -> None:
        super().__init__(**kw)
        self.lie = lie

    async def get_history(self, script_hash):
        return [
            {**e, "height": self.lie.get(e["tx_hash"], e["height"])} for e in await super().get_history(script_hash)
        ]


def _attach(monkeypatch, a, b) -> dict:
    monkeypatch.setattr(glyph_inspect, "_endpoint_pair", lambda ctx: (a, "wss://a", b, "wss://b"))
    payload = _payload(MOVED_H160)
    glyph_inspect._attach_name_at_mark(_ctx(), payload, name=NAME, min_confirmations=6)
    return payload["outputs"][0]["hashmark"]["name_at_mark"]


def _asked(server, what: str) -> list[str]:
    return [arg for call, arg in server.calls if call == what]


def test_the_tip_is_proved_by_the_endpoint_that_did_not_discover_the_chain(monkeypatch) -> None:
    """Plant: `tip_client=client_a`. A never indexed UPDATE_B, so its OWN unspent set certifies the
    stale tip UPDATE_A:1 — the one-server truncation the two-source rule exists for. With the tip
    proved on B the walk ends incomplete; with it proved on A it completed, and form 2 answered."""
    a = _Recording(indexer=False, hide=frozenset({UPDATE_B}), mark_heights={MARK: 458605})
    b = _Recording(indexer=True, mark_heights={MARK: 458605})
    nam = _attach(monkeypatch, a, b)
    assert nam["form"] == 1, nam
    assert nam["chain"]["complete"] is False
    assert f"{UPDATE_A}:1 is not proved unspent" in nam["degraded_reason"]
    assert _asked(b, "get_utxos"), "the tip server was never asked"
    assert not _asked(a, "get_utxos"), "the discovery server was asked to prove its own tip"


def test_the_marks_block_comes_from_the_endpoint_that_did_not_bind_the_name(monkeypatch) -> None:
    """Plant: the anchor fetched from the BINDING server (B) but labelled as A. The labels then
    pass every rule while B has supplied both the binding and the block. Here A and B place the
    mark in different blocks, so which one answered is visible — in the anchor, and in the calls."""
    a = _Recording(indexer=False, mark_heights={MARK: 458586})
    b = _Recording(indexer=True, mark_heights={MARK: 458595})
    nam = _attach(monkeypatch, a, b)
    assert nam["binding_source"] == "wss://b"
    assert nam["anchor_source"] == "wss://a"
    assert nam["anchor"]["height"] == 458586, "the anchor must be A's answer, not the binding server's"
    assert MARK in _asked(a, "get_transaction_verbose")
    # ...and B, asked separately, places the mark elsewhere — so the verdict refuses.
    assert nam["form"] == 1 and "disagree about the mark's block" in nam["degraded_reason"]
    by = {r["source"]: r["mark"] for r in nam["heights"]["by_source"]}
    assert by == {"wss://a": 458586, "wss://b": 458595}


def test_the_tip_server_is_asked_where_every_walked_step_is(monkeypatch) -> None:
    """B's HISTORY was never read before: only its unspent set. So B could say anything about
    heights and nothing changed. B now reports where each step is, independently, and a lie there
    — one update's height — changes the outcome. Asserted on the calls too: B was asked about the
    mutable output of EVERY walked step."""
    a = _Recording(indexer=False, mark_heights={MARK: 458595})
    b = _LyingHistoryHeights(indexer=True, mark_heights={MARK: 458595}, lie={UPDATE_A: 458580})
    nam = _attach(monkeypatch, a, b)
    assert nam["form"] == 1, nam
    assert f"chain step {UPDATE_A}" in nam["degraded_reason"] and "'wss://b' says 458580" in nam["degraded_reason"]
    assert set(_asked(b, "get_history")) >= {_sh_of(MINT, 1), _sh_of(UPDATE_A, 1), _sh_of(UPDATE_B, 1)}


def test_two_agreeing_recording_servers_each_did_their_own_part(monkeypatch) -> None:
    """The honest pair, with the division of labour pinned: A discovers and anchors, B binds and
    proves the tip, both report heights — and form 2 answers."""
    a = _Recording(indexer=False, mark_heights={MARK: 458595})
    b = _Recording(indexer=True, mark_heights={MARK: 458595})
    nam = _attach(monkeypatch, a, b)
    assert nam["form"] == 2, nam["degraded_reason"]
    assert [c for c, _ in b.extension_calls] == ["wave.resolve"] and not a.extension_calls
    assert _asked(b, "get_utxos") and not _asked(a, "get_utxos")
    assert MARK in _asked(a, "get_transaction_verbose") and MARK in _asked(b, "get_transaction_verbose")
    assert _asked(a, "get_history") and _asked(b, "get_history")


class TestOneConfiguredEndpointCarriesOneLabel:
    """The REAL `_endpoint_pair`, on a real `--electrumx URL` configuration. Plant: the second
    client labelled differently from the first. With one endpoint every source rule must see ONE
    source; two labels for it make the rules pass on a single server's word."""

    URL = "wss://only.example.invalid:50022"

    def test_the_pair_is_one_endpoint_under_one_label(self, tmp_path, monkeypatch) -> None:
        for var in ("PYRXD_NETWORK", "PYRXD_ELECTRUMX"):
            monkeypatch.delenv(var, raising=False)
        cfg = cfg_mod.load(tmp_path / "no-such.toml").for_network("mainnet", electrumx_override=self.URL)
        ctx = CliContext(config=cfg, output_mode="human", wallet_path=tmp_path / "w", network="mainnet")
        client_a, label_a, client_b, label_b = glyph_inspect._endpoint_pair(ctx)
        assert label_a == label_b == self.URL
        for client in (client_a, client_b):
            assert [e.url for e in client.profile.endpoints] == [self.URL]

    def test_through_the_command_a_single_endpoint_never_establishes_a_name(self, tmp_path, monkeypatch) -> None:
        """End to end: `pyrxd --electrumx URL verify … --wave-name`. Only the client CLASS is
        replaced (keyed by URL, one fresh fake per client, as the real code builds one per call);
        the config loader, `_endpoint_pair` and the command are real. The fake walk is complete
        whenever its two labels differ — so a second label for the one endpoint would reach form 2."""
        for var in ("PYRXD_NETWORK", "PYRXD_ELECTRUMX"):
            monkeypatch.delenv(var, raising=False)
        key = PrivateKey()
        content = b"a single-endpoint press kit\n"
        txid, raw = _tx(_signed(content, key))
        mint = "cd" * 32
        built: list[str] = []

        import pyrxd.network.failover as failover

        def factory(profile, *_a, **_k):
            url = profile.endpoints[0].url
            built.append(url)
            return _MarkServer({txid: raw}, indexer=True, target=_address(key), mint=mint)

        monkeypatch.setattr(failover, "FailoverElectrumXClient", factory)
        _fake_walk(monkeypatch, _address(key))
        args = ["--json", "--electrumx", self.URL, "verify", txid, "--digest", hashlib.sha256(content).hexdigest()]
        r = _invoke(tmp_path, [*args, "--wave-name", VICTIM_NAME, "--min-confirmations", "6"])
        nam = json.loads(r.stdout)["records"][0]["name_at_mark"]
        assert set(built) == {self.URL}, built
        assert nam["resolved"] and nam["form"] == 1, nam
        assert nam["binding_source"] == nam["anchor_source"] == self.URL
        assert "both came from" in nam["degraded_reason"]
