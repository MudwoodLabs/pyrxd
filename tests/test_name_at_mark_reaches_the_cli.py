"""§7.6 form 2 is reachable from `pyrxd glyph inspect --wave-name NAME --min-confirmations N`.

The plan that built the walker, the fold, the anchor and the judge stopped at the CLI on purpose:
form 2 needed a candidate set and nothing could produce one, and "wiring a caller that always
degrades would be a caller-shaped wrapper around dead code." Discovery from the chain removed that
block. This file drives the real CLI attach path with fakes standing in for the two endpoints, so
every line below reaches a human through the same functions production does.

The fakes are the DERIVED `FakeChainServer` from the discovery tests — history and unspent sets
computed from the real mainnet bytes — with an indexer extension bolted onto one of them, because
that is what the two public servers actually look like: `electrumx.radiant4people.com` answers
`wave.resolve` with `-32601`, `electrumx.radiantcore.org` answers it (measured 2026-09-16).
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from pyrxd.base58 import base58check_decode
from pyrxd.cli import glyph_inspect
from pyrxd.cli.errors import UserError
from pyrxd.security.errors import NetworkError
from tests.test_mutable_chain_is_discovered_from_the_chain import (
    MARK,
    MINT,
    MINT_TARGET,
    MOVED,
    UPDATE_B,
    FakeChainServer,
)

NAME = "custodian-gate-x7f3.rxd"
LABEL = "custodian-gate-x7f3"
MOVED_H160 = base58check_decode(MOVED)[1:].hex()
OTHER_H160 = "00" * 20


class _Server(FakeChainServer):
    """A FakeChainServer that may also run the indexer extension."""

    def __init__(self, *, indexer: bool, **kwargs) -> None:
        super().__init__(**kwargs)
        self.indexer = indexer
        self.extension_calls: list[tuple[str, list]] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc) -> None:
        return None

    async def call_extension(self, method: str, params: list | None = None):
        self.extension_calls.append((method, list(params or [])))
        if not self.indexer:
            raise NetworkError("ElectrumX RPC error (code -32601)")
        if method == "wave.resolve":
            if params and params[0] == LABEL:
                # The measured shape from the public indexer, 2026-09-16.
                return {
                    "name": LABEL,
                    "ref": f"{MINT}_0",
                    "target": MOVED,
                    "zone": {"address": MOVED},
                    "owner": "e4bf68e0c8eb9018f15fa0",
                    "available": False,
                    "canonical": True,
                    "has_duplicates": False,
                    "expires": 1850744391,
                    "status": "active",
                }
            return None
        raise NetworkError(f"unknown method {method}")


def _pair(mark_height: int | None, *, two: bool = True, indexer_on: str = "b"):
    a = _Server(indexer=indexer_on in ("a", "both"), mark_heights={MARK: mark_height} if mark_height else {})
    if not two:
        return a, "wss://only", a, "wss://only"
    b = _Server(indexer=indexer_on in ("b", "both"), mark_heights={MARK: mark_height} if mark_height else {})
    return a, "wss://a", b, "wss://b"


def _payload(h160_hex: str, *, txid: str | None = MARK, outcome: str = "valid") -> dict:
    hm = {"attestation": {"outcome": outcome, "recovered_hash160": h160_hex}}
    if txid is None:
        return {"hashmark": hm}  # the pasted-script shape: one record, no txid
    return {"txid": txid, "outputs": [{"hashmark": hm}]}


def _ctx() -> SimpleNamespace:
    return SimpleNamespace(network="mainnet", client_factory=None)


def _run(monkeypatch: pytest.MonkeyPatch, payload: dict, pair) -> dict:
    monkeypatch.setattr(glyph_inspect, "_endpoint_pair", lambda ctx: pair)
    glyph_inspect._attach_name_at_mark(_ctx(), payload, name=NAME, min_confirmations=6)
    records = [payload["hashmark"]] if payload.get("hashmark") else [r["hashmark"] for r in payload["outputs"]]
    assert len(records) == 1
    return records[0]["name_at_mark"]


# ---------------------------------------------------------------------------
# The whole point
# ---------------------------------------------------------------------------


def test_form_2_after_the_move_names_the_signer_as_the_target(monkeypatch: pytest.MonkeyPatch) -> None:
    """The mark sits at 458595, after the name moved to `14XmXG3d…`. The signer IS that key."""
    nam = _run(monkeypatch, _payload(MOVED_H160), _pair(458595))
    assert nam["resolved"] and nam["form"] == 2 and nam["point_in_time"] is True
    assert nam["name"] == NAME
    assert nam["target_at_height"] == MOVED
    assert nam["signer_is_target_at_height"] is True
    assert nam["reveal_txid"] == MINT
    assert nam["chain"]["complete"] and nam["chain"]["tip"] == f"{UPDATE_B}:1"
    assert nam["binding_verified"] is False, "discovery proved the chain, not the name→glyph binding"
    # the two source rules were satisfiable: binding and anchor on different servers,
    # candidates and tip proof on different servers
    assert nam["binding_source"] == "wss://b" and nam["anchor_source"] == "wss://a"
    assert nam["chain"]["discovery_source"] == "wss://a" and nam["chain"]["tip_source"] == "wss://b"


def test_form_2_before_the_move_says_the_signer_is_not_the_target(monkeypatch: pytest.MonkeyPatch) -> None:
    """Same signer, mark at 458586 — before the move. Then the name pointed at `1CPfirXZ…`,
    and the key that signed is NOT that address. A present-tense lookup would have said yes."""
    nam = _run(monkeypatch, _payload(MOVED_H160), _pair(458586))
    assert nam["form"] == 2
    assert nam["target_at_height"] == MINT_TARGET
    assert nam["target_now"] == MOVED, "the indexer's present-tense answer is carried beside it, labelled"
    assert nam["signer_is_target_at_height"] is False


# ---------------------------------------------------------------------------
# Every way it must refuse to say
# ---------------------------------------------------------------------------


def test_one_configured_server_degrades_to_form_1_with_the_reason(monkeypatch: pytest.MonkeyPatch) -> None:
    """ONE configured server (`--electrumx URL`, or a config naming one). Binding and height from
    one server is the case the judge refuses, and the CLI must carry that reason to the terminal
    rather than fall silent. (Not the shipped mainnet default, which this used to say: that ships
    two independent endpoints — pinned in `test_hashmark_verify_one_record.py`.)"""
    nam = _run(monkeypatch, _payload(MOVED_H160), _pair(458595, two=False, indexer_on="a"))
    assert nam["resolved"] and nam["form"] == 1 and nam["point_in_time"] is False
    assert "wss://only" in nam["degraded_reason"]
    assert "both came from" in nam["degraded_reason"]
    assert nam["target_at_height"] is None
    assert nam["signer_is_target_at_height"] is None


def test_an_unverified_signature_is_refused_before_any_lookup(monkeypatch: pytest.MonkeyPatch) -> None:
    a, la, b, lb = _pair(458595)
    nam = _run(monkeypatch, _payload(MOVED_H160, outcome="invalid_signature"), (a, la, b, lb))
    assert nam["resolved"] is False
    assert "refusing" in nam["reason"]
    assert a.extension_calls == [] and b.extension_calls == [], "nothing was asked of any server"


def test_a_pasted_script_has_no_block_and_says_so(monkeypatch: pytest.MonkeyPatch) -> None:
    nam = _run(monkeypatch, _payload(MOVED_H160, txid=None), _pair(None))
    assert nam["resolved"] and nam["form"] == 1
    assert "has no block" in nam["degraded_reason"]


def test_an_unregistered_name_is_reported_not_raised(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(glyph_inspect, "_endpoint_pair", lambda ctx: _pair(458595))
    payload = _payload(MOVED_H160)
    glyph_inspect._attach_name_at_mark(_ctx(), payload, name="nobody-here.rxd", min_confirmations=6)
    nam = payload["outputs"][0]["hashmark"]["name_at_mark"]
    assert nam["resolved"] is False
    assert "no registration" in nam["reason"]


def test_no_indexer_anywhere_is_reported_with_every_endpoint_named(monkeypatch: pytest.MonkeyPatch) -> None:
    nam = _run(monkeypatch, _payload(MOVED_H160), _pair(458595, indexer_on="none"))
    assert nam["resolved"] is False
    assert "wss://a" in nam["reason"] and "wss://b" in nam["reason"]


def test_the_indexer_is_asked_for_the_bare_label(monkeypatch: pytest.MonkeyPatch) -> None:
    """RXinDexer's validator rejects a dot before it does anything else. The qualified name
    the user typed must reach the server as its label."""
    a, la, b, lb = _pair(458595)
    _run(monkeypatch, _payload(MOVED_H160), (a, la, b, lb))
    assert ("wave.resolve", [LABEL]) in b.extension_calls


def test_a_mark_too_shallow_for_the_floor_degrades(monkeypatch: pytest.MonkeyPatch) -> None:
    """Tip is 464826; a mark at 464823 has 4 confirmations against a floor of 6."""
    nam = _run(monkeypatch, _payload(MOVED_H160), _pair(464823))
    assert nam["form"] == 1
    assert "too shallow" in nam["degraded_reason"]


def test_min_confirmations_is_required_and_names_the_flag() -> None:
    with pytest.raises(UserError, match="--min-confirmations"):
        glyph_inspect._require_min_confirmations(None)
    glyph_inspect._require_min_confirmations(6)  # honest path: a value is accepted


# ---------------------------------------------------------------------------
# It reaches a human
# ---------------------------------------------------------------------------


def test_the_human_renderer_prints_the_verdict_and_its_qualifiers(monkeypatch: pytest.MonkeyPatch) -> None:
    nam = _run(monkeypatch, _payload(MOVED_H160), _pair(458595))
    text = "\n".join(glyph_inspect._name_at_mark_lines(nam))
    assert "at the mark's block (458595)" in text
    assert MOVED in text
    assert "the signing key IS that address" in text
    assert "had signed this by that block" in text and "not that its holder put it here" in text
    assert "custody" not in text, "the overstated claim is gone, not merely joined by a weaker one"
    assert "not authorship" in text
    assert "not verified on chain" in text, "the binding qualifier must be printed with the claim"
    assert "proved unspent" in text
    # EXPIRY reached --json and no terminal (0.25.0 panel, INFO): "pointed at X at block N" printed
    # with nothing saying the name might have lapsed by then. The state is printed, not a number.
    assert f"expiry at that block: {nam['expiry']}" in text
    assert "renewals are decided by treasury payments" in text


def test_the_human_renderer_prints_the_degrade_reason(monkeypatch: pytest.MonkeyPatch) -> None:
    nam = _run(monkeypatch, _payload(MOVED_H160), _pair(458595, two=False, indexer_on="a"))
    text = "\n".join(glyph_inspect._name_at_mark_lines(nam))
    assert "not established" in text
    assert "both came from" in text
    assert "IS that address" not in text


def test_the_renderer_says_nothing_when_there_is_nothing() -> None:
    assert glyph_inspect._name_at_mark_lines(None) == []
    assert glyph_inspect._name_at_mark_lines({}) == []
