"""§7.6 form 2: the glyph an index binds a name to must NAME ITSELF that name.

THE FINDING (0.25.0 pre-release panel, LOW, two reviewers: C-L4 / E-L1). The name→glyph binding is
the indexer's word, and nothing compared the label that was asked about with the name in the
glyph's OWN mint payload — which the walk already fetches, txid-bound and hash-bound to the
covenant. So the indexer ALONE could bind ``bank.rxd`` (or ``victimcorp.rxd``) to the
``custodian-gate-x7f3`` chain, and every other rule passed, because they are all about the chain
and the block, not about which name the chain is. ``verify --wave-name bank.rxd`` then reported
ESTABLISHED for whoever ``custodian-gate-x7f3`` pointed at.

THE FIX. ``judge_name_at_mark`` takes the name asked about and reads the mint payload as RXinDexer's
claim path does (``wave_rules.indexed_wave_name``: ``attrs.name``, falling back to
``app.data.name``), lower-cased, with a trailing ``.rxd`` dropped because pyrxd through 0.24.0
wrote the QUALIFIED name into ``attrs.name``. A mismatch degrades, naming both.

What this does NOT establish, and the verdict still says so: that this glyph is the registration IN
FORCE for the name. A duplicate claim, or a lapsed registration, names it too — which of them the
indexer serves is still the indexer's word, so ``binding_verified`` stays False.
"""

from __future__ import annotations

import cbor2
import pytest

from pyrxd.base58 import base58check_decode
from pyrxd.cli import glyph_inspect, hashmark_cmds
from pyrxd.glyph.mark_anchor import MarkAnchor
from pyrxd.glyph.mutable_chain import ChainStep, MutableChainWalk
from pyrxd.glyph.wave_identity import HeightReport, judge_name_at_mark
from tests.test_mutable_chain_is_discovered_from_the_chain import MARK, MINT, MOVED
from tests.test_name_at_mark_reaches_the_cli import NAME, _ctx, _payload, _Server

MOVED_H160 = base58check_decode(MOVED)[1:].hex()


class _BindsAnyName(_Server):
    """An indexer that answers EVERY label with the custodian-gate chain's mint."""

    async def call_extension(self, method, params=None):
        self.extension_calls.append((method, list(params or [])))
        if method == "wave.resolve":
            return {"name": params[0], "ref": f"{MINT}_0", "target": MOVED, "status": "active"}
        return await super().call_extension(method, params)


def _attach(monkeypatch, name: str) -> dict:
    a = _Server(indexer=False, mark_heights={MARK: 458595})
    b = _BindsAnyName(indexer=True, mark_heights={MARK: 458595})
    monkeypatch.setattr(glyph_inspect, "_endpoint_pair", lambda ctx: (a, "wss://a", b, "wss://b"))
    payload = _payload(MOVED_H160)
    glyph_inspect._attach_name_at_mark(_ctx(), payload, name=name, min_confirmations=6)
    return payload["outputs"][0]["hashmark"]["name_at_mark"]


@pytest.mark.parametrize("asked", ["bank.rxd", "victimcorp.rxd"])
def test_the_indexer_alone_cannot_bind_another_names_glyph(monkeypatch, asked) -> None:
    """The panel's probes (``panel-c/test_panelc_probe_wrongglyph.py``,
    ``panel-e/...::test_b_alone_binds_another_name``). Before the fix: form 2, ESTABLISHED."""
    nam = _attach(monkeypatch, asked)
    assert nam["resolved"] and nam["form"] == 1, nam
    label = asked.split(".")[0]
    assert f"bound {label!r} to glyph" in nam["degraded_reason"]
    assert "whose own mint payload names 'custodian-gate-x7f3'" in nam["degraded_reason"]
    assert hashmark_cmds._name_check({"name_at_mark": nam}, asked=True)[0] == "NOT ESTABLISHED"


def test_the_same_indexer_asked_the_glyphs_real_name_still_answers(monkeypatch) -> None:
    """The honest pair: the same permissive indexer, asked for the name the glyph really claims."""
    nam = _attach(monkeypatch, NAME)
    assert nam["form"] == 2, nam["degraded_reason"]
    assert nam["signer_is_target_at_height"] is True


class _EchoesAnotherName(_Server):
    """Binds the name it was ASKED to the right glyph, but echoes a different ``name`` back."""

    async def call_extension(self, method, params=None):
        self.extension_calls.append((method, list(params or [])))
        if method == "wave.resolve":
            return {"name": "bank", "ref": f"{MINT}_0", "target": MOVED, "status": "active"}
        return await super().call_extension(method, params)


def test_the_name_printed_is_the_name_checked_not_the_indexers_echo(monkeypatch) -> None:
    """Every sentence of a form-2 verdict names the name: "NAME pointed at …", ESTABLISHED,
    "the glyph's own mint does name NAME". It was the indexer's ECHO (`record.name`), so an indexer
    asked about `custodian-gate-x7f3` could answer with that glyph and the label `bank` — and the
    terminal would say `bank.rxd` pointed at the signing key, which nothing checked."""
    a = _Server(indexer=False, mark_heights={MARK: 458595})
    b = _EchoesAnotherName(indexer=True, mark_heights={MARK: 458595})
    monkeypatch.setattr(glyph_inspect, "_endpoint_pair", lambda ctx: (a, "wss://a", b, "wss://b"))
    payload = _payload(MOVED_H160)
    glyph_inspect._attach_name_at_mark(_ctx(), payload, name=NAME, min_confirmations=6)
    nam = payload["outputs"][0]["hashmark"]["name_at_mark"]
    assert nam["form"] == 2, nam["degraded_reason"]
    assert nam["name"] == NAME
    text = "\n".join(glyph_inspect._name_at_mark_lines(nam))
    assert "bank" not in text
    assert "bank" not in hashmark_cmds._name_check({"name_at_mark": nam}, asked=True)[1]


def test_the_renderer_says_the_mint_names_it_and_what_that_does_not_prove(monkeypatch) -> None:
    text = " ".join("\n".join(glyph_inspect._name_at_mark_lines(_attach(monkeypatch, NAME))).split())
    assert f"the glyph's own mint does name {NAME}" in text
    assert "which registration of it is in force is not verified on chain" in text


# ---------------------------------------------------------------------------
# The judge, pure: both mint shapes, the fallback, and every refusal
# ---------------------------------------------------------------------------


def _walk_with_mint(payload: object) -> MutableChainWalk:
    raw = payload if isinstance(payload, bytes) else cbor2.dumps(payload)
    step = ChainStep(txid="aa" * 32, mut_vout=1, kind="mint", attrs={"target": MOVED}, envelope_cbor=raw)
    return MutableChainWalk(
        ref="r:1", steps=(step,), tip_txid="aa" * 32, tip_vout=1, tip_proved_unspent=True, complete=True
    )


def _judge(walk: MutableChainWalk, name: str):
    reports = [HeightReport(s, 900, {"aa" * 32: 800}) for s in ("node-A", "index-B")]
    anchor = MarkAnchor(txid="ma" * 32, height=900, confirmations=50, min_confirmations=6, source="node-A")
    return judge_name_at_mark(
        ref="r:1", name=name, binding_source="index-B", anchor=anchor, walk=walk, height_reports=reports
    )


PHOTONIC = {"p": [2, 5, 11], "name": "alice.rxd", "attrs": {"name": "alice", "domain": "rxd", "target": MOVED}}
PYRXD_024 = {"p": [2, 5, 11], "attrs": {"name": "alice.rxd", "domain": "rxd", "target": MOVED}}
APP_DATA = {"p": [2, 5, 11], "attrs": {"target": MOVED}, "app": {"data": {"name": "alice"}}}


@pytest.mark.parametrize(
    "payload", [PHOTONIC, PYRXD_024, APP_DATA], ids=["photonic-bare-label", "pyrxd-0.24-qualified", "app.data.name"]
)
@pytest.mark.parametrize("asked", ["alice.rxd", "alice", "ALICE.RXD", " Alice "])
def test_every_shape_that_names_the_label_answers(payload, asked) -> None:
    """A guard that refuses valid work is a bug: the Photonic shape, the shape pyrxd wrote through
    0.24.0, and the ``app.data.name`` fallback all name ``alice``, however the user typed it."""
    v = _judge(_walk_with_mint(payload), asked)
    assert v.form == 2, v.degraded_reason
    assert v.target_at_height == MOVED


@pytest.mark.parametrize(
    ("payload", "says"),
    [
        (PHOTONIC, "names 'alice'"),
        (
            {"p": [2, 5, 11], "attrs": {"name": "alice", "target": MOVED}, "app": {"data": {"name": "bob"}}},
            "names 'alice'",
        ),
        ({"p": [2, 5, 11], "attrs": {"target": MOVED}}, "names no WAVE label"),
        ({"p": [2, 5, 11], "attrs": "not-a-map"}, "cannot be read as a WAVE claim"),
        (["not", "a", "map"], "is not a CBOR map"),
        (b"\x9f", "does not decode"),  # an indefinite array that never ends
    ],
    ids=["other-label", "attrs-name-wins-over-app-data", "no-name", "attrs-not-a-map", "not-a-map", "undecodable"],
)
def test_a_mint_that_does_not_name_the_label_degrades_with_the_reason(payload, says) -> None:
    v = _judge(_walk_with_mint(payload), "bob.rxd")
    assert v.form == 1 and v.target_at_height is None
    assert says in v.degraded_reason, v.degraded_reason


def test_a_walk_without_the_mint_bytes_degrades_rather_than_trusting_the_index() -> None:
    """A step built without ``envelope_cbor`` (a consumer's own walk, or an older one) has nothing
    to compare. That fails CLOSED — it is not read as "no name, so anything goes"."""
    step = ChainStep(txid="aa" * 32, mut_vout=1, kind="mint", attrs={"name": "alice", "target": MOVED})
    walk = MutableChainWalk(
        ref="r:1", steps=(step,), tip_txid="aa" * 32, tip_vout=1, tip_proved_unspent=True, complete=True
    )
    v = _judge(walk, "alice.rxd")
    assert v.form == 1 and "no readable mint payload" in v.degraded_reason
