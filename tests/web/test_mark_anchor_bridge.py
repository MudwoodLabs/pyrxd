"""The browser's route to a mark's block — reachability first, then behaviour.

``resolve_mark_anchor`` is what turns "this transaction" into "this block": it binds
the echoed txid, refuses an unreadable confirmation depth rather than reading it as
zero, and derives the height from the chain tip because the verbose reply carries no
height field of its own. The browser panel needs all three, and until this work it
could not call the function at all.

**Why it could not.** ``mark_anchor.py`` imported ``nonneg_int`` from
``pyrxd.network._guards``, and importing anything under ``pyrxd.network`` executes
``pyrxd/network/__init__.py``, which eagerly re-exports the ElectrumX and Bitcoin
clients — so the import pulled ``coincurve``, ``aiohttp`` and ``websockets``. None
has a pure-Python wheel, so under Pyodide the import simply fails. The function was
correct, tested, and unreachable from the one surface that most needed it: exactly
the reachability failure the project's own rules describe, with the twist that the
barrier was an ``__init__`` three packages away rather than anything in the file.

The coercions moved to ``pyrxd.security.json_guards``, the dependency-free layer,
with ``pyrxd.network._guards`` re-exporting them so no call site changed. That is
the same move the genesis map made to ``constants.py``, for the same reason.

``tests/network/test_guards.py`` owns the coercions' own behaviour. This file owns
the property that makes them reachable, and the bridge built on top.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

_GLUE_DIR = Path(__file__).resolve().parents[2] / "docs" / "inspect_static" / "inspect"

#: A real mainnet HashMark transaction: height 460,572, carrying the signed v2 record
#: in ``tests/test_hashmark_mainnet_vectors.py``. The confirmation depth and tip below
#: were MEASURED from the page's own endpoint
#: (``wss://electrumx.radiant4people.com:50022``) on 2026-09-19, and the height they
#: derive to is the height the mainnet node reports for that transaction's block.
#: A fixture whose numbers could not co-occur in production proves nothing about
#: production; these did co-occur, at one moment, on the real chain.
_TXID = "a1a86ab4503901af4df3d092fcf668b07c03c5cd89240fe918ae70e02e045916"
_MEASURED_CONFIRMATIONS = 5140
_MEASURED_TIP = 465711
_KNOWN_HEIGHT = 460572


@pytest.fixture(scope="module")
def glue():
    """The page's own bridge module, imported the way the page imports it."""
    sys.path.insert(0, str(_GLUE_DIR))
    try:
        import glue as module

        yield module
    finally:
        sys.path.remove(str(_GLUE_DIR))
        sys.modules.pop("glue", None)


def _camel(snake: str) -> str:
    """``inspect_txid_with_raw`` -> ``inspectTxidWithRaw`` — the naming rule
    ``bootPyrxdRuntime`` applies when it hands a Python entry point to JS."""
    head, *rest = snake.split("_")
    return head + "".join(part[:1].upper() + part[1:] for part in rest)


def _glue_bridge_names(module) -> list[str]:
    """Every public entry point ``glue.py`` DEFINES, derived from the module.

    Functions it imported from elsewhere are excluded by ``__module__``: the page
    calls what glue defines, and a re-exported helper is not a bridge.
    """
    import inspect as _i

    return sorted(
        name
        for name, obj in vars(module).items()
        if not name.startswith("_") and _i.isfunction(obj) and obj.__module__ == module.__name__
    )


def _verbose(**over) -> str:
    reply = {
        "txid": _TXID,
        "hash": _TXID,
        "confirmations": _MEASURED_CONFIRMATIONS,
        "blockhash": "00" * 32,
        "blocktime": 1_756_000_000,
    }
    reply.update(over)
    return json.dumps(reply)


# ──────────────────────────────────────────────────────── reachability ──


class TestTheAnchorIsReachableFromTheBrowser:
    """The property the move exists for. Without it every test below is about code
    the page can never execute."""

    def test_importing_it_pulls_in_no_wheel_pyodide_lacks(self) -> None:
        """Measured the way ``test_inspect_imports_pyodide_clean`` measures the
        façade: evict everything, import, and look at what arrived."""
        heavy = {"coincurve", "aiohttp", "websockets", "Cryptodome"}
        saved = dict(sys.modules)
        for name in list(sys.modules):
            if name == "pyrxd" or name.startswith("pyrxd.") or name.split(".", 1)[0] in heavy:
                sys.modules.pop(name)
        try:
            import pyrxd.glyph.mark_anchor  # noqa: F401

            pulled = sorted(n for n in sys.modules if n.split(".", 1)[0] in heavy)
        finally:
            sys.modules.update(saved)
        assert not pulled, (
            f"importing pyrxd.glyph.mark_anchor pulled {pulled}, none of which has a pure-Python "
            f"wheel — so it cannot be imported under Pyodide and the browser panel cannot place a "
            f"mark in a block"
        )

    def test_it_does_not_reach_for_the_network_package(self) -> None:
        """The specific barrier, named rather than merely absent: ``pyrxd.network``'s
        ``__init__`` is what drags the heavy three in, so any import from anywhere
        under that package re-creates the problem even if the submodule is innocent."""
        import inspect as _i

        from pyrxd.glyph import mark_anchor

        source = _i.getsource(mark_anchor)
        assert "pyrxd.network" not in source and "from ..network" not in source, (
            "mark_anchor must not import from pyrxd.network: that package's __init__ "
            "eagerly loads the ElectrumX and Bitcoin clients"
        )

    def test_the_old_location_re_exports_rather_than_redefines(self) -> None:
        """~30 call sites still import from the old path. A second definition would
        be two guards that can disagree — the thing having one module prevented."""
        from pyrxd.network._guards import finite_int, hex_str, merkle_branch, nonneg_int, require_bool
        from pyrxd.security import json_guards

        for fn in (finite_int, hex_str, merkle_branch, nonneg_int, require_bool):
            assert fn is getattr(json_guards, fn.__name__), f"{fn.__name__} is a copy, not a re-export"

    def test_every_bridge_is_bound_by_the_shared_boot(self, glue) -> None:
        """A bridge function nothing calls is a bridge to nowhere.

        THE SET IS DERIVED, NOT TYPED. This guard used to name three functions and read
        one file, and both halves have since been wrong: the binding moved to
        ``shared.js`` when the public ``/verify/`` page needed the same runtime, and a
        hand-kept tuple of three would have gone on passing over a fourth bridge nobody
        had wired up. The universe here is whatever ``glue`` actually exposes.
        """
        import inspect as _i

        bridges = _glue_bridge_names(glue)
        assert bridges, "no public entry points found in glue.py — this scan is broken, not the page"
        boot = (_GLUE_DIR / "shared.js").read_text(encoding="utf-8")
        for name in bridges:
            assert callable(getattr(glue, name)), f"glue.{name} is missing"
            assert f"glue.{name}," in boot, (
                f"shared.js's bootPyrxdRuntime never binds glue.{name}, so no page can call it"
            )
        assert _i.ismodule(glue)

    def test_every_bound_bridge_reaches_a_page(self, glue) -> None:
        """The other direction, and the one that rots quietly: a bridge bound in the
        boot and called by nothing is a capability with no production caller. Each
        JS-side handle must appear in at least one shipped page script."""
        pages = {
            path.name: path.read_text(encoding="utf-8")
            for path in sorted(_GLUE_DIR.parent.glob("*/[a-z]*.js"))
            if path.name != "shared.js"
        }
        assert pages, "no page scripts found — this scan is broken, not the pages"
        # shared.js counts as a consumer: `hashFileWithRecordAlgorithm` calls two of
        # these itself, and a page reaches them through it. What must not happen is a
        # bridge that nothing anywhere reads off the `bridges` object.
        pages["shared.js"] = (_GLUE_DIR / "shared.js").read_text(encoding="utf-8")
        for name in _glue_bridge_names(glue):
            # `bridges.<handle>`, not the bare handle: a substring search for `run`
            # matches `runtime` and `runPython` and would pass on a page that never
            # touched the bridge at all.
            needle = f"bridges.{_camel(name)}"
            users = sorted(fname for fname, text in pages.items() if needle in text)
            assert users, f"glue.{name} is bound as `{needle}` and no shipped script reads it"


# ───────────────────────────────────────────── what the bridge answers ──


class TestTheBlockIsDerivedNotInvented:
    def test_the_measured_mainnet_reply_lands_on_the_right_block(self, glue) -> None:
        """The honest path, against numbers that really occurred together. The height
        is not in the reply at all — it is ``tip - confirmations + 1``, and this
        asserts that arithmetic against a block the node independently reports."""
        anchor = glue.mark_anchor(_TXID, _verbose(), _MEASURED_TIP)
        assert anchor["resolved"] is True
        assert anchor["height"] == _KNOWN_HEIGHT
        assert anchor["confirmations"] == _MEASURED_CONFIRMATIONS

    def test_the_caveat_travels_with_the_height(self, glue) -> None:
        """pyrxd has no Radiant header, proof-of-work or merkle check, so the height
        is an endpoint's claim. A reader who does not know that over-trusts every
        sentence built on it."""
        anchor = glue.mark_anchor(_TXID, _verbose(), _MEASURED_TIP)
        assert anchor["height_is_verified"] is False
        assert "NOT verified" in anchor["caveat"]

    def test_no_depth_verdict_is_shipped(self, glue) -> None:
        """Depth buys reorg-resistance priced in a chain's hashrate; a shipped number
        is folklore. The bridge reports the count and says the judgement is not its
        to make — it must not leak a pass/fail on depth."""
        anchor = glue.mark_anchor(_TXID, _verbose(), _MEASURED_TIP)
        assert "provisional" not in anchor
        assert "sets no confirmation-depth requirement" in anchor["no_depth_policy"]

    def test_an_unconfirmed_transaction_has_no_block_rather_than_block_zero(self, glue) -> None:
        anchor = glue.mark_anchor(_TXID, _verbose(confirmations=0), _MEASURED_TIP)
        assert anchor["resolved"] is True
        assert anchor["height"] is None
        assert anchor["confirmations"] == 0


class TestTheBridgeFailsClosed:
    """Losing the block must not lose the record, so every one of these returns a
    reason rather than raising — but none of them returns an ANSWER."""

    def test_an_endpoint_answering_about_another_transaction_is_refused(self, glue) -> None:
        """The one thing actually checked on this path. Without it the anchor's txid
        was simply the txid REQUESTED, however different the reply was."""
        anchor = glue.mark_anchor(_TXID, _verbose(txid="ff" * 32), _MEASURED_TIP)
        assert anchor["resolved"] is False
        assert "fail-closed" in anchor["reason"]

    @pytest.mark.parametrize(
        "bad",
        ["six", True, float("inf"), -3, None],
        ids=["string", "bool", "infinity", "negative", "null-with-tip"],
    )
    def test_an_unreadable_depth_is_refused_rather_than_read_as_zero(self, glue, bad) -> None:
        """An unconfirmed mark and a mark whose depth could not be read are different
        facts, and only one of them is benign. ``None`` is the exception the coercion
        deliberately allows — a missing key means zero — so it resolves."""
        anchor = glue.mark_anchor(_TXID, _verbose(confirmations=bad), _MEASURED_TIP)
        if bad is None:
            assert anchor["resolved"] is True and anchor["height"] is None
        else:
            assert anchor["resolved"] is False, f"{bad!r} produced an answer"

    def test_a_confirmed_transaction_with_no_tip_is_refused(self, glue) -> None:
        """No tip, no height. Guessing one would move the point in time the whole
        mark is about."""
        anchor = glue.mark_anchor(_TXID, _verbose(), None)
        assert anchor["resolved"] is False
        assert "no chain tip" in anchor["reason"]

    def test_an_unparseable_reply_is_refused(self, glue) -> None:
        anchor = glue.mark_anchor(_TXID, "{not json", _MEASURED_TIP)
        assert anchor["resolved"] is False
        assert "unreadable reply" in anchor["reason"]

    def test_a_reply_that_is_not_an_object_is_refused(self, glue) -> None:
        anchor = glue.mark_anchor(_TXID, json.dumps(["a", "list"]), _MEASURED_TIP)
        assert anchor["resolved"] is False

    def test_an_oversize_reply_is_refused_before_it_is_parsed(self, glue) -> None:
        anchor = glue.mark_anchor(_TXID, "x" * (glue._MAX_VERBOSE_JSON_CHARS + 1), _MEASURED_TIP)
        assert anchor["resolved"] is False
        assert "over the cap" in anchor["reason"]

    def test_the_reason_cannot_carry_control_characters_into_the_dom(self, glue) -> None:
        """The reply is a hostile server's to write, and its text ends up in an error
        string. A bidi override there makes the rendered reason differ from the real
        one."""
        anchor = glue.mark_anchor(_TXID, _verbose(txid="ff" * 32) + "‮", _MEASURED_TIP)
        assert anchor["resolved"] is False
        assert "‮" not in anchor["reason"]


class TestTheSyncDriverIsHonestAboutItsLimits:
    """``asyncio.run`` does not work on Pyodide's main thread, so the bridge steps the
    coroutine by hand. That is only sound because ``resolve_mark_anchor``'s single
    ``await`` is on a value the page already has."""

    def test_a_coroutine_that_really_suspends_raises_rather_than_half_answering(self, glue) -> None:
        import asyncio

        async def _suspends():
            await asyncio.sleep(0)
            return "never reached"

        with pytest.raises(RuntimeError, match="suspended"):
            glue._run_sync(_suspends())

    def test_a_coroutine_that_does_not_suspend_returns_its_value(self, glue) -> None:
        async def _immediate():
            return 42

        assert glue._run_sync(_immediate()) == 42


class TestThePanelAndTheCliShareOneAnchorShape:
    """``mark_anchor_dict`` was factored out in #703 so a height never reaches a
    screen without the caveat that it is one endpoint's unverified claim. The panel
    is its third consumer, and the point of routing through it is that a field added
    there appears on every surface instead of on the two somebody remembered.
    """

    @staticmethod
    def _cli_shape() -> dict:
        from pyrxd.glyph.mark_anchor import MarkAnchor, mark_anchor_dict

        return mark_anchor_dict(
            MarkAnchor(txid="a" * 64, height=_KNOWN_HEIGHT, confirmations=5, min_confirmations=1, source="s")
        )

    def test_the_bridge_calls_the_shared_helper(self) -> None:
        """Reachability, not resemblance: two dicts can match today and diverge on the
        next field. This asserts the panel goes THROUGH the helper."""
        import inspect as _i
        import sys

        sys.path.insert(0, str(_GLUE_DIR))
        try:
            import glue as module

            source = _i.getsource(module.mark_anchor)
        finally:
            sys.path.remove(str(_GLUE_DIR))
            sys.modules.pop("glue", None)
        assert "mark_anchor_dict(anchor)" in source, (
            "the browser bridge builds its own anchor dict again — that is the second "
            "display shape mark_anchor_dict exists to prevent"
        )

    #: The three the panel drops, each a verdict ON the depth rather than the depth.
    #: Pinned as a MEMBERSHIP: if the bridge ever drops a fourth, or stops dropping one
    #: of these, someone has to come back and re-read the reason rather than inherit it.
    _DELIBERATELY_ABSENT = frozenset({"provisional", "deep_enough", "min_confirmations"})

    def test_the_panel_carries_every_field_except_the_depth_verdicts(self, glue) -> None:
        panel = glue.mark_anchor(_TXID, _verbose(), _MEASURED_TIP)
        cli = set(self._cli_shape())
        missing = cli - set(panel)
        assert missing == self._DELIBERATELY_ABSENT, (
            f"the panel drops {sorted(missing)} from the shared anchor shape, and the "
            f"deliberate set is {sorted(self._DELIBERATELY_ABSENT)}. A field that went "
            f"missing without a reason is the caveat-shaped hole this helper prevents."
        )

    def test_the_caveat_is_among_the_fields_that_cross(self, glue) -> None:
        """The specific one. Everything else here is structure; this is the sentence."""
        panel = glue.mark_anchor(_TXID, _verbose(), _MEASURED_TIP)
        assert panel["caveat"] == self._cli_shape()["caveat"]

    def test_no_depth_verdict_reaches_the_page(self, glue) -> None:
        """The floor this page passes is 1 — "it is in a block at all", not a policy.
        A ``deep_enough: true`` derived from it would read as "buried enough", which
        nobody here has judged."""
        panel = glue.mark_anchor(_TXID, _verbose(), _MEASURED_TIP)
        for key in self._DELIBERATELY_ABSENT:
            assert key not in panel
