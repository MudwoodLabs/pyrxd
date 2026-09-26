"""The browser's route to a mark's block — reachability first, then behaviour.

``resolve_mark_anchor`` is what turns "this transaction" into "this block": it binds
the echoed txid, refuses an unreadable confirmation depth rather than reading it as
zero, and places the height by the chain tip (the verbose reply carries no height field
of its own) and then BINDS it to the endpoint's own header. The browser panel needs all
of it, and until this work it could not call the function at all.

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

#: The REAL mainnet headers around that block, and the block hash the node names for the
#: transaction — measured 2026-09-26, read-only, from the same endpoint with
#: ``blockchain.block.header`` and the verbose ``blockhash``. The header at 460,572 hashes to that
#: block hash (``pyrxd.hash.radiant_block_hash``), and its neighbours 460,570–460,574 do not, so a
#: binding that lands off by one or two lands on a header that really exists and really does not
#: match — and the whole search window can be served, which a true disagreement needs.
_MEASURED_BLOCKHASH = "000000000000003b235d5c1ae5e1015472bbbf422247513b8a2e2351977f3dd5"
_MEASURED_HEADERS = {
    460570: (
        "00000020e6a6fad8395f0753067d2d69e6ba46610fd02e120b2875176400000000000000e14812ab581446bd46242e"
        "4b80b07c4827f034e82736febc2096487d7522af4e22dd966ae9a7001a1a26f1a4"
    ),
    460571: (
        "000000202c638907983cee25c571ef5c208bba2f85c6f6a0f5e5364d1f000000000000001796c08709e087b10fc8"
        "f034d904a8fced63aa539f3ef52c5e60dd2f20429b61e4de966ac9a9001a480ae052"
    ),
    460572: (
        "0000002072f29019f4a61fda2a63b12deb0f9282a5bf2e8de1fc08e7a800000000000000531b3ef06ad67e5d7aeb"
        "209bc4c73d52fea59b789978b1ddc7be512d7a84025965e0966a31aa001a5d60f425"
    ),
    460573: (
        "00000020d53d7f9751232e8a3b51472242bfbb725401e1e51a5c5d233b000000000000008a4082936ad0e291e3ed"
        "d8b78c35af61dabe9e92fd97d91f81923080c6ff490df8e0966a6daa001a64076e42"
    ),
    460574: (
        "00000020f222ea1277c0dc6efc5d825a4f500a3059a33071336368a54700000000000000f0250538068cf8e459c936"
        "2a05ebae02f388629fd91e70766fb5b85529290b2c0fe3966a02aa001a8109ec8c"
    ),
}


def _page_loop(glue, verbose_json: str, tip, served: dict[int, str], *, rounds: int = 16):
    """What the page's `resolveMarkAnchor` does, in Python: call the bridge, fetch the ONE header
    it asks for from ``served`` (a height it lacks is the server's refusal), and call again.
    Returns ``(final answer, heights asked for, in order)``. The JavaScript loop is exercised on
    its own through the page harnesses; this is for testing the bridge's side of the protocol."""
    fetched: dict = {"headers": {}, "errors": {}}
    asked: list[int] = []
    for _ in range(rounds):
        answer = glue.mark_anchor(_TXID, verbose_json, tip, json.dumps(fetched))
        wanted = answer.get("needs_headers")
        if not wanted:
            return answer, asked
        height = wanted[0]
        asked.append(height)
        if height in served:
            fetched["headers"][str(height)] = served[height]
        else:
            fetched["errors"][str(height)] = f"height {height} out of range"
    raise AssertionError(f"the bridge was still asking for headers after {rounds} rounds: {asked}")


def _anchor(glue, verbose_json: str | None = None, tip=_MEASURED_TIP, served=None) -> dict:
    return _page_loop(glue, verbose_json or _verbose(), tip, _MEASURED_HEADERS if served is None else served)[0]


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
        "blockhash": _MEASURED_BLOCKHASH,
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
        """The honest path, against numbers that really occurred together. The height is not
        in the reply at all: ``tip - confirmations + 1`` is where the search starts, and the
        height returned is the one whose REAL header hashes to the block the node names."""
        anchor, asked = _page_loop(glue, _verbose(), _MEASURED_TIP, _MEASURED_HEADERS)
        assert anchor["resolved"] is True
        assert anchor["height"] == _KNOWN_HEIGHT
        assert anchor["confirmations"] == _MEASURED_CONFIRMATIONS
        assert anchor["header_bound"] is True
        assert asked == [_KNOWN_HEIGHT], "the honest path should need exactly the one header"

    def test_the_caveat_travels_with_the_height(self, glue) -> None:
        """The height is bound to the endpoint's OWN header and nothing more: nothing checks
        proof-of-work or merkle inclusion, so it is still an endpoint's claim. The caveat says
        exactly that — the bound one, not the one that says no header was checked."""
        from pyrxd.glyph.mark_anchor import BOUND_CAVEAT

        anchor = _anchor(glue)
        assert anchor["height_is_verified"] is False
        assert anchor["caveat"] == BOUND_CAVEAT
        assert "NOT verified" in anchor["caveat"]
        assert "not checked against any block header" not in anchor["caveat"]

    def test_no_depth_verdict_is_shipped(self, glue) -> None:
        """Depth buys reorg-resistance priced in a chain's hashrate; a shipped number
        is folklore. The bridge reports the count and says the judgement is not its
        to make — it must not leak a pass/fail on depth."""
        anchor = _anchor(glue)
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
    coroutine by hand. That is only sound because every ``await`` in ``resolve_mark_anchor`` is
    on a callable the bridge supplies — the verbose reply and the headers the page has already
    fetched — and none of them suspends."""

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
        """The shape the CLI's funnel produces — which always binds, so a BOUND anchor."""
        from pyrxd.glyph.mark_anchor import BOUND_CAVEAT, MarkAnchor, mark_anchor_dict

        return mark_anchor_dict(
            MarkAnchor(
                txid="a" * 64,
                height=_KNOWN_HEIGHT,
                confirmations=5,
                min_confirmations=1,
                source="s",
                caveat=BOUND_CAVEAT,
                header_bound=True,
            )
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
        panel = _anchor(glue)
        cli = set(self._cli_shape())
        missing = cli - set(panel)
        assert missing == self._DELIBERATELY_ABSENT, (
            f"the panel drops {sorted(missing)} from the shared anchor shape, and the "
            f"deliberate set is {sorted(self._DELIBERATELY_ABSENT)}. A field that went "
            f"missing without a reason is the caveat-shaped hole this helper prevents."
        )

    def test_the_caveat_is_among_the_fields_that_cross(self, glue) -> None:
        """The specific one. Everything else here is structure; this is the sentence."""
        panel = _anchor(glue)
        assert panel["caveat"] == self._cli_shape()["caveat"]

    def test_no_depth_verdict_reaches_the_page(self, glue) -> None:
        """The floor this page passes is 1 — "it is in a block at all", not a policy.
        A ``deep_enough: true`` derived from it would read as "buried enough", which
        nobody here has judged."""
        panel = _anchor(glue)
        for key in self._DELIBERATELY_ABSENT:
            assert key not in panel


# ─────────────────────────────────────── the height is BOUND to a header ──


class TestTheBridgeBindsTheHeightThroughTheOneRule:
    """``tip - confirmations + 1`` is one block low whenever the server's index trails its node,
    on every server at once (#744 measured it and fixed the CLI). The pages call the same
    ``resolve_mark_anchor`` with ``fetch_header``; the bridge runs that rule against the headers the
    page has fetched, and asks for the next one — the rule's own next candidate — when it needs it.
    Every case below uses the REAL mainnet headers around block 460,572."""

    def test_the_first_call_asks_for_the_derived_heights_header_and_names_no_block(self, glue) -> None:
        answer = glue.mark_anchor(_TXID, _verbose(), _MEASURED_TIP)
        assert answer == {
            "resolved": False,
            "needs_headers": [_KNOWN_HEIGHT],
            "reason": "the block's header has not been fetched yet, so no block number is shown",
        }

    def test_a_node_one_block_ahead_of_its_index_returns_the_true_block(self, glue) -> None:
        """THE FINDING, with real headers. The index tip one behind the node makes the formula say
        460,571; that block's real header does not hash to the node's block hash, 460,572's does."""
        anchor, asked = _page_loop(glue, _verbose(), _MEASURED_TIP - 1, _MEASURED_HEADERS)
        assert asked == [_KNOWN_HEIGHT - 1, _KNOWN_HEIGHT], "the rule's order: the formula, then +1"
        assert anchor["resolved"] is True and anchor["height"] == _KNOWN_HEIGHT
        assert anchor["header_bound"] is True

    @pytest.mark.parametrize("tip_shift", [-2, -1, 0, 1, 2])
    def test_the_bridge_gives_the_answer_the_cli_rule_gives(self, glue, tip_shift) -> None:
        """PARITY WITH THE CLI, by construction and by measurement. The same server answers are
        handed to ``resolve_mark_anchor(fetch_header=...)`` directly — the call the CLI makes — and
        to the page's loop through the bridge; the two must agree on the height, and on the order
        the headers were looked at."""
        import asyncio

        from pyrxd.glyph.mark_anchor import resolve_mark_anchor
        from pyrxd.security.errors import NetworkError

        verbose = json.loads(_verbose())
        order: list[int] = []

        async def fetch_verbose(_t):
            return verbose

        async def fetch_header(height):
            order.append(height)
            if height not in _MEASURED_HEADERS:
                raise NetworkError(f"height {height} out of range")
            return bytes.fromhex(_MEASURED_HEADERS[height])

        cli = asyncio.run(
            resolve_mark_anchor(
                txid=_TXID,
                fetch_verbose=fetch_verbose,
                source="s",
                min_confirmations=1,
                tip_height=_MEASURED_TIP + tip_shift,
                fetch_header=fetch_header,
            )
        )
        page, asked = _page_loop(glue, _verbose(), _MEASURED_TIP + tip_shift, _MEASURED_HEADERS)
        assert page["height"] == cli.height == _KNOWN_HEIGHT
        assert asked == order

    def test_the_matching_header_never_arriving_is_not_called_a_disagreement(self, glue) -> None:
        """ROUND 2. An honest chain whose header at the mark's own height is not served (a timeout,
        a refusal): every OTHER header in the window is served and, honestly, does not match. That
        is not the server contradicting itself, and the reason must not say it is — it names the
        height it did not get. Paired with the true disagreement below."""
        served = {h: hx for h, hx in _MEASURED_HEADERS.items() if h != _KNOWN_HEIGHT}
        anchor, asked = _page_loop(glue, _verbose(), _MEASURED_TIP, served)
        assert anchor["resolved"] is False and "height" not in anchor
        assert f"the server did not serve the block headers at heights {_KNOWN_HEIGHT}," in anchor["reason"]
        assert "disagree" not in anchor["reason"]
        assert sorted(asked) == list(range(_KNOWN_HEIGHT - 2, _KNOWN_HEIGHT + 3)), "the premise: every height asked"

    def test_a_header_that_does_not_hash_to_the_block_is_refused(self, glue) -> None:
        """EVERY header in the window is served, and none hashes to the block the node names: no
        height, and — only now — the reason says the server contradicted itself."""
        anchor, asked = _page_loop(glue, _verbose(blockhash="11" * 32), _MEASURED_TIP, _MEASURED_HEADERS)
        assert anchor["resolved"] is False
        assert "height" not in anchor
        assert "the server's index and its node disagree about which block holds this transaction" in anchor["reason"]
        assert "so no block number is shown" in anchor["reason"]
        assert sorted(asked) == [
            _KNOWN_HEIGHT - 2,
            _KNOWN_HEIGHT - 1,
            _KNOWN_HEIGHT,
            _KNOWN_HEIGHT + 1,
            _KNOWN_HEIGHT + 2,
        ]

    def test_a_server_that_serves_no_headers_is_not_called_inconsistent(self, glue) -> None:
        """A different fact, told differently: nothing was read, so nothing disagreed."""
        anchor, _asked = _page_loop(glue, _verbose(), _MEASURED_TIP, {})
        assert anchor["resolved"] is False and "height" not in anchor
        assert "did not serve the block headers needed" in anchor["reason"]
        assert "disagree" not in anchor["reason"]

    def test_a_confirmed_reply_that_names_no_block_is_refused_without_asking(self, glue) -> None:
        answer = glue.mark_anchor(_TXID, _verbose(blockhash=None), _MEASURED_TIP)
        assert answer["resolved"] is False and "needs_headers" not in answer and "height" not in answer
        assert "does not say which one" in answer["reason"]

    @pytest.mark.parametrize(
        "bad",
        [
            "zz" * 80,
            _MEASURED_HEADERS[_KNOWN_HEIGHT][:-2],
            _MEASURED_HEADERS[_KNOWN_HEIGHT] + "00",
            _MEASURED_HEADERS[_KNOWN_HEIGHT][:-1],
            12345,
        ],
        ids=["not-hex", "one-byte-short", "one-byte-long", "odd-length", "not-a-string"],
    )
    def test_a_malformed_header_is_an_error_for_its_height_never_a_header(self, glue, bad) -> None:
        """UNTRUSTED SERVER INPUT. A bad header at the derived height is treated as a header the
        server could not serve, so the rule moves on and asks for its next candidate — and the
        bridge does not raise on it (an odd number of hex digits is not bytes at all)."""
        fetched = {"headers": {str(_KNOWN_HEIGHT): bad}, "errors": {}}
        answer = glue.mark_anchor(_TXID, _verbose(), _MEASURED_TIP, json.dumps(fetched))
        assert answer.get("needs_headers") == [_KNOWN_HEIGHT + 1], answer

    def test_an_oversize_headers_map_is_refused_before_it_is_parsed(self, glue) -> None:
        answer = glue.mark_anchor(_TXID, _verbose(), _MEASURED_TIP, "x" * (glue._MAX_HEADERS_JSON_CHARS + 1))
        assert answer["resolved"] is False and "height" not in answer
        assert "not in a shape this page reads" in answer["reason"]

    def test_the_rules_order_wins_over_whatever_the_page_hands_over(self, glue) -> None:
        """Handed a later candidate that matches while an earlier one is missing, the bridge asks
        for the earlier one: the CLI fetches in order and stops at the first match, so answering
        with the later height could differ from the CLI."""
        fetched = {"headers": {str(_KNOWN_HEIGHT): _MEASURED_HEADERS[_KNOWN_HEIGHT]}, "errors": {}}
        # The formula says 460,571 (tip one low); the page handed over only 460,572, which matches.
        answer = glue.mark_anchor(_TXID, _verbose(), _MEASURED_TIP - 1, json.dumps(fetched))
        assert answer.get("needs_headers") == [_KNOWN_HEIGHT - 1], answer

    @staticmethod
    def _without_sha512_256(monkeypatch) -> None:
        """Reproduce Pyodide without its OpenSSL-backed ``_hashlib``: MEASURED in headless Chromium
        on Pyodide 0.26.4, ``hashlib.new("sha512_256")`` raises exactly this."""
        import hashlib

        real_new = hashlib.new

        def new(name, *args, **kwargs):
            if name == "sha512_256":
                raise ValueError("unsupported hash type sha512_256")
            return real_new(name, *args, **kwargs)

        monkeypatch.setattr(hashlib, "new", new)

    def test_a_runtime_that_cannot_hash_a_block_says_so_and_fetches_nothing(self, glue, monkeypatch) -> None:
        """FOUND IN THE BROWSER, not here: the first live run in Chromium showed the page blaming
        the server ("its index and its node disagree") for a hash its own Python could not compute.
        The rule catches the hashing error as an unreadable header, so the reason has to be decided
        before the rule runs out of heights — and no header should be asked for at all."""
        self._without_sha512_256(monkeypatch)
        answer = glue.mark_anchor(_TXID, _verbose(), _MEASURED_TIP)
        assert answer["resolved"] is False
        assert "needs_headers" not in answer and "height" not in answer
        assert "this browser's Python cannot compute a Radiant block hash" in answer["reason"]
        assert "disagree" not in answer["reason"]

    def test_an_unmined_mark_is_not_refused_over_a_hash_it_does_not_need(self, glue, monkeypatch) -> None:
        """The honest neighbour: no block, no header, no hash — the answer is unchanged."""
        self._without_sha512_256(monkeypatch)
        answer = glue.mark_anchor(_TXID, _verbose(confirmations=0), _MEASURED_TIP)
        assert answer["resolved"] is True and answer["height"] is None

    def test_the_boot_loads_the_hash_before_anything_imports_hashlib(self) -> None:
        """The Radiant block hash is ``hashlib.new("sha512_256")``, which Pyodide only has once its
        ``hashlib`` package (OpenSSL) is loaded, and only if that happens before ``hashlib`` is first
        imported — micropip imports it. So the boot's FIRST ``loadPackage`` must name it, and must
        come before micropip is used. Gated on the library really using that algorithm."""
        import inspect as _i
        import re

        from pyrxd.hash import radiant_block_hash

        assert 'hashlib.new("sha512_256"' in _i.getsource(radiant_block_hash), (
            "the premise: the block hash is OpenSSL's SHA-512/256 — if it no longer is, re-read this test"
        )
        shared = (_GLUE_DIR / "shared.js").read_text(encoding="utf-8")
        first = re.search(r"loadPackage\(\[([^\]]*)\]\)", shared)
        assert first, "no pyodide.loadPackage([...]) in shared.js — this scan is broken"
        assert '"hashlib"' in first.group(1), f"the first loadPackage is {first.group(1)} — no hashlib"
        assert first.start() < shared.index("import micropip"), "micropip is imported before hashlib is loaded"

    def test_the_pages_safety_stop_is_above_what_the_rule_can_ask(self) -> None:
        """`MAX_HEADER_REQUESTS` in shared.js only stops a runaway loop; it must never cut off a
        header the rule is entitled to ask for. Derived from the rule's own bound."""
        import re

        from pyrxd.glyph.mark_anchor import MAX_INDEX_LAG_BLOCKS

        shared = (_GLUE_DIR / "shared.js").read_text(encoding="utf-8")
        match = re.search(r"const MAX_HEADER_REQUESTS = (\d+);", shared)
        assert match, "shared.js no longer declares MAX_HEADER_REQUESTS — this scan is broken"
        assert int(match.group(1)) >= 2 * MAX_INDEX_LAG_BLOCKS + 1
