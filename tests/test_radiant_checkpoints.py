"""The shipped checkpoint table, and the script that is the only thing allowed to write it.

The table is trust: a wrong entry degrades honest marks, an attacker-chosen one would verify a
forged chain. So beyond its shape, this asserts the file is EXACTLY what the refresh script renders
from the file's own recorded inputs — a hand-edit anywhere (an entry, the docstring's statement of
who vouched for it) fails here — and that the script refuses on every disagreement it promises to.
"""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path

import pytest

from pyrxd.constants import GENESIS_BLOCK_HASHES
from pyrxd.spv import radiant_checkpoints as cp

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location(
    "refresh_radiant_checkpoints", ROOT / "scripts" / "refresh_radiant_checkpoints.py"
)
assert _spec and _spec.loader
refresh = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(refresh)

MAINNET = cp.CHECKPOINTS["mainnet"]

#: The recorded last-interval work, as the renderer takes it (the byte-identity test re-renders from it).
_WORK = dict(
    last_interval_max_work=cp.LAST_INTERVAL_MAX_WORK["mainnet"],
    last_interval_max_work_height=cp.LAST_INTERVAL_MAX_WORK_HEIGHT["mainnet"],
    newest_checkpoint_work=cp.NEWEST_CHECKPOINT_WORK["mainnet"],
)


def test_mainnet_is_not_empty_and_other_networks_are() -> None:
    """Non-vacuity for everything below; and regtest/testnet must DEGRADE, so they carry none."""
    assert len(MAINNET) >= 200
    assert cp.CHECKPOINTS["testnet"] == ()
    assert cp.CHECKPOINTS["regtest"] == ()


def test_entries_are_every_2016_blocks_from_genesis() -> None:
    assert cp.CHECKPOINT_INTERVAL == 2016
    assert [h for h, _ in MAINNET] == list(range(0, 2016 * len(MAINNET), 2016))


def test_block_zero_is_the_genesis_pyrxd_already_declares() -> None:
    """A known answer from an independent source (``pyrxd.constants``, used by ``assert_chain``)."""
    assert MAINNET[0] == (0, GENESIS_BLOCK_HASHES["mainnet"])


def test_hashes_are_lowercase_hex_and_distinct() -> None:
    assert all(re.fullmatch(r"[0-9a-f]{64}", h) for _, h in MAINNET)
    assert len({h for _, h in MAINNET}) == len(MAINNET)


def test_every_entry_was_deep_when_pinned() -> None:
    assert all(cp.PINNED_AT_TIP["mainnet"] - h >= cp.MIN_DEPTH_BELOW_TIP >= 1000 for h, _ in MAINNET)
    assert cp.PINNED_AT_TIP["mainnet"] - MAINNET[-1][0] < cp.MIN_DEPTH_BELOW_TIP + 2016, "a whole interval was skipped"


def test_the_table_was_confirmed_by_the_maintainers_node() -> None:
    """Regenerated 2026-09-30 with ``--node-cli``: the maintainer's Radiant Core node was a third
    source, and ``reconcile`` refuses the write unless every source answers every height alike.
    A later ``--write`` WITHOUT the node flips both of these back, and this test fails."""
    assert cp.NODE_CONFIRMED == {"mainnet": True}
    doc = " ".join((cp.__doc__ or "").split())
    ordinal = {2: "third", 3: "fourth"}[len(cp.SOURCES["mainnet"])]
    assert f"maintainer was a {ordinal}, REQUIRED source: on 2026-09-30" in doc
    assert "``radiant-cli getblockhash <height>`` for every entry" in doc
    assert "NO node" not in doc
    assert cp.SOURCES["mainnet"], "SOURCES lists the ElectrumX servers that agreed"
    assert all(u.startswith("wss://") for u in cp.SOURCES["mainnet"]), "the node is not one of SOURCES"


def test_a_table_written_without_a_node_says_so() -> None:
    """The other branch of the renderer: no node, no claim of one."""
    text = refresh.render_module(
        MAINNET[:1],
        servers=("wss://a/", "wss://b/"),
        node_cli=None,
        pinned_at_tip=5000,
        min_depth=1000,
        generated_utc="2026-01-01",
        **_WORK,
    )
    assert "NO node run by pyrxd's maintainer was consulted" in text
    assert 'NODE_CONFIRMED: dict[str, bool] = {"mainnet": False}' in text
    assert "REQUIRED" not in text


def test_the_file_is_exactly_what_the_script_renders() -> None:
    """No hand-edits: re-render from the recorded inputs and compare byte for byte."""
    text = refresh.render_module(
        MAINNET,
        servers=cp.SOURCES["mainnet"],
        node_cli="recorded" if cp.NODE_CONFIRMED["mainnet"] else None,
        pinned_at_tip=cp.PINNED_AT_TIP["mainnet"],
        min_depth=cp.MIN_DEPTH_BELOW_TIP,
        generated_utc=cp.GENERATED_UTC,
        **_WORK,
    )
    assert text == (ROOT / "src/pyrxd/spv/radiant_checkpoints.py").read_text(encoding="utf-8")


def test_the_sources_are_shipped_defaults_of_at_least_two_operators() -> None:
    """The table records the servers that ACTUALLY agreed when it was generated. Each is one pyrxd
    ships, and together they span two operators. They need not be every default: a default added
    since (a second server of an operator already listed) was not asked, and listing it here
    would claim a confirmation that never happened. The next regeneration asks every default."""
    from pyrxd.network.registry import DEFAULT_ENDPOINTS
    from pyrxd.network.source_identity import source_key

    recorded = cp.SOURCES["mainnet"]
    assert set(recorded) <= set(DEFAULT_ENDPOINTS["mainnet"])
    assert len({source_key(u) for u in recorded}) >= 2


def test_reconcile_counts_operators_not_urls() -> None:
    """Two servers of one operator are one source: they cannot be the two a table needs."""
    one_op = {
        "wss://electrumx.radiant4people.com:50022/": {0: G, 2016: A},
        "wss://electrumx2.radiant4people.com:50022/": {0: G, 2016: A},
    }
    with pytest.raises(refresh.Disagreement, match="different operators"):
        refresh.reconcile(one_op, [0, 2016], G)


@pytest.mark.parametrize(
    "second",
    ["wss://electrumx.radiantcore.org/", "node"],
)
def test_reconcile_accepts_a_second_operator_or_the_node(second) -> None:
    """The honest pair: a server of another operator, or the maintainer's node, is a second source."""
    answers = {"wss://electrumx.radiant4people.com:50022/": {0: G, 2016: A}, second: {0: G, 2016: A}}
    assert refresh.reconcile(answers, [0, 2016], G) == [(0, G), (2016, A)]


def test_the_rendered_prose_counts_the_servers_it_lists() -> None:
    """Three servers must not render as "both servers" or "any of the three"."""
    three = ("wss://a.example/", "wss://b.example/", "wss://c.example/")
    with_node = refresh.render_module(
        MAINNET[:1],
        servers=three,
        node_cli="x",
        pinned_at_tip=5000,
        min_depth=1000,
        generated_utc="2026-01-01",
        **_WORK,
    )
    flat = " ".join(with_node.split())
    assert "all three servers agreed on every entry" in flat
    assert "it agreed with all three servers on every one" in flat
    assert "was a fourth, REQUIRED source" in flat
    assert "any of the four would have refused" in flat
    assert "both servers" not in flat and "of the three" not in flat
    no_node = " ".join(
        refresh.render_module(
            MAINNET[:1],
            servers=three,
            node_cli=None,
            pinned_at_tip=5000,
            min_depth=1000,
            generated_utc="2026-01-01",
            **_WORK,
        ).split()
    )
    assert "rests on the three public servers alone. All are ElectrumX" in no_node
    assert "the two public" not in no_node


# ── the refresh script's refusals, each paired with the honest case ─────────────────────────

G = GENESIS_BLOCK_HASHES["mainnet"]
A = "aa" * 32
B = "bb" * 32


def test_reconcile_accepts_agreeing_sources() -> None:
    assert refresh.reconcile({"s1": {0: G, 2016: A}, "s2": {0: G, 2016: A}}, [0, 2016], G) == [(0, G), (2016, A)]


@pytest.mark.parametrize(
    ("answers", "match"),
    [
        ({"s1": {0: G, 2016: A}}, "at least two sources"),
        ({"s1": {0: G, 2016: A}, "s2": {0: G, 2016: B}}, "disagree at height 2016"),
        ({"s1": {0: G, 2016: A}, "s2": {0: G}}, "no usable hash for height 2016"),
        ({"s1": {0: G, 2016: A}, "s2": {0: G, 2016: A.upper()}}, "no usable hash"),
        ({"s1": {0: A, 2016: A}, "s2": {0: A, 2016: A}}, "not the declared mainnet genesis"),
    ],
    ids=["one_source", "disagree", "missing", "uppercase", "wrong_genesis"],
)
def test_reconcile_refuses(answers: dict, match: str) -> None:
    with pytest.raises(refresh.Disagreement, match=match):
        refresh.reconcile(answers, [0, 2016], G)


def test_checkpoint_heights_respect_the_depth() -> None:
    assert refresh.checkpoint_heights(5032, 1000) == [0, 2016, 4032]  # 4032 is exactly 1000 deep
    assert refresh.checkpoint_heights(5031, 1000) == [0, 2016]  # one block short
    assert refresh.checkpoint_heights(999, 1000) == []


def test_the_node_hook_asks_getblockcount_and_getblockhash() -> None:
    """The documented node-signer hook, run against a fake ``radiant-cli`` (no network)."""
    calls = []

    class Done:
        def __init__(self, out: str) -> None:
            self.stdout = out + "\n"

    def run(argv: list[str], **kwargs: object) -> Done:
        calls.append(argv)
        assert kwargs["check"] is True
        return Done("12345" if argv[-1] == "getblockcount" else A.upper())

    tip, got = refresh.node_hashes(["ssh", "node.example.com", "radiant-cli"], [0, 2016], run=run)
    assert tip == 12345
    assert got == {0: A, 2016: A}
    assert calls[0] == ["ssh", "node.example.com", "radiant-cli", "getblockcount"]
    assert calls[1] == ["ssh", "node.example.com", "radiant-cli", "getblockhash", "0"]


# --------------------------------------------------------------------------- the last interval's work


def test_the_shipped_last_interval_work_is_consistent() -> None:
    """The recorded numbers describe the table's last interval: the hardest header lies in it, carries
    at least the checkpoint's own work, and the gate prices mainnet at the pow limit the script used."""
    from pyrxd.gravity import funding_spv

    lo, hi = MAINNET[-2][0], MAINNET[-1][0]
    assert lo <= cp.LAST_INTERVAL_MAX_WORK_HEIGHT["mainnet"] <= hi
    assert cp.LAST_INTERVAL_MAX_WORK["mainnet"] >= cp.NEWEST_CHECKPOINT_WORK["mainnet"] > 0
    assert funding_spv.MAINNET_CHAIN.pow_limit == refresh.MAINNET_POW_LIMIT
    assert funding_spv.MAINNET_CHAIN.last_interval_max_work == cp.LAST_INTERVAL_MAX_WORK["mainnet"]
    assert funding_spv.MAINNET_CHAIN.newest_checkpoint_work == cp.NEWEST_CHECKPOINT_WORK["mainnet"]


def _interval() -> tuple[dict[int, bytes], list[tuple[int, str]]]:
    """REAL mainnet headers 460,564..460,570 (the recorded fixture), checkpoints at both ends."""
    from pyrxd.hash import radiant_block_hash
    from tests.test_mark_block_verification import MARKS

    headers = {h: MARKS["reference_460572"].headers[h] for h in range(460_564, 460_571)}
    return headers, [(460_564, radiant_block_hash(headers[460_564])), (460_570, radiant_block_hash(headers[460_570]))]


def test_reconcile_interval_finds_the_hardest_header_when_every_source_agrees() -> None:
    from pyrxd.spv.radiant import radiant_header_work

    headers, table = _interval()
    got = refresh.reconcile_interval({"s1": headers, "node": dict(headers)}, table)
    works = {h: radiant_header_work(b, pow_limit=refresh.MAINNET_POW_LIMIT) for h, b in headers.items()}
    best = max(works.values())
    assert got == (best, min(h for h, w in works.items() if w == best), works[460_570])


def test_reconcile_interval_refuses_disagreement_a_gap_and_a_broken_link() -> None:
    headers, table = _interval()
    flipped = bytes(headers[460_566][:-1]) + bytes([headers[460_566][-1] ^ 1])
    with pytest.raises(refresh.Disagreement, match="disagree on the header at height 460566"):
        refresh.reconcile_interval({"s1": headers, "s2": {**headers, 460_566: flipped}}, table)
    with pytest.raises(refresh.Disagreement, match="no 80-byte header for height 460567"):
        refresh.reconcile_interval({"s1": {h: b for h, b in headers.items() if h != 460_567}}, table)
    with pytest.raises(refresh.Disagreement, match="does not link"):
        refresh.reconcile_interval({"s1": {**headers, 460_566: flipped}}, table)


def test_the_node_interval_hook_asks_getblockhash_then_the_raw_header() -> None:
    calls = []

    class Done:
        def __init__(self, out: str) -> None:
            self.stdout = out + "\n"

    def run(argv: list[str], **kwargs: object) -> Done:
        calls.append(argv[3:])
        if argv[3] == "getblockhash":
            return Done(A)
        return Done("ab" * 80)

    got = refresh.node_interval(["ssh", "node.example.com", "radiant-cli"], 10, 12, run=run)
    assert got == {10: bytes.fromhex("ab" * 80), 11: bytes.fromhex("ab" * 80), 12: bytes.fromhex("ab" * 80)}
    assert ["getblockheader", A, "false"] in calls and ["getblockhash", "11"] in calls
