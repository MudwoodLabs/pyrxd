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


def test_the_table_does_not_claim_a_node_signed_it() -> None:
    """Generated from the two public servers only. When the maintainer's node is added, the
    script sets this True and rewrites the docstring, and this test must change with it."""
    assert cp.NODE_CONFIRMED == {"mainnet": False}
    assert "NO node run by pyrxd's maintainer was consulted" in (cp.__doc__ or "")
    assert len(cp.SOURCES["mainnet"]) == 2


def test_the_file_is_exactly_what_the_script_renders() -> None:
    """No hand-edits: re-render from the recorded inputs and compare byte for byte."""
    text = refresh.render_module(
        MAINNET,
        servers=cp.SOURCES["mainnet"],
        node_cli="recorded" if cp.NODE_CONFIRMED["mainnet"] else None,
        pinned_at_tip=cp.PINNED_AT_TIP["mainnet"],
        min_depth=cp.MIN_DEPTH_BELOW_TIP,
        generated_utc=cp.GENERATED_UTC,
    )
    assert text == (ROOT / "src/pyrxd/spv/radiant_checkpoints.py").read_text(encoding="utf-8")


def test_the_sources_are_the_shipped_default_servers() -> None:
    from pyrxd.network.registry import DEFAULT_ENDPOINTS

    assert cp.SOURCES["mainnet"] == tuple(DEFAULT_ENDPOINTS["mainnet"])


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

    tip, got = refresh.node_hashes(["ssh", "tr", "radiant-cli"], [0, 2016], run=run)
    assert tip == 12345
    assert got == {0: A, 2016: A}
    assert calls[0] == ["ssh", "tr", "radiant-cli", "getblockcount"]
    assert calls[1] == ["ssh", "tr", "radiant-cli", "getblockhash", "0"]
