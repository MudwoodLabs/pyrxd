"""The mark's block is the block its header says, not what `tip - confirmations + 1` says.

THE FINDING (0.25.0 panel, round 2, M1, lane E, measured read-only on mainnet). ``resolve_mark_anchor``
derived the height as ``tip - confirmations + 1``. The tip is ElectrumX's ``headers.subscribe`` —
its INDEXED height — while ``confirmations`` passes through from its node, which gets each new
block seconds before the index does. In that window the formula is one block LOW, and it is low
on EVERY server at once, so the two-server rule could not see it: of 470 paired samples over
1,171 s, both shipped servers were one block low together in 7 (they passed corroboration) and
disagreed in 5. In 12 live runs of `verify --wave-name custodian-gate-x7f3.rxd`, run 11 printed
ESTABLISHED at "block 460571"; the block whose header hashes to the verbose `blockhash` is 460572.
It flips a form-2 verdict when a name update shares the mark's block (rename, then sign).

THE FIX, at the funnel. ``resolve_anchor_from`` — the one door every CLI anchor comes through —
passes ``fetch_header``, and ``resolve_mark_anchor`` then returns the height whose header hashes to
the verbose ``blockhash``, searching up to ``MAX_INDEX_LAG_BLOCKS`` above the formula (it can only
be low for an honest endpoint), or raises. A block number no header confirmed is never printed.

The fakes here are the derived ``FakeChainServer``: every transaction real mainnet bytes, each
height's header a synthetic 80 bytes whose hash the fake reports as the verbose ``blockhash``. The
lag is modelled as an OPERATION on that truth — the index tip reported one block behind the node.
"""

from __future__ import annotations

import pathlib
import sys

import pytest

from pyrxd.cli import glyph_inspect
from pyrxd.glyph.mark_anchor import BOUND_CAVEAT, MAX_INDEX_LAG_BLOCKS, UNVERIFIED_CAVEAT, resolve_mark_anchor
from pyrxd.security.errors import NetworkError
from tests.test_mutable_chain_is_discovered_from_the_chain import (
    HEIGHTS,
    MARK,
    MINT,
    MINT_TARGET,
    MOVED,
    UPDATE_A,
    block_hash_at,
    synthetic_header,
)
from tests.test_name_at_mark_reaches_the_cli import MOVED_H160, _payload, _run, _Server

SAME_BLOCK = HEIGHTS[UPDATE_A]  # 458591: the name moved to MOVED in this block, and the mark is in it too


class _IndexBehindNode(_Server):
    """Honest data; the ElectrumX INDEX tip trails the node that answers the verbose call."""

    def __init__(self, *, lag: int = 1, **kw) -> None:
        super().__init__(**kw)
        self.lag = lag

    async def get_tip_height(self) -> int:
        return self.tip - self.lag

    async def get_block_header(self, height) -> bytes:
        # ElectrumX serves headers only up to its OWN index tip, which is the lagging one.
        if int(height) > self.tip - self.lag:
            self.calls.append(("get_block_header", str(int(height))))
            raise NetworkError(f"height {int(height)} out of range")
        return await super().get_block_header(height)


def _pair(a_cls=_Server, b_cls=_Server, **kw):
    a = a_cls(indexer=False, mark_heights={MARK: SAME_BLOCK}, **kw)
    b = b_cls(indexer=True, mark_heights={MARK: SAME_BLOCK}, **kw)
    return a, "wss://a", b, "wss://b"


# ---------------------------------------------------------------------------
# Through the CLI: lane E's probe
# ---------------------------------------------------------------------------


def test_both_indexes_one_block_behind_still_place_the_mark_in_its_real_block(monkeypatch) -> None:
    """LANE E'S PROBE (`panel-e-744/tests/test_panel_e_744_index_lag.py`). Before: both servers
    'agreed' on 458590, form 2 folded the mint only, and the new key read NOT THE SIGNER with an
    empty reason. Now both bind to 458591 by the header, and the moved target is the answer."""
    nam = _run(monkeypatch, _payload(MOVED_H160), _pair(_IndexBehindNode, _IndexBehindNode))
    assert nam["form"] == 2, nam["degraded_reason"]
    assert nam["height"] == SAME_BLOCK
    assert nam["anchor"]["height"] == SAME_BLOCK, "the anchor itself — what `verify` prints — is the real block"
    assert nam["target_at_height"] == MOVED and nam["signer_is_target_at_height"] is True


def test_one_lagging_index_no_longer_makes_honest_servers_disagree(monkeypatch) -> None:
    """The other half of the measurement (5 of 470 samples): one server low, one not. That was a
    false degrade of an honest pair; bound, both place the mark in the same, real block."""
    nam = _run(monkeypatch, _payload(MOVED_H160), _pair(_IndexBehindNode, _Server))
    assert nam["form"] == 2, nam["degraded_reason"]
    assert {r["mark"] for r in nam["heights"]["by_source"]} == {SAME_BLOCK}


def test_in_sync_servers_are_unchanged(monkeypatch) -> None:
    nam = _run(monkeypatch, _payload(MOVED_H160), _pair())
    assert nam["form"] == 2 and nam["height"] == SAME_BLOCK and nam["target_at_height"] == MOVED


def test_the_anchor_that_reaches_verify_asked_for_the_header(monkeypatch) -> None:
    """Reachability: the binding runs on the production path, not only in the unit below."""
    a, la, b, lb = _pair(_IndexBehindNode, _IndexBehindNode)
    _run(monkeypatch, _payload(MOVED_H160), (a, la, b, lb))
    assert ("get_block_header", str(SAME_BLOCK - 1)) in a.calls, "the formula's height was checked"
    assert ("get_block_header", str(SAME_BLOCK)) in a.calls, "and the real one found by its header"


def test_the_printed_caveat_says_what_the_binding_is(monkeypatch) -> None:
    """The unbound caveat says pyrxd has no header check; for a bound anchor that sentence is now
    false, so the bound one is printed — and it still says NOT verified."""
    nam = _run(monkeypatch, _payload(MOVED_H160), _pair())
    assert nam["anchor"]["caveat"] == BOUND_CAVEAT
    assert "NOT verified" in BOUND_CAVEAT and "checked only against the endpoint itself" in BOUND_CAVEAT


# ---------------------------------------------------------------------------
# The library: every branch of the binding
# ---------------------------------------------------------------------------


async def _resolve(*, confirmations: int, tip: int, verbose_extra=None, headers=None, bind=True):
    async def verbose(txid: str) -> dict:
        return {"txid": txid, "confirmations": confirmations, **(verbose_extra or {})}

    async def header(height: int) -> bytes:
        if headers is not None:
            return headers(height)
        return synthetic_header(height)

    return await resolve_mark_anchor(
        txid=MARK,
        fetch_verbose=verbose,
        source="endpoint",
        min_confirmations=6,
        tip_height=tip,
        fetch_header=header if bind else None,
    )


@pytest.mark.parametrize("lag", range(MAX_INDEX_LAG_BLOCKS + 1))
async def test_the_true_block_is_found_within_the_lag_window(lag) -> None:
    """The node's count says the mark is at 1000; the index tip is `lag` blocks behind."""
    node_tip, true_height = 1009, 1000
    anchor = await _resolve(
        confirmations=node_tip - true_height + 1,
        tip=node_tip - lag,
        verbose_extra={"blockhash": block_hash_at(true_height)},
    )
    assert anchor.height == true_height
    assert anchor.caveat == BOUND_CAVEAT
    assert anchor.confirmations == 10, "depth is the node's count, untouched by the binding"


async def test_beyond_the_window_it_refuses_rather_than_guessing() -> None:
    node_tip, true_height = 1009, 1000
    with pytest.raises(NetworkError, match="not its header at any height from"):
        await _resolve(
            confirmations=node_tip - true_height + 1,
            tip=node_tip - (MAX_INDEX_LAG_BLOCKS + 1),
            verbose_extra={"blockhash": block_hash_at(true_height)},
        )


async def test_a_confirmed_reply_with_no_block_hash_is_refused() -> None:
    with pytest.raises(NetworkError, match="no block hash to bind"):
        await _resolve(confirmations=10, tip=1009)
    with pytest.raises(NetworkError, match="no block hash to bind"):
        await _resolve(confirmations=10, tip=1009, verbose_extra={"blockhash": "zz" * 32})


async def test_a_header_the_endpoint_cannot_serve_is_refused() -> None:
    def refuse(height: int) -> bytes:
        raise NetworkError("height out of range")

    with pytest.raises(NetworkError, match="could not read the endpoint's header"):
        await _resolve(confirmations=10, tip=1009, verbose_extra={"blockhash": block_hash_at(1000)}, headers=refuse)


async def test_a_header_that_is_not_80_bytes_is_refused_not_hashed() -> None:
    with pytest.raises(NetworkError, match="could not read the endpoint's header"):
        await _resolve(
            confirmations=10, tip=1009, verbose_extra={"blockhash": block_hash_at(1000)}, headers=lambda h: b"\x00" * 79
        )


async def test_an_unmined_mark_needs_no_header() -> None:
    """Zero confirmations has no block to bind; nothing is fetched and nothing is claimed."""

    def never(height: int) -> bytes:
        raise AssertionError("a header was fetched for an unmined transaction")

    anchor = await _resolve(confirmations=0, tip=1009, headers=never)
    assert anchor.height is None


async def test_without_a_header_fetcher_the_library_is_still_the_formula() -> None:
    """The browser pages call the library WITHOUT `fetch_header` (they fetch the verbose reply and
    the tip themselves, in `shared.js`, and hand both to `glue.mark_anchor`). This pins what that
    path still does: the arithmetic, one block low under lag, with the UNBOUND caveat. When the
    pages bind (PR #741's territory, not this one), this fails and forces the sentence out."""
    node_tip, true_height = 1009, 1000
    anchor = await _resolve(
        confirmations=node_tip - true_height + 1,
        tip=node_tip - 1,
        verbose_extra={"blockhash": block_hash_at(true_height)},
        bind=False,
    )
    assert anchor.height == true_height - 1
    assert anchor.caveat == UNVERIFIED_CAVEAT


def test_the_pages_glue_does_not_bind_yet() -> None:
    """Executable, not prose: the page bridge calls `resolve_mark_anchor` with no header fetcher."""
    import inspect as _inspect

    glue_dir = pathlib.Path(__file__).resolve().parents[1] / "docs" / "inspect_static" / "inspect"
    sys.path.insert(0, str(glue_dir))
    try:
        import glue

        source = _inspect.getsource(glue.mark_anchor)
    finally:
        sys.path.remove(str(glue_dir))
        sys.modules.pop("glue", None)
    assert "resolve_mark_anchor(" in source, "the premise: the page calls the library"
    assert "fetch_header" not in source


def test_the_cli_funnel_always_binds() -> None:
    """`resolve_anchor_from` is the one door; the header fetcher is passed unconditionally there."""
    import inspect as _inspect

    source = _inspect.getsource(glyph_inspect.resolve_anchor_from)
    assert "fetch_header=client.get_block_header" in source


def test_one_block_earlier_the_name_pointed_at_the_old_key() -> None:
    """Non-vacuity for the CLI probe above: at SAME_BLOCK - 1 the mint is in force and the update
    is not, so a height one low really changes the answer rather than landing on the same one."""
    assert HEIGHTS[MINT] <= SAME_BLOCK - 1 < HEIGHTS[UPDATE_A]
    assert MINT_TARGET != MOVED
