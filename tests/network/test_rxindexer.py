"""`RxinDexerClient` — the parsing this SDK does on an indexer's answers.

WHY THIS FILE EXISTS. `network/rxindexer.py` scored 12% killed under cosmic-ray on 2026-09-16
(157 mutants, 20 killed, 88 annotation-equivalent, ~49 live). The live survivors sat almost
entirely in `wave_reverse_lookup` — the `expired` filter, the `{error}` refusal, the list/dict
parsing, the `.rxd` re-qualification — and every one of those lines IS tested, in
`tests/test_glyph_wave.py` and `tests/test_hashmark_wave_identity.py`. Neither file was in the
`network` group's test list (`scripts/mutation_test.sh`): the first sat under `glyphverify`, the
second under no group at all. The mutants survived because the run never executed the tests.

That wiring is fixed alongside this file. What remains here are the survivors those two files
still leave alive: the boundary cases they do not reach. Each test names the mutant it kills.

The statuses used below are the ones RXinDexer actually emits — `active`, `grace`, `expired`,
`superseded` (`electrumx/server/wave_index.py`, read upstream 2026-09-16, lines 1506/1508/1735/1742).
"""

from __future__ import annotations

import dataclasses

import pytest

from pyrxd.network.electrumx import script_hash_for_address
from pyrxd.network.rxindexer import IndexerStats, RxinDexerClient, RxinDexerError

# A real mainnet address (a WAVE target from tests/fixtures/wave_update_chain_mainnet.json): the
# reverse lookup hashes it to a scripthash before the call, so it has to decode.
ADDR = "1CPfirXZahPrTb93QouwBfKDoz1ykfcBb7"


class FakeElectrumXClient:
    """Canned-response transport double (the same shape as tests/test_glyph_wave.py's)."""

    def __init__(self, responses: dict | None = None):
        self.responses = responses or {}
        self.calls: list[tuple[str, list]] = []

    async def call_extension(self, method: str, params: list | None = None):
        self.calls.append((method, params or []))
        if method not in self.responses:
            raise RuntimeError(f"no canned response for {method}")
        result = self.responses[method]
        if isinstance(result, Exception):
            raise result
        return result


def _entry(name: str, status: str | None = None) -> dict:
    d = {"ref": "ab" * 32 + "_0", "name": name, "full_name": f"{name}.rxd"}
    if status is not None:
        d["status"] = status
    return d


# ---------------------------------------------------------------------------
# wave_reverse_lookup
# ---------------------------------------------------------------------------


async def test_only_the_literal_status_expired_is_dropped() -> None:
    """Kills line 118 `== "expired"` -> `>= "expired"` (and the `>`/`<`/`<=`/`!=` rewrites).

    A name in its GRACE period still resolves — upstream keeps answering for it until the grace
    window closes — and `"grace" > "expired"` lexicographically, so an ordering comparison would
    silently drop every name that is merely due for renewal. `superseded` sorts above too. The
    filter is an equality on one literal, and the test says so with every upstream status."""
    client = FakeElectrumXClient(
        {
            "wave.reverse_lookup": [
                _entry("alice", "active"),
                _entry("due", "grace"),
                _entry("old", "expired"),
                _entry("shouted", "EXPIRED"),
                _entry("replaced", "superseded"),
                _entry("bare"),
            ]
        }
    )
    names = await RxinDexerClient(client).wave_reverse_lookup(ADDR)
    assert names == ["alice.rxd", "due.rxd", "replaced.rxd", "bare.rxd"]
    assert client.calls == [("wave.reverse_lookup", [script_hash_for_address(ADDR).hex()])]


async def test_an_entry_with_no_name_is_skipped_not_the_rest_of_the_list() -> None:
    """Kills line 122 `continue` -> `break`. An entry the indexer answers without a name (a
    half-indexed record) must not end the listing: the names after it are still the caller's."""
    client = FakeElectrumXClient(
        {"wave.reverse_lookup": [{"ref": "cd" * 32 + "_0", "status": "active"}, _entry("after", "active")]}
    )
    assert await RxinDexerClient(client).wave_reverse_lookup(ADDR) == ["after.rxd"]


async def test_a_bare_name_spelled_error_is_a_name_not_a_refusal() -> None:
    """Kills line 111 `isinstance(result, dict) and "error" in result` -> `or`.

    The refusal check is SHAPE-based — a dict carrying an `error` key — because that is how
    RXinDexer reports a rejected argument. `"error" in <list>` is a membership test on the list's
    elements, so an `or` would refuse any older indexer whose bare-name list happened to contain
    a name spelled `error`. A name is a name."""
    client = FakeElectrumXClient({"wave.reverse_lookup": ["error", "alice.rxd"]})
    assert await RxinDexerClient(client).wave_reverse_lookup(ADDR) == ["error.rxd", "alice.rxd"]


async def test_an_entry_of_unexpected_shape_is_refused() -> None:
    """The else branch: neither dict nor str. An integer where a record should be is an indexer
    speaking a schema this client does not know, and guessing at it would put `42.rxd` in a list
    of names somebody then trusts."""
    client = FakeElectrumXClient({"wave.reverse_lookup": [42]})
    with pytest.raises(RxinDexerError, match="unexpected shape"):
        await RxinDexerClient(client).wave_reverse_lookup(ADDR)


# ---------------------------------------------------------------------------
# wave_get_subdomains / wave_stats
# ---------------------------------------------------------------------------


async def test_subdomains_are_returned_as_strings_and_a_non_list_is_refused() -> None:
    """Kills line 136 `if not isinstance(result, list)` -> `if isinstance(...)` (and its AddNot
    twin). The existing test covers only the `None` answer, on which the inverted guard happens to
    fall through to a TypeError; a real list must come back as strings, and a dict must be refused
    as the wrong shape rather than iterated as its keys."""
    ok = FakeElectrumXClient({"wave.get_subdomains": ["a.parent.rxd", "b.parent.rxd"]})
    assert await RxinDexerClient(ok).wave_get_subdomains("parent.rxd") == ["a.parent.rxd", "b.parent.rxd"]
    assert ok.calls == [("wave.get_subdomains", ["parent.rxd"])]

    bad = FakeElectrumXClient({"wave.get_subdomains": {"a.parent.rxd": 1}})
    with pytest.raises(RxinDexerError, match="expected list"):
        await RxinDexerClient(bad).wave_get_subdomains("parent.rxd")


async def test_stats_that_are_not_a_dict_are_refused() -> None:
    """Kills line 143 `if not isinstance(result, dict)` -> `if isinstance(...)`. A list here would
    otherwise reach `IndexerStats.from_response` and fail on `.get` with an AttributeError that
    names nothing about the server."""
    client = FakeElectrumXClient({"wave.stats": [1234, 500000]})
    with pytest.raises(RxinDexerError, match="expected dict"):
        await RxinDexerClient(client).wave_stats()


class TestIndexerStats:
    def test_missing_fields_read_as_zero_not_as_a_count(self) -> None:
        """Kills lines 46/47/53/54 `0` -> `1` / `-1`. A stats answer that omits `total_names` or
        `tip_height` is an indexer that has not said; the health check must read that as zero,
        not as one name or a negative height that no chain has."""
        s = IndexerStats.from_response({})
        assert (s.total_names, s.tip_height) == (0, 0)
        assert s.raw == {}
        assert (IndexerStats().total_names, IndexerStats().tip_height, IndexerStats().raw) == (0, 0, None)

    def test_a_snapshot_is_frozen(self) -> None:
        """Kills line 42 `frozen=True` -> `False` (and the decorator removal). A health snapshot
        is passed around as evidence of what the indexer said; it must not be editable after."""
        s = IndexerStats.from_response({"total_names": 1, "tip_height": 2})
        with pytest.raises(dataclasses.FrozenInstanceError):
            s.total_names = 3  # type: ignore[misc]


# ---------------------------------------------------------------------------
# swap_get_orders
# ---------------------------------------------------------------------------


async def test_swap_get_orders_defaults_are_the_first_fifty() -> None:
    """Kills lines 233/234 `limit: int = 50` -> 49/51 and `offset: int = 0` -> 1/-1.

    `rxindexer_source.py` always passes both explicitly, so the defaults are only what a direct
    caller gets — and what they get must be page one (`offset=0`), not a page that silently skips
    the newest order. The 50 is this client's contract; the server clamps at 200 (docstring)."""
    client = FakeElectrumXClient({"swap.get_orders": []})
    rx = RxinDexerClient(client)
    await rx.swap_get_orders("aa" * 32 + "_0")
    await rx.swap_get_orders("aa" * 32 + "_0", "bb" * 32 + "_0")
    assert client.calls == [
        ("swap.get_orders", ["aa" * 32 + "_0", None, 50, 0]),
        ("swap.get_orders", ["aa" * 32 + "_0", "bb" * 32 + "_0", 50, 0]),
    ]
