"""Where a mark's transaction sits — and refusing to overstate what that is worth.

Form 2 needs the block that carried the mark, and nothing was supplying it: `_classify_raw_tx`
takes a txid and raw bytes and returns no height, blockhash or confirmation count.

The height this produces is the ENDPOINT'S CLAIM. pyrxd has no Radiant header verifier, no Radiant
proof-of-work check and no Radiant merkle-inclusion check — `pyrxd.spv` is Bitcoin (SHA-256d) and
says so. Fetching a merkle path would not fix it: with no work check, fabricating a header whose
root commits to the transaction is free, so inclusion-without-work buys nothing against a hostile
endpoint while looking exactly like security.

There is deliberately NO DEPTH DEFAULT. `btc_wallet/chains.py` states the rule: depth buys
reorg-resistance priced in a chain's hashrate, "'6 confirmations' folklore transfers across chains
even less than it transfers across values", and that registry "deliberately does NOT ship depth
defaults". Neither does this.
"""

from __future__ import annotations

import pytest

from pyrxd.glyph.mark_anchor import UNVERIFIED_CAVEAT, MarkAnchor, resolve_mark_anchor
from pyrxd.security.errors import NetworkError, ValidationError

TXID = "ab" * 32


#: THE SHAPE A REAL RADIANT NODE RETURNS. Measured against a live mainnet node and both shipped
#: public ElectrumX servers for a real transaction: `getrawtransaction <txid> true` yields exactly
#: these keys and NO `height` / `blockheight`.
#:
#: The original fixtures here supplied `height=458591` — a field the real system never sends. So
#: every test passed while `resolve_mark_anchor` read a key that does not exist, `height` was
#: always None in production, and form 2 could never fire honestly. Worse: the ONLY way to get a
#: usable anchor was an endpoint that ADDED the key, so the feature was reachable exclusively by
#: anomalous or hostile responses. Driving the real shape is the whole point of this constant.
REAL_NODE_RESPONSE = {
    "blockhash": "00" * 32,
    "blocktime": 1757000000,
    "confirmations": 4446,
    "hash": "ab" * 32,
    "locktime": 0,
    "size": 828,
    "time": 1757000000,
    "txid": TXID,
    "version": 1,
}
#: The live tip when that response was taken. 463036 - 4446 + 1 = 458591, which is the real height
#: of the transaction it describes — the derivation is checked against chain data, not invented.
REAL_TIP = 463036
REAL_HEIGHT = 458591


def _verbose(**overrides):
    """A real node response, with fields overridden for the case under test."""
    body = {**REAL_NODE_RESPONSE, **overrides}

    async def fetch(_txid: str) -> dict:
        return body

    return fetch


def _raw(**fields):
    """An arbitrary dict, for shapes a real node would never send."""

    async def fetch(_txid: str) -> dict:
        return dict(fields)

    return fetch


async def test_the_real_node_shape_yields_a_usable_anchor() -> None:
    """THE defect the original fixtures hid: against a real response, height was always None."""
    anchor = await resolve_mark_anchor(
        txid=TXID, fetch_verbose=_verbose(), source="node-A", min_confirmations=6, tip_height=REAL_TIP
    )
    assert anchor.height == REAL_HEIGHT
    assert anchor.usable_for_point_in_time


async def test_the_real_shape_carries_no_height_field() -> None:
    """Non-vacuity: if this fixture ever grows a `height` key it stops being the real shape, and
    the test above would pass for the wrong reason."""
    assert "height" not in REAL_NODE_RESPONSE
    assert "blockheight" not in REAL_NODE_RESPONSE


async def test_confirmations_without_a_tip_is_refused_not_guessed() -> None:
    """A mined transaction whose height cannot be derived must not read as unmined — those are
    different facts, and only one is benign."""
    with pytest.raises(NetworkError, match="no chain tip was supplied"):
        await resolve_mark_anchor(txid=TXID, fetch_verbose=_verbose(), source="node-A", min_confirmations=6)


async def test_an_echoed_txid_for_another_transaction_is_refused() -> None:
    """The binding this module's docstring promised, now performed here rather than beside."""
    with pytest.raises(NetworkError, match="answered about"):
        await resolve_mark_anchor(
            txid=TXID,
            fetch_verbose=_verbose(txid="cd" * 32),
            source="node-A",
            min_confirmations=1,
            tip_height=REAL_TIP,
        )


@pytest.mark.parametrize("depth", ["", [], {}, -1, -(10**9), False])
async def test_falsy_and_negative_depths_are_refused_not_read_as_unmined(depth: object) -> None:
    """`or 0` turned every one of these into depth 0 and then into "unmined" — the exact
    conflation this module's contract forbids, while the height branch refused negatives. The
    original parametrization was a hand-kept list that omitted all of them."""
    with pytest.raises(NetworkError, match="unreadable confirmation depth"):
        await resolve_mark_anchor(
            txid=TXID,
            fetch_verbose=_raw(confirmations=depth, txid=TXID),
            source="node-A",
            min_confirmations=1,
            tip_height=REAL_TIP,
        )


async def test_more_confirmations_than_the_chain_has_is_refused() -> None:
    with pytest.raises(NetworkError, match="before the genesis block"):
        await resolve_mark_anchor(
            txid=TXID,
            fetch_verbose=_verbose(confirmations=999_999),
            source="node-A",
            min_confirmations=1,
            tip_height=100,
        )


async def test_a_buried_transaction_is_usable() -> None:
    anchor = await resolve_mark_anchor(
        txid=TXID,
        fetch_verbose=_verbose(confirmations=12),
        tip_height=REAL_TIP + 0,
        source="node-A",
        min_confirmations=6,
    )
    assert anchor.height == REAL_TIP - 12 + 1
    assert not anchor.provisional
    assert anchor.usable_for_point_in_time


async def test_a_shallow_transaction_is_provisional_not_usable() -> None:
    anchor = await resolve_mark_anchor(
        txid=TXID,
        fetch_verbose=_verbose(confirmations=2),
        tip_height=REAL_TIP + 0,
        source="node-A",
        min_confirmations=6,
    )
    assert anchor.provisional
    assert not anchor.usable_for_point_in_time
    assert anchor.height == REAL_TIP - 2 + 1, "still report where it is — it is real, just shallow"


async def test_an_unmined_transaction_has_no_block() -> None:
    """Form 2 is unavailable for it by construction, not by policy."""
    anchor = await resolve_mark_anchor(
        txid=TXID,
        fetch_verbose=_verbose(confirmations=0),
        tip_height=REAL_TIP + 0,
        source="node-A",
        min_confirmations=1,
    )
    assert anchor.height is None
    assert not anchor.usable_for_point_in_time


@pytest.mark.parametrize("depth", ["999999", float("inf"), float("nan"), 1.5, True])
async def test_an_unreadable_depth_fails_closed(depth: object) -> None:
    """An unreadable depth must not read as 0 and then as 'unconfirmed': an unconfirmed mark and
    a mark whose depth could not be read are different facts, and only one is benign."""
    with pytest.raises(NetworkError, match="unreadable confirmation depth"):
        await resolve_mark_anchor(
            txid=TXID, fetch_verbose=_raw(confirmations=depth, txid=TXID), source="node-A", min_confirmations=1
        )


@pytest.mark.parametrize("bad_height", ["458591", float("inf"), 1.5, -3])
async def test_an_unreadable_or_negative_height_fails_closed(bad_height: object) -> None:
    with pytest.raises(NetworkError):
        await resolve_mark_anchor(
            txid=TXID,
            fetch_verbose=_raw(confirmations=12, txid=TXID),
            source="node-A",
            min_confirmations=1,
        )


async def test_a_non_dict_answer_is_refused() -> None:
    async def fetch(_txid: str):
        return []

    with pytest.raises(NetworkError, match="did not return a dict"):
        await resolve_mark_anchor(txid=TXID, fetch_verbose=fetch, source="n", min_confirmations=1)


@pytest.mark.parametrize("floor", [0, -1, None, True, 1.5, "6"])
async def test_there_is_no_depth_default(floor: object) -> None:
    """Required, and validated. A shipped default would be folklore — the registry this follows
    refuses to ship one for exactly that reason."""
    with pytest.raises(ValidationError, match="min_confirmations"):
        await resolve_mark_anchor(
            txid=TXID,
            fetch_verbose=_verbose(confirmations=12),
            tip_height=REAL_TIP + 0,
            source="n",
            min_confirmations=floor,
        )


async def test_the_caveat_is_not_optional() -> None:
    """The whole value of form 2 rests on this height. A reader who does not know it is
    unverified will over-trust the sentence built on it."""
    anchor = await resolve_mark_anchor(
        txid=TXID, fetch_verbose=_verbose(confirmations=12), tip_height=REAL_TIP + 0, source="n", min_confirmations=1
    )
    assert anchor.caveat == UNVERIFIED_CAVEAT
    assert "NOT verified" in anchor.caveat
    assert anchor.height_is_verified is False


def test_height_is_verified_is_false_by_construction() -> None:
    """If this ever defaults True, something claimed a proof pyrxd cannot produce. There is no
    Radiant SPV in this codebase."""
    assert MarkAnchor(txid=TXID, height=1, confirmations=1, min_confirmations=1, source="n").height_is_verified is False
