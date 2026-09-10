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


def _verbose(**fields):
    async def fetch(_txid: str) -> dict:
        return dict(fields)

    return fetch


async def test_a_buried_transaction_is_usable() -> None:
    anchor = await resolve_mark_anchor(
        txid=TXID, fetch_verbose=_verbose(confirmations=12, height=458591), source="node-A", min_confirmations=6
    )
    assert anchor.height == 458591
    assert not anchor.provisional
    assert anchor.usable_for_point_in_time


async def test_a_shallow_transaction_is_provisional_not_usable() -> None:
    anchor = await resolve_mark_anchor(
        txid=TXID, fetch_verbose=_verbose(confirmations=2, height=458591), source="node-A", min_confirmations=6
    )
    assert anchor.provisional
    assert not anchor.usable_for_point_in_time
    assert anchor.height == 458591, "still report where it is — it is real, just shallow"


async def test_an_unmined_transaction_has_no_block() -> None:
    """Form 2 is unavailable for it by construction, not by policy."""
    anchor = await resolve_mark_anchor(
        txid=TXID, fetch_verbose=_verbose(confirmations=0), source="node-A", min_confirmations=1
    )
    assert anchor.height is None
    assert not anchor.usable_for_point_in_time


@pytest.mark.parametrize("depth", ["999999", float("inf"), float("nan"), 1.5, True])
async def test_an_unreadable_depth_fails_closed(depth: object) -> None:
    """An unreadable depth must not read as 0 and then as 'unconfirmed': an unconfirmed mark and
    a mark whose depth could not be read are different facts, and only one is benign."""
    with pytest.raises(NetworkError, match="unreadable confirmation depth"):
        await resolve_mark_anchor(
            txid=TXID, fetch_verbose=_verbose(confirmations=depth), source="node-A", min_confirmations=1
        )


@pytest.mark.parametrize("bad_height", ["458591", float("inf"), 1.5, -3])
async def test_an_unreadable_or_negative_height_fails_closed(bad_height: object) -> None:
    with pytest.raises(NetworkError):
        await resolve_mark_anchor(
            txid=TXID,
            fetch_verbose=_verbose(confirmations=12, height=bad_height),
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
            txid=TXID, fetch_verbose=_verbose(confirmations=12, height=1), source="n", min_confirmations=floor
        )


async def test_the_caveat_is_not_optional() -> None:
    """The whole value of form 2 rests on this height. A reader who does not know it is
    unverified will over-trust the sentence built on it."""
    anchor = await resolve_mark_anchor(
        txid=TXID, fetch_verbose=_verbose(confirmations=12, height=1), source="n", min_confirmations=1
    )
    assert anchor.caveat == UNVERIFIED_CAVEAT
    assert "NOT verified" in anchor.caveat
    assert anchor.height_is_verified is False


def test_height_is_verified_is_false_by_construction() -> None:
    """If this ever defaults True, something claimed a proof pyrxd cannot produce. There is no
    Radiant SPV in this codebase."""
    assert MarkAnchor(txid=TXID, height=1, confirmations=1, min_confirmations=1, source="n").height_is_verified is False
