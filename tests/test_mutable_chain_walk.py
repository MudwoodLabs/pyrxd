"""A truncated history is how a superseded value becomes authoritative. Prove the walk reached the tip.

`walk_mutable_chain` follows a mutable glyph along its OWN spend chain and refuses to call the
result current unless every link verified and the final mutable output is proved unspent. The
degrade path is the feature: stop one transaction early and a naive walker reports the previous
target with no sign anything is missing — which is exactly what an index was observed doing to a
live WAVE name.

Everything here runs on real Radiant mainnet bytes, because the model was wrong before it was
measured. Two findings the fixtures encode:

* **The chain is the singleton, not the index's history list.** `custodian-gate-x7f3.rxd`'s history
  contains `2cee4847`, which shares a block with a real update and is spent FROM by the next real
  update — and never touches the token. It must be EXCLUDED, not folded and not ordered with.
* **Height cannot order it.** Two of that name's transactions share height 458591.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from pyrxd.glyph.mutable_chain import MAX_CHAIN_STEPS, walk_mutable_chain
from pyrxd.security.errors import ValidationError
from pyrxd.transaction.transaction import Transaction

_FIX = pathlib.Path(__file__).parent / "fixtures"
_FOUR = json.loads((_FIX / "wave_update_chain_mainnet.json").read_text())
_THREE = json.loads((_FIX / "wave_fold_discriminating_chain_mainnet.json").read_text())

MINT_4 = "f644794b3fb9ab8330b236debbe1989ce1034e5b2a8f8f2516e05f4e54f3cf31"
UPDATE_A = "315b46300bf160470edd1ee0171beb42306fe9c69ef53a324cb0607089b33192"
SIBLING = "2cee48475b8f3095478612840964d300caeb630a4ce8baecd37eae1344308e8b"
UPDATE_B = "3c7b43dffe74fe57bc233f5305589714ee54335f9b15e81cc7dde0861c2482be"
MINT_3 = "0b45f50379878518815b8fecd99ea6898d9daaba3f796b1f17d8504d63240f39"

MOVED = "14XmXG3dSBWZUukGT3xzS9zxpiZ53vgx1i"
MINT_TARGET = "1CPfirXZahPrTb93QouwBfKDoz1ykfcBb7"


def _raw(doc: dict) -> dict[str, bytes]:
    return {t["txid"]: bytes.fromhex(t["raw"]) for t in doc["transactions"]}


def _fetcher(raw: dict[str, bytes]):
    async def fetch(txid: str):
        return Transaction.from_hex(raw[txid])

    return fetch


async def _unspent_always(_txid: str, _vout: int) -> bool:
    return True


async def _spent_always(_txid: str, _vout: int) -> bool:
    return False


async def _cannot_say(_txid: str, _vout: int) -> None:
    return None


# ---------------------------------------------------------------------------
# 1. The honest path, on real bytes
# ---------------------------------------------------------------------------


async def test_it_walks_the_real_chain_in_spend_order() -> None:
    raw = _raw(_FOUR)
    walk = await walk_mutable_chain(
        mint_txid=MINT_4,
        candidates=list(raw),
        fetch_tx=_fetcher(raw),
        is_unspent=_unspent_always,
        candidate_source="index",
        tip_source="node",
    )
    assert walk.complete, walk.reason
    assert [s.txid for s in walk.steps] == [MINT_4, UPDATE_A, UPDATE_B]
    assert [s.kind for s in walk.steps] == ["mint", "update", "update"]
    assert walk.steps[0].attrs["target"] == MINT_TARGET
    assert walk.steps[-1].attrs["target"] == MOVED


async def test_the_sibling_transaction_is_excluded_not_folded() -> None:
    """`2cee4847` is in the index's history, shares a block with a real update, and is spent FROM
    by the next one — and it never touches the token. A walker that took the history list as the
    chain would fold it."""
    raw = _raw(_FOUR)
    walk = await walk_mutable_chain(
        mint_txid=MINT_4,
        candidates=list(raw),
        fetch_tx=_fetcher(raw),
        is_unspent=_unspent_always,
        candidate_source="index",
        tip_source="node",
    )
    assert SIBLING not in [s.txid for s in walk.steps]
    assert walk.excluded == (SIBLING,)


async def test_the_ref_is_constant_and_reported() -> None:
    """The singleton's identity. Every mutable output in the chain carries it."""
    raw = _raw(_FOUR)
    walk = await walk_mutable_chain(
        mint_txid=MINT_4,
        candidates=list(raw),
        fetch_tx=_fetcher(raw),
        is_unspent=_unspent_always,
        candidate_source="index",
        tip_source="node",
    )
    assert walk.ref == "78e25bdcaec7eff36bcdf2fe9cee0c39c6e77e025603d916ee43980fd42c44b3:1"


async def test_a_chain_whose_middle_tx_never_touches_the_token(  # the 3-tx corpus
) -> None:
    raw = _raw(_THREE)
    walk = await walk_mutable_chain(
        mint_txid=MINT_3,
        candidates=list(raw),
        fetch_tx=_fetcher(raw),
        is_unspent=_unspent_always,
        candidate_source="index",
        tip_source="node",
    )
    assert walk.complete, walk.reason
    assert [s.kind for s in walk.steps] == ["mint", "update"]
    assert len(walk.excluded) == 1


async def test_order_is_not_height() -> None:
    """Non-vacuity for the ordering claim: without two transactions at one height the corpus
    cannot distinguish spend-order from height-order."""
    heights = [t["height"] for t in _FOUR["transactions"]]
    assert len(heights) != len(set(heights)), "the fixture no longer contains a height tie"


# ---------------------------------------------------------------------------
# 2. The degrade paths — the reason this returns a verdict rather than a list
# ---------------------------------------------------------------------------


async def test_a_truncated_candidate_set_is_NOT_reported_as_current() -> None:
    """THE defect this exists to prevent. Drop the last update and a naive walker happily
    reports the earlier target as the token's state."""
    raw = _raw(_FOUR)
    truncated = [t for t in raw if t != UPDATE_B]
    walk = await walk_mutable_chain(
        mint_txid=MINT_4,
        candidates=truncated,
        fetch_tx=_fetcher(raw),
        is_unspent=_spent_always,
        candidate_source="index",
        tip_source="node",
    )
    assert not walk.complete
    assert "not proved unspent" in walk.reason
    # The steps it DID walk are still returned — they are a prefix of the truth, and the caller
    # is told so rather than handed nothing.
    assert [s.txid for s in walk.steps] == [MINT_4, UPDATE_A]


async def test_an_unproved_tip_is_not_complete() -> None:
    """A source that cannot say is not a source that said yes."""
    raw = _raw(_FOUR)
    walk = await walk_mutable_chain(
        mint_txid=MINT_4,
        candidates=list(raw),
        fetch_tx=_fetcher(raw),
        is_unspent=_cannot_say,
        candidate_source="index",
        tip_source="node",
    )
    assert not walk.complete
    assert "could not say" in walk.reason


async def test_omitting_the_tip_proof_is_not_a_shortcut() -> None:
    """No proof available must not read as proof of nothing missing."""
    raw = _raw(_FOUR)
    walk = await walk_mutable_chain(mint_txid=MINT_4, candidates=list(raw), fetch_tx=_fetcher(raw))
    assert not walk.complete
    assert "no tip proof" in walk.reason


async def test_a_non_mint_txid_degrades_rather_than_raising() -> None:
    """Absence degrades. Handing this a transaction with no mutable output is a caller error,
    not a chain contradiction."""
    raw = _raw(_FOUR)
    walk = await walk_mutable_chain(
        mint_txid=SIBLING,
        candidates=list(raw),
        fetch_tx=_fetcher(raw),
        is_unspent=_unspent_always,
        candidate_source="index",
        tip_source="node",
    )
    assert not walk.complete
    assert "no mutable output" in walk.reason or "not a full payload" in walk.reason
    assert walk.steps == ()


async def test_the_step_cap_is_reported_not_silently_applied() -> None:
    """A padded candidate set must not make this run forever, and hitting the bound must be
    visible — a silent truncation is the failure this module exists to prevent."""
    raw = _raw(_FOUR)
    walk = await walk_mutable_chain(
        mint_txid=MINT_4,
        candidates=list(raw),
        fetch_tx=_fetcher(raw),
        is_unspent=_unspent_always,
        candidate_source="index",
        tip_source="node",
        max_steps=2,
    )
    assert not walk.complete
    assert "cap" in walk.reason
    assert len(walk.steps) == 2
    assert MAX_CHAIN_STEPS >= 2


# ---------------------------------------------------------------------------
# 3. Contradiction raises where absence degrades
# ---------------------------------------------------------------------------


async def test_a_step_carrying_a_DIFFERENT_ref_raises() -> None:
    """A transaction that spends this token's mutable output but whose own mutable output names
    another ref is not a continuation of this token. Following it would silently splice two
    histories together, so it is a contradiction and raises — the split `dmint/chain.py`'s S2
    verifier already draws between "no result" and "the data disagrees with itself".

    Built by taking the REAL spending transaction and swapping its mutable output's script for
    the REAL mutable output of a DIFFERENT name. Its inputs are untouched, so it still genuinely
    spends the previous step — which is what makes it reach the ref check at all. Serving some
    other transaction instead would simply never be selected as the spender, and the test would
    pass without ever exercising the check.
    """
    raw = _raw(_FOUR)
    other = _raw(_THREE)

    foreign = Transaction.from_hex(other[MINT_3])
    foreign_mut = next(o.locking_script for o in foreign.outputs if len(bytes(o.locking_script.serialize())) == 174)

    spliced = Transaction.from_hex(raw[UPDATE_A])
    swapped = False
    for out in spliced.outputs:
        if len(bytes(out.locking_script.serialize())) == 174:
            out.locking_script = foreign_mut
            swapped = True
    assert swapped, "no 174-byte MUT output found to swap — the fixture shape changed"

    async def fetch(txid: str):
        if txid == UPDATE_A:
            return spliced
        return Transaction.from_hex(raw[txid])

    with pytest.raises(ValidationError, match="different token"):
        await walk_mutable_chain(mint_txid=MINT_4, candidates=list(raw), fetch_tx=fetch, is_unspent=_unspent_always)


# ---------------------------------------------------------------------------
# 4. It is reachable the way a consumer reaches it
# ---------------------------------------------------------------------------


async def test_it_works_through_the_public_facade() -> None:
    """The repo's reachability guard caught this walker with no shipped caller, and it was
    right: a capability only tests invoke is not finished.

    Its in-repo caller arrives with form 2 (#598 Phase 4). Until then it is consumer surface —
    an indexer or wallet integrating a mutable glyph needs "what did this token say, and am I
    looking at its current state" — so it is exported deliberately, and this test reaches it the
    way a consumer would rather than by importing the module directly.
    """
    import pyrxd.glyph as facade

    raw = _raw(_FOUR)
    walk = await facade.walk_mutable_chain(
        mint_txid=MINT_4,
        candidates=list(raw),
        fetch_tx=_fetcher(raw),
        is_unspent=_unspent_always,
        candidate_source="index",
        tip_source="node",
    )
    assert isinstance(walk, facade.MutableChainWalk)
    assert walk.complete
    assert walk.steps[-1].attrs["target"] == MOVED
    assert isinstance(walk.steps[0], facade.ChainStep)
