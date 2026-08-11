"""RSWP v3 refund covenant on a REAL radiant-core regtest node — the consensus proof.

Mirrors (with pyrxd's own builders) what Photonic proved wallet-side on
2026-06-09, plus the pyrxd-specific paths:

* RESERVE + FILL: RXD reserved into the covenant; the taker fills the SWAP
  branch (``OP_1``) via ``take_covenant_order`` BEFORE expiry → accepted+mined.
* INDEX REALITY (design D1): the v3 advert is broadcast fine as a tx, but the
  deployed swapindex DROPS it — ``getopenorders`` must NOT list it. v3 posting
  is for ecosystem-rollout testing, not the live book.
* REFUND-TOO-EARLY: the REFUND branch before expiry is REJECTED (CLTV/finality).
* REFUND-AT-EXPIRY: at/after expiry the refund is ACCEPTED and the maker
  reclaims the reserved RXD.
* CANCEL-BEFORE-EXPIRY: the maker self-spends the SWAP branch at any height.
* SELECTOR MALLEABILITY (security F3, demonstrated ON PURPOSE): a refund tx
  with its selector flipped to ``OP_1`` is a DIFFERENT txid the node also
  accepts — proving why refunds must be tracked by outpoint, never txid.

Gating: ``@pytest.mark.integration`` + ``RSWP_REGTEST=1`` (same as the v2 e2e,
whose node harness this file reuses). Isolated container, no real value.

Run it:  RSWP_REGTEST=1 pytest tests/test_rswp_v3_regtest_e2e.py -m integration -s
"""

from __future__ import annotations

import pytest

from pyrxd.keys import PrivateKey
from pyrxd.script.script import Script
from pyrxd.swap import Asset, FundingInput
from pyrxd.swap.rswp import (
    build_advert_tx,
    build_covenant_cancel_tx,
    build_covenant_refund_tx,
    create_covenant_order,
    decode_rswp_order,
    prepare_covenant_offer,
    swap_token_id,
    take_covenant_order,
)
from pyrxd.transaction.transaction import Transaction
from tests.test_rswp_regtest_e2e import _FEE, _NODE_POLICY, _fund_key, _Node
from tests.test_rswp_regtest_e2e import node as node

pytestmark = pytest.mark.integration


def _tip(node: _Node) -> int:
    return int(node.cli("getblockcount"))


def _reserve_and_post(
    node: _Node, maker: PrivateKey, *, photons: int, demand: int, expiry: int
) -> tuple[Transaction, object]:
    """Reserve RXD into the covenant, broadcast the v3 advert, return (reservation tx, decoded order)."""
    mk_pkh = maker.public_key().hash160()
    fund_tx, fund_vout = _fund_key(node, maker, photons + 10_000_000)
    reserved = prepare_covenant_offer(
        funding=[FundingInput(fund_tx, fund_vout, maker)],
        photons=photons,
        owner_pkh=mk_pkh,
        expiry_height=expiry,
        change_pkh=mk_pkh,
        fee=_FEE,
        fee_policy=_NODE_POLICY,
    )
    node.send_and_mine(reserved)

    post = create_covenant_order(
        covenant_source_tx=reserved,
        covenant_vout=0,
        maker_key=maker,
        receive=Asset("rxd", demand),
        maker_receive_pkh=mk_pkh,
    )
    advert_fund, af_vout = _fund_key(node, maker, 20_000_000)
    node.send_and_mine(
        build_advert_tx(
            advert_script=post.advert_script,
            funding=[FundingInput(advert_fund, af_vout, maker)],
            change_pkh=mk_pkh,
            fee=_FEE,
        )
    )
    return reserved, decode_rswp_order(post.advert_script)


async def test_v3_fill_before_expiry_and_index_drops_the_advert(node) -> None:
    maker, taker = PrivateKey(), PrivateKey()
    tk_pkh = taker.public_key().hash160()
    expiry = _tip(node) + 50
    reserved, order = _reserve_and_post(node, maker, photons=10_000_000, demand=9_000_000, expiry=expiry)
    assert order.version == 3 and order.expiry_height == expiry

    # Design D1 reality check: the deployed swapindex parses v2 only — the v3
    # advert tx mined fine but the order must NOT appear in the book.
    assert node.cli("getopenorders", swap_token_id(None).hex()) == []

    fund_tx, fund_vout = _fund_key(node, taker, 20_000_000)
    completion = take_covenant_order(
        order,
        give_source_tx=reserved,
        funding=[FundingInput(fund_tx, fund_vout, taker)],
        taker_receive_pkh=tk_pkh,
        taker_change_pkh=tk_pkh,
        fee=_FEE,
        fee_policy=_NODE_POLICY,
        current_height=_tip(node),
    )
    verdict = node.accepts(completion.serialize().hex())
    assert verdict.get("allowed") is True, verdict
    txid = node.send_and_mine(completion)
    got = node.cli("gettxout", txid, "1", "true")  # taker's received RXD
    assert isinstance(got, dict) and round(got["value"] * 1e8) == 10_000_000


async def test_v3_refund_rejected_early_accepted_at_expiry(node) -> None:
    maker = PrivateKey()
    mk_pkh = maker.public_key().hash160()
    expiry = _tip(node) + 8
    reserved, _order = _reserve_and_post(node, maker, photons=8_000_000, demand=7_000_000, expiry=expiry)

    refund = build_covenant_refund_tx(
        covenant_source_tx=reserved,
        covenant_vout=0,
        maker_key=maker,
        refund_pkh=mk_pkh,
        fee=_FEE,
        fee_policy=_NODE_POLICY,
    )
    early = node.accepts(refund.serialize().hex())
    assert early.get("allowed") is False
    assert "final" in str(early).lower(), early  # bad-txns-nonfinal / non-final

    while _tip(node) < expiry:
        node.mine(1)
    late = node.accepts(refund.serialize().hex())
    assert late.get("allowed") is True, late
    txid = node.send_and_mine(refund)
    got = node.cli("gettxout", txid, "0", "true")
    assert isinstance(got, dict) and round(got["value"] * 1e8) == 8_000_000 - _FEE


async def test_v3_cancel_before_expiry_via_swap_branch(node) -> None:
    maker = PrivateKey()
    mk_pkh = maker.public_key().hash160()
    expiry = _tip(node) + 100  # nowhere near expiry
    reserved, _order = _reserve_and_post(node, maker, photons=6_000_000, demand=5_000_000, expiry=expiry)

    cancel = build_covenant_cancel_tx(
        covenant_source_tx=reserved,
        covenant_vout=0,
        maker_key=maker,
        refund_pkh=mk_pkh,
        fee=_FEE,
        fee_policy=_NODE_POLICY,
    )
    verdict = node.accepts(cancel.serialize().hex())
    assert verdict.get("allowed") is True, verdict
    node.send_and_mine(cancel)


async def test_v3_refund_txid_is_selector_malleable_by_design(node) -> None:
    """F3 demonstrated: flipping the unsigned selector to OP_1 yields a DIFFERENT
    txid the node ALSO accepts (same preimage validates through the SWAP branch,
    CLTV simply skipped). Operator lesson: track the covenant OUTPOINT."""
    maker = PrivateKey()
    mk_pkh = maker.public_key().hash160()
    expiry = _tip(node) + 4
    reserved, _order = _reserve_and_post(node, maker, photons=5_000_000, demand=4_000_000, expiry=expiry)
    while _tip(node) < expiry:
        node.mine(1)

    refund = build_covenant_refund_tx(
        covenant_source_tx=reserved,
        covenant_vout=0,
        maker_key=maker,
        refund_pkh=mk_pkh,
        fee=_FEE,
        fee_policy=_NODE_POLICY,
    )
    assert node.accepts(refund.serialize().hex()).get("allowed") is True

    malleated = Transaction.from_hex(refund.serialize())
    malleated.inputs[0].unlocking_script = Script(refund.inputs[0].unlocking_script.serialize()[:-1] + b"\x51")
    malleated.inputs[0].source_transaction = reserved  # repopulate prevout context lost by reserialize
    assert malleated.txid() != refund.txid()
    verdict = node.accepts(malleated.serialize().hex())
    assert verdict.get("allowed") is True, verdict  # same effect, different txid — F3 is real
