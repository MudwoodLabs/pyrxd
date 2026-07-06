"""FT-demand v3 covenant fill on a REAL radiant-core regtest node.

The maker reserves RXD into the refund covenant and demands a Glyph FT; the
taker funds with real FT UTXOs (ref-induction mint) and fills the SWAP branch.
Consensus proves the per-ref conservation the offline suite asserts: the maker
holds the demanded FT amount, the taker holds the FT change AND the reserved
RXD, all in one atomic completion.

Gating: ``@pytest.mark.integration`` + ``RSWP_REGTEST=1`` (reuses the v2 e2e
node harness). Isolated container, no real value.

Run it:  RSWP_REGTEST=1 pytest tests/test_rswp_v3_ft_demand_regtest_e2e.py -m integration -s
"""

from __future__ import annotations

import pytest

from pyrxd.glyph.script import is_ft_script
from pyrxd.keys import PrivateKey
from pyrxd.swap import Asset, FundingInput
from pyrxd.swap.rswp import create_covenant_order, decode_rswp_order, prepare_covenant_offer, take_covenant_order
from tests.test_rswp_regtest_e2e import _FEE, _fund_key, _mint_ft, _Node
from tests.test_rswp_regtest_e2e import node as node

pytestmark = pytest.mark.integration


def _tip(node: _Node) -> int:
    return int(node.cli("getblockcount"))


async def test_v3_ft_demand_fill_conserves_on_chain(node) -> None:
    maker, taker = PrivateKey(), PrivateKey()
    mk_pkh, tk_pkh = maker.public_key().hash160(), taker.public_key().hash160()

    # Maker reserves 10M photons, demanding 60k units of the taker's FT.
    taker_ft_tx, ref = _mint_ft(node, taker, units=100_000)
    fund_tx, fund_vout = _fund_key(node, maker, 20_000_000)
    reservation = prepare_covenant_offer(
        funding=[FundingInput(fund_tx, fund_vout, maker)],
        photons=10_000_000,
        owner_pkh=mk_pkh,
        expiry_height=_tip(node) + 60,
        change_pkh=mk_pkh,
        fee=_FEE,
    )
    node.send_and_mine(reservation)
    post = create_covenant_order(
        covenant_source_tx=reservation,
        covenant_vout=0,
        maker_key=maker,
        receive=Asset("ft", 60_000, ref),
        maker_receive_pkh=mk_pkh,
    )
    order = decode_rswp_order(post.advert_script)
    assert order.version == 3 and order.want_token_id is not None

    fee_fund, ff_vout = _fund_key(node, taker, 20_000_000)
    completion = take_covenant_order(
        order,
        give_source_tx=reservation,
        funding=[FundingInput(taker_ft_tx, 0, taker), FundingInput(fee_fund, ff_vout, taker)],
        taker_receive_pkh=tk_pkh,
        taker_change_pkh=tk_pkh,
        fee=_FEE,
        current_height=_tip(node),
    )
    verdict = node.accepts(completion.serialize().hex())
    assert verdict.get("allowed") is True, verdict
    txid = node.send_and_mine(completion)

    # On-chain conservation: output 0 = maker's 60k FT; output 1 = taker's 10M RXD;
    # an FT change output carries the remaining 40k back to the taker.
    out0 = node.cli("gettxout", txid, "0", "true")
    assert isinstance(out0, dict) and round(out0["value"] * 1e8) == 60_000
    assert is_ft_script(out0["scriptPubKey"]["hex"])
    out1 = node.cli("gettxout", txid, "1", "true")
    assert isinstance(out1, dict) and round(out1["value"] * 1e8) == 10_000_000
    change_vals = []
    for i in range(2, len(completion.outputs)):
        got = node.cli("gettxout", txid, str(i), "true")
        if isinstance(got, dict) and is_ft_script(got["scriptPubKey"]["hex"]):
            change_vals.append(round(got["value"] * 1e8))
    assert change_vals == [40_000]  # exact per-ref conservation, proven by consensus
