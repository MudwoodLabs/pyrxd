"""NFT singleton RSWP order on a REAL radiant-core regtest node — the consensus proof.

One end-to-end case: mint a consensus-valid NFT singleton (ref-induction — the
0xD8 OP_PUSHINPUTREFSINGLETON analogue of the FT trick; consensus enforces ref
uniqueness, not mint provenance), post an NFT→RXD v2 order, see it in the real
swapindex book, verify it fillable through the OrderbookClient, take it, and
confirm the TAKER owns the singleton afterwards with the carrier intact.

Gating: ``@pytest.mark.integration`` + ``RSWP_REGTEST=1`` (reuses the v2 e2e
node harness). Isolated container, no real value.

Run it:  RSWP_REGTEST=1 pytest tests/test_rswp_nft_regtest_e2e.py -m integration -s
"""

from __future__ import annotations

import pytest

from pyrxd.glyph.script import build_nft_locking_script, extract_owner_pkh_from_nft_script, is_nft_script
from pyrxd.glyph.types import GlyphRef
from pyrxd.keys import PrivateKey
from pyrxd.script.script import Script
from pyrxd.script.type import P2PKH
from pyrxd.security.types import Hex20, Txid
from pyrxd.swap import Asset, FundingInput
from pyrxd.swap.rswp import (
    OrderbookClient,
    build_advert_tx,
    create_rswp_order,
    decode_rswp_order,
    swap_token_id,
    take_rswp_order,
)
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_input import TransactionInput
from pyrxd.transaction.transaction_output import TransactionOutput
from tests.test_rswp_regtest_e2e import _FEE, _CliSource, _fund_key, _Node
from tests.test_rswp_regtest_e2e import node as node

pytestmark = pytest.mark.integration


def _mint_nft(node: _Node, owner: PrivateKey, carrier: int) -> tuple[Transaction, GlyphRef]:
    """Create a consensus-valid NFT singleton UTXO at vout 0 (ref = the spent outpoint)."""
    fund_tx, fund_vout = _fund_key(node, owner, carrier + 10_000_000)
    ref = GlyphRef(txid=Txid(fund_tx.txid()), vout=fund_vout)
    pkh = owner.public_key().hash160()
    tx = Transaction()
    tx.add_input(
        TransactionInput(
            source_transaction=fund_tx,
            source_output_index=fund_vout,
            unlocking_script_template=P2PKH().unlock(owner),
        )
    )
    tx.add_output(TransactionOutput(Script(build_nft_locking_script(Hex20(pkh), ref)), carrier))
    change = fund_tx.outputs[fund_vout].satoshis - carrier - _FEE
    tx.add_output(TransactionOutput(P2PKH().lock(pkh), change))
    tx.sign(bypass=True)
    node.send_and_mine(tx)
    return tx, ref


async def test_nft_order_post_browse_take_settle(node) -> None:
    maker, taker = PrivateKey(), PrivateKey()
    mk_pkh, tk_pkh = maker.public_key().hash160(), taker.public_key().hash160()

    nft_tx, ref = _mint_nft(node, maker, carrier=1_000_000)
    post = create_rswp_order(
        give_source_tx=nft_tx, give_vout=0, maker_key=maker, receive=Asset("rxd", 9_000_000), maker_receive_pkh=mk_pkh
    )
    order = decode_rswp_order(post.advert_script)
    assert order.offered_type == 1  # ContractType.NFT

    advert_fund, af_vout = _fund_key(node, maker, 20_000_000)
    node.send_and_mine(
        build_advert_tx(
            advert_script=post.advert_script,
            funding=[FundingInput(advert_fund, af_vout, maker)],
            change_pkh=mk_pkh,
            fee=_FEE,
        )
    )

    # The REAL swapindex lists the NFT order under sha256 of its ref (v2 frame).
    rows = node.cli("getopenorders", swap_token_id(ref).hex())
    assert isinstance(rows, list) and len(rows) == 1 and rows[0]["offered_type"] == 1

    entries = await OrderbookClient(_CliSource(node)).orders_offering(ref)
    assert len(entries) == 1 and entries[0].fillable, entries[0].problem

    fund_tx, fund_vout = _fund_key(node, taker, 20_000_000)
    completion = take_rswp_order(
        order,
        give_source_tx=nft_tx,
        funding=[FundingInput(fund_tx, fund_vout, taker)],
        taker_receive_pkh=tk_pkh,
        taker_change_pkh=tk_pkh,
        fee=_FEE,
    )
    verdict = node.accepts(completion.serialize().hex())
    assert verdict.get("allowed") is True, verdict
    txid = node.send_and_mine(completion)

    # Settlement: the taker holds the singleton at completion:1 with the carrier intact.
    got = node.cli("gettxout", txid, "1", "true")
    assert isinstance(got, dict) and round(got["value"] * 1e8) == 1_000_000
    spk = bytes.fromhex(got["scriptPubKey"]["hex"])
    assert is_nft_script(spk.hex()) and bytes(extract_owner_pkh_from_nft_script(spk)) == tk_pkh
    assert node.cli("getopenorders", swap_token_id(ref).hex()) == []  # book settled
