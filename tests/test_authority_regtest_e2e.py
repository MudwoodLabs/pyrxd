"""Live-regtest CONSENSUS proof for AUTHORITY-gated NFTs.

``build_authority_gated_nft_script`` puts ``OP_REQUIREINPUTREF <authority_ref>``
in an item's locking script. Photonic describes that as a **mint-time** gate: an
output carrying it can only be created by a transaction holding the issuer's
authority token. That much follows from the subset rule.

What does NOT follow, and what this file is for: Radiant's input ref set is not
just the outpoints a transaction spends — it also includes refs carried by the
spent inputs' own scripts. A gated output CARRIES the authority ref. So spending
one may put the authority ref straight back into the input ref set, and if it
does, the gate binds only the first item ever minted:

* a holder could mint FURTHER gated items with no authority token (forgery), and
* a holder could strip the gate entirely by transferring to a plain NFT script.

Either would make "authority-gated" a much weaker claim than the name suggests,
and no amount of reading the opcode table settles it. Only a node does.

Opt-in: ``@pytest.mark.integration`` + ``RADIANT_REGTEST=1``. Throwaway container,
no real value, no PoW.

Run: ``RADIANT_REGTEST=1 pytest tests/test_authority_regtest_e2e.py -m integration -s``
"""

from __future__ import annotations

import pytest
from test_container_regtest_e2e import (
    _COMMIT_VALUE,
    _FEE,
    _assert_fee_covers,
    _confirmed,
    _mint_nft,
    _out_spk,
    _reveal_unlock,
)
from test_htlc_regtest_e2e import (  # noqa: F401
    _p2pkh_unlock,
    _pay_to_spk,
    _RegtestNode,
    _src,
    node,
)

from pyrxd.glyph.builder import CommitParams, GlyphBuilder
from pyrxd.glyph.script import (
    build_authority_gated_nft_script,
    build_nft_locking_script,
    is_authority_gated_script,
    is_nft_script,
    parse_authority_gated_script,
)
from pyrxd.glyph.types import GlyphMetadata, GlyphProtocol, GlyphRef
from pyrxd.keys import PrivateKey
from pyrxd.script.script import Script
from pyrxd.script.type import P2PKH
from pyrxd.security.types import Hex20
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_input import TransactionInput
from pyrxd.transaction.transaction_output import TransactionOutput

pytestmark = pytest.mark.integration

_CARRIER = 60_000_000  # must exceed _FEE: the transfer cases spend this output alone


def _nft_input(token: dict) -> TransactionInput:
    return TransactionInput(
        source_transaction=_src(token["reveal_txid"], token["vout"], token["script"], token["value"]),
        source_txid=token["reveal_txid"],
        source_output_index=token["vout"],
        unlocking_script_template=_p2pkh_unlock(token["key"]),
    )


def _verdict(rt: _RegtestNode, tx: Transaction) -> dict:
    """Ask the node whether it would accept *tx*. Never broadcasts."""
    tx.sign()
    return rt.accepts(_assert_fee_covers(tx, _FEE))


def _send(rt: _RegtestNode, tx: Transaction, *, what: str) -> str:
    res = _verdict(rt, tx)
    assert res.get("allowed") is True, f"{what} REJECTED: {res}"
    txid = str(rt.cli("sendrawtransaction", tx.serialize().hex()))
    rt.mine(1)
    return txid


@pytest.fixture(scope="module")
def authority(node):  # noqa: F811
    """The issuer's authority token — an ordinary NFT with the AUTHORITY marker."""
    return _mint_nft(
        node,
        GlyphMetadata(
            protocol=[GlyphProtocol.NFT, GlyphProtocol.AUTHORITY],
            name="REGTEST-ISSUER-AUTHORITY",
            token_type="authority",
            attrs={"issuer": "regtest", "permissions": ["mint"], "revocable": True},
        ),
    )


def _gated_mint(node, authority, *, hold_authority: bool, gate_source: dict | None = None):  # noqa: F811
    """Commit + reveal one authority-gated item.

    *hold_authority* spends the real authority token in the reveal. *gate_source*
    instead spends an existing GATED item — the forgery case: its script already
    carries the authority ref, so if that counts as an input ref the mint
    succeeds without the issuer.
    """
    owner = PrivateKey()
    owner_pkh = Hex20(owner.public_key().hash160())
    builder = GlyphBuilder()
    commit = builder.prepare_commit(
        CommitParams(
            metadata=GlyphMetadata(protocol=[GlyphProtocol.NFT], name="GATED-ITEM"),
            owner_pkh=owner_pkh,
            change_pkh=owner_pkh,
            funding_satoshis=_COMMIT_VALUE,
        )
    )
    commit_txid = _pay_to_spk(node, commit.commit_script, _COMMIT_VALUE)
    node.mine(1)

    item_ref = GlyphRef(txid=commit_txid, vout=0)
    gated = build_authority_gated_nft_script(owner_pkh, item_ref, authority["ref"])

    from pyrxd.glyph.builder import RevealParams

    scripts = builder.prepare_reveal(
        RevealParams(
            commit_txid=commit_txid,
            commit_vout=0,
            commit_value=_COMMIT_VALUE,
            cbor_bytes=commit.cbor_bytes,
            owner_pkh=owner_pkh,
            is_nft=True,
        )
    )
    inputs = [
        TransactionInput(
            source_transaction=_src(commit_txid, 0, commit.commit_script, _COMMIT_VALUE),
            source_txid=commit_txid,
            source_output_index=0,
            unlocking_script_template=_reveal_unlock(owner, scripts.scriptsig_suffix),
        )
    ]
    outs = [TransactionOutput(Script(gated), _CARRIER)]
    if hold_authority:
        inputs.append(_nft_input(authority))
        outs.append(TransactionOutput(Script(authority["script"]), authority["value"]))
    if gate_source is not None:
        inputs.append(_nft_input(gate_source))
        outs.append(TransactionOutput(Script(gate_source["script"]), gate_source["value"]))

    spent = _COMMIT_VALUE + sum(
        t["value"] for t in ([authority] if hold_authority else []) + ([gate_source] if gate_source else [])
    )
    paid = sum(o.satoshis for o in outs)
    outs.append(TransactionOutput(P2PKH().lock(owner.public_key().hash160()), spent - paid - _FEE))

    tx = Transaction(tx_inputs=inputs, tx_outputs=outs)
    return {
        "tx": tx,
        "ref": item_ref,
        "script": gated,
        "key": owner,
        "pkh": owner_pkh,
        "value": _CARRIER,
    }


# --------------------------------------------------------------------------- the gate


def test_minting_a_gated_item_without_the_authority_is_rejected(node, authority):  # noqa: F811
    """The property the whole mechanism rests on."""
    attempt = _gated_mint(node, authority, hold_authority=False)
    res = _verdict(node, attempt["tx"])
    assert res.get("allowed") is not True, f"a gated item was minted WITHOUT the authority token: {res}"
    assert "invalid-transaction-reference-operations" in str(res.get("reject-reason", "")), res


@pytest.fixture(scope="module")
def gated_item(node, authority):  # noqa: F811
    """Step: mint one gated item, holding the authority."""
    built = _gated_mint(node, authority, hold_authority=True)
    txid = _send(node, built["tx"], what="gated mint with authority")
    # The authority moved to vout 1 of this transaction.
    authority.update({"reveal_txid": txid, "vout": 1})
    built.update({"reveal_txid": txid, "vout": 0})
    return built


def test_minting_with_the_authority_is_accepted(node, authority, gated_item):  # noqa: F811
    confirmed = _confirmed(node, gated_item["reveal_txid"])
    spk = _out_spk(confirmed, 0)
    assert is_authority_gated_script(spk.hex()) and len(spk) == 101
    parsed = parse_authority_gated_script(spk)
    assert parsed is not None
    auth_ref, item_ref, pkh = parsed
    assert auth_ref == authority["ref"] and item_ref == gated_item["ref"] and pkh == gated_item["pkh"]
    # The authority token itself survived, unchanged.
    assert _out_spk(confirmed, 1) == authority["script"]


# --------------------------------------------------------------------------- what the gate does NOT bind


def test_a_gated_item_cannot_be_transferred_while_KEEPING_the_gate(node, gated_item):  # noqa: F811
    """MEASURED: rejected. So the gate is not "mint-time" — it binds every move.

    Photonic's comment calls this a "creation-time (mint-time) rule". It is that,
    but it is also more: re-creating the gated script in ANY later transaction
    needs the authority ref among that transaction's inputs, and spending a gated
    output does NOT supply it. So a holder cannot move a gated item to a new
    owner, keeping the gate, without the issuer signing alongside them.
    """
    new_owner = PrivateKey()
    auth_ref = parse_authority_gated_script(gated_item["script"])[0]
    new_script = build_authority_gated_nft_script(Hex20(new_owner.public_key().hash160()), gated_item["ref"], auth_ref)
    tx = Transaction(
        tx_inputs=[_nft_input(gated_item)],
        tx_outputs=[TransactionOutput(Script(new_script), gated_item["value"] - _FEE)],
    )
    res = _verdict(node, tx)
    assert res.get("allowed") is not True, f"a gated item moved with its gate intact and no authority: {res}"
    assert "invalid-transaction-reference-operations" in str(res.get("reject-reason", "")), res


def test_the_holder_CAN_strip_the_gate_by_transferring_to_a_plain_nft(node, gated_item):  # noqa: F811
    """MEASURED: accepted. "Gated" is therefore NOT a durable property.

    The item's own singleton ref survives in the plain script, so the subset rule
    is satisfied by spending the gated output alone. The holder needs nobody's
    permission, and the resulting token has the same ref and no gate.

    Consequence, and the reason this is asserted rather than noted: a check of
    the form "is this token authority-gated?" applied to a token's CURRENT output
    can be defeated by its holder in one transaction. Authority gating is a
    statement about an item's GENESIS, and only reading the genesis transaction
    establishes it.
    """
    new_owner = PrivateKey()
    plain = build_nft_locking_script(Hex20(new_owner.public_key().hash160()), gated_item["ref"])
    tx = Transaction(
        tx_inputs=[_nft_input(gated_item)],
        tx_outputs=[TransactionOutput(Script(plain), gated_item["value"] - _FEE)],
    )
    res = _verdict(node, tx)
    assert res.get("allowed") is True, f"expected the gate to be strippable; node refused: {res}"
    assert is_nft_script(plain.hex()) and not is_authority_gated_script(plain.hex())


def test_a_gated_item_cannot_mint_another_gated_item(node, authority, gated_item):  # noqa: F811
    """MEASURED: rejected. The gate IS a supply cap.

    This was the one that could have gone either way. A gated output's script
    names the authority ref, so if that counted as an input ref when spent, any
    holder of one item could mint unlimited further gated items and the issuer's
    control would end at the first mint. Consensus does not count it.
    """
    attempt = _gated_mint(node, authority, hold_authority=False, gate_source=gated_item)
    res = _verdict(node, attempt["tx"])
    assert res.get("allowed") is not True, f"a gated item was forged from another gated item: {res}"
    assert "invalid-transaction-reference-operations" in str(res.get("reject-reason", "")), res
