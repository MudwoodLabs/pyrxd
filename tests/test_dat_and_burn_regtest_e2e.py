"""Live-regtest CONSENSUS proof for DAT commits and BURN proofs.

DAT is a new script shape, and a script shape is a claim about how an
interpreter will behave. The DAT commit drops the ``OP_REFTYPE_OUTPUT`` block
and adds a ``"dat"`` marker push, which means the reveal's scriptSig must push
its markers in the order the commit pops them. Get that wrong and the spend
fails — so it is proven here rather than asserted from the byte layout.

BURN needs a node for a different reason: the interesting claim is not that an
``OP_RETURN`` is relayed (it obviously is) but that Radiant really does let a
token disappear. The FT epilogue is ``>=`` rather than ``==`` and an NFT
singleton simply need not be re-created — both are read off the source, and both
are load-bearing for the burn proof meaning anything at all.

Opt-in: ``@pytest.mark.integration`` + ``RADIANT_REGTEST=1``. Throwaway
container, no real value, no PoW.

Run: ``RADIANT_REGTEST=1 pytest tests/test_dat_and_burn_regtest_e2e.py -m integration -s``
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
from pyrxd.glyph.burn import BurnBasis, build_burn_proof_script, parse_burn_proof, verify_burn
from pyrxd.glyph.inspector import GlyphInspector
from pyrxd.glyph.payload import build_reveal_scriptsig_suffix
from pyrxd.glyph.script import is_nft_script, iter_input_refs, parse_dat_commit_script
from pyrxd.glyph.types import GlyphMetadata, GlyphProtocol
from pyrxd.keys import PrivateKey
from pyrxd.script.script import Script
from pyrxd.script.type import P2PKH
from pyrxd.security.types import Hex20
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_input import TransactionInput
from pyrxd.transaction.transaction_output import TransactionOutput

pytestmark = pytest.mark.integration

INSPECTOR = GlyphInspector()


def _verdict(rt: _RegtestNode, tx: Transaction) -> dict:
    tx.sign()
    return rt.accepts(_assert_fee_covers(tx, _FEE))


def _send(rt: _RegtestNode, tx: Transaction, *, what: str) -> str:
    res = _verdict(rt, tx)
    assert res.get("allowed") is True, f"{what} REJECTED: {res}"
    txid = str(rt.cli("sendrawtransaction", tx.serialize().hex()))
    rt.mine(1)
    return txid


def _dat_reveal(node, *, use_ordinary_suffix: bool):  # noqa: F811
    """Commit + build a DAT reveal. *use_ordinary_suffix* omits the "dat" push."""
    owner = PrivateKey()
    owner_pkh = Hex20(owner.public_key().hash160())
    builder = GlyphBuilder()
    metadata = GlyphMetadata(
        protocol=[GlyphProtocol.DAT],
        name="REGTEST-DATA",
        description="stored, not minted",
    )
    commit = builder.prepare_dat_commit(
        CommitParams(metadata=metadata, owner_pkh=owner_pkh, change_pkh=owner_pkh, funding_satoshis=_COMMIT_VALUE)
    )
    commit_txid = _pay_to_spk(node, commit.commit_script, _COMMIT_VALUE)
    node.mine(1)

    suffix = (
        build_reveal_scriptsig_suffix(commit.cbor_bytes)
        if use_ordinary_suffix
        else builder.prepare_dat_reveal(commit.cbor_bytes).scriptsig_suffix
    )
    reveal = Transaction(
        tx_inputs=[
            TransactionInput(
                source_transaction=_src(commit_txid, 0, commit.commit_script, _COMMIT_VALUE),
                source_txid=commit_txid,
                source_output_index=0,
                unlocking_script_template=_reveal_unlock(owner, suffix),
            )
        ],
        # A DAT reveal mints nothing: the only output is ordinary change.
        tx_outputs=[TransactionOutput(P2PKH().lock(owner.public_key().hash160()), _COMMIT_VALUE - _FEE)],
    )
    return {"tx": reveal, "commit_txid": commit_txid, "commit_script": commit.commit_script}


# --------------------------------------------------------------------------- DAT


@pytest.fixture(scope="module")
def dat(node):  # noqa: F811
    built = _dat_reveal(node, use_ordinary_suffix=False)
    built["reveal_txid"] = _send(node, built["tx"], what="DAT reveal")
    return built


def test_a_dat_commit_is_spendable_and_mints_nothing(node, dat):  # noqa: F811
    """The whole shape, end to end: the script evaluates and no token appears."""
    confirmed = _confirmed(node, dat["reveal_txid"])
    assert len(confirmed["vout"]) == 1
    spk = _out_spk(confirmed, 0)
    assert not is_nft_script(spk.hex())
    # And nothing anywhere in the outputs carries a ref — nothing was minted.
    assert list(iter_input_refs(spk)) == []


def test_the_commit_output_classifies_as_a_dat_commit(node, dat):  # noqa: F811
    parsed = parse_dat_commit_script(dat["commit_script"])
    assert parsed is not None
    payload_hash, _pkh = parsed
    confirmed = _confirmed(node, dat["commit_txid"])
    assert _out_spk(confirmed, 0) == dat["commit_script"]
    assert len(payload_hash) == 32


def test_the_payload_is_recoverable_from_the_confirmed_reveal(node, dat):  # noqa: F811
    """DAT stores data; if it cannot be read back the shape is pointless."""
    raw = bytes.fromhex(str(node.cli("getrawtransaction", dat["reveal_txid"])))
    tx = Transaction.from_hex(raw)
    assert tx is not None
    scriptsigs = [i.unlocking_script.serialize() if i.unlocking_script else b"" for i in tx.inputs]
    found = INSPECTOR.find_reveal_metadata(scriptsigs)
    assert found is not None, "no Glyph envelope recoverable from the DAT reveal"
    assert found[1].name == "REGTEST-DATA"


def test_the_ordinary_reveal_suffix_does_NOT_satisfy_a_dat_commit(node):  # noqa: F811
    """NON-VACUITY for the extra push: the marker order is load-bearing.

    `build_reveal_scriptsig_suffix` pushes only "gly". A DAT commit pops "dat"
    first, so the OP_EQUALVERIFY compares the marker against whatever the P2PKH
    pushed. If this were accepted, `build_dat_reveal_scriptsig_suffix` would be
    unnecessary and the two builders indistinguishable in practice.
    """
    attempt = _dat_reveal(node, use_ordinary_suffix=True)
    res = _verdict(node, attempt["tx"])
    assert res.get("allowed") is not True, f"a DAT commit accepted the ordinary reveal suffix: {res}"
    assert "mandatory-script-verify-flag-failed" in str(res.get("reject-reason", "")), res


# --------------------------------------------------------------------------- BURN


def test_a_token_really_can_be_burned_and_the_proof_reads_back(node):  # noqa: F811
    """Radiant permits destroying a singleton; the proof records that it was meant.

    Both halves matter. If the chain refused to let the NFT vanish, a burn proof
    would be describing something that cannot happen; if it let it vanish but
    the proof were unreadable, nothing would distinguish a burn from a loss.
    """
    token = _mint_nft(
        node,
        GlyphMetadata(protocol=[GlyphProtocol.NFT], name="REGTEST-DOOMED", token_type="burnable"),
    )
    proof_script = build_burn_proof_script(token["ref"], burn_reason="regtest burn")
    owner = token["key"]

    burn_tx = Transaction(
        tx_inputs=[
            TransactionInput(
                source_transaction=_src(token["reveal_txid"], token["vout"], token["script"], token["value"]),
                source_txid=token["reveal_txid"],
                source_output_index=token["vout"],
                unlocking_script_template=_p2pkh_unlock(owner),
            )
        ],
        tx_outputs=[
            TransactionOutput(Script(proof_script), 0),
            TransactionOutput(P2PKH().lock(owner.public_key().hash160()), token["value"] - _FEE),
        ],
    )
    burn_txid = _send(node, burn_tx, what="burn")

    confirmed = _confirmed(node, burn_txid)
    outputs = [_out_spk(confirmed, i) for i in range(len(confirmed["vout"]))]

    # The proof survives the round trip through the chain.
    proof = next((p for p in (parse_burn_proof(s) for s in outputs) if p is not None), None)
    assert proof is not None and proof.token_ref == f"{token['ref'].txid}:{token['ref'].vout}"
    assert proof.reason == "regtest burn"

    # The token is gone: no output carries its ref.
    assert not any(any(op == token["ref"].to_bytes() for _o, op in iter_input_refs(s)) for s in outputs)

    # Without the spent outputs, the honest verdict is the weaker one...
    weak = verify_burn(outputs, token["ref"])
    assert weak.valid and weak.basis is BurnBasis.ABSENT_ONLY
    # ...and with them, the strong one.
    strong = verify_burn(outputs, token["ref"], spent_output_scripts=[token["script"]])
    assert strong.valid and strong.basis is BurnBasis.SPENT_AND_ABSENT


def test_a_burn_proof_about_a_token_this_tx_never_held_is_reported_as_such(node):  # noqa: F811
    """Consensus relays it happily. The proof is a claim, and the verdict says so.

    This is the divergence from Photonic's `validateBurn`, which checks only
    that the ref is absent from the outputs — a condition every unrelated
    transaction satisfies.
    """
    victim = _mint_nft(node, GlyphMetadata(protocol=[GlyphProtocol.NFT], name="REGTEST-NOT-YOURS"))
    liar = PrivateKey()
    forged = build_burn_proof_script(victim["ref"], burn_reason="I burned it (I did not)")

    funding_txid = _pay_to_spk(node, P2PKH().lock(liar.public_key().hash160()).serialize(), _COMMIT_VALUE)
    node.mine(1)
    tx = Transaction(
        tx_inputs=[
            TransactionInput(
                source_transaction=_src(
                    funding_txid, 0, bytes(P2PKH().lock(liar.public_key().hash160()).serialize()), _COMMIT_VALUE
                ),
                source_txid=funding_txid,
                source_output_index=0,
                unlocking_script_template=_p2pkh_unlock(liar),
            )
        ],
        tx_outputs=[
            TransactionOutput(Script(forged), 0),
            TransactionOutput(P2PKH().lock(liar.public_key().hash160()), _COMMIT_VALUE - _FEE),
        ],
    )
    forged_txid = _send(node, tx, what="forged burn proof")
    confirmed = _confirmed(node, forged_txid)
    outputs = [_out_spk(confirmed, i) for i in range(len(confirmed["vout"]))]

    # The chain accepted it — an OP_RETURN needs no permission.
    # Shown the spent outputs, the verdict refuses it.
    spent = [bytes(P2PKH().lock(liar.public_key().hash160()).serialize())]
    verdict = verify_burn(outputs, victim["ref"], spent_output_scripts=spent)
    assert not verdict.valid
    assert "spent nothing carrying the token ref" in verdict.reason

    # And the victim's token is still alive on chain.
    live = node.cli("gettxout", victim["reveal_txid"], str(victim["vout"]))
    assert live, "the victim's token should be untouched by someone else's OP_RETURN"
