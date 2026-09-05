"""Live-regtest CONSENSUS proof for delegate refs.

``prepare_delegate_setup`` and the 56-byte commit prefix were derived from the
Radiant opcode table and from Photonic Wallet's usage — NOT from a spend. Three
claims in that derivation are consensus questions that only a node can settle,
and every one of them is load-bearing:

1. **``OP_REQUIREINPUTREF`` is what authorises a base.** A base output naming a
   ref the transaction did not spend must be REJECTED. If it is accepted, the
   whole scheme is decoration: anyone could name any collection.
2. **The commit covenant really counts the burn output.** A reveal that omits it
   must be REJECTED. If it is accepted, a mint can claim a delegated ``in``/``by``
   without consuming anything.
3. **``OP_REFOUTPUTCOUNT_OUTPUTS`` does not count the burn's own
   ``OP_REQUIREINPUTREF``.** The prefix asserts the base ref appears in ZERO
   outputs while simultaneously requiring a burn output that names it. If that
   opcode counted ``0xd1`` operands the covenant would be unsatisfiable and the
   honest path would be dead — a guard that refuses all valid work.

Question 3 is the one that cannot be answered by reading the opcode table, and
it is why this file exists rather than a note saying "matches Photonic".

Also proven here, because getting it wrong is unrecoverable: a base transaction
**re-creates the parent singletons**. ``OP_REQUIREINPUTREF`` requires a ref as an
input and does not carry it forward, so a base whose only output is the base
BURNS the container and author tokens, and a consumed singleton can never be
re-minted (spec §7.5.1).

Opt-in: ``@pytest.mark.integration`` + ``RADIANT_REGTEST=1``. Never runs in
normal CI. Manages its own throwaway container; moves no real value. No PoW.

Run: ``RADIANT_REGTEST=1 pytest tests/test_delegate_regtest_e2e.py -m integration -s``
"""

from __future__ import annotations

import pytest
from test_container_regtest_e2e import (  # noqa: F401  (reuse the container harness wholesale)
    _COMMIT_VALUE,
    _FEE,
    _assert_fee_covers,
    _confirmed,
    _mint_nft,
    _out_spk,
    _reveal_unlock,
)
from test_htlc_regtest_e2e import (  # noqa: F401  (node = fixture)
    _p2pkh_unlock,
    _RegtestNode,
    _src,
    node,
)

from pyrxd.glyph.builder import CommitParams, GlyphBuilder, RevealParams
from pyrxd.glyph.inspector import GlyphInspector
from pyrxd.glyph.relationships import (
    RelationshipBacking,
    RelationshipKind,
    RelationshipOutcome,
    delegate_burn_refs,
    resolve_delegated_refs,
    verify_relationship_claims,
)
from pyrxd.glyph.script import (
    build_delegate_base_script,
    build_delegate_token_script,
    is_commit_nft_script,
    is_delegate_token_script,
    is_nft_script,
    parse_delegate_base_script,
    parse_delegate_burn_script,
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

# Every transaction here funds itself from what it spends, so the values form a
# chain: parents -> base -> tokens -> commit -> reveal, each leaving enough for
# the next one's flat _FEE. Radiant has no dust rule, so the carriers are small.
_BASE_VALUE = 200_000_000  # 2 RXD on the base, funding the token transaction
_PARENT_CARRIER = 60_000_000  # 0.6 RXD back onto each parent — enough to pay a fee later
_TOKEN_VALUE = 42_000_000  # 0.42 RXD per delegate token, so each can fund a commit
_MINT_CARRIER = 500_000  # photons on a minted token / a forged output
# Four, because each case below consumes one: the honest mint, the two negative
# reveals (whose COMMITS are broadcast even though their reveals are refused),
# and the no-prefix control.
_TOKEN_COUNT = 4

INSPECTOR = GlyphInspector()


# --------------------------------------------------------------------------- helpers


def _nft_input(token: dict) -> TransactionInput:
    """Spend a minted NFT's current UTXO with a plain P2PKH unlock."""
    return TransactionInput(
        source_transaction=_src(token["reveal_txid"], token["vout"], token["script"], token["value"]),
        source_txid=token["reveal_txid"],
        source_output_index=token["vout"],
        unlocking_script_template=_p2pkh_unlock(token["key"]),
    )


def _send(rt: _RegtestNode, tx: Transaction, *, what: str) -> str:
    tx.sign()
    raw = _assert_fee_covers(tx, _FEE)
    res = rt.accepts(raw)
    assert res.get("allowed") is True, f"{what} REJECTED by consensus: {res}"
    txid = str(rt.cli("sendrawtransaction", raw))
    rt.mine(1)
    return txid


def _rejects(rt: _RegtestNode, tx: Transaction) -> dict:
    """Serialize and ask the node — expecting refusal. Never broadcast."""
    tx.sign()
    res = rt.accepts(tx.serialize().hex())
    assert res.get("allowed") is not True, f"expected consensus to REJECT this, it did not: {res}"
    return res


# --------------------------------------------------------------------------- fixtures


@pytest.fixture(scope="module")
def parents(node):  # noqa: F811
    """A container token and an author token — the two things a delegate speaks for."""
    container = _mint_nft(
        node,
        GlyphMetadata(
            protocol=[GlyphProtocol.NFT, GlyphProtocol.CONTAINER],
            name="REGTEST-DELEGATE-COLLECTION",
            token_type="container",
        ),
    )
    author = _mint_nft(
        node,
        GlyphMetadata(protocol=[GlyphProtocol.NFT], name="REGTEST-DELEGATE-AUTHOR", token_type="author"),
    )
    return {"container": container, "author": author}


@pytest.fixture(scope="module")
def base(node, parents):  # noqa: F811
    """Step 1: spend both parents into a delegate base, re-creating them."""
    container, author = parents["container"], parents["author"]
    owner = container["key"]
    owner_pkh = container["pkh"]
    setup = GlyphBuilder().prepare_delegate_setup(
        owner_pkh,
        [container["ref"], author["ref"]],
        parent_owner_pkh=owner_pkh,
    )
    # The parents are re-created to ONE key here so a single unlock signs the
    # later spends; nothing about the mechanism requires that.
    total = container["value"] + author["value"]
    change = total - _BASE_VALUE - 2 * _PARENT_CARRIER - _FEE
    assert change > 0, f"value plan does not balance: {total=}"

    tx = Transaction(
        tx_inputs=[_nft_input(container), _nft_input(author)],
        tx_outputs=[
            TransactionOutput(Script(setup.base_script), _BASE_VALUE),
            # THE OUTPUTS THAT KEEP THE PARENTS ALIVE.
            TransactionOutput(Script(setup.parent_scripts[0]), _PARENT_CARRIER),
            TransactionOutput(Script(setup.parent_scripts[1]), _PARENT_CARRIER),
            TransactionOutput(P2PKH().lock(owner.public_key().hash160()), change),
        ],
    )
    txid = _send(node, tx, what="delegate base")

    # The parents now live at their new outpoints.
    container.update({"reveal_txid": txid, "vout": 1, "value": _PARENT_CARRIER, "script": setup.parent_scripts[0]})
    author.update({"reveal_txid": txid, "vout": 2, "value": _PARENT_CARRIER, "script": setup.parent_scripts[1]})
    return {
        "ref": GlyphRef(txid=txid, vout=0),
        "txid": txid,
        "script": setup.base_script,
        "value": _BASE_VALUE,
        "key": owner,
        "pkh": owner_pkh,
        "authorised": (container["ref"], author["ref"]),
    }


@pytest.fixture(scope="module")
def tokens(node, base):  # noqa: F811
    """Step 2: spend the base into N disposable delegate tokens."""
    setup = GlyphBuilder().prepare_delegate_setup(
        base["pkh"],
        list(base["authorised"]),
        base_ref=base["ref"],
        token_count=_TOKEN_COUNT,
    )
    change = base["value"] - _TOKEN_COUNT * _TOKEN_VALUE - _FEE
    assert change > 0

    tx = Transaction(
        tx_inputs=[
            TransactionInput(
                source_transaction=_src(base["txid"], 0, base["script"], base["value"]),
                source_txid=base["txid"],
                source_output_index=0,
                unlocking_script_template=_p2pkh_unlock(base["key"]),
            )
        ],
        tx_outputs=[TransactionOutput(Script(s), _TOKEN_VALUE) for s in setup.token_scripts]
        + [TransactionOutput(P2PKH().lock(base["key"].public_key().hash160()), change)],
    )
    txid = _send(node, tx, what="delegate token mint")
    return {"txid": txid, "scripts": setup.token_scripts, "value": _TOKEN_VALUE, "key": base["key"]}


def _delegated_mint(node, base, tokens, vout: int, *, omit_burn=False, carry_base_ref=False):  # noqa: F811
    """Commit+reveal one NFT authorised by delegate token *vout*.

    Returns the reveal txid, or the node's refusal when a negative variant is
    asked for.
    """
    owner = PrivateKey()
    owner_pkh = Hex20(owner.public_key().hash160())
    builder = GlyphBuilder()
    metadata = GlyphMetadata(
        protocol=[GlyphProtocol.NFT],
        name=f"DELEGATED-MEMBER-{vout}",
        container_refs=(base["authorised"][0],),
        author_refs=(base["authorised"][1],),
    )
    commit = builder.prepare_commit(
        CommitParams(
            metadata=metadata,
            owner_pkh=owner_pkh,
            change_pkh=owner_pkh,
            funding_satoshis=tokens["value"],
            delegate_ref=base["ref"],
        )
    )
    commit_value = tokens["value"] - _FEE
    commit_tx = Transaction(
        tx_inputs=[
            TransactionInput(
                source_transaction=_src(tokens["txid"], vout, tokens["scripts"][vout], tokens["value"]),
                source_txid=tokens["txid"],
                source_output_index=vout,
                unlocking_script_template=_p2pkh_unlock(tokens["key"]),
            )
        ],
        tx_outputs=[TransactionOutput(Script(commit.commit_script), commit_value)],
    )
    commit_txid = _send(node, commit_tx, what="delegated commit")

    reveal_scripts = builder.prepare_reveal(
        RevealParams(
            commit_txid=commit_txid,
            commit_vout=0,
            commit_value=commit_value,
            cbor_bytes=commit.cbor_bytes,
            owner_pkh=owner_pkh,
            is_nft=True,
            commit_script=commit.commit_script,
        )
    )
    assert reveal_scripts.delegate_burn_script is not None

    outs = [TransactionOutput(Script(reveal_scripts.locking_script), _MINT_CARRIER)]
    if not omit_burn:
        outs.append(TransactionOutput(Script(reveal_scripts.delegate_burn_script), 0))
    if carry_base_ref:
        # An output that PUSHES the base ref, which the prefix forbids.
        outs.append(TransactionOutput(Script(build_delegate_token_script(owner_pkh, base["ref"])), _MINT_CARRIER))
    change = commit_value - _MINT_CARRIER - (_MINT_CARRIER if carry_base_ref else 0) - _FEE
    outs.append(TransactionOutput(P2PKH().lock(owner.public_key().hash160()), change))

    reveal = Transaction(
        tx_inputs=[
            TransactionInput(
                source_transaction=_src(commit_txid, 0, commit.commit_script, commit_value),
                source_txid=commit_txid,
                source_output_index=0,
                unlocking_script_template=_reveal_unlock(owner, reveal_scripts.scriptsig_suffix),
            )
        ],
        tx_outputs=outs,
    )
    if omit_burn or carry_base_ref:
        return {"rejected": _rejects(node, reveal)}
    txid = _send(node, reveal, what="delegated reveal")
    return {"reveal_txid": txid, "ref": GlyphRef(txid=commit_txid, vout=0), "metadata": metadata}


# --------------------------------------------------------------------------- 1. the base


def test_the_base_is_accepted_and_the_parents_survive(node, parents, base):  # noqa: F811
    """Step 1 works, and — the unrecoverable half — nothing was burned."""
    confirmed = _confirmed(node, base["txid"])

    assert _out_spk(confirmed, 0) == base["script"]
    assert parse_delegate_base_script(_out_spk(confirmed, 0)) == (
        parents["container"]["ref"].to_bytes(),
        parents["author"]["ref"].to_bytes(),
    )
    # Both parents are back, as ordinary 63-byte singletons carrying their own refs.
    for vout, token in ((1, parents["container"]), (2, parents["author"])):
        spk = _out_spk(confirmed, vout)
        assert is_nft_script(spk.hex()) and len(spk) == 63
        assert spk[1:37] == token["ref"].to_bytes()


def test_a_base_naming_a_ref_it_did_not_spend_is_rejected(node, parents, base):  # noqa: F811
    """THE authorisation property. If this passes, delegates prove nothing.

    ``OP_REQUIREINPUTREF`` is subset-checked against the inputs, so a base can
    only name refs the transaction actually held. Here it names a ref belonging
    to a token this transaction never touches.
    """
    author = parents["author"]
    stranger = GlyphRef(txid="ab" * 32, vout=0)
    forged = build_delegate_base_script(author["pkh"], [stranger])

    tx = Transaction(
        tx_inputs=[_nft_input(author)],
        tx_outputs=[
            TransactionOutput(Script(forged), _MINT_CARRIER),
            TransactionOutput(Script(author["script"]), author["value"] - _MINT_CARRIER - _FEE),
        ],
    )
    res = _rejects(node, tx)
    assert "invalid-transaction-reference-operations" in str(res.get("reject-reason", "")), (
        f"rejected, but not by the ref subset rule this test is about: {res}"
    )


# --------------------------------------------------------------------------- 2. the tokens


def test_delegate_tokens_are_accepted_and_classify_as_delegate_tokens(node, base, tokens):  # noqa: F811
    confirmed = _confirmed(node, tokens["txid"])
    for vout in range(_TOKEN_COUNT):
        spk = _out_spk(confirmed, vout)
        assert is_delegate_token_script(spk.hex()), f"vout {vout} is not a delegate token: {spk.hex()}"
        # Same 63 bytes as an NFT singleton, different opcode. The chain keeps
        # them distinct; so must we.
        assert not is_nft_script(spk.hex())
        assert spk[1:37] == base["ref"].to_bytes()


# --------------------------------------------------------------------------- 3. the mint


@pytest.fixture(scope="module")
def delegated_mint(node, base, tokens):  # noqa: F811
    return _delegated_mint(node, base, tokens, 0)


def test_a_delegate_prefixed_commit_is_accepted(node, base, tokens, delegated_mint):  # noqa: F811
    """The 56-byte prefix does not make the commit output unspendable."""
    confirmed = _confirmed(node, delegated_mint["ref"].txid)
    spk = _out_spk(confirmed, 0)
    assert len(spk) == 131, f"expected the 75-byte commit behind a 56-byte prefix, got {len(spk)}"
    assert is_commit_nft_script(spk.hex()), "a delegate commit must still classify as a commit"


def test_the_reveal_is_accepted_with_its_burn_output(node, base, delegated_mint):  # noqa: F811
    """Question 3, answered by the chain.

    The prefix asserts the base ref appears in ZERO outputs AND requires a burn
    output naming it. Both hold only if ``OP_REFOUTPUTCOUNT_OUTPUTS`` ignores
    ``OP_REQUIREINPUTREF`` operands. Acceptance here is that answer.
    """
    confirmed = _confirmed(node, delegated_mint["reveal_txid"])
    burns = [parse_delegate_burn_script(_out_spk(confirmed, i)) for i in range(len(confirmed["vout"]))]
    assert base["ref"].to_bytes() in [b for b in burns if b is not None], "no burn output on the accepted reveal"


def test_a_reveal_without_the_burn_output_is_rejected(node, base, tokens):  # noqa: F811
    """Otherwise the burn is decoration and the delegate is never consumed."""
    out = _delegated_mint(node, base, tokens, 1, omit_burn=True)
    # The covenant's own OP_NUMEQUALVERIFY, not a fee or a malformed script.
    assert "OP_NUMEQUALVERIFY" in str(out["rejected"].get("reject-reason", "")), out["rejected"]


def test_a_reveal_carrying_the_base_ref_forward_is_rejected(node, base, tokens):  # noqa: F811
    """The authorisation is consumed by the mint, not inherited by the token."""
    out = _delegated_mint(node, base, tokens, 2, carry_base_ref=True)
    assert "OP_NUMEQUALVERIFY" in str(out["rejected"].get("reject-reason", "")), out["rejected"]


def test_the_same_reveal_without_the_prefix_is_accepted(node, tokens):  # noqa: F811
    """NON-VACUITY. Both refusals above must come from the delegate prefix.

    A reveal with no burn output is the NORMAL shape for an ordinary mint. If
    that were rejected for some incidental reason — a fee, an output count, a
    quirk of this harness — the two negative cases would pass without proving
    anything about the covenant. So: the identical mint, built from a commit
    WITHOUT the prefix, must be accepted.
    """
    owner = PrivateKey()
    owner_pkh = Hex20(owner.public_key().hash160())
    builder = GlyphBuilder()
    metadata = GlyphMetadata(protocol=[GlyphProtocol.NFT], name="UNDELEGATED-CONTROL")
    commit = builder.prepare_commit(
        CommitParams(
            metadata=metadata,
            owner_pkh=owner_pkh,
            change_pkh=owner_pkh,
            funding_satoshis=tokens["value"],
        )
    )
    assert len(commit.commit_script) == 75, "the control must NOT carry the prefix"

    commit_value = tokens["value"] - _FEE
    commit_txid = _send(
        node,
        Transaction(
            tx_inputs=[
                TransactionInput(
                    source_transaction=_src(tokens["txid"], 3, tokens["scripts"][3], tokens["value"]),
                    source_txid=tokens["txid"],
                    source_output_index=3,
                    unlocking_script_template=_p2pkh_unlock(tokens["key"]),
                )
            ],
            tx_outputs=[TransactionOutput(Script(commit.commit_script), commit_value)],
        ),
        what="control commit",
    )
    reveal_scripts = builder.prepare_reveal(
        RevealParams(
            commit_txid=commit_txid,
            commit_vout=0,
            commit_value=commit_value,
            cbor_bytes=commit.cbor_bytes,
            owner_pkh=owner_pkh,
            is_nft=True,
            commit_script=commit.commit_script,
        )
    )
    assert reveal_scripts.delegate_burn_script is None
    reveal = Transaction(
        tx_inputs=[
            TransactionInput(
                source_transaction=_src(commit_txid, 0, commit.commit_script, commit_value),
                source_txid=commit_txid,
                source_output_index=0,
                unlocking_script_template=_reveal_unlock(owner, reveal_scripts.scriptsig_suffix),
            )
        ],
        tx_outputs=[
            TransactionOutput(Script(reveal_scripts.locking_script), _MINT_CARRIER),
            TransactionOutput(P2PKH().lock(owner.public_key().hash160()), commit_value - _MINT_CARRIER - _FEE),
        ],
    )
    _send(node, reveal, what="control reveal (no prefix, no burn)")


# --------------------------------------------------------------------------- 4. read back


def test_the_claim_verifies_as_DELEGATED_from_chain_data_alone(node, base, delegated_mint):  # noqa: F811
    """End to end, through the real lookup a consumer performs.

    Nothing here is handed the answer: the burn is read off the confirmed
    reveal, the base is fetched by the ref inside it, and the authorised refs
    come from parsing that transaction's outputs.
    """
    reveal_raw = bytes.fromhex(str(node.cli("getrawtransaction", delegated_mint["reveal_txid"])))
    reveal_tx = Transaction.from_hex(reveal_raw)
    assert reveal_tx is not None
    reveal_outputs = [bytes(o.locking_script.serialize()) for o in reveal_tx.outputs]

    # 1. which base did this transaction burn?
    burned = delegate_burn_refs(reveal_outputs)
    assert burned == {base["ref"].to_bytes()}

    # 2. fetch that base transaction and read what it authorises
    base_ref = next(iter(burned))
    base_txid = GlyphRef.from_bytes(base_ref).txid
    base_raw = bytes.fromhex(str(node.cli("getrawtransaction", base_txid)))
    base_tx = Transaction.from_hex(base_raw)
    assert base_tx is not None
    authorised = resolve_delegated_refs(base_ref, [bytes(o.locking_script.serialize()) for o in base_tx.outputs])
    assert set(authorised) == {r.to_bytes() for r in base["authorised"]}

    # 3. the verdict
    scriptsigs = [i.unlocking_script.serialize() if i.unlocking_script else b"" for i in reveal_tx.inputs]
    found = INSPECTOR.find_reveal_metadata(scriptsigs)
    assert found is not None, "no Glyph envelope on the confirmed reveal"
    metadata = found[1]

    verdicts = {v.kind: v for v in verify_relationship_claims(metadata, reveal_outputs, delegated_refs=authorised)}
    for kind in (RelationshipKind.CONTAINER, RelationshipKind.AUTHOR):
        assert verdicts[kind].outcome is RelationshipOutcome.BACKED, f"{kind} unbacked on a real delegated mint"
        assert verdicts[kind].backing is RelationshipBacking.DELEGATED

    # And without the lookup it is honestly UNBACKED, not silently assumed.
    bare = verify_relationship_claims(metadata, reveal_outputs)
    assert all(v.outcome is RelationshipOutcome.UNBACKED for v in bare)
