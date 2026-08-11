"""Live-regtest CONSENSUS proof for CONTAINER (collection) tokens.

pyrxd shipped ``GlyphBuilder.prepare_container_reveal(child_ref=...)`` from
0.9.0 through 0.14.0. It prefixed the NFT body with ``OP_PUSHINPUTREF
<child_ref>`` and produced a 100-byte script that no classifier matched. The
question that decides whether that path should be completed or removed is a
consensus question, and only a node can answer it. This file asks it.

What each case proves:

1. **A container is an ordinary NFT, end to end.** Commit, reveal, classify,
   scan and transfer with no container-specific code path. Its locking script is
   the plain 63-byte singleton; container-ness is the ``7`` marker in the
   envelope. This is Photonic Wallet's model (one ``nftScript``, no container
   variant) and it is what makes a collection routable.
2. **Membership is a checkable claim.** The child declares the container in its
   envelope's ``in`` field, and its reveal spends and re-creates the container
   UTXO — so the container's ref appears among the reveal's output-script refs,
   which is the condition Photonic's indexer applies before honouring the claim
   (``filterRels``). Read back off the confirmed transaction.
3. **Transferring the container cannot break the collection.** The ref is
   unchanged and the membership lives in an envelope nobody re-writes.
4. **NEGATIVE — the removed 100-byte output is unspendable.** ``OP_PUSHINPUTREF``
   leaves the child ref on the stack and nothing drops it, so the P2PKH tail
   hashes the ref. Consensus rejects every spend of it. This is the finding that
   turned "complete the feature" into "remove it".
5. **NEGATIVE — a container naming a live token is rejected outright.** For an
   NFT, a ref pushed by ``OP_PUSHINPUTREFSINGLETON`` in one output may not appear
   in a sibling output. For an FT, the token's own epilogue breaks on the extra
   ref. There is no token type a container can name and leave alive.
6. **NEGATIVE — and the child can never be re-minted.** Once its singleton has
   been consumed into a ``0xd0`` push it is absent from ``inputSingletonRefSet``
   forever. Creating a legacy container destroyed the child NFT.
7. **NEGATIVE — membership itself is not enforced.** A token may claim ``in``
   for a container it never touched and the chain accepts it. That is why case 2
   is about making the claim *checkable*, not about making it binding.

Cases 4-6 build the removed shape by hand, on purpose: the builder refuses it
now, and the reason it refuses it has to stay proven.

Opt-in: ``@pytest.mark.integration`` + ``RADIANT_REGTEST=1``. Never runs in
normal CI. Manages its own throwaway container; moves no real value. No PoW, so
this is seconds.

Run: ``RADIANT_REGTEST=1 pytest tests/test_container_regtest_e2e.py -m integration -s``
"""

from __future__ import annotations

import hashlib

import cbor2
import pytest

# Reuse the isolated-regtest harness wholesale (same pattern as the FT airdrop
# and dMint e2e tests): the ``node`` fixture spins up + tears down a throwaway
# container.
from test_htlc_regtest_e2e import (  # noqa: F401  (node = fixture)
    _p2pkh_unlock,
    _pay_to_spk,
    _RegtestNode,
    _src,
    node,
)

from pyrxd.glyph.builder import CommitParams, GlyphBuilder, RevealParams, TransferParams
from pyrxd.glyph.inspector import GlyphInspector
from pyrxd.glyph.payload import decode_payload
from pyrxd.glyph.script import (
    build_ft_locking_script,
    build_nft_locking_script,
    is_legacy_container_script,
    is_nft_script,
)
from pyrxd.glyph.types import GlyphMetadata, GlyphProtocol, GlyphRef
from pyrxd.glyph.wave import classify_glyph_metadata
from pyrxd.keys import PrivateKey
from pyrxd.script.script import Script
from pyrxd.script.type import P2PKH, encode_pushdata, to_unlock_script_template
from pyrxd.security.types import Hex20
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_input import TransactionInput
from pyrxd.transaction.transaction_output import TransactionOutput

pytestmark = pytest.mark.integration

# Radiant's relay floor is 10,000 photons per byte of ``GetTotalSize()`` — not
# vsize — and there is neither RBF nor CPFP, so an underpaid transaction cannot
# be repaired and holds its inputs until the 8-hour mempool expiry. Every
# transaction here therefore pays a flat, generous fee AND is checked against
# its own serialized length before broadcast (:func:`_assert_fee_covers`).
_MIN_FEE_RATE = 10_000
_FEE = 20_000_000  # 0.2 RXD — covers ~2 KB at the relay floor
_COMMIT_VALUE = 200_000_000  # 2 RXD into the commit; funds the reveal + carrier
_CARRIER = 10_000_000  # photons parked on a token output (Radiant has no dust rule)
_LEGACY_CARRIER = 80_000_000  # 0.8 RXD on the dead output, so its spend can pay a fee

INSPECTOR = GlyphInspector()


# --------------------------------------------------------------------------- helpers


def _assert_fee_covers(tx: Transaction, fee: int) -> str:
    """Serialize *tx*, check the fee against the REAL byte length, return the hex.

    Sizing a Radiant fee from an estimate is how an unrepairable transaction gets
    built. The floor applies to the serialized total size, so measure it.
    """
    raw = tx.serialize()
    required = len(raw) * _MIN_FEE_RATE
    assert fee >= required, f"fee {fee} < relay floor {required} for a {len(raw)}-byte tx"
    return raw.hex()


def _reveal_unlock(key: PrivateKey, suffix: bytes):
    """P2PKH unlock with the ``'gly'``+CBOR push sequence appended."""
    pub = key.public_key().serialize()

    def _u(tx, idx):
        inp = tx.inputs[idx]
        sig = key.sign(tx.preimage(idx))
        return Script(encode_pushdata(sig + inp.sighash.to_bytes(1, "little")) + encode_pushdata(pub) + suffix)

    return to_unlock_script_template(_u, lambda: 110 + len(suffix))


def _confirmed(rt: _RegtestNode, txid: str) -> dict:
    info = rt.cli("getrawtransaction", txid, "true")
    assert info["confirmations"] >= 1, f"{txid} did not confirm"
    return info


def _out_spk(confirmed: dict, vout: int) -> bytes:
    return bytes.fromhex(confirmed["vout"][vout]["scriptPubKey"]["hex"])


def _envelope_from_confirmed(rt: _RegtestNode, txid: str) -> GlyphMetadata:
    """Re-read a reveal's CBOR envelope off the confirmed transaction.

    Deliberately goes back to the chain rather than reusing the bytes the test
    built: the point is what a third party can recover, not what we remember.
    """
    raw = bytes.fromhex(str(rt.cli("getrawtransaction", txid)))
    tx = Transaction.from_hex(raw)
    assert tx is not None
    scriptsigs = [i.unlocking_script.serialize() if i.unlocking_script else b"" for i in tx.inputs]
    found = INSPECTOR.find_reveal_metadata(scriptsigs)
    assert found is not None, "no Glyph envelope found on the confirmed reveal"
    return found[1]


def _output_refs(rt: _RegtestNode, txid: str) -> set[bytes]:
    """Every 36-byte ref carried by an NFT-shaped output of *txid*.

    This is the set Photonic's ``filterRels`` intersects a claimed ``in`` list
    against before it will honour the membership.
    """
    confirmed = _confirmed(rt, txid)
    refs = set()
    for out in confirmed["vout"]:
        spk = bytes.fromhex(out["scriptPubKey"]["hex"])
        if is_nft_script(spk.hex()):
            refs.add(spk[1:37])
    return refs


def _mint_nft(rt: _RegtestNode, metadata: GlyphMetadata) -> dict:
    """Commit + reveal a single-output NFT (a container is exactly this).

    Returns the token's ref, its UTXO, its locking script, and the owning key.
    """
    owner = PrivateKey()
    owner_pkh = Hex20(owner.public_key().hash160())
    builder = GlyphBuilder()

    commit = builder.prepare_commit(
        CommitParams(
            metadata=metadata,
            owner_pkh=owner_pkh,
            change_pkh=owner_pkh,
            funding_satoshis=_COMMIT_VALUE,
        )
    )
    commit_txid = _pay_to_spk(rt, commit.commit_script, _COMMIT_VALUE)
    rt.mine(1)

    reveal_scripts = builder.prepare_reveal(
        RevealParams(
            commit_txid=commit_txid,
            commit_vout=0,
            commit_value=_COMMIT_VALUE,
            cbor_bytes=commit.cbor_bytes,
            owner_pkh=owner_pkh,
            is_nft=True,
        )
    )
    reveal = Transaction(
        tx_inputs=[
            TransactionInput(
                source_transaction=_src(commit_txid, 0, commit.commit_script, _COMMIT_VALUE),
                source_txid=commit_txid,
                source_output_index=0,
                unlocking_script_template=_reveal_unlock(owner, reveal_scripts.scriptsig_suffix),
            )
        ],
        tx_outputs=[TransactionOutput(Script(reveal_scripts.locking_script), _COMMIT_VALUE - _FEE)],
    )
    reveal.sign()
    raw = _assert_fee_covers(reveal, _FEE)
    res = rt.accepts(raw)
    assert res.get("allowed") is True, f"NFT/container reveal rejected: {res}"
    reveal_txid = str(rt.cli("sendrawtransaction", raw))
    rt.mine(1)

    return {
        "ref": GlyphRef(txid=commit_txid, vout=0),
        "commit_txid": commit_txid,
        "reveal_txid": reveal_txid,
        "vout": 0,
        "value": _COMMIT_VALUE - _FEE,
        "script": reveal_scripts.locking_script,
        "key": owner,
        "pkh": owner_pkh,
    }


@pytest.fixture(scope="module")
def container(node):  # noqa: F811
    """A real collection token on the regtest chain.

    Later cases move it, so ``reveal_txid`` / ``vout`` / ``value`` / ``key``
    track its CURRENT outpoint. ``mint_txid`` is the immutable one — the
    transaction whose scriptSig carries the envelope.
    """
    minted = _mint_nft(
        node,
        GlyphMetadata(
            protocol=[GlyphProtocol.NFT, GlyphProtocol.CONTAINER],
            name="REGTEST-COLLECTION",
            token_type="container",
            description="regtest container fixture",
        ),
    )
    minted["mint_txid"] = minted["reveal_txid"]
    return minted


# --------------------------------------------------------------------------- 1. container


def test_container_is_an_ordinary_nft_on_chain(node, container):  # noqa: F811
    """Case 1. Minted through the plain NFT path; 63 bytes; classifies as an NFT."""
    confirmed = _confirmed(node, container["mint_txid"])
    spk = _out_spk(confirmed, 0)

    assert len(spk) == 63, f"a container must be the plain NFT singleton, got {len(spk)} bytes"
    assert spk == build_nft_locking_script(container["pkh"], container["ref"])
    assert is_nft_script(spk.hex())
    assert not is_legacy_container_script(spk.hex())

    glyphs = INSPECTOR.find_glyphs([(container["value"], spk)])
    assert [g.glyph_type for g in glyphs] == ["nft"]
    assert glyphs[0].ref == container["ref"]
    assert glyphs[0].spendable is True


def test_container_ness_is_recoverable_from_the_confirmed_reveal(node, container):  # noqa: F811
    """Case 1. The only place container-ness exists is the envelope — so read it
    back off the chain and check the classifier agrees."""
    metadata = _envelope_from_confirmed(node, container["mint_txid"])
    assert GlyphProtocol.CONTAINER in metadata.protocol
    assert metadata.is_container is True
    assert classify_glyph_metadata(metadata) == "container"


# --------------------------------------------------------------------------- 2. membership


@pytest.fixture(scope="module")
def member(node, container):  # noqa: F811
    """A token minted INTO the container, with the provable reveal shape."""
    owner = PrivateKey()
    owner_pkh = Hex20(owner.public_key().hash160())
    builder = GlyphBuilder()

    metadata = GlyphMetadata(
        protocol=[GlyphProtocol.NFT],
        name="REGTEST-MEMBER",
        description="member of REGTEST-COLLECTION",
        container_refs=(container["ref"],),
    )
    commit = builder.prepare_commit(
        CommitParams(
            metadata=metadata,
            owner_pkh=owner_pkh,
            change_pkh=owner_pkh,
            funding_satoshis=_COMMIT_VALUE,
        )
    )
    commit_txid = _pay_to_spk(node, commit.commit_script, _COMMIT_VALUE)
    node.mine(1)

    scripts = builder.prepare_container_child_reveal(
        commit_txid,
        0,
        commit.cbor_bytes,
        owner_pkh,
        container["ref"],
        container["pkh"],
    )
    reveal = Transaction(
        tx_inputs=[
            TransactionInput(
                source_transaction=_src(commit_txid, 0, commit.commit_script, _COMMIT_VALUE),
                source_txid=commit_txid,
                source_output_index=0,
                unlocking_script_template=_reveal_unlock(owner, scripts.scriptsig_suffix),
            ),
            TransactionInput(
                source_transaction=_src(
                    container["reveal_txid"], container["vout"], container["script"], container["value"]
                ),
                source_txid=container["reveal_txid"],
                source_output_index=container["vout"],
                unlocking_script_template=_p2pkh_unlock(container["key"]),
            ),
        ],
        tx_outputs=[
            TransactionOutput(Script(scripts.nft_script), _CARRIER),
            TransactionOutput(Script(scripts.container_script), container["value"]),
            TransactionOutput(P2PKH().lock(owner.public_key().hash160()), _COMMIT_VALUE - _CARRIER - _FEE),
        ],
    )
    reveal.sign()
    raw = _assert_fee_covers(reveal, _FEE)
    res = node.accepts(raw)
    assert res.get("allowed") is True, f"container-child reveal REJECTED by consensus: {res}"
    txid = str(node.cli("sendrawtransaction", raw))
    node.mine(1)

    # The container moved to a new outpoint; later cases spend it from there.
    container["reveal_txid"] = txid
    container["vout"] = 1
    return {"ref": scripts.ref, "reveal_txid": txid, "key": owner, "pkh": owner_pkh}


def test_member_reveal_is_accepted_and_recreates_the_container(node, container, member):  # noqa: F811
    """Case 2. Both token outputs survive: the new member AND the collection.

    That both singletons can coexist here — while case 5 shows they cannot when
    the ref is carried into a sibling output — is the whole reason membership is
    metadata.
    """
    confirmed = _confirmed(node, member["reveal_txid"])
    child_spk = _out_spk(confirmed, 0)
    container_spk = _out_spk(confirmed, 1)

    assert is_nft_script(child_spk.hex()) and len(child_spk) == 63
    assert is_nft_script(container_spk.hex()) and len(container_spk) == 63
    assert child_spk[1:37] == member["ref"].to_bytes()
    assert container_spk[1:37] == container["ref"].to_bytes()
    assert container_spk == build_nft_locking_script(container["pkh"], container["ref"]), (
        "minting a member must re-create the container unchanged, not move or re-own it"
    )


def test_membership_is_readable_and_checkable_off_the_chain(node, container, member):  # noqa: F811
    """Case 2. The claim decodes, and it passes the check an indexer applies."""
    metadata = _envelope_from_confirmed(node, member["reveal_txid"])
    assert metadata.container_refs == (container["ref"],)

    # Photonic's ``filterRels``: a claimed ``in`` ref counts only if it also
    # appears among the refs of the reveal's own outputs.
    assert container["ref"].to_bytes() in _output_refs(node, member["reveal_txid"])


# --------------------------------------------------------------------------- 3. transfer


def test_container_transfers_with_the_ordinary_nft_builder(node, container, member):  # noqa: F811
    """Case 3. No container-specific transfer path, and nothing to preserve by
    hand — the ref is carried by ``build_nft_transfer_tx`` and the membership
    lives in an envelope no transfer touches."""
    new_owner = PrivateKey()
    new_pkh = Hex20(new_owner.public_key().hash160())

    result = GlyphBuilder().build_nft_transfer_tx(
        TransferParams(
            nft_script=container["script"],
            nft_utxo_txid=container["reveal_txid"],
            nft_utxo_vout=container["vout"],
            nft_utxo_value=container["value"],
            new_owner_pkh=new_pkh,
            private_key=container["key"],
            fee_rate=_MIN_FEE_RATE,
        )
    )
    raw = result.tx.serialize().hex()
    res = node.accepts(raw)
    assert res.get("allowed") is True, f"container transfer REJECTED: {res}"
    txid = str(node.cli("sendrawtransaction", raw))
    node.mine(1)

    confirmed = _confirmed(node, txid)
    spk = _out_spk(confirmed, 0)
    assert spk == build_nft_locking_script(new_pkh, container["ref"])
    assert spk[1:37] == container["ref"].to_bytes(), "the collection's ref must survive the transfer"

    # The member's declared membership still names this exact container.
    metadata = _envelope_from_confirmed(node, member["reveal_txid"])
    assert metadata.container_refs == (container["ref"],)

    container["reveal_txid"] = txid
    container["vout"] = 0
    container["value"] = confirmed["vout"][0]["value"]
    container["key"] = new_owner
    container["pkh"] = new_pkh
    container["script"] = spk


# --------------------------------------------------------------------------- 4-6. the removed shape


def _legacy_container_script(child_ref: GlyphRef, container_ref: GlyphRef, owner_pkh: Hex20) -> bytes:
    """The exact 100-byte script pyrxd built for 0.9.0-0.14.0.

    Spelled out here because ``prepare_container_reveal`` refuses to build it
    now — and the reason it refuses has to keep being demonstrated, not asserted.
    """
    return bytes([0xD0]) + child_ref.to_bytes() + build_nft_locking_script(owner_pkh, container_ref)


@pytest.fixture(scope="module")
def legacy(node):  # noqa: F811
    """A legacy container output, created the only way consensus allows.

    Namely: by consuming a real child NFT and NOT re-creating it. Returns the
    child NFT it destroyed along with the dead output.
    """
    child = _mint_nft(node, GlyphMetadata(protocol=[GlyphProtocol.NFT], name="DOOMED-CHILD"))

    owner = PrivateKey()
    owner_pkh = Hex20(owner.public_key().hash160())
    builder = GlyphBuilder()
    metadata = GlyphMetadata(
        protocol=[GlyphProtocol.NFT, GlyphProtocol.CONTAINER], name="LEGACY-COLLECTION", token_type="container"
    )
    commit = builder.prepare_commit(
        CommitParams(metadata=metadata, owner_pkh=owner_pkh, change_pkh=owner_pkh, funding_satoshis=_COMMIT_VALUE)
    )
    commit_txid = _pay_to_spk(node, commit.commit_script, _COMMIT_VALUE)
    node.mine(1)

    scripts = builder.prepare_container_reveal(commit_txid, 0, commit.cbor_bytes, owner_pkh)
    container_ref = scripts.ref
    dead_script = _legacy_container_script(child["ref"], container_ref, owner_pkh)
    assert len(dead_script) == 100
    assert is_legacy_container_script(dead_script.hex())

    return {
        "child": child,
        "commit_txid": commit_txid,
        "commit_script": commit.commit_script,
        "scriptsig_suffix": scripts.scriptsig_suffix,
        "container_ref": container_ref,
        "owner": owner,
        "owner_pkh": owner_pkh,
        "script": dead_script,
    }


def _legacy_reveal(node, legacy, *, keep_child: bool) -> Transaction:  # noqa: F811
    """Build the legacy container reveal, optionally trying to keep the child."""
    child = legacy["child"]
    # Funded well above the relay floor so the "can it be spent?" case fails on
    # the script, not on an unpayable fee — a rejection for the wrong reason
    # would be a false pass dressed as a negative control.
    outputs = [TransactionOutput(Script(legacy["script"]), _LEGACY_CARRIER)]
    spent = _LEGACY_CARRIER
    if keep_child:
        outputs.append(TransactionOutput(Script(build_nft_locking_script(child["pkh"], child["ref"])), _CARRIER))
        spent += _CARRIER
    change = _COMMIT_VALUE + child["value"] - spent - _FEE
    outputs.append(TransactionOutput(P2PKH().lock(legacy["owner"].public_key().hash160()), change))

    tx = Transaction(
        tx_inputs=[
            TransactionInput(
                source_transaction=_src(legacy["commit_txid"], 0, legacy["commit_script"], _COMMIT_VALUE),
                source_txid=legacy["commit_txid"],
                source_output_index=0,
                unlocking_script_template=_reveal_unlock(legacy["owner"], legacy["scriptsig_suffix"]),
            ),
            TransactionInput(
                source_transaction=_src(child["reveal_txid"], child["vout"], child["script"], child["value"]),
                source_txid=child["reveal_txid"],
                source_output_index=child["vout"],
                unlocking_script_template=_p2pkh_unlock(child["key"]),
            ),
        ],
        tx_outputs=outputs,
    )
    tx.sign()
    return tx


def test_a_container_naming_a_surviving_child_is_rejected(node, legacy):  # noqa: F811
    """Case 5 (NEGATIVE). The child cannot survive the transaction that names it.

    ``OP_PUSHINPUTREFSINGLETON`` files its ref into ``foundDisallowedSiblingRefs``
    as well as the push-ref set (``CScript::GetPushRefs``), so no *other* output
    of the same transaction may carry that ref — by ``0xd0`` or otherwise. A
    script-level link from a container to a live NFT is therefore impossible on
    Radiant, whatever the opcodes.
    """
    tx = _legacy_reveal(node, legacy, keep_child=True)
    res = node.accepts(_assert_fee_covers(tx, _FEE))
    assert res.get("allowed") is False, (
        f"consensus ACCEPTED a container naming a child that survives — the sibling rule this "
        f"whole design rests on does not hold: {res}"
    )
    reason = str(res.get("reject-reason", ""))
    assert "invalid-transaction-reference-operations" in reason, (
        f"rejected, but not by the ref rule this control is testing: {res}"
    )
    print(f"[case 5] container + surviving child reject-reason: {reason}")


def test_creating_a_legacy_container_consumes_the_child(node, legacy):  # noqa: F811
    """Case 6a. The only accepted form destroys the child NFT.

    This one is ACCEPTED — which is exactly the problem. A caller who thought
    they were adding a token to a collection has burned it.
    """
    tx = _legacy_reveal(node, legacy, keep_child=False)
    raw = _assert_fee_covers(tx, _FEE)
    res = node.accepts(raw)
    assert res.get("allowed") is True, f"legacy container reveal rejected for an unrelated reason: {res}"
    legacy["txid"] = str(node.cli("sendrawtransaction", raw))
    node.mine(1)

    spk = _out_spk(_confirmed(node, legacy["txid"]), 0)
    assert spk == legacy["script"]
    # The child NFT's UTXO is gone and no output re-created it.
    assert node.cli("gettxout", legacy["child"]["reveal_txid"], str(legacy["child"]["vout"])) in ("", None)


def test_the_legacy_container_output_cannot_be_spent(node, legacy):  # noqa: F811
    """Case 4 (NEGATIVE). The decisive finding: the output is dead.

    ``OP_PUSHINPUTREF <child_ref>`` pushes 36 bytes that nothing drops, so when
    the P2PKH tail runs ``OP_DUP OP_HASH160`` the top of the stack is the ref,
    not the pubkey. The comparison against the owner PKH is between two unrelated
    values and no scriptSig can change that — the failing item is pushed by the
    *locking* script.
    """
    assert "txid" in legacy, "depends on test_creating_a_legacy_container_consumes_the_child"
    dest = PrivateKey()
    tx = Transaction(
        tx_inputs=[
            TransactionInput(
                source_transaction=_src(legacy["txid"], 0, legacy["script"], _LEGACY_CARRIER),
                source_txid=legacy["txid"],
                source_output_index=0,
                unlocking_script_template=_p2pkh_unlock(legacy["owner"]),
            )
        ],
        tx_outputs=[TransactionOutput(P2PKH().lock(dest.public_key().hash160()), _LEGACY_CARRIER - _FEE)],
    )
    tx.sign()
    res = node.accepts(_assert_fee_covers(tx, _FEE))
    assert res.get("allowed") is False, (
        f"consensus ACCEPTED a spend of the 100-byte container output — the removal rationale is wrong: {res}"
    )
    reason = str(res.get("reject-reason", ""))
    assert "EQUALVERIFY" in reason, f"rejected, but not by the P2PKH tail this control is testing: {res}"
    print(f"[case 4] legacy container spend reject-reason: {reason}")

    # ...and here is why, arithmetically: the tail compares these two values.
    child_ref_hash = hashlib.new("ripemd160", hashlib.sha256(legacy["child"]["ref"].to_bytes()).digest()).digest()
    assert child_ref_hash != bytes(legacy["owner_pkh"])


def test_the_consumed_child_singleton_can_never_be_re_minted(node, legacy):  # noqa: F811
    """Case 6b (NEGATIVE). The destruction is permanent.

    A singleton ref re-enters ``inputSingletonRefSet`` only from an input's
    ``0xd8`` push or an input outpoint. The legacy container holds it as a
    ``0xd0`` push and the child's genesis outpoint is long spent, so there is no
    transaction that can bring the NFT back.
    """
    assert "txid" in legacy, "depends on test_creating_a_legacy_container_consumes_the_child"
    dest = PrivateKey()
    tx = Transaction(
        tx_inputs=[
            TransactionInput(
                source_transaction=_src(legacy["txid"], 0, legacy["script"], _LEGACY_CARRIER),
                source_txid=legacy["txid"],
                source_output_index=0,
                unlocking_script_template=_p2pkh_unlock(legacy["owner"]),
            )
        ],
        tx_outputs=[
            TransactionOutput(
                Script(build_nft_locking_script(Hex20(dest.public_key().hash160()), legacy["child"]["ref"])),
                _LEGACY_CARRIER - _FEE,
            )
        ],
    )
    tx.sign()
    res = node.accepts(_assert_fee_covers(tx, _FEE))
    assert res.get("allowed") is False, f"consensus let the destroyed child NFT be re-minted: {res}"
    reason = str(res.get("reject-reason", ""))
    assert "invalid-transaction-reference-operations" in reason, (
        f"rejected, but not by the singleton rule this control is testing: {res}"
    )
    print(f"[case 6b] child re-mint reject-reason: {reason}")


def test_a_container_naming_a_live_ft_is_rejected_too(node):  # noqa: F811
    """Case 5b (NEGATIVE). The FT route is closed as well.

    Normal (``0xd0``) refs may be duplicated across outputs, so the sibling rule
    of case 5 does not apply to an FT — which makes "name an FT instead" the
    obvious next idea. It fails on the FT's own epilogue: that requires the ref's
    output count to equal the FT code-script-hash output count (one FT output,
    one ref), and a container output carrying the same ref breaks the equality.
    So there is no token type a container can name in its script and leave alive.
    """
    builder = GlyphBuilder()

    # Deploy a real FT — a fabricated script would not do, since consensus only
    # lets an output push a ref an input already carries.
    ft_owner = PrivateKey()
    ft_pkh = Hex20(ft_owner.public_key().hash160())
    ft_meta = GlyphMetadata(protocol=[GlyphProtocol.FT], name="CHILD-FT", ticker="CFT")
    ft_commit = builder.prepare_commit(
        CommitParams(metadata=ft_meta, owner_pkh=ft_pkh, change_pkh=ft_pkh, funding_satoshis=_COMMIT_VALUE)
    )
    ft_commit_txid = _pay_to_spk(node, ft_commit.commit_script, _COMMIT_VALUE)
    node.mine(1)
    ft_reveal_scripts = builder.prepare_ft_deploy_reveal(
        commit_txid=ft_commit_txid,
        commit_vout=0,
        commit_value=_COMMIT_VALUE,
        cbor_bytes=ft_commit.cbor_bytes,
        premine_pkh=ft_pkh,
        premine_amount=_COMMIT_VALUE - _FEE,
    )
    ft_reveal = Transaction(
        tx_inputs=[
            TransactionInput(
                source_transaction=_src(ft_commit_txid, 0, ft_commit.commit_script, _COMMIT_VALUE),
                source_txid=ft_commit_txid,
                source_output_index=0,
                unlocking_script_template=_reveal_unlock(ft_owner, ft_reveal_scripts.scriptsig_suffix),
            )
        ],
        tx_outputs=[TransactionOutput(Script(ft_reveal_scripts.locking_script), _COMMIT_VALUE - _FEE)],
    )
    ft_reveal.sign()
    raw = _assert_fee_covers(ft_reveal, _FEE)
    assert node.accepts(raw).get("allowed") is True
    ft_txid = str(node.cli("sendrawtransaction", raw))
    node.mine(1)
    ft_ref = GlyphRef(txid=ft_commit_txid, vout=0)
    ft_value = _COMMIT_VALUE - _FEE

    # Now a container that names the FT's ref, with the FT kept alive beside it.
    owner = PrivateKey()
    owner_pkh = Hex20(owner.public_key().hash160())
    meta = GlyphMetadata(
        protocol=[GlyphProtocol.NFT, GlyphProtocol.CONTAINER], name="FT-COLLECTION", token_type="container"
    )
    commit = builder.prepare_commit(
        CommitParams(metadata=meta, owner_pkh=owner_pkh, change_pkh=owner_pkh, funding_satoshis=_COMMIT_VALUE)
    )
    commit_txid = _pay_to_spk(node, commit.commit_script, _COMMIT_VALUE)
    node.mine(1)
    scripts = builder.prepare_container_reveal(commit_txid, 0, commit.cbor_bytes, owner_pkh)
    dead_script = _legacy_container_script(ft_ref, scripts.ref, owner_pkh)

    tx = Transaction(
        tx_inputs=[
            TransactionInput(
                source_transaction=_src(commit_txid, 0, commit.commit_script, _COMMIT_VALUE),
                source_txid=commit_txid,
                source_output_index=0,
                unlocking_script_template=_reveal_unlock(owner, scripts.scriptsig_suffix),
            ),
            TransactionInput(
                source_transaction=_src(ft_txid, 0, ft_reveal_scripts.locking_script, ft_value),
                source_txid=ft_txid,
                source_output_index=0,
                unlocking_script_template=_p2pkh_unlock(ft_owner),
            ),
        ],
        tx_outputs=[
            TransactionOutput(Script(dead_script), _CARRIER),
            TransactionOutput(Script(build_ft_locking_script(ft_pkh, ft_ref)), ft_value),
            TransactionOutput(P2PKH().lock(owner.public_key().hash160()), _COMMIT_VALUE - _CARRIER - _FEE),
        ],
    )
    tx.sign()
    res = node.accepts(_assert_fee_covers(tx, _FEE))
    assert res.get("allowed") is False, f"consensus ACCEPTED a container naming a live FT: {res}"
    reason = str(res.get("reject-reason", ""))
    assert "NUMEQUALVERIFY" in reason or "invalid-transaction-reference" in reason, (
        f"rejected, but not by the FT conservation rule this control is testing: {res}"
    )
    print(f"[case 5b] container naming a live FT reject-reason: {reason}")


# --------------------------------------------------------------------------- 7. not enforced


def test_membership_is_advisory_not_consensus_enforced(node, container):  # noqa: F811
    """Case 7 (NEGATIVE control on the claim, not the chain).

    A token may declare ``in`` for a container it never spent, and the chain
    confirms it without complaint. Nothing about ``in`` is enforced — which is
    why the reveal shape of case 2 (spend + re-create the container) matters:
    it is what lets a *reader* tell the two apart.
    """
    owner = PrivateKey()
    owner_pkh = Hex20(owner.public_key().hash160())
    builder = GlyphBuilder()
    metadata = GlyphMetadata(
        protocol=[GlyphProtocol.NFT],
        name="SQUATTER",
        container_refs=(container["ref"],),
    )
    commit = builder.prepare_commit(
        CommitParams(metadata=metadata, owner_pkh=owner_pkh, change_pkh=owner_pkh, funding_satoshis=_COMMIT_VALUE)
    )
    commit_txid = _pay_to_spk(node, commit.commit_script, _COMMIT_VALUE)
    node.mine(1)

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
    reveal = Transaction(
        tx_inputs=[
            TransactionInput(
                source_transaction=_src(commit_txid, 0, commit.commit_script, _COMMIT_VALUE),
                source_txid=commit_txid,
                source_output_index=0,
                unlocking_script_template=_reveal_unlock(owner, scripts.scriptsig_suffix),
            )
        ],
        tx_outputs=[TransactionOutput(Script(scripts.locking_script), _COMMIT_VALUE - _FEE)],
    )
    reveal.sign()
    raw = _assert_fee_covers(reveal, _FEE)
    assert node.accepts(raw).get("allowed") is True, "a forged membership claim was rejected — unexpected"
    txid = str(node.cli("sendrawtransaction", raw))
    node.mine(1)

    # It decodes, it names the collection, and the chain does not care.
    assert _envelope_from_confirmed(node, txid).container_refs == (container["ref"],)
    # But the container's ref is nowhere in this reveal's outputs, so the check
    # an indexer applies fails and the claim is discarded.
    assert container["ref"].to_bytes() not in _output_refs(node, txid)


def test_envelope_cbor_is_photonic_shaped(node, container, member):  # noqa: F811
    """Interop: ``in`` must be a list of 36-byte wire refs, not a text form.

    Photonic compares the raw bytes; any other encoding silently drops the
    membership on every wallet but ours.
    """
    raw = bytes.fromhex(str(node.cli("getrawtransaction", member["reveal_txid"])))
    tx = Transaction.from_hex(raw)
    assert tx is not None
    envelope = None
    for inp in tx.inputs:
        sig_script = inp.unlocking_script.serialize() if inp.unlocking_script else b""
        parsed = INSPECTOR.extract_reveal_metadata(sig_script)
        if parsed is not None:
            envelope = sig_script
            break
    assert envelope is not None
    # Pull the CBOR push straight out of the scriptSig and inspect it raw.
    marker = envelope.find(b"gly")
    assert marker > 0
    cbor_start = marker + 3
    length_byte = envelope[cbor_start]
    if length_byte <= 75:
        payload = envelope[cbor_start + 1 : cbor_start + 1 + length_byte]
    else:  # OP_PUSHDATA1
        assert length_byte == 0x4C
        n = envelope[cbor_start + 1]
        payload = envelope[cbor_start + 2 : cbor_start + 2 + n]
    decoded = cbor2.loads(payload)
    assert isinstance(decoded["in"], list)
    assert decoded["in"] == [container["ref"].to_bytes()]
    assert decode_payload(payload).container_refs == (container["ref"],)
