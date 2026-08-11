"""Live-regtest CONSENSUS proof for MUT (mutable NFT) and WAVE reveals.

``GlyphBuilder.prepare_mutable_reveal`` and ``prepare_wave_reveal`` are
script-emitting reveal builders — the same class of builder that shipped
``prepare_container_reveal(child_ref=...)``, whose output was permanently
unspendable and whose creation destroyed the child token. Neither had ever been
shown to a node. Put to one, they were broken:

**Every MUT/WAVE reveal built as the docstring described was rejected by
consensus.** The two output scripts carried the *same* 36-byte ref under
``OP_PUSHINPUTREFSINGLETON``, and a transaction may not have two outputs
claiming one singleton ref (``CScript::GetPushRefs`` files a ``0xd8`` ref into
``foundDisallowedSiblingRefs`` as well as the push-ref set; see
``validateTransactionReferenceOperations``). Case 1 holds that finding down.
Independently, the mutable contract's own body recomputes the token ref as
``mutable_ref.vout - 1``, so an equal pair could never have matched even with
the sibling rule repaired — case 2.

Fixing the reveal exposed a second, deeper defect, in the *core signing* path:
pyrxd's BIP143 ``hashOutputHashes`` ref walker skipped the 36-byte operand of
``OP_REQUIREINPUTREF`` / ``OP_DISALLOWPUSHINPUTREF`` /
``OP_DISALLOWPUSHINPUTREFSIBLING``, desynchronising from consensus on any output
carrying one, and producing an invalid signature. Case 7.

What each case proves:

1. **NEGATIVE — the shape shipped through 0.15.0 is rejected.** Two outputs, one ref. Built
   by hand, because the builder no longer emits it and the reason it does not
   has to keep being demonstrated.
2. **The contract computes ``token_ref = mutable_ref - 1``.** Read straight off
   the confirmed reveal, so the ``+1`` is pinned as chain arithmetic, not taste.
3. **The corrected reveal confirms**, and both token outputs survive it.
4. **Both outputs are discoverable** — ``find_glyphs`` classifies them ``nft``
   and ``mut``, and the envelope is recoverable from the confirmed scriptSig.
5. **The NFT output is spendable** with the ordinary transfer builder, ref
   intact. An unspendable output was half the CONTAINER bug.
6. **The mutation path works**: a ``mod`` spend installs a new payload hash, and
   the chain shows it. Plus two negative controls on the covenant's own binds.
7. **NEGATIVE + regression — signing over a ref-operand output.** A transaction
   paying to a script with ``OP_DISALLOWPUSHINPUTREF`` must be signable.
8. **WAVE**: the reveal confirms and the name resolves out of the envelope.

Opt-in: ``@pytest.mark.integration`` + ``RADIANT_REGTEST=1``. Never runs in
normal CI. Manages its own throwaway container; moves no real value. No PoW, so
this is seconds.

Run: ``RADIANT_REGTEST=1 pytest tests/test_mut_wave_regtest_e2e.py -m integration -s``
"""

from __future__ import annotations

import hashlib

import pytest

# Reuse the isolated-regtest harness wholesale (same pattern as the container,
# FT-airdrop and dMint e2e tests): the ``node`` fixture spins up + tears down a
# throwaway container.
from test_htlc_regtest_e2e import (  # noqa: F401  (node = fixture)
    _RELAY_FEE_SATS,
    _biggest_utxo,
    _p2pkh_unlock,
    _RegtestNode,
    _src,
    node,
)

from pyrxd.glyph.builder import CommitParams, GlyphBuilder, TransferParams
from pyrxd.glyph.inspector import GlyphInspector
from pyrxd.glyph.payload import build_mutable_scriptsig, encode_payload
from pyrxd.glyph.script import (
    build_mutable_nft_script,
    build_nft_locking_script,
    hash_payload,
    is_nft_script,
    parse_mutable_nft_script,
)
from pyrxd.glyph.types import GlyphMetadata, GlyphProtocol, GlyphRef
from pyrxd.glyph.wave import build_wave_metadata, classify_glyph_metadata, wave_attrs_from_metadata
from pyrxd.keys import PrivateKey
from pyrxd.script.script import Script
from pyrxd.script.type import P2PKH, encode_pushdata, to_unlock_script_template
from pyrxd.security.types import Hex20
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_input import TransactionInput
from pyrxd.transaction.transaction_output import TransactionOutput
from pyrxd.transaction.transaction_preimage import _get_push_refs

pytestmark = pytest.mark.integration

# Radiant's relay floor is 10,000 photons per byte of ``GetTotalSize()`` — not
# vsize — and there is neither RBF nor CPFP, so an underpaid transaction cannot
# be repaired and holds its inputs until the 8-hour mempool expiry. Every
# transaction here therefore pays a flat, generous fee AND is checked against
# its own serialized length before broadcast (:func:`_assert_fee_covers`).
_MIN_FEE_RATE = 10_000
_FEE = 20_000_000  # 0.2 RXD — covers ~2 KB at the relay floor
_COMMIT_VALUE = 200_000_000  # 2 RXD into the commit; funds the reveal + carriers
_SEED_VALUE = 10_000_000  # the second commit outpoint, which seeds the contract ref
_CARRIER = 10_000_000  # photons parked on a token output (Radiant has no dust rule)

INSPECTOR = GlyphInspector()


# --------------------------------------------------------------------------- helpers


def _assert_fee_covers(tx: Transaction, fee: int) -> str:
    """Serialize *tx*, check the fee against the REAL byte length, return the hex."""
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


def _raw_unlock(script_bytes: bytes):
    """A fixed, signature-less scriptSig — how a covenant input is unlocked."""
    return to_unlock_script_template(lambda tx, idx: Script(script_bytes), lambda: len(script_bytes))


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


def _pay_outputs(rt: _RegtestNode, outputs: list[tuple[bytes, int]]) -> str:
    """Broadcast a wallet-funded tx paying ``outputs`` at successive vouts.

    ``_pay_to_spk`` in the HTLC harness only ever emits one destination at vout
    0. A MUT commit needs TWO consecutive outpoints — the commit hashlock at
    ``vout`` and a plain seed at ``vout + 1`` whose spend puts the contract's
    singleton ref into the transaction's input ref set — so this one takes a
    list. Change lands after them; the caller must not assume its index.
    """
    u = _biggest_utxo(rt)
    wif = rt.cli("dumpprivkey", u["address"], wallet=True)
    key = PrivateKey(str(wif))
    spk = bytes.fromhex(u["scriptPubKey"])
    in_sats = round(u["amount"] * 1e8)
    fin = TransactionInput(
        source_transaction=_src(u["txid"], u["vout"], spk, in_sats),
        source_txid=u["txid"],
        source_output_index=u["vout"],
        unlocking_script_template=_p2pkh_unlock(key),
    )
    fin.satoshis = in_sats
    fin.locking_script = Script(spk)
    change = in_sats - sum(v for _, v in outputs) - _RELAY_FEE_SATS
    assert change > 546, f"change {change} too small"
    tx = Transaction(
        tx_inputs=[fin],
        tx_outputs=[TransactionOutput(Script(s), v) for s, v in outputs]
        + [TransactionOutput(P2PKH().lock(key.public_key().hash160()), change)],
    )
    tx.sign()
    txid = rt.cli("sendrawtransaction", tx.serialize().hex())
    assert isinstance(txid, str), f"funding broadcast failed: {txid}"
    rt.mine(1)
    return txid


def _auth_token_script(mutable_ref: GlyphRef, scriptsig_hash: bytes, token_ref: GlyphRef, pkh: Hex20) -> bytes:
    """Photonic's ``nftAuthScript`` — the token shape a ``mod`` spend requires.

    ``OP_REQUIREINPUTREF <mutable_ref> <sha256(contract scriptSig)> OP_2DROP``
    as the STATE part, then the ordinary singleton + P2PKH after the separator.
    The mutable covenant reads bytes ``[1:70]`` of that state script and demands
    they equal ``mutable_ref || 0x20 || sha256(OP_INPUTBYTECODE)`` — which is why
    ``ref_hash_index`` is 1 (it skips the ``0xd1`` opcode byte).

    pyrxd has no builder for this shape; spelled out here so the mutation path
    can be exercised at all. 135 bytes.
    """
    script = (
        b"\xd1"
        + mutable_ref.to_bytes()  # OP_REQUIREINPUTREF <ref>
        + b"\x20"
        + scriptsig_hash  # PUSH32 <sha256(scriptSig)>
        + b"\x6d"  # OP_2DROP
        + b"\xbd"  # OP_STATESEPARATOR
        + b"\xd8"
        + token_ref.to_bytes()  # OP_PUSHINPUTREFSINGLETON <token ref>
        + b"\x75"  # OP_DROP
        + b"\x76\xa9\x14"
        + bytes(pkh)
        + b"\x88\xac"
    )
    assert len(script) == 135
    return script


def _mint_mut(rt: _RegtestNode, metadata: GlyphMetadata, *, name: str | None = None) -> dict:
    """Commit + reveal a MUT (or WAVE) token in the shape consensus accepts.

    Two inputs — the commit outpoint and the seed outpoint one vout along — and
    two token outputs. Returns everything later cases need to keep spending.
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
    # The seed output at commit_vout+1 is what makes the contract's singleton ref
    # spendable-into-existence. Held under a throwaway key of our own.
    seed_key = PrivateKey()
    seed_spk = P2PKH().lock(seed_key.public_key().hash160()).serialize()
    commit_txid = _pay_outputs(rt, [(commit.commit_script, _COMMIT_VALUE), (seed_spk, _SEED_VALUE)])

    if name is None:
        scripts = builder.prepare_mutable_reveal(commit_txid, 0, commit.cbor_bytes, owner_pkh)
    else:
        scripts = builder.prepare_wave_reveal(commit_txid, 0, commit.cbor_bytes, owner_pkh, name)

    change = _COMMIT_VALUE + _SEED_VALUE - 2 * _CARRIER - _FEE
    reveal = Transaction(
        tx_inputs=[
            TransactionInput(
                source_transaction=_src(commit_txid, 0, commit.commit_script, _COMMIT_VALUE),
                source_txid=commit_txid,
                source_output_index=0,
                unlocking_script_template=_reveal_unlock(owner, scripts.scriptsig_suffix),
            ),
            TransactionInput(
                source_transaction=_src(commit_txid, 1, seed_spk, _SEED_VALUE),
                source_txid=commit_txid,
                source_output_index=1,
                unlocking_script_template=_p2pkh_unlock(seed_key),
            ),
        ],
        tx_outputs=[
            TransactionOutput(Script(scripts.nft_script), _CARRIER),
            TransactionOutput(Script(scripts.contract_script), _CARRIER),
            TransactionOutput(P2PKH().lock(owner.public_key().hash160()), change),
        ],
    )
    reveal.sign()
    raw = _assert_fee_covers(reveal, _FEE)
    res = rt.accepts(raw)
    assert res.get("allowed") is True, f"MUT reveal REJECTED by consensus: {res}"
    reveal_txid = str(rt.cli("sendrawtransaction", raw))
    rt.mine(1)

    return {
        "scripts": scripts,
        "cbor": commit.cbor_bytes,
        "commit_txid": commit_txid,
        "commit_script": commit.commit_script,
        "reveal_txid": reveal_txid,
        "ref": scripts.ref,
        "mutable_ref": scripts.mutable_ref,
        "nft_script": scripts.nft_script,
        "contract_script": scripts.contract_script,
        "nft_value": _CARRIER,
        "contract_value": _CARRIER,
        "change_value": change,
        "key": owner,
        "pkh": owner_pkh,
    }


def _mut_metadata() -> GlyphMetadata:
    return GlyphMetadata(
        protocol=[GlyphProtocol.NFT, GlyphProtocol.MUT],
        name="REGTEST-MUTABLE",
        description="regtest mutable-NFT fixture",
    )


@pytest.fixture(scope="module")
def mut(node):  # noqa: F811
    """A real mutable NFT on the regtest chain.

    Later cases move its outputs, so ``reveal_txid`` is the immutable mint tx and
    the per-output outpoints are tracked in the dict.
    """
    return _mint_mut(node, _mut_metadata())


# --------------------------------------------------------------------------- 1-2. the defect


def test_the_two_reveal_outputs_may_not_share_a_singleton_ref(node):  # noqa: F811
    """Case 1 (NEGATIVE). The decisive finding: the reveal shipped through 0.15.0 is dead.

    pyrxd 0.9.0-0.15.0 gave ``prepare_mutable_reveal``'s NFT script and mutable
    contract the SAME ref, and told the caller to put both in one reveal. Every
    such transaction is rejected: ``OP_PUSHINPUTREFSINGLETON`` registers its ref
    as a disallowed *sibling* as well as a push ref, and
    ``validateTransactionReferenceOperations`` refuses a second output claiming
    it. Built here by hand, because the builder no longer emits it.

    Nothing is lost when this fires — the commit output is still spendable by
    its owner — but no MUT or WAVE token could be minted at all.
    """
    owner = PrivateKey()
    owner_pkh = Hex20(owner.public_key().hash160())
    builder = GlyphBuilder()
    commit = builder.prepare_commit(
        CommitParams(
            metadata=_mut_metadata(),
            owner_pkh=owner_pkh,
            change_pkh=owner_pkh,
            funding_satoshis=_COMMIT_VALUE,
        )
    )
    seed_key = PrivateKey()
    seed_spk = P2PKH().lock(seed_key.public_key().hash160()).serialize()
    commit_txid = _pay_outputs(node, [(commit.commit_script, _COMMIT_VALUE), (seed_spk, _SEED_VALUE)])
    scripts = builder.prepare_mutable_reveal(commit_txid, 0, commit.cbor_bytes, owner_pkh)

    # The contract script pyrxd emitted through 0.15.0: same ref as the NFT.
    dead_contract = build_mutable_nft_script(scripts.ref, scripts.payload_hash)
    assert dead_contract[36:72] == scripts.nft_script[1:37], "this control must use the SAME ref in both outputs"

    tx = Transaction(
        tx_inputs=[
            TransactionInput(
                source_transaction=_src(commit_txid, 0, commit.commit_script, _COMMIT_VALUE),
                source_txid=commit_txid,
                source_output_index=0,
                unlocking_script_template=_reveal_unlock(owner, scripts.scriptsig_suffix),
            ),
            TransactionInput(
                source_transaction=_src(commit_txid, 1, seed_spk, _SEED_VALUE),
                source_txid=commit_txid,
                source_output_index=1,
                unlocking_script_template=_p2pkh_unlock(seed_key),
            ),
        ],
        tx_outputs=[
            TransactionOutput(Script(scripts.nft_script), _CARRIER),
            TransactionOutput(Script(dead_contract), _CARRIER),
            TransactionOutput(
                P2PKH().lock(owner.public_key().hash160()), _COMMIT_VALUE + _SEED_VALUE - 2 * _CARRIER - _FEE
            ),
        ],
    )
    tx.sign()
    res = node.accepts(_assert_fee_covers(tx, _FEE))
    assert res.get("allowed") is False, (
        f"consensus ACCEPTED two outputs claiming one singleton ref — the whole rationale for the "
        f"ref change is wrong: {res}"
    )
    reason = str(res.get("reject-reason", ""))
    assert "invalid-transaction-reference-operations" in reason, (
        f"rejected, but not by the sibling-ref rule this control is testing: {res}"
    )
    print(f"[case 1] same-ref MUT reveal reject-reason: {reason}")


def test_the_contract_derives_the_token_ref_by_subtracting_one(node, mut):  # noqa: F811
    """Case 2. ``mutable_ref.vout == ref.vout + 1`` is chain arithmetic.

    The covenant's first seven opcodes are ``OP_DUP 20 OP_SPLIT OP_BIN2NUM
    OP_1SUB OP_4 OP_NUM2BIN OP_CAT`` — split the ref at 32, read the 4-byte LE
    vout, subtract one, re-concatenate. That derived value is what the contract
    then looks for among the token output's refs. So the ``+1`` is not a
    convention that could have been chosen differently; equal refs would make
    the contract hunt for ``vout - 1`` and match nothing.

    Read back off the confirmed reveal rather than off the builder's return.
    """
    confirmed = _confirmed(node, mut["reveal_txid"])
    nft_spk = _out_spk(confirmed, 0)
    contract_spk = _out_spk(confirmed, 1)

    parsed = parse_mutable_nft_script(contract_spk)
    assert parsed is not None, "the mutable contract output did not parse"
    contract_ref, payload_hash = parsed
    token_ref = GlyphRef.from_bytes(nft_spk[1:37])

    assert contract_ref.txid == token_ref.txid
    assert contract_ref.vout == token_ref.vout + 1
    assert payload_hash == hash_payload(mut["cbor"])

    # And the derivation the covenant performs, done here in Python: strip the
    # 4-byte LE vout off the contract's ref, subtract one, re-attach.
    raw = contract_ref.to_bytes()
    derived = raw[:32] + (int.from_bytes(raw[32:36], "little") - 1).to_bytes(4, "little")
    assert derived == token_ref.to_bytes()


# --------------------------------------------------------------------------- 3-4. the reveal


def test_mut_reveal_confirms_with_both_token_outputs_intact(node, mut):  # noqa: F811
    """Case 3. Both singletons coexist — because they are different refs."""
    confirmed = _confirmed(node, mut["reveal_txid"])
    nft_spk = _out_spk(confirmed, 0)
    contract_spk = _out_spk(confirmed, 1)

    assert len(nft_spk) == 63, f"expected the plain NFT singleton, got {len(nft_spk)} bytes"
    assert len(contract_spk) == 174, f"expected the 174-byte mutable contract, got {len(contract_spk)} bytes"
    assert nft_spk == build_nft_locking_script(mut["pkh"], mut["ref"])
    assert contract_spk == build_mutable_nft_script(mut["mutable_ref"], hash_payload(mut["cbor"]))
    assert nft_spk[0] == 0xD8 and contract_spk[35] == 0xD8
    assert nft_spk[1:37] != contract_spk[36:72]


def test_both_mut_outputs_are_discoverable(node, mut):  # noqa: F811
    """Case 4. ``find_glyphs`` sees a token, not two unrecognised scripts.

    The CONTAINER shape was invisible to every classifier, which is how it went
    five releases without anyone noticing it was dead.
    """
    confirmed = _confirmed(node, mut["reveal_txid"])
    outputs = [(round(o["value"] * 1e8), bytes.fromhex(o["scriptPubKey"]["hex"])) for o in confirmed["vout"]]

    glyphs = INSPECTOR.find_glyphs(outputs)
    assert [g.glyph_type for g in glyphs] == ["nft", "mut"], f"unexpected classification: {glyphs}"
    assert glyphs[0].ref == mut["ref"]
    assert glyphs[0].spendable is True
    assert glyphs[1].ref == mut["mutable_ref"]


def test_mut_envelope_is_recoverable_and_classifies_as_mut(node, mut):  # noqa: F811
    """Case 4. Mutability is an envelope property — recover it from the chain."""
    metadata = _envelope_from_confirmed(node, mut["reveal_txid"])
    assert GlyphProtocol.MUT in metadata.protocol
    assert GlyphProtocol.NFT in metadata.protocol
    assert classify_glyph_metadata(metadata) == "mut"
    assert metadata.name == "REGTEST-MUTABLE"


# --------------------------------------------------------------------------- 5. spendable


def test_the_nft_output_is_spendable(node):  # noqa: F811
    """Case 5. The token half transfers with the ordinary NFT builder.

    A separate mint, so the module-scoped ``mut`` fixture's outpoints stay put
    for the mutation cases. An output that confirms but cannot be spent is a
    fund trap, not a token — that was half the CONTAINER bug.
    """
    minted = _mint_mut(node, _mut_metadata())
    new_owner = PrivateKey()
    new_pkh = Hex20(new_owner.public_key().hash160())

    result = GlyphBuilder().build_nft_transfer_tx(
        TransferParams(
            nft_script=minted["nft_script"],
            nft_utxo_txid=minted["reveal_txid"],
            nft_utxo_vout=0,
            nft_utxo_value=minted["nft_value"],
            new_owner_pkh=new_pkh,
            private_key=minted["key"],
            fee_rate=_MIN_FEE_RATE,
        )
    )
    raw = result.tx.serialize().hex()
    res = node.accepts(raw)
    assert res.get("allowed") is True, f"MUT token transfer REJECTED: {res}"
    txid = str(node.cli("sendrawtransaction", raw))
    node.mine(1)

    spk = _out_spk(_confirmed(node, txid), 0)
    assert spk == build_nft_locking_script(new_pkh, minted["ref"])
    assert spk[1:37] == minted["ref"].to_bytes(), "the token's ref must survive the transfer"
    assert is_nft_script(spk.hex())


# --------------------------------------------------------------------------- 6. mutation


def _mod_tx(
    minted: dict,
    new_cbor: bytes,
    *,
    token_script_override: bytes | None = None,
    contract_script_override: bytes | None = None,
) -> Transaction:
    """Build the ``mod`` spend: install ``new_cbor``'s hash in the contract.

    Input order follows Photonic (``packages/lib/src/mint.ts``): the NFT first,
    the contract second, funding last — so ``OP_INPUTINDEX`` inside the covenant
    is 1 and the scriptSig it hashes is the contract's own. That scriptSig
    carries no signature, so it is known before signing and there is no
    circularity in committing to its hash from an output.
    """
    scriptsig = build_mutable_scriptsig(
        "mod",
        new_cbor,
        contract_output_index=1,
        ref_hash_index=1,  # skips the OP_REQUIREINPUTREF opcode byte
        ref_index=0,  # the token output carries exactly one push ref
        token_output_index=0,
    )
    new_pkh = Hex20(minted["key"].public_key().hash160())
    token_out = token_script_override or _auth_token_script(
        minted["mutable_ref"], hashlib.sha256(scriptsig).digest(), minted["ref"], new_pkh
    )
    contract_out = contract_script_override or build_mutable_nft_script(minted["mutable_ref"], hash_payload(new_cbor))
    p2pkh_spk = P2PKH().lock(minted["key"].public_key().hash160()).serialize()

    tx = Transaction(
        tx_inputs=[
            TransactionInput(
                source_transaction=_src(minted["reveal_txid"], 0, minted["nft_script"], minted["nft_value"]),
                source_txid=minted["reveal_txid"],
                source_output_index=0,
                unlocking_script_template=_p2pkh_unlock(minted["key"]),
            ),
            TransactionInput(
                source_transaction=_src(minted["reveal_txid"], 1, minted["contract_script"], minted["contract_value"]),
                source_txid=minted["reveal_txid"],
                source_output_index=1,
                unlocking_script_template=_raw_unlock(scriptsig),
            ),
            TransactionInput(
                source_transaction=_src(minted["reveal_txid"], 2, p2pkh_spk, minted["change_value"]),
                source_txid=minted["reveal_txid"],
                source_output_index=2,
                unlocking_script_template=_p2pkh_unlock(minted["key"]),
            ),
        ],
        tx_outputs=[
            TransactionOutput(Script(token_out), minted["nft_value"]),
            TransactionOutput(Script(contract_out), minted["contract_value"]),
            TransactionOutput(Script(p2pkh_spk), minted["change_value"] - _FEE),
        ],
    )
    tx.sign()
    return tx


def test_mod_installs_a_new_payload_hash_on_chain(node, mut):  # noqa: F811
    """Case 6. The mutation path, end to end.

    The contract UTXO is spent with no signature at all — what gates it is the
    ref-induction rule: the token output re-pushes the NFT's singleton, which is
    only legal if the P2PKH-locked NFT is co-spent. So "who may mutate" is
    "whoever holds the token", enforced by consensus rather than by a key check
    inside the covenant.
    """
    new_metadata = GlyphMetadata(
        protocol=[GlyphProtocol.NFT, GlyphProtocol.MUT],
        name="REGTEST-MUTABLE",
        description="mutated on regtest",
    )
    new_cbor, new_hash = encode_payload(new_metadata)
    assert new_hash != hash_payload(mut["cbor"]), "the mutation must actually change the payload"

    tx = _mod_tx(mut, new_cbor)
    raw = _assert_fee_covers(tx, _FEE)
    res = node.accepts(raw)
    assert res.get("allowed") is True, f"mod spend of the mutable contract REJECTED: {res}"
    txid = str(node.cli("sendrawtransaction", raw))
    node.mine(1)

    confirmed = _confirmed(node, txid)
    contract_spk = _out_spk(confirmed, 1)
    parsed = parse_mutable_nft_script(contract_spk)
    assert parsed is not None
    contract_ref, payload_hash = parsed
    assert contract_ref == mut["mutable_ref"], "the contract id must survive a mutation"
    assert payload_hash == new_hash, "the new payload hash is not what the chain stored"

    # The token output is the auth shape the covenant demands, and it still
    # carries the same token ref — the identity did not move.
    token_spk = _out_spk(confirmed, 0)
    assert len(token_spk) == 135
    assert token_spk[0] == 0xD1  # OP_REQUIREINPUTREF <mutable_ref>
    assert token_spk[1:37] == mut["mutable_ref"].to_bytes()
    assert token_spk[73:109] == mut["ref"].to_bytes()

    mut["reveal_txid"] = txid
    mut["nft_script"] = token_spk
    mut["contract_script"] = contract_spk
    mut["change_value"] = mut["change_value"] - _FEE
    mut["cbor"] = new_cbor


def test_mod_against_a_plain_nft_token_output_is_rejected(node):  # noqa: F811
    """Case 6 (NEGATIVE). The covenant will not accept the shape pyrxd can build.

    ``build_nft_locking_script`` emits a 63-byte script with no
    ``OP_STATESEPARATOR``, so ``OP_STATESCRIPTBYTECODE_OUTPUT`` pushes an empty
    item and the covenant's 69-byte read runs off the end. This is why
    :func:`_auth_token_script` has to exist in this file: pyrxd has no builder
    for the token shape a mutation requires.
    """
    minted = _mint_mut(node, _mut_metadata())
    new_cbor, _ = encode_payload(
        GlyphMetadata(protocol=[GlyphProtocol.NFT, GlyphProtocol.MUT], name="REGTEST-MUTABLE", description="v2")
    )
    plain = build_nft_locking_script(Hex20(minted["key"].public_key().hash160()), minted["ref"])
    tx = _mod_tx(minted, new_cbor, token_script_override=plain)

    res = node.accepts(_assert_fee_covers(tx, _FEE))
    assert res.get("allowed") is False, f"consensus ACCEPTED a mod with a stateless token output: {res}"
    reason = str(res.get("reject-reason", ""))
    assert "OP_SPLIT" in reason, f"rejected, but not by the state-script read this control is testing: {res}"
    print(f"[case 6a] mod with a plain NFT token output reject-reason: {reason}")


def test_mod_that_lies_about_the_new_payload_hash_is_rejected(node):  # noqa: F811
    """Case 6 (NEGATIVE). The covenant binds the hash to the CBOR it was given.

    Without this, ``mod`` would be a free-form rewrite: any state could be
    installed regardless of the metadata pushed in the scriptSig, and the
    payload hash would prove nothing about the payload.
    """
    minted = _mint_mut(node, _mut_metadata())
    new_cbor, _ = encode_payload(
        GlyphMetadata(protocol=[GlyphProtocol.NFT, GlyphProtocol.MUT], name="REGTEST-MUTABLE", description="v2")
    )
    _, other_hash = encode_payload(
        GlyphMetadata(protocol=[GlyphProtocol.NFT, GlyphProtocol.MUT], name="REGTEST-MUTABLE", description="LIE")
    )
    assert other_hash != hash_payload(new_cbor)
    # scriptSig announces new_cbor; the contract output installs a hash of
    # something else entirely.
    liar = build_mutable_nft_script(minted["mutable_ref"], other_hash)
    tx = _mod_tx(minted, new_cbor, contract_script_override=liar)

    res = node.accepts(_assert_fee_covers(tx, _FEE))
    assert res.get("allowed") is False, f"consensus ACCEPTED a mod whose state does not hash its own payload: {res}"
    reason = str(res.get("reject-reason", ""))
    assert "EQUALVERIFY" in reason, f"rejected, but not by the state-hash bind this control is testing: {res}"
    print(f"[case 6b] mod with a mismatched payload hash reject-reason: {reason}")


# --------------------------------------------------------------------------- 7. sighash walker

# A ref chosen to make the through-0.15.0 preimage walker fail DETERMINISTICALLY
# rather than ~80% of the time. That walker skipped OP_DISALLOWPUSHINPUTREF as a
# bare one-byte opcode and resumed inside the ref: here it would read four
# OP_1s and then a 0xd8, and collect the following 36 bytes as a PHANTOM push
# ref. A phantom ref changes ``hashOutputHashes``, which changes the sighash,
# which invalidates every signature in the transaction.
_ADVERSARIAL_REF = b"\x51\x51\x51\x51\xd8" + bytes(range(1, 32))
assert len(_ADVERSARIAL_REF) == 36


def test_signing_an_output_that_requires_a_ref(node):  # noqa: F811
    """Case 7 (REGRESSION). pyrxd must be able to sign over a ref-operand output.

    ``OP_DISALLOWPUSHINPUTREF`` / ``OP_REQUIREINPUTREF`` /
    ``OP_DISALLOWPUSHINPUTREFSIBLING`` each carry a 36-byte immediate operand
    (``GetScriptOp``), but only ``0xd0``/``0xd8`` refs go into the push-ref set
    the sighash hashes. The preimage walker must therefore WALK all five and
    COLLECT two — it used to collect two and walk two, so it desynchronised on
    any output carrying one of the other three and produced a signature the node
    rejects with NULLFAIL. Nothing pyrxd itself built hit this; paying to a
    Photonic auth token or delegate-burn script did.

    Asserted twice: on the walker directly (deterministic), and by putting the
    transaction to a node (the thing that actually decides).
    """
    dest = PrivateKey()
    spk = b"\xd2" + _ADVERSARIAL_REF + b"\x75" + P2PKH().lock(dest.public_key().hash160()).serialize()

    # The walker: no phantom, no real ref (0xd2 contributes to neither set).
    assert _get_push_refs(spk) == [], "the preimage walker invented a ref that consensus does not see"

    # Funded well above the relay floor so the spend below fails on the script if
    # it fails at all, never on an unpayable fee.
    funded = _COMMIT_VALUE
    txid = _pay_outputs(node, [(spk, funded)])
    confirmed = _confirmed(node, txid)
    assert _out_spk(confirmed, 0) == spk

    # ...and the output is real: spend it back out with an ordinary P2PKH unlock.
    out = Transaction(
        tx_inputs=[
            TransactionInput(
                source_transaction=_src(txid, 0, spk, funded),
                source_txid=txid,
                source_output_index=0,
                unlocking_script_template=_p2pkh_unlock(dest),
            )
        ],
        tx_outputs=[TransactionOutput(P2PKH().lock(PrivateKey().public_key().hash160()), funded - _FEE)],
    )
    out.sign()
    res = node.accepts(_assert_fee_covers(out, _FEE))
    assert res.get("allowed") is True, f"spending a ref-operand output REJECTED: {res}"


# --------------------------------------------------------------------------- 8. WAVE


@pytest.fixture(scope="module")
def wave(node):  # noqa: F811
    """A real WAVE name registration on the regtest chain."""
    target = PrivateKey().public_key().address()
    metadata = build_wave_metadata(
        qualified_name="regtest-alice.rxd",
        target=target,
        description="regtest WAVE fixture",
    )
    minted = _mint_mut(node, metadata, name="regtest-alice.rxd")
    minted["target"] = target
    return minted


def test_wave_reveal_confirms_with_the_same_two_output_shape(node, wave):  # noqa: F811
    """Case 8. ``prepare_wave_reveal`` delegates to the MUT builder — so it
    inherited the defect, and it inherits the fix."""
    confirmed = _confirmed(node, wave["reveal_txid"])
    nft_spk = _out_spk(confirmed, 0)
    contract_spk = _out_spk(confirmed, 1)
    assert len(nft_spk) == 63 and len(contract_spk) == 174
    assert nft_spk[1:37] != contract_spk[36:72]

    parsed = parse_mutable_nft_script(contract_spk)
    assert parsed is not None
    contract_ref, _ = parsed
    assert contract_ref.vout == GlyphRef.from_bytes(nft_spk[1:37]).vout + 1


def test_the_wave_name_resolves_off_the_confirmed_reveal(node, wave):  # noqa: F811
    """Case 8. The name is recoverable, in the shape an indexer expects.

    A bare node has no name index — resolution against RXinDexer is a network
    concern and out of scope here. What a node CAN settle is whether the
    registration a third party reads off the chain carries the Photonic-shaped
    ``attrs`` that resolution depends on. A token minted with only a top-level
    ``name`` confirms identically and is invisible to the indexer, so this is
    the assertion that separates the two.
    """
    metadata = _envelope_from_confirmed(node, wave["reveal_txid"])
    assert GlyphProtocol.WAVE in metadata.protocol
    assert GlyphProtocol.MUT in metadata.protocol
    assert classify_glyph_metadata(metadata) == "wave"

    attrs = wave_attrs_from_metadata(metadata)
    assert attrs is not None, "the registration is not indexer-visible — attrs.name is missing"
    assert attrs.name == "regtest-alice.rxd"
    assert attrs.domain == "rxd"
    assert attrs.target == wave["target"]
    assert attrs.target_type == "address"


def test_the_wave_token_is_discoverable_and_spendable(node, wave):  # noqa: F811
    """Case 8. A WAVE name is a transferable token, not a registry row."""
    confirmed = _confirmed(node, wave["reveal_txid"])
    outputs = [(round(o["value"] * 1e8), bytes.fromhex(o["scriptPubKey"]["hex"])) for o in confirmed["vout"]]
    assert [g.glyph_type for g in INSPECTOR.find_glyphs(outputs)] == ["nft", "mut"]

    new_owner = PrivateKey()
    new_pkh = Hex20(new_owner.public_key().hash160())
    result = GlyphBuilder().build_nft_transfer_tx(
        TransferParams(
            nft_script=wave["nft_script"],
            nft_utxo_txid=wave["reveal_txid"],
            nft_utxo_vout=0,
            nft_utxo_value=wave["nft_value"],
            new_owner_pkh=new_pkh,
            private_key=wave["key"],
            fee_rate=_MIN_FEE_RATE,
        )
    )
    raw = result.tx.serialize().hex()
    res = node.accepts(raw)
    assert res.get("allowed") is True, f"WAVE name transfer REJECTED: {res}"
    txid = str(node.cli("sendrawtransaction", raw))
    node.mine(1)
    assert _out_spk(_confirmed(node, txid), 0) == build_nft_locking_script(new_pkh, wave["ref"])

    # The registration still names the same target: a transfer moves custody of
    # the name, not what it points at.
    attrs = wave_attrs_from_metadata(_envelope_from_confirmed(node, wave["reveal_txid"]))
    assert attrs is not None and attrs.target == wave["target"]
