"""Live-regtest proof of the Glyph TIMELOCK lifecycle: seal -> wait -> reveal -> verify.

``tests/test_glyph_timelock_e2e.py`` walks the same lifecycle "using only pyrxd
primitives" — its own words — and every object in it is in-memory. That leaves the
one question a product built on this machinery actually turns on unanswered: **what
does a node do with it?** Seventeen timelock test files, and not one of them had ever
shown a mint to a node or asked whether an early reveal relays.

THE HEADLINE FINDING, and the reason this file exists:

    **The TIMELOCK is enforced ENTIRELY CLIENT-SIDE.** There is no covenant, no
    ``OP_CHECKLOCKTIMEVERIFY``, and no ``nLockTime`` anywhere on the reveal path. A
    reveal is a plain value-0 ``OP_RETURN`` funded by an ordinary P2PKH input
    (:func:`pyrxd.glyph.timelock_reveal_tx.build_timelock_reveal`), and the chain has
    no opinion whatever about ``unlock_at``, about ``sha256(cek)``, or about how many
    reveals a token gets. :class:`TestTheNodeHasNoOpinion` proves each of those three
    against a real node by BROADCASTING the thing that should not work and watching it
    confirm.

    So the guarantee on offer is: *nobody can read the sealed payload early, because
    nobody but the minter has the key* — a confidentiality property resting on key
    custody. It is NOT *the key cannot be published early*, which is what a covenant
    would buy and what the phrase "timelock" invites a reader to assume. Every refusal
    in :mod:`pyrxd.glyph.timelock_reveal_tx` is an honest-operator guard rail: it stops
    a mistake, not an adversary. ``allow_early=True`` walks past it, and so does any
    other tool, because the bytes it would broadcast are unremarkable.

What each case proves, and WHO enforces it:

1. :class:`TestTheSealIsAcceptedByTheNode` — a TIMELOCK mint relays, confirms, and its
   ``crypto.timelock`` commitment, mode and ``unlock_at`` are recoverable from the
   confirmed transaction by the same decode path ``pyrxd glyph timelock-reveal`` uses.
   **NODE-ENFORCED** that it relays; the envelope contents are pyrxd's.
2. :class:`TestBeforeExpiry` — ``plan_timelock_reveal`` refuses, against a real tip
   height read from the node, for both ``block`` and ``time`` modes.
   **PYRXD-ENFORCED, client-side, and that is the whole of it.**
3. :class:`TestTheNodeHasNoOpinion` — an early reveal, a reveal publishing the WRONG
   key, and a duplicate reveal, each broadcast and mined; plus a control case the node
   really does refuse, so the three acceptances are not a harness artefact.
   **NODE-MEASURED.**
4. :class:`TestAfterExpiry` — mine past ``unlock_at``; the same call that refused now
   returns a plan, and the reveal relays and confirms. **NODE-ENFORCED** relay;
   pyrxd-enforced gate.
5. :class:`TestThirdPartyVerification` — with nothing but the node's raw transaction
   bytes (plus the ciphertext, which the protocol says never goes on chain), recover
   the proof, validate it against the commitment read off the MINT transaction, and
   decrypt to the original plaintext. **This is the product-critical one**: it is what
   a verifier who was not present at mint time can do.
6. :class:`TestNegatives` — a wrong CEK fails ``verify_cek_reveal``; a reveal script
   tampered in its on-chain bytes fails ``validate_reveal_proof``; a proof for the
   wrong token fails. **PYRXD-ENFORCED** — see case 3 for what the node does with the
   same bytes.

Opt-in: ``@pytest.mark.integration`` + ``RADIANT_REGTEST=1``. Throwaway container,
no real value, no PoW.

Run: ``RADIANT_REGTEST=1 pytest tests/test_glyph_timelock_regtest_e2e.py -m integration -s``
"""

from __future__ import annotations

import os
import secrets

import pytest
from test_container_regtest_e2e import (
    _FEE,
    _MIN_FEE_RATE,
    _assert_fee_covers,
    _confirmed,
    _envelope_from_confirmed,
    _mint_nft,
)
from test_htlc_regtest_e2e import (  # noqa: F401  (node = fixture)
    _biggest_utxo,
    _p2pkh_unlock,
    _pay_to_spk,
    _RegtestNode,
    _src,
    node,
)

from pyrxd.crypto.aead import decrypt_chunked
from pyrxd.crypto.kem import unwrap_cek_x25519, x25519_public_key
from pyrxd.glyph.inspector import GlyphInspector
from pyrxd.glyph.timelock import (
    TimelockParams,
    TimelockRecipient,
    build_timelock_mint,
    cek_wrap_aad,
    compute_cek_hash,
    parse_cek_hash,
    spec_is_unlocked,
    spec_unlock_remaining,
    verify_cek_reveal,
)
from pyrxd.glyph.timelock_reveal_tx import (
    CekCommitmentMismatch,
    TimelockNotExpired,
    create_reveal_proof,
    parse_reveal_proof_script,
    plan_timelock_reveal,
    timelock_reveal_funding_bar,
    validate_reveal_proof,
)
from pyrxd.glyph.types import GlyphProtocol
from pyrxd.keys import PrivateKey
from pyrxd.script.script import Script
from pyrxd.security.types import Hex20
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_input import TransactionInput
from pyrxd.transaction.transaction_output import TransactionOutput

pytestmark = pytest.mark.integration

INSPECTOR = GlyphInspector()

#: The bytes being sealed. Long enough to be a real payload and short enough to stay
#: in one ``chunked-aead-v1`` chunk.
SEALED_PLAINTEXT = b"sealed bid: 12,345 RXD; bidder ref 7f3a; valid until settlement\n" * 3

#: ``unlock_at`` offset for the token whose lock is allowed to MATURE.
#:
#: Sized well ABOVE the blocks this file mines incidentally between that fixture and
#: :class:`TestAfterExpiry` (three per mint, one per broadcast) rather than just above
#: them, because the failure it guards against is silent. If the maturing token expired on its own before :class:`TestAfterExpiry` ran,
#: that class's "refused, then mined, then allowed" sequence would collapse into
#: "allowed" — still green, and no longer evidence of anything. :class:`TestAfterExpiry`
#: asserts the token is still locked when it starts, so drift fails loudly instead.
_MATURING_OFFSET = 60

#: ``unlock_at`` offset for the token that must stay locked for the whole run. Chosen
#: so that no amount of mining any test in this file does can reach it: the early-reveal
#: probes would silently become honest-reveal probes and pass for the wrong reason.
_FOREVER_OFFSET = 100_000


# --------------------------------------------------------------------------- helpers


def _tip(rt: _RegtestNode) -> int:
    """The node's own tip height — the clock the gate is judged against."""
    return int(rt.cli("getblockcount"))  # type: ignore[arg-type]


def _tip_time(rt: _RegtestNode) -> int:
    """The tip header's unix timestamp, for a ``mode="time"`` lock.

    ``GlyphClient.plan_timelock_reveal`` takes this from an ElectrumX header; here it
    comes from the node directly. Either way it is a number the SDK does not
    authenticate — see ``TimelockRevealPlan.judged_at``.
    """
    tip_hash = str(rt.cli("getbestblockhash"))
    header = rt.cli("getblockheader", tip_hash)
    assert isinstance(header, dict), header
    return int(header["time"])


def _seal(rt: _RegtestNode, *, unlock_offset: int, mode: str = "block", recipient_sk: bytes | None = None) -> dict:
    """Seal a payload, mint the token that commits to its key, and read it back.

    Goes through :func:`pyrxd.glyph.timelock.build_timelock_mint` — the production
    one-shot entry point ``GlyphClient.mint_timelocked_nft`` and ``pyrxd glyph
    timelock-mint`` both call — and then through the ordinary NFT commit/reveal mint.
    Nothing timelock-specific happens at the transaction layer, which is itself the
    finding: the mint is an NFT mint whose envelope happens to carry ``crypto.timelock``.
    """
    base = _tip(rt) if mode == "block" else _tip_time(rt)
    unlock_at = base + unlock_offset
    recipients = ()
    if recipient_sk is not None:
        recipients = (TimelockRecipient(kid="auctioneer-1", public_key=x25519_public_key(recipient_sk)),)

    build = build_timelock_mint(
        name="REGTEST-SEALED",
        content_type="text/plain",
        plaintext=SEALED_PLAINTEXT,
        params=TimelockParams(mode=mode, unlock_at=unlock_at, hint="opens at settlement"),  # type: ignore[arg-type]
        recipients=recipients,
    )
    token = _mint_nft(rt, build.metadata)
    token_ref = f"{token['ref'].txid}:{token['ref'].vout}"

    # Read the envelope back off the CONFIRMED reveal, not out of `build`. Everything
    # downstream judges against THIS object, so that the commitment a reveal is checked
    # against is one that survived CBOR, a scriptSig, a signature and a block — which is
    # the only version a third party will ever see.
    on_chain = _envelope_from_confirmed(rt, token["reveal_txid"])
    return {
        "build": build,
        "token": token,
        "token_ref": token_ref,
        "on_chain": on_chain,
        "unlock_at": unlock_at,
        "mode": mode,
    }


def _reveal_tx(rt: _RegtestNode, op_return_script: bytes) -> tuple[Transaction, str]:
    """Wrap reveal-proof bytes in a funded, signed transaction. Broadcasts nothing.

    Deliberately hand-built rather than routed through
    :func:`pyrxd.glyph.timelock_reveal_tx.build_timelock_reveal`, which needs an
    ``HdWallet`` and a live ElectrumX client that this harness does not have — a
    regtest node speaks JSON-RPC, not the Electrum protocol. The SHAPE is the
    builder's: one P2PKH input, the OP_RETURN at value 0 in output 0, change back to
    the funding address, and a fee at or above the bar
    :func:`timelock_reveal_funding_bar` computes. Two of those are checked rather than
    described — the fee bar below, and the value-0 OP_RETURN at output 0 in
    ``test_an_early_reveal_is_relayed_and_mined``, which also pins the script bytes to
    the plan's. The production functions that decide whether a reveal may exist at all,
    ``plan_timelock_reveal`` and the fee bar, are called directly; what is NOT exercised
    here is ``build_timelock_reveal``'s own UTXO selection, which refuses to spend a
    token-bearing UTXO.
    """
    u = _biggest_utxo(rt)
    key = PrivateKey(str(rt.cli("dumpprivkey", u["address"], wallet=True)))
    pkh = bytes(Hex20(key.public_key().hash160()))
    change_spk = b"\x76\xa9\x14" + pkh + b"\x88\xac"
    in_sats = round(u["amount"] * 1e8)

    rate = rt.relay_rate()
    bar = timelock_reveal_funding_bar(op_return_script, rate)
    fee = max(_FEE, bar)
    for _ in range(3):
        fin = TransactionInput(
            source_transaction=_src(u["txid"], u["vout"], bytes.fromhex(u["scriptPubKey"]), in_sats),
            source_txid=u["txid"],
            source_output_index=u["vout"],
            unlocking_script_template=_p2pkh_unlock(key),
        )
        fin.satoshis = in_sats
        fin.locking_script = Script(bytes.fromhex(u["scriptPubKey"]))
        tx = Transaction(
            tx_inputs=[fin],
            tx_outputs=[
                TransactionOutput(Script(op_return_script), 0),
                TransactionOutput(Script(change_spk), in_sats - fee),
            ],
        )
        tx.sign()
        required = len(tx.serialize()) * rate
        if fee >= required:
            break
        fee = required
    else:  # pragma: no cover - the loop reaches its fixed point in one correction
        raise AssertionError(f"reveal fee did not settle above the node's floor ({rate} photons/byte)")

    assert fee >= bar, f"fee {fee} is under the builder's own funding bar {bar}"
    return tx, _assert_fee_covers(tx, fee)


def _underpaid_reveal_tx(rt: _RegtestNode, op_return_script: bytes) -> str:
    """The same reveal, one photon under the node's floor. The control case.

    Every "the node ACCEPTED this" finding in this file is worth exactly as much as
    the node's capacity to say no. A ``testmempoolaccept`` that returned ``allowed``
    for everything — a harness bug, a node started without a policy, a verdict read
    off the wrong key — would make :class:`TestTheNodeHasNoOpinion` green and
    meaningless, and nothing in its output would look wrong. So this builds one reveal
    whose answer is known in advance.

    Converged by re-signing rather than computed once, because a DER signature is 70-72
    bytes and its length is not known until it exists: aiming at ``size * rate - 1`` from
    a trial signing lands ABOVE the floor whenever the next signature comes out shorter,
    and an overpaid transaction that the node then accepts would invert this control
    without changing how it reads. The loop exits only on a transaction measured to be
    under the floor for its OWN serialized length.
    """
    u = _biggest_utxo(rt)
    key = PrivateKey(str(rt.cli("dumpprivkey", u["address"], wallet=True)))
    pkh = bytes(Hex20(key.public_key().hash160()))
    change_spk = b"\x76\xa9\x14" + pkh + b"\x88\xac"
    in_sats = round(u["amount"] * 1e8)
    rate = rt.relay_rate()

    fee = _FEE
    for _ in range(8):
        fin = TransactionInput(
            source_transaction=_src(u["txid"], u["vout"], bytes.fromhex(u["scriptPubKey"]), in_sats),
            source_txid=u["txid"],
            source_output_index=u["vout"],
            unlocking_script_template=_p2pkh_unlock(key),
        )
        fin.satoshis = in_sats
        fin.locking_script = Script(bytes.fromhex(u["scriptPubKey"]))
        tx = Transaction(
            tx_inputs=[fin],
            tx_outputs=[
                TransactionOutput(Script(op_return_script), 0),
                TransactionOutput(Script(change_spk), in_sats - fee),
            ],
        )
        tx.sign()
        raw = tx.serialize()
        if fee < len(raw) * rate:
            return raw.hex()
        fee = len(raw) * rate - 1
    raise AssertionError("could not build a reveal under the node's floor")  # pragma: no cover


def _op_return_from_chain(rt: _RegtestNode, txid: str) -> bytes:
    """Output 0's locking script, read back off the confirmed transaction."""
    return bytes.fromhex(_confirmed(rt, txid)["vout"][0]["scriptPubKey"]["hex"])


def _spec_of(metadata: object) -> object:
    spec = getattr(getattr(metadata, "crypto", None), "timelock", None)
    return spec if spec is not None else metadata.timelock


# --------------------------------------------------------------------------- fixtures


@pytest.fixture(scope="module")
def recipient_sk() -> bytes:
    """A recipient who may open the content WITHOUT waiting for the reveal."""
    return secrets.token_bytes(32)


@pytest.fixture(scope="module")
def locked_forever(node) -> dict:  # noqa: F811
    """A sealed token whose lock no test in this file can reach.

    Every pre-expiry claim is made against THIS token rather than against the maturing
    one, so no assertion here depends on running before :class:`TestAfterExpiry` mines.
    A pre-expiry test that silently became a post-expiry test would still pass, and
    would prove the opposite of what it says.
    """
    return _seal(node, unlock_offset=_FOREVER_OFFSET)


@pytest.fixture(scope="module")
def maturing(node, recipient_sk) -> dict:  # noqa: F811
    """A sealed token whose lock expires a few blocks out, with one wrap recipient."""
    return _seal(node, unlock_offset=_MATURING_OFFSET, recipient_sk=recipient_sk)


# --------------------------------------------------------------------------- 1. the seal


class TestTheSealIsAcceptedByTheNode:
    def test_a_timelock_mint_relays_and_confirms(self, node, locked_forever):  # noqa: F811
        """NODE-ENFORCED: the mint is accepted and mined.

        ``_mint_nft`` already asserts ``testmempoolaccept`` said allowed; this re-reads
        the confirmation off the chain so the claim is about a mined transaction and not
        about a mempool verdict.
        """
        token = locked_forever["token"]
        confirmed = _confirmed(node, token["reveal_txid"])
        assert confirmed["confirmations"] >= 1
        assert _confirmed(node, token["commit_txid"])["confirmations"] >= 1

    def test_the_commitment_survives_the_wire(self, node, locked_forever):  # noqa: F811
        """The three things a reveal is later checked against, recovered from the chain.

        The decode path is the production one: ``GlyphScanner.fetch_metadata`` — which
        ``pyrxd glyph timelock-reveal`` uses to get the metadata it checks a CEK
        against — ends in ``GlyphInspector.extract_reveal_metadata`` on the scriptSig
        that spent the commit outpoint. That exact call is asserted below beside the
        helper's, so this is not merely "some parser can read it".
        """
        on_chain = locked_forever["on_chain"]
        build = locked_forever["build"]
        assert GlyphProtocol.TIMELOCK in on_chain.protocol
        assert GlyphProtocol.ENCRYPTED in on_chain.protocol

        spec = _spec_of(on_chain)
        assert spec is not None, "no crypto.timelock came back off the chain"
        assert spec.cek_hash == build.cek_hash
        assert spec.mode == "block"
        assert spec.unlock_at == locked_forever["unlock_at"]

        # The plaintext hash, which is the AAD prefix decryption needs, is on chain too.
        assert on_chain.encrypted_main is not None
        assert parse_cek_hash(on_chain.encrypted_main.hash) == build.ciphertext.plaintext_hash
        assert on_chain.encrypted_main.size == len(SEALED_PLAINTEXT)

        # And the CEK itself is NOT. Nothing published so far can open the payload.
        raw = bytes.fromhex(str(node.cli("getrawtransaction", locked_forever["token"]["reveal_txid"])))
        assert build.cek not in raw, "the mint transaction carries the CEK — the seal is not a seal"
        assert build.cek_hash.encode("ascii") in raw, "the commitment should be on chain even though the key is not"
        assert compute_cek_hash(build.cek).hex().encode("ascii") in raw

        # Production decode path, on the input that spent the commit outpoint.
        tx = Transaction.from_hex(raw)
        assert tx is not None
        direct = INSPECTOR.extract_reveal_metadata(tx.inputs[0].unlocking_script.serialize())
        assert direct is not None
        assert _spec_of(direct).cek_hash == spec.cek_hash

    def test_a_wrap_recipient_opens_the_payload_without_any_reveal(self, node, maturing, recipient_sk):  # noqa: F811
        """Chain data + a recipient private key is enough, BEFORE unlock_at.

        Worth measuring on a node because it is the half of the design that is not a
        timelock at all: the wrap goes on chain at mint time, so a named recipient is
        never gated by anything. A product that assumes "nobody can read it until the
        reveal" has to account for whoever it minted wraps to.
        """
        assert _tip(node) < maturing["unlock_at"], "this claim only means something while still locked"
        on_chain = maturing["on_chain"]
        wraps = list(on_chain.crypto.recipients)
        assert len(wraps) == 1 and wraps[0].kid == "auctioneer-1"

        # The wrap's AAD is the on-chain `crypto.cek_hash` TEXT, read off the chain copy — what
        # Photonic's unlock path binds (see `cek_wrap_aad`). This test was written against the
        # raw 32-byte digest, which is what pyrxd 0.24.0 wrapped under and Photonic cannot open.
        cek = unwrap_cek_x25519(
            wraps[0].wrapped_cek,
            wraps[0].epk,
            recipient_sk,
            cek_wrap_aad(on_chain.crypto.cek_hash),
            allow_legacy_info=False,
        )
        assert verify_cek_reveal(cek, _spec_of(on_chain).cek_hash)
        with pytest.raises(ValueError):  # the raw digest must not open it, or the AAD proves nothing
            unwrap_cek_x25519(
                wraps[0].wrapped_cek, wraps[0].epk, recipient_sk, parse_cek_hash(on_chain.crypto.cek_hash)
            )
        opened = decrypt_chunked(maturing["build"].ciphertext, cek, parse_cek_hash(on_chain.encrypted_main.hash))
        assert opened == SEALED_PLAINTEXT


# --------------------------------------------------------------------------- 2. before expiry


class TestBeforeExpiry:
    """PYRXD-ENFORCED, and this class is the entire enforcement story.

    The node is consulted only for the CLOCK — a tip height, a tip header timestamp —
    and never for a verdict. That is not an omission: see
    :class:`TestTheNodeHasNoOpinion` for the measurement that says there is no verdict
    to ask it for.
    """

    def test_the_gate_refuses_against_the_nodes_real_tip(self, node, locked_forever):  # noqa: F811
        tip = _tip(node)
        assert tip < locked_forever["unlock_at"], "fixture is not actually locked"

        with pytest.raises(TimelockNotExpired) as exc:
            plan_timelock_reveal(
                locked_forever["on_chain"],
                token_ref=locked_forever["token_ref"],
                cek=locked_forever["build"].cek,
                current_block=tip,
            )
        # The refusal names the reading it judged against, not just the verdict.
        assert str(locked_forever["unlock_at"]) in str(exc.value)
        assert f"{locked_forever['unlock_at'] - tip:,}" in str(exc.value)

        spec = _spec_of(locked_forever["on_chain"])
        assert spec_is_unlocked(spec, current_block=tip) is False
        assert spec_unlock_remaining(spec, current_block=tip) == locked_forever["unlock_at"] - tip

    def test_a_time_mode_lock_is_judged_against_the_tip_header(self, node):  # noqa: F811
        """The other branch of the mode conditional, against a real block timestamp.

        ``mode="time"`` is the branch a block-mode test never enters, and the clock it
        reads is a different one: the tip HEADER's unix time, not a height. Minted and
        judged here rather than asserted from the spec, because "the node's clock" is
        exactly the input an offline test cannot supply.
        """
        sealed = _seal(node, unlock_offset=_FOREVER_OFFSET, mode="time")
        now = _tip_time(node)
        assert now < sealed["unlock_at"]

        with pytest.raises(TimelockNotExpired):
            plan_timelock_reveal(
                sealed["on_chain"],
                token_ref=sealed["token_ref"],
                cek=sealed["build"].cek,
                current_time=now,
            )

        # And the conservative half: a time-mode lock handed a BLOCK clock cannot be
        # judged at all, and reads as locked rather than as open.
        with pytest.raises(TimelockNotExpired) as exc:
            plan_timelock_reveal(
                sealed["on_chain"],
                token_ref=sealed["token_ref"],
                cek=sealed["build"].cek,
                current_block=_tip(node),
            )
        assert "no current_time was supplied" in str(exc.value)

    def test_the_wrong_key_is_refused_before_the_clock_is_consulted(self, node, locked_forever):  # noqa: F811
        """A wrong CEK raises ``CekCommitmentMismatch``, not ``TimelockNotExpired``.

        Order matters and is load-bearing: the token is locked, so BOTH refusals apply,
        and an operator told "not expired yet" would come back after the unlock point
        and publish the wrong key then.
        """
        with pytest.raises(CekCommitmentMismatch):
            plan_timelock_reveal(
                locked_forever["on_chain"],
                token_ref=locked_forever["token_ref"],
                cek=os.urandom(32),
                current_block=_tip(node),
                allow_early=True,
            )


# --------------------------------------------------------------------------- 3. the node's view


class TestTheNodeHasNoOpinion:
    """NODE-MEASURED. Three cases broadcast bytes the protocol's prose implies should
    not work — an early reveal, a wrong-key reveal, a duplicate reveal — and all three
    confirm. The first test is a control that is REFUSED, and the last reads the
    confirmed early reveal without broadcasting anything.

    These are not assertions that pyrxd is wrong. They are the measurement of where
    the boundary is, and the boundary is: pyrxd's client-side gate, and nothing after
    it. A second implementation, or this one with ``--allow-early``, is unconstrained.
    """

    def test_the_node_does_refuse_reveals_so_the_acceptances_below_mean_something(
        self,
        node,  # noqa: F811
        locked_forever,
    ):
        """The control, run FIRST: a reveal the node is known to reject.

        Without it, the three acceptances that follow would be indistinguishable from
        a harness that never reached the node at all. Same script, same shape, one
        photon under the floor — and the reason it is refused must be the FEE, not
        something incidental, or the control is measuring the wrong thing.
        """
        script, _ = create_reveal_proof(locked_forever["token_ref"], locked_forever["build"].cek)
        verdict = node.accepts(_underpaid_reveal_tx(node, script))
        assert verdict.get("allowed") is False, f"the node accepted an underpaid reveal: {verdict}"
        assert "min relay fee not met" in verdict.get("reject-reason", ""), verdict

    def test_an_early_reveal_is_relayed_and_mined(self, node, locked_forever):  # noqa: F811
        """THE headline: the CEK goes public ~100,000 blocks before ``unlock_at``.

        Built through ``plan_timelock_reveal(allow_early=True)`` — the production path,
        with the production escape hatch — so the bytes are exactly what the SDK emits.
        """
        tip = _tip(node)
        remaining = locked_forever["unlock_at"] - tip
        assert remaining > 0

        plan = plan_timelock_reveal(
            locked_forever["on_chain"],
            token_ref=locked_forever["token_ref"],
            cek=locked_forever["build"].cek,
            current_block=tip,
            allow_early=True,
        )
        assert plan.unlocked is False
        assert plan.early_override is True
        assert plan.remaining == remaining
        assert plan.judged_at == tip

        tx, raw = _reveal_tx(node, plan.op_return_script)
        # Shape check against the builder's model: OP_RETURN at value 0 in output 0.
        assert tx.outputs[0].satoshis == 0
        assert tx.outputs[0].locking_script.serialize() == plan.op_return_script
        assert plan.op_return_script[0] == 0x6A

        verdict = node.accepts(raw)
        assert verdict.get("allowed") is True, (
            f"the node REFUSED an early reveal — if this ever fails, the finding in this "
            f"file's docstring is wrong and the timelock has acquired teeth: {verdict}"
        )
        txid = str(node.cli("sendrawtransaction", raw))
        node.mine(1)
        assert _confirmed(node, txid)["confirmations"] >= 1

        # Still locked, and the key is now public anyway.
        assert _tip(node) < locked_forever["unlock_at"]
        published = parse_reveal_proof_script(_op_return_from_chain(node, txid))
        assert published is not None
        assert bytes.fromhex(published.cek) == locked_forever["build"].cek
        locked_forever["early_reveal_txid"] = txid

    def test_consensus_does_not_check_the_commitment(self, node, locked_forever):  # noqa: F811
        """A reveal publishing a key that is NOT this token's key confirms.

        ``create_reveal_proof`` is reachable on its own — it takes a CEK and a ref and
        never sees the token — so this is not a contrived shape. It is what any caller
        that skips the gate produces, and the chain records it beside the honest one
        with nothing to tell them apart.
        """
        junk = os.urandom(32)
        script, proof = create_reveal_proof(locked_forever["token_ref"], junk)
        # Self-consistent, and wrong: sha256(junk) == proof.cek_hash, but the token
        # committed to something else. Only the on-chain metadata separates them.
        assert validate_reveal_proof(proof, expected_token_ref=locked_forever["token_ref"]).valid is True
        against_token = validate_reveal_proof(
            proof,
            expected_token_ref=locked_forever["token_ref"],
            expected_cek_hash=_spec_of(locked_forever["on_chain"]).cek_hash,
        )
        assert against_token.valid is False
        assert "does not match on-chain commitment" in against_token.error

        _tx, raw = _reveal_tx(node, script)
        verdict = node.accepts(raw)
        assert verdict.get("allowed") is True, f"node refused a wrong-CEK reveal: {verdict}"
        txid = str(node.cli("sendrawtransaction", raw))
        node.mine(1)
        assert _confirmed(node, txid)["confirmations"] >= 1

    def test_a_token_can_be_revealed_more_than_once(self, node, locked_forever):  # noqa: F811
        """Nothing on chain makes a reveal unique, so "first reveal wins" is an
        INDEXER rule a product would have to implement and defend itself.

        By the time this runs, three transactions claim ``token_ref`` for this one
        token: the early reveal (carrying the right key), the wrong-CEK reveal above,
        and this duplicate. All three are mined. Consensus ranks them not at all.
        """
        assert "early_reveal_txid" in locked_forever, "ordering: the early reveal must have run first"
        plan = plan_timelock_reveal(
            locked_forever["on_chain"],
            token_ref=locked_forever["token_ref"],
            cek=locked_forever["build"].cek,
            current_block=_tip(node),
            allow_early=True,
        )
        _tx, raw = _reveal_tx(node, plan.op_return_script)
        assert node.accepts(raw).get("allowed") is True
        second = str(node.cli("sendrawtransaction", raw))
        node.mine(1)
        assert second != locked_forever["early_reveal_txid"]
        assert _confirmed(node, second)["confirmations"] >= 1

    def test_the_mint_does_not_bind_the_reveal_to_anyone(self, node, locked_forever):  # noqa: F811
        """The reveal is funded by a wallet UTXO with no relationship to the token.

        Read off the confirmed early reveal rather than argued from the builder: its
        inputs do not include the token's outpoint, and the token is still unspent. So
        a reveal costs a fee and proves possession of a key — not of the token.

        The same confirmed transaction is where the "no time constraint anywhere" claim
        is MEASURED rather than asserted from the source: ``nLockTime`` is 0 and the
        input sequence is final, so nothing in the transaction defers it and nothing in
        it would have been rejected as non-final at any height.
        """
        confirmed = _confirmed(node, locked_forever["early_reveal_txid"])
        token = locked_forever["token"]
        spent = {(vin["txid"], vin["vout"]) for vin in confirmed["vin"]}
        assert (token["reveal_txid"], 0) not in spent
        assert node.cli("gettxout", token["reveal_txid"], "0") not in (None, ""), (
            "the token UTXO should still be unspent — the reveal does not touch it"
        )

        assert int(confirmed["locktime"]) == 0, f"reveal carries an nLockTime: {confirmed['locktime']}"
        assert all(int(vin["sequence"]) == 0xFFFFFFFF for vin in confirmed["vin"]), confirmed["vin"]


# --------------------------------------------------------------------------- 4. after expiry


class TestAfterExpiry:
    def test_mining_past_unlock_at_opens_the_gate_and_the_reveal_confirms(self, node, maturing):  # noqa: F811
        """The honest path: the SAME call that refused now returns a plan.

        The refusal is asserted first, on this token, so that the pass afterwards is
        known to be caused by the mining and not by the fixture having been open all
        along.
        """
        before = _tip(node)
        assert before < maturing["unlock_at"], (
            f"tip {before} already past unlock_at {maturing['unlock_at']} before this test mined a "
            "single block — the sequence below would prove nothing. Raise _MATURING_OFFSET."
        )
        with pytest.raises(TimelockNotExpired):
            plan_timelock_reveal(
                maturing["on_chain"],
                token_ref=maturing["token_ref"],
                cek=maturing["build"].cek,
                current_block=before,
            )
        node.mine(maturing["unlock_at"] - before)

        tip = _tip(node)
        assert tip >= maturing["unlock_at"]

        plan = plan_timelock_reveal(
            maturing["on_chain"],
            token_ref=maturing["token_ref"],
            cek=maturing["build"].cek,
            current_block=tip,
            hint="settled",
        )
        assert plan.unlocked is True
        assert plan.early_override is False
        assert plan.remaining == 0
        assert plan.judged_at == tip
        assert plan.commitment == maturing["build"].cek_hash

        _tx, raw = _reveal_tx(node, plan.op_return_script)
        verdict = node.accepts(raw)
        assert verdict.get("allowed") is True, f"matured reveal rejected: {verdict}"
        txid = str(node.cli("sendrawtransaction", raw))
        node.mine(1)
        assert _confirmed(node, txid)["confirmations"] >= 1
        maturing["reveal_txid"] = txid

    def test_the_reveal_pays_for_its_own_size_at_the_nodes_floor(self, node, maturing):  # noqa: F811
        """The production fee bar, checked against the node's own advertised rate.

        A reveal's OP_RETURN is large by data-carrier standards, and Radiant has
        neither RBF nor CPFP — an underpaid reveal cannot be repaired and holds its
        funding until mempool expiry. ``timelock_reveal_funding_bar`` is the function
        that is supposed to stop that; here it is compared to what the node charged.
        """
        assert "reveal_txid" in maturing, "ordering: the matured reveal must have run first"
        confirmed = _confirmed(node, maturing["reveal_txid"])
        script = bytes.fromhex(confirmed["vout"][0]["scriptPubKey"]["hex"])
        rate = node.relay_rate()
        assert rate == _MIN_FEE_RATE, f"node is at {rate} photons/byte, not mainnet's {_MIN_FEE_RATE}"

        size = int(confirmed["size"])
        bar = timelock_reveal_funding_bar(script, rate)
        # The bar models the no-change shape, so it is a floor for this (larger) tx.
        assert bar >= size * rate * 0.9, (
            f"funding bar {bar} is far under the real cost of a {size}-byte reveal at {rate}/B — "
            "the model has drifted from the transaction"
        )
        # MEASURED: a 277-byte data carrier relayed and mined. That is far over
        # Bitcoin's 83-byte `datacarriersize` default and over the 223-byte
        # MAX_OP_RETURN_RELAY that `tests/test_consensus_opcode_parity.py` records
        # Radiant as declaring — which that file also records as standardness, never
        # reached because `fRequireStandard` is hardcoded false. This assertion checks
        # the size, not that claim; what the node did with it is the evidence.
        assert len(script) > 223, (
            f"reveal OP_RETURN is {len(script)} B — at or under the 223-byte figure, so this "
            "run would NOT have shown an oversized data carrier relaying"
        )


# --------------------------------------------------------------------------- 5. third party


class TestThirdPartyVerification:
    """Everything here starts from ``getrawtransaction`` and the ciphertext.

    No object built earlier in the process is consulted except ``build.ciphertext``,
    which the protocol says does not go on chain — the envelope carries only its hash,
    size and chunk count. That one input is the product's off-chain obligation, and
    naming it is the point.
    """

    def test_the_proof_is_recovered_and_validated_from_raw_chain_bytes(self, node, maturing):  # noqa: F811
        assert "reveal_txid" in maturing, "ordering: the matured reveal must have run first"
        raw = bytes.fromhex(str(node.cli("getrawtransaction", maturing["reveal_txid"])))
        tx = Transaction.from_hex(raw)
        assert tx is not None
        script = tx.outputs[0].locking_script.serialize()

        proof = parse_reveal_proof_script(script)
        assert proof is not None, "a third party cannot read the reveal off the chain"
        assert proof.action == "reveal"
        assert proof.p == [9]
        assert proof.token_ref == maturing["token_ref"]
        assert proof.hint == "settled"

        # The commitment comes off the MINT transaction, independently fetched.
        mint_meta = _envelope_from_confirmed(node, maturing["token"]["reveal_txid"])
        commitment = _spec_of(mint_meta).cek_hash

        verdict = validate_reveal_proof(proof, expected_token_ref=maturing["token_ref"], expected_cek_hash=commitment)
        assert verdict.valid is True, verdict.error
        assert verify_cek_reveal(bytes.fromhex(proof.cek), commitment) is True

    def test_the_published_key_decrypts_the_payload(self, node, maturing):  # noqa: F811
        proof = parse_reveal_proof_script(_op_return_from_chain(node, maturing["reveal_txid"]))
        assert proof is not None
        mint_meta = _envelope_from_confirmed(node, maturing["token"]["reveal_txid"])

        opened = decrypt_chunked(
            maturing["build"].ciphertext,  # off-chain, by design
            bytes.fromhex(proof.cek),  # from the reveal tx
            parse_cek_hash(mint_meta.encrypted_main.hash),  # from the mint tx
        )
        assert opened == SEALED_PLAINTEXT

    def test_the_chain_alone_is_not_enough_and_says_so(self, node, maturing):  # noqa: F811
        """The envelope pins the ciphertext it expects, so a substituted one is caught.

        ``main.hash`` is the AAD prefix. Handing ``decrypt_chunked`` a ciphertext that
        is not the one the mint committed to fails the Poly1305 tag rather than
        returning plausible bytes — which is what makes the off-chain half auditable
        instead of merely required.
        """
        proof = parse_reveal_proof_script(_op_return_from_chain(node, maturing["reveal_txid"]))
        assert proof is not None
        mint_meta = _envelope_from_confirmed(node, maturing["token"]["reveal_txid"])
        other = _seal(node, unlock_offset=_FOREVER_OFFSET)["build"].ciphertext

        with pytest.raises(ValueError):
            decrypt_chunked(other, bytes.fromhex(proof.cek), parse_cek_hash(mint_meta.encrypted_main.hash))


# --------------------------------------------------------------------------- 6. negatives


class TestNegatives:
    """PYRXD-ENFORCED refusals, each measured on bytes that came off the chain."""

    def test_a_wrong_cek_fails_the_commitment_check(self, node, maturing):  # noqa: F811
        commitment = _spec_of(_envelope_from_confirmed(node, maturing["token"]["reveal_txid"])).cek_hash
        assert verify_cek_reveal(maturing["build"].cek, commitment) is True
        for _ in range(3):
            assert verify_cek_reveal(os.urandom(32), commitment) is False
        # A near-miss too: one bit of the real key.
        flipped = bytearray(maturing["build"].cek)
        flipped[0] ^= 0x01
        assert verify_cek_reveal(bytes(flipped), commitment) is False

    def test_a_tampered_on_chain_reveal_fails_validation(self, node, maturing):  # noqa: F811
        """Edit the CONFIRMED script's bytes, re-parse, and watch validation refuse.

        The CEK rides in the CBOR as a 64-character text string, so changing one
        character keeps every length prefix intact — the proof still parses, which is
        the interesting case. A mutation that broke the encoding would be caught by the
        parser and would prove nothing about the validator.
        """
        script = _op_return_from_chain(node, maturing["reveal_txid"])
        good = parse_reveal_proof_script(script)
        assert good is not None

        cek_ascii = good.cek.encode()
        assert script.count(cek_ascii) == 1, "expected exactly one copy of the CEK hex in the script"
        swapped = b"0" if cek_ascii[:1] != b"0" else b"1"
        tampered = script.replace(cek_ascii, swapped + cek_ascii[1:], 1)
        assert len(tampered) == len(script)

        reparsed = parse_reveal_proof_script(tampered)
        assert reparsed is not None, "the tamper broke the encoding — it proves nothing about validation"
        assert reparsed.cek != good.cek
        verdict = validate_reveal_proof(reparsed, expected_token_ref=maturing["token_ref"])
        assert verdict.valid is False
        assert "self-consistency" in verdict.error

    def test_a_proof_for_another_token_is_refused(self, node, maturing, locked_forever):  # noqa: F811
        """Same bytes, wrong token. The ``token_ref`` binding is what stops a reveal
        lifted off one token being replayed onto another."""
        proof = parse_reveal_proof_script(_op_return_from_chain(node, maturing["reveal_txid"]))
        assert proof is not None
        verdict = validate_reveal_proof(proof, expected_token_ref=locked_forever["token_ref"])
        assert verdict.valid is False
        assert "token_ref mismatch" in verdict.error

    def test_a_reveal_naming_the_other_tokens_commitment_is_refused(self, node, maturing, locked_forever):  # noqa: F811
        """And the cross-check that catches a right-shaped proof for the wrong seal."""
        proof = parse_reveal_proof_script(_op_return_from_chain(node, maturing["reveal_txid"]))
        assert proof is not None
        verdict = validate_reveal_proof(
            proof,
            expected_token_ref=maturing["token_ref"],
            expected_cek_hash=_spec_of(locked_forever["on_chain"]).cek_hash,
        )
        assert verdict.valid is False
        assert "does not match on-chain commitment" in verdict.error
