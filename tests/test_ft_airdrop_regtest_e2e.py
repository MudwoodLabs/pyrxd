"""Live-regtest CONSENSUS proof for the **multi-recipient FT airdrop**.

An airdrop is a transaction shape pyrxd had never emitted: several FT outputs
carrying the same ref, plus an FT change output, plus plain-P2PKH outputs, all
in one transaction. Radiant enforces FT semantics in *consensus* — the 12-byte
epilogue on every FT lock runs on every spend — so whether that shape is legal
is a question only a node can answer. Constructing it is not evidence: this repo
has shipped builders whose output assembled cleanly and was rejected by
consensus (the non-minimal height push that made every pre-redesign V2 contract
un-mineable; the multi-ref sighash endianness bug).

What each case proves:

1. **A many-to-many FT transaction is accepted.** Three recipient outputs on one
   ref plus change. If the ref/amount epilogue objected to N outputs rather than
   the 1-or-2 the shipped transfer emits, this is where it would show.
2. **Plain-P2PKH outputs may ride along.** The fee funding's change output, and
   any royalty payout, carry no ref. The whole reason a royalty is safe to bolt
   onto an FT transfer is that a ref-less output contributes to no conservation
   sum — assumed until a node agrees.
3. **The fee comes from RXD, not from the token.** After the airdrop the units
   are all still there: what went out equals what came in. A builder that took
   the fee off a token output would show up here as a deficit.
4. **A token-inflating airdrop is REJECTED.** The negative control. A node that
   accepts everything cannot masquerade as a pass, so the same tx with one
   recipient output inflated by a unit must fail.

Opt-in: ``@pytest.mark.integration`` + ``RADIANT_REGTEST=1``. Never runs in
normal CI. Manages its own throwaway container; moves no real value. No PoW
here — an FT deploy is commit+reveal only — so this is seconds, not minutes.

Run: ``RADIANT_REGTEST=1 pytest tests/test_ft_airdrop_regtest_e2e.py -m integration -s``
"""

from __future__ import annotations

import secrets

import cbor2
import pytest

# Reuse the isolated-regtest harness wholesale (same pattern as the dMint e2e
# tests): the ``node`` fixture spins up + tears down a throwaway container.
from test_htlc_regtest_e2e import (  # noqa: F401  (node = fixture)
    _RELAY_FEE_SATS,
    _p2pkh_unlock,
    _pay_to_spk,
    _RegtestNode,
    _src,
    node,
)

from pyrxd.glyph.builder import CommitParams, GlyphBuilder
from pyrxd.glyph.ft import AirdropFunding, AirdropRecipient, FtUtxo, FtUtxoSet
from pyrxd.glyph.script import build_ft_locking_script, is_ft_script
from pyrxd.glyph.types import GlyphMetadata, GlyphProtocol, GlyphRef, GlyphRoyalty
from pyrxd.keys import PrivateKey
from pyrxd.script.script import Script
from pyrxd.script.type import P2PKH, encode_pushdata, to_unlock_script_template
from pyrxd.security.types import Hex20
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_input import TransactionInput
from pyrxd.transaction.transaction_output import TransactionOutput

pytestmark = pytest.mark.integration

# The FT supply, in photons == units. Large enough that a handful of recipient
# outputs and a change output are all comfortably above any wallet floor, and
# small enough to read in a failure message.
_SUPPLY = 100_000_000  # 1 RXD worth of units
# The commit must fund the WHOLE supply plus the reveal's fee: the reveal emits
# _SUPPLY photons of FT and has no other input, so a commit worth less than that
# is `bad-txns-in-belowout` — inputs below outputs.
_REVEAL_FEE_HEADROOM = 30_000_000
_COMMIT_VALUE = _SUPPLY + _REVEAL_FEE_HEADROOM
_FUND_VALUE = 200_000_000  # plain RXD that pays the airdrop fee


def _reveal_unlock(key: PrivateKey, suffix: bytes):
    """P2PKH unlock with the ``'gly'``+CBOR push sequence appended.

    Same shape as :func:`pyrxd.glyph.mint.build_reveal_unlock_template`, spelled
    out here so the test does not depend on the mint facade's storage layer.
    """
    pub = key.public_key().serialize()

    def _u(tx, idx):
        inp = tx.inputs[idx]
        sig = key.sign(tx.preimage(idx))
        return Script(encode_pushdata(sig + inp.sighash.to_bytes(1, "little")) + encode_pushdata(pub) + suffix)

    return to_unlock_script_template(_u, lambda: 110 + len(suffix))


class _DeployedFt:
    """A real FT on the regtest chain: ref, UTXO, and the key that owns it."""

    def __init__(self, ref: GlyphRef, txid: str, vout: int, value: int, script: bytes, key: PrivateKey) -> None:
        self.ref = ref
        self.txid = txid
        self.vout = vout
        self.value = value
        self.script = script
        self.key = key

    def as_utxo(self) -> FtUtxo:
        return FtUtxo(
            txid=self.txid,
            vout=self.vout,
            value=self.value,
            ft_amount=self.value,  # 1 photon = 1 FT unit
            ft_script=self.script,
        )


def _deploy_ft(rt: _RegtestNode) -> _DeployedFt:
    """Commit + reveal a plain FT, so the airdrop spends a genuine ref.

    A fabricated FT script would not do: Radiant only lets an output push a ref
    that an input already carries (or that is being minted from the matching
    outpoint), so an airdrop can only be proven against a token the chain
    actually created.
    """
    owner = PrivateKey()
    owner_pkh = Hex20(owner.public_key().hash160())
    builder = GlyphBuilder()

    metadata = GlyphMetadata(
        protocol=[GlyphProtocol.FT],
        name="AIRDROP-TEST",
        ticker="ADT",
        description="regtest airdrop fixture",
    )
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

    reveal_scripts = builder.prepare_ft_deploy_reveal(
        commit_txid=commit_txid,
        commit_vout=0,
        commit_value=_COMMIT_VALUE,
        cbor_bytes=commit.cbor_bytes,
        premine_pkh=owner_pkh,
        premine_amount=_SUPPLY,
    )
    # Sanity: the deploy's ref is the COMMIT outpoint, not the reveal's txid.
    ref = GlyphRef(txid=commit_txid, vout=0)
    assert cbor2.loads(commit.cbor_bytes)["p"] == [int(GlyphProtocol.FT)]

    reveal = Transaction(
        tx_inputs=[
            TransactionInput(
                source_transaction=_src(commit_txid, 0, commit.commit_script, _COMMIT_VALUE),
                source_txid=commit_txid,
                source_output_index=0,
                unlocking_script_template=_reveal_unlock(owner, reveal_scripts.scriptsig_suffix),
            )
        ],
        tx_outputs=[TransactionOutput(Script(reveal_scripts.locking_script), _SUPPLY)],
    )
    reveal.sign()
    raw = reveal.serialize().hex()
    res = rt.accepts(raw)
    assert res.get("allowed") is True, f"FT deploy reveal rejected: {res}"
    reveal_txid = str(rt.cli("sendrawtransaction", raw))
    rt.mine(1)

    return _DeployedFt(
        ref=ref,
        txid=reveal_txid,
        vout=0,
        value=_SUPPLY,
        script=reveal_scripts.locking_script,
        key=owner,
    )


def _plain_funding(rt: _RegtestNode) -> AirdropFunding:
    """A plain-P2PKH UTXO under our own key, to pay the airdrop's fee."""
    key = PrivateKey()
    spk = P2PKH().lock(key.public_key().hash160()).serialize()
    txid = _pay_to_spk(rt, spk, _FUND_VALUE)
    rt.mine(1)
    return AirdropFunding(txid=txid, vout=0, value=_FUND_VALUE, private_key=key)


@pytest.fixture(scope="module")
def deployed(node):  # noqa: F811 — `node` is the imported fixture
    return _deploy_ft(node)


def test_multi_recipient_airdrop_is_accepted(node, deployed):  # noqa: F811
    """Case 1 + 2 + 3: N FT outputs + change + a ref-less P2PKH output."""
    recipients = [
        AirdropRecipient(pkh=Hex20(secrets.token_bytes(20)), amount=amt) for amt in (5_000_000, 2_500_000, 1_000_000)
    ]
    utxo_set = FtUtxoSet(ref=deployed.ref, utxos=[deployed.as_utxo()])
    result = utxo_set.build_airdrop_tx(
        recipients,
        deployed.key,
        funding=[_plain_funding(node)],
    )

    raw = result.tx.serialize().hex()
    res = node.accepts(raw)
    assert res.get("allowed") is True, f"multi-recipient FT airdrop REJECTED by consensus: {res}"

    txid = str(node.cli("sendrawtransaction", raw))
    node.mine(1)
    confirmed = node.cli("getrawtransaction", txid, "true")
    assert confirmed["confirmations"] >= 1

    # Case 2: at least one ref-less plain-P2PKH output rode along (the funding
    # change) and consensus did not object.
    spks = [bytes.fromhex(o["scriptPubKey"]["hex"]) for o in confirmed["vout"]]
    assert any(len(s) == 25 and s[:3] == b"\x76\xa9\x14" for s in spks)

    # Case 3: units in == units out. Nothing was burned to pay the fee.
    ft_out = sum(o["value"] for o, s in zip(confirmed["vout"], spks, strict=True) if is_ft_script(s.hex()))
    assert round(ft_out * 100_000_000) == _SUPPLY, "FT units were not conserved across the airdrop"


def test_airdrop_with_an_advisory_royalty_output_is_accepted(node, deployed):  # noqa: F811
    """A royalty payout is a plain P2PKH output funded from RXD.

    It is ADVISORY — nothing in this transaction, or in any script pyrxd builds,
    compels it. What this proves is only that adding it does not break the FT
    conservation the chain *does* enforce.

    ``pay_royalty=True`` is required to make one appear at all: ``GlyphRoyalty``
    defaults to ``enforced=False``, and since #393 the default (``None``)
    consults that flag rather than paying regardless. Without the opt-in this
    builds an airdrop with no royalty output and proves nothing.
    """
    fresh = _deploy_ft(node)
    royalty = GlyphRoyalty(bps=250, address=PrivateKey().public_key().address())
    recipients = [AirdropRecipient(pkh=Hex20(secrets.token_bytes(20)), amount=3_000_000)]
    result = FtUtxoSet(ref=fresh.ref, utxos=[fresh.as_utxo()]).build_airdrop_tx(
        recipients,
        fresh.key,
        funding=[_plain_funding(node)],
        royalty=royalty,
        sale_price=40_000_000,
        pay_royalty=True,
    )
    assert [p.photons for p in result.royalty_payouts] == [1_000_000]

    res = node.accepts(result.tx.serialize().hex())
    assert res.get("allowed") is True, f"airdrop with a royalty output REJECTED: {res}"


def test_inflating_an_airdrop_output_is_rejected(node, deployed):  # noqa: F811
    """Negative control: a node that accepts everything is not a pass.

    Re-signs a valid airdrop with one recipient output inflated by a single
    unit. Radiant's FT epilogue enforces conservation in consensus, so this must
    die — and if it does not, every "accepted" above means nothing.
    """
    fresh = _deploy_ft(node)
    recipients = [AirdropRecipient(pkh=Hex20(secrets.token_bytes(20)), amount=3_000_000)]
    funding = _plain_funding(node)
    good = FtUtxoSet(ref=fresh.ref, utxos=[fresh.as_utxo()]).build_airdrop_tx(
        recipients,
        fresh.key,
        funding=[funding],
    )
    assert node.accepts(good.tx.serialize().hex()).get("allowed") is True

    # Rebuild by hand with one extra unit on the recipient output, taken out of
    # the funding change so the transaction still balances in RXD terms.
    bad = Transaction(
        tx_inputs=[
            TransactionInput(
                source_transaction=_src(fresh.txid, fresh.vout, fresh.script, fresh.value),
                source_txid=fresh.txid,
                source_output_index=fresh.vout,
                unlocking_script_template=_p2pkh_unlock(fresh.key),
            ),
            TransactionInput(
                source_transaction=_src(
                    funding.txid,
                    funding.vout,
                    P2PKH().lock(funding.private_key.public_key().hash160()).serialize(),
                    funding.value,
                ),
                source_txid=funding.txid,
                source_output_index=funding.vout,
                unlocking_script_template=_p2pkh_unlock(funding.private_key),
            ),
        ],
        tx_outputs=[
            TransactionOutput(Script(build_ft_locking_script(recipients[0].pkh, fresh.ref)), 3_000_000 + 1),
            TransactionOutput(
                Script(build_ft_locking_script(Hex20(fresh.key.public_key().hash160()), fresh.ref)),
                fresh.value - 3_000_000,
            ),
            TransactionOutput(
                P2PKH().lock(funding.private_key.public_key().hash160()), funding.value - _RELAY_FEE_SATS * 10 - 1
            ),
        ],
    )
    bad.sign()
    res = node.accepts(bad.serialize().hex())
    assert res.get("allowed") is False, (
        f"consensus ACCEPTED an inflating FT airdrop — the positive cases prove nothing: {res}"
    )
    # Assert WHY, not just that it failed: a rejection for a malformed
    # signature or a bad fee would be a false pass dressed as a negative
    # control. The FT epilogue's own failure surfaces as a script-verify error.
    reason = str(res.get("reject-reason", ""))
    assert "invalid-transaction-reference" in reason or "script-verify" in reason, (
        f"rejected, but not by the FT conservation rule this control is testing: {res}"
    )
    print(f"negative control reject-reason: {reason}")
