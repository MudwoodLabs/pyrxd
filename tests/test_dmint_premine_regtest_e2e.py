"""Live-regtest CONSENSUS proof for **dMint deploy-with-premine** (V1 + V2).

Premine was the largest deferral left in shipped code: ``glyph/builder.py``
refused ``premine_amount`` at every V1/V2 deploy entry point. The design was
already written down (``docs/dmint-research-photonic-deploy.md`` §7.2; Photonic
``mint.ts`` ``createRevealOutputs`` appends one ``ftScript`` output after the
``numContracts`` contract outputs) — what did not exist was any evidence that a
node would *accept* the resulting reveal.

Constructing a transaction is not evidence. This repo has shipped builders whose
output assembled cleanly and was rejected by consensus (the non-minimal height
push that made every pre-redesign V2 contract un-mineable; the multi-ref sighash
endianness bug). So this file proves, against a real ``radiant-core`` regtest
node, the three things a premine could plausibly break:

1. **The reveal is accepted.** The premine adds an output carrying ``tokenRef``
   under ``OP_PUSHINPUTREF`` while the commit hashlock the reveal spends asserts
   ``OP_REFTYPE_OUTPUT == OP_1`` for exactly that ref. If the premine were
   emitted as a singleton (0xd8) instead of a normal ref (0xd0), that assert
   would see refType SINGLETON and the reveal would die. A node saying "allowed"
   is the only way to know we got it right.
2. **The premined FT is spendable.** Through the shipped
   ``GlyphBuilder.build_ft_transfer_tx`` path, not a hand-rolled tx.
3. **The contract still mints afterwards.** The premine must not disturb the
   contract carriers — the V1/V2 covenants hardcode ``OP_OUTPUTVALUE OP_1`` — nor
   the FT-conservation sum the mint covenant enforces over the reward output.
   Proven with a real PoW-mined claim, plus a wrong-nonce negative control so a
   node that accepts everything cannot masquerade as a pass.

Opt-in: ``@pytest.mark.integration`` + ``RADIANT_REGTEST=1``. Never runs in
normal CI (the PoW grind is the cost PR #140 removed on purpose). Manages its
own throwaway container; moves no real value.

Run: ``RADIANT_REGTEST=1 pytest tests/test_dmint_premine_regtest_e2e.py -m integration -s``
"""

from __future__ import annotations

import os
import secrets
import sys

import pytest

# Reuse the isolated-regtest harness wholesale (same pattern as the V1/V2 dMint
# e2e tests): the ``node`` fixture spins up + tears down a throwaway container.
from test_htlc_regtest_e2e import (  # noqa: F401  (node = fixture)
    _RELAY_FEE_SATS,
    _p2pkh_unlock,
    _pay_to_spk,
    _RegtestNode,
    _src,
    node,
)

from pyrxd.glyph.builder import (
    DmintV1DeployParams,
    DmintV2DeployParams,
    FtTransferParams,
    FtUtxo,
    GlyphBuilder,
)
from pyrxd.glyph.dmint import (
    DmintContractUtxo,
    DmintMinerFundingUtxo,
    DmintState,
    build_dmint_mint_tx,
    build_dmint_v1_mint_preimage,
    build_dmint_v2_mint_preimage,
    build_mint_scriptsig,
    mine_solution_dispatch,
)
from pyrxd.glyph.script import build_ft_locking_script
from pyrxd.glyph.types import GlyphMetadata, GlyphProtocol, GlyphRef
from pyrxd.keys import PrivateKey
from pyrxd.script.script import Script
from pyrxd.script.type import encode_pushdata, to_unlock_script_template
from pyrxd.security.errors import MaxAttemptsError
from pyrxd.security.types import Hex20
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_input import TransactionInput
from pyrxd.transaction.transaction_output import TransactionOutput

pytestmark = pytest.mark.integration

_CARRIER = 1  # contract singleton carrier — both covenants hardcode vout0 value == 1
_PREMINE = 50_000_000  # 0.5 RXD of premined FT units; comfortably covers a transfer fee
_REWARD = 50_000
_MAX_HEIGHT = 628_328
_DIFFICULTY = 1  # target 0x7fffffffffffffff — the easiest legal target
_FUNDING = 50_000_000  # plain coin funding a mint (reward + fee + change)

_MINER_ARGV = [sys.executable, "-m", "pyrxd.contrib.miner"]
if os.environ.get("DMINT_MINE_WORKERS"):
    _MINER_ARGV += ["--workers", os.environ["DMINT_MINE_WORKERS"]]
# The PoW floor is consensus-hardcoded (4 zero bytes + a signed-positive int64), so
# each claim is an intrinsic ~2**33-hash search no parameter can shorten. The default
# ceiling is 3600s rather than the 1800s the other dMint regtest suites use because
# the tail is fat: on a 24-worker run measured here the V1 claim landed in 58s and the
# V2 claim in 1505s, which is within one unlucky factor of a 1800s false failure.
_MINE_TIMEOUT_S = float(os.environ.get("DMINT_MINE_TIMEOUT_S", "3600"))


def _p2pkh(pkh: object) -> bytes:
    return b"\x76\xa9\x14" + bytes(pkh) + b"\x88\xac"


def _commit_reveal_unlock(key: PrivateKey, suffix: bytes):
    """``<sig> <pubkey> <gly> <CBOR>`` unlock for the reveal's FT-commit input."""
    pub = key.public_key().serialize()

    def _u(tx, idx):
        inp = tx.inputs[idx]
        sig = key.sign(tx.preimage(idx))
        return Script(encode_pushdata(sig + inp.sighash.to_bytes(1, "little")) + encode_pushdata(pub) + suffix)

    return to_unlock_script_template(_u, lambda: 110 + len(suffix))


class _PremineDeploy:
    """What a premine deploy leaves on chain, for the assertions below."""

    def __init__(
        self,
        contract: DmintContractUtxo,
        token_ref: GlyphRef,
        premine_txid: str,
        premine_vout: int,
        premine_script: bytes,
        premine_value: int,
    ) -> None:
        self.contract = contract
        self.token_ref = token_ref
        self.premine_txid = premine_txid
        self.premine_vout = premine_vout
        self.premine_script = premine_script
        self.premine_value = premine_value


def _deploy_with_premine(node: _RegtestNode, owner: PrivateKey, *, v2: bool) -> _PremineDeploy:
    """Deploy one dMint contract WITH a premine and return the live UTXOs.

    Output layout of the reveal follows ``DmintV1RevealScripts``' documented
    order (Photonic ``createRevealOutputs`` parity)::

        vout0  contract (value 1)
        vout1  premine FT (value _PREMINE)
        vout2  change
    """
    owner_pkh = Hex20(owner.public_key().hash160())
    owner_spk = _p2pkh(owner_pkh)
    meta = GlyphMetadata.for_dmint_ft(
        ticker="PRE",
        name="premine regtest",
        decimals=0,
        protocol=[int(GlyphProtocol.FT), int(GlyphProtocol.DMINT)],
    )
    common = dict(
        metadata=meta,
        owner_pkh=owner_pkh,
        num_contracts=1,
        max_height=_MAX_HEIGHT if not v2 else 1_000,
        reward_photons=_REWARD if not v2 else 1_000,
        difficulty=_DIFFICULTY,
        premine_amount=_PREMINE,
    )
    params = DmintV2DeployParams(**common) if v2 else DmintV1DeployParams(**common)
    deploy = GlyphBuilder().prepare_dmint_deploy(params)
    commit_script = deploy.commit_result.commit_script

    # --- commit tx: [FT-commit hashlock | ref-seed | change] ---
    # commit:0 must carry the premine photons forward — they are real value, not
    # an accounting entry, and the reveal has no other funding input.
    seed_value = 200_000_000
    seed_txid = _pay_to_spk(node, owner_spk, seed_value)
    commit0, commit1 = _PREMINE + 2_000_000, 1_000_000
    cin = TransactionInput(
        source_transaction=_src(seed_txid, 0, owner_spk, seed_value),
        source_txid=seed_txid,
        source_output_index=0,
        unlocking_script_template=_p2pkh_unlock(owner),
    )
    cin.satoshis = seed_value
    cin.locking_script = Script(owner_spk)
    commit_tx = Transaction(
        tx_inputs=[cin],
        tx_outputs=[
            TransactionOutput(Script(commit_script), commit0),
            TransactionOutput(Script(owner_spk), commit1),
            TransactionOutput(Script(owner_spk), seed_value - commit0 - commit1 - _RELAY_FEE_SATS),
        ],
    )
    commit_tx.sign()
    commit_txid = node.cli("sendrawtransaction", commit_tx.serialize().hex())
    assert isinstance(commit_txid, str), f"commit broadcast failed: {commit_txid}"
    node.mine(1)

    # --- reveal tx ---
    rev = deploy.build_reveal_outputs(commit_txid)
    token_ref = GlyphRef(txid=commit_txid, vout=0)
    assert rev.premine_amount == _PREMINE
    assert rev.premine_script == build_ft_locking_script(owner_pkh, token_ref), (
        "premine output must be the canonical 75-byte FT lock on tokenRef"
    )

    rin0 = TransactionInput(
        source_transaction=_src(commit_txid, 0, commit_script, commit0),
        source_txid=commit_txid,
        source_output_index=0,
        unlocking_script_template=_commit_reveal_unlock(owner, rev.scriptsig_suffix),
    )
    rin0.satoshis = commit0
    rin0.locking_script = Script(commit_script)
    rin1 = TransactionInput(
        source_transaction=_src(commit_txid, 1, owner_spk, commit1),
        source_txid=commit_txid,
        source_output_index=1,
        unlocking_script_template=_p2pkh_unlock(owner),
    )
    rin1.satoshis = commit1
    rin1.locking_script = Script(owner_spk)

    change = commit0 + commit1 - _CARRIER - _PREMINE - _RELAY_FEE_SATS
    assert change > 0
    reveal_tx = Transaction(
        tx_inputs=[rin0, rin1],
        tx_outputs=[
            TransactionOutput(Script(rev.contract_scripts[0]), rev.contract_value),
            TransactionOutput(Script(rev.premine_script), rev.premine_amount),
            TransactionOutput(Script(owner_spk), change),
        ],
    )
    reveal_tx.sign()
    raw = reveal_tx.serialize().hex()

    # THE PROOF for claim 1: the node accepts a reveal carrying a premine output.
    res = node.accepts(raw)
    assert res.get("allowed") is True, f"premine deploy reveal REJECTED by consensus: {res}"
    reveal_txid = node.cli("sendrawtransaction", raw)
    assert isinstance(reveal_txid, str), f"reveal broadcast failed: {reveal_txid}"
    node.mine(1)

    # The premine landed as its own confirmed UTXO with the exact expected bytes.
    live = node.cli("gettxout", reveal_txid, "1")
    assert isinstance(live, dict), f"premine UTXO missing from the chain: {live}"
    assert bytes.fromhex(live["scriptPubKey"]["hex"]) == rev.premine_script
    assert round(float(live["value"]) * 100_000_000) == _PREMINE

    # The contract carrier is untouched: still the 1-photon singleton at height 0.
    state = DmintState.from_script(rev.contract_scripts[0])
    assert state.height == 0
    assert state.is_v1 is (not v2)
    contract = DmintContractUtxo(
        txid=reveal_txid,
        vout=0,
        value=rev.contract_value,
        script=rev.contract_scripts[0],
        state=state,
    )
    assert contract.value == 1, "premine must not perturb the 1-photon contract carrier"
    return _PremineDeploy(contract, token_ref, reveal_txid, 1, rev.premine_script, _PREMINE)


def _spend_premine(node: _RegtestNode, owner: PrivateKey, dep: _PremineDeploy) -> None:
    """Move the premined FT through the shipped transfer path and prove acceptance."""
    recipient_pkh = Hex20(secrets.token_bytes(20))
    result = GlyphBuilder().build_ft_transfer_tx(
        FtTransferParams(
            ref=dep.token_ref,
            utxos=[
                FtUtxo(
                    txid=dep.premine_txid,
                    vout=dep.premine_vout,
                    value=dep.premine_value,
                    ft_amount=dep.premine_value,
                    ft_script=dep.premine_script,
                )
            ],
            amount=dep.premine_value,
            new_owner_pkh=recipient_pkh,
            private_key=owner,
        )
    )
    raw = result.tx.serialize().hex()
    res = node.accepts(raw)
    assert res.get("allowed") is True, f"premined FT is NOT spendable — consensus rejected the transfer: {res}"
    txid = node.cli("sendrawtransaction", raw)
    assert isinstance(txid, str), f"premine transfer broadcast failed: {txid}"
    node.mine(1)

    assert not node.cli("gettxout", dep.premine_txid, str(dep.premine_vout)), "premine UTXO not spent"
    moved = node.cli("gettxout", txid, "0")
    assert isinstance(moved, dict), f"transferred FT UTXO missing: {moved}"
    assert bytes.fromhex(moved["scriptPubKey"]["hex"]) == build_ft_locking_script(recipient_pkh, dep.token_ref)


def _mine_and_assert(node: _RegtestNode, dep: _PremineDeploy, *, v2: bool) -> None:
    """PoW-mine one claim from the post-premine contract; accept it, reject a bad nonce."""
    miner = PrivateKey(secrets.token_bytes(32))
    miner_pkh = bytes(Hex20(miner.public_key().hash160()))
    fund_spk = _p2pkh(miner_pkh)
    fund_txid = _pay_to_spk(node, fund_spk, _FUNDING)
    funding = DmintMinerFundingUtxo(txid=fund_txid, vout=0, value=_FUNDING, script=fund_spk)
    nonce_width = 8 if v2 else 4

    mint = pre = nonce = None
    for attempt in range(40):
        # V1's 4-byte nonce space holds a solution only ~39% of the time at the
        # consensus 4-zero-byte floor, so real miners reroll the preimage; the
        # OP_RETURN is the cheapest field to vary. V2's 8-byte space always has one.
        mint = build_dmint_mint_tx(
            dep.contract,
            nonce=b"\x00" * nonce_width,
            miner_pkh=miner_pkh,
            current_time=0,
            funding_utxo=funding,
            op_return_msg=b"pre" + attempt.to_bytes(2, "big"),
        )
        if v2:
            # V2 has no canonical "OP_RETURN at vout[2]" convention, so the caller
            # picks which output the covenant binds outputHash to (matching
            # tests/test_dmint_v2_regtest_e2e.py: the OP_RETURN at vout[2]).
            pre = build_dmint_v2_mint_preimage(dep.contract, funding, mint.tx.outputs[2].locking_script.script)
        else:
            pre = build_dmint_v1_mint_preimage(dep.contract, funding, mint.tx)
        try:
            result = mine_solution_dispatch(
                pre.preimage,
                target=dep.contract.state.target,
                nonce_width=nonce_width,
                miner_argv=_MINER_ARGV,
                timeout_s=_MINE_TIMEOUT_S,
            )
        except MaxAttemptsError:
            print(f"[mine] reroll {attempt}: nonce space exhausted; varying OP_RETURN", flush=True)
            continue
        nonce = result.nonce
        print(f"[mine] hit on reroll {attempt}: nonce={nonce.hex()} in {result.elapsed_s:.0f}s", flush=True)
        break
    assert nonce is not None, "no nonce found within 40 preimage rerolls (P < 1e-13 — investigate)"

    def _finalise(n: bytes) -> str:
        mint.tx.inputs[0].unlocking_script = Script(
            build_mint_scriptsig(n, pre.input_hash, pre.output_hash, nonce_width=nonce_width)
        )
        fsig = miner.sign(mint.tx.preimage(1))
        fsh = mint.tx.inputs[1].sighash.to_bytes(1, "little")
        mint.tx.inputs[1].unlocking_script = Script(
            encode_pushdata(fsig + fsh) + encode_pushdata(miner.public_key().serialize())
        )
        return mint.tx.serialize().hex()

    raw_good = _finalise(nonce)
    good = node.accepts(raw_good)
    assert good.get("allowed") is True, f"mint from a premined contract REJECTED by consensus: {good}"

    bad_nonce = bytes([nonce[0] ^ 0xFF]) + nonce[1:]
    assert bad_nonce != nonce
    bad = node.accepts(_finalise(bad_nonce))
    assert bad.get("allowed") is False, f"wrong-nonce mint ACCEPTED (PoW not enforced!): {bad}"

    mint_txid = node.cli("sendrawtransaction", _finalise(nonce))
    assert isinstance(mint_txid, str), f"mint broadcast failed: {mint_txid}"
    node.mine(1)
    recreated = node.cli("gettxout", mint_txid, "0")
    assert isinstance(recreated, dict), f"recreated contract UTXO missing: {recreated}"
    new_spk = bytes.fromhex(recreated["scriptPubKey"]["hex"])
    assert DmintState.from_script(new_spk).height == 1, "recreated contract not at height 1"


class TestDmintPremineOnConsensus:
    def test_v1_premine_deploy_spend_and_mint(self, node: _RegtestNode) -> None:
        owner = PrivateKey(secrets.token_bytes(32))
        dep = _deploy_with_premine(node, owner, v2=False)
        _spend_premine(node, owner, dep)
        _mine_and_assert(node, dep, v2=False)

    def test_v2_premine_deploy_spend_and_mint(self, node: _RegtestNode) -> None:
        owner = PrivateKey(secrets.token_bytes(32))
        dep = _deploy_with_premine(node, owner, v2=True)
        _spend_premine(node, owner, dep)
        _mine_and_assert(node, dep, v2=True)
