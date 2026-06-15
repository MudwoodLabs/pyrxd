"""dMint **V2** (FIXED difficulty) end-to-end consensus proof on a real
radiant-core regtest node — the V2 analog of ``test_dmint_v1_regtest_e2e.py``
(issue #219).

V2 dMint had never been validated against on-chain bytes (hence
``V2UnvalidatedWarning``) and was in fact broken at the covenant-bytecode level
— it has never worked on any chain (consistent with "no V2 contract in the
wild"). Two transcription bugs (inherited from Photonic's ``script.ts``) made
every V2 mint consensus-invalid, and are fixed in ``pyrxd.glyph.dmint``:

1. ``_PART_A`` was missing ``OP_INPUTINDEX`` (0xc0) before ``OP_OUTPOINTTXHASH``,
   so the latter popped the ``target`` state value as the input index →
   "input index out of range".
2. ``_PART_C`` began with a duplicate ``a269`` (the PoW target-compare
   ``_PART_B2`` already performs), which after ``_PART_B4`` ran ``maxHeight >=
   reward`` → "Script failed an OP_VERIFY operation".

This test proves the fixed V2 covenant is accepted by REAL Radiant consensus:
deploy a FIXED-difficulty V2 contract, PoW-mine an 8-byte-nonce mint, and
confirm the node accepts it (and rejects a wrong nonce).

Two paths are proven: ``test_v2_fixed_mint_...`` deploys by direct ref-induction
(spend two genesis outpoints so the singleton ``contractRef`` + normal
``tokenRef`` are inducted) as a focused covenant proof, and
``test_v2_deploy_via_api_then_mint`` exercises the full library API
(``prepare_dmint_deploy(DmintV2DeployParams)`` -> commit -> reveal ->
``build_reveal_outputs``). Both feed ``build_dmint_mint_tx``, which emits the
consensus-correct V1-shaped mint: contract + funding inputs; outputs = recreated
contract (value **1**, a singleton) at vout[0], FT reward at vout[1], OP_RETURN
at vout[2], change. The recreated state equals the current state with **only**
``height`` incremented — which is also why DAA/ASERT/LWMA cannot work with this
covenant (FIXED only).

Gating / safety: opt-in via ``@pytest.mark.integration`` + ``RADIANT_REGTEST=1``;
reuses the isolated throwaway-container harness from ``test_htlc_regtest_e2e``
(same pattern as the V1 test). Never touches mainnet, moves no real value.

Run: ``RADIANT_REGTEST=1 pytest tests/test_dmint_v2_regtest_e2e.py -m integration -s``
"""

from __future__ import annotations

import secrets
import sys
import warnings

import pytest

# Reuse the isolated-regtest harness wholesale (same pattern as the V1 test):
# the ``node`` fixture spins up + tears down a throwaway radiant-core container.
from test_htlc_regtest_e2e import (  # noqa: F401  (node = fixture)
    _RELAY_FEE_SATS,
    _p2pkh_unlock,
    _pay_to_spk,
    _RegtestNode,
    _src,
    node,
)

from pyrxd.glyph.builder import DmintV2DeployParams, GlyphBuilder
from pyrxd.glyph.dmint import (
    DaaMode,
    DmintAlgo,
    DmintContractUtxo,
    DmintDeployParams,
    DmintMinerFundingUtxo,
    DmintState,
    V2UnvalidatedWarning,
    build_dmint_contract_script,
    build_dmint_mint_tx,
    build_dmint_v2_mint_preimage,
    build_mint_scriptsig,
    mine_solution_dispatch,
)
from pyrxd.glyph.types import GlyphMetadata, GlyphProtocol, GlyphRef
from pyrxd.keys import PrivateKey
from pyrxd.script.script import Script
from pyrxd.script.type import encode_pushdata, to_unlock_script_template
from pyrxd.security.types import Hex20
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_input import TransactionInput
from pyrxd.transaction.transaction_output import TransactionOutput

pytestmark = pytest.mark.integration

_MINER_ARGV = [sys.executable, "-m", "pyrxd.contrib.miner"]
_CONTRACT_VALUE = 1  # V2 contract is a value-1 singleton (covenant: OP_OUTPUTVALUE OP_1 OP_NUMEQUALVERIFY)


def _p2pkh_spk(key: PrivateKey) -> bytes:
    return b"\x76\xa9\x14" + bytes(Hex20(key.public_key().hash160())) + b"\x88\xac"


class _Coin:
    def __init__(self, txid: str, spk: bytes, val: int, key: PrivateKey) -> None:
        self.txid, self.vout, self.spk, self.val, self.key = txid, 0, spk, val, key


def _carve(node: _RegtestNode, value: int) -> _Coin:
    """Carve a fresh plain-P2PKH UTXO worth ``value`` under a brand-new key
    (genesis outpoint for ref induction, or the miner's funding coin)."""
    key = PrivateKey(secrets.token_bytes(32))
    spk = _p2pkh_spk(key)
    txid = _pay_to_spk(node, spk, value)
    return _Coin(txid, spk, value, key)


def _spend(coin: _Coin) -> TransactionInput:
    tin = TransactionInput(
        source_transaction=_src(coin.txid, coin.vout, coin.spk, coin.val),
        source_txid=coin.txid,
        source_output_index=coin.vout,
        unlocking_script_template=_p2pkh_unlock(coin.key),
    )
    tin.satoshis = coin.val
    tin.locking_script = Script(coin.spk)
    return tin


def _sign_funding_input(tx: Transaction, idx: int, key: PrivateKey) -> None:
    """Manually sign a P2PKH input whose unlocking_script is a placeholder."""
    inp = tx.inputs[idx]
    sig = key.sign(tx.preimage(idx))
    inp.unlocking_script = Script(
        encode_pushdata(sig + inp.sighash.to_bytes(1, "little")) + encode_pushdata(key.public_key().serialize())
    )


def _v2_params(*, max_height, reward, height, last_time, contract_ref, token_ref):
    return DmintDeployParams(
        contract_ref=contract_ref,
        token_ref=token_ref,
        max_height=max_height,
        reward=reward,
        difficulty=1,  # FIXED, easiest target — only the 4-zero-byte PoW floor applies
        algo=DmintAlgo.SHA256D,
        daa_mode=DaaMode.FIXED,
        target_time=60,
        half_life=3600,
        height=height,
        last_time=last_time,
    )


def _deploy_v2_contract(node: _RegtestNode, *, max_height: int, reward: int) -> DmintContractUtxo:
    """Create a FIXED-difficulty V2 dMint contract UTXO (value-1 singleton) by
    inducting the singleton ``contractRef`` + normal ``tokenRef`` from two spent
    genesis outpoints, with the V2 contract script at vout 0.
    """
    g_tok = _carve(node, 200_000_000)
    g_con = _carve(node, 200_000_000)
    token_ref = GlyphRef(txid=g_tok.txid, vout=0)
    contract_ref = GlyphRef(txid=g_con.txid, vout=0)

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", V2UnvalidatedWarning)
        params = _v2_params(
            max_height=max_height,
            reward=reward,
            height=0,
            last_time=0,
            contract_ref=contract_ref,
            token_ref=token_ref,
        )
        contract_script = build_dmint_contract_script(params)
        state = DmintState.from_script(contract_script)
    assert state.is_v1 is False, "deployed script did not parse as V2"

    change_key = PrivateKey(secrets.token_bytes(32))
    change_val = g_tok.val + g_con.val - _CONTRACT_VALUE - _RELAY_FEE_SATS
    deploy = Transaction(
        tx_inputs=[_spend(g_tok), _spend(g_con)],
        tx_outputs=[
            TransactionOutput(Script(contract_script), _CONTRACT_VALUE),
            TransactionOutput(Script(_p2pkh_spk(change_key)), change_val),
        ],
    )
    deploy.sign()
    res = node.accepts(deploy.serialize().hex())
    assert res["allowed"] is True, f"V2 deploy not accepted by consensus: {res}"
    dtxid = node.cli("sendrawtransaction", deploy.serialize().hex())
    assert isinstance(dtxid, str), dtxid
    node.mine(1)
    assert node.cli("gettxout", dtxid, "0"), "deployed V2 contract UTXO missing"
    return DmintContractUtxo(txid=dtxid, vout=0, value=_CONTRACT_VALUE, script=contract_script, state=state)


def _build_signed_v2_mint(node: _RegtestNode, contract: DmintContractUtxo) -> tuple[Transaction, bytes]:
    """Build, mine, and sign a consensus-correct (V1-shaped) FIXED V2 mint.

    Returns ``(tx, nonce)``. The recreated contract carries the next state
    (current state with only ``height`` incremented) at value 1; the FT reward +
    fee come from a plain funding input; the OP_RETURN at vout[2] is the
    preimage's bound output. An 8-byte nonce reliably solves in a single ~2**32
    sweep (no message-rolling, unlike V1's 4-byte nonce).
    """
    funding_coin = _carve(node, 50_000_000)
    funding = DmintMinerFundingUtxo(
        txid=funding_coin.txid, vout=funding_coin.vout, value=funding_coin.val, script=funding_coin.spk
    )
    miner_pkh = bytes(Hex20(PrivateKey(secrets.token_bytes(32)).public_key().hash160()))

    # Build the mint via the real library API — the V2 path now emits the
    # consensus-correct V1-shaped tx (contract + funding inputs; value-1 singleton
    # recreated at height+1; FT reward; OP_RETURN at vout[2]; change).
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", V2UnvalidatedWarning)
        result = build_dmint_mint_tx(
            contract,
            nonce=b"\x00" * 8,
            miner_pkh=miner_pkh,
            current_time=0,
            funding_utxo=funding,
            op_return_msg=b"pyrxd-v2-regtest",
        )
        tx = result.tx
        op_return_script = tx.outputs[2].locking_script.script
        pre = build_dmint_v2_mint_preimage(contract, funding, op_return_script)

    mined = mine_solution_dispatch(
        preimage=pre.preimage, target=contract.state.target, nonce_width=8, miner_argv=_MINER_ARGV, timeout_s=900.0
    )
    nonce = mined.nonce
    tx.inputs[0].unlocking_script = Script(build_mint_scriptsig(nonce, pre.input_hash, pre.output_hash, nonce_width=8))
    _sign_funding_input(tx, 1, funding_coin.key)
    return tx, nonce


# --------------------------------------------------------------------------- deploy via the real API


def _p2pkh(pkh) -> bytes:
    return b"\x76\xa9\x14" + bytes(pkh) + b"\x88\xac"


def _commit_reveal_unlock(key: PrivateKey, suffix: bytes):
    """Unlock template for the reveal's FT-commit hashlock input:
    ``<sig> <pubkey> <gly> <CBOR>`` (the ``<gly><CBOR>`` part is ``suffix``)."""
    pub = key.public_key().serialize()

    def _u(tx, idx):
        inp = tx.inputs[idx]
        sig = key.sign(tx.preimage(idx))
        return Script(encode_pushdata(sig + inp.sighash.to_bytes(1, "little")) + encode_pushdata(pub) + suffix)

    return to_unlock_script_template(_u, lambda: 110 + len(suffix))


def _deploy_v2_via_api(node: _RegtestNode, owner: PrivateKey) -> DmintContractUtxo:
    """Deploy a 1-contract V2 dMint via the real API (prepare_dmint_deploy +
    commit -> reveal + build_reveal_outputs) and return the live value-1 singleton
    contract UTXO. Mirrors the V1 deploy; asserts the reveal is accepted by
    consensus before the caller spends minutes mining.
    """
    owner_pkh = Hex20(owner.public_key().hash160())
    owner_spk = _p2pkh(owner_pkh)
    meta = GlyphMetadata.for_dmint_ft(
        ticker="TV2",
        name="V2 dMint regtest",
        decimals=0,
        protocol=[int(GlyphProtocol.FT), int(GlyphProtocol.DMINT)],
    )
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", V2UnvalidatedWarning)
        deploy = GlyphBuilder().prepare_dmint_deploy(
            DmintV2DeployParams(
                metadata=meta,
                owner_pkh=owner_pkh,
                num_contracts=1,
                max_height=1000,
                reward_photons=1000,
                difficulty=1,
            ),
            allow_v2_deploy=True,
        )
    commit_script = deploy.commit_result.commit_script

    # commit tx: FT-commit (vout0) | ref-seed -> contractRef genesis (vout1) | change
    seed_txid = _pay_to_spk(node, owner_spk, 10_000_000)
    c0, c1 = 2_000_000, 1_000_000
    cin = TransactionInput(
        source_transaction=_src(seed_txid, 0, owner_spk, 10_000_000),
        source_txid=seed_txid,
        source_output_index=0,
        unlocking_script_template=_p2pkh_unlock(owner),
    )
    cin.satoshis = 10_000_000
    cin.locking_script = Script(owner_spk)
    commit_change = 10_000_000 - c0 - c1 - _RELAY_FEE_SATS
    commit_tx = Transaction(
        tx_inputs=[cin],
        tx_outputs=[
            TransactionOutput(Script(commit_script), c0),
            TransactionOutput(Script(owner_spk), c1),
            TransactionOutput(Script(owner_spk), commit_change),
        ],
    )
    commit_tx.sign()
    commit_txid = node.cli("sendrawtransaction", commit_tx.serialize().hex())
    assert isinstance(commit_txid, str), commit_txid
    node.mine(1)

    # reveal tx: spend commit:0 (FT-commit + CBOR) AND commit:1 (contractRef genesis)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", V2UnvalidatedWarning)
        rev = deploy.build_reveal_outputs(commit_txid)
    contract_script = rev.contract_scripts[0]
    rin0 = TransactionInput(
        source_transaction=_src(commit_txid, 0, commit_script, c0),
        source_txid=commit_txid,
        source_output_index=0,
        unlocking_script_template=_commit_reveal_unlock(owner, rev.scriptsig_suffix),
    )
    rin0.satoshis = c0
    rin0.locking_script = Script(commit_script)
    rin1 = TransactionInput(
        source_transaction=_src(commit_txid, 1, owner_spk, c1),
        source_txid=commit_txid,
        source_output_index=1,
        unlocking_script_template=_p2pkh_unlock(owner),
    )
    rin1.satoshis = c1
    rin1.locking_script = Script(owner_spk)
    reveal_change = c0 + c1 - _CONTRACT_VALUE - _RELAY_FEE_SATS
    reveal_tx = Transaction(
        tx_inputs=[rin0, rin1],
        tx_outputs=[
            TransactionOutput(Script(contract_script), rev.contract_value),  # value 1 (singleton)
            TransactionOutput(Script(owner_spk), reveal_change),
        ],
    )
    reveal_tx.sign()
    res = node.accepts(reveal_tx.serialize().hex())
    assert res.get("allowed") is True, f"V2 deploy reveal REJECTED by consensus: {res}"
    reveal_txid = node.cli("sendrawtransaction", reveal_tx.serialize().hex())
    assert isinstance(reveal_txid, str), reveal_txid
    node.mine(1)
    state = DmintState.from_script(contract_script)
    assert state.is_v1 is False and state.height == 0
    return DmintContractUtxo(txid=reveal_txid, vout=0, value=rev.contract_value, script=contract_script, state=state)


class TestRadiantDmintV2OnConsensus:
    def test_v2_fixed_mint_accepted_and_wrong_nonce_rejected(self, node):
        contract = _deploy_v2_contract(node, max_height=10, reward=1000)
        tx, nonce = _build_signed_v2_mint(node, contract)

        raw_good = tx.serialize().hex()
        res = node.accepts(raw_good)
        assert res["allowed"] is True, f"valid FIXED V2 mint rejected by consensus: {res}"

        # Wrong nonce: flip the first nonce byte → PoW four-zero-bytes check fails.
        good_ss = tx.inputs[0].unlocking_script.script
        # V2 scriptsig: <0x08><nonce8><0x20><ih32><0x20><oh32><0x00>
        ih = good_ss[10:42]
        oh = good_ss[43:75]
        bad_nonce = bytes([nonce[0] ^ 0xFF]) + nonce[1:]
        tx.inputs[0].unlocking_script = Script(build_mint_scriptsig(bad_nonce, ih, oh, nonce_width=8))
        raw_wrong = tx.serialize().hex()
        tx.inputs[0].unlocking_script = Script(good_ss)
        assert raw_wrong != raw_good
        res = node.accepts(raw_wrong)
        assert res["allowed"] is False, f"wrong-nonce V2 mint was accepted: {res}"

        # The valid mint spends the contract + recreates it at height+1 with the FT reward.
        mtxid = node.cli("sendrawtransaction", raw_good)
        assert isinstance(mtxid, str), mtxid
        node.mine(1)
        assert node.cli("gettxout", contract.txid, "0") in (None, ""), "V2 contract UTXO should be spent after mint"
        recreated_out = node.cli("gettxout", mtxid, "0")
        assert recreated_out and round(recreated_out["value"] * 1e8) == _CONTRACT_VALUE, "recreated V2 contract wrong"
        reward_out = node.cli("gettxout", mtxid, "1")
        assert reward_out and round(reward_out["value"] * 1e8) == 1000, "V2 FT reward output (vout 1) wrong"

    def test_v2_deploy_via_api_then_mint(self, node):
        """The real deploy API (prepare_dmint_deploy(DmintV2DeployParams) ->
        commit -> reveal -> build_reveal_outputs) produces a value-1 V2 singleton
        that the real mint builder can spend and consensus accepts."""
        owner = PrivateKey(secrets.token_bytes(32))
        contract = _deploy_v2_via_api(node, owner)
        assert contract.value == 1 and contract.state.is_v1 is False
        tx, _nonce = _build_signed_v2_mint(node, contract)
        res = node.accepts(tx.serialize().hex())
        assert res["allowed"] is True, f"mint of API-deployed V2 contract rejected: {res}"
