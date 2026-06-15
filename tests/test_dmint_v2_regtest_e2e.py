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

The deploy uses direct ref-induction (the HTLC-R1 mechanism: spend two genesis
outpoints so the contract output's singleton ``contractRef`` + normal
``tokenRef`` are inducted) rather than ``prepare_dmint_deploy``, because the V2
deploy/mint *builder* still emits the wrong "pool"/1-input shape — rewriting it
to the consensus-correct shape proven here is deferred follow-up (see #219). The
mint is therefore built in the **consensus-correct shape** the covenant
requires: contract + funding inputs; outputs = recreated contract (value **1**,
a singleton) at vout[0], 75-byte FT reward at vout[1], OP_RETURN at vout[2],
change at vout[3]; the recreated contract's state equals the current state with
**only** ``height`` incremented (the covenant forbids changing any other state
field — which is also why DAA/ASERT/LWMA cannot work with this covenant; FIXED
only).

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

from pyrxd.glyph.dmint import (
    DaaMode,
    DmintAlgo,
    DmintContractUtxo,
    DmintDeployParams,
    DmintState,
    V2UnvalidatedWarning,
    build_dmint_contract_script,
    build_dmint_v1_ft_output_script,
    build_mint_scriptsig,
    build_pow_preimage,
    mine_solution_dispatch,
)
from pyrxd.glyph.types import GlyphRef
from pyrxd.keys import PrivateKey
from pyrxd.script.script import Script
from pyrxd.script.type import encode_pushdata
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
    state = contract.state
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", V2UnvalidatedWarning)
        recreated = build_dmint_contract_script(
            _v2_params(
                max_height=state.max_height,
                reward=state.reward,
                height=state.height + 1,
                last_time=state.last_time,
                contract_ref=state.contract_ref,
                token_ref=state.token_ref,
            )
        )
    miner_pkh = bytes(Hex20(PrivateKey(secrets.token_bytes(32)).public_key().hash160()))
    reward_script = build_dmint_v1_ft_output_script(miner_pkh, state.token_ref)
    msg = b"pyrxd-v2-regtest"
    op_return = b"\x6a\x03msg" + bytes([len(msg)]) + msg

    funding = _carve(node, 50_000_000)
    change_key = PrivateKey(secrets.token_bytes(32))

    placeholder = b"\xff" * 32
    # Contract input: a covenant UTXO (raw scriptSig), not a P2PKH — build directly.
    contract_in = TransactionInput(
        source_transaction=_src(contract.txid, contract.vout, contract.script, contract.value),
        source_txid=contract.txid,
        source_output_index=contract.vout,
        unlocking_script_template=None,
    )
    contract_in.satoshis = contract.value
    contract_in.locking_script = Script(contract.script)
    contract_in.unlocking_script = Script(build_mint_scriptsig(b"\x00" * 8, placeholder, placeholder, nonce_width=8))
    funding_in = _spend(funding)
    funding_in.unlocking_script_template = None
    funding_in.unlocking_script = Script(b"\x00" * 108)

    outs = [
        TransactionOutput(Script(recreated), _CONTRACT_VALUE),
        TransactionOutput(Script(reward_script), state.reward),
        TransactionOutput(Script(op_return), 0),
        TransactionOutput(Script(_p2pkh_spk(change_key)), 0),
    ]
    tx = Transaction(tx_inputs=[contract_in, funding_in], tx_outputs=outs)
    fee = len(tx.serialize()) * 10_000
    change_val = funding.val - state.reward - fee
    assert change_val > 546, f"funding too small: change {change_val}"
    outs[3].satoshis = change_val

    pre = build_pow_preimage(
        txid_le=bytes.fromhex(contract.txid)[::-1],
        contract_ref_bytes=state.contract_ref.to_bytes(),
        input_script=funding.spk,
        output_script=op_return,
    )
    mined = mine_solution_dispatch(
        preimage=pre.preimage, target=state.target, nonce_width=8, miner_argv=_MINER_ARGV, timeout_s=900.0
    )
    nonce = mined.nonce
    contract_in.unlocking_script = Script(build_mint_scriptsig(nonce, pre.input_hash, pre.output_hash, nonce_width=8))
    _sign_funding_input(tx, 1, funding.key)
    return tx, nonce


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
