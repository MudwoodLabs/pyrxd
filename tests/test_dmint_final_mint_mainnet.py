"""Real mainnet V1 dMint final mints, rebuilt by pyrxd from the contracts they spent.

``tests/test_dmint_final_mint.py`` checks the final mint against a transcription of the
covenant's output-validation block, and that transcription takes height and maxHeight from the
state pyrxd parsed, the same state the builder decides from. A parse that was wrong in a way
that moved both together would pass there. Transactions the chain accepted cannot be wrong that
way, so here pyrxd rebuilds them.

``tests/fixtures/dmint_v1_final_mints_mainnet.json`` holds five mainnet final mints and one
ordinary mint (the control), each with the transaction that created the contract output it
spends. Nothing in the file is taken on trust: every txid is re-derived from the raw bytes, and
the spent contract and the funding coin are read out of the spent transaction, whose own bytes
must hash to the outpoint the mint spends.

For each one, pyrxd parses the spent contract from its real script; ``next_mint_is_final``
must say what the chain did (a burn at output 0, or a contract recreated one height up); and
``build_dmint_mint_tx``, given the real funding coin and the reward key hash and message the
chain paid, must build outputs 0-2 byte for byte. The change output is the one output pyrxd
cannot reproduce, and does not try to: pyrxd pays change to the reward key, while these miners
paid it back to the funding address, and the fee rate was theirs. So the change output is taken
from the chain, with the two scriptSigs (the nonce and the signature, which pyrxd leaves as
placeholders), and the result must then be the chain's transaction exactly: its bytes and its
txid, so version, both outpoints, sequences, all four outputs and locktime.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
from pathlib import Path

import pytest

from pyrxd.glyph.dmint import (
    DmintContractUtxo,
    DmintMinerFundingUtxo,
    DmintState,
    build_dmint_contract_burn_script,
    build_dmint_mint_tx,
)
from pyrxd.script.script import Script
from pyrxd.security.errors import ValidationError
from pyrxd.transaction.transaction import Transaction

_FIXTURE = json.loads((Path(__file__).parent / "fixtures" / "dmint_v1_final_mints_mainnet.json").read_text())
_MINTS = _FIXTURE["mints"]
_IDS = [f"{m['ticker']}-{m['txid'][:8]}" for m in _MINTS]


def _txid(raw: bytes) -> str:
    return hashlib.sha256(hashlib.sha256(raw).digest()).digest()[::-1].hex()


def _read(entry: dict):
    """Everything the rebuild needs, derived from the raw bytes and checked against the txids."""
    raw, spent_raw = bytes.fromhex(entry["raw"]), bytes.fromhex(entry["spent_raw"])
    assert _txid(raw) == entry["txid"], "the fixture's mint bytes are not the transaction it names"
    assert _txid(spent_raw) == entry["spent_txid"], "the fixture's spent bytes are not the transaction it names"
    chain, spent = Transaction.from_hex(raw), Transaction.from_hex(spent_raw)
    assert chain.serialize() == raw and spent.serialize() == spent_raw
    contract_in, funding_in = chain.inputs
    assert contract_in.source_txid == funding_in.source_txid == entry["spent_txid"]
    assert (contract_in.source_output_index, funding_in.source_output_index) == (0, 3)
    c_out, f_out = spent.outputs[0], spent.outputs[3]
    script = c_out.locking_script.serialize()
    contract = DmintContractUtxo(
        txid=entry["spent_txid"], vout=0, value=c_out.satoshis, script=script, state=DmintState.from_script(script)
    )
    funding = DmintMinerFundingUtxo(
        txid=entry["spent_txid"], vout=3, value=f_out.satoshis, script=f_out.locking_script.serialize()
    )
    return raw, chain, contract, funding


def _reward_pkh_and_message(chain: Transaction) -> tuple[bytes, bytes]:
    reward = chain.outputs[1].locking_script.serialize()
    assert reward[:3] == b"\x76\xa9\x14", "output 1 is not the P2PKH-led FT reward"
    op_return = chain.outputs[2].locking_script.serialize()
    assert op_return[:5] == b"\x6a\x03msg" and len(op_return) == 6 + op_return[5], "output 2 is not a 'msg' OP_RETURN"
    return reward[3:23], op_return[6:]


def _target_push_opcode(script: bytes) -> int:
    """The opcode of a V1 state's 6th item, walked here rather than taken from the parser."""
    pos = 5 + 37 + 37  # 04 <height>, d8 <contractRef>, d0 <tokenRef>
    for _ in range(2):  # maxHeight, reward: OP_0 / OP_1..OP_16 or a direct push
        op = script[pos]
        pos += 1 + (op if 1 <= op <= 0x4B else 0)
    return script[pos]


def test_the_fixture_is_what_this_file_says_it_is() -> None:
    """Five final mints and one control; every spent contract V1, with an 8-byte target push."""
    finals = 0
    for entry in _MINTS:
        _raw, chain, contract, _funding = _read(entry)
        assert contract.state.is_v1 and _target_push_opcode(contract.script) == 0x08
        finals += chain.outputs[0].locking_script.serialize() == build_dmint_contract_burn_script(
            contract.state.contract_ref
        )
    assert (len(_MINTS), finals) == (6, 5)


@pytest.mark.parametrize("entry", _MINTS, ids=_IDS)
def test_pyrxd_predicts_what_the_chain_did_with_output_zero(entry: dict) -> None:
    _raw, chain, contract, _funding = _read(entry)
    out0 = chain.outputs[0].locking_script.serialize()
    burned = out0 == build_dmint_contract_burn_script(contract.state.contract_ref)
    assert contract.state.next_mint_is_final is burned
    if burned:
        assert chain.outputs[0].satoshis == 0
    else:  # the covenant's continue branch: the same contract, one height up
        assert DmintState.from_script(out0).height == contract.state.height + 1


@pytest.mark.parametrize("entry", _MINTS, ids=_IDS)
def test_pyrxd_rebuilds_the_mint_the_chain_accepted(entry: dict) -> None:
    raw, chain, contract, funding = _read(entry)
    reward_pkh, message = _reward_pkh_and_message(chain)
    res = build_dmint_mint_tx(contract, b"\x00" * 4, reward_pkh, 0, funding_utxo=funding, op_return_msg=message)
    assert res.is_final_mint is contract.state.next_mint_is_final
    built = res.tx
    assert len(built.outputs) == len(chain.outputs) == 4
    for i in range(3):  # the contract-or-burn, the FT reward, the message: pyrxd's own bytes
        assert built.outputs[i].serialize() == chain.outputs[i].serialize(), f"output {i} differs from the chain's"

    # The miner's own choices, taken from the chain: the nonce and signature, the change output.
    for built_in, chain_in in zip(built.inputs, chain.inputs, strict=True):
        built_in.unlocking_script = Script(chain_in.unlocking_script.serialize())
    built.outputs[3].locking_script = Script(chain.outputs[3].locking_script.serialize())
    built.outputs[3].satoshis = chain.outputs[3].satoshis
    assert built.serialize() == raw
    assert built.txid() == entry["txid"]


@pytest.mark.parametrize("entry", _MINTS, ids=_IDS)
def test_the_state_check_accepts_the_real_contract_and_refuses_a_forged_state(entry: dict) -> None:
    """``build_dmint_mint_tx`` refuses a V1 state that is not the one its script carries. The
    honest half is every real mainnet contract here, parsed from its own script: accepted (the
    rebuild above goes through the same check). The forged half is that contract's state one
    height BEHIND its script: for a final mint's contract, pyrxd would recreate the contract
    where the covenant demands the burn. (One height ahead of a final mint's contract is
    ``max_height``, which the exhausted check refuses first.)"""
    _raw, chain, contract, funding = _read(entry)
    reward_pkh, message = _reward_pkh_and_message(chain)
    build_dmint_mint_tx(contract, b"\x00" * 4, reward_pkh, 0, funding_utxo=funding, op_return_msg=message)
    behind = dataclasses.replace(contract, state=dataclasses.replace(contract.state, height=contract.state.height - 1))
    with pytest.raises(ValidationError, match="does not match the state contract_utxo.script carries"):
        build_dmint_mint_tx(behind, b"\x00" * 4, reward_pkh, 0, funding_utxo=funding, op_return_msg=message)
