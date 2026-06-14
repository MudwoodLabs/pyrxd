"""Live-regtest CONSENSUS proof for the V1 dMint deploy + PoW-mint path.

This closes the last real dMint gap. The builders (``build_dmint_v1_contract_script``,
``GlyphBuilder.prepare_dmint_deploy``) and the miner (``mine_solution``,
``build_dmint_v1_mint_preimage``, ``build_mint_scriptsig``, ``build_dmint_mint_tx``)
have all shipped and are covered by byte-equal / mainnet-byte-equality golden
vectors — but NOTHING had ever been validated against a real Radiant node's
script interpreter. ``docs/threat-model.md`` item 12 ("dMint PoW path not
implemented") is stale in wording; the true gap was "never node-validated".

This test proves, on an isolated ``radiant-core`` regtest node via
``testmempoolaccept``, that:

1. a pyrxd-built V1 dMint **deploy** (commit -> reveal that genesises the
   contract UTXO carrying a valid singleton ``contractRef`` + normal
   ``tokenRef``) is ACCEPTED;
2. a real **PoW-mined mint** that spends the contract, recreates it at
   height+1, and pays the FT-wrapped reward is ACCEPTED;
3. the SAME mint with a **wrong nonce** is REJECTED — i.e. the node is
   actually enforcing the covenant's PoW gate, not accepting blindly.

Opt-in: ``@pytest.mark.integration`` + ``RADIANT_REGTEST=1`` (skips, never
fails, otherwise). It never runs in normal CI — honouring the PR #140
"no PoW grinding in CI" decision. It manages its own throwaway container
and moves no real value. The one-time ~3-4 min mine (the irreducible
4-zero-byte SHA256d floor at difficulty 1) runs via the bundled parallel
miner across all cores.

Run: ``RADIANT_REGTEST=1 pytest tests/test_dmint_v1_regtest_e2e.py -m integration -s``
"""

from __future__ import annotations

import os
import sys

import pytest

# Reuse the isolated-regtest harness wholesale (same pattern as the SPV
# differential test): the ``node`` fixture spins up + tears down a throwaway
# radiant-core container; ``.accepts()`` == testmempoolaccept.
from test_htlc_regtest_e2e import (  # noqa: F401  (node = fixture)
    _RELAY_FEE_SATS,
    _p2pkh_unlock,
    _pay_to_spk,
    _RegtestNode,
    _src,
    node,
)

from pyrxd.glyph.builder import DmintV1DeployParams, GlyphBuilder
from pyrxd.glyph.dmint import (
    DmintContractUtxo,
    DmintMinerFundingUtxo,
    DmintState,
    build_dmint_mint_tx,
    build_dmint_v1_mint_preimage,
    build_mint_scriptsig,
    mine_solution_dispatch,
)
from pyrxd.glyph.types import GlyphMetadata, GlyphProtocol
from pyrxd.keys import PrivateKey
from pyrxd.script.script import Script
from pyrxd.script.type import encode_pushdata, to_unlock_script_template
from pyrxd.security.errors import MaxAttemptsError
from pyrxd.security.types import Hex20
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_input import TransactionInput
from pyrxd.transaction.transaction_output import TransactionOutput

pytestmark = pytest.mark.integration

# --- contract parameters (mainnet-RBG-canonical so the covenant sees the
#     exact field encodings it was reverse-engineered from; only the carrier
#     deviates — mainnet's 1 photon would hit the regtest dust floor, so we
#     use 100_000 like the passing soulbound regtest covenant test) ---
_REWARD = 50_000  # FT reward photons per mint (mainnet RBG value)
_MAX_HEIGHT = 628_328  # mainnet RBG max_height (4-byte push)
_DIFFICULTY = 1  # -> target 0x7fffffffffffffff, the easiest legal target
_CARRIER = 1  # contract singleton carrier — the covenant HARDCODES vout0 value==1
#             (continue branch: `OP_OUTPUTVALUE OP_1 OP_NUMEQUALVERIFY`); mainnet
#             dMint contracts are all 1 photon (ref-bearing outputs are dust-exempt).
_FUNDING = 50_000_000  # 0.5 RXD plain coin to fund the mint (reward + fee + change)
_OP_RETURN = b"r2w"  # forces the 4-output shape the V1 mint preimage requires


def _p2pkh(pkh: object) -> bytes:
    return b"\x76\xa9\x14" + bytes(pkh) + b"\x88\xac"


def _commit_reveal_unlock(key: PrivateKey, suffix: bytes):
    """Unlock template for the FT-commit hashlock input of the reveal.

    Stack the covenant needs: ``<sig> <pubkey> <gly> <CBOR-payload>``. The
    ``<gly><CBOR>`` part is ``suffix`` (from ``build_reveal_outputs``); we
    prepend the standard P2PKH ``<sig> <pubkey>`` that the commit script's
    P2PKH tail checks.
    """
    pub = key.public_key().serialize()

    def _u(tx, idx):
        inp = tx.inputs[idx]
        sig = key.sign(tx.preimage(idx))
        return Script(encode_pushdata(sig + inp.sighash.to_bytes(1, "little")) + encode_pushdata(pub) + suffix)

    return to_unlock_script_template(_u, lambda: 110 + len(suffix))


def _deploy_v1_dmint(node: _RegtestNode, owner: PrivateKey) -> DmintContractUtxo:
    """Deploy a 1-contract V1 dMint via commit -> reveal; return the live contract UTXO.

    Asserts the reveal is accepted by the node BEFORE the caller spends the
    ~minutes mining the claim, so any genesis/ref/CBOR bug surfaces in seconds.
    """
    owner_pkh = Hex20(owner.public_key().hash160())
    owner_spk = _p2pkh(owner_pkh)

    meta = GlyphMetadata.for_dmint_ft(
        ticker="TST",
        name="A1 dMint regtest",
        decimals=0,
        protocol=[int(GlyphProtocol.FT), int(GlyphProtocol.DMINT)],
    )
    deploy = GlyphBuilder().prepare_dmint_deploy(
        DmintV1DeployParams(
            metadata=meta,
            owner_pkh=owner_pkh,
            num_contracts=1,
            max_height=_MAX_HEIGHT,
            reward_photons=_REWARD,
            difficulty=_DIFFICULTY,
            premine_amount=None,
            op_return_msg=None,
        )
    )
    commit_script = deploy.commit_result.commit_script

    # --- commit tx: fund owner, then 3 outputs (FT-commit | ref-seed | change) ---
    seed_txid = _pay_to_spk(node, owner_spk, 10_000_000)  # owner-controlled coin at vout 0
    _commit0, _commit1 = 2_000_000, 1_000_000
    cin = TransactionInput(
        source_transaction=_src(seed_txid, 0, owner_spk, 10_000_000),
        source_txid=seed_txid,
        source_output_index=0,
        unlocking_script_template=_p2pkh_unlock(owner),
    )
    cin.satoshis = 10_000_000
    cin.locking_script = Script(owner_spk)
    commit_change = 10_000_000 - _commit0 - _commit1 - _RELAY_FEE_SATS
    commit_tx = Transaction(
        tx_inputs=[cin],
        tx_outputs=[
            TransactionOutput(Script(commit_script), _commit0),  # vout0: FT-commit hashlock -> tokenRef
            TransactionOutput(Script(owner_spk), _commit1),  # vout1: ref-seed -> contractRef genesis
            TransactionOutput(Script(owner_spk), commit_change),  # vout2: change
        ],
    )
    commit_tx.sign()
    commit_txid = node.cli("sendrawtransaction", commit_tx.serialize().hex())
    assert isinstance(commit_txid, str), f"commit broadcast failed: {commit_txid}"
    node.mine(1)

    # --- reveal tx: spend commit:0 (tokenRef + CBOR reveal) AND commit:1 (contractRef) ---
    rev = deploy.build_reveal_outputs(commit_txid)
    contract_script = rev.contract_scripts[0]

    rin0 = TransactionInput(
        source_transaction=_src(commit_txid, 0, commit_script, _commit0),
        source_txid=commit_txid,
        source_output_index=0,
        unlocking_script_template=_commit_reveal_unlock(owner, rev.scriptsig_suffix),
    )
    rin0.satoshis = _commit0
    rin0.locking_script = Script(commit_script)

    rin1 = TransactionInput(
        source_transaction=_src(commit_txid, 1, owner_spk, _commit1),
        source_txid=commit_txid,
        source_output_index=1,
        unlocking_script_template=_p2pkh_unlock(owner),
    )
    rin1.satoshis = _commit1
    rin1.locking_script = Script(owner_spk)

    reveal_change = _commit0 + _commit1 - _CARRIER - _RELAY_FEE_SATS
    reveal_tx = Transaction(
        tx_inputs=[rin0, rin1],
        tx_outputs=[
            TransactionOutput(Script(contract_script), _CARRIER),  # vout0: the dMint contract UTXO
            TransactionOutput(Script(owner_spk), reveal_change),
        ],
    )
    reveal_tx.sign()
    raw_reveal = reveal_tx.serialize().hex()
    res = node.accepts(raw_reveal)
    assert res.get("allowed") is True, f"deploy reveal REJECTED (genesis/ref/CBOR bug): {res}"
    reveal_txid = node.cli("sendrawtransaction", raw_reveal)
    assert isinstance(reveal_txid, str), f"reveal broadcast failed: {reveal_txid}"
    node.mine(1)

    return DmintContractUtxo(
        txid=reveal_txid,
        vout=0,
        value=_CARRIER,
        script=contract_script,
        state=DmintState.from_script(contract_script),
    )


class TestDmintV1OnConsensus:
    def test_deploy_and_mint_accepted_wrong_nonce_rejected(self, node: _RegtestNode) -> None:
        owner = PrivateKey(os.urandom(32))
        miner = PrivateKey(os.urandom(32))
        miner_pkh = bytes(Hex20(miner.public_key().hash160()))

        # 1) Deploy + genesis (asserts reveal accepted before we pay to mine).
        contract = _deploy_v1_dmint(node, owner)
        assert contract.state.is_v1 and contract.state.height == 0

        # 2) Carve a plain funding coin for the mint.
        fund_spk = _p2pkh(miner_pkh)
        fund_txid = _pay_to_spk(node, fund_spk, _FUNDING)
        funding = DmintMinerFundingUtxo(txid=fund_txid, vout=0, value=_FUNDING, script=fund_spk)

        # 3) Mine the claim. V1's nonce is only 4 bytes (2**32 space) and the
        #    covenant's 4-zero-byte + value<target gate makes the per-nonce
        #    success ~2**-33 at difficulty 1, so a single preimage's nonce
        #    space has only ~39% chance of containing ANY solution. This is
        #    why real dMint miners REROLL the preimage (vary an output/funding
        #    field) on exhaustion — the preimage binds vout[2] (the OP_RETURN),
        #    so we vary it until the parallel miner finds a nonce. Total
        #    expected work to a hit is ~2**33 hashes regardless of rerolls.
        mint = pre = nonce = None
        for attempt in range(40):
            op_msg = b"r2w" + attempt.to_bytes(2, "big")
            mint = build_dmint_mint_tx(
                contract,
                nonce=b"\x00" * 4,
                miner_pkh=miner_pkh,
                current_time=0,
                funding_utxo=funding,
                op_return_msg=op_msg,
            )
            pre = build_dmint_v1_mint_preimage(contract, funding, mint.tx)
            try:
                result = mine_solution_dispatch(
                    pre.preimage,
                    target=contract.state.target,
                    nonce_width=4,
                    miner_argv=[sys.executable, "-m", "pyrxd.contrib.miner"],
                    timeout_s=1800,
                )
            except MaxAttemptsError:
                print(f"[mine] reroll {attempt}: 2**32 nonce space exhausted; varying OP_RETURN", flush=True)
                continue
            nonce = result.nonce
            print(f"[mine] hit on reroll {attempt}: nonce={nonce.hex()} in {result.elapsed_s:.0f}s", flush=True)
            break
        assert nonce is not None, "no nonce found within 40 preimage rerolls (P < 1e-13 — investigate)"

        # 4) Finalise: real mint scriptSig on the contract input, sign the funding input.
        mint.tx.inputs[0].unlocking_script = Script(
            build_mint_scriptsig(nonce, pre.input_hash, pre.output_hash, nonce_width=4)
        )
        fsig = miner.sign(mint.tx.preimage(1))
        fsh = mint.tx.inputs[1].sighash.to_bytes(1, "little")
        mint.tx.inputs[1].unlocking_script = Script(
            encode_pushdata(fsig + fsh) + encode_pushdata(miner.public_key().serialize())
        )
        raw_good = mint.tx.serialize().hex()

        # 5) THE PROOF — node accepts a real PoW-mined V1 dMint mint.
        good = node.accepts(raw_good)
        assert good.get("allowed") is True, f"valid mint REJECTED by consensus: {good}"

        # 6) Negative — same tx, wrong nonce, must be rejected (PoW actually enforced).
        bad_nonce = ((int.from_bytes(nonce, "little") + 1) & 0xFFFFFFFF).to_bytes(4, "little")
        assert bad_nonce != nonce
        mint.tx.inputs[0].unlocking_script = Script(
            build_mint_scriptsig(bad_nonce, pre.input_hash, pre.output_hash, nonce_width=4)
        )
        bad = node.accepts(mint.tx.serialize().hex())
        assert bad.get("allowed") is False, f"wrong-nonce mint ACCEPTED (PoW not enforced!): {bad}"

        # 7) Strengthen — broadcast the real mint, mine it, prove recreation at height+1.
        mint.tx.inputs[0].unlocking_script = Script(
            build_mint_scriptsig(nonce, pre.input_hash, pre.output_hash, nonce_width=4)
        )
        mint_txid = node.cli("sendrawtransaction", mint.tx.serialize().hex())
        assert isinstance(mint_txid, str), f"mint broadcast failed: {mint_txid}"
        node.mine(1)
        # contract input is spent; the recreated contract sits at the mint's vout 0.
        # (gettxout prints nothing for a spent/absent output -> cli() returns "".)
        assert not node.cli("gettxout", contract.txid, "0"), "old contract UTXO not spent"
        recreated = node.cli("gettxout", mint_txid, "0")
        assert isinstance(recreated, dict), f"recreated contract UTXO missing: {recreated}"
        new_spk = bytes.fromhex(recreated["scriptPubKey"]["hex"])
        assert DmintState.from_script(new_spk).height == 1, "recreated contract not at height 1"
