"""Live-regtest proof that a WAVE registration paying the protocol fee is accepted by a node.

``tests/test_wave_registration_fee.py`` proves the fee output is on every registration path,
at the right tier and to the right script. What a unit test cannot show is that a node ACCEPTS
the transaction pyrxd builds with it: that the reveal, now with an extra 5-100 RXD output, still
funds itself, still satisfies the commit covenant and the mutable contract's ref rules, and
still pays the relay floor. This module shows it to a Radiant Core node running at MAINNET's
relay floor.

1. **Photonic's shape** — ``prepare_commit`` + ``prepare_wave_reveal``, fee at vout 2 after the
   NFT and the mutable contract, as Photonic's ``mintToken`` places it and as mainnet claim
   ``f644794b…`` has it. Two tiers (5 RXD and 50 RXD).
2. **The CLI's shape** — the commit sized by ``commit_value_for_reveal`` from the reveal
   estimate, the reveal assembled by ``pyrxd glyph mint-nft``'s own ``_build_reveal_tx`` with
   the fee at vout 1 and funded from the commit alone.
3. **NEGATIVE** — the same CLI-shaped reveal from a commit sized WITHOUT the fee is rejected:
   the fee's VALUE has to be in the funding, not only its output in the transaction. The
   commit is left unspent, so nothing is lost.

After each acceptance the confirmed transaction is read back from the node and the fee output
compared with the treasury P2PKH script the MAINNET claim paid (read from the fixture, not
built here) and the tier value both cited sources give. Paying the mainnet treasury's hash160
on regtest is just a script: nobody on this throwaway chain holds its key.

What this does NOT prove: that RXinDexer registers the name. A bare node has no name index,
and the indexer does not read the fee at registration anyway (``wave_index.py:706-807`` at
``ca8a6a4e``); the claim's indexer-facing shape is proved in
``tests/test_wave_claim_registers_with_the_indexer.py``.

Opt-in: ``@pytest.mark.integration`` + ``RADIANT_REGTEST=1``. Manages its own container under
a name no other suite uses. No PoW; seconds.

Run: ``RADIANT_REGTEST=1 pytest -o addopts= -m integration tests/test_wave_registration_fee_regtest_e2e.py -rap``
"""

from __future__ import annotations

import json
import os
import pathlib
import shutil
import subprocess

import pytest
from test_htlc_regtest_e2e import (
    _IMAGE,
    MAINNET_MIN_RELAY_RXD_PER_KB,
    _p2pkh_unlock,
    _RegtestNode,
    _src,
)
from test_mut_wave_regtest_e2e import _assert_fee_covers, _confirmed, _out_spk, _pay_outputs, _reveal_unlock

from pyrxd.cli.glyph_cmds import _build_reveal_tx
from pyrxd.fee_models import SatoshisPerKilobyte
from pyrxd.glyph.builder import CommitParams, GlyphBuilder, RevealParams
from pyrxd.glyph.fees import commit_value_for_reveal, estimate_reveal_fee_for_metadata
from pyrxd.glyph.inspector import GlyphInspector
from pyrxd.glyph.wave import build_wave_metadata
from pyrxd.glyph.wave_rules import WAVE_TREASURY_ADDRESS, wave_registered_label, wave_registration_price
from pyrxd.keys import PrivateKey
from pyrxd.script.script import Script
from pyrxd.script.type import P2PKH
from pyrxd.security.types import Hex20
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_input import TransactionInput
from pyrxd.transaction.transaction_output import TransactionOutput

pytestmark = pytest.mark.integration

#: DISTINCT from every other suite's container: ``_RegtestNode.start`` force-removes by name.
_CONTAINER = "pyrxd-wave-fee-regtest-pytest"

_MIN_FEE_RATE = 10_000  # photons/byte: mainnet's floor, which this node enforces
_FEE = 20_000_000  # flat reveal fee for the hand-assembled Photonic shape; checked per tx
_SEED_VALUE = 10_000_000
_CARRIER = 10_000_000

_FIXTURE = pathlib.Path(__file__).parent / "fixtures" / "wave_update_chain_mainnet.json"
_MAINNET_CLAIM = Transaction.from_hex(
    next(t for t in json.loads(_FIXTURE.read_text())["transactions"] if t["txid"].startswith("f644794b"))["raw"]
)
#: The treasury P2PKH the mainnet claim f644794b… paid at vout 2 — read off the chain.
_TREASURY_SCRIPT = _MAINNET_CLAIM.outputs[2].locking_script.serialize()


@pytest.fixture(scope="module")
def node():
    if not os.environ.get("RADIANT_REGTEST"):
        pytest.skip("RADIANT_REGTEST not set (opt-in for the live regtest e2e)")
    if shutil.which("docker") is None:
        pytest.skip("docker not available")
    if subprocess.run(["docker", "image", "inspect", _IMAGE], capture_output=True).returncode != 0:
        pytest.skip(f"{_IMAGE} image not available")
    n = _RegtestNode(container=_CONTAINER, min_relay_rxd_per_kb=MAINNET_MIN_RELAY_RXD_PER_KB)
    n.start()
    try:
        yield n
    finally:
        n.stop()


def _target() -> str:
    return PrivateKey().public_key().address()


def _assert_the_fee_output(rt: _RegtestNode, txid: str, vout: int, label: str, rxd: int) -> None:
    """Read the CONFIRMED transaction back and check its fee output against the sources."""
    confirmed = _confirmed(rt, txid)
    assert _out_spk(confirmed, vout) == _TREASURY_SCRIPT, "the fee output is not the treasury P2PKH"
    assert P2PKH().lock(WAVE_TREASURY_ADDRESS).serialize() == _TREASURY_SCRIPT
    # The tier value both sources give, spelled here in RXD: NOT wave_registration_price, the
    # function under test, which a wrong tier would move in step with the output.
    assert round(confirmed["vout"][vout]["value"] * 1e8) == rxd * 100_000_000 == wave_registration_price(label)
    spks = [bytes.fromhex(o["scriptPubKey"]["hex"]) for o in confirmed["vout"]]
    assert spks.count(_TREASURY_SCRIPT) == 1
    # ...and what the chain carries registers the name that was paid for.
    raw = Transaction.from_hex(bytes.fromhex(str(rt.cli("getrawtransaction", txid))))
    cbor = GlyphInspector().extract_reveal_cbor(raw.inputs[0].unlocking_script.serialize())
    assert wave_registered_label(cbor) == label


@pytest.mark.parametrize(
    ("label", "rxd"),
    [("regtest-fee-alice", 5), ("abcd", 50)],
    ids=["6-plus-tier", "4-char-tier"],
)
def test_photonic_shape_the_fee_at_vout_2_is_accepted(node, label: str, rxd: int) -> None:
    """``prepare_wave_reveal``'s result, placed as its docstring says: NFT, contract, fee, change."""
    owner = PrivateKey()
    owner_pkh = Hex20(owner.public_key().hash160())
    builder = GlyphBuilder()
    metadata = build_wave_metadata(qualified_name=f"{label}.rxd", target=_target())
    commit = builder.prepare_commit(
        CommitParams(metadata=metadata, owner_pkh=owner_pkh, change_pkh=owner_pkh, funding_satoshis=0)
    )
    fee = commit.registration_fee_output
    assert fee is not None and fee.value == rxd * 100_000_000
    # The commit funds the reveal: the two carriers, the reveal's miner fee and the
    # registration fee, which prepare_commit reported before anything was broadcast.
    commit_value = 2 * _CARRIER + _FEE + fee.value
    seed_key = PrivateKey()
    seed_spk = P2PKH().lock(seed_key.public_key().hash160()).serialize()
    commit_txid = _pay_outputs(node, [(commit.commit_script, commit_value), (seed_spk, _SEED_VALUE)])

    scripts = builder.prepare_wave_reveal(commit_txid, 0, commit.cbor_bytes, owner_pkh, f"{label}.rxd")
    assert scripts.registration_fee_output == fee
    reveal = Transaction(
        tx_inputs=[
            TransactionInput(
                source_transaction=_src(commit_txid, 0, commit.commit_script, commit_value),
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
            TransactionOutput(Script(fee.locking_script), fee.value),
            TransactionOutput(P2PKH().lock(owner.public_key().hash160()), _SEED_VALUE),
        ],
    )
    reveal.sign()
    raw = _assert_fee_covers(reveal, _FEE)
    res = node.accepts(raw)
    assert res.get("allowed") is True, f"the fee-paying WAVE reveal was REJECTED: {res}"
    txid = str(node.cli("sendrawtransaction", raw))
    node.mine(1)
    _assert_the_fee_output(node, txid, 2, label, rxd)


def _cli_shaped(node: _RegtestNode, label: str, *, pay_for_it_in_the_commit: bool) -> tuple[str, str]:
    """Commit sized by the estimator, reveal built by ``glyph mint-nft``'s own assembler.

    Returns ``(commit_txid, signed reveal hex)``. The reveal always carries the fee output;
    ``pay_for_it_in_the_commit`` decides whether the commit was sized to fund it.
    """
    owner = PrivateKey()
    owner_pkh = Hex20(owner.public_key().hash160())
    builder = GlyphBuilder()
    metadata = build_wave_metadata(qualified_name=f"{label}.rxd", target=_target())
    estimate = estimate_reveal_fee_for_metadata(
        metadata, fee_rate=_MIN_FEE_RATE, pay_registration_fee=pay_for_it_in_the_commit
    )
    commit_value = commit_value_for_reveal(546, estimate)
    commit = builder.prepare_commit(
        CommitParams(metadata=metadata, owner_pkh=owner_pkh, change_pkh=owner_pkh, funding_satoshis=0)
    )
    commit_txid = _pay_outputs(node, [(commit.commit_script, commit_value)])
    scripts = builder.prepare_reveal(
        RevealParams(
            commit_txid=commit_txid,
            commit_vout=0,
            commit_value=commit_value,
            cbor_bytes=commit.cbor_bytes,
            owner_pkh=owner_pkh,
            is_nft=True,
        )
    )
    assert scripts.registration_fee_output is not None
    reveal = _build_reveal_tx(
        commit_txid=commit_txid,
        commit_value=commit_value,
        commit_script=commit.commit_script,
        reveal_locking_script=scripts.locking_script,
        carrier_value=546,
        change_locking=P2PKH().lock(owner.public_key().hash160()),
        funding_key=owner,
        scriptsig_suffix=scripts.scriptsig_suffix,
        registration_fee=scripts.registration_fee_output,
    )
    reveal.fee(SatoshisPerKilobyte(_MIN_FEE_RATE * 1000))
    reveal.sign()
    return commit_txid, reveal.serialize().hex()


def test_cli_shape_the_fee_at_vout_1_funded_by_the_commit_is_accepted(node) -> None:
    label = "regtest-fee-cli"
    _commit_txid, raw = _cli_shaped(node, label, pay_for_it_in_the_commit=True)
    res = node.accepts(raw)
    assert res.get("allowed") is True, f"the CLI-shaped fee-paying reveal was REJECTED: {res}"
    txid = str(node.cli("sendrawtransaction", raw))
    node.mine(1)
    _assert_the_fee_output(node, txid, 1, label, 5)


def test_a_commit_sized_without_the_fee_cannot_fund_it(node) -> None:
    """NEGATIVE, and why the funding checks count the fee's VALUE: the output alone is not enough."""
    commit_txid, raw = _cli_shaped(node, "regtest-fee-short", pay_for_it_in_the_commit=False)
    res = node.accepts(raw)
    assert res.get("allowed") is False, f"a reveal paying more than its commit holds was ACCEPTED: {res}"
    # Refused for its VALUE, not for some other defect in the transaction.
    assert "in-belowout" in str(res.get("reject-reason", "")), res
    assert node.cli("gettxout", commit_txid, "0"), "the commit output should still be unspent"
