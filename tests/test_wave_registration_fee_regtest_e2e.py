"""Live-regtest proof that a WAVE registration paying the protocol fee is accepted by a node.

``tests/test_wave_registration_fee.py`` proves the fee output is on every registration path,
at the right tier and to the right script, and ``tests/cli/test_wave_registration_fee_cli.py``
proves what ``pyrxd glyph mint-nft`` builds against a fake chain. What neither can show is that
a node ACCEPTS those transactions: that a reveal with a 5-100 RXD output and a second input
funding it still satisfies the commit covenant and the mutable contract's ref rules, and still
pays the relay floor. This module shows it to a Radiant Core node running at MAINNET's relay
floor.

1. **Photonic's shape** — ``prepare_commit`` + ``prepare_wave_reveal``: the reveal spends the
   commit, the mutable seed and a third output of the commit transaction that funds the fee
   (Photonic funds its reveal from wallet inputs, its commit's change among them), and pays the
   fee at vout 2 after the NFT and the mutable contract — as mainnet claim ``f644794b…`` has it.
   Two tiers (5 RXD and 50 RXD).
2. **The real CLI** — ``pyrxd glyph mint-nft`` through click (``_mint_nft_inner`` and all), with
   a wallet and an ElectrumX stand-in both answered by the node: every broadcast is
   ``sendrawtransaction``, every UTXO is ``gettxout``. The reveal spends the commit and the
   commit's change, pays the treasury at vout 1, and returns change.
3. **The CLI's recovery** — the name is reported taken between commit and reveal: ``mint-nft``
   stops without paying, and ``resume-mint --no-wave-registration-fee`` reveals the commit on
   chain with no fee.
4. **NEGATIVE** — a reveal carrying the fee output with no input to fund it (the commit sized
   for the carrier and the miner fee only, as the commit now always is) is rejected for its
   value. The commit is left unspent, so nothing is lost.
5. **The 0.25.0 panel's money-path findings** — a name reported taken at the last check, after
   the reveal's confirmation, puts no reveal on chain (D-L2); and a pending record edited to pay
   another treasury pays nothing until it is put back, after which the printed command pays the
   treasury the mint named (D-L1).

After each acceptance the confirmed transaction is read back from the node and the fee output
compared with the treasury P2PKH script the MAINNET claim paid (read from the fixture, not
built here) and the tier value both cited sources give, spelled here in RXD. Paying the mainnet
treasury's hash160 on regtest is just a script: nobody on this throwaway chain holds its key.

What this does NOT prove: that RXinDexer registers the name, or answers ``wave.check_available``
as the stand-in does. A bare node has no name index, and the indexer does not read the fee at
registration anyway (``wave_index.py:706-807`` at ``ca8a6a4e``); the claim's indexer-facing
shape is proved in ``tests/test_wave_claim_registers_with_the_indexer.py``.

Opt-in: ``@pytest.mark.integration`` + ``RADIANT_REGTEST=1``. Manages its own container under
a name no other suite uses. No PoW; seconds.

Run: ``RADIANT_REGTEST=1 pytest -o addopts= -m integration tests/test_wave_registration_fee_regtest_e2e.py -rap``
"""

from __future__ import annotations

import functools
import json
import os
import pathlib
import shlex
import shutil
import subprocess
from typing import Any

import pytest
from click.testing import CliRunner
from test_htlc_regtest_e2e import (
    _IMAGE,
    MAINNET_MIN_RELAY_RXD_PER_KB,
    _p2pkh_unlock,
    _pay_to_spk,
    _RegtestNode,
    _src,
)
from test_mut_wave_regtest_e2e import _assert_fee_covers, _confirmed, _out_spk, _pay_outputs, _reveal_unlock

from pyrxd.base58 import base58check_encode
from pyrxd.cli import glyph_cmds
from pyrxd.cli.main import cli
from pyrxd.constants import NETWORK_ADDRESS_PREFIX_DICT, Network
from pyrxd.glyph.builder import CommitParams, GlyphBuilder, RevealParams
from pyrxd.glyph.fees import commit_value_for_reveal, estimate_reveal_fee_for_metadata
from pyrxd.glyph.inspector import GlyphInspector
from pyrxd.glyph.mint import JsonFilePendingStore
from pyrxd.glyph.wave import build_wave_metadata
from pyrxd.glyph.wave_rules import WAVE_TREASURY_ADDRESS, wave_registered_label, wave_registration_fee_for
from pyrxd.keys import PrivateKey
from pyrxd.network import confirm
from pyrxd.network.electrumx import UtxoRecord, script_hash_for_script
from pyrxd.script.script import Script
from pyrxd.script.type import P2PKH
from pyrxd.security.types import Hex20
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_input import TransactionInput
from pyrxd.transaction.transaction_output import TransactionOutput
from tests import rxindexer_oracle as oracle

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
#: The same hash160 as a regtest (testnet-prefixed) address, for ``--wave-treasury``: the CLI
#: pays the published treasury only on mainnet, so on regtest it is named. Same script bytes.
_TREASURY_ON_REGTEST = base58check_encode(NETWORK_ADDRESS_PREFIX_DICT[Network.TESTNET] + _TREASURY_SCRIPT[3:23])


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


def _assert_the_fee_output(rt: _RegtestNode, txid: str, vout: int, label: str, rxd: int) -> dict:
    """Read the CONFIRMED transaction back and check its fee output against the sources."""
    confirmed = _confirmed(rt, txid)
    assert _out_spk(confirmed, vout) == _TREASURY_SCRIPT, "the fee output is not the treasury P2PKH"
    assert P2PKH().lock(WAVE_TREASURY_ADDRESS).serialize() == _TREASURY_SCRIPT
    # The tier value both sources give, spelled here in RXD: NOT wave_registration_price, the
    # function under test, which a wrong tier would move in step with the output.
    assert round(confirmed["vout"][vout]["value"] * 1e8) == rxd * 100_000_000
    spks = [bytes.fromhex(o["scriptPubKey"]["hex"]) for o in confirmed["vout"]]
    assert spks.count(_TREASURY_SCRIPT) == 1
    # ...and what the chain carries registers the name that was paid for: by pyrxd's rule, which
    # decided the fee, and by RXinDexer's own claim path at the pinned commit, which is what
    # registers names (tests/rxindexer_oracle.py).
    raw = Transaction.from_hex(bytes.fromhex(str(rt.cli("getrawtransaction", txid))))
    cbor = GlyphInspector().extract_reveal_cbor(raw.inputs[0].unlocking_script.serialize())
    assert wave_registered_label(cbor) == label
    assert oracle.registers(oracle.to_upstream_tx(raw)) == oracle.Verdict(f"{label}.rxd", True)
    return confirmed


# ─────────────────────────────────────────────────────── (1) Photonic's shape ──


@pytest.mark.parametrize(
    ("label", "rxd"),
    [("regtest-fee-alice", 5), ("abcd", 50)],
    ids=["6-plus-tier", "4-char-tier"],
)
def test_photonic_shape_the_fee_at_vout_2_funded_by_a_wallet_input_is_accepted(node, label: str, rxd: int) -> None:
    """``prepare_wave_reveal``'s result, placed as its docstring says: NFT, contract, fee, change,
    with a third input that funds the fee."""
    owner = PrivateKey()
    owner_pkh = Hex20(owner.public_key().hash160())
    owner_spk = P2PKH().lock(owner.public_key().hash160()).serialize()
    builder = GlyphBuilder()
    metadata = build_wave_metadata(qualified_name=f"{label}.rxd", target=_target())
    commit = builder.prepare_commit(
        CommitParams(metadata=metadata, owner_pkh=owner_pkh, change_pkh=owner_pkh, funding_satoshis=0)
    )
    fee = wave_registration_fee_for(commit.cbor_bytes)
    assert fee is not None and fee.value == rxd * 100_000_000
    # The commit output carries the two carriers and the reveal's miner fee, and nothing for
    # the registration fee. The fee comes from a plain output beside it (Photonic's commit
    # change), which the reveal spends as its third input.
    commit_value = 2 * _CARRIER + _FEE
    seed_key = PrivateKey()
    seed_spk = P2PKH().lock(seed_key.public_key().hash160()).serialize()
    commit_txid = _pay_outputs(
        node, [(commit.commit_script, commit_value), (seed_spk, _SEED_VALUE), (owner_spk, fee.value)]
    )

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
            TransactionInput(
                source_transaction=_src(commit_txid, 2, owner_spk, fee.value),
                source_txid=commit_txid,
                source_output_index=2,
                unlocking_script_template=_p2pkh_unlock(owner),
            ),
        ],
        tx_outputs=[
            TransactionOutput(Script(scripts.nft_script), _CARRIER),
            TransactionOutput(Script(scripts.contract_script), _CARRIER),
            TransactionOutput(Script(fee.locking_script), fee.value),
            TransactionOutput(Script(owner_spk), _SEED_VALUE),
        ],
    )
    reveal.sign()
    raw = _assert_fee_covers(reveal, _FEE)
    res = node.accepts(raw)
    assert res.get("allowed") is True, f"the fee-paying WAVE reveal was REJECTED: {res}"
    txid = str(node.cli("sendrawtransaction", raw))
    node.mine(1)
    confirmed = _assert_the_fee_output(node, txid, 2, label, rxd)
    assert [(i["txid"], i["vout"]) for i in confirmed["vin"]] == [(commit_txid, 0), (commit_txid, 1), (commit_txid, 2)]


# ─────────────────────────────────────────────────────────── (2) the real CLI ──


class _NodeNet:
    """ElectrumX for the real CLI, answered by the node: nothing here decides validity."""

    def __init__(self, rt: _RegtestNode, *, available: list[bool]) -> None:
        self.rt = rt
        #: False leaves a broadcast in the mempool, so a wait for it times out.
        self.mine_on_broadcast = True
        self.known: set[tuple[str, int]] = set()
        self.available = available
        self.asked: list[list[Any]] = []

    async def __aenter__(self) -> _NodeNet:
        return self

    async def __aexit__(self, *exc: object) -> bool:
        return False

    def track(self, txid: str) -> None:
        tx = Transaction.from_hex(bytes.fromhex(str(self.rt.cli("getrawtransaction", txid))))
        self.known.update((txid, n) for n in range(len(tx.outputs)))

    async def broadcast(self, raw: bytes) -> str:
        txid = str(self.rt.cli("sendrawtransaction", bytes(raw).hex()))
        if self.mine_on_broadcast:
            self.rt.mine(1)
        self.track(txid)
        return txid

    async def get_transaction(self, txid: Any) -> bytes:
        return bytes.fromhex(str(self.rt.cli("getrawtransaction", str(txid))))

    async def get_transaction_verbose(self, txid: Any) -> dict:
        return self.rt.cli("getrawtransaction", str(txid), "true")  # type: ignore[return-value]

    async def get_utxos(self, script_hash: Any) -> list[UtxoRecord]:
        found = []
        for txid, vout in sorted(self.known):
            info = self.rt.cli("gettxout", txid, str(vout))
            if not isinstance(info, dict):
                continue  # spent: gettxout answers nothing
            spk = bytes.fromhex(info["scriptPubKey"]["hex"])
            if bytes(script_hash_for_script(spk)) == bytes(script_hash):
                found.append(UtxoRecord(tx_hash=txid, tx_pos=vout, value=round(info["value"] * 1e8), height=1))
        return found

    async def call_extension(self, method: str, params: list[Any]) -> Any:
        # The one stand-in: a bare node runs no RXinDexer.
        assert method == "wave.check_available", method
        self.asked.append(list(params))
        return {"available": self.available[min(len(self.asked) - 1, len(self.available) - 1)]}


class _NodeWallet:
    def __init__(self, key: PrivateKey, net: _NodeNet) -> None:
        self.key = key
        self.net = net
        self.address = key.address(network=Network.TESTNET)
        self.script = P2PKH().lock(self.address).serialize()

    async def collect_spendable(self, client: object) -> list:
        return [(u, self.address, self.key) for u in await self.net.get_utxos(script_hash_for_script(self.script))]

    def privkey_for_address(self, address: str) -> PrivateKey:
        assert address == self.address
        return self.key


def _wire(
    node: _RegtestNode, monkeypatch: pytest.MonkeyPatch, *, available: list[bool]
) -> tuple[_NodeNet, _NodeWallet]:
    for var in ("PYRXD_NETWORK", "PYRXD_ELECTRUMX", "PYRXD_FEE_RATE", "PYRXD_WALLET_PATH"):
        monkeypatch.delenv(var, raising=False)
    net = _NodeNet(node, available=available)
    wallet = _NodeWallet(PrivateKey(), net)
    net.track(_pay_to_spk(node, wallet.script, 30 * 100_000_000))
    monkeypatch.setattr(glyph_cmds, "_load_wallet", lambda ctx, **kw: wallet)
    monkeypatch.setattr(glyph_cmds.CliContext, "make_client", lambda self: net)
    return net, wallet


def _cli(tmp_path: pathlib.Path, *args: str) -> Any:
    base = ["--config", str(tmp_path / "absent.toml"), "--network", "regtest", "--wallet", str(tmp_path / "w.dat")]
    return CliRunner().invoke(cli, [*base, "--json", "--yes", "glyph", *args])


def _metadata_file(tmp_path: pathlib.Path, label: str) -> pathlib.Path:
    path = tmp_path / f"{label}.json"
    path.write_text(
        json.dumps(
            {
                "protocol": ["NFT", "MUT", "WAVE"],
                "name": f"{label}.rxd",
                "token_type": "wave_name",
                "attrs": {"name": label, "domain": "rxd", "target": _target(), "target_type": "address"},
            }
        )
    )
    return path


def test_the_cli_pays_the_fee_at_reveal_time_from_a_wallet_input(
    node, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    label = "regtest-cli-fee"
    net, wallet = _wire(node, monkeypatch, available=[True])
    result = _cli(tmp_path, "mint-nft", str(_metadata_file(tmp_path, label)), "--wave-treasury", _TREASURY_ON_REGTEST)
    assert result.exit_code == 0, (result.output, result.exception)
    out = json.loads(result.stdout)
    commit_txid, reveal_txid = out["commit_txid"], out["reveal_txid"]

    # Read the commit and the reveal back from the node.
    commit = _confirmed(node, commit_txid)
    assert len(commit["vout"]) == 2  # the commit output, and change
    assert round(commit["vout"][0]["value"] * 1e8) < 5 * 100_000_000  # nothing for the fee in it
    assert _out_spk(commit, 1) == wallet.script
    reveal = _assert_the_fee_output(node, reveal_txid, 1, label, 5)
    # The funding input: the commit's change, a plain wallet UTXO — not the commit output.
    assert [(i["txid"], i["vout"]) for i in reveal["vin"]] == [(commit_txid, 0), (commit_txid, 1)]
    # [NFT carrier, fee, change], and the change is the wallet's.
    assert len(reveal["vout"]) == 3
    assert round(reveal["vout"][0]["value"] * 1e8) == 546
    assert _out_spk(reveal, 2) == wallet.script
    ins = round(commit["vout"][0]["value"] * 1e8) + round(commit["vout"][1]["value"] * 1e8)
    outs = sum(round(o["value"] * 1e8) for o in reveal["vout"])
    assert ins - outs >= reveal["size"] * _MIN_FEE_RATE  # the node took it; this is the margin, read back
    assert out["wave_registration"]["fee_input"] == f"{commit_txid}:1"
    # Before the commit, before the reveal's confirmation, and again just before its broadcast.
    assert net.asked == [[label], [label], [label]]
    assert JsonFilePendingStore(tmp_path / "pending-mints").list_pending() == []


def test_a_name_taken_after_the_commit_is_recovered_without_the_fee(
    node, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    label = "regtest-cli-taken"
    _net, wallet = _wire(node, monkeypatch, available=[True, False])
    stopped = _cli(tmp_path, "mint-nft", str(_metadata_file(tmp_path, label)), "--wave-treasury", _TREASURY_ON_REGTEST)
    assert stopped.exit_code == 1, stopped.output
    assert "NOT paying the registration fee" in stopped.stderr
    commit_txid = json.loads(stopped.stdout)["commit_txid"]
    assert node.cli("gettxout", commit_txid, "0"), "the commit should be confirmed and unspent"

    recovered = _cli(tmp_path, "resume-mint", commit_txid, "--no-wave-registration-fee")
    assert recovered.exit_code == 0, (recovered.output, recovered.exception)
    reveal = _confirmed(node, json.loads(recovered.stdout)["reveal_txid"])
    assert [(i["txid"], i["vout"]) for i in reveal["vin"]] == [(commit_txid, 0)]
    assert _TREASURY_SCRIPT not in [bytes.fromhex(o["scriptPubKey"]["hex"]) for o in reveal["vout"]]
    assert _out_spk(reveal, 1) == wallet.script  # the commit's value, back as change
    assert not node.cli("gettxout", commit_txid, "0")


def test_a_declined_fee_survives_a_timeout_and_the_printed_recover_keeps_it(
    node, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """M2 against a node: `mint-nft --no-wave-registration-fee` times out waiting for its commit;
    the `recover` command it prints, run exactly as printed, reveals WITHOUT the fee. Before
    round 3 that command was a bare `resume-mint`, which paid the declined fee."""
    label = "regtest-cli-declined"
    net, wallet = _wire(node, monkeypatch, available=[True])
    net.mine_on_broadcast = False

    async def _no_sleep(_s: float) -> None:
        return None

    # The real waiter, one poll: the commit sits in the mempool, so mint-nft times out.
    monkeypatch.setattr(
        glyph_cmds,
        "wait_for_confirmation",
        functools.partial(confirm.wait_for_confirmation, max_iterations=1, sleep=_no_sleep),
    )
    stopped = _cli(tmp_path, "mint-nft", str(_metadata_file(tmp_path, label)), "--no-wave-registration-fee")
    assert stopped.exit_code == 2, stopped.output
    doc = json.loads(stopped.stdout)
    commit_txid = doc["commit_txid"]
    assert doc["wave_fee"] == "decline" and shlex.split(doc["recover"])[-1] == "--no-wave-registration-fee"

    node.mine(1)
    net.mine_on_broadcast = True
    argv = shlex.split(doc["recover"])
    assert argv[0] == "pyrxd"
    recovered = CliRunner().invoke(cli, ["--config", str(tmp_path / "absent.toml"), "--json", "--yes", *argv[1:]])
    assert recovered.exit_code == 0, (recovered.output, recovered.exception)
    reveal = _confirmed(node, json.loads(recovered.stdout)["reveal_txid"])
    assert [(i["txid"], i["vout"]) for i in reveal["vin"]] == [(commit_txid, 0)]
    assert _TREASURY_SCRIPT not in [bytes.fromhex(o["scriptPubKey"]["hex"]) for o in reveal["vout"]]
    assert _out_spk(reveal, 1) == wallet.script
    assert not node.cli("gettxout", commit_txid, "0")
    assert JsonFilePendingStore(tmp_path / "pending-mints").list_pending() == []


def test_a_name_reported_taken_at_the_last_check_is_not_paid_on_chain(
    node, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Panel D-L2 against a node: the indexer is asked once more AFTER the reveal's confirmation
    and immediately before its broadcast. Free before the commit, free when the reveal prompt is
    built, taken at the last check: no reveal reaches the node, the fee's funding input (the
    commit's change) stays unspent, and the printed decline still recovers the commit."""
    label = "regtest-cli-late"
    net, wallet = _wire(node, monkeypatch, available=[True, True, False])
    stopped = _cli(tmp_path, "mint-nft", str(_metadata_file(tmp_path, label)), "--wave-treasury", _TREASURY_ON_REGTEST)
    assert stopped.exit_code == 1, stopped.output
    assert "registered now — NOT paying the registration fee" in stopped.stderr
    assert net.asked == [[label], [label], [label]]
    doc = json.loads(stopped.stdout)
    commit_txid = doc["commit_txid"]
    assert node.cli("gettxout", commit_txid, "0"), "the commit output should be confirmed and unspent"
    assert node.cli("gettxout", commit_txid, "1"), "the fee's funding input should be unspent"

    recovered = CliRunner().invoke(
        cli,
        [
            "--config",
            str(tmp_path / "absent.toml"),
            "--json",
            "--yes",
            *shlex.split(doc["recover_without_wave_fee"])[1:],
        ],
    )
    assert recovered.exit_code == 0, (recovered.output, recovered.exception)
    reveal = _confirmed(node, json.loads(recovered.stdout)["reveal_txid"])
    assert [(i["txid"], i["vout"]) for i in reveal["vin"]] == [(commit_txid, 0)]
    assert _TREASURY_SCRIPT not in [bytes.fromhex(o["scriptPubKey"]["hex"]) for o in reveal["vout"]]
    assert _out_spk(reveal, 1) == wallet.script


def test_an_edited_record_treasury_is_not_paid_on_chain(
    node, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Panel D-L1 against a node. A mint that named a treasury times out; its record is then
    edited to pay another address. Neither the printed command (which names the real treasury)
    nor a bare resume-mint pays the edited one — the commit stays unspent on the node — and once
    the record is put back, the printed command reveals and pays the treasury the mint named."""
    label = "regtest-cli-redirect"
    net, _wallet = _wire(node, monkeypatch, available=[True])
    net.mine_on_broadcast = False

    async def _no_sleep(_s: float) -> None:
        return None

    monkeypatch.setattr(
        glyph_cmds,
        "wait_for_confirmation",
        functools.partial(confirm.wait_for_confirmation, max_iterations=1, sleep=_no_sleep),
    )
    stopped = _cli(tmp_path, "mint-nft", str(_metadata_file(tmp_path, label)), "--wave-treasury", _TREASURY_ON_REGTEST)
    assert stopped.exit_code == 2, stopped.output
    doc = json.loads(stopped.stdout)
    commit_txid = doc["commit_txid"]
    assert shlex.split(doc["recover"])[-2:] == ["--wave-treasury", _TREASURY_ON_REGTEST]
    node.mine(1)
    net.mine_on_broadcast = True

    record = tmp_path / "pending-mints" / f"{commit_txid}.json"
    honest = record.read_text()
    edited = json.loads(honest)
    edited["wave_treasury"] = PrivateKey().public_key().address(network=Network.TESTNET)
    record.write_text(json.dumps(edited))

    def _run(argv: list[str]) -> Any:
        return CliRunner().invoke(cli, ["--config", str(tmp_path / "absent.toml"), "--json", "--yes", *argv])

    printed = _run(shlex.split(doc["recover"])[1:])
    assert printed.exit_code == 1 and "--wave-treasury is not the treasury the mint chose" in printed.stderr
    bare = _cli(tmp_path, "resume-mint", commit_txid)
    assert bare.exit_code == 1 and "which is NOT the published WAVE treasury" in bare.stderr
    assert node.cli("gettxout", commit_txid, "0"), "nothing may have spent the commit"

    record.write_text(honest)
    recovered = _run(shlex.split(doc["recover"])[1:])
    assert recovered.exit_code == 0, (recovered.output, recovered.exception)
    reveal = _assert_the_fee_output(node, json.loads(recovered.stdout)["reveal_txid"], 1, label, 5)
    assert (reveal["vin"][0]["txid"], reveal["vin"][0]["vout"]) == (commit_txid, 0)
    assert not node.cli("gettxout", commit_txid, "0")
    assert JsonFilePendingStore(tmp_path / "pending-mints").list_pending() == []


# ─────────────────────────────────────────────────────────────── (4) negative ──


def test_a_fee_output_with_no_input_to_fund_it_is_rejected(node) -> None:
    """NEGATIVE: the commit carries only the carrier and the miner fee, so a reveal that adds the
    fee output without the wallet input that funds it pays out more than it spends."""
    label = "regtest-fee-short"
    owner = PrivateKey()
    owner_pkh = Hex20(owner.public_key().hash160())
    builder = GlyphBuilder()
    metadata = build_wave_metadata(qualified_name=f"{label}.rxd", target=_target())
    estimate = estimate_reveal_fee_for_metadata(metadata, fee_rate=_MIN_FEE_RATE)
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
    fee = scripts.registration_fee_output
    assert fee is not None
    reveal = Transaction(
        tx_inputs=[
            TransactionInput(
                source_transaction=_src(commit_txid, 0, commit.commit_script, commit_value),
                source_txid=commit_txid,
                source_output_index=0,
                unlocking_script_template=_reveal_unlock(owner, scripts.scriptsig_suffix),
            )
        ],
        tx_outputs=[
            TransactionOutput(Script(scripts.locking_script), 546),
            TransactionOutput(Script(fee.locking_script), fee.value),
        ],
    )
    reveal.sign()
    res = node.accepts(reveal.serialize().hex())
    assert res.get("allowed") is False, f"a reveal paying more than its commit holds was ACCEPTED: {res}"
    # Refused for its VALUE, not for some other defect in the transaction.
    assert "in-belowout" in str(res.get("reject-reason", "")), res
    assert node.cli("gettxout", commit_txid, "0"), "the commit output should still be unspent"
