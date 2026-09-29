"""Live-node proof that ``glyph deploy-dmint``'s commit-echo recovery rebuilds the SAME token (#786).

When the server's reply to the commit broadcast names some other txid, ``deploy-dmint`` stops (it
keeps no pending record) and prints SDK code to rebuild the reveal. The commit script checks the
metadata body, the owner key and that the token ref is carried as an FT — and none of the contract
parameters. So a rebuild with any parameter different from the original deploy still spends the
commit and deploys a different token, permanently. The recipe therefore prints every parameter
the CLI used.

What this proves, on a real ``radiantd -regtest`` at the mainnet relay floor:

1. The real ``deploy-dmint`` command, run through the root ``cli`` with a V2 EPOCH deploy (a
   non-default ``--max-adjustment``, so the log2 mapping is exercised), a premine and an
   OP_RETURN, and ``--last-time`` NOT given (so the build resolves it to "now"), relays its commit
   to the node and stops on a lying echo.
2. Running the printed code, unmodified, and building the reveal as the message says, gives reveal
   outputs byte-identical to the ones the CLI built for that commit; the node accepts and mines it.
3. The control: the same rebuild with one parameter wrong (``max_adjustment_log2`` left at its
   default) is ALSO accepted by the node. The commit does not bind the parameters, which is why
   the recipe must carry them.

Opt-in: ``@pytest.mark.integration`` + ``RADIANT_REGTEST=1``. Its own container name. REGTEST ONLY.
Every key comes from ``PrivateKey()``.

Run::

    RADIANT_REGTEST=1 pytest tests/test_dmint_commit_echo_recovery_regtest_e2e.py -m integration -s
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from dataclasses import replace
from typing import Any

import pytest
from click.testing import CliRunner
from test_htlc_regtest_e2e import _IMAGE, _pay_to_spk, _RegtestNode

from pyrxd.cli import glyph_cmds
from pyrxd.cli.glyph_helpers import _build_glyph_unlock
from pyrxd.cli.main import cli
from pyrxd.fee_models import SatoshisPerKilobyte
from pyrxd.glyph.builder import GlyphBuilder
from pyrxd.keys import PrivateKey
from pyrxd.network.electrumx import ElectrumXClient, UtxoRecord
from pyrxd.script.script import Script
from pyrxd.script.type import P2PKH
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_input import TransactionInput
from pyrxd.transaction.transaction_output import TransactionOutput

pytestmark = pytest.mark.integration

_CONTAINER = "dmint-echo-recovery-pytest"
_LIE = "ee" * 32
_FUND = 1_000_000_000  # 10 RXD: the commit carries the reveal's fee at the mainnet floor


@pytest.fixture(scope="module")
def node():
    if not os.environ.get("RADIANT_REGTEST"):
        pytest.skip("RADIANT_REGTEST not set (opt-in for the live regtest e2e)")
    if shutil.which("docker") is None:
        pytest.skip("docker not available")
    if subprocess.run(["docker", "image", "inspect", _IMAGE], capture_output=True).returncode != 0:
        pytest.skip(f"{_IMAGE} image not available")
    n = _RegtestNode(container=_CONTAINER)
    n.start()
    try:
        yield n
    finally:
        n.stop()


class _LyingNodeClient(ElectrumXClient):
    """A real ``ElectrumXClient`` whose wire sends a broadcast to the node, then lies about it.

    The shipped ``broadcast`` (and the echo check in it) runs; only ``_call`` is replaced.
    """

    def __init__(self, node: _RegtestNode) -> None:
        super().__init__(["wss://fake.invalid/"])
        self.node = node
        self.sent: list[bytes] = []

    async def __aenter__(self) -> _LyingNodeClient:
        return self

    async def __aexit__(self, *exc: object) -> bool:
        return False

    async def _ensure_connected(self) -> None:
        return None

    async def _call(self, method: str, params: list[Any]) -> Any:
        assert method == "blockchain.transaction.broadcast", method
        self.sent.append(bytes.fromhex(params[0]))
        self.node.cli("sendrawtransaction", params[0])  # it relays
        return _LIE


def _recipe_code(output: str) -> str:
    m = re.search(r"Rebuild the reveal with the SDK: run\n(.*?)\nUse every parameter", output, re.S)
    assert m, output
    return m.group(1)


def _reveal_tx(commit: Transaction, rev, *, owner: PrivateKey, n: int) -> Transaction:
    """The reveal, built as the message says: commit:0 and commit:1..n in, rev's outputs in order."""
    owner_spk = P2PKH().lock(owner.public_key().address())
    rin0 = TransactionInput(
        source_transaction=commit,
        source_output_index=0,
        unlocking_script_template=_build_glyph_unlock(owner, rev.scriptsig_suffix),
    )
    rin0.satoshis = commit.outputs[0].satoshis
    rin0.locking_script = commit.outputs[0].locking_script
    inputs = [rin0]
    for i in range(1, n + 1):
        rin = TransactionInput(
            source_transaction=commit, source_output_index=i, unlocking_script_template=P2PKH().unlock(owner)
        )
        rin.satoshis = commit.outputs[i].satoshis
        rin.locking_script = owner_spk
        inputs.append(rin)
    outs = [TransactionOutput(Script(s), rev.contract_value) for s in rev.contract_scripts]
    if rev.premine_script is not None and rev.premine_amount:
        outs.append(TransactionOutput(Script(rev.premine_script), rev.premine_amount))
    if rev.op_return_script:
        outs.append(TransactionOutput(Script(rev.op_return_script), 0))
    outs.append(TransactionOutput(owner_spk, 0, change=True))
    tx = Transaction(tx_inputs=inputs, tx_outputs=outs)
    tx.fee(SatoshisPerKilobyte(10_000 * 1000))
    tx.sign()
    return tx


def test_the_printed_recipe_rebuilds_the_token_the_cli_would_have_deployed(node, tmp_path, monkeypatch) -> None:
    assert node.cli("getblockchaininfo")["chain"] == "regtest"

    owner = PrivateKey()
    owner_spk = bytes(P2PKH().lock(owner.public_key().address()).serialize())
    fund_txid = _pay_to_spk(node, owner_spk, _FUND)

    class _Wallet:
        async def collect_spendable(self, _client):
            return [
                (UtxoRecord(tx_hash=fund_txid, tx_pos=0, value=_FUND, height=1), owner.public_key().address(), owner)
            ]

    client = _LyingNodeClient(node)
    monkeypatch.setattr(glyph_cmds, "_load_wallet", lambda ctx, prompt_passphrase=False: _Wallet())
    monkeypatch.setattr(glyph_cmds.CliContext, "make_client", lambda self: client)
    # What the CLI itself built, so "correct" means the reveal it would have broadcast.
    built: list[Any] = []
    real_prepare = GlyphBuilder.prepare_dmint_deploy

    def _spy(self, params, **kw):
        result = real_prepare(self, params, **kw)
        built.append((params, result))
        return result

    monkeypatch.setattr(GlyphBuilder, "prepare_dmint_deploy", _spy)

    meta = tmp_path / "dmint.json"
    meta.write_text(json.dumps({"name": "T", "description": "t", "protocol": ["FT", "DMINT"], "ticker": "TT"}))
    flags = [
        "--v2",
        "--daa-mode", "epoch",
        "--difficulty", "32768",
        "--epoch-length", "10",
        "--max-adjustment", "8",
        "--num-contracts", "2",
        "--max-height", "50",
        "--reward", "700",
        "--premine", "12345",
        "--op-return", "echo-recovery",
    ]  # fmt: skip
    base = ["--config", str(tmp_path / "absent.toml"), "--network", "regtest", "--wallet", str(tmp_path / "w.dat")]
    result = CliRunner().invoke(cli, [*base, "--yes", "glyph", "deploy-dmint", str(meta), *flags])

    # 1. The commit relayed, and the command stopped on the lie.
    assert result.exit_code == 1, result.output
    assert len(client.sent) == 1, "the commit, and no reveal"
    commit = Transaction.from_hex(client.sent[0])
    local = commit.txid()
    assert node.cli("getrawtransaction", local), "the commit is on the node"
    node.mine(1)
    cli_params, cli_deploy = built[-1]
    assert cli_params.max_adjustment_log2 == 3, "--max-adjustment 8"
    assert cli_params.last_time is None and isinstance(cli_deploy.last_time, int), "resolved by the build"
    expected = cli_deploy.build_reveal_outputs(local)

    # 2. Follow the printed recipe, unmodified.
    code = _recipe_code(result.output)
    print(f"\nprinted recipe:\n{code}")
    ns: dict[str, Any] = {}
    exec(code, ns)  # the recipe IS the thing under test
    rev = ns["rev"]
    assert ns["params"] == replace(cli_params, last_time=cli_deploy.last_time), "every parameter the CLI used"
    assert rev.contract_scripts == expected.contract_scripts
    assert rev.premine_script == expected.premine_script and rev.premine_amount == expected.premine_amount
    assert rev.op_return_script == expected.op_return_script

    # 3. The control, first (testmempoolaccept is side-effect free): one parameter wrong is accepted
    #    too. Here it is max_adjustment_log2 left at its default of 2, what a rebuild gets by passing
    #    the flag's value 8 through no mapping or by omitting it. The commit does not bind it.
    wrong_params = replace(ns["params"], max_adjustment_log2=2)
    wrong_rev = GlyphBuilder().prepare_dmint_deploy(wrong_params, allow_v2_deploy=True).build_reveal_outputs(local)
    assert wrong_rev.contract_scripts != expected.contract_scripts, "a different token"
    wrong = _reveal_tx(commit, wrong_rev, owner=owner, n=2)
    verdict = node.accepts(wrong.serialize().hex())
    print(f"wrong-parameter rebuild: {verdict}")
    assert verdict.get("allowed") is True, "the node takes a mis-parameterised reveal of the same commit"

    reveal = _reveal_tx(commit, rev, owner=owner, n=2)
    assert node.accepts(reveal.serialize().hex()).get("allowed") is True
    reveal_txid = str(node.cli("sendrawtransaction", reveal.serialize().hex()))
    node.mine(1)
    onchain = Transaction.from_hex(str(node.cli("getrawtransaction", reveal_txid)))
    assert node.cli("getrawtransaction", reveal_txid, "1")["confirmations"] >= 1
    assert [bytes(o.locking_script.serialize()) for o in onchain.outputs[:2]] == list(expected.contract_scripts)
    print(f"reveal {reveal_txid} confirmed; contract outputs byte-identical to the CLI's")
