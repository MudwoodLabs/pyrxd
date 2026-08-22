"""Tests for `pyrxd wallet sweep` — move funds from a derived path (value-bearing)."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
from click.testing import CliRunner

from pyrxd.cli.config import Config
from pyrxd.cli.context import CliContext
from pyrxd.cli.wallet_cmds import wallet_group
from pyrxd.hd.wallet import HdWallet
from pyrxd.network.electrumx import UtxoRecord

MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
# A valid, unrelated P2PKH destination (the canonical abandon-seed coin-0 address).
DEST = "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA"


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


def _addr(coin_type: int, account: int, change: int, index: int) -> str:
    w = HdWallet.from_mnemonic(MNEMONIC, account=account, coin_type=coin_type)
    return w._derive_address(change, index)


def _funded_client(funded_addr: str | None, *, value: int = 100_000_000) -> MagicMock:
    """Mock ElectrumX: *funded_addr* has history + one UTXO; everything else empty."""
    from pyrxd.network.electrumx import script_hash_for_address

    async def _get_history(script_hash):
        if funded_addr and script_hash_for_address(funded_addr) == script_hash:
            return [{"tx_hash": "ab" * 32, "height": 800000}]
        return []

    async def _get_utxos(script_hash):
        if funded_addr and script_hash_for_address(funded_addr) == script_hash:
            return [UtxoRecord(tx_hash="ab" * 32, tx_pos=0, value=value, height=800000)]
        return []

    client = MagicMock()
    client.get_history = _get_history
    client.get_utxos = _get_utxos
    client.get_balance = AsyncMock(return_value=(0, 0))
    client.broadcast = AsyncMock(return_value="cd" * 32)
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=None)
    return client


def _ctx(client: MagicMock, *, output_mode: str = "human", yes: bool = False) -> CliContext:
    return CliContext(
        config=Config(
            network="mainnet", electrumx="wss://test/", fee_rate=10_000, wallet_path=Path("/tmp/_pyrxd_sweep")
        ),
        network="mainnet",
        electrumx_url="wss://test/",
        fee_rate=10_000,
        wallet_path=Path("/tmp/_pyrxd_sweep"),
        output_mode=output_mode,
        yes=yes,
        client_factory=lambda: client,
    )


def _invoke(runner: CliRunner, ctx: CliContext, args: list[str], *, confirm: str = "y"):
    # Mnemonic at the hidden prompt, then the y/N broadcast confirmation.
    return runner.invoke(wallet_group, args, obj=ctx, input=f"{MNEMONIC}\n{confirm}\n")


class TestWalletSweep:
    def test_sweeps_funded_path_and_broadcasts(self, runner: CliRunner) -> None:
        funded = _addr(0, 0, 0, 0)
        client = _funded_client(funded)
        result = _invoke(runner, _ctx(client), ["sweep", "--coin-type", "0", "--to", DEST], confirm="y")
        assert result.exit_code == 0, result.output
        assert "Swept" in result.output
        assert "cdcd" in result.output  # txid prefix
        client.broadcast.assert_awaited_once()

    def test_confirmation_decline_does_not_broadcast(self, runner: CliRunner) -> None:
        funded = _addr(0, 0, 0, 0)
        client = _funded_client(funded)
        result = _invoke(runner, _ctx(client), ["sweep", "--coin-type", "0", "--to", DEST], confirm="n")
        assert result.exit_code != 0
        assert "abort" in result.output.lower()
        client.broadcast.assert_not_awaited()

    def test_no_funds_errors_without_broadcast(self, runner: CliRunner) -> None:
        client = _funded_client(None)  # nothing funded anywhere
        result = _invoke(runner, _ctx(client), ["sweep", "--coin-type", "0", "--to", DEST])
        assert result.exit_code != 0
        assert "no spendable funds" in result.output
        client.broadcast.assert_not_awaited()

    def test_sub_fee_balance_refused_without_broadcast(self, runner: CliRunner) -> None:
        # A balance at/below the network fee (dust) must be refused cleanly,
        # before any broadcast. Mirrors the real mainnet 0.01-RXD case.
        funded = _addr(512, 0, 0, 0)
        client = _funded_client(funded, value=1_000)  # far below the per-tx fee
        result = _invoke(runner, _ctx(client), ["sweep", "--coin-type", "512", "--to", DEST], confirm="y")
        assert result.exit_code != 0
        assert "could not build the sweep transaction" in result.output
        assert "too small to move" in result.output  # honest dust framing
        client.broadcast.assert_not_awaited()

    def test_invalid_destination_rejected(self, runner: CliRunner) -> None:
        client = _funded_client(None)
        result = _invoke(runner, _ctx(client), ["sweep", "--coin-type", "0", "--to", "not-an-address"])
        assert result.exit_code != 0
        assert "invalid --to" in result.output
        client.broadcast.assert_not_awaited()

    def test_json_requires_yes(self, runner: CliRunner) -> None:
        client = _funded_client(_addr(0, 0, 0, 0))
        result = _invoke(runner, _ctx(client, output_mode="json"), ["sweep", "--coin-type", "0", "--to", DEST])
        assert result.exit_code != 0
        assert "--yes" in result.output
        client.broadcast.assert_not_awaited()

    def test_json_with_yes_emits_txid(self, runner: CliRunner) -> None:
        funded = _addr(512, 0, 0, 0)
        client = _funded_client(funded)
        ctx = _ctx(client, output_mode="json", yes=True)
        # --yes skips the confirm prompt; only the mnemonic is read from stdin.
        result = runner.invoke(
            wallet_group, ["sweep", "--coin-type", "512", "--to", DEST], obj=ctx, input=f"{MNEMONIC}\n"
        )
        assert result.exit_code == 0, result.output
        start, end = result.output.find("{"), result.output.rfind("}")
        payload = json.loads(result.output[start : end + 1])
        assert payload["txid"] == "cd" * 32
        assert payload["from_path"] == "m/44'/512'/0'"
        assert payload["to"] == DEST
        client.broadcast.assert_awaited_once()

    def test_invalid_mnemonic_rejected_without_broadcast(self, runner: CliRunner) -> None:
        client = _funded_client(_addr(0, 0, 0, 0))
        result = runner.invoke(
            wallet_group,
            ["sweep", "--coin-type", "0", "--to", DEST],
            obj=_ctx(client),
            input="not a real bip39 mnemonic phrase here\ny\n",
        )
        assert result.exit_code != 0
        client.broadcast.assert_not_awaited()

    def test_empty_mnemonic_rejected(self, runner: CliRunner) -> None:
        client = _funded_client(_addr(0, 0, 0, 0))
        result = runner.invoke(wallet_group, ["sweep", "--coin-type", "0", "--to", DEST], obj=_ctx(client), input="\n")
        assert result.exit_code != 0
        assert "mnemonic is required" in result.output
        client.broadcast.assert_not_awaited()

    def test_testnet_address_rejected_on_mainnet(self, runner: CliRunner) -> None:
        # MEDIUM-1 fix: a testnet-prefixed --to must be rejected on a mainnet
        # config, or the sweep would pay a script no mainnet key can spend.
        testnet_dest = "mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn"  # valid testnet P2PKH
        client = _funded_client(_addr(0, 0, 0, 0))
        result = _invoke(runner, _ctx(client), ["sweep", "--coin-type", "0", "--to", testnet_dest])
        assert result.exit_code != 0
        assert "invalid --to" in result.output
        client.broadcast.assert_not_awaited()

    def test_zero_fee_rate_rejected_before_seed_prompt(self, runner: CliRunner) -> None:
        # LOW-2 fix: bad --fee-rate fails before the mnemonic is requested.
        client = _funded_client(_addr(0, 0, 0, 0))
        result = runner.invoke(
            wallet_group,
            ["sweep", "--coin-type", "0", "--to", DEST, "--fee-rate", "0"],
            obj=_ctx(client),
            input="",  # no mnemonic provided — must fail before needing it
        )
        assert result.exit_code != 0
        assert "--fee-rate" in result.output
        assert "Mnemonic" not in result.output  # never reached the seed prompt
        client.broadcast.assert_not_awaited()

    @pytest.mark.parametrize("rate", ["1", "100", "9999"])
    def test_sub_floor_fee_rate_rejected_before_seed_prompt(self, runner: CliRunner, rate: str) -> None:
        """``--fee-rate`` was checked only for ``> 0``, so it was the one path into a
        spend that could still set a rate the network will not relay. Radiant has
        neither RBF nor CPFP, so such a transaction cannot be bumped and squats on
        its own inputs until mempool expiry. The config file's ``fee_rate`` has been
        floor-checked since e0772e0; the flag that overrides it was not."""
        client = _funded_client(_addr(0, 0, 0, 0))
        result = runner.invoke(
            wallet_group,
            ["sweep", "--coin-type", "0", "--to", DEST, "--fee-rate", rate],
            obj=_ctx(client),
            input="",
        )
        assert result.exit_code != 0
        assert "relay floor" in result.output
        assert "Mnemonic" not in result.output
        client.broadcast.assert_not_awaited()

    @pytest.mark.parametrize("rate", ["100001", "10000000"])
    def test_overpay_rejected_before_seed_prompt(self, runner: CliRunner, rate: str) -> None:
        """#457. ``--fee-rate`` bounded only the LOW end; the SDK has bounded the high end
        since #456, so the CLI was the looser guard over the likelier slip — a human
        pasting a per-kB figure into a per-BYTE flag. ``10000000`` is exactly
        ``RADIANT_EFFECTIVE_MIN_RELAY_PHOTONS_PER_KB``, a 1000x overpay.

        Sweep is the sharpest case in the CLI: it has **no change output**, so the entire
        difference leaves with the miner, and Radiant has neither RBF nor CPFP to recover
        it. Refused before the seed prompt, like the sub-floor case above."""
        client = _funded_client(_addr(0, 0, 0, 0))
        result = runner.invoke(
            wallet_group,
            ["sweep", "--coin-type", "0", "--to", DEST, "--fee-rate", rate],
            obj=_ctx(client),
            input="",
        )
        assert result.exit_code != 0
        assert "ceiling" in result.output
        assert "--allow-overpay" in result.output, "the message must name the way through"
        client.broadcast.assert_not_awaited()

    def test_allow_overpay_gets_past_the_ceiling_but_not_past_the_floor(self, runner: CliRunner) -> None:
        """The opt-out skips its own bound only. A flag that also waived the floor would
        turn a fat-finger guard into a way to build an unrelayable transaction."""
        client = _funded_client(_addr(0, 0, 0, 0))
        result = runner.invoke(
            wallet_group,
            ["sweep", "--coin-type", "0", "--to", DEST, "--fee-rate", "1", "--allow-overpay"],
            obj=_ctx(client),
            input="",
        )
        assert result.exit_code != 0
        assert "relay floor" in result.output
        client.broadcast.assert_not_awaited()

    def test_allow_overpay_actually_reaches_the_builder_not_just_the_cli_gate(self, runner: CliRunner) -> None:
        """The flag must be a real path, not a broken promise.

        Found by exploiting the first cut of #457: ``--allow-overpay`` satisfied the CLI
        gate and the builder was then called WITHOUT it, so the SDK's own ceiling refused
        the spend a moment later. The operator is told "pass --allow-overpay", does, and
        is refused again — a guard rejecting work the operator explicitly authorised,
        which is the same bug class #458 exists to fix.

        Asserting on the broadcast rather than the exit code is deliberate: a CLI-gate-only
        fix would still fail here, because the refusal happens after the gate.
        """
        funded = _addr(0, 0, 0, 0)
        client = _funded_client(funded, value=500_000_000)
        result = _invoke(
            runner,
            _ctx(client),
            ["sweep", "--coin-type", "0", "--to", DEST, "--fee-rate", "200000", "--allow-overpay"],
            confirm="y",
        )
        assert "ceiling" not in result.output, "the builder refused a rate the operator authorised"
        assert result.exit_code == 0, result.output
        client.broadcast.assert_awaited_once()

    def test_fee_rate_help_says_per_byte_not_per_kB(self, runner: CliRunner) -> None:
        """``hd/wallet.py`` computes ``fee = size * fee_rate`` with size in BYTES.
        The help said "per kB", which understates the fee by 1000x to anyone who
        reads it and does the arithmetic."""
        result = runner.invoke(wallet_group, ["sweep", "--help"])
        assert "per BYTE" in result.output
        assert "per kB" not in result.output

    def test_negative_coin_type_rejected(self, runner: CliRunner) -> None:
        client = _funded_client(None)
        result = _invoke(runner, _ctx(client), ["sweep", "--coin-type", "-1", "--to", DEST])
        assert result.exit_code != 0
        client.broadcast.assert_not_awaited()

    def test_summary_shows_amount_fee_and_destination(self, runner: CliRunner) -> None:
        funded = _addr(0, 0, 0, 0)
        client = _funded_client(funded)
        result = _invoke(runner, _ctx(client), ["sweep", "--coin-type", "0", "--to", DEST], confirm="y")
        assert "from path:   m/44'/0'/0'" in result.output
        assert "to address:" in result.output
        assert DEST in result.output
        assert "you receive" in result.output


class TestTheOverpayOptOutReachesEveryBuilder:
    """``--allow-overpay`` must reach the BUILDER, not just the CLI gate.

    The first cut of #457 added the flag, validated it in ``_checked_fee_rate``, and then
    called the builders without it — so the flag cleared one ceiling and was refused by
    the next. Three call sites were affected (``sweep``, and both of ``send``'s paths:
    agent and in-process), and two of them are inside module-level helpers that did not
    take the parameter at all, which surfaced as a ``NameError`` rather than a wrong fee.

    A source-level assertion rather than three behavioural ones: the failure is a MISSING
    kwarg, so the thing worth pinning is that no call site can be added later without it.
    """

    @staticmethod
    def _wallet_cmds_source() -> str:
        import inspect

        from pyrxd.cli import wallet_cmds

        return inspect.getsource(wallet_cmds)

    def test_every_builder_call_forwards_allow_overpay(self) -> None:
        import re

        src = self._wallet_cmds_source()
        # Each call spans several lines after formatting, so match the call and take
        # everything up to its closing paren at the same indent.
        calls = re.findall(r"\.(build_send_max_tx|build_send_tx|build_send)\((.*?)\n(\s*)\)", src, re.S)
        assert calls, "no builder calls found — this test has stopped testing anything"
        for name, body, _indent in calls:
            assert "allow_overpay" in body, (
                f"{name}(...) does not forward allow_overpay; --allow-overpay would clear the "
                "CLI gate and then be refused by the builder's own ceiling"
            )

    def test_both_send_helpers_accept_the_flag(self) -> None:
        """They are module-level, so a closure will not carry the value for them."""
        import inspect

        from pyrxd.cli.wallet_cmds import _send_in_process, _send_via_agent

        for fn in (_send_via_agent, _send_in_process):
            params = inspect.signature(fn).parameters
            assert "allow_overpay" in params, fn.__name__
            assert params["allow_overpay"].default is False, f"{fn.__name__} must default closed"
