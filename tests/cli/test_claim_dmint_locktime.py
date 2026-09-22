"""``claim-dmint``'s locktime, through the shipped CLI: the default, the deploy hint, the refusals.

The V2 covenant writes the mint's locktime back into the recreated contract as ``lastTime``
(``04 || NUM2BIN(locktime, 4)``), and ASERT, LWMA and EPOCH read that item back as a script
number when they retarget. Two things went wrong together before this file:

* ``--current-time`` defaulted to ``0``, so the default claim wrote a lastTime the
  contract's next retarget could not read.
* once deploy started stamping ``lastTime = now``, the mint builder's old "backwards"
  refusal turned the claim hint ``deploy-dmint`` prints into a command that always failed
  for every non-FIXED mode, with a reason that did not describe those contracts.

Everything here runs the real ``claim-dmint`` (and, for the hint, the real ``deploy-dmint``)
through click's CliRunner. What is stubbed, and why:

* the wallet and the ElectrumX client — there is no node here; the fakes hand the commands
  a funded key and record what they broadcast;
* ``_claim_prepare`` — the ElectrumX read of the contract; it returns the contract script
  the deploy command itself broadcast, so the claim spends the deploy's real bytes;
* ``_mine_bundled_parallel`` — the PoW grind. Its NONCE is not the subject (no covenant
  evaluates it here); whether the grind STARTED is, so every stub records its calls.

The mint builder, its guards, the CLI's exception mapping and the default-time resolution
all run for real.
"""

from __future__ import annotations

import shlex
import time
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from click.testing import CliRunner

from pyrxd.cli import glyph_cmds
from pyrxd.cli.main import cli
from pyrxd.glyph.dmint import (
    DaaMode,
    DmintContractUtxo,
    DmintDeployParams,
    DmintMinerFundingUtxo,
    DmintState,
    build_dmint_contract_script,
    is_readable_last_time,
)
from pyrxd.glyph.types import GlyphRef
from pyrxd.keys import PrivateKey
from pyrxd.network.electrumx import UtxoRecord
from pyrxd.transaction.transaction import Transaction


def _write_dmint_meta(path: Path) -> Path:
    path.write_text('{"name": "T", "description": "t", "protocol": ["FT", "DMINT"], "ticker": "TT", "decimals": 0}')
    return path


class _Net:
    """The fake network both commands talk to: records every broadcast, confirms at once."""

    def __init__(self) -> None:
        self.broadcasts: list[bytes] = []

    async def __aenter__(self) -> _Net:
        return self

    async def __aexit__(self, *exc: object) -> bool:
        return False

    async def broadcast(self, raw: bytes) -> str:
        self.broadcasts.append(bytes(raw))
        return Transaction.from_hex(bytes(raw).hex()).txid()  # an honest echo

    get_transaction_verbose = AsyncMock(return_value={"confirmations": 1})


def _patch_network_and_wallet(monkeypatch: pytest.MonkeyPatch, net: _Net, key: PrivateKey) -> None:
    utxo = UtxoRecord(tx_hash="ab" * 32, tx_pos=0, value=500_000_000, height=100)

    class _Wallet:
        async def collect_spendable(self, client: object) -> list:
            return [(utxo, key.address(), key)]

    monkeypatch.setattr(glyph_cmds, "_load_wallet", lambda ctx, **kw: _Wallet())
    monkeypatch.setattr(glyph_cmds.CliContext, "make_client", lambda self: net)


def _patch_claim(monkeypatch: pytest.MonkeyPatch, contract: DmintContractUtxo, grinds: list[int]) -> list[str | None]:
    """Serve ``contract`` to claim-dmint, fund it, and record grinds + the contract asked for."""
    key = PrivateKey()  # fresh random key; never hand-written material
    pkh = bytes(key.public_key().hash160())
    funding = DmintMinerFundingUtxo(
        txid="ef" * 32, vout=0, value=50_000_000, script=b"\x76\xa9\x14" + pkh + b"\x88\xac"
    )
    asked: list[str | None] = []

    async def _fake_prepare(ctx, wallet, contract_arg, token_ref_arg, reward_address, client):
        asked.append(contract_arg)
        return contract, funding, key, pkh

    def _fake_grind(preimage: bytes, target: int, **kw: object) -> bytes:
        grinds.append(target)
        return b"\x00" * 8

    monkeypatch.setattr(glyph_cmds, "_claim_prepare", _fake_prepare)
    monkeypatch.setattr(glyph_cmds, "_mine_bundled_parallel", _fake_grind)
    return asked


def _claim_args(wallet: Path, *extra: str) -> list[str]:
    return ["--wallet", str(wallet), "--yes", "glyph", "claim-dmint", "--no-progress", *extra]


def _minted_state(net: _Net) -> tuple[Transaction, DmintState]:
    tx = Transaction.from_hex(net.broadcasts[-1].hex())
    return tx, DmintState.from_script(tx.outputs[0].locking_script.script)


# ---------------------------------------------------------------------------
# (a) The claim deploy-dmint tells you to run is a claim that builds.
# ---------------------------------------------------------------------------

_DEPLOY_FLAGS = {
    "asert": ["--daa-mode", "asert"],
    "lwma": ["--daa-mode", "lwma"],
    "epoch": ["--daa-mode", "epoch", "--difficulty", "32768", "--epoch-length", "10", "--max-adjustment", "4"],
    "schedule": ["--daa-mode", "schedule", "--schedule", "[[100, 4]]"],
}


class TestTheDeployHintClaims:
    @pytest.mark.parametrize("mode", sorted(_DEPLOY_FLAGS))
    def test_the_printed_claim_command_builds_a_mint_with_a_readable_last_time(
        self, mode: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """deploy-dmint (no --last-time: the deploy stamps now) -> the exact ``claim with:``
        line it prints -> claim-dmint (no --current-time: the claim uses now).

        Before the fix this failed for all four modes: the claim wrote locktime 0, which the
        builder refused as "backwards" against the deploy's stamp."""
        wallet = tmp_path / "w.dat"
        meta = _write_dmint_meta(tmp_path / "m.json")
        net = _Net()
        _patch_network_and_wallet(monkeypatch, net, PrivateKey())

        runner = CliRunner()
        deployed = runner.invoke(
            cli,
            [
                "--wallet",
                str(wallet),
                "--yes",
                "glyph",
                "deploy-dmint",
                str(meta),
                "--v2",
                "--max-height",
                "100",
                "--reward",
                "1000",
                *_DEPLOY_FLAGS[mode],
            ],
        )
        assert deployed.exit_code == 0, deployed.output
        hint = next(ln for ln in deployed.output.splitlines() if "claim with:" in ln)
        hint_argv = shlex.split(hint.split("claim with:", 1)[1])
        assert hint_argv[:2] == ["glyph", "claim-dmint"], hint
        assert "--current-time" not in hint_argv, "the hint must work WITHOUT a locktime flag"

        reveal = Transaction.from_hex(net.broadcasts[-1].hex())
        spk = reveal.outputs[0].locking_script.script
        contract = DmintContractUtxo(txid=reveal.txid(), vout=0, value=1, script=spk, state=DmintState.from_script(spk))
        assert contract.state.daa_mode == DaaMode[mode.upper()]
        grinds: list[int] = []
        asked = _patch_claim(monkeypatch, contract, grinds)

        before = int(time.time())
        claimed = runner.invoke(cli, ["--wallet", str(wallet), "--yes", *hint_argv, "--no-progress"])
        after = int(time.time())
        assert claimed.exit_code == 0, claimed.output
        assert asked == [f"{reveal.txid()}:0"], "the hint named a different contract than the deploy made"
        assert len(grinds) == 1

        tx, state = _minted_state(net)
        assert state.height == 1
        assert state.last_time == tx.locktime  # the covenant rebuilds lastTime from OP_TXLOCKTIME
        assert before <= state.last_time <= after, "the default locktime is the wall clock at claim"
        # Read off the PARSED state, not by searching the script for `04 00000000`: Part B1
        # carries those same five bytes (the four-zero-byte PoW prefix compare), so a byte
        # search would find them in every contract.
        assert is_readable_last_time(state.last_time)


# ---------------------------------------------------------------------------
# (b) The default claim of an EPOCH contract no longer writes 04 00000000.
# ---------------------------------------------------------------------------


def _epoch_contract(*, height: int, last_time: int) -> DmintContractUtxo:
    """An EPOCH contract (epochLength 10, 4x clamp) — lastTime 0 is what every EPOCH deploy
    pyrxd made before 2026-09-22 carries, and what the conformance vector carries."""
    params = DmintDeployParams(
        contract_ref=GlyphRef(txid="ab" * 32, vout=1),
        token_ref=GlyphRef(txid="cd" * 32, vout=0),
        max_height=1000,
        reward=1000,
        difficulty=32768,
        daa_mode=DaaMode.EPOCH,
        target_time=60,
        height=height,
        last_time=last_time,
        epoch_length=10,
        max_adjustment_log2=2,
    )
    spk = build_dmint_contract_script(params)
    return DmintContractUtxo(txid="ab" * 32, vout=0, value=1, script=spk, state=DmintState.from_script(spk))


class TestEpochDefaultClaim:
    _EPOCH = ("--contract", "ab" * 32 + ":0", "--epoch-length", "10", "--max-adjustment", "4")

    def test_the_mint_before_a_boundary_writes_a_readable_last_time(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Height 9 -> 10: the state this mint creates is an epoch boundary, so the NEXT mint
        reads the lastTime this one writes. The old default wrote 0 there."""
        net = _Net()
        monkeypatch.setattr(glyph_cmds, "_load_wallet", lambda ctx, **kw: object())
        monkeypatch.setattr(glyph_cmds.CliContext, "make_client", lambda self: net)
        grinds: list[int] = []
        _patch_claim(monkeypatch, _epoch_contract(height=9, last_time=0), grinds)

        result = CliRunner().invoke(cli, _claim_args(tmp_path / "w.dat", *self._EPOCH))
        assert result.exit_code == 0, result.output
        tx, state = _minted_state(net)
        assert state.height == 10 and state.height % 10 == 0  # the next mint retargets
        assert is_readable_last_time(state.last_time) and state.last_time == tx.locktime

    def test_an_explicit_zero_is_refused_before_the_grind(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The refusal behind the default: the same claim with --current-time 0 would write the
        unreadable 04 00000000 and is refused — before any proof-of-work is spent."""
        net = _Net()
        monkeypatch.setattr(glyph_cmds, "_load_wallet", lambda ctx, **kw: object())
        monkeypatch.setattr(glyph_cmds.CliContext, "make_client", lambda self: net)
        grinds: list[int] = []
        _patch_claim(monkeypatch, _epoch_contract(height=9, last_time=0), grinds)

        result = CliRunner().invoke(cli, _claim_args(tmp_path / "w.dat", *self._EPOCH, "--current-time", "0"))
        assert result.exit_code != 0
        assert "could not build a valid mint" in result.output
        assert "is below 2**23" in result.output
        assert "funding can't cover" not in result.output
        assert grinds == [] and net.broadcasts == []


# ---------------------------------------------------------------------------
# A contract that can no longer be minted is reported as such, not ground against.
# ---------------------------------------------------------------------------


class TestAnUnmineableContractIsNotGroundAgainst:
    def _asert(self, last_time: int) -> DmintContractUtxo:
        params = DmintDeployParams(
            contract_ref=GlyphRef(txid="ab" * 32, vout=1),
            token_ref=GlyphRef(txid="cd" * 32, vout=0),
            max_height=100,
            reward=1000,
            difficulty=8,
            daa_mode=DaaMode.ASERT,
            target_time=60,
            last_time=last_time,
        )
        spk = build_dmint_contract_script(params)
        return DmintContractUtxo(txid="ab" * 32, vout=0, value=1, script=spk, state=DmintState.from_script(spk))

    def _run(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, contract: DmintContractUtxo):
        net = _Net()
        monkeypatch.setattr(glyph_cmds, "_load_wallet", lambda ctx, **kw: object())
        monkeypatch.setattr(glyph_cmds.CliContext, "make_client", lambda self: net)
        grinds: list[int] = []
        _patch_claim(monkeypatch, contract, grinds)
        result = CliRunner().invoke(cli, _claim_args(tmp_path / "w.dat", "--contract", "ab" * 32 + ":0"))
        return result, grinds, net

    def test_last_time_zero_is_reported_as_unmineable_and_never_ground(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        result, grinds, net = self._run(tmp_path, monkeypatch, self._asert(0))
        assert result.exit_code != 0
        assert "can no longer be minted" in result.output
        assert "funding can't cover" not in result.output
        assert grinds == [] and net.broadcasts == []

    def test_the_honest_neighbour_mints(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """lastTime 2**23 — the smallest readable value — is not refused."""
        result, grinds, net = self._run(tmp_path, monkeypatch, self._asert(1 << 23))
        assert result.exit_code == 0, result.output
        assert len(grinds) == 1 and len(net.broadcasts) == 1


# ---------------------------------------------------------------------------
# An EPOCH contract whose lower retarget clamp is 0 (pyrxd no longer deploys one)
# ---------------------------------------------------------------------------


def _small_target_time_epoch(*, last_time: int) -> DmintContractUtxo:
    """EPOCH, target_time 2 with a 4x clamp, at an epoch boundary. The params refuse
    target_time 2 now, so they are built legal and the real value is set afterwards — such a
    contract can still exist on chain, and the claim path is what is under test."""
    params = DmintDeployParams(
        contract_ref=GlyphRef(txid="ab" * 32, vout=1),
        token_ref=GlyphRef(txid="cd" * 32, vout=0),
        max_height=1000,
        reward=1000,
        difficulty=32768,
        daa_mode=DaaMode.EPOCH,
        target_time=4,
        height=10,
        last_time=last_time,
        epoch_length=10,
        max_adjustment_log2=2,
    )
    object.__setattr__(params, "target_time", 2)
    spk = build_dmint_contract_script(params)
    return DmintContractUtxo(txid="ab" * 32, vout=0, value=1, script=spk, state=DmintState.from_script(spk))


class TestTheDefaultClaimNeverWritesTargetOne:
    _EPOCH = ("--contract", "ab" * 32 + ":0", "--epoch-length", "10", "--max-adjustment", "4")

    def _run(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, contract: DmintContractUtxo):
        net = _Net()
        monkeypatch.setattr(glyph_cmds, "_load_wallet", lambda ctx, **kw: object())
        monkeypatch.setattr(glyph_cmds.CliContext, "make_client", lambda self: net)
        grinds: list[int] = []
        _patch_claim(monkeypatch, contract, grinds)
        return CliRunner().invoke(cli, _claim_args(tmp_path / "w.dat", *self._EPOCH)), grinds, net

    def test_a_contract_last_time_ahead_of_the_local_clock_is_refused_not_mined_to_target_1(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        result, grinds, net = self._run(
            tmp_path, monkeypatch, _small_target_time_epoch(last_time=int(time.time()) + 30)
        )
        assert result.exit_code != 0
        assert "could not build a valid mint" in result.output
        assert "target would be 1" in result.output
        assert "funding can't cover" not in result.output
        assert grinds == [] and net.broadcasts == []

    def test_the_honest_neighbour_mints(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """The same contract with its lastTime in the past: the default claim builds."""
        result, grinds, net = self._run(
            tmp_path, monkeypatch, _small_target_time_epoch(last_time=int(time.time()) - 600)
        )
        assert result.exit_code == 0, result.output
        _tx, state = _minted_state(net)
        assert state.target > 1 and len(grinds) == 1


# ---------------------------------------------------------------------------
# deploy-dmint: parameter refusals surface as CLI errors, not tracebacks
# ---------------------------------------------------------------------------


class TestDeployDmintParameterRefusals:
    def _deploy(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *extra: str):
        net = _Net()
        _patch_network_and_wallet(monkeypatch, net, PrivateKey())
        meta = _write_dmint_meta(tmp_path / "m.json")
        args = ["--wallet", str(tmp_path / "w.dat"), "--yes", "glyph", "deploy-dmint", str(meta), "--v2"]
        return CliRunner().invoke(cli, [*args, "--max-height", "100", "--reward", "1000", *extra]), net

    @pytest.mark.parametrize(("mode", "extra"), [("fixed", ()), ("epoch", ("--difficulty", "32768"))])
    def test_a_last_time_outside_four_bytes_is_a_parameter_error(
        self, mode: str, extra: tuple[str, ...], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        result, net = self._deploy(tmp_path, monkeypatch, "--daa-mode", mode, *extra, "--last-time", str(1 << 32))
        assert result.exit_code != 0
        assert "invalid dMint deploy parameters" in result.output
        assert "4-byte lastTime push" in result.output
        # A UserError exits through SystemExit (a BaseException); a raw struct.error would not.
        assert not isinstance(result.exception, Exception), repr(result.exception)
        assert net.broadcasts == []

    def test_an_epoch_target_time_below_2_pow_n_is_refused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        flags = ("--daa-mode", "epoch", "--difficulty", "32768", "--max-adjustment", "4")
        result, net = self._deploy(tmp_path, monkeypatch, *flags, "--target-time", "3")
        assert result.exit_code != 0
        assert "invalid dMint deploy parameters" in result.output
        assert net.broadcasts == []
        # Honest neighbour: target_time 4 == 2**2 deploys.
        ok, net_ok = self._deploy(tmp_path, monkeypatch, *flags, "--target-time", "4")
        assert ok.exit_code == 0, ok.output
        assert len(net_ok.broadcasts) == 2  # commit + reveal
