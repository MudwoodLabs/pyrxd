"""``glyph transfer-nft --allow-overpay`` and ``glyph timelock-reveal --allow-overpay`` (#793).

Both flags were dead for the same reason as ``mark --allow-overpay``. Each value went only to
the rate CEILING in ``assert_fee_rate_clears_relay_floor``. Neither command has a
``--fee-rate``, so the rate is ``ctx.fee_rate``, and the config loader (``validated_fee_rate``)
has already refused it above that same ceiling before the command runs. So all three are now
deprecated through one helper, ``_deprecated_allow_overpay_option``. The flag is still
accepted, hidden from ``--help``, prints one note on stderr, and is never forwarded.

``mark``'s own tests are ``tests/test_hashmark_mark_cli.py::TestMarkAllowOverpayIsDeprecated``.
Every run here goes through the top-level ``cli``, so the config load is included. Only the
wallet loader and the ElectrumX client are faked. ``--config`` names a path that does not
exist, so the rate is the built-in default rather than the configuration of whatever machine
runs the suite.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import click
import pytest
from click.testing import CliRunner, Result

from pyrxd.cli.context import CliContext
from pyrxd.cli.main import cli
from pyrxd.glyph.script import build_nft_locking_script
from pyrxd.glyph.types import GlyphRef
from pyrxd.keys import PrivateKey
from pyrxd.network.electrumx import UtxoRecord
from pyrxd.script.script import Script
from pyrxd.script.type import P2PKH
from pyrxd.security.types import Hex20
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_output import TransactionOutput

_NOTE = "--allow-overpay is deprecated and has no effect on `pyrxd {command}`"


def _source_tx(vout: int, spk: bytes, value: int) -> bytes:
    outs = [TransactionOutput(Script(b""), 0) for _ in range(vout)]
    outs.append(TransactionOutput(Script(spk), value))
    return Transaction(tx_inputs=[], tx_outputs=outs).serialize()


class _NftNet:
    """A wallet holding one NFT singleton and one plain-RXD UTXO, and a node serving their parents.

    One instance is used for both runs of a comparison. Its keys are fixed and signing is
    RFC 6979, so the two runs build byte-identical transactions and any difference is the flag's.
    """

    REF = f"{'aa' * 32}:0"

    def __init__(self, fund_value: int = 60_000_000) -> None:
        self.triples: list = []
        self.txmap: dict[str, bytes] = {}
        self.broadcasts: list[bytes] = []
        owner = PrivateKey()
        ref = GlyphRef(txid="aa" * 32, vout=0)
        self._add(owner, build_nft_locking_script(Hex20(owner.public_key().hash160()), ref), 1000)
        fund_key = PrivateKey()
        self._add(fund_key, P2PKH().lock(fund_key.address()).serialize(), fund_value)
        self.to = PrivateKey().address()

        async def _bcast(raw: bytes) -> str:
            self.broadcasts.append(raw)
            return Transaction.from_hex(raw.hex()).txid()

        client = MagicMock()
        client.get_transaction = AsyncMock(side_effect=lambda t: self.txmap[str(t)])
        client.broadcast = _bcast
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=None)
        self.client = client
        net = self

        class _Wallet:
            async def collect_spendable(self, client):
                return list(net.triples)

        self.wallet = _Wallet()

    def _add(self, key: PrivateKey, spk: bytes, value: int) -> None:
        txid = f"{len(self.triples) + 1:02x}" * 32
        self.txmap[txid] = _source_tx(1, spk, value)
        self.triples.append((UtxoRecord(tx_hash=txid, tx_pos=1, value=value, height=100), key.address(), key))


def _run(monkeypatch, tmp_path: Path, module, wallet, client, args: list[str], *, top=()) -> Result:
    monkeypatch.setattr(module, "_load_wallet", lambda ctx, **kw: wallet)
    monkeypatch.setattr(CliContext, "make_client", lambda self: client)
    monkeypatch.delenv("PYRXD_FEE_RATE", raising=False)
    monkeypatch.delenv("PYRXD_NETWORK", raising=False)
    return CliRunner().invoke(
        cli,
        ["--config", str(tmp_path / "absent.toml"), "--wallet", str(tmp_path / "w.dat"), *top, *args],
    )


def _transfer_nft(monkeypatch, tmp_path, *, top, flag: bool, net: _NftNet) -> tuple[Result, list[bytes]]:
    import pyrxd.cli.glyph_cmds as gc

    net.broadcasts.clear()
    args = ["glyph", "transfer-nft", _NftNet.REF, "--to", net.to, *(["--allow-overpay"] if flag else [])]
    r = _run(monkeypatch, tmp_path, gc, net.wallet, net.client, args, top=top)
    return r, list(net.broadcasts)


class _Reveal:
    """A sealed timelock mint and a funded wallet whose tip is at the unlock point.

    One instance per comparison, for the same reason as :class:`_NftNet`.
    """

    def __init__(self, tmp_path: Path) -> None:
        from tests.test_glyph_timelock_write_side_is_reachable import UNLOCK_AT, _RevealHarness, _seal

        self.build = _seal()
        self.harness = _RevealHarness(tip=UNLOCK_AT)
        self.harness.client.__aenter__ = AsyncMock(return_value=self.harness.client)
        self.harness.client.__aexit__ = AsyncMock(return_value=None)
        self.cek_file = tmp_path / "cek.hex"
        self.cek_file.write_text(self.build.cek.hex())


def _timelock_reveal(monkeypatch, tmp_path, *, top, extra, flag: bool, rv: _Reveal) -> tuple[Result, list[bytes]]:
    import pyrxd.cli.glyph_timelock_cmds as gtc
    from pyrxd.glyph.payload import decode_payload, encode_payload
    from tests.test_glyph_timelock_write_side_is_reachable import TOKEN_REF

    metadata = rv.build.metadata

    async def _fetch(self, ref):
        return decode_payload(encode_payload(metadata)[0])

    monkeypatch.setattr(gtc.GlyphScanner, "fetch_metadata", _fetch)
    rv.harness.broadcast_calls.clear()
    args = [
        "glyph",
        "timelock-reveal",
        TOKEN_REF,
        "--cek-file",
        str(rv.cek_file),
        *extra,
        *(["--allow-overpay"] if flag else []),
    ]
    r = _run(monkeypatch, tmp_path, gtc, rv.harness.wallet, rv.harness.client, args, top=top)
    return r, list(rv.harness.broadcast_calls)


def _assert_only_the_note_differs(command: str, without: Result, with_flag: Result) -> None:
    note = _NOTE.format(command=command)
    assert without.exit_code == 0, without.output
    assert with_flag.exit_code == 0, with_flag.output
    assert without.stdout_bytes, "an empty stdout would make the comparison vacuous"
    assert with_flag.stdout_bytes == without.stdout_bytes
    assert note not in without.stderr
    assert with_flag.stderr.count(note) == 1, with_flag.stderr
    note_line = next(ln for ln in with_flag.stderr.splitlines() if note in ln)
    assert with_flag.stderr.replace(note_line + "\n", "", 1) == without.stderr


_MODES = [("--yes",), ("--json", "--yes"), ("--quiet", "--yes")]
_MODE_IDS = ["human", "json", "quiet"]


class TestTransferNftAllowOverpayIsDeprecated:
    @pytest.mark.parametrize("top", _MODES, ids=_MODE_IDS)
    def test_the_flag_changes_no_byte_of_stdout_or_of_the_broadcast(self, monkeypatch, tmp_path, top) -> None:
        net = _NftNet()
        without, sent_without = _transfer_nft(monkeypatch, tmp_path, top=top, flag=False, net=net)
        with_flag, sent_with = _transfer_nft(monkeypatch, tmp_path, top=top, flag=True, net=net)
        _assert_only_the_note_differs("glyph transfer-nft", without, with_flag)
        assert len(sent_without) == 1, "control: the transfer was broadcast"
        assert sent_with == sent_without

    def test_the_flag_is_not_in_the_help(self) -> None:
        r = CliRunner().invoke(cli, ["glyph", "transfer-nft", "--help"])
        assert r.exit_code == 0, r.output
        assert "--passphrase" in r.output, "control: an option the help does list"
        assert "overpay" not in r.output.lower()

    def test_the_rate_gate_is_never_told_to_allow_an_overpay(self, monkeypatch, tmp_path) -> None:
        seen = _spy_on_the_rate_gate(monkeypatch)
        r, _ = _transfer_nft(monkeypatch, tmp_path, top=("--json", "--yes"), flag=True, net=_NftNet())
        assert r.exit_code == 0, r.output
        assert seen, "control: the gate the flag used to reach was called"
        assert seen == [False] * len(seen)


class TestTimelockRevealAllowOverpayIsDeprecated:
    @pytest.mark.parametrize(
        ("top", "extra"),
        [((), ["--dry-run"]), *((m, []) for m in _MODES)],
        ids=["human-dry-run", *_MODE_IDS],
    )
    def test_the_flag_changes_no_byte_of_stdout_or_of_the_broadcast(self, monkeypatch, tmp_path, top, extra) -> None:
        rv = _Reveal(tmp_path)
        without, sent_without = _timelock_reveal(monkeypatch, tmp_path, top=top, extra=extra, flag=False, rv=rv)
        with_flag, sent_with = _timelock_reveal(monkeypatch, tmp_path, top=top, extra=extra, flag=True, rv=rv)
        _assert_only_the_note_differs("glyph timelock-reveal", without, with_flag)
        assert len(sent_without) == (0 if "--dry-run" in extra else 1), "control: broadcast iff not a dry run"
        assert sent_with == sent_without

    def test_the_flag_is_not_in_the_help(self) -> None:
        r = CliRunner().invoke(cli, ["glyph", "timelock-reveal", "--help"])
        assert r.exit_code == 0, r.output
        assert "--allow-early" in r.output, "control: an option the help does list"
        assert "overpay" not in r.output.lower()

    def test_the_rate_gate_is_never_told_to_allow_an_overpay(self, monkeypatch, tmp_path) -> None:
        seen = _spy_on_the_rate_gate(monkeypatch)
        rv = _Reveal(tmp_path)
        r, _ = _timelock_reveal(monkeypatch, tmp_path, top=(), extra=["--dry-run"], flag=True, rv=rv)
        assert r.exit_code == 0, r.output
        assert seen, "control: the gate the flag used to reach was called"
        assert seen == [False] * len(seen)


def _spy_on_the_rate_gate(monkeypatch) -> list[bool]:
    """Record ``allow_overpay`` at the one place both flags' values used to go.

    Both builders import ``assert_fee_rate_clears_relay_floor`` from :mod:`pyrxd.fee_sizing`
    at call time, so patching the module attribute is what they call.
    """
    import pyrxd.fee_sizing as fs

    real = fs.assert_fee_rate_clears_relay_floor
    seen: list[bool] = []

    def _spy(*args, **kwargs):
        seen.append(kwargs.get("allow_overpay", False))
        return real(*args, **kwargs)

    monkeypatch.setattr(fs, "assert_fee_rate_clears_relay_floor", _spy)
    return seen


def _allow_overpay_options() -> dict[str, click.Option]:
    """Every command in the real CLI tree that takes ``--allow-overpay``, derived by walking it."""
    found: dict[str, click.Option] = {}

    def _walk(cmd: click.Command, path: list[str]) -> None:
        if isinstance(cmd, click.Group):
            for name, sub in cmd.commands.items():
                _walk(sub, [*path, name])
            return
        for p in cmd.params:
            if isinstance(p, click.Option) and "--allow-overpay" in p.opts:
                found[" ".join(path)] = p

    _walk(cli, [])
    return found


class TestWhichCommandsHaveADeadFlag:
    """Membership pinned, so a change to either set has to be looked at, not inherited.

    The deprecated set shares one callback, so the three behave identically. The live set is
    the flags that still decide something: ``wallet send`` / ``sweep`` (their own
    ``--fee-rate``), ``swap build-claim`` / ``build-refund`` (the fee UTXO's value), and
    ``glyph transfer-ft`` / ``airdrop-ft``. The last two are unreachable today only because of
    the 2x funding rule in ``ft_funding``, and are kept as an escape hatch.
    """

    DEPRECATED = {"mark", "glyph transfer-nft", "glyph timelock-reveal"}
    LIVE = {
        "wallet send",
        "wallet sweep",
        "swap build-claim",
        "swap build-refund",
        "glyph transfer-ft",
        "glyph airdrop-ft",
    }

    def test_the_deprecated_set_and_the_live_set(self) -> None:
        opts = _allow_overpay_options()
        assert {name for name, o in opts.items() if o.hidden} == self.DEPRECATED
        assert {name for name, o in opts.items() if not o.hidden} == self.LIVE

    def test_every_deprecated_flag_is_the_shared_one(self) -> None:
        opts = _allow_overpay_options()
        for name in self.DEPRECATED:
            o = opts[name]
            assert o.expose_value is False, f"{name}: the value must not reach the command"
            assert o.callback is not None, name
            assert o.callback.__qualname__ == "_deprecated_allow_overpay_option.<locals>._note", name
