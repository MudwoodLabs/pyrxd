"""Tests for the agent transport, confirmation UI, process hygiene, and the
Unix-socket daemon + client (Phase 4, issue #8 A').

The daemon tests run a real AF_UNIX server in a thread against a tmp-dir socket
(no docker, deterministic). They cover the round-trip (status/xpub/sign), the
declined-confirmation path, socket permissions (0700 dir / 0600 socket), the
fallback when the agent is down, on-demand lock (seed zeroized), and — as pure
unit checks — peer authorization and the idle auto-lock predicate.
"""

from __future__ import annotations

import io
import os
import socket
import stat
import threading
import time

import pytest

from pyrxd.agent import (
    AgentClient,
    AgentDaemon,
    SignerDeclined,
    SignerError,
    SignerUnavailableError,
    SigningRequest,
    TtyConfirmer,
    WatchOnlyTxBuilder,
    WatchOnlyUtxo,
    format_spend_summary,
)
from pyrxd.agent import confirm as confirm_mod
from pyrxd.agent.hygiene import HardeningReport, harden_process
from pyrxd.agent.protocol import ExternalOutput, SpendSummary
from pyrxd.agent.transport import MAX_FRAME_BYTES, recv_frame, send_frame
from pyrxd.hd.bip32 import Xpub
from pyrxd.hd.wallet import HdWallet
from pyrxd.keys import PrivateKey
from pyrxd.script.type import P2PKH
from pyrxd.security.errors import KeyMaterialError
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_output import TransactionOutput

TEST_MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
_ACCEPT = lambda _s: True  # noqa: E731
_REJECT = lambda _s: False  # noqa: E731
_RECIPIENT_ADDR = PrivateKey().public_key().address()


def _wallet() -> HdWallet:
    return HdWallet.from_mnemonic(TEST_MNEMONIC)


def _utxo(w: HdWallet, change: int, index: int, value: int) -> WatchOnlyUtxo:
    src = Transaction()
    src.add_output(TransactionOutput(P2PKH().lock(w._derive_address(change, index)), value))
    return WatchOnlyUtxo(
        txid=src.txid(), vout=0, value=value, change=change, index=index, source_tx_hex=src.serialize().hex()
    )


def _signing_request(w: HdWallet) -> SigningRequest:
    builder = WatchOnlyTxBuilder(Xpub.from_xprv(w._xprv))
    utxos = [_utxo(w, 0, 0, 100_000_000)]
    return builder.build_send(utxos, _RECIPIENT_ADDR, photons=10_000_000, change_index=0).request


def _start(daemon: AgentDaemon) -> threading.Thread:
    t = threading.Thread(target=daemon.serve_forever, daemon=True)
    t.start()
    deadline = time.monotonic() + 3.0
    while time.monotonic() < deadline:
        if daemon._socket_path.exists():
            probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            probe.settimeout(0.2)
            try:
                probe.connect(str(daemon._socket_path))
                probe.close()
                return t
            except OSError:
                pass
        time.sleep(0.02)
    raise RuntimeError("daemon did not come up")


# ─────────────────────────────── transport ────────────────────────────────────


def test_frame_roundtrip() -> None:
    a, b = socket.socketpair()
    try:
        send_frame(a, {"op": "status", "n": 7})
        assert recv_frame(b) == {"op": "status", "n": 7}
    finally:
        a.close()
        b.close()


def test_recv_rejects_oversize_length() -> None:
    a, b = socket.socketpair()
    try:
        a.sendall((MAX_FRAME_BYTES + 1).to_bytes(4, "big"))
        with pytest.raises(SignerError, match="frame too large"):
            recv_frame(b)
    finally:
        a.close()
        b.close()


def test_recv_raises_on_closed_connection() -> None:
    a, b = socket.socketpair()
    a.close()
    try:
        with pytest.raises(SignerError, match="closed mid-frame"):
            recv_frame(b)
    finally:
        b.close()


def test_recv_rejects_non_object_body() -> None:
    a, b = socket.socketpair()
    try:
        body = b"[1,2,3]"
        a.sendall(len(body).to_bytes(4, "big") + body)
        with pytest.raises(SignerError, match="must be a JSON object"):
            recv_frame(b)
    finally:
        a.close()
        b.close()


# ──────────────────────────── confirmation UI ──────────────────────────────────


def _summary(total_external: int) -> SpendSummary:
    return SpendSummary(
        external_outputs=(ExternalOutput(output_index=0, dest="p2pkh:deadbeef", amount=total_external),),
        total_external=total_external,
        change_total=5,
        input_total=total_external + 105,
        fee=100,
        sighash_flags=(0x41,),
    )


def test_format_spend_summary_shows_payees_and_fee() -> None:
    text = format_spend_summary(_summary(120_000))
    assert "120,000" in text
    assert "p2pkh:deadbeef" in text
    assert "fee" in text and "0x41" in text


def test_tty_confirmer_auto_confirms_under_threshold() -> None:
    # total_external (100) <= threshold (100) → approved without touching any tty.
    assert TtyConfirmer(auto_confirm_under=100)(_summary(100)) is True


def test_tty_confirmer_reads_yes_no(monkeypatch: pytest.MonkeyPatch) -> None:
    class _FakeTty(io.StringIO):
        def __init__(self, answer: str) -> None:
            super().__init__(answer)
            self.written = ""

        def write(self, s: str) -> int:  # capture prompt, count chars
            self.written += s
            return len(s)

    for answer, expected in [("y\n", True), ("yes\n", True), ("n\n", False), ("\n", False)]:
        fake = _FakeTty(answer)
        # readline must return the answer; StringIO seeded with prompt-as-buffer won't,
        # so back it with a separate read buffer.
        fake.seek(0)
        monkeypatch.setattr(confirm_mod, "open", lambda *_a, _f=fake, **_k: _f, raising=False)
        assert TtyConfirmer(auto_confirm_under=0)(_summary(120_000)) is expected


def test_tty_confirmer_fails_closed_without_tty(monkeypatch: pytest.MonkeyPatch) -> None:
    def _no_tty(*_a, **_k):
        raise OSError("no controlling tty")

    monkeypatch.setattr(confirm_mod, "open", _no_tty, raising=False)
    assert TtyConfirmer(auto_confirm_under=0)(_summary(120_000)) is False


# ──────────────────────────────── hygiene ──────────────────────────────────────


def test_harden_process_returns_report_without_raising() -> None:
    report = harden_process()
    assert isinstance(report, HardeningReport)
    d = report.as_dict()
    assert set(d) == {"mlock", "non_dumpable", "core_dumps_disabled"}
    assert all(isinstance(v, bool) for v in d.values())


# ──────────────────────────── daemon policy (pure) ─────────────────────────────


def test_peer_authorized_only_for_owner_uid() -> None:
    d = AgentDaemon(_wallet(), socket_path="/tmp/unused.sock", confirm=_ACCEPT, harden=False)
    assert d._peer_authorized(os.getuid()) is True
    assert d._peer_authorized(os.getuid() + 1) is False


def test_should_autolock_after_idle() -> None:
    now = [1000.0]
    d = AgentDaemon(
        _wallet(),
        socket_path="/tmp/unused.sock",
        confirm=_ACCEPT,
        idle_timeout_s=60.0,
        clock=lambda: now[0],
        harden=False,
    )
    assert d._should_autolock(1000.0 + 59.0) is False
    assert d._should_autolock(1000.0 + 60.0) is True
    d.lock()
    assert d._should_autolock(1000.0 + 10_000.0) is False  # already locked → no re-lock


# ─────────────────────────── daemon ⇄ client (real socket) ─────────────────────


def test_daemon_client_status_xpub_and_sign(tmp_path) -> None:
    w = _wallet()
    sock_path = tmp_path / "agent" / "agent.sock"
    daemon = AgentDaemon(w, socket_path=sock_path, confirm=_ACCEPT, harden=False)
    t = _start(daemon)
    try:
        client = AgentClient(sock_path)
        assert client.is_live() is True
        assert client.account_xpub() == str(Xpub.from_xprv(_wallet()._xprv))

        result = client.sign(_signing_request(_wallet()))
        signed = Transaction.from_hex(bytes.fromhex(result.signed_tx_hex))
        assert signed is not None
        assert all(ti.unlocking_script and ti.unlocking_script.serialize() != b"" for ti in signed.inputs)
    finally:
        daemon.lock()
        t.join(timeout=3)


def test_socket_permissions_are_locked_down(tmp_path) -> None:
    sock_path = tmp_path / "agent" / "agent.sock"
    daemon = AgentDaemon(_wallet(), socket_path=sock_path, confirm=_ACCEPT, harden=False)
    t = _start(daemon)
    try:
        assert stat.S_IMODE(os.stat(sock_path).st_mode) == 0o600
        assert stat.S_IMODE(os.stat(sock_path.parent).st_mode) == 0o700
    finally:
        daemon.lock()
        t.join(timeout=3)


def test_declined_confirmation_propagates(tmp_path) -> None:
    sock_path = tmp_path / "agent.sock"
    daemon = AgentDaemon(_wallet(), socket_path=sock_path, confirm=_REJECT, harden=False)
    t = _start(daemon)
    try:
        with pytest.raises(SignerDeclined):
            AgentClient(sock_path).sign(_signing_request(_wallet()))
    finally:
        daemon.lock()
        t.join(timeout=3)


def test_client_against_missing_agent_is_unavailable(tmp_path) -> None:
    client = AgentClient(tmp_path / "nope.sock")
    assert client.is_live() is False
    with pytest.raises(SignerUnavailableError):
        client.sign(_signing_request(_wallet()))


def test_lock_zeroizes_seed_and_stops(tmp_path) -> None:
    w = _wallet()
    sock_path = tmp_path / "agent.sock"
    daemon = AgentDaemon(w, socket_path=sock_path, confirm=_ACCEPT, harden=False)
    t = _start(daemon)
    AgentClient(sock_path).lock()
    t.join(timeout=3)
    assert daemon.locked is True
    assert not sock_path.exists()  # socket cleaned up
    with pytest.raises(KeyMaterialError):  # seed scrubbed → access after zeroize raises
        w._seed.unsafe_raw_bytes()


def test_idle_autolock_fires(tmp_path) -> None:
    sock_path = tmp_path / "agent.sock"
    daemon = AgentDaemon(
        _wallet(), socket_path=sock_path, confirm=_ACCEPT, idle_timeout_s=0.2, poll_interval_s=0.05, harden=False
    )
    t = _start(daemon)
    deadline = time.monotonic() + 3.0
    while time.monotonic() < deadline and not daemon.locked:
        time.sleep(0.05)
    t.join(timeout=3)
    assert daemon.locked is True


def test_concurrent_clients_all_get_valid_responses(tmp_path) -> None:
    """The serial accept loop must service many simultaneous clients correctly
    (each connection one request/response) — none dropped or cross-talked."""
    sock_path = tmp_path / "agent.sock"
    daemon = AgentDaemon(_wallet(), socket_path=sock_path, confirm=_ACCEPT, harden=False)
    t = _start(daemon)
    try:
        expected_xpub = str(Xpub.from_xprv(_wallet()._xprv))
        results: list[str] = []
        errors: list[Exception] = []

        def _query() -> None:
            try:
                results.append(AgentClient(sock_path).account_xpub())
            except Exception as exc:  # record for the assertion
                errors.append(exc)

        threads = [threading.Thread(target=_query) for _ in range(8)]
        for th in threads:
            th.start()
        for th in threads:
            th.join(timeout=5)
        assert not errors, errors
        assert results == [expected_xpub] * 8
    finally:
        daemon.lock()
        t.join(timeout=3)
