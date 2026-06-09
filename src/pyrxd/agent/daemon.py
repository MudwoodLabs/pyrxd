"""The signing-agent daemon: a local Unix-socket server holding the unlocked
wallet and signing on the CLI's behalf (load-bearing §6-7).

Security posture (all THREE required, not any one):
* ``0700`` on the socket's directory **and** ``0600`` on the socket itself, so
  only the owner can reach it at the filesystem layer.
* ``SO_PEERCRED`` — the connecting process's uid must equal the daemon owner's;
  a different uid is refused before any request is read.

The seed lives in the held :class:`HdWallet` for the unlock window only. An idle
timeout auto-locks (zeroizes the seed and shuts down); ``lock`` does it on
demand. Confirmation is delegated to an injected :data:`ConfirmFn` that must
prompt on the daemon's OWN terminal (see :mod:`pyrxd.agent.confirm`) — never the
requester, who is the very same-uid process the confirmation defends against.

The accept loop is single-threaded and serial: one connection, one request, one
response. That is plenty for a single-user CLI agent and keeps the seed-touching
path free of concurrency. The listening socket carries a short timeout so the
loop wakes to evaluate the idle auto-lock even with no traffic.
"""

from __future__ import annotations

import os
import socket
import struct
import time
from collections.abc import Callable
from pathlib import Path

from ..hd.bip32 import Xpub
from .errors import SignerDeclined, SignerError
from .hygiene import harden_process
from .protocol import SigningRequest
from .signer import AgentSigner, ConfirmFn
from .transport import recv_frame, send_frame

#: ``struct ucred`` from SO_PEERCRED: pid, uid, gid (three 32-bit ints).
_UCRED = struct.Struct("3i")

#: Default idle window before auto-lock (15 minutes).
DEFAULT_IDLE_TIMEOUT_S = 900.0


class AgentDaemon:
    """Holds an unlocked wallet and signs requests arriving on a Unix socket."""

    def __init__(
        self,
        wallet,
        *,
        socket_path: str | Path,
        confirm: ConfirmFn,
        idle_timeout_s: float = DEFAULT_IDLE_TIMEOUT_S,
        poll_interval_s: float = 0.5,
        clock: Callable[[], float] = time.monotonic,
        harden: bool = True,
    ) -> None:
        self._wallet = wallet
        self._signer: AgentSigner | None = AgentSigner(wallet)
        # The account xpub is public — cache it so it survives lock() and the CLI
        # can keep building watch-only after the seed is gone.
        self._account_xpub = str(Xpub.from_xprv(wallet._xprv))
        self._socket_path = Path(socket_path)
        self._confirm = confirm
        self._idle_timeout_s = idle_timeout_s
        self._poll = poll_interval_s
        self._clock = clock
        self._harden = harden
        self._owner_uid = os.getuid()
        self._last_activity = clock()
        self._locked = False
        self._sock: socket.socket | None = None
        self._hardening: dict | None = None

    # ---- pure, unit-testable policy --------------------------------------

    def _peer_authorized(self, uid: int) -> bool:
        """A peer is authorized iff its uid is the daemon owner's."""
        return uid == self._owner_uid

    def _should_autolock(self, now: float) -> bool:
        return not self._locked and (now - self._last_activity) >= self._idle_timeout_s

    @property
    def locked(self) -> bool:
        return self._locked

    # ---- lifecycle -------------------------------------------------------

    def serve_forever(self) -> None:
        """Bind, harden, then serve until locked (idle, on-demand, or signal)."""
        self._bind()
        if self._harden:
            self._hardening = harden_process().as_dict()
        try:
            while not self._locked:
                try:
                    conn, _ = self._sock.accept()
                except TimeoutError:
                    if self._should_autolock(self._clock()):
                        self.lock()
                    continue
                except OSError:
                    break  # socket closed under us (lock() / shutdown)
                with conn:
                    self._serve_conn(conn)
        finally:
            self._close_socket()

    def lock(self) -> None:
        """Zeroize the seed, drop the wallet, and stop serving. Idempotent."""
        if self._locked:
            return
        self._locked = True
        wallet, self._wallet, self._signer = self._wallet, None, None
        try:
            wallet._seed.zeroize()
        except Exception:  # nosec B110 — best-effort scrub; locking must succeed even if zeroize raises
            pass
        self._close_socket()

    # ---- socket plumbing -------------------------------------------------

    def _bind(self) -> None:
        directory = self._socket_path.parent
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(directory, 0o700)  # enforce even if it pre-existed looser
        if self._socket_path.exists():
            if self._probe_live():
                raise SignerError(f"an agent is already running at {self._socket_path}")
            self._socket_path.unlink()  # stale socket from a dead daemon

        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        # umask so the socket is created 0600 (no group/other), then chmod to be sure.
        old_umask = os.umask(0o177)
        try:
            sock.bind(str(self._socket_path))
        finally:
            os.umask(old_umask)
        os.chmod(self._socket_path, 0o600)
        sock.listen(8)
        sock.settimeout(self._poll)
        self._sock = sock

    def _probe_live(self) -> bool:
        """True iff something is accepting on the existing socket (single-instance)."""
        probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        probe.settimeout(0.5)
        try:
            probe.connect(str(self._socket_path))
            return True
        except OSError:
            return False
        finally:
            probe.close()

    def _close_socket(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            finally:
                self._sock = None
        try:
            self._socket_path.unlink()
        except OSError:
            pass

    # ---- request handling ------------------------------------------------

    def _serve_conn(self, conn: socket.socket) -> None:
        uid = self._read_peer_uid(conn)
        if uid is None or not self._peer_authorized(uid):
            self._safe_send(conn, {"ok": False, "kind": "error", "error": "peer not authorized"})
            return
        try:
            req = recv_frame(conn)
        except SignerError as exc:
            self._safe_send(conn, {"ok": False, "kind": "error", "error": str(exc)})
            return
        self._safe_send(conn, self._dispatch(req))

    def _read_peer_uid(self, conn: socket.socket) -> int | None:
        try:
            raw = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, _UCRED.size)
            _pid, uid, _gid = _UCRED.unpack(raw)
            return uid
        except OSError:
            return None

    def _dispatch(self, req: dict) -> dict:
        if self._locked or self._signer is None:
            return {"ok": False, "kind": "locked", "error": "agent is locked"}
        self._last_activity = self._clock()
        op = req.get("op")
        if op == "status":
            return {"ok": True, "result": {"unlocked": True, "xpub": self._account_xpub, "hardening": self._hardening}}
        if op == "xpub":
            return {"ok": True, "result": {"xpub": self._account_xpub}}
        if op == "lock":
            self.lock()
            return {"ok": True, "result": {"locked": True}}
        if op == "sign":
            return self._handle_sign(req)
        return {"ok": False, "kind": "error", "error": f"unknown op {op!r}"}

    def _handle_sign(self, req: dict) -> dict:
        try:
            request = SigningRequest.from_dict(req["request"])
        except (KeyError, TypeError, ValueError) as exc:
            return {"ok": False, "kind": "error", "error": f"bad signing request: {exc}"}
        try:
            result = self._signer.sign(request, confirm=self._confirm)
        except SignerDeclined as exc:
            return {"ok": False, "kind": "declined", "error": str(exc)}
        except SignerError as exc:
            return {"ok": False, "kind": "error", "error": str(exc)}
        return {"ok": True, "result": result.to_dict()}

    @staticmethod
    def _safe_send(conn: socket.socket, obj: dict) -> None:
        try:
            send_frame(conn, obj)
        except (OSError, SignerError):
            pass  # peer hung up; nothing more to do
