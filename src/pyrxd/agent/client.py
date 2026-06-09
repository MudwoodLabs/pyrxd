"""CLI-side client for the signing agent.

Thin, stateless wrapper over the Unix socket: each call opens a connection, does
one request/response round-trip, and closes. If the socket is absent or refuses
the connection the agent is simply not running — the caller gets a typed
:class:`SignerUnavailableError` and falls back to the in-process mnemonic prompt.
Daemon-side refusals (declined confirmation, validation failures) surface as the
same typed errors the in-process signer raises, so callers handle one vocabulary.
"""

from __future__ import annotations

import socket
from pathlib import Path

from .errors import SignerDeclined, SignerError, SignerUnavailableError
from .protocol import SignedResult, SigningRequest
from .transport import recv_frame, send_frame


class AgentClient:
    """Talks to a running :class:`~pyrxd.agent.daemon.AgentDaemon`."""

    def __init__(self, socket_path: str | Path, *, connect_timeout_s: float = 2.0) -> None:
        self._socket_path = Path(socket_path)
        self._timeout = connect_timeout_s

    def is_live(self) -> bool:
        """True iff an agent answers a status query on the socket (never raises)."""
        try:
            resp = self._roundtrip({"op": "status"})
        except (SignerUnavailableError, SignerError):
            return False
        return bool(resp.get("ok"))

    def account_xpub(self) -> str:
        """The account xpub the agent vends (for watch-only tx building)."""
        return self._unwrap(self._roundtrip({"op": "xpub"}))["xpub"]

    def sign(self, request: SigningRequest) -> SignedResult:
        """Send a signing request; return the signed tx or raise the typed error."""
        resp = self._roundtrip({"op": "sign", "request": request.to_dict()})
        return SignedResult.from_dict(self._unwrap(resp))

    def lock(self) -> None:
        """Ask the agent to lock (zeroize + shut down). No-op if already down."""
        try:
            self._roundtrip({"op": "lock"})
        except SignerUnavailableError:
            pass

    # ---- internals -------------------------------------------------------

    def _connect(self) -> socket.socket:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self._timeout)
        try:
            sock.connect(str(self._socket_path))
        except OSError as exc:
            sock.close()
            raise SignerUnavailableError(f"signing agent not reachable at {self._socket_path}: {exc}") from exc
        return sock

    def _roundtrip(self, request: dict) -> dict:
        sock = self._connect()
        try:
            send_frame(sock, request)
            return recv_frame(sock)
        finally:
            sock.close()

    @staticmethod
    def _unwrap(resp: dict) -> dict:
        """Return the ``result`` payload, or raise the typed error the daemon sent."""
        if resp.get("ok"):
            return resp["result"]
        kind = resp.get("kind")
        message = str(resp.get("error", "agent error"))
        if kind == "declined":
            raise SignerDeclined(message)
        raise SignerError(message)
