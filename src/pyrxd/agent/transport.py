"""Length-prefixed JSON framing for the agent's Unix socket.

A frame is a 4-byte big-endian unsigned length followed by that many bytes of
UTF-8 JSON. Both sides cap the frame size so a hostile peer cannot make the
daemon (or the CLI) allocate unbounded memory. This module is pure transport —
it knows nothing about signing; the request/response *shapes* live in
:mod:`pyrxd.agent.protocol` and are carried as the JSON body.
"""

from __future__ import annotations

import json
import socket
import struct

from .errors import SignerError

#: Hard cap on a single frame (8 MiB). A normal signing request — an unsigned tx
#: plus a handful of full source txs — is kilobytes; this is pure abuse defense.
MAX_FRAME_BYTES = 8 * 1024 * 1024

_LEN = struct.Struct(">I")


def send_frame(sock: socket.socket, obj: dict) -> None:
    """Serialize ``obj`` as JSON and write it as one length-prefixed frame."""
    body = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    if len(body) > MAX_FRAME_BYTES:
        raise SignerError(f"frame too large to send ({len(body)} > {MAX_FRAME_BYTES})")
    sock.sendall(_LEN.pack(len(body)) + body)


def recv_frame(sock: socket.socket) -> dict:
    """Read exactly one length-prefixed JSON frame and return the decoded dict.

    Raises :class:`SignerError` on a closed/short connection, an over-cap length,
    or a non-object/invalid JSON body — fail-closed, never a partial parse.
    """
    header = _recv_exact(sock, _LEN.size)
    (length,) = _LEN.unpack(header)
    if length > MAX_FRAME_BYTES:
        raise SignerError(f"frame too large ({length} > {MAX_FRAME_BYTES})")
    body = _recv_exact(sock, length)
    try:
        obj = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SignerError(f"malformed frame body: {exc}") from exc
    if not isinstance(obj, dict):
        raise SignerError("frame body must be a JSON object")
    return obj


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    """Read exactly ``n`` bytes or raise — a short read means the peer hung up."""
    chunks: list[bytes] = []
    remaining = n
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise SignerError("connection closed mid-frame")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)
