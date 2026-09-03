"""Decode the Photonic ``msg`` convention — the only OP_RETURN format with real
volume on Radiant mainnet.

``OP_RETURN PUSH3 "msg" <push> <message>``. The 3-byte ``msg`` marker is what
wallet and explorer parsers key on. pyrxd already WRITES this (see
:data:`pyrxd.constants.MAX_OP_RETURN_MSG_BYTES` and the dMint miner's
``op_return_msg``); until now it could not read one back, so every such output
rendered as an opaque hex blob.

Measured on 20 consecutive mainnet blocks: **73 of 73** ``OP_RETURN`` outputs
carried this marker, and nothing else did.

The message is arbitrary operator bytes. This module returns it as data and does
NOT sanitise — display sanitisation belongs at the render boundary, which already
has ``_sanitize_display_string`` for bidi overrides and friends. Returning
pre-mangled text would make the raw bytes unrecoverable for a caller that wants
to verify them.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .script import data_pushes_after_op_return

__all__ = ["MSG_MARKER", "MessageOutcome", "MessageRecord", "decode_message"]

#: The marker push, compared as bytes.
MSG_MARKER = b"msg"


class MessageOutcome(Enum):
    OK = "ok"
    #: Not a `msg` output. Skip silently — most data carriers belong to something else.
    NOT_MESSAGE = "not_message"
    #: Claims to be one (carries the marker) and is malformed.
    INVALID = "invalid"


@dataclass(frozen=True)
class MessageRecord:
    outcome: MessageOutcome
    #: The message decoded as UTF-8, or None when the bytes are not valid UTF-8.
    #: NOT sanitised for display; the renderer does that.
    text: str | None = None
    #: The raw message bytes, always present on OK — a caller verifying a
    #: commitment needs the bytes, not a lossy decode of them.
    raw: bytes | None = None
    is_utf8: bool = False
    detail: str | None = None

    @property
    def ok(self) -> bool:
        return self.outcome is MessageOutcome.OK


def decode_message(script: bytes) -> MessageRecord:
    """Decode a ``scriptPubKey`` as a Photonic ``msg`` data carrier."""
    pushes = data_pushes_after_op_return(script)
    if pushes is None or not pushes or pushes[0] != MSG_MARKER:
        return MessageRecord(MessageOutcome.NOT_MESSAGE)

    # Past the marker the output claims to be a message, so a bad shape is a
    # genuine defect rather than another protocol's data.
    if len(pushes) != 2:
        return MessageRecord(
            MessageOutcome.INVALID,
            detail=f"expected exactly 2 pushes (marker + message), found {len(pushes)}",
        )
    raw = pushes[1]
    if not raw:
        return MessageRecord(MessageOutcome.INVALID, detail="message push is empty")

    # NON-UTF-8 IS NOT AN ERROR. The bytes are already on chain and nothing
    # constrains them to text; refusing would lose a record we can otherwise
    # describe exactly. Report the bytes and say the decode failed.
    try:
        return MessageRecord(MessageOutcome.OK, text=raw.decode("utf-8"), raw=raw, is_utf8=True)
    except UnicodeDecodeError:
        return MessageRecord(MessageOutcome.OK, text=None, raw=raw, is_utf8=False)
