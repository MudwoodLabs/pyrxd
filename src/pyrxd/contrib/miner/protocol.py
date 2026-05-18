"""Wire protocol for the pyrxd external-miner JSON-over-subprocess contract.

Pinned in 0.5.1. Future protocol changes are **additive only**, gated
by the ``protocol`` field in the request. A miner that receives an
unknown ``protocol`` value rejects the request (exit code 1).

This module is the single source of truth for the protocol shape.
Both the miner (this package's ``cli.main``) and the verifier
(:func:`pyrxd.glyph.dmint.mine_solution_external` in pyrxd core)
must agree on what the bytes on the wire look like.
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass
from typing import Any, Literal

# Wire-protocol version. Bump when adding a non-additive change.
# 0.5.1 ships protocol=1.
PROTOCOL_VERSION = 1

# Mirrors the on-chain target ceiling (V1/V2 covenant). The miner clamps
# any caller-supplied target above this — a target above the ceiling
# would make every hash with a 4-zero prefix trivially valid.
MAX_SHA256D_TARGET = 0x7FFFFFFFFFFFFFFF

# Upper-bound stdin payload size. A request larger than this is malformed
# by construction (a valid request is well under 1 KB). Bounded read
# defends against an upstream component dumping unbounded data into the
# miner's stdin and exhausting RAM before we hit the json parser.
MAX_REQUEST_BYTES = 4096

# Upper-bound stdout response size. The miner writes one short JSON
# line; anything larger is a bug.
MAX_RESPONSE_BYTES = 4096


class ProtocolError(ValueError):
    """The request or response failed protocol validation.

    Distinct from generic ``ValueError`` so the CLI can map it cleanly
    to exit code 1 (usage error) without catching unrelated upstream
    bugs that also raise ``ValueError``.
    """


@dataclass(frozen=True)
class MineRequest:
    """One inbound mining request.

    :param preimage:    64-byte preimage from :func:`pyrxd.glyph.dmint.build_pow_preimage`.
    :param target:      The PoW target as a Python int (clamped to
                        :data:`MAX_SHA256D_TARGET` at use time).
    :param nonce_width: 4 (V1 contracts) or 8 (V2).
    :param protocol:    Wire-protocol version. Currently always 1.
    """

    preimage: bytes
    target: int
    nonce_width: Literal[4, 8]
    protocol: int = PROTOCOL_VERSION

    @classmethod
    def from_json(cls, raw: bytes | str) -> MineRequest:
        """Parse one JSON object from a bytes/str payload.

        Validates field types + lengths before returning. Bytes input
        is decoded as UTF-8; anything else is a :class:`ProtocolError`.
        """
        if isinstance(raw, bytes):
            if len(raw) > MAX_REQUEST_BYTES:
                raise ProtocolError(f"request too large: {len(raw)} > {MAX_REQUEST_BYTES} bytes")
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise ProtocolError("request is not valid UTF-8") from exc
        else:
            if len(raw) > MAX_REQUEST_BYTES:
                raise ProtocolError(f"request too large: {len(raw)} > {MAX_REQUEST_BYTES} chars")
            text = raw

        try:
            obj = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ProtocolError(f"request is not valid JSON: {exc.msg}") from exc

        if not isinstance(obj, dict):
            raise ProtocolError("request must be a JSON object")

        try:
            preimage_hex = obj["preimage_hex"]
            target_hex = obj["target_hex"]
            nonce_width = obj["nonce_width"]
        except KeyError as exc:
            raise ProtocolError(f"request missing required field: {exc.args[0]!r}") from exc

        protocol = obj.get("protocol", PROTOCOL_VERSION)
        if not isinstance(protocol, int) or isinstance(protocol, bool):
            raise ProtocolError("'protocol' must be an integer")
        if protocol != PROTOCOL_VERSION:
            raise ProtocolError(f"unsupported protocol version: {protocol} (this miner speaks {PROTOCOL_VERSION})")

        if not isinstance(preimage_hex, str):
            raise ProtocolError("'preimage_hex' must be a string")
        try:
            preimage = bytes.fromhex(preimage_hex)
        except ValueError as exc:
            raise ProtocolError(f"'preimage_hex' is not valid hex: {exc}") from exc
        if len(preimage) != 64:
            raise ProtocolError(f"preimage must be 64 bytes, got {len(preimage)}")

        if not isinstance(target_hex, str):
            raise ProtocolError("'target_hex' must be a string")
        try:
            target = int(target_hex, 16)
        except ValueError as exc:
            raise ProtocolError(f"'target_hex' is not valid hex: {exc}") from exc
        if target <= 0:
            raise ProtocolError(f"target must be positive, got {target}")

        if isinstance(nonce_width, bool) or not isinstance(nonce_width, int):
            raise ProtocolError("'nonce_width' must be an integer")
        if nonce_width not in (4, 8):
            raise ProtocolError(f"'nonce_width' must be 4 or 8, got {nonce_width}")

        return cls(
            preimage=preimage,
            target=target,
            nonce_width=nonce_width,
            protocol=protocol,
        )


@dataclass(frozen=True)
class MineSuccess:
    """Successful mining result. Wire-shape on stdout.

    :param nonce:     The mined nonce, ``nonce_width`` bytes wide.
    :param attempts:  Number of nonces tried (best-effort metric).
    :param elapsed_s: Wall-clock seconds spent searching.
    """

    nonce: bytes
    attempts: int
    elapsed_s: float

    def to_json(self) -> str:
        """Serialise to the one-line JSON shape pyrxd's verifier expects.

        ``elapsed_s`` must be finite — pyrxd rejects NaN/Inf on the
        receiving side. We assert here so a buggy miner produces a
        loud failure rather than a silent rejection.
        """
        if not math.isfinite(self.elapsed_s):
            raise ProtocolError(f"elapsed_s must be finite, got {self.elapsed_s!r}")
        return json.dumps(
            {
                "nonce_hex": self.nonce.hex(),
                "attempts": self.attempts,
                "elapsed_s": self.elapsed_s,
            }
        )


@dataclass(frozen=True)
class MineExhausted:
    """Signal that the nonce space was searched without finding a hit.

    Wire-shape on stdout: ``{"exhausted": true}``. pyrxd's
    :func:`mine_solution_external` recognises this and raises
    :class:`MaxAttemptsError` immediately rather than waiting for the
    parent timeout.

    Old miners that don't know this convention can still surface
    exhaustion by sleeping past the parent's ``timeout_s`` and being
    SIGKILLed — that path still works as a fallback.
    """

    def to_json(self) -> str:
        return json.dumps({"exhausted": True})


def parse_response(raw: bytes | str) -> MineSuccess | MineExhausted:
    """Parse a stdout response back into a typed object.

    Used by pyrxd's :func:`mine_solution_external` on the verifier
    side. The miner doesn't call this — it serialises with
    :meth:`MineSuccess.to_json` or :meth:`MineExhausted.to_json`.

    :raises ProtocolError: malformed JSON, oversize payload, or a
        response that matches neither schema.
    """
    if isinstance(raw, bytes):
        if len(raw) > MAX_RESPONSE_BYTES:
            raise ProtocolError(f"response too large: {len(raw)} > {MAX_RESPONSE_BYTES} bytes")
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ProtocolError("response is not valid UTF-8") from exc
    else:
        if len(raw) > MAX_RESPONSE_BYTES:
            raise ProtocolError(f"response too large: {len(raw)} > {MAX_RESPONSE_BYTES} chars")
        text = raw

    try:
        obj: Any = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ProtocolError(f"response is not valid JSON: {exc.msg}") from exc

    if not isinstance(obj, dict):
        raise ProtocolError("response must be a JSON object")

    if obj.get("exhausted") is True:
        return MineExhausted()

    try:
        nonce_hex = obj["nonce_hex"]
        attempts = obj["attempts"]
        elapsed_s = obj["elapsed_s"]
    except KeyError as exc:
        raise ProtocolError(f"response missing required field: {exc.args[0]!r}") from exc

    if not isinstance(nonce_hex, str):
        raise ProtocolError("'nonce_hex' must be a string")
    try:
        nonce = bytes.fromhex(nonce_hex)
    except ValueError as exc:
        raise ProtocolError(f"'nonce_hex' is not valid hex: {exc}") from exc

    if isinstance(attempts, bool) or not isinstance(attempts, int):
        raise ProtocolError("'attempts' must be an integer")
    if attempts < 0:
        raise ProtocolError(f"'attempts' must be non-negative, got {attempts}")

    if isinstance(elapsed_s, bool) or not isinstance(elapsed_s, (int, float)):
        raise ProtocolError("'elapsed_s' must be a number")
    elapsed_s_float = float(elapsed_s)
    if not math.isfinite(elapsed_s_float):
        raise ProtocolError(f"'elapsed_s' must be finite, got {elapsed_s!r}")
    if elapsed_s_float < 0:
        raise ProtocolError(f"'elapsed_s' must be non-negative, got {elapsed_s_float}")

    return MineSuccess(nonce=nonce, attempts=attempts, elapsed_s=elapsed_s_float)
