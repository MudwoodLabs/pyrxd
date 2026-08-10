"""Optional TLS SubjectPublicKeyInfo (SPKI) pinning for ElectrumX connections.

What it buys you
----------------
Ordinary TLS says "some CA vouches for this hostname". That is not the same as
"this is the server whose key I decided to trust". An adversary who can obtain a
valid certificate for the hostname — a mis-issuing or compelled CA, a corporate
TLS-inspecting middlebox, a hijacked DNS record plus an ACME challenge — sits in
the middle with a chain your OS trust store happily accepts. Pinning the hash of
the server's **public key** closes that: a substituted server presents a
different key, the pin does not match, and the connection is refused before any
RPC is sent.

Why it is OFF by default
------------------------
A pin is a hard commitment to a specific key. When the operator legitimately
rotates their TLS key — a routine, unannounced event on a Let's Encrypt-style
renewal that generates a fresh key — every pinned client breaks at once, and the
failure looks exactly like an attack. Silently defaulting people into that is how
pinning earned its bad reputation (and why HPKP was withdrawn from the web
platform). So: pinning here is **opt-in**, enabled by naming the pins you accept,
and a mismatch raises a distinct, loud :class:`~pyrxd.security.errors.TlsPinMismatchError`
that says which endpoint failed and what the observed pin was, so a rotation is a
one-line config edit rather than a mystery.

Pin format
----------
``sha256/<standard-base64 of SHA-256 over the DER SubjectPublicKeyInfo>`` — the
same string HPKP, Android's Network Security Config, and ``curl --pinnedpubkey``
use, so an operator can produce one with tools they already have::

    openssl s_client -connect host:port -servername host </dev/null 2>/dev/null \\
      | openssl x509 -pubkey -noout \\
      | openssl pkey -pubin -outform der \\
      | openssl dgst -sha256 -binary | base64

A bare base64 digest (no ``sha256/`` prefix) is accepted and normalised.

Pinning the **SPKI**, not the certificate, is deliberate: a renewal that reuses
the key keeps the pin valid, which is the common, safe case.

When the check happens
----------------------
After the TLS handshake and the WebSocket opening handshake complete, and before
any JSON-RPC request is written. The opening handshake is a bare HTTP ``GET`` with
no credentials and no wallet data, so nothing sensitive has been disclosed to an
impostor at the point the pin is evaluated; being able to reject before the
handshake would require reimplementing the connect path, and would buy nothing.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
from collections.abc import Sequence
from typing import Any

from ..security.errors import TlsPinMismatchError, ValidationError

__all__ = [
    "PIN_PREFIX",
    "assert_pin_matches",
    "normalize_pin",
    "peer_certificate_der",
    "spki_pin_from_cert_der",
    "verify_connection_pin",
]

PIN_PREFIX = "sha256/"

# A SHA-256 digest is 32 bytes; standard base64 of 32 bytes is 44 characters
# including one '=' pad. Anything else is not a pin, and accepting it would let a
# typo silently disable the very check the operator asked for.
_DIGEST_BYTES = 32


def normalize_pin(pin: str) -> str:
    """Canonicalise a caller-supplied pin to ``sha256/<base64>``.

    Accepts the prefixed form and a bare base64 digest. Whitespace is stripped.

    Raises:
        ValidationError: if *pin* is not a base64 SHA-256 digest. Failing here —
            at config-load time — is the point: a malformed pin must never be
            silently ignored, because "ignored" means "unpinned".
    """
    if not isinstance(pin, str):
        raise ValidationError(f"SPKI pin must be a string, got {type(pin).__name__}")
    text = pin.strip()
    if not text:
        raise ValidationError("SPKI pin must be a non-empty string")
    body = text[len(PIN_PREFIX) :] if text.lower().startswith(PIN_PREFIX) else text
    try:
        raw = base64.b64decode(body, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValidationError("SPKI pin must be standard base64 (see pyrxd.network.tls_pin)") from exc
    if len(raw) != _DIGEST_BYTES:
        raise ValidationError(f"SPKI pin must decode to {_DIGEST_BYTES} bytes (SHA-256), got {len(raw)}")
    return PIN_PREFIX + base64.b64encode(raw).decode("ascii")


def spki_pin_from_cert_der(cert_der: bytes) -> str:
    """Return the ``sha256/<base64>`` pin for a DER-encoded X.509 certificate.

    Hashes the certificate's ``SubjectPublicKeyInfo``, re-serialised to DER by
    ``cryptography`` (already a pyrxd runtime dependency), so the value does not
    depend on how the peer happened to encode the outer certificate.
    """
    if not isinstance(cert_der, (bytes, bytearray)) or not cert_der:
        raise ValidationError("certificate DER must be non-empty bytes")
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    try:
        cert = x509.load_der_x509_certificate(bytes(cert_der))
        spki = cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    except Exception as exc:
        # Never echo certificate bytes: they are attacker-supplied.
        raise ValidationError(f"could not parse peer certificate ({type(exc).__name__})") from None
    return PIN_PREFIX + base64.b64encode(hashlib.sha256(spki).digest()).decode("ascii")


def assert_pin_matches(cert_der: bytes, pins: Sequence[str], *, url: str = "") -> str:
    """Verify *cert_der* against the accepted *pins*; return the observed pin.

    *pins* is a SET of acceptable pins, not a single value — that is what makes a
    key rotation deployable (publish the new pin alongside the old, rotate, drop
    the old) and what lets one pin list cover several failover endpoints.

    Raises:
        TlsPinMismatchError: when the observed pin is in none of *pins*.
        ValidationError: when *pins* is empty (the caller asked for a check it did
            not configure — refuse rather than pass vacuously).
    """
    accepted = tuple(normalize_pin(p) for p in pins)
    if not accepted:
        raise ValidationError("assert_pin_matches called with no pins configured")
    observed = spki_pin_from_cert_der(cert_der)
    if observed not in accepted:
        where = f" for {url}" if url else ""
        raise TlsPinMismatchError(
            f"TLS SPKI pin mismatch{where}: server presented {observed}, "
            f"configured pins are {', '.join(accepted)}. "
            "If the operator rotated their key, add the new pin to spki_pins; "
            "otherwise this connection is not the server you pinned."
        )
    return observed


def peer_certificate_der(connection: Any) -> bytes | None:
    """Best-effort DER of the peer certificate behind a websockets connection.

    Returns ``None`` when the connection is not TLS or exposes no socket (a test
    double, a plaintext ``ws://``). Callers decide what ``None`` means — for
    :func:`verify_connection_pin` it is a hard failure, because "we asked to pin
    and could not look" must not read as "the pin passed".
    """
    transport = getattr(connection, "transport", None)
    get_extra_info = getattr(transport, "get_extra_info", None)
    if get_extra_info is None:
        return None
    ssl_object = get_extra_info("ssl_object")
    if ssl_object is None:
        return None
    getpeercert = getattr(ssl_object, "getpeercert", None)
    if getpeercert is None:
        return None
    der = getpeercert(True)
    return bytes(der) if der else None


def verify_connection_pin(connection: Any, pins: Sequence[str], *, url: str = "") -> str:
    """Pin-check a live websockets connection. No-op contract: never call with empty *pins*.

    Raises:
        TlsPinMismatchError: on a mismatch, or when the peer certificate cannot be
            read at all. Both are "I cannot prove I am talking to the pinned
            server", and both must fail closed.
    """
    cert_der = peer_certificate_der(connection)
    if cert_der is None:
        where = f" for {url}" if url else ""
        raise TlsPinMismatchError(
            f"TLS SPKI pinning is enabled{where} but no peer certificate is available "
            "(is the endpoint plaintext ws://?). Refusing to continue unverified."
        )
    return assert_pin_matches(cert_der, pins, url=url)
