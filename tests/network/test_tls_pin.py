"""Optional TLS SPKI pinning.

Pinning is opt-in, so the tests that matter are the ones proving it is (a) really
off unless asked for, and (b) really fatal when asked for and violated — including
the "we could not look" case, which must not read as "the pin passed".
"""

from __future__ import annotations

import base64
import datetime
import hashlib
from typing import Any
from unittest.mock import patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from pyrxd.network.electrumx import ElectrumXClient
from pyrxd.network.tls_pin import (
    PIN_PREFIX,
    assert_pin_matches,
    normalize_pin,
    peer_certificate_der,
    spki_pin_from_cert_der,
    verify_connection_pin,
)
from pyrxd.security.errors import NetworkError, TlsPinMismatchError, ValidationError


def _self_signed() -> tuple[bytes, str]:
    """Return ``(cert_der, expected_pin)`` for a fresh throwaway EC key.

    Generated per call — never a hard-coded key. (Hand-written test keys have bitten
    this repo before; see the contributing notes on generating key material.)
    """
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "pyrxd-test")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    der = cert.public_bytes(serialization.Encoding.DER)
    spki = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return der, PIN_PREFIX + base64.b64encode(hashlib.sha256(spki).digest()).decode()


class _FakeSsl:
    def __init__(self, der: bytes | None) -> None:
        self._der = der

    def getpeercert(self, binary_form: bool = False) -> bytes | None:
        assert binary_form is True
        return self._der


class _FakeTransport:
    def __init__(self, ssl_object: Any) -> None:
        self._ssl = ssl_object

    def get_extra_info(self, name: str) -> Any:
        return self._ssl if name == "ssl_object" else None


class _FakeConnection:
    def __init__(self, ssl_object: Any, *, with_transport: bool = True) -> None:
        if with_transport:
            self.transport = _FakeTransport(ssl_object)


# ── pin parsing ───────────────────────────────────────────────────────────────


class TestNormalizePin:
    def test_accepts_prefixed_form(self) -> None:
        _, pin = _self_signed()
        assert normalize_pin(pin) == pin

    def test_accepts_bare_base64_and_adds_the_prefix(self) -> None:
        _, pin = _self_signed()
        bare = pin[len(PIN_PREFIX) :]
        assert normalize_pin(bare) == pin

    def test_strips_whitespace(self) -> None:
        _, pin = _self_signed()
        assert normalize_pin(f"  {pin}\n") == pin

    def test_rejects_non_base64(self) -> None:
        with pytest.raises(ValidationError, match="base64"):
            normalize_pin("sha256/not base64 at all!!")

    def test_rejects_a_digest_of_the_wrong_length(self) -> None:
        """A truncated pin must not silently become "no pin"."""
        short = base64.b64encode(b"\x01" * 16).decode()
        with pytest.raises(ValidationError, match="32 bytes"):
            normalize_pin(short)

    def test_rejects_empty(self) -> None:
        with pytest.raises(ValidationError, match="non-empty"):
            normalize_pin("   ")

    def test_rejects_non_string(self) -> None:
        with pytest.raises(ValidationError, match="must be a string"):
            normalize_pin(b"sha256/abc")  # type: ignore[arg-type]


class TestSpkiPinFromCert:
    def test_matches_the_key_that_signed_the_cert(self) -> None:
        der, expected = _self_signed()
        assert spki_pin_from_cert_der(der) == expected

    def test_two_keys_give_two_pins(self) -> None:
        assert _self_signed()[1] != _self_signed()[1]

    def test_rejects_garbage_without_echoing_the_bytes(self) -> None:
        with pytest.raises(ValidationError) as exc:
            spki_pin_from_cert_der(b"\x30\x82not-a-cert")
        assert "not-a-cert" not in str(exc.value)

    def test_rejects_empty(self) -> None:
        with pytest.raises(ValidationError, match="non-empty"):
            spki_pin_from_cert_der(b"")


class TestAssertPinMatches:
    def test_match_returns_the_observed_pin(self) -> None:
        der, pin = _self_signed()
        assert assert_pin_matches(der, [pin]) == pin

    def test_match_against_a_pin_set_supports_rotation(self) -> None:
        der, pin = _self_signed()
        _, other = _self_signed()
        assert assert_pin_matches(der, [other, pin]) == pin

    def test_mismatch_raises_and_names_both_sides(self) -> None:
        der, pin = _self_signed()
        _, other = _self_signed()
        with pytest.raises(TlsPinMismatchError) as exc:
            assert_pin_matches(der, [other], url="wss://a.example/")
        message = str(exc.value)
        assert "wss://a.example/" in message
        assert pin in message and other in message
        assert "spki_pins" in message  # tells the operator how to fix a rotation

    def test_empty_pin_set_is_a_configuration_error_not_a_pass(self) -> None:
        der, _ = _self_signed()
        with pytest.raises(ValidationError, match="no pins configured"):
            assert_pin_matches(der, [])

    def test_is_a_network_error_subclass_so_existing_handlers_still_catch_it(self) -> None:
        assert issubclass(TlsPinMismatchError, NetworkError)


class TestVerifyConnectionPin:
    def test_reads_the_peer_certificate_and_matches(self) -> None:
        der, pin = _self_signed()
        conn = _FakeConnection(_FakeSsl(der))
        assert verify_connection_pin(conn, [pin]) == pin

    def test_mismatch_raises(self) -> None:
        der, _ = _self_signed()
        _, other = _self_signed()
        with pytest.raises(TlsPinMismatchError):
            verify_connection_pin(_FakeConnection(_FakeSsl(der)), [other])

    def test_no_certificate_fails_closed(self) -> None:
        """ "Enabled but unverifiable" must fail. A check that silently degrades to
        no check is worse than no check, because it is believed."""
        with pytest.raises(TlsPinMismatchError, match="no peer certificate"):
            verify_connection_pin(_FakeConnection(_FakeSsl(None)), ["sha256/" + "A" * 43 + "="])

    def test_no_transport_fails_closed(self) -> None:
        with pytest.raises(TlsPinMismatchError, match="no peer certificate"):
            verify_connection_pin(_FakeConnection(None, with_transport=False), ["sha256/" + "A" * 43 + "="])

    def test_peer_certificate_der_returns_none_off_tls(self) -> None:
        assert peer_certificate_der(_FakeConnection(None)) is None
        assert peer_certificate_der(_FakeConnection(None, with_transport=False)) is None


# ── integration with ElectrumXClient ──────────────────────────────────────────


def _patch_connect(ws: Any):
    async def _connect(url: str, *args: Any, **kwargs: Any) -> Any:
        return ws

    return patch("pyrxd.network.electrumx.websockets.connect", new=_connect)


class _FakeWs(_FakeConnection):
    def __init__(self, der: bytes | None) -> None:
        super().__init__(_FakeSsl(der))
        self.closed = False

    async def close(self) -> None:
        self.closed = True


class TestElectrumXClientPinning:
    def test_pinning_is_off_by_default(self) -> None:
        """No pins configured -> the peer certificate is never even consulted."""
        client = ElectrumXClient(["wss://a.example/"])
        assert client._spki_pins == ()

    def test_malformed_pin_fails_at_construction_not_at_connect_time(self) -> None:
        with pytest.raises(ValidationError):
            ElectrumXClient(["wss://a.example/"], spki_pins=["nope"])

    @pytest.mark.asyncio
    async def test_matching_pin_connects(self) -> None:
        der, pin = _self_signed()
        ws = _FakeWs(der)
        client = ElectrumXClient(["wss://a.example/"], spki_pins=[pin], timeout=1.0)
        with _patch_connect(ws):
            got = await client._connect_first(["wss://a.example/"], 1.0)
        assert got is ws
        assert not ws.closed

    @pytest.mark.asyncio
    async def test_mismatched_pin_refuses_and_closes_the_socket(self) -> None:
        der, _ = _self_signed()
        _, other = _self_signed()
        ws = _FakeWs(der)
        client = ElectrumXClient(["wss://a.example/"], spki_pins=[other], timeout=1.0)
        with _patch_connect(ws), pytest.raises(TlsPinMismatchError):
            await client._connect_first(["wss://a.example/"], 1.0)
        # The socket that failed the pin must not be left open.
        assert ws.closed

    @pytest.mark.asyncio
    async def test_pin_failure_is_not_reported_as_a_generic_connect_failure(self) -> None:
        """An opt-in security control that fails must not look like a flaky network."""
        der, _ = _self_signed()
        _, other = _self_signed()
        client = ElectrumXClient(["wss://a.example/"], spki_pins=[other], timeout=1.0)
        with _patch_connect(_FakeWs(der)), pytest.raises(TlsPinMismatchError) as exc:
            await client._connect_first(["wss://a.example/"], 1.0)
        assert "Failed to connect" not in str(exc.value)
