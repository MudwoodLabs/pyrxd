"""Tests for pyrxd.security.errors."""

from __future__ import annotations

import pytest

from pyrxd.security.errors import (
    ContractExhaustedError,
    CovenantError,
    DmintError,
    InvalidFundingUtxoError,
    KeyMaterialError,
    MaxAttemptsError,
    NetworkError,
    PoolTooSmallError,
    RxdSdkError,
    SpvVerificationError,
    ValidationError,
    redact,
)


class TestExceptionHierarchy:
    def test_all_inherit_from_rxd_sdk_error(self) -> None:
        for exc_cls in (
            KeyMaterialError,
            ValidationError,
            SpvVerificationError,
            NetworkError,
            CovenantError,
        ):
            assert issubclass(exc_cls, RxdSdkError)

    def test_rxd_sdk_error_inherits_from_exception(self) -> None:
        assert issubclass(RxdSdkError, Exception)

    def test_isinstance_checks(self) -> None:
        err = KeyMaterialError("short msg")
        assert isinstance(err, KeyMaterialError)
        assert isinstance(err, RxdSdkError)
        assert isinstance(err, Exception)

    def test_distinct_classes(self) -> None:
        # KeyMaterialError and ValidationError must be distinguishable.
        assert not issubclass(KeyMaterialError, ValidationError)
        assert not issubclass(ValidationError, KeyMaterialError)


class TestRedact:
    def test_short_string_passes_through(self) -> None:
        # 8 or fewer chars: return as-is.
        assert redact("abc") == "abc"
        assert redact("12345678") == "12345678"

    def test_long_hex_string_is_redacted(self) -> None:
        long_hex = "a" * 64
        assert redact(long_hex) == "<redacted>"

    def test_long_base58_string_is_redacted(self) -> None:
        # WIF-style: all base58 chars, long.
        wif = "L1aW4aubDFB7yfras2S1mN3bqg9nwySY8nkoLmJebSLD5BWv3ENZ"
        assert redact(wif) == "<redacted>"

    def test_mnemonic_string_is_redacted(self) -> None:
        mnemonic = "abandon ability able about above absent absorb abstract"
        assert redact(mnemonic) == "<redacted>"

    def test_short_hex_not_redacted(self) -> None:
        # <= 8 chars: not redacted even if hex.
        assert redact("abcdef12") == "abcdef12"

    def test_long_non_keyish_string_not_redacted(self) -> None:
        # Long but contains spaces / punctuation that break hex/base58.
        msg = "this is a normal error message, not a key!"
        assert redact(msg) == msg

    def test_short_bytes_passes_through(self) -> None:
        assert redact(b"abc") == b"abc"
        assert redact(b"12345678") == b"12345678"

    def test_long_bytes_is_redacted(self) -> None:
        data = b"\x00" * 32
        assert redact(data) == "<redacted:32b>"

    def test_non_string_non_bytes_passes_through(self) -> None:
        assert redact(42) == 42
        assert redact(None) is None
        assert redact(["a", "b"]) == ["a", "b"]


class TestRxdSdkErrorRedaction:
    def test_long_hex_arg_is_redacted_in_exception(self) -> None:
        secret_hex = "deadbeef" * 8  # 64 hex chars
        err = KeyMaterialError(secret_hex)
        # The original secret must NOT appear anywhere in args/repr/str.
        assert secret_hex not in str(err)
        assert secret_hex not in repr(err)
        assert secret_hex not in err.args

    def test_long_bytes_arg_is_redacted_in_exception(self) -> None:
        secret = b"\xde\xad\xbe\xef" * 8
        err = ValidationError(secret)
        assert secret not in err.args
        assert "redacted" in str(err)

    def test_short_string_arg_preserved(self) -> None:
        err = KeyMaterialError("bad input")
        # Short, non-hex: preserved so messages stay useful.
        assert "bad input" in str(err)

    def test_mnemonic_redacted_in_exception(self) -> None:
        mnemonic = "abandon ability able about above absent absorb abstract absurd"
        err = KeyMaterialError(mnemonic)
        assert mnemonic not in err.args

    def test_raise_and_catch_roundtrip(self) -> None:
        with pytest.raises(KeyMaterialError):
            raise KeyMaterialError("bad thing")

    def test_catch_via_base_class(self) -> None:
        with pytest.raises(RxdSdkError):
            raise NetworkError("connection refused")

    def test_all_subclasses_apply_redaction(self) -> None:
        # Confirm every subclass applies redaction, not just KeyMaterialError.
        sensitive = "a" * 64
        for exc_cls in (
            KeyMaterialError,
            ValidationError,
            SpvVerificationError,
            NetworkError,
            CovenantError,
        ):
            err = exc_cls(sensitive)
            assert sensitive not in err.args, f"{exc_cls.__name__} leaked args"


class TestDmintErrors:
    """The DmintError hierarchy added for V1 mint support (M1)."""

    def test_dmint_error_inherits_from_rxd_sdk_error(self) -> None:
        assert issubclass(DmintError, RxdSdkError)

    def test_subclasses_inherit_from_dmint_error(self) -> None:
        for exc_cls in (
            ContractExhaustedError,
            PoolTooSmallError,
            InvalidFundingUtxoError,
            MaxAttemptsError,
        ):
            assert issubclass(exc_cls, DmintError)
            assert issubclass(exc_cls, RxdSdkError)

    def test_max_attempts_error_carries_telemetry(self) -> None:
        err = MaxAttemptsError("exhausted", attempts=42, elapsed_s=1.5)
        assert err.attempts == 42
        assert err.elapsed_s == 1.5

    def test_max_attempts_error_default_attributes(self) -> None:
        # Default values let callers raise without telemetry args.
        err = MaxAttemptsError("exhausted")
        assert err.attempts == 0
        assert err.elapsed_s == 0.0

    def test_dmint_errors_can_be_caught_via_dmint_error(self) -> None:
        for exc_cls in (
            ContractExhaustedError,
            PoolTooSmallError,
            InvalidFundingUtxoError,
            MaxAttemptsError,
        ):
            with pytest.raises(DmintError):
                raise exc_cls("test")
