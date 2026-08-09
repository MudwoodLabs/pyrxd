"""Tests for pyrxd.security.errors."""

from __future__ import annotations

import pytest

from pyrxd.security.errors import (
    ConfirmationTimeoutError,
    ContractExhaustedError,
    CovenantError,
    DmintError,
    InsufficientConfirmationsError,
    InsufficientFundsError,
    InvalidFundingUtxoError,
    KeyMaterialError,
    MaxAttemptsError,
    NetworkError,
    PolicyRejection,
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


class TestInsufficientConfirmationsError:
    """Tests for the typed retry-eligible subclass introduced post-cbd5fc0."""

    def test_is_subclass_of_network_error(self) -> None:
        # Existing handlers catching NetworkError still catch this.
        assert issubclass(InsufficientConfirmationsError, NetworkError)
        assert issubclass(InsufficientConfirmationsError, RxdSdkError)

    def test_message_format_and_attrs(self) -> None:
        exc = InsufficientConfirmationsError(have=2, required=6)
        assert exc.have == 2
        assert exc.required == 6
        # Message preserves the substring older callers may still match on.
        assert "confirmations, required" in str(exc)
        assert "2" in str(exc) and "6" in str(exc)

    def test_catchable_as_network_error(self) -> None:
        with pytest.raises(NetworkError):
            raise InsufficientConfirmationsError(have=0, required=1)

    def test_catchable_as_specific_class(self) -> None:
        # The point of the class: a retry guard can discriminate this from generic
        # NetworkError without substring-matching the message.
        with pytest.raises(InsufficientConfirmationsError) as ei:
            raise InsufficientConfirmationsError(have=0, required=1)
        assert ei.value.have == 0
        assert ei.value.required == 1


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


class TestInsufficientFundsError:
    """The typed pre-flight funding error added for the Glyph reveal-fee guard (C-1)."""

    def test_subclasses_validation_error(self) -> None:
        # ~16 sites already raise a bare ValidationError("Insufficient funds…"); every
        # existing `except ValidationError` handler must keep catching this one.
        assert issubclass(InsufficientFundsError, ValidationError)
        assert issubclass(InsufficientFundsError, RxdSdkError)
        with pytest.raises(ValidationError):
            raise InsufficientFundsError("short")

    def test_is_not_the_transaction_builder_insufficient_funds(self) -> None:
        # transaction.InsufficientFunds is a bare ValueError outside the SDK family.
        # Neither catches the other — that separation is deliberate, so assert it.
        from pyrxd.transaction.transaction import InsufficientFunds

        assert not issubclass(InsufficientFundsError, InsufficientFunds)
        assert not issubclass(InsufficientFunds, InsufficientFundsError)
        assert not issubclass(InsufficientFunds, RxdSdkError)

    def test_carries_shortfall(self) -> None:
        err = InsufficientFundsError("short", available=100, required=175)
        assert err.available == 100
        assert err.required == 175
        assert err.shortfall == 75

    def test_shortfall_is_none_when_amounts_unknown(self) -> None:
        assert InsufficientFundsError("short").shortfall is None
        assert InsufficientFundsError("short", available=1).shortfall is None
        assert InsufficientFundsError("short", required=1).shortfall is None


class TestConfirmationTimeoutError:
    """A confirmation timeout is 'shallow, retry', not 'transport is broken'."""

    def test_subclasses_insufficient_confirmations_not_bare_network_error(self) -> None:
        assert issubclass(ConfirmationTimeoutError, InsufficientConfirmationsError)
        assert issubclass(ConfirmationTimeoutError, NetworkError)

    def test_message_names_the_txid_and_the_wait(self) -> None:
        err = ConfirmationTimeoutError(txid="ab" * 32, have=0, required=1, waited_s=1800.0)
        text = str(err)
        assert "0 confirmations, required 1" in text
        assert "ab" * 32 in text  # public chain data — the only actionable detail
        assert "1800s" in text
        assert err.txid == "ab" * 32
        assert err.waited_s == 1800.0
        assert err.reason == "timeout"

    def test_reason_is_carried(self) -> None:
        err = ConfirmationTimeoutError(txid="cd" * 32, have=2, required=6, waited_s=5.0, reason="max_iterations=3")
        assert err.reason == "max_iterations=3"
        assert "max_iterations=3" in str(err)
        assert err.have == 2 and err.required == 6

    def test_insufficient_confirmations_detail_is_optional(self) -> None:
        # The unadorned message the 8 existing call sites in network/bitcoin.py produce
        # must not change.
        assert str(InsufficientConfirmationsError(have=1, required=6)) == "tx has 1 confirmations, required 6"
        assert "(why)" in str(InsufficientConfirmationsError(have=1, required=6, detail="why"))


class TestPolicyRejectionParentage:
    """PolicyRejection is now actually raised (from network/electrumx), so its
    parentage has to work for every handler that already wraps a broadcast."""

    def test_catchable_as_both_covenant_error_and_network_error(self) -> None:
        assert issubclass(PolicyRejection, CovenantError)
        assert issubclass(PolicyRejection, NetworkError)
        with pytest.raises(CovenantError):
            raise PolicyRejection("rejected")
        with pytest.raises(NetworkError):
            raise PolicyRejection("rejected")

    def test_carries_code_and_reason(self) -> None:
        err = PolicyRejection("node rejected the transaction (code 1): dust", code=1, reason="dust")
        assert err.code == 1
        assert err.reason == "dust"

    def test_defaults_have_no_code_or_reason(self) -> None:
        err = PolicyRejection("rejected")
        assert err.code is None
        assert err.reason is None
