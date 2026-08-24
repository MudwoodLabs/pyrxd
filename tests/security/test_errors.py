"""Tests for pyrxd.security.errors."""

from __future__ import annotations

import copy
import inspect
import pickle

import pytest

from pyrxd.security import errors
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
    TlsPinMismatchError,
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


class TestTlsPinMismatchParentage:
    """Raised by the opt-in TLS SPKI pin check (pyrxd.network.tls_pin)."""

    def test_catchable_as_a_network_error(self) -> None:
        # Existing `except NetworkError` handlers around every network call must
        # keep catching it; a pinning failure is still a failure to reach a server.
        assert issubclass(TlsPinMismatchError, NetworkError)
        with pytest.raises(NetworkError):
            raise TlsPinMismatchError("pin mismatch")

    def test_is_distinct_from_a_plain_transport_fault(self) -> None:
        # ...but distinguishable, because the operator response is different:
        # "the operator rotated their key" vs "the socket dropped".
        with pytest.raises(TlsPinMismatchError):
            raise TlsPinMismatchError("pin mismatch")
        assert not issubclass(NetworkError, TlsPinMismatchError)


# ---------------------------------------------------------------------------
# Pickle / copy round trips
# ---------------------------------------------------------------------------
#
# ``BaseException.__reduce__`` replays ``self.args`` POSITIONALLY through the
# constructor. Several classes here take keyword-only arguments and *derive* args
# from them, so the replay raised
# ``TypeError: __init__() takes 1 positional argument but 2 were given`` — breaking
# ``pickle.loads``, ``copy.copy``, and the re-raise of an SDK error across a
# ``ProcessPoolExecutor`` boundary (where the real failure is replaced by an opaque
# unpickling TypeError). ``RxdSdkError.__reduce__`` fixes it for the whole family.

# One sample value per constructor parameter name used anywhere in the module. The
# round-trip test below builds EVERY exported exception from this table, so adding a
# class with a new parameter fails the test until the table is extended — which is the
# point: the next keyword-only exception cannot silently ship unpicklable.
_SAMPLE_ARGS: dict[str, object] = {
    "message": "boom",
    "available": 3,
    "required": 6,
    "have": 1,
    "detail": "gave up early",
    "txid": "ab" * 32,
    "waited_s": 12.5,
    "reason": "max_iterations=3",
    "code": -26,
    "attempts": 9,
    "elapsed_s": 1.5,
    "tx_hash": "0x" + "ab" * 32,
}


def _all_sdk_exception_classes() -> list[type[RxdSdkError]]:
    """Every exception class this module exports, discovered — not hand-listed."""
    found = [getattr(errors, name) for name in errors.__all__]
    return sorted(
        (obj for obj in found if isinstance(obj, type) and issubclass(obj, RxdSdkError)),
        key=lambda c: c.__name__,
    )


def _construct(exc_cls: type[RxdSdkError]) -> RxdSdkError:
    """Instantiate *exc_cls* with a value for every parameter its ``__init__`` declares."""
    args: list[object] = []
    kwargs: dict[str, object] = {}
    params = list(inspect.signature(exc_cls.__init__).parameters.values())[1:]  # drop self
    for param in params:
        if param.kind is inspect.Parameter.VAR_POSITIONAL:
            args.append(_SAMPLE_ARGS["message"])  # the *args message
            continue
        if param.kind is inspect.Parameter.VAR_KEYWORD:
            continue
        assert param.name in _SAMPLE_ARGS, (
            f"{exc_cls.__name__}.__init__ takes an unknown parameter {param.name!r}; "
            "add a sample value to _SAMPLE_ARGS so the pickle round trip covers it"
        )
        value = _SAMPLE_ARGS[param.name]
        if param.kind is inspect.Parameter.KEYWORD_ONLY:
            kwargs[param.name] = value
        else:
            args.append(value)
    return exc_cls(*args, **kwargs)  # type: ignore[arg-type]


class TestExceptionRoundTrips:
    """Every SDK exception must survive pickle and copy — including keyword-only ones."""

    @pytest.mark.parametrize("exc_cls", _all_sdk_exception_classes(), ids=lambda c: c.__name__)
    def test_pickle_round_trip_preserves_message_and_attributes(self, exc_cls: type[RxdSdkError]) -> None:
        original = _construct(exc_cls)
        restored = pickle.loads(pickle.dumps(original))
        assert type(restored) is exc_cls
        assert restored.args == original.args
        assert str(restored) == str(original)
        assert vars(restored) == vars(original)

    @pytest.mark.parametrize("exc_cls", _all_sdk_exception_classes(), ids=lambda c: c.__name__)
    def test_copy_round_trip(self, exc_cls: type[RxdSdkError]) -> None:
        # copy.copy goes through the same __reduce_ex__ path as pickle.
        original = _construct(exc_cls)
        assert str(copy.copy(original)) == str(original)
        assert vars(copy.deepcopy(original)) == vars(original)

    def test_every_exported_exception_is_covered(self) -> None:
        # Guards the discovery itself: if __all__ stops exporting the exception classes
        # the parametrized tests above would silently shrink to nothing.
        names = {c.__name__ for c in _all_sdk_exception_classes()}
        assert {"ConfirmationTimeoutError", "InsufficientConfirmationsError", "PolicyRejection"} <= names

    def test_keyword_only_classes_were_the_regression(self) -> None:
        # The exact repro: both take keyword-only args and derive `args` from them, so
        # the default BaseException.__reduce__ replayed a message string positionally.
        err = ConfirmationTimeoutError(txid="ab" * 32, have=0, required=1, waited_s=1.0)
        restored = pickle.loads(pickle.dumps(err))
        assert restored.txid == err.txid
        assert (restored.have, restored.required, restored.waited_s) == (0, 1, 1.0)
        base = InsufficientConfirmationsError(have=0, required=2, detail="why")
        assert str(pickle.loads(pickle.dumps(base))) == str(base)

    def test_round_trip_does_not_re_redact(self) -> None:
        # Rebuilding restores args verbatim rather than replaying them through
        # __init__, so a redacted arg cannot be redacted a second time.
        err = KeyMaterialError("cafebabe" * 8)
        assert str(err) == "<redacted>"
        assert str(pickle.loads(pickle.dumps(err))) == "<redacted>"

    def test_raising_a_restored_exception_still_works(self) -> None:
        restored = pickle.loads(pickle.dumps(NetworkError("down")))
        with pytest.raises(NetworkError, match="down"):
            raise restored
