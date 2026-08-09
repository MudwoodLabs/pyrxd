"""Exception hierarchy for pyrxd.

Design rules
------------
1. No exception class in this SDK may embed raw private-key bytes, mnemonics,
   or WIF strings in its ``args``. The ``redact`` helper enforces this by
   replacing any ``str``/``bytes`` value longer than 8 characters that
   "looks like" key material with the literal ``"<redacted>"``.
2. All SDK-defined exceptions inherit from :class:`RxdSdkError`, so callers can
   catch the whole family with a single handler.
3. Call sites SHOULD construct these exceptions via ``redact`` on any
   caller-supplied value, e.g. ``raise KeyMaterialError(redact(bad_wif))``.

Redaction heuristic
-------------------
The heuristic is intentionally aggressive: anything longer than 8 chars/bytes
that is hex-only, base58-only, or high-entropy bytes is treated as potential
key material. False positives (a long error code or filename) are acceptable
— a slightly less informative error message is a much better failure mode
than a private key in a stack trace.
"""

from __future__ import annotations

import re
from typing import Any

__all__ = [
    "ConfirmationTimeoutError",
    "ContractExhaustedError",
    "CovenantError",
    "DmintError",
    "FeePoolExhaustedError",
    "InsufficientConfirmationsError",
    "InsufficientFundsError",
    "InvalidFundingUtxoError",
    "KeyMaterialError",
    "MaxAttemptsError",
    "NetworkError",
    "PolicyRejection",
    "PoolTooSmallError",
    "RxdSdkError",
    "SpvVerificationError",
    "UnsupportedScriptError",
    "ValidationError",
    "redact",
]

_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_BASE58_RE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]+$")


def _looks_like_key_material(value: str) -> bool:
    """Return True if ``value`` looks like it could be key material.

    Checks for:
      * all hex characters (private keys, hashes, ciphertext)
      * all base58 characters (WIF, addresses, mnemonic seeds in base58)
      * bip39-style all-lowercase ASCII words joined by spaces (>=8 tokens)
    """
    if _HEX_RE.match(value):
        return True
    if _BASE58_RE.match(value):
        return True
    # BIP-39 mnemonic heuristic: >=8 space-separated ASCII lowercase tokens.
    tokens = value.split()
    return bool(len(tokens) >= 8 and all(t.isascii() and t.isalpha() and t.islower() for t in tokens))


def redact(value: Any) -> Any:
    """Return a redacted representation of ``value`` if it looks sensitive.

    * ``str`` longer than 8 chars that looks like key material -> ``"<redacted>"``
    * ``bytes`` longer than 8 bytes -> ``"<redacted:Nb>"``
    * other types -> returned unchanged
    """
    if isinstance(value, bytes):
        if len(value) > 8:
            return f"<redacted:{len(value)}b>"
        return value
    if isinstance(value, str):
        if len(value) > 8 and _looks_like_key_material(value):
            return "<redacted>"
        return value
    return value


def _rebuild_error(cls: type[BaseException], args: tuple[Any, ...]) -> BaseException:
    """Reconstruct *cls* from its ``args`` without going through ``__init__``.

    The unpickle half of :meth:`RxdSdkError.__reduce__`. Deliberately bypasses the
    subclass constructor: several of the classes below take **keyword-only**
    arguments and derive ``args`` from them, so replaying ``args`` positionally
    (what the default ``BaseException.__reduce__`` does) cannot work. Instance
    attributes are restored separately by pickle, from the state dict.
    """
    exc = cls.__new__(cls)
    BaseException.__init__(exc, *args)
    return exc


class RxdSdkError(Exception):
    """Base class for every exception raised by pyrxd.

    Applying ``redact`` to each positional arg on construction defends against
    accidental key-material leakage when callers pass user-supplied values
    straight into the exception.
    """

    def __init__(self, *args: Any) -> None:
        super().__init__(*(redact(a) for a in args))

    def __reduce__(self) -> tuple[Any, ...]:
        """Make the whole family picklable, including keyword-only subclasses.

        ``BaseException.__reduce__`` returns ``(type(self), self.args)`` and pickle
        then calls ``type(self)(*args)``. That is wrong for any subclass whose
        constructor is keyword-only and *derives* ``args`` from those keywords —
        :class:`InsufficientConfirmationsError` and :class:`ConfirmationTimeoutError`
        both build a single message string from ``have``/``required``/…, so the replay
        raised ``TypeError: __init__() takes 1 positional argument but 2 were given``.
        That breaks ``pickle``, ``copy.copy``, and — the one that bites in production —
        re-raising an SDK exception across a ``ProcessPoolExecutor`` boundary, where the
        real error is replaced by an opaque unpickling ``TypeError``.

        Rebuilding via :func:`_rebuild_error` skips ``__init__`` entirely and restores
        ``args`` verbatim (already redacted at construction — never re-redacted, so a
        round trip is idempotent). Instance attributes ride along in the state dict,
        which pickle applies to ``__dict__`` after the call. Defined on the base class
        so a *new* subclass with keyword-only arguments is correct by default.
        """
        return (_rebuild_error, (type(self), self.args), self.__dict__.copy())


class KeyMaterialError(RxdSdkError):
    """Raised for errors touching private keys, mnemonics, or WIFs.

    Constructors raising this error MUST NOT include the offending key
    material in the message — pass a static description only.
    """


class ValidationError(RxdSdkError):
    """Raised when input fails a trust-boundary validation check."""


class InsufficientFundsError(ValidationError):
    """A pre-flight value check found less funding than the operation provably needs.

    Deliberately a **subclass of** :class:`ValidationError`: the SDK already raises
    a bare ``ValidationError("Insufficient funds…")`` from ~16 sites in
    ``wallet.py``, ``hd/wallet.py``, ``agent/watch_only.py`` and
    ``btc_wallet/payment.py``, and every existing ``except ValidationError``
    handler must keep catching this. The subclass only *adds* the machine-readable
    ``available`` / ``required`` / ``shortfall`` triple so a caller can say how much
    more is needed instead of substring-matching a message.

    Not to be confused with :class:`pyrxd.transaction.transaction.InsufficientFunds`,
    which is a bare ``ValueError`` raised by the low-level transaction builder and is
    **not** part of the :class:`RxdSdkError` family. That one means "these inputs do
    not cover these outputs" at serialisation time; this one means "we checked before
    spending anything and the operation cannot succeed". The two are not
    interchangeable and neither catches the other; new library code should raise this
    one.

    Args:
        message: static description — must not embed key material.
        available: value the caller actually has, in the operation's own units.
        required: value the operation needs, same units.
    """

    def __init__(self, message: str, *, available: int | None = None, required: int | None = None) -> None:
        super().__init__(message)
        self.available = available
        self.required = required

    @property
    def shortfall(self) -> int | None:
        """``required - available`` when both are known, else ``None``."""
        if self.available is None or self.required is None:
            return None
        return self.required - self.available


class SpvVerificationError(RxdSdkError):
    """Raised when an SPV proof (Merkle path, header chain) fails to verify."""


class NetworkError(RxdSdkError):
    """Raised for transport / RPC / network failures."""


class InsufficientConfirmationsError(NetworkError):
    """A tx exists but has fewer confirmations than the caller required.

    Subclass of :class:`NetworkError` so existing handlers still catch it, but
    catchable as a distinct class for ``wait-for-conf`` retry loops that need to
    discriminate "tx is just shallow, retry later" from "real transport error,
    fail fast". The legacy substring match (``"confirmations, required" in
    str(exc)``) was fragile across reader implementations — this class is the
    typed replacement.

    Args:
        have: observed confirmation depth at read time (0 if unconfirmed).
        required: the caller-supplied ``min_confirmations`` threshold.
        detail: optional extra context appended in parentheses (e.g. why the
            wait gave up). Static description only — never key material.
    """

    def __init__(self, *, have: int, required: int, detail: str | None = None) -> None:
        message = f"tx has {have} confirmations, required {required}"
        if detail:
            message = f"{message} ({detail})"
        super().__init__(message)
        self.have = have
        self.required = required


class ConfirmationTimeoutError(InsufficientConfirmationsError):
    """A confirmation wait gave up before the tx reached the required depth.

    A subclass of :class:`InsufficientConfirmationsError` (and therefore of
    :class:`NetworkError`) — which is exactly the distinction that class exists to
    make: "the tx is just shallow, retry / check the explorer" is a fundamentally
    different operator response from "the transport is broken". A confirmation
    timeout is the former, so raising a bare :class:`NetworkError` would tell the
    caller the wrong thing.

    Carries ``txid`` and ``waited_s`` so a caller can render a resume hint. The txid
    is public chain data and is intentionally kept verbatim — it is the only thing
    that makes the failure actionable.

    Args:
        txid: the transaction that failed to reach ``required`` confirmations.
        have: the last observed depth (0 if the tx was never seen).
        required: the caller-supplied ``min_confirmations`` threshold.
        waited_s: elapsed seconds on the injected clock when the wait gave up.
        reason: why the wait stopped (``"timeout"``, ``"max_iterations"``, …).
    """

    def __init__(
        self,
        *,
        txid: str,
        have: int,
        required: int,
        waited_s: float,
        reason: str = "timeout",
    ) -> None:
        super().__init__(
            have=have,
            required=required,
            detail=f"{reason} after {waited_s:.0f}s waiting for {txid}",
        )
        self.txid = txid
        self.waited_s = waited_s
        self.reason = reason


class CovenantError(RxdSdkError):
    """Raised for covenant construction or verification failures."""


class PolicyRejection(CovenantError, NetworkError):
    """Raised when a node rejects a transaction on a consensus/policy rule
    (e.g. ``mandatory-script-verify-flag-failed``, dust, min-relay-fee, an
    ElectrumX ``code 1``).

    Surface this distinctly rather than letting a node rejection be reclassified as a
    plain :class:`NetworkError` — that masking hid a critical dMint covenant-rejection
    bug for weeks (see docs/solutions/logic-errors/dmint-v1-mint-scriptsig-divergence.md).
    The masking harm was that the node's *reason* was discarded, so a script failure
    was indistinguishable from a dropped socket.

    Parentage: it inherits from **both** :class:`CovenantError` (its original parent —
    keeps every ``except CovenantError`` handler working) and :class:`NetworkError`
    (so the ~30 ``except NetworkError`` handlers that already wrap broadcast calls do
    not silently stop catching rejections now that this class is actually raised).
    A node rejection is not covenant-specific — a dust or min-relay-fee rejection has
    nothing to do with covenants — so the covenant-only parentage it shipped with was
    too narrow. Widening it here is the compatible fix; re-rooting it under a
    dedicated ``NodeRejection`` base would be the cleaner shape but is a breaking
    change for existing handlers.

    Args:
        message: sanitized, caller-safe description. Node messages are
            attacker-influencable text — run them through :func:`redact` and strip
            control characters *before* constructing this.
        code: the RPC error code, when the server supplied one.
        reason: the sanitized server reason on its own, for programmatic matching.
    """

    def __init__(self, *args: Any, code: Any = None, reason: str | None = None) -> None:
        super().__init__(*args)
        self.code = code
        self.reason = reason


class FeePoolExhaustedError(RxdSdkError):
    """Raised by a capped fee source when it refuses to dispense another fee UTXO —
    the pre-funded pool is empty or the configured total-spend cap would be exceeded.

    Fail-closed: the caller (e.g. an autonomous covenant spend) must surface this and
    refuse/page rather than fall back to an uncapped wallet. This is the structural
    spend ceiling for autonomous RXD fee-paying (see
    ``pyrxd.gravity.capped_fee_source.CappedFeeWalletSource``).
    """


class UnsupportedScriptError(RxdSdkError):
    """Raised when the script engine encounters an opcode or script type it
    does not fully implement.

    Callers should treat this as a hard failure — silently returning "valid"
    for an unrecognised script is a security vulnerability.
    """


class DmintError(RxdSdkError):
    """Base class for dMint-specific errors (mint, deploy, mining)."""


class ContractExhaustedError(DmintError):
    """Raised when a dMint contract has reached its max_height and cannot be minted."""


class PoolTooSmallError(DmintError):
    """Raised when a dMint contract's pool cannot cover reward + fee + dust."""


class InvalidFundingUtxoError(DmintError):
    """Raised when a candidate funding UTXO is itself a token-bearing UTXO.

    Spending an FT or dMint UTXO as fee silently destroys the token. Callers
    assembling miner inputs must filter out token UTXOs and surface this
    error if no plain-RXD candidates remain.
    """


class MaxAttemptsError(DmintError):
    """Raised by ``mine_solution`` when ``max_attempts`` is reached without a solution.

    Carries ``attempts`` and ``elapsed_s`` attributes for telemetry; callers
    can either widen ``max_attempts`` or escalate to an external miner.
    """

    def __init__(self, *args: Any, attempts: int = 0, elapsed_s: float = 0.0) -> None:
        super().__init__(*args)
        self.attempts = attempts
        self.elapsed_s = elapsed_s
