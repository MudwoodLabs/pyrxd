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
from pathlib import Path
from typing import Any, ClassVar

__all__ = [
    "Base58Error",
    "ClaimNotConfirmed",
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
    "PreRevealAbort",
    "PreRevealExpired",
    "RxdSdkError",
    "SpvVerificationError",
    "TlsPinMismatchError",
    "UnsupportedScriptError",
    "ValidationError",
    "redact",
]

_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_BASE58_RE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]+$")


#: Every word of every BIP-39 wordlist the SDK ships, casefolded. Populated on
#: first use by :func:`_bip39_vocabulary`; ``None`` until then.
_BIP39_VOCABULARY: frozenset[str] | None = None


#: Where :mod:`pyrxd.hd.bip39` keeps its wordlists. Reached as *data*, deliberately
#: not by importing that module: this package is the SDK's dependency leaf, and
#: ``pyrxd.hd.bip39`` pulls in ``pyrxd.utils``, ``pyrxd.constants`` and from there most
#: of the tree. That is not only an architectural smell — ``task ci`` type-checks
#: ``src/pyrxd/security/`` and mypy follows function-local imports, so the import turned
#: a 5-file check into a 36-file one and reported 266 pre-existing errors from modules
#: this package has nothing to do with.
#:
#: Globbing beats naming the files: ``WordList.files`` hardcodes ``en``/``zh-cn``, so a
#: newly-shipped wordlist would be covered here automatically but not there.
#: ``tests/security/test_key_material_never_echoed.py`` pins the two together.
_WORDLIST_DIR = Path(__file__).resolve().parent.parent / "hd" / "wordlist"


def _bip39_vocabulary() -> frozenset[str]:
    """Return the shipped BIP-39 words, casefolded, or an empty set if unavailable.

    Two properties this must hold, because it runs inside exception construction:

    * **It never raises.** ``redact`` is called from ``RxdSdkError.__init__``; an
      exception raised while building an exception replaces a real error with an
      unrelated one. Any failure degrades to the shape heuristic in
      :func:`_looks_like_mnemonic`.
    * **Failure is not cached.** Only a non-empty result is memoised, so a transient
      read failure cannot silently disable this branch for the life of the process.
    """
    global _BIP39_VOCABULARY
    if _BIP39_VOCABULARY is not None:
        return _BIP39_VOCABULARY
    words: set[str] = set()
    try:
        for path in sorted(_WORDLIST_DIR.glob("*.txt")):
            words.update(path.read_text(encoding="utf-8").split())
    except Exception:
        # Deliberately broad, and it RETURNS rather than swallowing: see "never raises"
        # above. Any failure degrades this branch, it does not break the exception being
        # constructed. (No `nosec` needed — bandit's B110 is about a bare `pass`.)
        return frozenset()
    vocabulary = frozenset(word.casefold() for word in words)
    if vocabulary:
        _BIP39_VOCABULARY = vocabulary
    return vocabulary


def _looks_like_mnemonic(value: str) -> bool:
    """Return True if ``value`` looks like a BIP-39 seed phrase.

    Two branches, because neither alone is sufficient:

    1. **Shape** — >=8 space-separated alphabetic tokens carrying no uppercase.
       This is the BIP-39 lowercase convention, and it holds for wordlists this
       SDK does not ship (fr/es/it/ja/ko/cs/pt) as well as the two it does.
       It used to additionally require ``t.isascii()``, which silently exempted
       every non-Latin wordlist — ``hd/wordlist/chinese_simplified.txt`` is a
       first-class ``lang=`` option, and a Chinese mnemonic passed through
       completely unredacted. ``str.islower()`` is False for CJK (no case at all),
       so the test is "contains no uppercase" rather than "is lowercase".

    2. **Vocabulary, case-insensitively** — all tokens are real BIP-39 words.
       Branch 1 assumed a mnemonic is *written* in the case the spec stores it in.
       Operators do not: every stamped-tile steel backup product (Cryptosteel,
       Billfodl, …) is UPPERCASE-only, and phone keyboards and spreadsheets
       autocapitalise the first word. Those phrases sailed through branch 1 and
       were interpolated verbatim. The disclosure is total, not partial —
       wordlists are lowercase, so lowercasing a leaked phrase reproduces the
       mnemonic exactly.

    Branch 2 is a vocabulary test rather than a second shape test on purpose:
    simply dropping branch 1's case condition would redact every capitalised
    sentence of eight or more words, and ``redact`` runs over the args of EVERY
    exception this SDK raises. Requiring real BIP-39 words is a far narrower net.

    **What this deliberately does NOT claim.** An earlier version of this note said
    the vocabulary test "cannot match a sentence". It can, and both branches
    over-match by design — measured 2026-08-12 against the shipped 4096-word
    vocabulary (en + zh-cn):

    * Branch 1 matches any run of >= 8 lowercase alphabetic tokens, so
      ``"could not connect to the remote peer at this time"`` IS redacted.
    * Branch 2 matches a sentence built only from BIP-39 words, and English ones
      exist: ``"Client Must Supply Valid Input Before Program Can Process Order"``
      is ten words, every one on the list, and IS redacted.

    That direction of error is the intended one and is not worth narrowing. The cost
    of a false positive is one exception message reading ``<redacted>``; the cost of a
    false negative is a seed phrase in a log. A caller who needs prose to survive
    should not be passing it as a whole exception arg alongside secrets.

    **The residual gap, stated rather than left to be discovered.** An UPPERCASE or
    Title-Case phrase from a wordlist this SDK does not SHIP (fr/es/it/ja/ko/cs/pt) is
    matched by neither branch — branch 1 sees the case, branch 2 has never read those
    words — and passes through unredacted. Verified: a 12-word uppercase French
    mnemonic is not redacted. Closing it means shipping those wordlists, which is a
    packaging decision rather than a fix here; the two shipped languages and every
    lowercase phrase in any language are covered.
    """
    tokens = value.split()
    if len(tokens) < 8 or not all(t.isalpha() for t in tokens):
        return False
    if all(not t.isupper() and t == t.lower() for t in tokens):
        return True
    vocabulary = _bip39_vocabulary()
    return bool(vocabulary) and all(t.casefold() in vocabulary for t in tokens)


def _looks_like_key_material(value: str) -> bool:
    """Return True if ``value`` looks like it could be key material.

    Checks for:
      * all hex characters (private keys, hashes, ciphertext)
      * all base58 characters (WIF, addresses, mnemonic seeds in base58)
      * a BIP-39 seed phrase, in any script and any case (see
        :func:`_looks_like_mnemonic`)
    """
    if _HEX_RE.match(value):
        return True
    if _BASE58_RE.match(value):
        return True
    return _looks_like_mnemonic(value)


def redact(value: Any) -> Any:
    """Return a redacted representation of ``value`` if it looks sensitive.

    * ``str`` longer than 8 chars that looks like key material -> ``"<redacted>"``
    * ``bytes`` longer than 8 bytes -> ``"<redacted:Nb>"``
    * other types -> returned unchanged

    .. warning::
       This matches the value as a **whole**. ``redact(wif)`` redacts; ``redact(f"bad wif
       {wif}")`` does **not** — the interpolated string is neither all-hex nor all-base58,
       so the heuristic declines and the secret passes through verbatim. So the idiom at
       the top of this module, ``raise KeyMaterialError(redact(bad_wif))``, is the *only*
       defended shape, and ``raise ValidationError(f"bad wif {wif}")`` is undefended by
       construction.

       Making this per-token instead is not the fix: nearly every English word longer than
       8 characters is also a valid base58 string (``"transaction"`` is), so per-token
       redaction would replace ordinary prose with ``<redacted>``, and it would also
       swallow the public txids that errors like :class:`ConfirmationTimeoutError`
       deliberately keep verbatim because they are the only thing that makes the failure
       actionable. The defence for the embedded shape is therefore the call-site
       discipline this module documents, enforced by
       ``tests/security/test_key_material_never_echoed.py`` — not a wider heuristic here.
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


class Base58Error(ValidationError, ValueError):
    """A base58 / base58check string could not be decoded.

    **Never carries the offending string, or any part of it.** The decoder cannot
    know whether the thing it was handed is an address (public) or a WIF / xprv
    (spending authority), so it must assume the worst. Echoing a WIF with one
    mistyped character — a line wrap, a stray space, an ``O``/``I``/``l`` typo —
    publishes 51 of its 52 characters into terminal scrollback and any pasted bug
    report, and a few thousand checksum-verifiable candidates recover the key.
    Length, position, and the decoded prefix are all withheld for the same reason.

    Parentage is deliberately dual:

    * :class:`ValidationError` — this is a trust-boundary rejection like every
      other, and ``except RxdSdkError`` handlers must catch it.
    * :class:`ValueError` — :mod:`pyrxd.base58` and :func:`pyrxd.utils.decode_wif`
      raised bare ``ValueError`` for the SDK's whole history, and callers across
      the CLI, ``hd``, and ``gravity`` still catch that. Widening rather than
      swapping keeps every one of them working.
    """


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


class ClaimNotConfirmed(RxdSdkError):
    """A claim was broadcast but could NOT be confirmed to have succeeded on chain.

    The exact inverse of :class:`PreRevealAbort`: this one is raised only AFTER the transaction
    left the process, so the preimage must be assumed **public**. It covers three outcomes that a
    bare "submitted" return could not distinguish from success:

    * the tx mined and REVERTED (``status != 1``) — expired, underfunded, already settled, frozen,
      out of gas. A reverted claim is still mined WITH ``p`` in its calldata, so the counterparty
      can take the other leg while this side received nothing.
    * the tx mined but emitted no ``Claimed(p)`` log from this swap's own contract.
    * no receipt arrived before the deadline — the outcome is simply unknown.

    ``tx_hash`` is carried as an attribute because it is the only handle an operator has on a claim
    that may be public but did not pay: without it there is nothing to investigate. The swap must
    NOT be advanced to a revealed/completed state on this exception.
    """

    def __init__(self, message: str, *, tx_hash: str | None = None) -> None:
        super().__init__(message)
        self.tx_hash = tx_hash


class PreRevealAbort(RxdSdkError):
    """A claim was abandoned BEFORE the preimage could leave this process.

    Raised only by the checks that run strictly before a claim is submitted — chain-id assertion,
    fee/nonce reads, the ERC-20 freeze gate and funded-balance re-read. It is a promise about
    *where* the failure happened, not about why: nothing was broadcast, no ``eth_call`` carried the
    calldata to a provider, and the preimage is therefore **still secret**.

    That distinction is load-bearing for the caller. ``SwapCoordinator.maker_claims_btc`` zeroizes
    the preimage once a claim has been attempted, because from that point ``p`` may be public and
    keeping a copy in memory buys nothing. Doing the same on a pre-broadcast failure would destroy
    the only copy of a secret that is still safe, stranding a swap that a retry would have
    completed — a transient RPC blip turning into a dead swap (see #479).

    Any new check added before the submit MUST raise this rather than a bare ``NetworkError``, or
    the caller will treat a recoverable failure as an irreversible one.

    ``retryable`` says whether trying again can succeed. It is True here because every original
    member was a transient read — an RPC blip, a stale balance — and the docstring above promises
    "a swap that a retry would have completed". A later check broke that promise: refusing to
    build a claim too close to the HTLC timeout is a condition that strictly WORSENS with time, so
    a driver honouring the contract would spin until the deadline instead of pivoting to refund.
    That case is :class:`PreRevealExpired` (#485). Check ``retryable`` — or catch the subclass
    first — before retrying.
    """

    #: Can trying again succeed? See :class:`PreRevealExpired` for the case where it cannot.
    retryable: ClassVar[bool] = True


class PreRevealExpired(PreRevealAbort):
    """A pre-reveal abort that a retry can NEVER resolve, because time is the thing that failed.

    Subclass of :class:`PreRevealAbort` so the preimage handling is unchanged — nothing was
    broadcast, ``p`` is still secret, and the caller must not zeroize it. What differs is the
    caller's NEXT move: retrying walks further past the deadline, so the driver must stop and take
    the refund path.

    Raised when a claim is refused for being too close to the HTLC timeout. A claim that mines
    late still publishes the preimage in its calldata while paying nothing, which hands the
    counterparty both legs — so refusing is right, and refusing again a second later is still
    right, forever.
    """

    retryable: ClassVar[bool] = False


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


class TlsPinMismatchError(NetworkError):
    """Raised when a TLS SPKI pin check fails, or cannot be performed at all.

    A subclass of :class:`NetworkError` so the ~30 existing ``except NetworkError``
    handlers keep working, but a distinct class because the operator response is
    completely different from a dropped socket: either the server operator rotated
    their key (add the new pin) or you are not talking to the server you pinned
    (stop). Pinning is opt-in — see :mod:`pyrxd.network.tls_pin` — so this can only
    fire for someone who deliberately asked for the check.

    "Cannot be performed" (no peer certificate available) raises this too, on
    purpose: a check that silently degrades to no check is worse than no check,
    because it is believed.
    """


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
