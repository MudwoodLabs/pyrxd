"""No decoder in the base58 / keys / WIF path may echo what it failed to decode.

The bug this suite exists to make unreachable
---------------------------------------------
``pyrxd.base58.b58_decode`` raised ``ValueError(f"invalid base58 encoded {encoded}")``.
``pyrxd.keys.PrivateKey(wif)`` reaches it through ``decode_wif``, the ``swap recovery``
CLI reaches ``PrivateKey(wif)`` through ``_pkh_from_wif``, and ``cli/main.py``'s
error boundary prints ``cause: {exc}`` for anything that is not a
``NetworkError``/``OSError``. So a WIF with **one** character outside the base58
alphabet — a line wrap, a stray space, an ``O``/``I``/``l`` typo — printed 51 of
its 52 characters to stderr, into terminal scrollback and into any pasted bug
report. A few thousand checksum-verifiable candidates recover the key from that.

The fix is at the source, not the call site: the decoder cannot know whether the
string it was handed is an address (public) or a WIF/xprv (spending authority),
so it treats every input as secret.

Every key in this file is generated (``PrivateKey()`` / ``os.urandom``) and never
printed. Assertions are written to report only *whether* a leak occurred, never
the material itself.
"""

from __future__ import annotations

import ast
import hashlib
import hmac
import os
import re

import pytest

from pyrxd.base58 import b58_decode, base58check_decode
from pyrxd.glyph.encrypted_content import (
    KEY_FORMAT_WRAPPED,
    SCHEME_CHUNKED_AEAD_V1,
    CryptoMetadata,
    EncryptedContentStub,
    EncryptionMetadata,
)
from pyrxd.glyph.timelock import (
    TimelockParams,
    add_timelock_to_metadata,
    format_cek_hash,
    verify_cek_reveal,
)
from pyrxd.glyph.types import GlyphProtocol
from pyrxd.hd.bip32 import Xprv, master_xprv_from_seed
from pyrxd.hd.bip39 import mnemonic_from_entropy, seed_from_mnemonic, validate_mnemonic
from pyrxd.keys import PrivateKey
from pyrxd.security.errors import Base58Error, KeyMaterialError, RxdSdkError, ValidationError, redact
from pyrxd.utils import decode_address, decode_wif, from_base58

#: Shortest run of the secret we treat as a leak. A WIF is 51-52 chars and an
#: xprv 111, so any contiguous 8-character run is already a search-space cut.
_LEAK_WINDOW = 8


def _every_rendering(exc: BaseException) -> list[str]:
    """All operator-visible text for *exc*: its own message and repr, plus the
    whole ``__cause__`` / ``__context__`` chain — a traceback prints all of it."""
    out: list[str] = []
    seen: set[int] = set()
    node: BaseException | None = exc
    while node is not None and id(node) not in seen:
        seen.add(id(node))
        out.append(str(node))
        out.append(repr(node))
        out.append(repr(node.args))
        node = node.__cause__ or node.__context__
    return out


def _assert_no_leak(exc: BaseException, secret: str) -> None:
    """Fail if any ``_LEAK_WINDOW``-char run of *secret* is visible anywhere."""
    renderings = _every_rendering(exc)
    windows = [secret[i : i + _LEAK_WINDOW] for i in range(len(secret) - _LEAK_WINDOW + 1)]
    for index, window in enumerate(windows):
        for text in renderings:
            # Report position only. Printing the window would defeat the test.
            assert window not in text, (
                f"{type(exc).__name__} leaked a {_LEAK_WINDOW}-char run of the input "
                f"at offset {index} (of {len(secret)} chars)"
            )


def _corrupt(s: str, index: int) -> str:
    """Replace one character with ``0`` — not in the base58 alphabet, and the
    single likeliest transcription error for an ``O``."""
    return s[:index] + "0" + s[index + 1 :]


# ── the headline case: a mistyped WIF ─────────────────────────────────────────


@pytest.mark.parametrize("bad_index", [0, 1, 25, 30, 50])
def test_a_mistyped_wif_is_never_echoed_by_PrivateKey(bad_index: int) -> None:
    """THE regression test. Reproduced before the fix as 51/52 characters of a
    live key on stderr; must now be 0."""
    wif = PrivateKey().wif()
    with pytest.raises(ValueError) as exc:
        PrivateKey(_corrupt(wif, bad_index))
    _assert_no_leak(exc.value, wif)


def test_a_wif_with_a_bad_checksum_is_never_echoed() -> None:
    """The other arm: every character is in-alphabet, so decoding succeeds and
    the *checksum* fails. Neither the claimed checksum (bytes of the caller's
    own string) nor the computed one (hash256 over the decoded payload, which
    for a mistyped WIF IS the private key) may be reported."""
    wif = PrivateKey().wif()
    # Swap two in-alphabet characters: still decodable, checksum now wrong.
    mangled = wif[:-2] + ("ab" if wif[-2:] != "ab" else "cd")
    with pytest.raises(ValueError) as exc:
        PrivateKey(mangled)
    _assert_no_leak(exc.value, wif)
    _assert_no_leak(exc.value, mangled)


def test_a_wif_pasted_into_an_address_field_is_never_echoed() -> None:
    """``decode_address`` rejects a WIF on its regex — the branch that used to
    print ``invalid P2PKH address <the whole WIF>``. Confusing the two fields is
    an ordinary paste error, not an exotic one."""
    wif = PrivateKey().wif()
    with pytest.raises(ValueError) as exc:
        decode_address(wif)
    _assert_no_leak(exc.value, wif)


def test_a_mistyped_xprv_is_never_echoed() -> None:
    """The same sink reached through ``Xkey.__init__`` — an xprv is 111 base58
    characters of spending authority for an entire wallet tree."""
    seed = seed_from_mnemonic(mnemonic_from_entropy(os.urandom(16)))
    xprv = master_xprv_from_seed(seed).serialize()
    with pytest.raises(ValueError) as exc:
        Xprv(_corrupt(xprv, 60))
    _assert_no_leak(exc.value, xprv)


def test_decode_wif_never_reports_the_decoded_version_byte() -> None:
    """A checksum-valid WIF under an unrecognised version byte must not have any
    part of its *decoded* payload interpolated into the message either."""
    from pyrxd.base58 import base58check_encode

    payload = b"\x99" + os.urandom(32) + b"\x01"  # 0x99 is not a known WIF prefix
    wif = base58check_encode(payload)
    with pytest.raises(ValueError) as exc:
        decode_wif(wif)
    _assert_no_leak(exc.value, wif)
    _assert_no_leak(exc.value, payload.hex())


# ── the decoders themselves ───────────────────────────────────────────────────


def test_b58_decode_does_not_echo() -> None:
    secret = PrivateKey().wif()
    with pytest.raises(Base58Error) as exc:
        b58_decode(_corrupt(secret, 10))
    _assert_no_leak(exc.value, secret)


def test_base58check_decode_does_not_echo_on_checksum_failure() -> None:
    secret = PrivateKey().wif()
    with pytest.raises(Base58Error) as exc:
        base58check_decode(secret[:-1] + ("a" if secret[-1] != "a" else "b"))
    _assert_no_leak(exc.value, secret)


def test_the_legacy_from_base58_helper_does_not_echo() -> None:
    """``pyrxd.utils.from_base58`` is a second, independent base58 implementation
    with the identical ``f\"...'{str_}'\"`` pattern. Same rule applies."""
    secret = PrivateKey().wif()
    with pytest.raises(Base58Error) as exc:
        from_base58(_corrupt(secret, 15))
    _assert_no_leak(exc.value, secret)


# ── type contract ─────────────────────────────────────────────────────────────


def test_base58_error_is_both_a_ValueError_and_an_SDK_error() -> None:
    """Dual parentage is load-bearing: ``base58`` raised a bare ``ValueError`` for
    the SDK's whole history and callers across the CLI, ``hd`` and ``gravity``
    still catch that, while new code catches ``RxdSdkError``."""
    with pytest.raises(ValueError):
        b58_decode("l")
    with pytest.raises(RxdSdkError):
        b58_decode("l")


def test_no_cause_chain_is_left_to_resurface_the_input() -> None:
    """``raise ... from None``: the underlying ``ValueError`` from
    ``str.index`` must not be reachable as ``__cause__``."""
    secret = PrivateKey().wif()
    with pytest.raises(Base58Error) as exc:
        b58_decode(_corrupt(secret, 20))
    assert exc.value.__cause__ is None
    assert exc.value.__suppress_context__ is True


# ── the other direction: a secret handed BACK on a result object ──────────────
#
# Everything above is a secret ARRIVING as input, echoed by a decoder that could
# not know what it was handed. This section is the return path, and it has a sink
# the decoders do not: ``@dataclass`` writes a ``__repr__`` for you, over every
# field, and nobody reviews a method nobody wrote. Two carriers in this tree
# already opt out by hand (``FeeInput.wif``, ``HdWallet._seed``); a third did not.
#
# The assertions below are byte-level rather than character-level because a
# ``bytes`` field renders as ``b'\\x8f\\xa2...'``, not as hex — a hex-window
# search would pass over a full disclosure without seeing it.


def _renderings_of(obj: object) -> list[str]:
    """Every way an operator's code could turn *obj* into text.

    ``print``, ``logging.info("%s", obj)`` and an f-string all land on ``__str__``;
    ``%r``, ``repr()`` and the interactive echo land on ``__repr__``; a dataclass
    without an explicit ``__str__`` routes both to the generated ``__repr__``.
    """
    return [repr(obj), str(obj), f"{obj}", f"{obj!r}", "%s" % (obj,), "%r" % (obj,)]  # noqa: UP031


def _bytes_literals_in(text: str) -> list[bytes]:
    """Every ``b'...'`` literal in *text*, evaluated back to the bytes it denotes.

    This is the recovery an attacker actually performs on a log line: the repr of
    a ``bytes`` field is valid Python source for the value it discloses.
    """
    found: list[bytes] = []
    for match in re.finditer(r"""b'(?:[^'\\]|\\.)*'|b"(?:[^"\\]|\\.)*\"""", text):
        try:
            value = ast.literal_eval(match.group(0))
        except (ValueError, SyntaxError):  # pragma: no cover - malformed slice
            continue
        if isinstance(value, bytes):
            found.append(value)
    return found


def _describe_echo(renderings: list[str], secret: bytes) -> str | None:
    """A description of the first leak found, or ``None``.

    Two independent checks, because either alone can be evaded: a full literal
    that ``ast.literal_eval`` reconstructs (compared by digest, so the comparison
    itself never holds the material next to a description of it), and any
    ``_LEAK_WINDOW``-char run of the escaped form, which catches a truncated or
    reformatted disclosure.

    Returning a string rather than asserting inline is not style, and the callers
    below invoke it from the test body rather than through an assertion helper for
    the same reason. ``assert window not in text`` hands pytest's assertion
    rewriting both operands; an assertion helper hands pytest the secret as a
    displayed frame argument. The first two drafts of this file did each in turn,
    and both printed a CEK into the log the test exists to keep it out of.
    """
    digest = hashlib.sha256(secret).digest()
    escaped = repr(secret)[2:-1]  # strip the b'' wrapper; keep the escaping
    windows = [escaped[i : i + _LEAK_WINDOW] for i in range(len(escaped) - _LEAK_WINDOW + 1)]
    for text in renderings:
        for candidate in _bytes_literals_in(text):
            if hmac.compare_digest(hashlib.sha256(candidate).digest(), digest):
                return "a bytes literal in a rendering evaluates to the secret itself — directly recoverable"
        for index, window in enumerate(windows):
            # Report the position only. Returning the window would defeat the test.
            if window in text:
                return (
                    f"a {_LEAK_WINDOW}-char run of the secret's escaped form is visible "
                    f"at offset {index} (of {len(escaped)} chars)"
                )
    return None


def _encrypted_stub() -> EncryptedContentStub:
    """The minimum an ENCRYPTED stub needs for TIMELOCK to attach to it."""
    payload = b"sealed until the unlock height"
    return EncryptedContentStub(
        p=[GlyphProtocol.NFT, GlyphProtocol.ENCRYPTED],
        type="image/png",
        name="sealed",
        main=EncryptionMetadata(
            type="image/png",
            hash=format_cek_hash(hashlib.sha256(payload).digest()),
            size=len(payload),
            chunks=1,
            scheme=SCHEME_CHUNKED_AEAD_V1,
        ),
        crypto=CryptoMetadata(mode="encrypted", key_format=KEY_FORMAT_WRAPPED),
    )


def test_the_timelock_mint_result_never_echoes_the_content_key() -> None:
    """The CEK decrypts a TIMELOCK payload BEFORE its unlock height.

    That is the whole protocol: the chain carries only ``sha256(cek)``, and the
    key stays off-chain until the reveal transaction publishes it. A result
    object that prints it verbatim collapses the wait to whoever reads the log.
    """
    cek = os.urandom(32)
    result = add_timelock_to_metadata(_encrypted_stub(), cek, TimelockParams(mode="block", unlock_at=900_000))
    leak = _describe_echo(_renderings_of(result), cek)
    assert leak is None, leak


def test_the_recovered_key_would_have_been_a_working_one() -> None:
    """The counterfactual, stated so the severity is not re-argued later.

    If the field is ever echoed again, what leaks is not a fingerprint of the key
    but the key: it verifies against the on-chain commitment and decrypts. This
    test pins that the commitment in the metadata is the CEK's, so the leak test
    above is guarding a live secret rather than an opaque blob.
    """
    cek = os.urandom(32)
    result = add_timelock_to_metadata(_encrypted_stub(), cek, TimelockParams(mode="block", unlock_at=900_000))
    assert result.metadata.crypto.timelock is not None
    assert verify_cek_reveal(cek, result.metadata.crypto.timelock.cek_hash)


def test_the_key_is_still_reachable_through_the_field() -> None:
    """Hiding it from ``repr`` must not hide it from the caller.

    The CEK is the ONLY way to broadcast the reveal later; a fix that dropped it
    would destroy the payload rather than protect it.
    """
    cek = os.urandom(32)
    result = add_timelock_to_metadata(_encrypted_stub(), cek, TimelockParams(mode="block", unlock_at=900_000))
    assert result.cek_for_caller_to_store == cek


def test_an_exception_carrying_the_result_does_not_echo_the_key() -> None:
    """The error boundary in ``cli/main.py`` prints ``cause: {exc}``, and an
    exception built with the result object in its args renders through the same
    ``__repr__``. This is the path that turned a mistyped WIF into 51 disclosed
    characters."""
    cek = os.urandom(32)
    result = add_timelock_to_metadata(_encrypted_stub(), cek, TimelockParams(mode="block", unlock_at=900_000))
    exc = RuntimeError("timelock mint failed", result)
    leak = _describe_echo(_every_rendering(exc), cek)
    assert leak is None, leak


# ── the redaction heuristic's case assumption ────────────────────────────────
#
# ``redact`` is the SDK's declared defence: ``RxdSdkError.__init__`` runs every
# positional arg through it, so it is what stands between an embedder's
# ``raise ValidationError(mnemonic)`` and a seed phrase in a stack trace.
#
# Its BIP-39 branch used to require ``t.isascii()``, which exempted every
# non-Latin wordlist the SDK ships. That was fixed. The SAME predicate carried a
# second, independent assumption that was not: that a mnemonic is written in
# lowercase. It is not. Steel backup plates (Cryptosteel, Billfodl, and every
# stamped-tile product) are UPPERCASE-only, and a mobile keyboard or a
# spreadsheet autocapitalises the first word. Those are not exotic inputs — they
# are what an operator has in hand at exactly the moment they are typing a seed
# phrase into something that then errors.
#
# The recovery is trivial and total: BIP-39 wordlists are lowercase, so
# lowercasing a disclosed uppercase phrase yields the original mnemonic
# verbatim. There is no partial-disclosure argument to make here.


def _generated_mnemonic(words: int = 12) -> str:
    """A real, checksum-valid mnemonic from fresh entropy. Never printed."""
    return mnemonic_from_entropy(os.urandom(16 if words == 12 else 32))


@pytest.mark.parametrize(
    ("label", "transform"),
    [
        ("as-generated lowercase", lambda m: m),
        ("uppercase (steel backup plate)", str.upper),
        ("title case (autocapitalised)", lambda m: " ".join(w.capitalize() for w in m.split())),
        ("first word capitalised", lambda m: m[0].upper() + m[1:]),
        ("mixed case", lambda m: " ".join(w.upper() if i % 2 else w for i, w in enumerate(m.split()))),
    ],
)
@pytest.mark.parametrize("word_count", [12, 24])
def test_a_mnemonic_is_redacted_whatever_its_case(label: str, transform, word_count: int) -> None:
    """Case is a transcription convention, not a signal about secrecy."""
    written = transform(_generated_mnemonic(word_count))
    # Collapse to a bool BEFORE asserting: a bare ``assert redact(x) == "..."``
    # makes pytest print both operands, i.e. the phrase, on failure.
    was_redacted = redact(written) == "<redacted>"
    assert was_redacted, f"redact() passed a {word_count}-word mnemonic through verbatim ({label})"


@pytest.mark.parametrize("transform", [str.upper, lambda m: " ".join(w.capitalize() for w in m.split())])
def test_a_non_lowercase_mnemonic_does_not_reach_exception_args(transform) -> None:
    """The sink that matters: ``RxdSdkError`` redacts every positional arg."""
    written = transform(_generated_mnemonic())
    _assert_no_leak(KeyMaterialError(written), written)
    _assert_no_leak(ValidationError(f"{written}"), written)


def test_the_disclosed_form_would_have_restored_the_wallet() -> None:
    """Why the above is a total disclosure and not a partial one.

    Asserts on the *recovery*, not on the redaction: if an uppercase phrase ever
    escapes, lowercasing it is the whole attack. Uses a locally-built uppercase
    string so the test states the threat without depending on the guard it guards.
    """
    mnemonic = _generated_mnemonic()
    recovered = " ".join(w.lower() for w in mnemonic.upper().split())
    validate_mnemonic(recovered)  # raises if it is not a valid BIP-39 phrase
    round_trips = recovered == mnemonic
    assert round_trips, "lowercasing an uppercase phrase did not reproduce the original"


def test_redaction_did_not_widen_into_ordinary_prose() -> None:
    """The counterweight. ``redact`` runs on EVERY SDK exception arg, so a
    heuristic that swallows ordinary sentences replaces actionable errors with
    ``<redacted>``. These are real messages raised in this tree."""
    for message in (
        "Wallet file too short to contain header",
        "tx has 0 confirmations, required 6",
        "invalid mnemonic, checksum mismatch",
        "Could not connect to the remote peer at this time",
        "Wallet file decrypted but contains invalid JSON — disk corruption?",
        "descriptor key must be an extended PUBLIC key",
    ):
        assert redact(message) == message, "redact() swallowed an ordinary error message"
