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

import os

import pytest

from pyrxd.base58 import b58_decode, base58check_decode
from pyrxd.hd.bip32 import Xprv, master_xprv_from_seed
from pyrxd.hd.bip39 import mnemonic_from_entropy, seed_from_mnemonic
from pyrxd.keys import PrivateKey
from pyrxd.security.errors import Base58Error, RxdSdkError
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
