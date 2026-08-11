"""No error path that RECEIVES secret material may echo it — swept across the SDK.

``tests/security/test_key_material_never_echoed.py`` pins the base58 / WIF / xprv decode
path, which is where the original leak lived: a WIF with one mistyped character was echoed
verbatim, publishing 51 of its 52 characters into stderr and any pasted bug report.

This file extends the same discipline to **every other entry point that takes caller-supplied
secret material**, enumerated from the source rather than guessed:

===========================  =============================================================
Secret                       Entry points swept here
===========================  =============================================================
private key (raw/hex/WIF)    ``PrivateKey``, ``to_bytes(enc="hex")``, ``PrivateKeyMaterial``
signature (r‖s DER)          ``deserialize_ecdsa_der``
BIP-39 mnemonic              ``seed_from_mnemonic`` (every shipped wordlist language)
BIP-32 xprv / chain code     ``Xprv``, ``Xpub``, the base ``Xkey``, ``ckd``, descriptors
seed bytes                   ``master_xprv_from_seed``
passphrase                   ``seed_from_mnemonic(passphrase=…)``, encrypted-wallet unlock
AEAD / KEM keys and nonces   ``aead_encrypt`` / ``aead_decrypt``, ``kem`` wrap/unwrap
AES-CBC key / IV / padding   ``aes_cbc``
HTLC preimage                ``build_htlc_claim_tx``-side preimage checks
===========================  =============================================================

For each, the sink checked is every one an operator or a bug report can see: the exception
message, its ``repr``, its ``args``, the whole ``__cause__``/``__context__`` chain (a
traceback prints all of it, and ``pyrxd swap --debug`` renders it explicitly), and the
``repr``/``str`` of any object that holds the material.

Two rules borrowed from the original file and kept absolutely:

* **Every key here is generated** — ``PrivateKey()`` / ``os.urandom`` / ``mnemonic_from_entropy``.
  A hand-written test key was once swept by a real bot.
* **No assertion prints the secret**, including on failure. Failures report the byte offset
  of the leak and nothing else.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from typing import Any

import pytest

from pyrxd import utils
from pyrxd.aes_cbc import InvalidPadding, aes_decrypt_with_iv, aes_encrypt_with_iv
from pyrxd.crypto.aead import decrypt_xchacha20_poly1305, encrypt_xchacha20_poly1305
from pyrxd.hd.bip32 import Xkey, Xprv, Xpub, master_xprv_from_seed
from pyrxd.hd.bip39 import WordList, mnemonic_from_entropy, seed_from_mnemonic, validate_mnemonic
from pyrxd.keys import PrivateKey
from pyrxd.security.errors import Base58Error, KeyMaterialError, ValidationError, redact
from pyrxd.security.secrets import PrivateKeyMaterial, SecretBytes

#: Shortest run of a secret we treat as a leak. A WIF is 51-52 chars, an xprv 111, and a
#: 64-char hex key: any contiguous 8-character run is already a real search-space cut.
LEAK_WINDOW = 8


def every_rendering(exc: BaseException) -> list[str]:
    """All operator-visible text for *exc* — its message, repr and args, plus the entire
    ``__cause__``/``__context__`` chain, because a traceback renders all of it."""
    out: list[str] = []
    seen: set[int] = set()
    node: BaseException | None = exc
    while node is not None and id(node) not in seen:
        seen.add(id(node))
        out.extend((str(node), repr(node), repr(node.args)))
        node = node.__cause__ or node.__context__
    return out


def assert_no_leak(renderings: list[str], secret: str, *, label: str) -> None:
    """Fail if any ``LEAK_WINDOW``-char run of *secret* appears in any rendering.

    Reports the offset only. Printing the window would defeat the test.
    """
    for index in range(len(secret) - LEAK_WINDOW + 1):
        window = secret[index : index + LEAK_WINDOW]
        for text in renderings:
            assert window not in text, (
                f"{label}: leaked a {LEAK_WINDOW}-char run of the secret at offset {index} of {len(secret)}"
            )


def assert_call_never_echoes(
    fn: Callable[[], Any],
    secret: str,
    *,
    label: str,
    expect: type[BaseException] | tuple[type[BaseException], ...],
) -> None:
    """Call ``fn``, require it to fail with ``expect``, and check no rendering leaks ``secret``.

    ``expect`` is not decoration. This helper used to be a bare
    ``try: fn() / except BaseException: assert_no_leak(...)`` with a docstring blessing a
    call that succeeded, and that made two whole classes of dead test invisible — a
    swallowed exception is indistinguishable from a redaction that works:

    **The call never reached the branch.** ``seed_from_mnemonic(swapped, lang=lang,
    validate=True)`` named a keyword argument that does not exist on
    ``seed_from_mnemonic``, so CPython raised ``TypeError`` while *binding the
    arguments* — before one line of the function body ran. The ``TypeError`` was caught,
    plainly contained no mnemonic, and the test passed. The BIP-39 checksum-mismatch
    redaction path it claimed to cover was untested in **every** shipped wordlist.

    **The call never failed at all.** ``to_bytes(key_with_a_"!"_in_it, enc="hex")``
    strips non-alphanumeric characters before parsing, so the "mistyped" key was
    repaired and returned successfully; the ``ValueError`` branch the test named was
    never reached, and ``assert_no_leak`` never ran, in all four parametrizations.

    Naming the exception closes both. A signature that drifts raises ``TypeError``
    instead of ``expect`` and is re-raised instead of laundered; a call that stops
    failing is reported instead of passing silently.

    The unexpected exception's *message* is deliberately withheld from the failure
    report — this file exists because messages on these paths carry secret material.
    """
    try:
        fn()
    except expect as exc:  # type: ignore[misc]
        assert_no_leak(every_rendering(exc), secret, label=label)
        return
    except BaseException as exc:
        raise AssertionError(
            f"{label}: expected {expect}, got {type(exc).__name__} — so the branch under "
            "test was never reached and nothing about it was asserted. (Message withheld: "
            "it may carry the secret.)"
        ) from None
    raise AssertionError(
        f"{label}: the call SUCCEEDED. This asserts about a failure path, so a call that "
        "does not fail asserts nothing — the input no longer reaches the branch."
    )


def corrupt(text: str, index: int) -> str:
    """Replace one character with ``0`` — outside the base58 alphabet, and the single
    likeliest transcription error for an ``O``."""
    return text[:index] + "0" + text[index + 1 :]


# ── private keys: hex, raw, and the WIF round trip ────────────────────────────


@pytest.mark.parametrize("bad_index", [0, 1, 31, 63])
def test_hex_private_key_is_never_echoed_by_to_bytes(bad_index: int) -> None:
    """``to_bytes(key_hex, enc="hex")`` fed a mistyped key must not echo any of it.

    CPython's own message is ``invalid literal for int() with base 16: 'XY'`` — two
    characters of whatever was handed in. This is the only place in the SDK where
    ``int(x, 16)`` runs directly on a caller-supplied string that may be a private key.

    The mistyped character must be **alphanumeric**. ``to_bytes`` sanitises with
    ``"".join(filter(str.isalnum, msg))`` and then left-pads an odd length back to even,
    so a ``"!"`` was silently stripped and the key repaired — the call returned
    successfully and this test asserted nothing at all until ``expect=`` caught it.
    ``"z"`` survives the filter and is still outside the hex alphabet.
    """
    key_hex = os.urandom(32).hex()
    mistyped = key_hex[:bad_index] + "z" + key_hex[bad_index + 1 :]
    assert_call_never_echoes(
        lambda: utils.to_bytes(mistyped, enc="hex"), key_hex, label=f"to_bytes[{bad_index}]", expect=ValueError
    )


def test_private_key_repr_and_str_never_carry_the_key() -> None:
    """``PrivateKey`` is printed by every debugger, logger and ``%r`` format string."""
    key = PrivateKey()
    secret_hex = key.serialize().hex()
    wif = key.wif()
    for rendering in (repr(key), str(key), f"{key}", f"{key!r}"):
        assert_no_leak([rendering], secret_hex, label="PrivateKey rendering (hex)")
        assert_no_leak([rendering], wif, label="PrivateKey rendering (wif)")


@pytest.mark.parametrize("bad_index", [0, 20, 50])
def test_private_key_material_from_wif_never_echoes(bad_index: int) -> None:
    """``PrivateKeyMaterial.from_wif`` is the zeroing wrapper the CLI reaches for."""
    wif = PrivateKey().wif()
    assert_call_never_echoes(
        lambda: PrivateKeyMaterial.from_wif(corrupt(wif, bad_index)),
        wif,
        label="PrivateKeyMaterial",
        expect=KeyMaterialError,
    )


def test_secret_holder_reprs_never_carry_the_material() -> None:
    """``SecretBytes`` / ``PrivateKeyMaterial`` exist to make ``%r`` safe. Pin that."""
    raw = os.urandom(32)
    holders = [SecretBytes(raw), PrivateKeyMaterial(raw)]
    for holder in holders:
        for rendering in (repr(holder), str(holder), f"{holder}", f"{holder!r}"):
            assert_no_leak([rendering], raw.hex(), label=f"{type(holder).__name__} rendering")


# ── signatures: r‖s recovers the key when the nonce is reused ─────────────────


class _OddSequence(bytes):
    """A ``bytes`` subclass whose indexing yields a non-int at one position.

    This exists to REACH ``deserialize_ecdsa_der``'s catch-all branch, which plain ``bytes``
    cannot: every explicit check in the walker raises ``ValueError`` and is re-raised
    untouched, and ``int.from_bytes`` over real ``bytes`` never raises ``TypeError``. So the
    leak below was **latent** — live, exported, but not reachable with an ordinary argument.
    It is still worth closing: the function is public API with no in-``src`` callers, i.e. it
    exists purely for SDK consumers, who are exactly the population that pastes an error
    message into a bug report.
    """

    def __getitem__(self, item):
        # Integer indexing behaves normally, so every explicit ValueError check in the
        # walker passes. Only the SLICE handed to ``int.from_bytes`` yields a non-int,
        # which raises TypeError — the one exception class that falls through to the
        # catch-all rather than being re-raised by ``except (ValueError, ValidationError)``.
        if isinstance(item, slice):
            return [1, 1.5]
        return super().__getitem__(item)


def test_der_signature_is_never_echoed_on_the_catch_all_branch() -> None:
    """``deserialize_ecdsa_der``'s catch-all raised ``ValueError(f"invalid DER encoded {signature.hex()}")``.

    A signature is key material: ``r`` and ``s`` produced with a reused or leaked nonce ``k`` —
    exactly what ``PrivateKey._sign_custom_k``'s R-puzzle path yields — plus the message hash
    recover the private key. It was a **bare** ``ValueError`` too, so ``security.errors.redact``
    never ran on it, and ``cli/main.py``'s catch-all prints ``cause: {exc}`` straight to stderr.
    """
    key = PrivateKey()
    signature = key.sign(b"a message to sign")
    hostile = _OddSequence(signature)

    with pytest.raises(ValueError) as caught:
        utils.deserialize_ecdsa_der(hostile)
    assert_no_leak(every_rendering(caught.value), bytes(signature).hex(), label="deserialize_ecdsa_der")


@pytest.mark.parametrize(
    "mangle",
    [
        lambda sig: sig[:-1],  # truncated
        lambda sig: sig + b"\x00",  # trailing junk
        lambda sig: b"\x31" + sig[1:],  # wrong SEQUENCE tag
        lambda sig: sig[:3] + b"\x00" + sig[4:],  # zero-length r
        lambda sig: b"\x30\xff" + sig[2:],  # lying total length
    ],
    ids=["truncated", "trailing", "bad_tag", "zero_r_len", "lying_total_len"],
)
def test_ordinary_der_rejections_never_echo_the_signature(mangle) -> None:
    """The reachable rejection branches must stay static-message too."""
    signature = PrivateKey().sign(b"a message to sign")
    mangled = mangle(signature)
    assert_call_never_echoes(
        lambda: utils.deserialize_ecdsa_der(mangled),
        bytes(mangled).hex(),
        label="deserialize_ecdsa_der",
        expect=ValueError,
    )


# ── BIP-39 mnemonics, in every wordlist the SDK ships ─────────────────────────


def a_transcription_slip_that_really_breaks_the_checksum(words: list[str], lang: str) -> str:
    """The same valid words in a wrong order, whose checksum is GENUINELY invalid.

    Swapping one fixed pair is not enough. A 12-word mnemonic carries 4 checksum bits,
    so a reordering leaves the checksum accidentally valid about one time in sixteen —
    measured over 2000 draws per language: 6.65% (en), 5.80% (zh-cn). When that happens
    ``seed_from_mnemonic`` SUCCEEDS and there is no error path to check at all.

    Under the old swallow-everything helper that was invisible (a successful call
    asserted nothing); with ``expect=`` it would be a ~6% flake. Neither is acceptable
    for a test that is the only cover for this branch, so the mismatch is *confirmed*
    here rather than assumed. Each adjacent swap is an independent ~15/16 chance of
    breaking it, so the search effectively always succeeds on the first or second try.
    """
    for i in range(len(words) - 1):
        candidate = " ".join([*words[:i], words[i + 1], words[i], *words[i + 2 :]])
        try:
            validate_mnemonic(candidate, lang)
        except ValidationError:
            return candidate
    raise AssertionError(f"no adjacent swap in {len(words)} words broke the {lang} checksum")


@pytest.mark.parametrize("lang", sorted(WordList.files))
def test_a_bad_mnemonic_is_never_echoed(lang: str) -> None:
    """A mnemonic IS the wallet. No rejection may name a word, an index, or the phrase.

    Swept across every shipped language because the redaction heuristic used to require
    ``t.isascii()``, which exempted the non-Latin wordlists entirely.
    """
    mnemonic = mnemonic_from_entropy(os.urandom(16), lang=lang)
    words = mnemonic.split()
    broken = " ".join([*words[:-1], "notarealbip39word"])
    assert_call_never_echoes(
        lambda: seed_from_mnemonic(broken, lang=lang),
        mnemonic,
        label=f"seed_from_mnemonic[{lang}]",
        expect=ValueError,
    )
    # Same phrase, valid words, wrong checksum: the classic single-word transcription slip.
    # NO ``validate=`` keyword — ``seed_from_mnemonic`` has never had one, and passing it
    # made CPython raise TypeError at argument binding. The old helper swallowed that, so
    # this branch (``validate_mnemonic`` -> "invalid mnemonic, checksum mismatch") was
    # dead in every shipped language. Validation is unconditional; there is nothing to
    # opt into.
    swapped = a_transcription_slip_that_really_breaks_the_checksum(words, lang)
    assert_call_never_echoes(
        lambda: seed_from_mnemonic(swapped, lang=lang),
        mnemonic,
        label=f"seed_from_mnemonic checksum[{lang}]",
        expect=ValidationError,
    )


@pytest.mark.parametrize("lang", sorted(WordList.files))
def test_redact_covers_mnemonics_in_every_shipped_language(lang: str) -> None:
    """``redact`` required ASCII tokens, so a Chinese mnemonic passed through verbatim.

    ``chinese_simplified`` is a first-class ``lang=`` option of ``mnemonic_from_entropy``,
    so "we only support English" was never true.
    """
    mnemonic = mnemonic_from_entropy(os.urandom(16), lang=lang)
    assert redact(mnemonic) == "<redacted>", f"redact() left a {lang} mnemonic unredacted"


def test_redact_still_passes_ordinary_diagnostic_text() -> None:
    """The heuristic must stay usable: widening it must not eat normal error prose.

    Uppercase and digits are the discriminators — a BIP-39 phrase has neither.
    """
    for benign in (
        "tx has 3 confirmations, required 6",
        "Insufficient funds for the requested amount",
        "output index must be a non-negative int",
    ):
        assert redact(benign) == benign


# ── BIP-32: xprv, chain code, seed ────────────────────────────────────────────


def test_the_base_xkey_does_not_serialize_an_xprv_through_str() -> None:
    """``Xkey.__str__`` returned ``base58check_encode(self.payload)`` unconditionally.

    ``Xprv`` overrides it, but ``Xkey`` is exported and constructible, so ``str(Xkey(xprv))``
    printed all 111 characters — master private key AND chain code, i.e. the whole wallet.
    """
    xprv = master_xprv_from_seed(os.urandom(64))
    serialized = xprv.serialize()
    base = Xkey(serialized)
    for rendering in (str(base), repr(base), f"{base}", f"{base!r}"):
        assert_no_leak([rendering], serialized, label="Xkey rendering")
        assert_no_leak([rendering], xprv.chain_code.hex(), label="Xkey chain code")


def test_xprv_renderings_never_carry_the_key_or_chain_code() -> None:
    xprv = master_xprv_from_seed(os.urandom(64))
    for rendering in (str(xprv), repr(xprv), f"{xprv}", f"{xprv!r}"):
        assert_no_leak([rendering], xprv.serialize(), label="Xprv rendering")
        assert_no_leak([rendering], xprv.chain_code.hex(), label="Xprv chain code")


def test_xpub_remains_printable() -> None:
    """The redaction must not break the public half: ``str(xpub)`` IS the xpub.

    ``cli/wallet_cmds`` and ``hd/descriptor`` both rely on it, and an xpub is public —
    ``Xpub.__init__`` has already proved the payload carries a SEC1 public-key prefix.
    """
    xpub = master_xprv_from_seed(os.urandom(64)).xpub()
    assert str(xpub) == xpub.serialize()
    assert str(xpub).startswith("xpub")


@pytest.mark.parametrize("bad_index", [0, 4, 60, 110])
def test_a_mistyped_xprv_is_never_echoed(bad_index: int) -> None:
    """111 characters, of which a corrupted copy still gives away 110."""
    serialized = master_xprv_from_seed(os.urandom(64)).serialize()
    assert_call_never_echoes(
        lambda: Xprv(corrupt(serialized, bad_index)), serialized, label=f"Xprv[{bad_index}]", expect=Base58Error
    )


@pytest.mark.parametrize("bad_index", [0, 4, 60, 110])
def test_a_mistyped_xpub_never_echoes_a_pasted_xprv(bad_index: int) -> None:
    """The likeliest thing pasted into an xpub field by mistake is an **xprv**.

    So the xpub decoder must be as silent as the xprv one — it cannot know which it got.
    """
    serialized = master_xprv_from_seed(os.urandom(64)).serialize()
    assert_call_never_echoes(
        lambda: Xpub(corrupt(serialized, bad_index)), serialized, label=f"Xpub[{bad_index}]", expect=Base58Error
    )


def test_ckd_derivation_failures_never_echo_the_parent_key() -> None:
    """A bad derivation path must not drag the parent xprv into the message."""
    xprv = master_xprv_from_seed(os.urandom(64))
    serialized = xprv.serialize()
    # Each bad index fails in a different layer, so each names its own exception rather
    # than hiding behind a catch-all: hex decoding, the 4-byte width check, and int
    # packing respectively.
    for bad_index, expected in (
        ("not-a-path", ValueError),
        (b"\x00", ValidationError),
        (2**40, OverflowError),
    ):
        assert_call_never_echoes(
            lambda i=bad_index: xprv.ckd(i), serialized, label=f"Xprv.ckd[{expected.__name__}]", expect=expected
        )


def test_master_xprv_from_seed_never_echoes_the_seed() -> None:
    """The seed is upstream of every key in the wallet.

    ``seed.hex()`` is deliberately NOT in this list: ``Xprv.from_seed`` accepts a ``str``
    and hex-decodes it, so the hex form of a valid 64-byte seed is a valid seed and
    derives successfully. It sat here as a third "bad seed" and asserted nothing.
    """
    seed = os.urandom(64)
    for bad_seed in (seed[:3], seed + seed):
        assert_call_never_echoes(
            lambda s=bad_seed: master_xprv_from_seed(s),
            seed.hex(),
            label="master_xprv_from_seed",
            expect=ValidationError,
        )


def test_the_hex_form_of_a_seed_is_accepted_rather_than_rejected() -> None:
    """Pin the reason ``seed.hex()`` was removed above, so it is a decision and not a loss."""
    seed = os.urandom(64)
    assert master_xprv_from_seed(seed.hex()).serialize() == master_xprv_from_seed(seed).serialize()


# ── passphrases ───────────────────────────────────────────────────────────────


def test_a_passphrase_is_never_echoed_by_seed_derivation() -> None:
    """A BIP-39 passphrase is the 13th word — losing it loses the wallet, and printing it
    hands over a wallet whose mnemonic may already be backed up in plaintext."""
    passphrase = os.urandom(16).hex()
    broken = "notarealbip39word " * 12
    assert_call_never_echoes(
        lambda: seed_from_mnemonic(broken.strip(), passphrase=passphrase),
        passphrase,
        label="seed_from_mnemonic passphrase",
        expect=ValueError,
    )


# ── symmetric crypto: keys, nonces, IVs, and the padding oracle ───────────────


@pytest.mark.parametrize(
    ("bad_key", "bad_nonce"),
    [
        (os.urandom(16), os.urandom(24)),  # wrong key length
        (os.urandom(32), os.urandom(7)),  # wrong nonce length
        (os.urandom(31), os.urandom(23)),  # both wrong
    ],
    ids=["short_key", "short_nonce", "both"],
)
def test_aead_errors_never_echo_key_or_nonce(bad_key: bytes, bad_nonce: bytes) -> None:
    """AEAD rejections report lengths, never values. Pin that they keep doing so."""
    assert_call_never_echoes(
        lambda: encrypt_xchacha20_poly1305(b"plaintext", bad_key, bad_nonce),
        bad_key.hex(),
        label="aead key",
        expect=ValueError,
    )
    assert_call_never_echoes(
        lambda: encrypt_xchacha20_poly1305(b"plaintext", bad_key, bad_nonce),
        bad_nonce.hex(),
        label="aead nonce",
        expect=ValueError,
    )


def test_aead_decrypt_failure_never_echoes_the_key() -> None:
    """A tamper/wrong-key failure must say only "it failed" — never which check, never the key."""
    key, nonce = os.urandom(32), os.urandom(24)
    ciphertext = encrypt_xchacha20_poly1305(b"a secret message", key, nonce, b"aad")
    wrong_key = os.urandom(32)
    assert_call_never_echoes(
        lambda: decrypt_xchacha20_poly1305(ciphertext, wrong_key, nonce, b"aad"),
        wrong_key.hex(),
        label="aead_decrypt",
        expect=ValueError,
    )


def test_aes_cbc_padding_errors_never_echo_key_iv_or_padding_bytes() -> None:
    """The classic padding-oracle shape: the message must not vary with, or contain, the key."""
    key, iv = os.urandom(32), os.urandom(16)
    ciphertext = aes_encrypt_with_iv(key, iv, b"a secret message")
    corrupted = bytes([ciphertext[0] ^ 0xFF]) + ciphertext[1:]
    for secret in (key.hex(), iv.hex()):
        assert_call_never_echoes(
            lambda: aes_decrypt_with_iv(key, iv, corrupted), secret, label="aes_cbc padding", expect=InvalidPadding
        )
