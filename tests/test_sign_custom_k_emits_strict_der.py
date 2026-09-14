"""``sign(k=...)`` was protected by an assertion every possible defect satisfies.

Mutation testing of ``keys.py`` (cryptoprim group, 2026-09-13) left 138 killable mutants
alive in ``_sign_custom_k`` — 92% of the module's real survivors, against 12 spread over
its other eight functions. The cause was one test::

    sig  = pk.sign(msg, k=54321)
    sig2 = pk.sign(msg, k=54321)
    assert sig == sig2          # "Same k produces same sig"

A mutated pure function is still deterministic, so that assertion cannot fail for ANY
change to the signing arithmetic, the DER framing or the low-s normalisation. Surviving
mutants included ``if r_bytes[0] & 0x80`` inverted (emits malformed DER), the total-length
byte computed with ``%``/``&``/``^``, ``to_bytes(1)`` widened to ``to_bytes(2)``, and
``if s > curve.n // 2`` rewritten to ``if s != curve.n // 2`` — i.e. low-s normalisation
applied to almost every signature instead of half of them.

These tests found a LIVE defect on first contact: the DER encoder emitted non-minimal
integers for ~0.7% of signatures, which Radiant's SCRIPT_VERIFY_STRICTENC rejects. See
the note above the last two tests. The rest of the function was correct; what was
missing was anything that would notice either way.

Two properties make these tests bite where the old one did not:

* **Round-trip through the transport that actually carries the value.**
  ``utils.deserialize_ecdsa_der`` is the project's strict parser and documents itself as
  applying "every rule Radiant applies when it validates a signature". Asserting on the
  raw bytes we just produced proves self-consistency; parsing them with the consensus
  decoder proves they are a signature a block can contain.
* **Both sides of the padding branch.** ``r`` is a function of ``k`` alone, so a FIXED
  test ``k`` pins ``r_bytes[0] & 0x80`` to one value and the other branch never executes.
  The ``k`` values below are chosen at run time to force each branch.

Keys are generated, never hand-written: ``PrivateKey()`` with no argument draws a random
key, and nothing here asserts an exact value derived from it.
"""

from __future__ import annotations

import pytest

from pyrxd.curve import curve, curve_multiply
from pyrxd.hash import hash256
from pyrxd.keys import PrivateKey
from pyrxd.utils import deserialize_ecdsa_der

#: Modules this file is a dedicated test for, read by scripts/derive_mutation_test_lists.py.
#: Needed because neither derivation signal can see this test: it is named after a function
#: rather than a module, and its coverage is unremarkable (rank 60 of 97, zero exclusive arcs)
#: because `test_coverage_gaps2.py` already executes the same lines — it just asserts only that
#: signing is deterministic, which every mutant satisfies. The difference is in the assertions,
#: and coverage cannot see assertions.
MUTATION_TARGETS = ["keys"]

_MESSAGE = b"strict der round trip"


def _r_of(k: int) -> int:
    """The ``r`` a given ``k`` produces. Independent of the signing key."""
    point = curve_multiply(k % curve.n, curve.g)
    assert point is not None
    return point.x


def _k_forcing_high_bit(*, set_: bool) -> int:
    """Smallest k whose r has its most-significant byte's top bit set (or clear).

    DER encodes signed integers, so a leading byte >= 0x80 must be padded with 0x00 or the
    value reads as negative. Which branch runs is decided by ``k``, which is why one fixed
    ``k`` can never exercise both.
    """
    for k in range(1, 4096):
        if bool(_r_of(k).to_bytes(32, "big")[0] & 0x80) is set_:
            return k
    raise AssertionError("no k found in 1..4095 forcing the requested padding branch")


@pytest.fixture(scope="module")
def padding_ks() -> tuple[int, int]:
    """One k that triggers the 0x00 pad, one that does not. Both branches, every test."""
    return _k_forcing_high_bit(set_=True), _k_forcing_high_bit(set_=False)


def test_both_padding_branches_are_reachable(padding_ks: tuple[int, int]) -> None:
    """Non-vacuity: if this fails, every test below is silently exercising one branch."""
    padded, unpadded = padding_ks
    assert _r_of(padded).to_bytes(32, "big")[0] & 0x80
    assert not _r_of(unpadded).to_bytes(32, "big")[0] & 0x80


def test_signature_parses_under_the_consensus_strict_decoder(padding_ks: tuple[int, int]) -> None:
    """The old test never parsed the bytes, so any framing error survived."""
    key = PrivateKey()
    for k in padding_ks:
        signature = key.sign(_MESSAGE, k=k)
        # require_low_s=True is the consensus rule; a high-s signature raises here.
        r, s = deserialize_ecdsa_der(signature, require_low_s=True)
        assert r == _r_of(k), "r is not the x-coordinate of k*G"
        assert 0 < s <= curve.n // 2, "s outside the canonical low-s range"


def test_r_and_s_match_an_independent_derivation(padding_ks: tuple[int, int]) -> None:
    """Re-derive ECDSA from the definition and compare, so arithmetic edits are caught.

    This is deliberately a second expression of the spec rather than a call into the code
    under test: a mutation to ``keys.py`` does not change what this computes.
    """
    key = PrivateKey()
    d = int.from_bytes(key.serialize(), "big")
    z = int.from_bytes(hash256(_MESSAGE), "big")
    for k in padding_ks:
        r_expected = _r_of(k)
        s_expected = (pow(k % curve.n, -1, curve.n) * (z + r_expected * d)) % curve.n
        if s_expected > curve.n // 2:  # canonical low-s
            s_expected = curve.n - s_expected

        r, s = deserialize_ecdsa_der(key.sign(_MESSAGE, k=k), require_low_s=True)
        assert (r, s) == (r_expected, s_expected)


def test_the_signature_actually_verifies(padding_ks: tuple[int, int]) -> None:
    """The honest path must still pass — a signer that refuses valid work is a bug."""
    key = PrivateKey()
    for k in padding_ks:
        assert key.public_key().verify(key.sign(_MESSAGE, k=k), _MESSAGE)


def test_the_encoding_is_byte_exact_against_a_reference_framing(padding_ks: tuple[int, int]) -> None:
    """Pin the DER layout itself: ``30 len 02 rlen r 02 slen s``.

    Parsing catches framing that is *invalid*; this catches framing that is merely
    *different* — a wider length field, or a pad added where none is required.
    """
    key = PrivateKey()
    for k in padding_ks:
        signature = key.sign(_MESSAGE, k=k)
        r, s = deserialize_ecdsa_der(signature, require_low_s=True)

        # Minimal encoding, exactly as `utils.serialize_ecdsa_der` does it. Building the
        # expectation with a fixed 32-byte int would re-enact the very defect this file
        # found, and would pass only for k values whose r has no leading zero byte.
        r_bytes = r.to_bytes(32, "big").lstrip(b"\x00")
        s_bytes = s.to_bytes(32, "big").lstrip(b"\x00")
        if r_bytes[0] & 0x80:
            r_bytes = b"\x00" + r_bytes
        if s_bytes[0] & 0x80:
            s_bytes = b"\x00" + s_bytes
        expected = (
            b"\x30"
            + (4 + len(r_bytes) + len(s_bytes)).to_bytes(1, "big")
            + b"\x02"
            + len(r_bytes).to_bytes(1, "big")
            + r_bytes
            + b"\x02"
            + len(s_bytes).to_bytes(1, "big")
            + s_bytes
        )
        assert signature == expected


@pytest.mark.parametrize("bad_k", [0, curve.n, 2 * curve.n])
def test_a_nonce_congruent_to_zero_is_refused(bad_k: int) -> None:
    """``k`` is reduced mod n before the check, so n and 2n are the same defect as 0.

    A signature made with k = 0 is not a signature; ``r`` would be the point at infinity.

    ``match="Invalid nonce k"`` is load-bearing, not decoration. Deleting the explicit
    ``if k == 0: raise ValueError("Invalid nonce k")`` guard in ``_sign_custom_k`` still
    raises ``ValueError`` for every case here — ``if R is None`` and Python's own
    ``pow(k, -1, n)`` both refuse k ≡ 0 (mod n) on their own — so a bare
    ``pytest.raises(ValueError)`` cannot tell "the guard works" from "the guard is absent".
    """
    key = PrivateKey()
    with pytest.raises(ValueError, match="Invalid nonce k"):
        key.sign(_MESSAGE, k=bad_k)


# --------------------------------------------------------------------------------------
# The defect these tests found on first contact.
#
# `_sign_custom_k` encoded r and s as FIXED 32-byte integers and never stripped leading
# zeros, while DER requires minimal encoding. Whenever r or s fell below 2**248 — about
# 1/256 each — the signature carried a leading 0x00 that DER forbids, and Radiant applies
# SCRIPT_VERIFY_STRICTENC, so it could not confirm. Measured on the old code: 14 of 2000
# signatures rejected by this project's own strict parser (0.70%).
#
# The correct encoder, `utils.serialize_ecdsa_der`, was already imported in keys.py. The
# fix deletes the duplicate rather than patching it, so there is no second spelling left
# to drift. These two tests pin the branch the old code got wrong, deterministically: a
# probabilistic defect needs a trigger chosen on purpose, or the test is merely flaky.
# --------------------------------------------------------------------------------------


def _has_redundant_leading_zero(value: int) -> bool:
    """True when a fixed 32-byte encoding of *value* carries a zero DER forbids.

    A leading 0x00 is REQUIRED when the next byte's high bit is set, or the integer reads
    as negative. It is redundant — and non-minimal, and consensus-invalid — only when the
    next byte's high bit is clear. Getting this wrong makes the test pass for the wrong
    reason: k=153 gives r=0x00e3..., where the zero IS required, so the pre-fix encoder is
    accidentally correct there and the planted defect went undetected.
    """
    raw = value.to_bytes(32, "big")
    return raw[0] == 0x00 and not (raw[1] & 0x80)


def _k_with_redundant_leading_zero_r() -> int:
    """Smallest k whose r carries a zero byte DER forbids. k=246 at the time of writing."""
    for k in range(1, 200_000):
        if _has_redundant_leading_zero(_r_of(k)):
            return k
    raise AssertionError("no k in 1..199999 produces an r with a redundant leading zero")


def test_a_leading_zero_in_r_is_encoded_minimally() -> None:
    """r < 2**248 used to emit `02 21 00 ...` — non-minimal, and consensus-invalid."""
    key = PrivateKey()
    k = _k_with_redundant_leading_zero_r()
    assert _has_redundant_leading_zero(_r_of(k)), "this k no longer triggers the branch"

    signature = key.sign(_MESSAGE, k=k)
    r, _ = deserialize_ecdsa_der(signature, require_low_s=True)  # raised before the fix
    assert r == _r_of(k)
    # and the encoding itself carries no redundant pad
    r_len = signature[3]
    assert signature[4] != 0x00 or (signature[5] & 0x80), "r retains a non-minimal zero byte"
    assert r_len <= 33


def test_a_leading_zero_in_s_is_encoded_minimally() -> None:
    """Same defect on the s half. s depends on the key, so search k for this key."""
    key = PrivateKey()
    z_msg = _MESSAGE
    for k in range(1, 20_000):
        signature = key.sign(z_msg, k=k)
        _, s = deserialize_ecdsa_der(signature, require_low_s=True)
        if _has_redundant_leading_zero(s):
            s_off = 4 + signature[3] + 2
            assert signature[s_off] != 0x00 or (signature[s_off + 1] & 0x80), "s retains a non-minimal zero byte"
            return
    raise AssertionError("no k in 1..19999 produced an s with a leading zero byte")


# --------------------------------------------------------------------------------------
# The low-S boundary itself: `if s > curve.n // 2:` in `utils.serialize_ecdsa_der`.
#
# A `>=` mutant here survives every test above: raw s == n // 2 exactly requires z and d to
# collide on one specific residue, which does not happen by chance with a random key and a
# hashed message (probability 2^-256). It is a live defect if introduced — n is prime hence
# odd, so n - n // 2 == n // 2 + 1, and a signature with s == n // 2 + 1 is HIGH-S, which
# libsecp256k1 (and this project's own `require_low_s=True` decoder) rejects.
# --------------------------------------------------------------------------------------


def _identity_hasher(message: bytes) -> bytes:
    """Pass the digest straight through, so the caller controls z exactly."""
    return message


def test_the_low_s_boundary_normalises_exactly_at_n_over_2() -> None:
    """Force s to land exactly on, and one past, the low-S boundary for a REAL random key.

    ``_sign_custom_k`` computes ``s = k^-1 * (z + r*d) mod n``. Solving for z given a chosen
    k and a target s — ``z = (target_s * k - r * d) mod n`` — lands s exactly where wanted for
    whatever key ``PrivateKey()`` happened to draw, because z is free: it comes from the
    message via ``hasher``, and the identity hasher below lets this test supply the raw digest
    directly instead of hashing arbitrary text and hoping for a collision.

    Both raw s == n // 2 and s == n // 2 + 1 must normalise to s == n // 2 — the first
    unchanged (already low), the second flipped via ``n - s``. A `>` -> `>=` mutant instead
    flips the FIRST case too, emitting n // 2 + 1 (HIGH-S), which is what this test exists to
    catch: not a value derived from the random key, but the curve's own public constant.
    """
    key = PrivateKey()
    d = int.from_bytes(key.serialize(), "big")
    k = 1
    r = _r_of(k)

    for target_s in (curve.n // 2, curve.n // 2 + 1):
        z = (target_s * k - r * d) % curve.n
        message = z.to_bytes(32, "big")
        signature = key.sign(message, hasher=_identity_hasher, k=k)

        r_out, s_out = deserialize_ecdsa_der(signature, require_low_s=True)
        assert r_out == r
        assert s_out == curve.n // 2, f"raw s={target_s} did not normalise to the low-S boundary"
        assert key.public_key().verify(signature, message, _identity_hasher), (
            "the honest path must still verify — a boundary-correct signature is not a broken one"
        )
