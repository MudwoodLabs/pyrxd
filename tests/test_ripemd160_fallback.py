"""Coverage for the pure-Python RIPEMD160 fallback in :mod:`pyrxd.hash`.

The module picks ``hashlib.new("ripemd160")`` when OpenSSL exposes it
and falls back to a vendored pure-Python implementation otherwise. On
any current OpenSSL-3 distro (and on Pyodide) the fallback is what
runs in production, so it gets first-class test coverage:

* **Standard test vectors** from the original RIPEMD-160 paper
  (Dobbertin, Bosselaers, Preneel, 1996). These lock the algorithm
  itself — if a future maintainer reshuffles the rotation tables or
  the message-word selection these break loudly.
* **Cross-check against hashlib** at varied sizes spanning the block
  boundaries (55 → 56 → 63 → 64 → 65 bytes are the interesting
  transitions). Two independent implementations agreeing on random
  inputs is strong evidence neither has drifted from spec.
* **Path-selection sanity check** — both branches of ``_select_ripemd160``
  return a working callable on the empty string. We don't assert which
  branch is selected (depends on the host's OpenSSL build); we assert
  both branches produce the right answer when explicitly invoked.
"""

from __future__ import annotations

import hashlib
import os

import pytest

from pyrxd.hash import _ripemd160_pure_python, _select_ripemd160, ripemd160

# Standard test vectors from the RIPEMD-160 paper. The 1M-'a' vector at
# the bottom is the canonical "long message" stress test — included
# because its absence has historically masked bugs in pure-Python ports.
_VECTORS = [
    (b"", "9c1185a5c5e9fc54612808977ee8f548b2258d31"),
    (b"a", "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe"),
    (b"abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"),
    (b"message digest", "5d0689ef49d2fae572b881b123a85ffa21595f36"),
    (b"abcdefghijklmnopqrstuvwxyz", "f71c27109c692c1b56bbdceb5b9d2865b3708dbc"),
    (
        b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "12a053384a9c0c88e405a06c27dcf49ada62eb2b",
    ),
    (
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        "b0e20b6e3116640286ed3a87a5713079b21f5189",
    ),
    (b"1234567890" * 8, "9b752e45573d4b39f4dbd3323cab82bf63326bfb"),
]


class TestPureImplementationVectors:
    """The pure-Python implementation matches every published vector."""

    @pytest.mark.parametrize("message,expected", _VECTORS)
    def test_standard_vector(self, message, expected):
        assert _ripemd160_pure_python(message).hex() == expected

    def test_one_million_a_vector(self):
        """The canonical long-message vector. Slow (~half a second) but
        catches finalisation/length-encoding bugs the short vectors miss."""
        result = _ripemd160_pure_python(b"a" * 1_000_000).hex()
        assert result == "52783243c1697bdbe16d37f97f68f08325dc1528"


class TestPureMatchesHashlib:
    """When OpenSSL also exposes RIPEMD160, both implementations must agree.

    Skips on hosts where OpenSSL refused — i.e. the very environments
    where the pure fallback is in production. Keeping the assertion
    one-sided (pure ⊆ hashlib agreement) is intentional.
    """

    @staticmethod
    def _hashlib_or_skip(payload: bytes) -> bytes:
        """Compute ``hashlib.new("ripemd160", payload).digest()`` or skip
        the test entirely if OpenSSL on this host has the legacy provider
        disabled. Centralising the skip logic here also keeps each test
        body free of half-initialised locals.

        ``pytest.skip`` raises ``Skipped`` (a BaseException subclass) so
        control never returns past it; the ``raise`` after the skip call
        is unreachable but makes that fact visible to static analysis
        (CodeQL's py/mixed-returns otherwise flags the apparent
        explicit-return-mixed-with-implicit-None pattern).
        """
        try:
            return hashlib.new("ripemd160", payload).digest()
        except ValueError:
            pytest.skip("OpenSSL on this host does not expose ripemd160")
            raise AssertionError("unreachable: pytest.skip raises")  # pragma: no cover

    @pytest.mark.parametrize("size", [0, 1, 31, 32, 55, 56, 63, 64, 65, 119, 127, 128, 1023, 1024])
    def test_random_input_at_block_boundaries(self, size):
        payload = b"x" * size
        expected = self._hashlib_or_skip(payload)
        assert _ripemd160_pure_python(payload) == expected

    def test_random_payloads(self):
        # 32 random samples across varied sizes — cheap, broad coverage.
        rng = os.urandom
        for _ in range(32):
            n = int.from_bytes(rng(2), "big") % 4097  # 0..4096
            payload = rng(n)
            expected = self._hashlib_or_skip(payload)
            assert _ripemd160_pure_python(payload) == expected, f"diverged at n={n}"


class TestSelectRipemd160:
    """``_select_ripemd160`` returns a working callable, regardless of
    which branch it picks."""

    def test_returns_callable_that_hashes_empty(self):
        impl = _select_ripemd160()
        assert impl(b"") == bytes.fromhex("9c1185a5c5e9fc54612808977ee8f548b2258d31")

    @pytest.mark.parametrize(
        "exception_factory",
        [
            lambda: ValueError("simulated OpenSSL-3 disabled-legacy-provider"),
            lambda: OSError("simulated FIPS-mode hashlib"),
            lambda: RuntimeError("simulated degenerate hashlib"),
            lambda: AttributeError("simulated partial namespace package"),
            lambda: ImportError("simulated vendored hashlib stub"),
        ],
    )
    def test_falls_back_when_hashlib_raises(self, monkeypatch, exception_factory):
        """Force the hashlib path to fail and verify the selector picks
        the pure-Python implementation. The selector catches the broad
        ``Exception`` so any flavour of degenerate hashlib falls through
        rather than aborting module import. Cover every exception type
        the comment in ``_select_ripemd160`` enumerates as a real
        scenario."""
        from pyrxd import hash as hash_mod

        def _boom(_payload):
            raise exception_factory()

        monkeypatch.setattr(hash_mod, "_ripemd160_via_hashlib", _boom)
        impl = hash_mod._select_ripemd160()
        assert impl is hash_mod._ripemd160_pure_python
        assert impl(b"") == bytes.fromhex("9c1185a5c5e9fc54612808977ee8f548b2258d31")

    def test_rejects_hashlib_with_wrong_answer(self, monkeypatch):
        """A maliciously broken hashlib (custom OpenSSL build that
        returns garbage) must not be selected — the empty-string
        verification step weeds it out."""
        from pyrxd import hash as hash_mod

        def _wrong(_payload):
            return b"\x00" * 20

        monkeypatch.setattr(hash_mod, "_ripemd160_via_hashlib", _wrong)
        impl = hash_mod._select_ripemd160()
        assert impl is hash_mod._ripemd160_pure_python


class TestStreamingUpdate:
    """The internal streaming class supports incremental updates so a
    future caller can hash large buffers without materialising them."""

    def test_chunked_update_matches_one_shot(self):
        from pyrxd.hash import _RIPEMD160

        payload = b"the quick brown fox jumps over the lazy dog" * 50
        one_shot = _RIPEMD160().update(payload).digest()

        for chunk_size in (1, 7, 31, 64, 100):
            chunked = _RIPEMD160()
            for i in range(0, len(payload), chunk_size):
                chunked.update(payload[i : i + chunk_size])
            assert chunked.digest() == one_shot, f"streaming mismatch at chunk_size={chunk_size}"

    def test_digest_is_idempotent(self):
        """Calling ``digest()`` twice returns the same bytes — finalising
        must not mutate state."""
        from pyrxd.hash import _RIPEMD160

        h = _RIPEMD160().update(b"hello world")
        first = h.digest()
        second = h.digest()
        assert first == second


class TestPublicAPI:
    """The package's public ``ripemd160`` function dispatches to whichever
    implementation was selected at import time, and returns 20 bytes."""

    @pytest.mark.parametrize("message,expected", _VECTORS)
    def test_public_function_matches_vectors(self, message, expected):
        assert ripemd160(message).hex() == expected

    def test_returns_20_bytes(self):
        assert len(ripemd160(b"any payload")) == 20
