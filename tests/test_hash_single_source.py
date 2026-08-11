"""Every hash in the SDK comes from ``pyrxd.hash``, and why that is not cosmetic.

Two rules, two very different consequences.

**hash160 must go through** :func:`pyrxd.hash.hash160`. That function picks
between ``hashlib.new("ripemd160")`` and a pure-Python fallback at import time,
because OpenSSL 3 moved RIPEMD160 into the legacy provider and
``hashlib.new("ripemd160")`` **raises** on Ubuntu 24.04, Debian 12, the
python.org macOS builds, and Pyodide. Three modules called ``hashlib.new``
directly and so had no fallback at all — including the P2SH address derivation
on the Gravity claim path. ``TestHash160SurvivesAnOpenSSL3Box`` simulates that
environment; before the consolidation the three direct callers raised there.

**hash256 must not be confused with the Radiant block hash.** Radiant's block
header hash is a double **SHA-512/256** (``primitives/block.h:129``), not
SHA-256d. Both are "the double hash", they are the same length, and neither
looks wrong next to the other. ``TestTheBlockHashIsADifferentFunction`` pins
them apart.
"""

from __future__ import annotations

import hashlib

import pytest

from pyrxd.hash import hash160, hash256, ripemd160

pytestmark = pytest.mark.unit


@pytest.fixture
def openssl3_without_legacy_provider(monkeypatch):
    """A faithful stand-in for a box where OpenSSL refuses RIPEMD160.

    Two halves, and both are needed for the simulation to mean anything:

    * ``hashlib.new("ripemd160", ...)`` raises, as it does on Ubuntu 24.04,
      Debian 12, the python.org macOS builds and Pyodide; and
    * ``pyrxd.hash`` is bound to the pure-Python implementation, which is what
      its import-time ``_select_ripemd160`` would have chosen on such a box.
      Without this half the fixture would break ``pyrxd.hash`` too and every
      test below would fail for the wrong reason — the CI box this suite runs on
      happens to *have* a working RIPEMD160, so the selection made at import
      here is the fast path.

    A failure under this fixture therefore means exactly one thing: that code
    path reaches ``hashlib`` directly instead of going through ``pyrxd.hash``.
    """
    import pyrxd.hash as pyrxd_hash

    real_new = hashlib.new

    def refusing_new(name, *args, **kwargs):
        if name.lower().replace("-", "") == "ripemd160":
            raise ValueError("unsupported hash type ripemd160")
        return real_new(name, *args, **kwargs)

    monkeypatch.setattr(hashlib, "new", refusing_new)
    monkeypatch.setattr(pyrxd_hash, "_ripemd160_impl", pyrxd_hash._ripemd160_pure_python)
    return refusing_new


class TestHash160SurvivesAnOpenSSL3Box:
    def test_the_fixture_really_breaks_hashlib(self, openssl3_without_legacy_provider):
        """Control. Without this the tests below could pass vacuously."""
        with pytest.raises(ValueError):
            hashlib.new("ripemd160", b"")

    def test_the_canonical_helper_still_works(self, openssl3_without_legacy_provider):
        """The other control: ``pyrxd.hash.hash160`` is fine on such a box, so
        every failure below is a bypass and not an environment problem."""
        assert hash160(b"pyrxd") == ripemd160(hashlib.sha256(b"pyrxd").digest())

    def test_the_pure_python_fallback_matches_the_reference_vector(self):
        from pyrxd.hash import _ripemd160_pure_python

        assert _ripemd160_pure_python(b"").hex() == "9c1185a5c5e9fc54612808977ee8f548b2258d31"
        assert _ripemd160_pure_python(b"abc").hex() == "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"

    def test_p2sh_script_pubkey_derivation_has_a_fallback(self, openssl3_without_legacy_provider):
        """``gravity/codehash.py`` derives the P2SH scriptPubKey the Gravity
        claim path pays to. A direct ``hashlib.new`` here is a hard failure on
        any OpenSSL-3 box, not a degraded mode."""
        from pyrxd.gravity.codehash import compute_p2sh_script_pubkey

        spk = compute_p2sh_script_pubkey(b"\x51")
        assert len(spk) == 23 and spk[0] == 0xA9

    def test_the_gravity_hash160_helper_has_a_fallback(self, openssl3_without_legacy_provider):
        from pyrxd.gravity.codehash import hash160 as gravity_hash160

        assert gravity_hash160(b"pyrxd") == hash160(b"pyrxd")

    def test_btc_p2pkh_address_derivation_has_a_fallback(self, openssl3_without_legacy_provider):
        from pyrxd.btc_wallet.keys import _hash160 as btc_hash160

        assert btc_hash160(b"pyrxd") == hash160(b"pyrxd")


class TestEveryHash160SpellingAgrees:
    @pytest.mark.parametrize("payload", [b"", b"a", b"pyrxd", bytes(range(256))])
    def test_all_of_them_produce_the_same_digest(self, payload):
        from pyrxd.btc_wallet.keys import _hash160 as btc_hash160
        from pyrxd.gravity.codehash import hash160 as gravity_hash160

        expected = ripemd160(hashlib.sha256(payload).digest())
        assert hash160(payload) == expected
        assert btc_hash160(payload) == expected
        assert gravity_hash160(payload) == expected


class TestEveryHash256SpellingAgrees:
    @pytest.mark.parametrize("payload", [b"", b"a", b"pyrxd", bytes(range(256))])
    def test_all_of_them_produce_the_same_digest(self, payload):
        """Every module-level ``hash256``/``_hash256`` in ``src/``.

        They were nine separate definitions of ``sha256(sha256(x))``. Agreement
        today is not the point — the point is that after the consolidation there
        is only one object for them to disagree about, and this test names the
        list so a tenth is a deliberate addition.
        """
        from pyrxd.btc_wallet.payment import _hash256 as payment_hash256
        from pyrxd.btc_wallet.taproot import _hash256 as taproot_hash256
        from pyrxd.gravity.codehash import hash256 as codehash_hash256
        from pyrxd.gravity.htlc_covenant import _hash256 as htlc_hash256
        from pyrxd.network.bitcoin import _hash256 as bitcoin_hash256
        from pyrxd.spv.pow import hash256 as pow_hash256

        expected = hashlib.sha256(hashlib.sha256(payload).digest()).digest()
        for name, fn in [
            ("pyrxd.hash.hash256", hash256),
            ("spv.pow.hash256", pow_hash256),
            ("btc_wallet.payment._hash256", payment_hash256),
            ("btc_wallet.taproot._hash256", taproot_hash256),
            ("gravity.codehash.hash256", codehash_hash256),
            ("gravity.htlc_covenant._hash256", htlc_hash256),
            ("network.bitcoin._hash256", bitcoin_hash256),
        ]:
            assert fn(payload) == expected, name

    def test_they_are_literally_the_same_object(self):
        """Equal outputs can still drift; the same object cannot.

        ``spv.pow.hash256`` and ``gravity.codehash.hash256`` are public names in
        their modules' ``__all__``, so they stay as re-exports rather than being
        deleted — but they must be re-exports, not re-implementations.
        """
        from pyrxd.gravity.codehash import hash256 as codehash_hash256
        from pyrxd.spv.pow import hash256 as pow_hash256

        assert pow_hash256 is hash256
        assert codehash_hash256 is hash256


class TestTheBlockHashIsADifferentFunction:
    """SHA-256d and Radiant's block hash must never be folded together.

    ``network/registry.py`` computes the header hash as a double SHA-512/256.
    Consolidating it onto ``hash256`` would produce a plausible-looking 32-byte
    digest that is not the block's id, and every header check built on it would
    silently compare the wrong value.
    """

    def test_the_radiant_block_hash_is_not_sha256d(self):
        from pyrxd.network.registry import block_hash_hex

        header = bytes(range(80))
        assert block_hash_hex(header) != hash256(header)[::-1].hex()

    def test_the_radiant_block_hash_is_double_sha512_256(self):
        from pyrxd.network.registry import block_hash_hex

        header = bytes(range(80))
        once = hashlib.new("sha512_256", header).digest()
        twice = hashlib.new("sha512_256", once).digest()
        assert block_hash_hex(header) == twice[::-1].hex()
