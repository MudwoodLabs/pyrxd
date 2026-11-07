"""``docs/inspect_static/playground/sandbox_curve.py`` against the real coincurve.

The playground signs with a pure-Python stand-in because coincurve has no Pyodide build.
Each entry point ``src/pyrxd/keys.py`` and ``src/pyrxd/curve.py`` reaches is compared here
with libsecp256k1 through coincurve, on fresh random keys and messages. Both sign with
RFC 6979 and normalise to low-s, so signatures must be BYTE-identical, not merely valid.

Keys here are generated (``os.urandom``), never written out, and hold nothing.
"""

from __future__ import annotations

import hashlib
import importlib.util
import os
import random
from pathlib import Path

import coincurve
import pytest
from coincurve.ecdsa import der_to_cdata

_PATH = Path(__file__).resolve().parents[2] / "docs" / "inspect_static" / "playground" / "sandbox_curve.py"
N_CASES = 64


@pytest.fixture(scope="module")
def sc():
    spec = importlib.util.spec_from_file_location("sandbox_curve_under_test", _PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def cases():
    rng = random.Random(os.urandom(8))
    out = []
    for _ in range(N_CASES):
        out.append((coincurve.PrivateKey().secret, os.urandom(rng.randrange(0, 120))))
    return out


def test_public_keys_match(sc, cases):
    for secret, _ in cases:
        real, ours = coincurve.PrivateKey(secret), sc.PrivateKey(secret)
        assert real.public_key.format() == ours.public_key.format()
        assert real.public_key.format(False) == ours.public_key.format(False)
        assert real.public_key.point() == ours.public_key.point()
        assert real.to_int() == ours.to_int()


@pytest.mark.parametrize(
    "hasher",
    [lambda m: hashlib.sha256(m).digest(), None, lambda m: hashlib.sha256(hashlib.sha256(m).digest()).digest()],
)
def test_signatures_are_byte_identical(sc, cases, hasher):
    for secret, msg in cases:
        if hasher is None:
            msg = hashlib.sha256(msg).digest()
        real, ours = coincurve.PrivateKey(secret), sc.PrivateKey(secret)
        assert real.sign(msg, hasher) == ours.sign(msg, hasher)
        assert real.sign_recoverable(msg, hasher) == ours.sign_recoverable(msg, hasher)


def test_verify_and_recover_agree(sc, cases):
    for secret, msg in cases:
        real = coincurve.PrivateKey(secret)
        sig = real.sign(msg)
        ours_pub = sc.PublicKey(real.public_key.format())
        assert ours_pub.verify(sig, msg) is True
        assert ours_pub.verify(sig, msg + b"x") is False
        rec = real.sign_recoverable(msg)
        assert sc.PublicKey.from_signature_and_message(rec, msg).format() == real.public_key.format()


def test_high_s_does_not_verify_in_either(sc, cases):
    secret, msg = cases[0]
    real = coincurve.PrivateKey(secret)
    r, s = sc.der_to_cdata(real.sign(msg))
    high = sc.cdata_to_der((r, sc.N - s))
    assert real.public_key.verify(high, msg) is False
    assert sc.PublicKey(real.public_key.format()).verify(high, msg) is False


def _accepts(fn, data) -> bool:
    try:
        fn(data)
    except ValueError:
        return False
    return True


def test_der_parse_accepts_and_refuses_what_libsecp256k1_does(sc, cases):
    """Bit flips, truncations, extensions and junk: the same accept/reject, and the same verdict."""
    rng = random.Random(os.urandom(8))
    checked = 0
    for secret, msg in cases:
        real = coincurve.PrivateKey(secret)
        sig = real.sign(msg)
        variants = [sig[:n] for n in range(len(sig))] + [sig + b"\x00", os.urandom(rng.randrange(0, 80))]
        for _ in range(40):
            b = bytearray(sig)
            b[rng.randrange(len(b))] ^= 1 << rng.randrange(8)
            variants.append(bytes(b))
        for v in variants:
            a, o = _accepts(der_to_cdata, v), _accepts(sc.der_to_cdata, v)
            assert a == o, v.hex()
            if a:
                assert real.public_key.verify(v, msg) == sc.PublicKey(real.public_key.format()).verify(v, msg), v.hex()
            checked += 1
    assert checked > N_CASES * 40


def test_point_operations_match(sc, cases):
    for secret, _ in cases[:16]:
        real = coincurve.PrivateKey(secret).public_key
        ours = sc.PublicKey(real.format())
        k = coincurve.PrivateKey().secret
        assert real.multiply(k).format() == ours.multiply(k).format()
        other = coincurve.PrivateKey().public_key
        assert real.combine([other]).format() == ours.combine([sc.PublicKey(other.format())]).format()
        tweak = coincurve.PrivateKey().secret
        assert real.add(tweak).format() == ours.add(tweak).format()
        x, y = real.point()
        assert sc.PublicKey.from_point(x, y).format() == coincurve.PublicKey.from_point(x, y).format()


def test_bad_public_keys_are_refused_like_coincurve(sc):
    good = coincurve.PrivateKey().public_key.format()
    bad = [b"", good[:-1], b"\x05" + good[1:], b"\x02" + b"\xff" * 32, b"\x04" + b"\x00" * 64]
    for v in [*bad, good, coincurve.PrivateKey().public_key.format(False)]:
        assert _accepts(coincurve.PublicKey, v) == _accepts(sc.PublicKey, v), v.hex()


def test_secret_range_is_enforced_like_coincurve(sc):
    for v in [b"\x00" * 32, sc.N.to_bytes(32, "big"), (sc.N - 1).to_bytes(32, "big"), b"\x01"]:
        assert _accepts(coincurve.PrivateKey, v) == _accepts(sc.PrivateKey, v), v.hex()


def test_install_refuses_when_the_real_library_is_present(sc):
    with pytest.raises(RuntimeError, match="real coincurve"):
        sc.install()


def test_a_prehashed_digest_at_or_above_the_order_signs_as_libsecp256k1_does(sc):
    """libsecp256k1 reduces the digest mod n before seeding RFC 6979 (review F5)."""
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    rng = random.Random(949)
    digests = [n.to_bytes(32, "big"), (n + 1).to_bytes(32, "big"), b"\xff" * 32]
    digests += [(n + rng.randrange(2**256 - n)).to_bytes(32, "big") for _ in range(5)]
    for _ in range(3):
        secret = os.urandom(32)
        real, ours = coincurve.PrivateKey(secret), sc.PrivateKey(secret)
        for d in digests:
            assert ours.sign(d, hasher=None) == real.sign(d, hasher=None), d.hex()
            assert ours.sign_recoverable(d, hasher=None) == real.sign_recoverable(d, hasher=None), d.hex()


def test_a_secret_longer_than_32_bytes_is_refused(sc):
    """Deliberately stricter than coincurve, which takes b'\\x00' + k and signs as another key."""
    k = os.urandom(31) + b"\x01"
    assert coincurve.PrivateKey(b"\x00" + k).public_key.format() != coincurve.PrivateKey(k).public_key.format()
    with pytest.raises(ValueError):
        sc.PrivateKey(b"\x00" + k)
    assert sc.PrivateKey(k).public_key.format() == coincurve.PrivateKey(k).public_key.format()
