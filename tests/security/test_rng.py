"""Tests for pyrxd.security.rng."""

from __future__ import annotations

import pytest

from pyrxd.security.rng import secure_random_bytes
from pyrxd.security.secrets import PrivateKeyMaterial, secure_scalar_mod_n

# secp256k1 curve order
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


class TestSecureRandomBytes:
    def test_returns_correct_length(self) -> None:
        for n in (1, 16, 32, 64, 128):
            data = secure_random_bytes(n)
            assert len(data) == n
            assert isinstance(data, bytes)

    def test_rejects_zero(self) -> None:
        with pytest.raises(ValueError):
            secure_random_bytes(0)

    def test_rejects_negative(self) -> None:
        with pytest.raises(ValueError):
            secure_random_bytes(-1)
        with pytest.raises(ValueError):
            secure_random_bytes(-100)

    def test_rejects_non_int(self) -> None:
        with pytest.raises(TypeError):
            secure_random_bytes(16.0)  # type: ignore[arg-type]
        with pytest.raises(TypeError):
            secure_random_bytes("16")  # type: ignore[arg-type]

    def test_produces_different_values(self) -> None:
        # Two 32-byte draws must not collide.
        a = secure_random_bytes(32)
        b = secure_random_bytes(32)
        assert a != b


class TestSecureScalarModN:
    def test_returns_private_key_material(self) -> None:
        pk = secure_scalar_mod_n()
        assert isinstance(pk, PrivateKeyMaterial)

    def test_scalar_in_valid_range(self) -> None:
        # Run many times: every output must be in [1, N-1].
        for _ in range(20):
            pk = secure_scalar_mod_n()
            assert len(pk) == 32
            scalar = int.from_bytes(pk.unsafe_raw_bytes(), "big")
            assert 1 <= scalar < _N

    def test_statistical_uniqueness(self) -> None:
        # 100 draws from a 256-bit uniform -> the birthday bound says
        # collision probability is ~100^2 / 2^257, which is astronomically
        # small. Any collision indicates a broken RNG.
        values = {secure_scalar_mod_n().unsafe_raw_bytes() for _ in range(100)}
        assert len(values) == 100


class TestSecureScalarModNRejectionSampling:
    def test_rejection_sampling_handles_out_of_range(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Feed one out-of-range candidate, then a valid one. The function
        # must loop past the bad draw.
        invalid = (_N).to_bytes(32, "big")  # scalar = N (invalid)
        valid = (42).to_bytes(32, "big")
        seq = iter([invalid, valid])

        from pyrxd.security import rng as rng_mod

        def fake_srb(n: int) -> bytes:
            return next(seq)

        monkeypatch.setattr(rng_mod, "secure_random_bytes", fake_srb)
        pk = PrivateKeyMaterial(rng_mod.secure_scalar_bytes_mod_n())
        assert int.from_bytes(pk.unsafe_raw_bytes(), "big") == 42

    def test_rejection_sampling_rejects_zero(self, monkeypatch: pytest.MonkeyPatch) -> None:
        zero = b"\x00" * 32
        valid = (1).to_bytes(32, "big")
        seq = iter([zero, valid])

        from pyrxd.security import rng as rng_mod

        def fake_srb(n: int) -> bytes:
            return next(seq)

        monkeypatch.setattr(rng_mod, "secure_random_bytes", fake_srb)
        pk = PrivateKeyMaterial(rng_mod.secure_scalar_bytes_mod_n())
        assert int.from_bytes(pk.unsafe_raw_bytes(), "big") == 1

    def test_rejection_sampling_exhaustion_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # If every draw is invalid (broken RNG simulation), the function
        # must raise RuntimeError rather than loop forever.
        from pyrxd.security import rng as rng_mod

        def always_zero(n: int) -> bytes:
            return b"\x00" * 32

        monkeypatch.setattr(rng_mod, "secure_random_bytes", always_zero)
        with pytest.raises(RuntimeError, match="RNG"):
            rng_mod.secure_scalar_bytes_mod_n()
