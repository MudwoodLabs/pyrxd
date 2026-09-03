"""The key -> name bridge, and the gate in front of it.

A HashMark v2 signer is a hash160, which is what a P2PKH address encodes, and
WAVE resolves names to addresses. So a verified signature can answer the question
a recipient actually has: *was this recorded by the holder of `company.rxd`?*

The gate matters more than the lookup. Resolving an UNVERIFIED signer would dress
a claim up as an identity — anyone can put someone else's hash160 in a record —
which is the exact failure the signature check exists to prevent.
"""

from __future__ import annotations

import pytest

from pyrxd.glyph.wave import wave_names_for_hash160
from pyrxd.keys import PrivateKey
from pyrxd.security.errors import ValidationError


class _FakeIndexer:
    """A fake at the REAL seam — the transport `RxinDexerClient` calls.

    `WaveResolver` wraps anything that is not already an `RxinDexerClient` in one,
    so faking `wave_reverse_lookup` would bypass the wrapper the production path
    actually goes through. Faking `call_extension` exercises it.
    """

    def __init__(self, names: dict[str, list[str]] | None = None) -> None:
        self.names = names or {}
        self.asked: list[str] = []

    async def call_extension(self, method: str, params: list):
        assert method == "wave.reverse_lookup", method
        address = params[0]
        self.asked.append(address)
        return self.names.get(address, [])


class TestTheKeyToNameBridge:
    @pytest.mark.asyncio
    async def test_it_looks_up_the_signers_own_address(self) -> None:
        """The join is hash160 -> address -> names, and the address must be the
        one the signing key actually encodes."""
        key = PrivateKey()
        addr = key.public_key().address()
        idx = _FakeIndexer({addr: ["company.rxd", "invoices.company.rxd"]})

        names = await wave_names_for_hash160(idx, key.public_key().hash160())

        assert idx.asked == [addr], "must derive the signer's own address"
        assert names == ["company.rxd", "invoices.company.rxd"]

    @pytest.mark.asyncio
    async def test_a_key_owning_no_name_returns_empty_not_an_error(self) -> None:
        """Most keys own no WAVE name. That is an answer, not a failure."""
        idx = _FakeIndexer()
        assert await wave_names_for_hash160(idx, PrivateKey().public_key().hash160()) == []

    @pytest.mark.asyncio
    @pytest.mark.parametrize("bad", [b"", b"\x11" * 19, b"\x11" * 21])
    async def test_a_wrong_width_hash_is_refused(self, bad: bytes) -> None:
        with pytest.raises(ValidationError, match="20 bytes"):
            await wave_names_for_hash160(_FakeIndexer(), bad)


class TestTheGateInFrontOfIt:
    """`_attach_wave_identity` must never resolve an unproven signer."""

    @staticmethod
    def _payload(outcome: str | None) -> dict:
        hm: dict = {"version": 2, "signer_hash160": "aa" * 20}
        if outcome is not None:
            hm["attestation"] = {"outcome": outcome, "recovered_hash160": "aa" * 20}
        return {"hashmark": hm}

    @pytest.mark.parametrize(
        ("outcome", "expect"),
        [
            ("invalid_signature", "unproven signer"),
            ("not_attested", "no verified v2 signature"),
            (None, "no verified v2 signature"),
        ],
    )
    def test_an_unverified_signature_is_NOT_resolved(self, outcome, expect: str) -> None:
        """No network call, and a reason the operator can read."""
        from pyrxd.cli.glyph_inspect import _attach_wave_identity

        payload = self._payload(outcome)
        # ctx is never used on this path — reaching for it would mean the gate failed.
        _attach_wave_identity(None, payload)  # type: ignore[arg-type]

        wi = payload["hashmark"]["wave_identity"]
        assert wi["resolved"] is False
        assert expect in wi["reason"]

    def test_a_payload_with_no_hashmark_is_untouched(self) -> None:
        from pyrxd.cli.glyph_inspect import _attach_wave_identity

        payload: dict = {"type": "op_return"}
        _attach_wave_identity(None, payload)  # type: ignore[arg-type]
        assert payload == {"type": "op_return"}
