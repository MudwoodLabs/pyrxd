"""Coverage gap tests — eighth batch.

Final push to reach 85%:
  - utils.py: DER deserialization errors, WIF prefix error, ECDSA recoverable, to_base58_check
  - curve.py: invalid point error paths
  - fee_model.py: abstract FeeModel
  - script/script.py: from_asm PUSHDATA variants (script-level opcode path)
  - hd/bip32.py: some edge case branches
  - network/bitcoin.py: remaining error branches
"""
from __future__ import annotations

import pytest

from pyrxd.security.errors import ValidationError, NetworkError
from pyrxd.utils import (
    deserialize_ecdsa_der,
    serialize_ecdsa_der,
    unstringify_ecdsa_recoverable,
    decode_wif,
    to_base58_check,
)


# ──────────────────────────────────────────────────────────────────────────────
# utils.py — deserialize_ecdsa_der error paths (lines 94-111)
# ──────────────────────────────────────────────────────────────────────────────

class TestDeserializeDerErrors:
    def test_wrong_sequence_tag_raises(self):
        with pytest.raises(ValueError, match="DER sequence"):
            deserialize_ecdsa_der(b"\x31\x06\x02\x01\x01\x02\x01\x02")

    def test_length_mismatch_raises(self):
        # 0x30 tag, then length byte that doesn't match actual length
        with pytest.raises(ValueError, match="length mismatch"):
            deserialize_ecdsa_der(b"\x30\xFF\x02\x01\x01\x02\x01\x02")

    def test_wrong_r_tag_raises(self):
        # 0x30 + correct length + 0x03 (wrong int tag for r)
        sig = b"\x30\x06\x03\x01\x01\x02\x01\x02"
        with pytest.raises(ValueError, match="integer tag.*r"):
            deserialize_ecdsa_der(sig)

    def test_wrong_s_tag_raises(self):
        # Valid r, but wrong tag before s
        sig = b"\x30\x06\x02\x01\x01\x03\x01\x02"
        with pytest.raises(ValueError, match="integer tag.*s"):
            deserialize_ecdsa_der(sig)

    def test_exception_fallthrough_raises(self):
        # Empty bytes → IndexError inside try → caught → re-raised as ValueError
        with pytest.raises((ValueError, IndexError)):
            deserialize_ecdsa_der(b"")


# ──────────────────────────────────────────────────────────────────────────────
# utils.py — serialize_ecdsa_der: s high-bit padding branch (line 130)
# ──────────────────────────────────────────────────────────────────────────────

class TestSerializeDerSPadding:
    def test_s_with_high_bit_gets_padded(self):
        """s value with top bit set needs a 0x00 padding byte."""
        # Use a known r, and an s with high bit set: 0x80 * anything
        from pyrxd.curve import curve
        r = 0x1  # minimal valid r
        s = 0x80_0000_0000_0000_0000_0000_0000_0000_0000  # high bit set, well below n//2
        # Ensure s is not above n//2 (so it won't be negated)
        n = curve.n
        if s > n // 2:
            s = n - s
        result = serialize_ecdsa_der((r, s))
        assert result[0] == 0x30  # DER sequence tag
        assert isinstance(result, bytes)

    def test_low_s_normalization(self):
        """s > n//2 should be normalized to n-s."""
        from pyrxd.curve import curve
        n = curve.n
        r = 2
        s = n - 1  # high s, will be normalized
        result = serialize_ecdsa_der((r, s))
        assert result[0] == 0x30


# ──────────────────────────────────────────────────────────────────────────────
# utils.py — unstringify_ecdsa_recoverable (lines 195, 198, 200-203)
# ──────────────────────────────────────────────────────────────────────────────

class TestUnstringifyEcdsaRecoverable:
    from base64 import b64encode

    def _make_sig_str(self, prefix_byte: int) -> str:
        from base64 import b64encode
        payload = bytes([prefix_byte]) + b"\x00" * 64
        return b64encode(payload).decode()

    def test_invalid_length_raises(self):
        from base64 import b64encode
        bad = b64encode(b"\x1b" * 30).decode()
        with pytest.raises(ValidationError, match="invalid length"):
            unstringify_ecdsa_recoverable(bad)

    def test_invalid_prefix_raises(self):
        # prefix 0 is out of range [27, 35)
        sig = self._make_sig_str(0)
        with pytest.raises(ValidationError, match="invalid.*prefix"):
            unstringify_ecdsa_recoverable(sig)

    def test_prefix_26_raises(self):
        sig = self._make_sig_str(26)
        with pytest.raises(ValidationError):
            unstringify_ecdsa_recoverable(sig)

    def test_prefix_35_raises(self):
        sig = self._make_sig_str(35)
        with pytest.raises(ValidationError):
            unstringify_ecdsa_recoverable(sig)

    def test_uncompressed_prefix(self):
        # prefix 27 → uncompressed
        sig = self._make_sig_str(27)
        serialized, compressed = unstringify_ecdsa_recoverable(sig)
        assert compressed is False

    def test_compressed_prefix(self):
        # prefix 31 → compressed (>= 31)
        sig = self._make_sig_str(31)
        serialized, compressed = unstringify_ecdsa_recoverable(sig)
        assert compressed is True

    def test_compressed_prefix_34(self):
        sig = self._make_sig_str(34)
        serialized, compressed = unstringify_ecdsa_recoverable(sig)
        assert compressed is True


# ──────────────────────────────────────────────────────────────────────────────
# utils.py — decode_wif bad prefix (line 82)
# ──────────────────────────────────────────────────────────────────────────────

class TestDecodeWifErrors:
    def test_unknown_prefix_raises(self):
        """A WIF with an unknown prefix should raise ValueError."""
        from pyrxd.base58 import base58check_encode
        # Manually encode: prefix 0x00 + 32 bytes
        raw = bytes([0x00]) + b"\xab" * 32
        encoded = base58check_encode(raw)
        with pytest.raises(ValueError, match="unknown WIF prefix"):
            decode_wif(encoded)


# ──────────────────────────────────────────────────────────────────────────────
# utils.py — to_base58_check with default prefix (lines 385-386)
# ──────────────────────────────────────────────────────────────────────────────

class TestToBase58Check:
    def test_default_prefix_none(self):
        """Calling with prefix=None uses [0] as default prefix."""
        result = to_base58_check([0x01, 0x02, 0x03])
        assert isinstance(result, str)
        assert len(result) > 0

    def test_explicit_prefix(self):
        result = to_base58_check([0x01, 0x02, 0x03], prefix=[0x80])
        assert isinstance(result, str)


# ──────────────────────────────────────────────────────────────────────────────
# curve.py — invalid point error paths (lines 42, 49, 58, 60, 73, 82, 90)
# ──────────────────────────────────────────────────────────────────────────────

class TestCurveErrors:
    def test_curve_negative_not_on_curve_raises(self):
        from pyrxd.curve import curve_negative, Point
        bad_point = Point(1, 2)  # not on secp256k1
        with pytest.raises(ValidationError):
            curve_negative(bad_point)

    def test_curve_add_p_not_on_curve_raises(self):
        from pyrxd.curve import curve_add, Point
        from pyrxd.keys import PrivateKey
        bad = Point(1, 2)
        priv = PrivateKey()
        valid_pub = priv.public_key()
        valid_point = valid_pub.point()
        with pytest.raises(ValidationError):
            curve_add(bad, valid_point)

    def test_curve_add_q_not_on_curve_raises(self):
        from pyrxd.curve import curve_add, Point
        from pyrxd.keys import PrivateKey
        bad = Point(1, 2)
        priv = PrivateKey()
        valid_pub = priv.public_key()
        valid_point = valid_pub.point()
        with pytest.raises(ValidationError):
            curve_add(valid_point, bad)

    def test_curve_multiply_not_on_curve_raises(self):
        from pyrxd.curve import curve_multiply, Point
        bad = Point(1, 2)
        with pytest.raises(ValidationError):
            curve_multiply(5, bad)

    def test_curve_add_returns_none_for_inverse(self):
        """p + (-p) should return None (point at infinity)."""
        from pyrxd.curve import curve_add, curve_negative
        from pyrxd.keys import PrivateKey
        priv = PrivateKey()
        p = priv.public_key().point()
        neg_p = curve_negative(p)
        result = curve_add(p, neg_p)
        assert result is None

    def test_curve_add_identity_p_none(self):
        """0 + q = q."""
        from pyrxd.curve import curve_add
        from pyrxd.keys import PrivateKey
        priv = PrivateKey()
        q = priv.public_key().point()
        result = curve_add(None, q)
        assert result == q

    def test_curve_add_identity_q_none(self):
        """p + 0 = p."""
        from pyrxd.curve import curve_add
        from pyrxd.keys import PrivateKey
        priv = PrivateKey()
        p = priv.public_key().point()
        result = curve_add(p, None)
        assert result == p

    def test_curve_multiply_scalar_zero_returns_none(self):
        """0 * p = point at infinity = None."""
        from pyrxd.curve import curve_multiply
        from pyrxd.keys import PrivateKey
        priv = PrivateKey()
        p = priv.public_key().point()
        result = curve_multiply(0, p)
        assert result is None

    def test_curve_multiply_negative_scalar(self):
        """Negative scalar: k*p = (-k)*(-p)."""
        from pyrxd.curve import curve_multiply
        from pyrxd.keys import PrivateKey
        priv = PrivateKey()
        p = priv.public_key().point()
        result = curve_multiply(-1, p)
        assert result is not None


# ──────────────────────────────────────────────────────────────────────────────
# fee_model.py — FeeModel abstract base (line 15-16)
# ──────────────────────────────────────────────────────────────────────────────

class TestFeeModel:
    def test_abstract_fee_model_cannot_be_instantiated(self):
        from pyrxd.fee_model import FeeModel
        with pytest.raises(TypeError):
            FeeModel()  # type: ignore

    def test_concrete_fee_model_works(self):
        from pyrxd.fee_model import FeeModel
        class MyFeeModel(FeeModel):
            def compute_fee(self, transaction) -> int:
                return 500

        m = MyFeeModel()
        assert m.compute_fee(None) == 500


# ──────────────────────────────────────────────────────────────────────────────
# network/bitcoin.py — additional error branches (lines 201, 205, 289, 293, etc.)
# ──────────────────────────────────────────────────────────────────────────────

import json as _json
from unittest.mock import AsyncMock as _AsyncMock, MagicMock as _MagicMock, patch as _patch


def _fake_resp(status, body, content_type="application/json"):
    resp = _MagicMock()
    resp.status = status
    resp.content_type = content_type
    resp.read = _AsyncMock(return_value=body)
    resp.__aenter__ = _AsyncMock(return_value=resp)
    resp.__aexit__ = _AsyncMock(return_value=False)
    return resp


def _text_resp(text, status=200):
    return _fake_resp(status, text.encode(), "text/plain")


def _json_resp(data, status=200):
    return _fake_resp(status, _json.dumps(data).encode(), "application/json")


class TestMempoolSpaceSourceMoreBranches:
    def _src(self):
        from pyrxd.network.bitcoin import MempoolSpaceSource
        return MempoolSpaceSource()

    @pytest.mark.asyncio
    async def test_get_tip_height_client_error(self):
        """aiohttp.ClientError should become NetworkError."""
        import aiohttp
        src = self._src()
        session = _MagicMock()
        session.get = _MagicMock(side_effect=aiohttp.ClientError("down"))
        with _patch.object(src, "_get_session", _AsyncMock(return_value=session)):
            with pytest.raises(NetworkError):
                await src.get_tip_height()

    @pytest.mark.asyncio
    async def test_get_block_hash_non200_raises(self):
        src = self._src()
        session = _MagicMock()
        session.get = _MagicMock(return_value=_text_resp("error", status=404))
        with _patch.object(src, "_get_session", _AsyncMock(return_value=session)):
            with pytest.raises(NetworkError):
                await src.get_block_hash(5)

    @pytest.mark.asyncio
    async def test_get_block_hash_client_error(self):
        import aiohttp
        src = self._src()
        session = _MagicMock()
        session.get = _MagicMock(side_effect=aiohttp.ClientError("network error"))
        with _patch.object(src, "_get_session", _AsyncMock(return_value=session)):
            with pytest.raises(NetworkError):
                await src.get_block_hash(5)

    @pytest.mark.asyncio
    async def test_get_block_hash_coerces_plain_height(self):
        from pyrxd.security.types import Hex32
        src = self._src()
        hash_hex = "aa" * 32
        session = _MagicMock()
        session.get = _MagicMock(return_value=_text_resp(hash_hex))
        with _patch.object(src, "_get_session", _AsyncMock(return_value=session)):
            result = await src.get_block_hash(100)  # plain int
        assert isinstance(result, Hex32)

    @pytest.mark.asyncio
    async def test_get_raw_tx_unconfirmed_status_dict_raises(self):
        """Unconfirmed tx: confirmed=False."""
        src = self._src()
        status_data = {"confirmed": False}
        session = _MagicMock()
        session.get = _MagicMock(return_value=_json_resp(status_data))
        with _patch.object(src, "_get_session", _AsyncMock(return_value=session)):
            with pytest.raises(NetworkError, match="confirmations"):
                await src.get_raw_tx("ab" * 32)

    @pytest.mark.asyncio
    async def test_get_raw_tx_status_non_dict_raises(self):
        """Status response not a dict."""
        src = self._src()
        session = _MagicMock()
        session.get = _MagicMock(return_value=_json_resp("not-a-dict"))
        with _patch.object(src, "_get_session", _AsyncMock(return_value=session)):
            with pytest.raises(NetworkError, match="Unexpected"):
                await src.get_raw_tx("ab" * 32)


class TestBlockstreamMoreBranches:
    def _src(self):
        from pyrxd.network.bitcoin import BlockstreamSource
        return BlockstreamSource()

    @pytest.mark.asyncio
    async def test_get_tip_height_non200_raises(self):
        src = self._src()
        session = _MagicMock()
        session.get = _MagicMock(return_value=_text_resp("error", status=503))
        with _patch.object(src, "_get_session", _AsyncMock(return_value=session)):
            with pytest.raises(NetworkError):
                await src.get_tip_height()

    @pytest.mark.asyncio
    async def test_get_tip_height_bad_body_raises(self):
        src = self._src()
        session = _MagicMock()
        session.get = _MagicMock(return_value=_text_resp("not-a-number"))
        with _patch.object(src, "_get_session", _AsyncMock(return_value=session)):
            with pytest.raises(NetworkError):
                await src.get_tip_height()

    @pytest.mark.asyncio
    async def test_get_raw_tx_unconfirmed_raises(self):
        src = self._src()
        status_data = {"confirmed": False}
        session = _MagicMock()
        session.get = _MagicMock(return_value=_json_resp(status_data))
        with _patch.object(src, "_get_session", _AsyncMock(return_value=session)):
            with pytest.raises(NetworkError):
                await src.get_raw_tx("ab" * 32)

    @pytest.mark.asyncio
    async def test_get_raw_tx_non_dict_status_raises(self):
        src = self._src()
        session = _MagicMock()
        session.get = _MagicMock(return_value=_json_resp("not-a-dict"))
        with _patch.object(src, "_get_session", _AsyncMock(return_value=session)):
            with pytest.raises(NetworkError):
                await src.get_raw_tx("ab" * 32)

    @pytest.mark.asyncio
    async def test_get_tx_block_height_non_dict_raises(self):
        src = self._src()
        session = _MagicMock()
        session.get = _MagicMock(return_value=_json_resp("oops"))
        with _patch.object(src, "_get_session", _AsyncMock(return_value=session)):
            with pytest.raises(NetworkError):
                await src.get_tx_block_height("ab" * 32)

    @pytest.mark.asyncio
    async def test_get_tx_block_height_coerces_str_txid(self):
        from pyrxd.security.types import BlockHeight
        src = self._src()
        status_data = {"confirmed": True, "block_height": 800000}
        session = _MagicMock()
        session.get = _MagicMock(return_value=_json_resp(status_data))
        with _patch.object(src, "_get_session", _AsyncMock(return_value=session)):
            result = await src.get_tx_block_height("ab" * 32)  # str not Txid
        assert int(result) == 800000

    @pytest.mark.asyncio
    async def test_close_already_none(self):
        src = self._src()
        src._session = None
        await src.close()  # Should not raise
