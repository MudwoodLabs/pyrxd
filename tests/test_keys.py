import pytest

from pyrxd.keys import PrivateKey, PublicKey
from pyrxd.security.errors import ValidationError

# secp256k1 curve order
_SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def test_import_private_key_and_verify():
    priv_key_hex = "E9873D79C6D87DC0FB6A5778633389F4453213303DA61F20BD67FC233AA33262"
    
    key = PrivateKey.from_hex(priv_key_hex)

    assert key.hex() == priv_key_hex.lower()

def test_private_key_to_wif_verify():
    priv_key_hex = "0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D"
    
    key = PrivateKey.from_hex(priv_key_hex)
    
    # Test uncompressed WIF
    key.compressed = False
    wif = key.wif()
    assert wif == "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"
    
    # Test compressed WIF
    key.compressed = True
    wif2 = key.wif()
    assert wif2 == "KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617"

def test_wif_to_private_key_uncompressed():
    wif = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"
    
    key = PrivateKey(wif)
    
    private_key_hex = key.hex()
    
    assert private_key_hex == "0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d"
    assert key.compressed is False

def test_wif_to_private_key_compressed():
    wif = "L5EZftvrYaSudiozVRzTqLcHLNDoVn7H5HSfM9BAN6tMJX8oTWz6"
    
    key = PrivateKey(wif)
    
    private_key_hex = key.hex()
    
    assert private_key_hex == "ef235aacf90d9f4aadd8c92e4b2562e1d9eb97f0df9ba3b508258739cb013db2"
    assert key.compressed is True


def test_pub_key_from_private_key():
    private_key = PrivateKey.from_hex("E9873D79C6D87DC0FB6A5778633389F4453213303DA61F20BD67FC233AA33262")
    
    pub_key = private_key.public_key()
    pub_key_hex = pub_key.hex()
    
    assert pub_key_hex == "02588d202afcc1ee4ab5254c7847ec25b9a135bbda0f2bc69ee1a714749fd77dc9"

def test_pub_key_from_hex():
    pub_key = PublicKey("02588d202afcc1ee4ab5254c7847ec25b9a135bbda0f2bc69ee1a714749fd77dc9")

    pub_key_hex = pub_key.hex()

    assert pub_key_hex == "02588d202afcc1ee4ab5254c7847ec25b9a135bbda0f2bc69ee1a714749fd77dc9"


# ── Security hardening tests ─────────────────────────────────────────────────

_TEST_KEY_HEX = "0101010101010101010101010101010101010101010101010101010101010101"


def test_private_key_repr_does_not_leak_key():
    """PrivateKey.__repr__ and __str__ must not contain the key scalar."""
    key = PrivateKey.from_hex(_TEST_KEY_HEX)
    r = repr(key)
    s = str(key)
    assert _TEST_KEY_HEX.lower() not in r.lower()
    assert _TEST_KEY_HEX.lower() not in s.lower()
    # Also verify no WIF (52 chars base58) slips through
    assert key.wif() not in r
    assert key.wif() not in s


def test_wif_encode_decode_round_trip():
    """WIF encode then decode should recover the exact same key bytes."""
    key_bytes = bytes.fromhex(_TEST_KEY_HEX)
    key = PrivateKey(key_bytes)

    wif = key.wif()
    restored = PrivateKey(wif)

    assert restored.hex() == key.hex()
    assert restored.compressed == key.compressed


def test_signing_is_deterministic():
    """Signing the same message twice with the same key must yield the same DER signature."""
    key = PrivateKey.from_hex(_TEST_KEY_HEX)
    message = b"test message for determinism"

    sig1 = key.sign(message)
    sig2 = key.sign(message)

    assert sig1 == sig2, "signature must be deterministic (RFC6979)"


def test_low_s_signature():
    """Signature S value must be in the lower half of the curve order."""
    key = PrivateKey.from_hex(_TEST_KEY_HEX)
    message = b"low s test"

    sig = key.sign(message)

    # DER-decode to extract s
    # DER: 0x30 <len> 0x02 <rlen> <r> 0x02 <slen> <s>
    assert sig[0] == 0x30
    r_len = sig[3]
    s_len = sig[5 + r_len]
    s = int.from_bytes(sig[6 + r_len : 6 + r_len + s_len], "big")

    assert s <= _SECP256K1_N // 2, f"S value {s!r} is not in lower half of curve order"


def test_bip32_sdk_vector_master_key():
    """BIP32 master key from BIP39 'abandon*11 about' (no passphrase) is stable.

    Note: BIP32 spec TV1 uses a 16-byte raw seed; this SDK enforces a 64-byte
    seed (BIP39 PBKDF2 output). Test uses the 64-byte seed derived from the
    same well-known mnemonic, locked for regression.
    """
    from pyrxd.hd.bip32 import Xprv

    # Seed from 'abandon abandon ... about' (12 words, no passphrase)
    seed_hex = "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"  # noqa: E501

    master_xprv = Xprv.from_seed(seed_hex)
    master_xpub = master_xprv.xpub()

    assert master_xprv.serialize() == "xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu"  # noqa: E501
    assert str(master_xpub) == "xpub661MyMwAqRbcFkPHucMnrGNzDwb6teAX1RbKQmqtEF8kK3Z7LZ59qafCjB9eCRLiTVG3uxBxgKvRgbubRhqSKXnGGb1aoaqLrpMBDrVxga8"  # noqa: E501


def test_bip32_sdk_vector_hardened_child():
    """BIP32 m/0' derivation from known 64-byte seed produces a depth-1 key."""
    from pyrxd.hd.bip32 import Xprv, ckd

    seed_hex = "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"  # noqa: E501

    master_xprv = Xprv.from_seed(seed_hex)
    child = ckd(master_xprv, "m/0'")

    assert child.depth == 1
    assert child.serialize().startswith("xprv")
    assert str(child.xpub()).startswith("xpub")


class TestPrivateKeySecurityAudit2026:
    """Regression tests for security audit findings on PrivateKey (2026-04-25)."""

    def test_private_key_not_hashable(self):
        """HIGH: PrivateKey must not be hashable — key in dict/set exposes it to side-channels."""
        k = PrivateKey(0x1111111111111111111111111111111111111111111111111111111111111111)
        with pytest.raises(TypeError, match="unhashable"):
            hash(k)

    def test_private_key_not_picklable(self):
        """HIGH: PrivateKey must not be picklable — serializing defeats in-memory protection."""
        import pickle
        k = PrivateKey(0x1111111111111111111111111111111111111111111111111111111111111111)
        with pytest.raises(TypeError, match="cannot be pickled"):
            pickle.dumps(k)

    def test_private_key_not_copyable(self):
        """HIGH: PrivateKey must not be copy.copy()-able."""
        import copy
        k = PrivateKey(0x1111111111111111111111111111111111111111111111111111111111111111)
        with pytest.raises(TypeError, match="cannot be copied"):
            copy.copy(k)

    def test_private_key_not_deepcopyable(self):
        """HIGH: PrivateKey must not be copy.deepcopy()-able."""
        import copy
        k = PrivateKey(0x1111111111111111111111111111111111111111111111111111111111111111)
        with pytest.raises(TypeError, match="cannot be deep-copied"):
            copy.deepcopy(k)

    def test_sign_k_none_uses_deterministic_path(self):
        """HIGH: sign(k=None) must use deterministic RFC6979 path, not treat None as falsy k."""
        k = PrivateKey(0x1111111111111111111111111111111111111111111111111111111111111111)
        sig1 = k.sign(b"test message")
        sig2 = k.sign(b"test message")
        assert sig1 == sig2  # deterministic

    def test_sign_k_zero_raises(self):
        """HIGH: sign(k=0) must raise (k=0 is invalid), not silently use deterministic path.

        Before the fix, `if k:` was False for k=0, so it fell through to the standard
        signing path instead of raising InvalidNonce from _sign_custom_k.
        """
        k = PrivateKey(0x1111111111111111111111111111111111111111111111111111111111111111)
        with pytest.raises((ValueError, Exception)):
            k.sign(b"test message", k=0)


def test_decrypt_rejects_short_message():
    """BIE1 decrypt must raise ValidationError (not AssertionError) for short input."""
    key = PrivateKey.from_hex(_TEST_KEY_HEX)
    with pytest.raises(ValidationError, match="invalid encrypted length"):
        key.decrypt(b"\x00" * 10)
