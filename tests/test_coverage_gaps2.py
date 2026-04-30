"""Coverage gap tests — second batch.

Targets (from 2026-04-24 coverage report):
- script/type.py          (35% → target ≥ 80%)
- script/script.py        (43% → target ≥ 80%)
- transaction/transaction.py  (46% → target ≥ 75%)
- keys.py                 (61% → target ≥ 80%)
"""
from __future__ import annotations

import pytest

from pyrxd.keys import PrivateKey, PublicKey, recover_public_key, verify_signed_text
from pyrxd.script.script import Script, ScriptChunk
from pyrxd.script.type import (
    BareMultisig,
    OpReturn,
    P2PK,
    P2PKH,
    RPuzzle,
)
from pyrxd.transaction.transaction import InsufficientFunds, Transaction
from pyrxd.transaction.transaction_input import TransactionInput
from pyrxd.transaction.transaction_output import TransactionOutput
from pyrxd.security.errors import ValidationError


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def keypair():
    pk = PrivateKey(1)   # deterministic
    return pk, pk.public_key()


@pytest.fixture(scope="module")
def address(keypair):
    return keypair[0].address()


def _p2pkh_script(addr: str) -> Script:
    return P2PKH().lock(addr)


# ---------------------------------------------------------------------------
# script/type.py — P2PKH lock from bytes
# ---------------------------------------------------------------------------

class TestP2PKHLock:
    def test_lock_from_address(self, address):
        s = P2PKH().lock(address)
        assert s.byte_length() == 25

    def test_lock_from_pkh_bytes(self, keypair):
        pk = keypair[1]
        pkh = pk.hash160()
        s = P2PKH().lock(pkh)
        assert s.byte_length() == 25

    def test_lock_bad_type_raises_type_error(self):
        with pytest.raises(TypeError):
            P2PKH().lock(12345)  # type: ignore[arg-type]

    def test_lock_bad_pkh_length_raises(self):
        with pytest.raises(ValidationError):
            P2PKH().lock(b"\xab" * 10)   # 10 bytes, not 20


# ---------------------------------------------------------------------------
# script/type.py — OpReturn
# ---------------------------------------------------------------------------

class TestOpReturn:
    def test_lock_bytes_pushdata(self):
        s = OpReturn().lock([b"hello", b"world"])
        assert s.byte_length() > 2

    def test_lock_str_pushdata(self):
        s = OpReturn().lock(["pyrxd", "test"])
        raw = s.serialize()
        assert b"pyrxd" in raw

    def test_lock_bad_type_raises(self):
        with pytest.raises(TypeError):
            OpReturn().lock([42])  # type: ignore[arg-type]

    def test_empty_pushdatas(self):
        s = OpReturn().lock([])
        assert s.byte_length() == 2   # OP_FALSE OP_RETURN only


# ---------------------------------------------------------------------------
# script/type.py — P2PK
# ---------------------------------------------------------------------------

class TestP2PK:
    def test_lock_from_bytes(self, keypair):
        pub_bytes = keypair[1].serialize()
        s = P2PK().lock(pub_bytes)
        assert s.byte_length() == 35    # 33-byte compressed + OP_CHECKSIG + push

    def test_lock_from_hex_str(self, keypair):
        pub_hex = keypair[1].hex()
        s = P2PK().lock(pub_hex)
        assert s.byte_length() == 35

    def test_lock_bad_type_raises(self):
        with pytest.raises(TypeError):
            P2PK().lock(12345)  # type: ignore[arg-type]

    def test_lock_bad_key_length_raises(self):
        with pytest.raises(ValidationError):
            P2PK().lock(b"\x02" + b"\xab" * 10)   # wrong length


# ---------------------------------------------------------------------------
# script/type.py — BareMultisig
# ---------------------------------------------------------------------------

class TestBareMultisig:
    def test_lock_2of3(self):
        keys = [PrivateKey(i) for i in range(1, 4)]
        pubs = [k.public_key().hex() for k in keys]
        s = BareMultisig().lock(pubs, threshold=2)
        assert s.byte_length() > 10

    def test_lock_bad_threshold_raises(self):
        keys = [PrivateKey(i) for i in range(1, 3)]
        pubs = [k.public_key().hex() for k in keys]
        with pytest.raises(ValidationError):
            BareMultisig().lock(pubs, threshold=5)   # > len(pubs)

    def test_lock_bad_pub_type_raises(self):
        with pytest.raises(TypeError):
            BareMultisig().lock([12345], threshold=1)  # type: ignore[list-item]

    def test_lock_bad_pub_length_raises(self):
        with pytest.raises(ValidationError):
            BareMultisig().lock([b"\xab" * 5], threshold=1)

    def test_unlock_produces_template(self):
        keys = [PrivateKey(i) for i in range(1, 3)]
        tmpl = BareMultisig().unlock(keys)
        assert hasattr(tmpl, "sign")
        assert hasattr(tmpl, "estimated_unlocking_byte_length")


# ---------------------------------------------------------------------------
# script/type.py — RPuzzle
# ---------------------------------------------------------------------------

class TestRPuzzle:
    def test_invalid_type_raises(self):
        with pytest.raises(ValidationError):
            RPuzzle("MD5")

    def test_lock_raw(self):
        r_value = b"\xab" * 32
        s = RPuzzle("raw").lock(r_value)
        assert s.byte_length() > 0

    def test_lock_with_hash_type(self):
        r_hash = b"\xcd" * 20
        s = RPuzzle("HASH160").lock(r_hash)
        assert s.byte_length() > 0

    def test_unlock_produces_template(self, keypair):
        pk = keypair[0]
        tmpl = RPuzzle("raw").unlock(k=12345, private_key=pk)
        assert hasattr(tmpl, "sign")
        assert tmpl.estimated_unlocking_byte_length() == 108

    def test_unlock_sign_outputs_none(self, keypair):
        pk = keypair[0]
        tmpl = RPuzzle("raw").unlock(k=12345, private_key=pk, sign_outputs="none")
        assert tmpl is not None

    def test_unlock_sign_outputs_single(self, keypair):
        pk = keypair[0]
        tmpl = RPuzzle("raw").unlock(k=12345, private_key=pk, sign_outputs="single")
        assert tmpl is not None

    def test_unlock_anyonecanpay(self, keypair):
        pk = keypair[0]
        tmpl = RPuzzle("raw").unlock(k=12345, private_key=pk, anyone_can_pay=True)
        assert tmpl is not None


# ---------------------------------------------------------------------------
# script/script.py — ScriptChunk
# ---------------------------------------------------------------------------

class TestScriptChunk:
    def test_str_with_data(self):
        chunk = ScriptChunk(b"\x01", b"\xab")
        assert "ab" in str(chunk)

    def test_repr(self):
        chunk = ScriptChunk(b"\x01", b"\xcd")
        assert repr(chunk) == str(chunk)


# ---------------------------------------------------------------------------
# script/script.py — Script
# ---------------------------------------------------------------------------

class TestScript:
    def test_none_creates_empty(self):
        s = Script(None)
        assert s.byte_length() == 0

    def test_bytes_input(self):
        s = Script(b"\x00\x01\x02")
        assert s.byte_length() == 3

    def test_bad_type_raises(self):
        with pytest.raises(TypeError):
            Script(42)  # type: ignore[arg-type]

    def test_hex_output(self):
        s = Script("aabb")
        assert s.hex() == "aabb"

    def test_serialize(self):
        s = Script(b"\x01\x02")
        assert s.serialize() == b"\x01\x02"

    def test_byte_length_varint(self):
        s = Script(b"\xff" * 10)
        varint = s.byte_length_varint()
        assert isinstance(varint, bytes)
        assert varint[0] == 10

    def test_size_alias(self):
        s = Script(b"\x01\x02\x03")
        assert s.size() == 3

    def test_size_varint_alias(self):
        s = Script(b"\x01\x02\x03")
        assert s.size_varint() == s.byte_length_varint()

    def test_is_push_only_true(self):
        s = Script(b"\x01\xab")   # push 1 byte
        assert s.is_push_only() is True

    def test_is_push_only_false(self):
        # OP_DUP (0x76) > OP_16
        s = Script(b"\x76")
        assert s.is_push_only() is False

    def test_eq_same_bytes(self):
        a = Script("aabb")
        b = Script("aabb")
        assert a == b

    def test_eq_different_bytes(self):
        a = Script("aabb")
        b = Script("ccdd")
        assert a != b

    def test_str(self):
        s = Script("aabb")
        assert str(s) == "aabb"

    def test_repr(self):
        s = Script("aabb")
        assert repr(s) == "aabb"

    def test_from_chunks_roundtrip(self):
        original = Script("76a914" + "ab" * 20 + "88ac")
        rebuilt = Script.from_chunks(original.chunks)
        assert rebuilt.hex() == original.hex()

    def test_from_asm_op_dup(self):
        s = Script.from_asm("OP_DUP OP_HASH160")
        assert s.byte_length() == 2

    def test_from_asm_zero_token(self):
        s = Script.from_asm("0")
        assert s.serialize() == b"\x00"

    def test_from_asm_minus_one(self):
        s = Script.from_asm("-1")
        assert s.byte_length() == 1

    def test_from_asm_hex_data(self):
        s = Script.from_asm("deadbeef")
        assert b"\xde\xad\xbe\xef" in s.serialize()

    def test_to_asm(self):
        s = Script.from_asm("OP_DUP OP_HASH160")
        asm = s.to_asm()
        assert "OP_DUP" in asm

    def test_find_and_delete(self):
        s = Script("76a914" + "ab" * 20 + "88ac")
        pattern = Script("76")   # OP_DUP
        result = Script.find_and_delete(s, pattern)
        assert b"\x76" not in result.serialize()

    def test_write_bin(self):
        s = Script.write_bin(b"\xde\xad")
        assert b"\xde\xad" in s.serialize()

    def test_pushdata1_parsing(self):
        # OP_PUSHDATA1 (0x4c) + len byte + data
        data = b"\xab" * 80
        script_bytes = b"\x4c" + bytes([80]) + data
        s = Script(script_bytes)
        assert len(s.chunks) == 1
        assert s.chunks[0].data == data

    def test_pushdata2_parsing(self):
        data = b"\xcd" * 300
        import struct
        script_bytes = b"\x4d" + struct.pack("<H", 300) + data
        s = Script(script_bytes)
        assert len(s.chunks) == 1
        assert s.chunks[0].data == data


# ---------------------------------------------------------------------------
# transaction/transaction.py — estimated_byte_length
# ---------------------------------------------------------------------------

class TestTransactionEstimatedLength:
    def _simple_tx(self):
        pk = PrivateKey(999)
        addr = pk.address()
        locking = _p2pkh_script(addr)
        src_out = TransactionOutput(locking, 10_000)
        src_tx = Transaction(tx_inputs=[], tx_outputs=[src_out])
        tx_in = TransactionInput(
            source_transaction=src_tx,
            source_output_index=0,
            unlocking_script_template=P2PKH().unlock(pk),
        )
        tx_out = TransactionOutput(locking, 9_000)
        return Transaction(tx_inputs=[tx_in], tx_outputs=[tx_out])

    def test_estimated_byte_length(self):
        tx = self._simple_tx()
        est = tx.estimated_byte_length()
        assert est > 0

    def test_estimated_size_alias(self):
        tx = self._simple_tx()
        assert tx.estimated_size() == tx.estimated_byte_length()

    def test_fee_none_uses_default_model(self):
        pk = PrivateKey(998)
        addr = pk.address()
        locking = _p2pkh_script(addr)
        src_out = TransactionOutput(locking, 100_000)
        src_tx = Transaction(tx_inputs=[], tx_outputs=[src_out])
        tx_in = TransactionInput(
            source_transaction=src_tx,
            source_output_index=0,
            unlocking_script_template=P2PKH().unlock(pk),
        )
        spend_out = TransactionOutput(locking, 50_000, change=False)
        change_out = TransactionOutput(locking, None, change=True)
        tx = Transaction(tx_inputs=[tx_in], tx_outputs=[spend_out, change_out])
        tx.fee()  # default model — must not raise
        assert change_out.satoshis is not None

    def test_fee_integer_amount(self):
        pk = PrivateKey(997)
        addr = pk.address()
        locking = _p2pkh_script(addr)
        src_out = TransactionOutput(locking, 100_000)
        src_tx = Transaction(tx_inputs=[], tx_outputs=[src_out])
        tx_in = TransactionInput(
            source_transaction=src_tx,
            source_output_index=0,
            unlocking_script_template=P2PKH().unlock(pk),
        )
        change_out = TransactionOutput(locking, None, change=True)
        tx = Transaction(tx_inputs=[tx_in], tx_outputs=[change_out])
        tx.fee(500)  # integer fee
        assert change_out.satoshis is not None

    def test_fee_change_too_small_removes_change_outputs(self):
        """When change < change_count, change outputs are dropped."""
        pk = PrivateKey(996)
        addr = pk.address()
        locking = _p2pkh_script(addr)
        src_out = TransactionOutput(locking, 1_000)
        src_tx = Transaction(tx_inputs=[], tx_outputs=[src_out])
        tx_in = TransactionInput(
            source_transaction=src_tx,
            source_output_index=0,
            unlocking_script_template=P2PKH().unlock(pk),
        )
        spend_out = TransactionOutput(locking, 999, change=False)
        change_out = TransactionOutput(locking, None, change=True)
        tx = Transaction(tx_inputs=[tx_in], tx_outputs=[spend_out, change_out])
        tx.fee(10_000)  # huge fee, change goes negative
        # Change output should be removed
        assert all(not o.change for o in tx.outputs)

    def test_from_hex_with_bytes_input(self):
        hex_str = (
            "01000000029e8d016a7b0dc49a325922d05da1f916d1e4d4f0cb840c9727f3d22ce8d1363f"
            "000000008c493046022100e9318720bee5425378b4763b0427158b1051eec8b08442ce3fbfbf"
            "7b30202a44022100d4172239ebd701dae2fbaaccd9f038e7ca166707333427e3fb2a2865b19a"
            "7f27014104510c67f46d2cbb29476d1f0b794be4cb549ea59ab9cc1e731969a7bf5be95f7ad"
            "5e7f904e5ccf50a9dc1714df00fbeb794aa27aaff33260c1032d931a75c56f2ffffffff"
            "a3195e7a1ab665473ff717814f6881485dc8759bebe97e31c301ffe7933a656f020000008b"
            "48304502201c282f35f3e02a1f32d2089265ad4b561f07ea3c288169dedcf2f785e6065efa"
            "022100e8db18aadacb382eed13ee04708f00ba0a9c40e3b21cf91da8859d0f7d99e0c50141"
            "042b409e1ebbb43875be5edde9c452c82c01e3903d38fa4fd89f3887a52cb8aea9dc8aec7e"
            "2c9d5b3609c03eb16259a2537135a1bf0f9c5fbbcbdbaf83ba402442ffffffff"
            "02206b1000000000001976a91420bb5c3bfaef0231dc05190e7f1c8e22e098991e88ac"
            "f0ca0100000000001976a9149e3e2d23973a04ec1b02be97c30ab9f2f27c3b2c88ac00000000"
        )
        raw = bytes.fromhex(hex_str)
        tx = Transaction.from_hex(raw)
        assert tx is not None
        assert tx.txid() is not None

    def test_to_ef_format(self):
        pk = PrivateKey(995)
        addr = pk.address()
        locking = _p2pkh_script(addr)
        src_out = TransactionOutput(locking, 50_000)
        src_tx = Transaction(tx_inputs=[], tx_outputs=[src_out])
        tx_in = TransactionInput(
            source_transaction=src_tx,
            source_output_index=0,
            unlocking_script=Script("00"),  # pre-signed stub
        )
        tx_out = TransactionOutput(locking, 49_000)
        tx = Transaction(tx_inputs=[tx_in], tx_outputs=[tx_out])
        ef = tx.to_ef()
        assert isinstance(ef, bytes)
        assert len(ef) > 0

    def test_parse_script_offsets(self):
        hex_str = (
            "01000000029e8d016a7b0dc49a325922d05da1f916d1e4d4f0cb840c9727f3d22ce8d1363f"
            "000000008c493046022100e9318720bee5425378b4763b0427158b1051eec8b08442ce3fbfbf"
            "7b30202a44022100d4172239ebd701dae2fbaaccd9f038e7ca166707333427e3fb2a2865b19a"
            "7f27014104510c67f46d2cbb29476d1f0b794be4cb549ea59ab9cc1e731969a7bf5be95f7ad"
            "5e7f904e5ccf50a9dc1714df00fbeb794aa27aaff33260c1032d931a75c56f2ffffffff"
            "a3195e7a1ab665473ff717814f6881485dc8759bebe97e31c301ffe7933a656f020000008b"
            "48304502201c282f35f3e02a1f32d2089265ad4b561f07ea3c288169dedcf2f785e6065efa"
            "022100e8db18aadacb382eed13ee04708f00ba0a9c40e3b21cf91da8859d0f7d99e0c50141"
            "042b409e1ebbb43875be5edde9c452c82c01e3903d38fa4fd89f3887a52cb8aea9dc8aec7e"
            "2c9d5b3609c03eb16259a2537135a1bf0f9c5fbbcbdbaf83ba402442ffffffff"
            "02206b1000000000001976a91420bb5c3bfaef0231dc05190e7f1c8e22e098991e88ac"
            "f0ca0100000000001976a9149e3e2d23973a04ec1b02be97c30ab9f2f27c3b2c88ac00000000"
        )
        result = Transaction.parse_script_offsets(hex_str)
        assert "inputs" in result
        assert "outputs" in result
        assert len(result["inputs"]) == 2
        assert len(result["outputs"]) == 2

    def test_parse_script_offsets_bytes(self):
        tx = Transaction(tx_inputs=[], tx_outputs=[])
        raw = tx.serialize()
        result = Transaction.parse_script_offsets(raw)
        assert result["inputs"] == []
        assert result["outputs"] == []

    def test_insufficient_funds_is_value_error(self):
        assert issubclass(InsufficientFunds, ValueError)
        e = InsufficientFunds("not enough")
        assert "not enough" in str(e)


# ---------------------------------------------------------------------------
# keys.py — PrivateKey constructors and methods
# ---------------------------------------------------------------------------

class TestPrivateKeyConstructors:
    def test_from_int(self):
        pk = PrivateKey(1)
        assert pk is not None

    def test_from_bytes(self):
        pk = PrivateKey(b"\x01" * 32)
        assert pk is not None

    def test_from_hex_classmethod(self):
        pk = PrivateKey.from_hex("01" * 32)
        assert pk is not None

    def test_bad_type_raises(self):
        with pytest.raises(TypeError):
            PrivateKey([1, 2, 3])  # type: ignore[arg-type]

    def test_wif_roundtrip(self):
        pk = PrivateKey(42)
        wif = pk.wif()
        pk2 = PrivateKey(wif)
        assert pk == pk2

    def test_int_method(self):
        pk = PrivateKey(99)
        assert pk.int() == 99

    def test_hex_method(self):
        pk = PrivateKey(1)
        assert pk.hex() == pk.serialize().hex()

    def test_str_repr_no_secret(self):
        pk = PrivateKey(1)
        s = str(pk)
        assert pk.hex() not in s

    def test_eq_same_key(self):
        assert PrivateKey(1) == PrivateKey(1)

    def test_eq_different_key(self):
        assert PrivateKey(1) != PrivateKey(2)

    def test_not_hashable(self):
        pk = PrivateKey(1)
        with pytest.raises(TypeError, match="unhashable"):
            hash(pk)

    def test_not_picklable(self):
        import pickle
        pk = PrivateKey(1)
        with pytest.raises(TypeError, match="cannot be pickled"):
            pickle.dumps(pk)

    def test_not_copyable(self):
        import copy
        pk = PrivateKey(1)
        with pytest.raises(TypeError, match="cannot be copied"):
            copy.copy(pk)

    def test_not_deep_copyable(self):
        import copy
        pk = PrivateKey(1)
        with pytest.raises(TypeError, match="cannot be deep-copied"):
            copy.deepcopy(pk)


class TestPrivateKeySignVerify:
    def test_sign_and_verify(self):
        pk = PrivateKey(777)
        msg = b"test message"
        sig = pk.sign(msg)
        assert pk.public_key().verify(sig, msg)

    def test_sign_custom_k(self):
        pk = PrivateKey(777)
        msg = b"test message"
        sig = pk.sign(msg, k=54321)
        # Same k produces same sig
        sig2 = pk.sign(msg, k=54321)
        assert sig == sig2

    def test_sign_recoverable(self):
        pk = PrivateKey(555)
        msg = b"recoverable test"
        sig = pk.sign_recoverable(msg)
        assert len(sig) == 65   # r(32) + s(32) + recovery_id(1)

    def test_verify_recoverable(self):
        pk = PrivateKey(555)
        msg = b"recoverable test"
        sig = pk.sign_recoverable(msg)
        assert pk.verify_recoverable(sig, msg)

    def test_sign_text_and_verify(self):
        pk = PrivateKey(333)
        text = "hello pyrxd"
        addr, sig_str = pk.sign_text(text)
        assert verify_signed_text(text, addr, sig_str)

    def test_sign_text_wrong_address_fails(self):
        pk = PrivateKey(333)
        pk2 = PrivateKey(334)
        text = "hello pyrxd"
        addr, sig_str = pk.sign_text(text)
        wrong_addr = pk2.address()
        assert not verify_signed_text(text, wrong_addr, sig_str)


class TestPrivateKeyECIES:
    def test_decrypt_encrypt_roundtrip(self):
        pk = PrivateKey(1111)
        plaintext = b"secret message for ECIES"
        encrypted = pk.public_key().encrypt(plaintext)
        decrypted = pk.decrypt(encrypted)
        assert decrypted == plaintext

    def test_decrypt_text_roundtrip(self):
        pk = PrivateKey(2222)
        text = "hello ECIES text"
        encrypted_b64 = pk.public_key().encrypt_text(text)
        decrypted = pk.decrypt_text(encrypted_b64)
        assert decrypted == text

    def test_decrypt_bad_magic_raises(self):
        pk = PrivateKey(3333)
        # Encrypt something valid, then corrupt the magic bytes
        encrypted = pk.public_key().encrypt(b"hello")
        bad_msg = b"XYZW" + encrypted[4:]   # replace "BIE1" with garbage
        with pytest.raises(ValidationError, match="invalid magic bytes"):
            pk.decrypt(bad_msg)

    def test_decrypt_too_short_raises(self):
        pk = PrivateKey(4444)
        with pytest.raises(ValidationError, match="invalid encrypted length"):
            pk.decrypt(b"\x00" * 10)


class TestPrivateKeyBRC42:
    def test_derive_child_pub_and_priv_agree(self):
        """alice.pub.derive_child(bob_priv) == alice.priv.derive_child(bob.pub).public_key()"""
        alice_priv = PrivateKey(100)
        bob_priv = PrivateKey(200)
        # Derived public key via PublicKey.derive_child
        child_pub_via_pub = alice_priv.public_key().derive_child(bob_priv, "invoice-001")
        # Derived public key via PrivateKey.derive_child
        child_pub_via_priv = alice_priv.derive_child(bob_priv.public_key(), "invoice-001").public_key()
        assert child_pub_via_pub == child_pub_via_priv

    def test_derive_child_private_key(self):
        alice_priv = PrivateKey(100)
        bob_pub = PrivateKey(200).public_key()
        child_priv = alice_priv.derive_child(bob_pub, "invoice-001")
        assert isinstance(child_priv, PrivateKey)


class TestPublicKeyExtra:
    def test_from_bytes(self):
        pk = PrivateKey(1)
        pub_bytes = pk.public_key().serialize()
        pub = PublicKey(pub_bytes)
        assert pub == pk.public_key()

    def test_from_hex(self):
        pk = PrivateKey(1)
        pub_hex = pk.public_key().hex()
        pub = PublicKey(bytes.fromhex(pub_hex))
        assert pub == pk.public_key()

    def test_derive_shared_secret_symmetric(self):
        a = PrivateKey(10)
        b = PrivateKey(20)
        shared_a = a.public_key().derive_shared_secret(b)
        shared_b = b.public_key().derive_shared_secret(a)
        assert shared_a == shared_b

    def test_recover_public_key(self):
        pk = PrivateKey(999)
        msg = b"recovery test"
        sig = pk.sign_recoverable(msg)
        recovered = recover_public_key(sig, msg)
        assert recovered == pk.public_key()
