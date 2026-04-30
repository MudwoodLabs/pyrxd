"""Coverage gap tests batch 5: BEEF format, witness stripping, RPuzzle, script type unlocks,
tx_preimages variants."""

from __future__ import annotations

import pytest

from pyrxd.constants import SIGHASH
from pyrxd.hash import hash256
from pyrxd.keys import PrivateKey
from pyrxd.merkle_path import MerklePath
from pyrxd.script.script import Script
from pyrxd.script.type import P2PK, P2PKH, BareMultisig, RPuzzle
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_input import TransactionInput
from pyrxd.transaction.transaction_output import TransactionOutput

# ──────────────────────────────────────────────────────────────────────────────
# Helpers for building minimal valid transactions
# ──────────────────────────────────────────────────────────────────────────────

_DUMMY_TXID = "aa" * 32


def _p2pkh_script(key: PrivateKey) -> Script:
    addr = key.public_key().address()
    return P2PKH().lock(addr)


def _make_tx(satoshis: int = 1000) -> Transaction:
    """One-input one-output transaction with source attached (needed for EF / BEEF)."""
    priv = PrivateKey()
    lock = _p2pkh_script(priv)
    source = Transaction()
    source.outputs.append(TransactionOutput(satoshis=satoshis, locking_script=lock))

    tx = Transaction()
    tx_in = TransactionInput(
        source_transaction=source,
        source_output_index=0,
        unlocking_script=Script(),
        sequence=0xFFFFFFFF,
    )
    tx.inputs.append(tx_in)
    tx.outputs.append(TransactionOutput(satoshis=satoshis - 100, locking_script=lock))
    return tx


def _simple_merkle_path(block_height: int = 1) -> MerklePath:
    """Minimal valid MerklePath: depth-1 tree with txid at offset 0 and sibling at offset 1."""
    leaf_hash = "ab" * 32
    sibling_hash = "cd" * 32
    return MerklePath(
        block_height,
        [
            [
                {"offset": 0, "hash_str": leaf_hash, "txid": True},
                {"offset": 1, "hash_str": sibling_hash},
            ],
        ],
    )


# ──────────────────────────────────────────────────────────────────────────────
# BEEF round-trip (to_beef / from_beef)
# ──────────────────────────────────────────────────────────────────────────────


class TestBEEFRoundTrip:
    """Tests for Transaction.to_beef() and Transaction.from_beef()."""

    def _tx_with_merkle_path(self) -> Transaction:
        """Source tx has a MerklePath (the "proven" ancestor)."""
        priv = PrivateKey()
        lock = _p2pkh_script(priv)

        # Build the source tx and attach a merkle path
        source = Transaction()
        source.outputs.append(TransactionOutput(satoshis=5000, locking_script=lock))
        source.merkle_path = _simple_merkle_path(block_height=100)

        # Build the spending tx
        tx = Transaction()
        tx_in = TransactionInput(
            source_transaction=source,
            source_output_index=0,
            unlocking_script=Script(),
            sequence=0xFFFFFFFF,
        )
        tx.inputs.append(tx_in)
        tx.outputs.append(TransactionOutput(satoshis=4900, locking_script=lock))
        return tx

    def test_to_beef_produces_bytes(self):
        tx = self._tx_with_merkle_path()
        beef = tx.to_beef()
        assert isinstance(beef, bytes)
        assert len(beef) > 10

    def test_beef_magic_version(self):
        tx = self._tx_with_merkle_path()
        beef = tx.to_beef()
        version = int.from_bytes(beef[:4], "little")
        assert version == 4022206465  # 0xEFBEEF01

    def test_from_beef_hex_string(self):
        tx = self._tx_with_merkle_path()
        beef_hex = tx.to_beef().hex()
        recovered = Transaction.from_beef(beef_hex)
        assert recovered.txid() == tx.txid()

    def test_from_beef_bytes(self):
        tx = self._tx_with_merkle_path()
        beef_bytes = tx.to_beef()
        recovered = Transaction.from_beef(beef_bytes)
        assert recovered.txid() == tx.txid()

    def test_from_beef_reader(self):
        from pyrxd.utils import Reader

        tx = self._tx_with_merkle_path()
        beef_bytes = tx.to_beef()
        reader = Reader(beef_bytes)
        recovered = Transaction.from_beef(reader)
        assert recovered.txid() == tx.txid()

    def test_from_beef_invalid_version_raises(self):
        tx = self._tx_with_merkle_path()
        beef = bytearray(tx.to_beef())
        # Corrupt version bytes
        beef[0] = 0xFF
        beef[1] = 0xFF
        beef[2] = 0xFF
        beef[3] = 0xFF
        with pytest.raises(ValueError, match="Invalid BEEF version"):
            Transaction.from_beef(bytes(beef))

    def test_to_beef_missing_source_raises(self):
        """to_beef should raise when an input has no source_transaction."""
        priv = PrivateKey()
        lock = _p2pkh_script(priv)
        tx = Transaction()
        tx_in = TransactionInput(
            source_txid=_DUMMY_TXID,
            source_output_index=0,
            unlocking_script=Script(),
            sequence=0xFFFFFFFF,
        )
        # No source_transaction attached, no merkle_path
        tx.inputs.append(tx_in)
        tx.outputs.append(TransactionOutput(satoshis=100, locking_script=lock))
        with pytest.raises(ValueError, match="source transaction is missing"):
            tx.to_beef()

    def test_from_beef_restores_merkle_path(self):
        tx = self._tx_with_merkle_path()
        recovered = Transaction.from_beef(tx.to_beef())
        # The source tx in the recovered tx should have a merkle path
        source_tx = recovered.inputs[0].source_transaction
        assert isinstance(source_tx, Transaction)
        assert isinstance(source_tx.merkle_path, MerklePath)

    def test_to_beef_two_inputs_same_merkle_path(self):
        """Two inputs sharing the same MerklePath block height → paths get merged (combined)."""
        priv = PrivateKey()
        lock = _p2pkh_script(priv)
        path = _simple_merkle_path(block_height=200)

        source1 = Transaction()
        source1.outputs.append(TransactionOutput(satoshis=2000, locking_script=lock))
        source1.merkle_path = path

        source2 = Transaction()
        source2.outputs.append(TransactionOutput(satoshis=3000, locking_script=lock))
        source2.merkle_path = path  # same object → same path

        tx = Transaction()
        for src in (source1, source2):
            tx_in = TransactionInput(
                source_transaction=src,
                source_output_index=0,
                unlocking_script=Script(),
                sequence=0xFFFFFFFF,
            )
            tx.inputs.append(tx_in)
        tx.outputs.append(TransactionOutput(satoshis=4800, locking_script=lock))

        beef = tx.to_beef()
        assert isinstance(beef, bytes)
        recovered = Transaction.from_beef(beef)
        assert recovered.txid() == tx.txid()


# ──────────────────────────────────────────────────────────────────────────────
# spv/witness.py – strip_witness
# ──────────────────────────────────────────────────────────────────────────────


class TestStripWitness:
    """Tests for pyrxd.spv.witness.strip_witness."""

    from pyrxd.spv.witness import strip_witness

    def test_legacy_tx_returned_unchanged(self):
        from pyrxd.spv.witness import strip_witness

        # A legacy tx starts with version(4) + non-zero varint for input count
        # Build a minimal raw legacy tx: version + 1 input + 1 output + locktime
        raw = _build_legacy_tx()
        result = strip_witness(raw)
        assert result == raw

    def test_segwit_tx_stripped(self):
        from pyrxd.spv.witness import strip_witness

        raw, expected_stripped = _build_segwit_tx()
        result = strip_witness(raw)
        assert result == expected_stripped

    def test_too_short_raises(self):
        from pyrxd.security.errors import ValidationError as VE
        from pyrxd.spv.witness import strip_witness

        with pytest.raises(VE):
            strip_witness(b"\x01\x00\x00\x00\x00")  # 5 bytes < 10

    def test_unexpected_flag_raises(self):
        from pyrxd.security.errors import ValidationError
        from pyrxd.spv.witness import strip_witness

        # Build bytes that start with version(4) + 0x00 (segwit marker) + 0x02 (bad flag)
        data = b"\x01\x00\x00\x00" + b"\x00\x02" + b"\x00" * 20
        with pytest.raises(ValidationError, match="unexpected segwit flag"):
            strip_witness(data)

    def test_varint_fd_encoding(self):
        from pyrxd.spv.witness import _read_varint

        # 0xFD prefix encodes 2-byte little-endian value
        data = bytes([0xFD, 0x01, 0x00])  # encodes 1
        val, pos = _read_varint(data, 0)
        assert val == 1
        assert pos == 3

    def test_varint_fe_encoding(self):
        from pyrxd.spv.witness import _read_varint

        data = bytes([0xFE, 0x02, 0x00, 0x00, 0x00])  # encodes 2
        val, pos = _read_varint(data, 0)
        assert val == 2
        assert pos == 5

    def test_varint_ff_encoding(self):
        from pyrxd.spv.witness import _read_varint

        data = bytes([0xFF, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])  # encodes 3
        val, pos = _read_varint(data, 0)
        assert val == 3
        assert pos == 9

    def test_varint_truncated_fd_raises(self):
        from pyrxd.security.errors import ValidationError
        from pyrxd.spv.witness import _read_varint

        with pytest.raises(ValidationError):
            _read_varint(bytes([0xFD, 0x01]), 0)  # only 1 byte after prefix

    def test_varint_truncated_fe_raises(self):
        from pyrxd.security.errors import ValidationError
        from pyrxd.spv.witness import _read_varint

        with pytest.raises(ValidationError):
            _read_varint(bytes([0xFE, 0x01, 0x00]), 0)  # only 2 bytes after prefix

    def test_varint_truncated_ff_raises(self):
        from pyrxd.security.errors import ValidationError
        from pyrxd.spv.witness import _read_varint

        with pytest.raises(ValidationError):
            _read_varint(bytes([0xFF, 0x01, 0x00, 0x00, 0x00]), 0)  # only 4 bytes after prefix

    def test_varint_at_end_raises(self):
        from pyrxd.security.errors import ValidationError
        from pyrxd.spv.witness import _read_varint

        with pytest.raises(ValidationError):
            _read_varint(b"", 0)

    def test_encode_varint_negative_raises(self):
        from pyrxd.security.errors import ValidationError
        from pyrxd.spv.witness import _encode_varint

        with pytest.raises(ValidationError):
            _encode_varint(-1)

    def test_encode_varint_roundtrip_small(self):
        from pyrxd.spv.witness import _encode_varint, _read_varint

        for n in [0, 1, 0xFC]:
            encoded = _encode_varint(n)
            val, _ = _read_varint(encoded, 0)
            assert val == n

    def test_encode_varint_roundtrip_fd(self):
        from pyrxd.spv.witness import _encode_varint, _read_varint

        for n in [0xFD, 0xFFFF]:
            encoded = _encode_varint(n)
            val, _ = _read_varint(encoded, 0)
            assert val == n

    def test_encode_varint_roundtrip_fe(self):
        from pyrxd.spv.witness import _encode_varint, _read_varint

        n = 0x10000
        encoded = _encode_varint(n)
        val, _ = _read_varint(encoded, 0)
        assert val == n

    def test_encode_varint_roundtrip_ff(self):
        from pyrxd.spv.witness import _encode_varint, _read_varint

        n = 0x1_0000_0000
        encoded = _encode_varint(n)
        val, _ = _read_varint(encoded, 0)
        assert val == n


def _varint(n: int) -> bytes:
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + n.to_bytes(2, "little")
    if n <= 0xFFFFFFFF:
        return b"\xfe" + n.to_bytes(4, "little")
    return b"\xff" + n.to_bytes(8, "little")


def _build_legacy_tx() -> bytes:
    """Minimal legacy tx: version + 1 input (no script) + 1 output (no script) + locktime."""
    version = b"\x01\x00\x00\x00"
    # 1 input
    prevout = b"\xaa" * 32 + b"\x00\x00\x00\x00"  # txid + vout
    script_sig = b""
    inp = prevout + _varint(len(script_sig)) + script_sig + b"\xff\xff\xff\xff"
    # 1 output
    value = (1000).to_bytes(8, "little")
    script_pk = b"\x76\xa9\x14" + b"\x00" * 20 + b"\x88\xac"
    out = value + _varint(len(script_pk)) + script_pk
    locktime = b"\x00\x00\x00\x00"
    return version + _varint(1) + inp + _varint(1) + out + locktime


def _build_segwit_tx():
    """Build a minimal segwit tx and its expected stripped version."""
    version = b"\x01\x00\x00\x00"
    # 1 input
    prevout = b"\xbb" * 32 + b"\x01\x00\x00\x00"
    script_sig = b""
    inp = prevout + _varint(len(script_sig)) + script_sig + b"\xff\xff\xff\xff"
    # 1 output
    value = (500).to_bytes(8, "little")
    script_pk = b"\x00\x14" + b"\xcc" * 20  # P2WPKH
    out = value + _varint(len(script_pk)) + script_pk
    locktime = b"\x00\x00\x00\x00"

    # Witness data for 1 input: 2 items [sig(72), pk(33)]
    wit_item1 = b"\xdd" * 72
    wit_item2 = b"\x02" + b"\xee" * 32  # compressed pubkey
    witness = _varint(2) + _varint(len(wit_item1)) + wit_item1 + _varint(len(wit_item2)) + wit_item2

    # Segwit wire format: version + marker(0x00) + flag(0x01) + inputs + outputs + witness + locktime
    segwit = version + b"\x00\x01" + _varint(1) + inp + _varint(1) + out + witness + locktime

    # Expected stripped: version + inputs + outputs + locktime (no marker/flag/witness)
    stripped = version + _varint(1) + inp + _varint(1) + out + locktime

    return segwit, stripped


# ──────────────────────────────────────────────────────────────────────────────
# script/type.py – unlock methods (RPuzzle, P2PK, BareMultisig)
# ──────────────────────────────────────────────────────────────────────────────


class TestRPuzzleUnlock:
    """Tests for RPuzzle.unlock() sign/estimate functions."""

    def _make_signed_tx_rpuzzle(self, sign_outputs="all", anyone_can_pay=False):
        priv = PrivateKey()
        # Generate k deterministically
        k = int.from_bytes(hash256(b"test k value"), "big") % (
            0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        )
        # Derive R-value: k*G x-coordinate (low-level via coincurve)
        import coincurve

        pub = coincurve.PublicKey.from_valid_secret(k.to_bytes(32, "big"))
        r_bytes = pub.format(compressed=False)[1:33]  # x coordinate

        rpuzzle = RPuzzle("raw")
        lock = rpuzzle.lock(r_bytes)

        source = Transaction()
        source.outputs.append(TransactionOutput(satoshis=5000, locking_script=lock))

        tx = Transaction()
        # Pass source_transaction to constructor so satoshis/locking_script are populated
        tx_in = TransactionInput(
            source_transaction=source,
            source_output_index=0,
            unlocking_script=Script(),
            sequence=0xFFFFFFFF,
        )
        tx.inputs.append(tx_in)

        addr = priv.public_key().address()
        out_lock = P2PKH().lock(addr)
        tx.outputs.append(TransactionOutput(satoshis=4900, locking_script=out_lock))

        unlock_template = rpuzzle.unlock(
            k=k, private_key=priv, sign_outputs=sign_outputs, anyone_can_pay=anyone_can_pay
        )
        signed_script = unlock_template.sign(tx, 0)
        return signed_script, unlock_template

    def test_rpuzzle_sign_all(self):
        signed, _template = self._make_signed_tx_rpuzzle("all")
        assert isinstance(signed, Script)
        assert len(signed.serialize()) > 0

    def test_rpuzzle_sign_none(self):
        signed, _ = self._make_signed_tx_rpuzzle("none")
        assert isinstance(signed, Script)

    def test_rpuzzle_sign_single(self):
        signed, _ = self._make_signed_tx_rpuzzle("single")
        assert isinstance(signed, Script)

    def test_rpuzzle_anyone_can_pay(self):
        signed, _ = self._make_signed_tx_rpuzzle("all", anyone_can_pay=True)
        assert isinstance(signed, Script)

    def test_rpuzzle_estimated_length(self):
        priv = PrivateKey()
        k = 12345
        template = RPuzzle("raw").unlock(k=k, private_key=priv)
        length = template.estimated_unlocking_byte_length()
        assert isinstance(length, int)
        assert length > 0

    def test_rpuzzle_sha1_lock(self):
        import hashlib

        raw = b"\xab" * 20
        h = hashlib.sha1(raw).digest()
        lock = RPuzzle("SHA1").lock(h)
        assert isinstance(lock, Script)
        assert len(lock.serialize()) > 0

    def test_rpuzzle_hash256_lock(self):
        raw = hash256(b"test")
        lock = RPuzzle("HASH256").lock(raw)
        assert isinstance(lock, Script)

    def test_rpuzzle_invalid_type_raises(self):
        from pyrxd.security.errors import ValidationError

        with pytest.raises(ValidationError, match="unsupported puzzle type"):
            RPuzzle("BLAKE2")


class TestP2PKUnlock:
    """Tests for P2PK.unlock()."""

    def test_p2pk_unlock_produces_script(self):
        priv = PrivateKey()
        pk_bytes = priv.public_key().serialize()
        lock = P2PK().lock(pk_bytes)

        source = Transaction()
        source.outputs.append(TransactionOutput(satoshis=1000, locking_script=lock))

        tx = Transaction()
        tx_in = TransactionInput(
            source_transaction=source,
            source_output_index=0,
            unlocking_script=Script(),
            sequence=0xFFFFFFFF,
        )
        tx.inputs.append(tx_in)
        tx.outputs.append(TransactionOutput(satoshis=900, locking_script=lock))

        unlock = P2PK().unlock(priv)
        signed = unlock.sign(tx, 0)
        assert isinstance(signed, Script)
        assert len(signed.serialize()) > 0

    def test_p2pk_estimated_length(self):
        priv = PrivateKey()
        unlock = P2PK().unlock(priv)
        assert unlock.estimated_unlocking_byte_length() == 73


class TestBareMultisigUnlock:
    """Tests for BareMultisig.unlock()."""

    def test_multisig_1_of_2_unlock(self):
        priv1 = PrivateKey()
        priv2 = PrivateKey()
        pk1 = priv1.public_key().serialize()
        pk2 = priv2.public_key().serialize()

        lock = BareMultisig().lock([pk1, pk2], 1)

        source = Transaction()
        source.outputs.append(TransactionOutput(satoshis=2000, locking_script=lock))

        tx = Transaction()
        tx_in = TransactionInput(
            source_transaction=source,
            source_output_index=0,
            unlocking_script=Script(),
            sequence=0xFFFFFFFF,
        )
        tx.inputs.append(tx_in)
        tx.outputs.append(TransactionOutput(satoshis=1900, locking_script=lock))

        unlock = BareMultisig().unlock([priv1])
        signed = unlock.sign(tx, 0)
        assert isinstance(signed, Script)
        assert len(signed.serialize()) > 0

    def test_multisig_estimated_length(self):
        priv1 = PrivateKey()
        priv2 = PrivateKey()
        unlock = BareMultisig().unlock([priv1, priv2])
        # 1 (OP_0) + 73*2 (sigs) + 1 (null dummy)
        assert unlock.estimated_unlocking_byte_length() == 1 + 73 * 2 + 1

    def test_multisig_bad_threshold_raises(self):
        from pyrxd.security.errors import ValidationError

        priv = PrivateKey()
        pk = priv.public_key().serialize()
        with pytest.raises(ValidationError):
            BareMultisig().lock([pk], 0)  # threshold < 1

    def test_multisig_bad_participant_type_raises(self):
        with pytest.raises(TypeError):
            BareMultisig().lock([12345], 1)  # int is invalid type


# ──────────────────────────────────────────────────────────────────────────────
# transaction_preimage.py – tx_preimages (all SIGHASH branches)
# ──────────────────────────────────────────────────────────────────────────────


class TestTxPreimages:
    """Tests for tx_preimages() covering all sighash variant branches."""

    def _make_inputs_outputs(self, count_in=2, count_out=2):
        priv = PrivateKey()
        addr = priv.public_key().address()
        lock = P2PKH().lock(addr)

        source = Transaction()
        for _ in range(count_in):
            source.outputs.append(TransactionOutput(satoshis=5000, locking_script=lock))

        inputs = []
        for i in range(count_in):
            tx_in = TransactionInput(
                source_transaction=source,
                source_output_index=i,
                unlocking_script=Script(),
                sequence=0xFFFFFFFF,
            )
            inputs.append(tx_in)

        outputs = [TransactionOutput(satoshis=2000, locking_script=lock) for _ in range(count_out)]
        return inputs, outputs

    def test_all_inputs_produce_preimages(self):
        from pyrxd.transaction.transaction_preimage import tx_preimages

        inputs, outputs = self._make_inputs_outputs()
        preimages = tx_preimages(inputs, outputs, 1, 0)
        assert len(preimages) == len(inputs)
        for p in preimages:
            assert isinstance(p, bytes)
            assert len(p) > 0

    def test_sighash_none_branch(self):
        from pyrxd.transaction.transaction_preimage import tx_preimages

        inputs, outputs = self._make_inputs_outputs()
        inputs[0].sighash = SIGHASH.NONE | SIGHASH.FORKID
        preimages = tx_preimages(inputs, outputs, 1, 0)
        assert len(preimages) == 2

    def test_sighash_single_in_range(self):
        from pyrxd.transaction.transaction_preimage import tx_preimages

        inputs, outputs = self._make_inputs_outputs(2, 2)
        inputs[0].sighash = SIGHASH.SINGLE | SIGHASH.FORKID
        preimages = tx_preimages(inputs, outputs, 1, 0)
        assert len(preimages) == 2

    def test_sighash_single_out_of_range(self):
        """SIGHASH_SINGLE with input index >= output count → zero hash_outputs."""
        from pyrxd.transaction.transaction_preimage import tx_preimages

        # 2 inputs, 1 output → input[1] is out of range for SINGLE
        inputs, outputs = self._make_inputs_outputs(2, 1)
        inputs[1].sighash = SIGHASH.SINGLE | SIGHASH.FORKID
        preimages = tx_preimages(inputs, outputs, 1, 0)
        assert len(preimages) == 2

    def test_sighash_anyonecanpay(self):
        from pyrxd.transaction.transaction_preimage import tx_preimages

        inputs, outputs = self._make_inputs_outputs()
        inputs[0].sighash = SIGHASH.ALL | SIGHASH.FORKID | SIGHASH.ANYONECANPAY
        preimages = tx_preimages(inputs, outputs, 1, 0)
        assert len(preimages) == 2

    def test_sighash_anyonecanpay_none(self):
        from pyrxd.transaction.transaction_preimage import tx_preimages

        inputs, outputs = self._make_inputs_outputs()
        inputs[0].sighash = SIGHASH.NONE | SIGHASH.FORKID | SIGHASH.ANYONECANPAY
        preimages = tx_preimages(inputs, outputs, 1, 0)
        assert len(preimages) == 2

    def test_sighash_anyonecanpay_single(self):
        from pyrxd.transaction.transaction_preimage import tx_preimages

        inputs, outputs = self._make_inputs_outputs(2, 2)
        inputs[0].sighash = SIGHASH.SINGLE | SIGHASH.FORKID | SIGHASH.ANYONECANPAY
        preimages = tx_preimages(inputs, outputs, 1, 0)
        assert len(preimages) == 2

    def test_preimage_deterministic(self):
        """Same tx → same preimage bytes."""
        from pyrxd.transaction.transaction_preimage import tx_preimages

        inputs, outputs = self._make_inputs_outputs()
        p1 = tx_preimages(inputs, outputs, 1, 0)
        p2 = tx_preimages(inputs, outputs, 1, 0)
        assert p1 == p2


# ──────────────────────────────────────────────────────────────────────────────
# script/type.py – remaining uncovered branches (lines 139-149, 179-186, 248-265)
# ──────────────────────────────────────────────────────────────────────────────


class TestScriptTypeEdgeCases:
    """Edge cases in script type module not yet covered."""

    def test_p2pkh_lock_bytes_input(self):
        """P2PKH.lock() accepts raw 20-byte hash."""
        pkh = b"\x01" * 20
        lock = P2PKH().lock(pkh)
        assert isinstance(lock, Script)

    def test_p2pkh_lock_invalid_type_raises(self):
        with pytest.raises(TypeError):
            P2PKH().lock(12345)

    def test_p2pkh_lock_wrong_length_raises(self):
        from pyrxd.security.errors import ValidationError

        with pytest.raises(ValidationError):
            P2PKH().lock(b"\x01" * 10)  # Not 20 bytes

    def test_p2pk_lock_uncompressed_pubkey(self):
        """P2PK.lock() accepts 65-byte uncompressed public key."""
        priv = PrivateKey()
        pub_uncompressed = priv.public_key().serialize(compressed=False)
        lock = P2PK().lock(pub_uncompressed)
        assert isinstance(lock, Script)

    def test_p2pk_lock_bytes_input(self):
        priv = PrivateKey()
        pk_bytes = priv.public_key().serialize()
        lock = P2PK().lock(pk_bytes)
        assert isinstance(lock, Script)

    def test_p2pk_lock_invalid_type_raises(self):
        with pytest.raises(TypeError):
            P2PK().lock(12345)

    def test_p2pk_lock_wrong_length_raises(self):
        from pyrxd.security.errors import ValidationError

        with pytest.raises(ValidationError):
            P2PK().lock(b"\x01" * 10)  # Not 33 or 65 bytes

    def test_bare_multisig_str_hex_pubkeys(self):
        """BareMultisig.lock() accepts hex-string pubkeys."""
        priv = PrivateKey()
        pk_hex = priv.public_key().serialize().hex()
        lock = BareMultisig().lock([pk_hex], 1)
        assert isinstance(lock, Script)

    def test_bare_multisig_threshold_too_high_raises(self):
        from pyrxd.security.errors import ValidationError

        priv = PrivateKey()
        pk = priv.public_key().serialize()
        with pytest.raises(ValidationError):
            BareMultisig().lock([pk], 2)  # threshold > len(participants)
