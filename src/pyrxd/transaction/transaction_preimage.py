from __future__ import annotations

import struct
from io import BytesIO

from ..constants import SIGHASH
from ..hash import hash256
from .transaction_input import TransactionInput
from .transaction_output import TransactionOutput

_ZERO_REF = b"\x00" * 32


_OP_PUSHINPUTREF = 0xD0  # OP_PUSHINPUTREF
_OP_PUSHINPUTREFSINGLETON = 0xD8  # OP_PUSHINPUTREFSINGLETON


def _get_push_refs(script_bytes: bytes) -> list:
    """Return sorted, deduplicated list of 36-byte ref buffers found in script_bytes.

    Scans for OP_PUSHINPUTREF (0xd0) and OP_PUSHINPUTREFSINGLETON (0xd8);
    each is followed by exactly 36 bytes of ref data. All other opcodes are
    skipped using their standard encoding (data-push length or single byte).

    The sort + dedup behavior is **consensus-required**, not a bug:
    radiantjs ``GetHashOutputHashes`` (lib/transaction/sighash.js) produces
    the same encoding, and pyrxd's vectors are pinned against a confirmed
    mainnet reveal tx (see ``tests/test_preimage.py``).

    Raises ``ValidationError`` if a pushref opcode is followed by fewer
    than 36 bytes (truncated script). Earlier versions silently produced
    a short ref entry that still got hashed, diverging from node consensus
    on malformed inputs.
    """
    refs = {}
    n_total = len(script_bytes)
    i = 0
    while i < n_total:
        op = script_bytes[i]
        i += 1
        if op in (_OP_PUSHINPUTREF, _OP_PUSHINPUTREFSINGLETON):
            if i + 36 > n_total:
                from pyrxd.security.errors import ValidationError

                raise ValidationError(
                    f"truncated pushref at offset {i - 1}: expected 36 bytes of ref data, only {n_total - i} available"
                )
            ref = script_bytes[i : i + 36]
            i += 36
            refs[ref.hex()] = ref
        elif 0x01 <= op <= 0x4B:
            i += op  # direct push: skip data bytes
        elif op == 0x4C:  # OP_PUSHDATA1
            n = script_bytes[i]
            i += 1 + n
        elif op == 0x4D:  # OP_PUSHDATA2
            n = int.from_bytes(script_bytes[i : i + 2], "little")
            i += 2 + n
        elif op == 0x4E:  # OP_PUSHDATA4
            n = int.from_bytes(script_bytes[i : i + 4], "little")
            i += 4 + n
        # else: single-byte opcode, already advanced by 1
    return [refs[k] for k in sorted(refs.keys())]


def _compute_hash_output_hashes(outputs: list[TransactionOutput], index: int = None) -> bytes:
    """Radiant-specific hashOutputHashes field in the BIP143 preimage.

    For each output (all outputs, or just output[index] for SIGHASH_SINGLE):
      - value (8-byte LE)
      - hash256(locking_script)
      - count of push refs (4-byte LE)
      - if count > 0: hash256(sorted ref bytes concatenated); else: 32 zero bytes

    The whole blob is then hash256'd.
    """
    buf = BytesIO()
    start = 0 if index is None else index
    end = (len(outputs) - 1) if index is None else index
    for i in range(start, end + 1):
        out = outputs[i]
        script_bytes = out.locking_script.serialize()
        buf.write(out.satoshis.to_bytes(8, "little"))
        buf.write(hash256(script_bytes))
        push_refs = _get_push_refs(script_bytes)
        buf.write(struct.pack("<I", len(push_refs)))
        if push_refs:
            combined = b"".join(push_refs)
            buf.write(hash256(combined))
        else:
            buf.write(_ZERO_REF)
    return hash256(buf.getvalue())


def _preimage(
    tx_input: TransactionInput,
    tx_version: int,
    tx_locktime: int,
    hash_prevouts: bytes,
    hash_sequence: bytes,
    hash_output_hashes: bytes,
    hash_outputs: bytes,
) -> bytes:
    """
    Radiant BIP-143 extension of the sighash preimage.

    Identical to Bitcoin SV BIP143 except field 8 (hashOutputHashes) is
    inserted before hashOutputs. This extra field hashes each output's value,
    script hash, and ref count (always 0 for standard P2PKH/FT/NFT outputs).

     1. nVersion (4-byte LE)
     2. hashPrevouts (32-byte hash)
     3. hashSequence (32-byte hash)
     4. outpoint (32-byte hash + 4-byte LE)
     5. scriptCode of the input (varint-length-prefixed)
     6. value of the output spent by this input (8-byte LE)
     7. nSequence (4-byte LE)
     8. hashOutputHashes (32-byte hash) ← Radiant extension
     9. hashOutputs (32-byte hash)
    10. nLocktime (4-byte LE)
    11. sighash type (4-byte LE)
    """
    stream = BytesIO()
    stream.write(tx_version.to_bytes(4, "little"))  # 1
    stream.write(hash_prevouts)  # 2
    stream.write(hash_sequence)  # 3
    stream.write(bytes.fromhex(tx_input.source_txid)[::-1])  # 4
    stream.write(tx_input.source_output_index.to_bytes(4, "little"))
    stream.write(tx_input.locking_script.byte_length_varint())  # 5
    stream.write(tx_input.locking_script.serialize())
    stream.write(tx_input.satoshis.to_bytes(8, "little"))  # 6
    stream.write(tx_input.sequence.to_bytes(4, "little"))  # 7
    stream.write(hash_output_hashes)  # 8 Radiant extension
    stream.write(hash_outputs)  # 9
    stream.write(tx_locktime.to_bytes(4, "little"))  # 10
    stream.write(tx_input.sighash.to_bytes(4, "little"))  # 11
    return stream.getvalue()


def tx_preimages(
    inputs: list[TransactionInput],
    outputs: list[TransactionOutput],
    tx_version: int,
    tx_locktime: int,
) -> list[bytes]:
    """
    :returns: the preimages of unsigned transaction (one per input)
    """
    _hash_prevouts = hash256(
        b"".join(bytes.fromhex(_in.source_txid)[::-1] + _in.source_output_index.to_bytes(4, "little") for _in in inputs)
    )
    _hash_sequence = hash256(b"".join(_in.sequence.to_bytes(4, "little") for _in in inputs))
    _hash_outputs = hash256(b"".join(tx_output.serialize() for tx_output in outputs))
    _compute_hash_output_hashes_all = _compute_hash_output_hashes(outputs)
    digests = []
    for i in range(len(inputs)):
        sighash = inputs[i].sighash
        # hash previous outs
        if not sighash & SIGHASH.ANYONECANPAY:
            hash_prevouts = _hash_prevouts
        else:
            hash_prevouts = b"\x00" * 32
        # hash sequence
        if not sighash & SIGHASH.ANYONECANPAY and sighash & 0x1F != SIGHASH.SINGLE and sighash & 0x1F != SIGHASH.NONE:
            hash_sequence = _hash_sequence
        else:
            hash_sequence = b"\x00" * 32
        # hash outputs and hashOutputHashes
        if sighash & 0x1F != SIGHASH.SINGLE and sighash & 0x1F != SIGHASH.NONE:
            hash_outputs = _hash_outputs
            hash_output_hashes = _compute_hash_output_hashes_all
        elif sighash & 0x1F == SIGHASH.SINGLE and i < len(outputs):
            hash_outputs = hash256(outputs[i].serialize())
            hash_output_hashes = _compute_hash_output_hashes(outputs, index=i)
        else:
            hash_outputs = b"\x00" * 32
            hash_output_hashes = b"\x00" * 32
        digests.append(
            _preimage(
                inputs[i], tx_version, tx_locktime, hash_prevouts, hash_sequence, hash_output_hashes, hash_outputs
            )
        )
    return digests


def tx_preimage(
    input_index: int,
    inputs: list[TransactionInput],
    outputs: list[TransactionOutput],
    tx_version: int,
    tx_locktime: int,
) -> bytes:
    """Calculates and returns the Radiant BIP143 preimage for a specific input index."""
    sighash = inputs[input_index].sighash

    # hash previous outs
    if not sighash & SIGHASH.ANYONECANPAY:
        hash_prevouts = hash256(
            b"".join(
                bytes.fromhex(_in.source_txid)[::-1] + _in.source_output_index.to_bytes(4, "little") for _in in inputs
            )
        )
    else:
        hash_prevouts = b"\x00" * 32

    # hash sequence
    if not sighash & SIGHASH.ANYONECANPAY and sighash & 0x1F != SIGHASH.SINGLE and sighash & 0x1F != SIGHASH.NONE:
        hash_sequence = hash256(b"".join(_in.sequence.to_bytes(4, "little") for _in in inputs))
    else:
        hash_sequence = b"\x00" * 32

    # hash outputs and hashOutputHashes (Radiant extension)
    if sighash & 0x1F != SIGHASH.SINGLE and sighash & 0x1F != SIGHASH.NONE:
        hash_outputs = hash256(b"".join(tx_output.serialize() for tx_output in outputs))
        hash_output_hashes = _compute_hash_output_hashes(outputs)
    elif sighash & 0x1F == SIGHASH.SINGLE and input_index < len(outputs):
        hash_outputs = hash256(outputs[input_index].serialize())
        hash_output_hashes = _compute_hash_output_hashes(outputs, index=input_index)
    else:
        hash_outputs = b"\x00" * 32
        hash_output_hashes = b"\x00" * 32

    return _preimage(
        inputs[input_index],
        tx_version,
        tx_locktime,
        hash_prevouts,
        hash_sequence,
        hash_output_hashes,
        hash_outputs,
    )
