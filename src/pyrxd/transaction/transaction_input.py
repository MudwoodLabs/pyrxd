from __future__ import annotations

from contextlib import suppress
from io import BytesIO

from ..constants import SIGHASH, TRANSACTION_SEQUENCE
from ..script.script import Script
from ..script.unlocking_template import UnlockingScriptTemplate
from ..utils import Reader


class TransactionInput:
    def __init__(
        self,
        source_transaction=None,
        source_txid: str | None = None,
        source_output_index: int = 0,
        unlocking_script: Script | None = None,
        unlocking_script_template: UnlockingScriptTemplate = None,
        sequence: int = TRANSACTION_SEQUENCE,
        sighash: SIGHASH = SIGHASH.ALL_FORKID,
    ):
        utxo = None
        if source_transaction:
            utxo = source_transaction.outputs[source_output_index]

        self.source_txid = source_txid
        if source_transaction and not source_txid:
            self.source_txid = source_transaction.txid()

        self.source_output_index: int = source_output_index
        self.satoshis: int = utxo.satoshis if utxo else None
        self.locking_script: Script = utxo.locking_script if utxo else None
        self.source_transaction = source_transaction
        self.unlocking_script: Script = unlocking_script
        self.unlocking_script_template = unlocking_script_template
        self.sequence: int = sequence
        self.sighash: SIGHASH = sighash

    def serialize(self) -> bytes:
        stream = BytesIO()
        stream.write(bytes.fromhex(self.source_txid)[::-1])
        stream.write(self.source_output_index.to_bytes(4, "little"))
        stream.write(self.unlocking_script.byte_length_varint() if self.unlocking_script else b"\x00")
        stream.write(self.unlocking_script.serialize() if self.unlocking_script else b"")
        stream.write(self.sequence.to_bytes(4, "little"))
        return stream.getvalue()

    def __str__(self) -> str:  # pragma: no cover
        return (
            f"<TransactionInput outpoint={self.source_txid}:{self.source_output_index} "
            f"value={self.satoshis} locking_script={self.locking_script}>"
        )

    def __repr__(self) -> str:  # pragma: no cover
        return self.__str__()

    @classmethod
    def from_hex(cls, stream: str | bytes | Reader) -> TransactionInput | None:
        with suppress(Exception):
            stream = (
                stream
                if isinstance(stream, Reader)
                else Reader(stream if isinstance(stream, bytes) else bytes.fromhex(stream))
            )
            txid = stream.read_bytes(32)[::-1]
            if len(txid) != 32:
                raise ValueError("expected 32-byte txid")
            vout = stream.read_int(4)
            if vout is None:
                raise ValueError("failed to read vout")
            script_length = stream.read_var_int_num()
            if script_length is None:
                raise ValueError("failed to read script length")
            unlocking_script_bytes = stream.read_bytes(script_length)
            # ``read_bytes`` returns however many bytes are left at EOF rather than
            # erroring, so a varint that over-claims used to yield an input whose
            # unlocking script had swallowed the sequence field — and then
            # ``read_int(4)`` zero-extended whatever fragment was left. The result
            # was a TransactionInput that re-serialized to DIFFERENT bytes, so any
            # txid taken over the parse described a transaction the input bytes do
            # not encode. ``TransactionOutput.from_hex`` has always refused this;
            # the two halves of the same wire format disagreeing about malformed
            # input is how a transaction gets accepted by one and rejected by the
            # other.
            if len(unlocking_script_bytes) != script_length:
                raise ValueError(
                    f"truncated input script: varint claims {script_length} bytes, "
                    f"only {len(unlocking_script_bytes)} available"
                )
            sequence = stream.read_int(4)
            if sequence is None:
                raise ValueError("failed to read sequence")

            return TransactionInput(
                source_txid=txid.hex(),
                source_output_index=vout,
                # Chain bytes: consensus permits a script that ``GetOp`` cannot
                # walk to sit inside a perfectly valid transaction, because a
                # script is only executed when it is spent. Refusing to
                # deserialize one would make pyrxd unable to read real history —
                # a worse bug than the one above. The leniency is confined here
                # and is visible in ``Script.truncated_at``.
                unlocking_script=Script(unlocking_script_bytes, allow_malformed=True),
                sequence=sequence,
            )

        return None
