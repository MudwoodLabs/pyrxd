"""Publish a HashMark record: the plan that can only hold a verified one, and the funded transaction.

:mod:`pyrxd.script.hashmark` builds and reads the record BYTES. This module is the
step between those bytes and a chain: it wraps a record in an ordinary transaction —
the ``OP_RETURN`` at value 0 in output 0, a single plain-RXD input paying the fee,
change back to the funding address — and broadcasts nothing.

**The argument type is the whole design.** :func:`build_hashmark_mark` takes a
:class:`MarkPlan`, never a ``script: bytes``. That is copied deliberately from
:func:`pyrxd.glyph.timelock_reveal_tx.build_timelock_reveal`, whose docstring says
why in one sentence: *"a ``script: bytes`` parameter would have let a caller skip
both [checks] and still get signed bytes back."* The same reasoning applies here to
two things a HashMark caller must not be able to skip:

* **Label canonicalisation.** §5.4 makes trimming and NFC an ENCODER obligation, and
  in v2 the label is inside the signed statement — so an encoder that silently
  trimmed would sign a string its caller never saw. :func:`canonicalize_label`
  transforms and :func:`encode_hashmark` REFUSES; a ``bytes`` door would let a
  hand-assembled record carry a label that renders as something other than what was
  signed.
* **The signature.** A record whose own signature does not verify is well-formed and
  permanently false. On chain there is no edit.

:class:`MarkPlan` enforces both in ``__post_init__`` rather than documenting them,
so there is no way to *hold* a plan whose bytes are not a v2 HashMark that decodes
and attests. Note where that lands the label rule: :func:`decode_hashmark` makes a
non-canonical v2 label ``INVALID`` (it is inside the signed statement), so a plan
carrying one cannot be constructed at all — by the encoder or by hand. The
canonicalisation gate is therefore structural, not a convention the encoder happens
to apply.

:func:`build_hashmark_mark` additionally refuses anything that is not really a
:class:`MarkPlan`. The type annotation alone is a mypy-time claim, and the one door
this module exists to close is a caller assembling their own object; an
``isinstance`` check costs nothing and makes the annotation load-bearing at runtime.

**What a mark proves, and what this module must not be read as claiming.** A mark
proves that *someone knew this digest no later than the confirmed block containing
this transaction*. Not authorship, not ownership, not originality, not that the
contents are true. A v2 signature identifies the key that made the statement — never
the author. See :mod:`pyrxd.script.hashmark` for the full list; it is normative for
any UI built on this.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .script.hashmark import (
    RADIANT_MAINNET_GENESIS,
    AttestationResult,
    HashMarkRecord,
    _require_signable_genesis,
    algorithm_for,
    decode_hashmark,
    encode_hashmark,
    verify_attestation,
)
from .security.errors import ValidationError

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .keys import PrivateKey
    from .transaction.transaction import Transaction

__all__ = [
    "MARK_MODELLED_BYTES",
    "MarkBuild",
    "MarkPlan",
    "broadcast_hashmark_mark",
    "build_hashmark_mark",
    "digest_file",
    "hashmark_mark_funding_bar",
    "plan_hashmark",
    "plan_hashmark_for_file",
]

#: How much of a file is read at a time when digesting it. A mark is routinely taken
#: over something far larger than the 32 bytes that reach the chain — that asymmetry is
#: the point of the format — so the file is streamed rather than read whole.
_DIGEST_CHUNK_BYTES = 1024 * 1024


def digest_file(path: Path | str, *, algorithm_id: int = 0x01) -> bytes:
    """Digest the file at *path* with the hash *algorithm_id* names, streamed.

    The hasher is looked up through :func:`pyrxd.script.hashmark.algorithm_for`, which
    reads the same id→name table the encoder writes into the record's header byte.
    Spelling ``sha256`` here instead would be a second source of truth for which
    algorithm a record claims, and the two would eventually disagree — the record would
    say one thing and the bytes would be the other, with no test able to see it.
    """
    hasher = hashlib.new(algorithm_for(algorithm_id))
    # `open` rather than `Path.open`: *path* is accepted as a str too, and the extra
    # `Path(...)` round trip buys nothing on a read that is immediately streamed.
    with open(path, "rb") as fh:
        while chunk := fh.read(_DIGEST_CHUNK_BYTES):
            hasher.update(chunk)
    return hasher.digest()


@dataclass(frozen=True)
class MarkPlan:
    """A HashMark record that has been decoded and attested from its own published bytes.

    Holding one of these means all of the following are true OF THE BYTES IN
    ``op_return_script``, not of the object they were built from:

    * they decode as a v2 HashMark (:class:`~pyrxd.script.hashmark.HashMarkOutcome.OK`);
    * every push is minimally encoded — §4.1 gives a record exactly one valid
      serialization, and :func:`decode_hashmark` treats a non-minimal push as
      not-a-HashMark rather than a HashMark to repair;
    * the label, if any, is canonical per §5.4 — a non-canonical v2 label makes the
      record ``INVALID``, because it is inside the signed statement;
    * the signature recovers to the signer the record commits to, against
      ``network_genesis``.

    The checks run in ``__post_init__``, so there is no order of operations that
    produces an unchecked one. ``record`` and ``attestation`` are not constructor
    arguments for the same reason: derived here, they cannot be supplied inconsistently
    with the bytes.

    :param op_return_script: the ``scriptPubKey`` that will be published verbatim.
    :param network_genesis: the genesis hash, in RPC/display order, of the chain these
        bytes are FOR. It is not carried by the record; it is part of the signed
        statement, so the same bytes on another chain are a different statement and do
        not verify there (§5.6, §2.10). Getting this wrong does not produce a broken
        transaction — it produces a perfectly relayable record whose claim is false on
        the chain it lands on. So it must be 64 lowercase hex and the genesis of a chain
        pyrxd knows: the attestation check below verifies against THIS string, so on its
        own it is circular for exactly this field — bytes signed for ``"mainnet"`` verify
        against ``"mainnet"``.
    :param source: what was digested, for a confirmation prompt to show. Local only;
        no part of it reaches the chain.
    :param allow_unknown_genesis: accept a well-formed genesis pyrxd has no constant for.
        See :func:`~pyrxd.script.hashmark.encode_hashmark`.
    """

    op_return_script: bytes
    network_genesis: str = RADIANT_MAINNET_GENESIS
    source: str | None = None
    allow_unknown_genesis: bool = False
    #: The record as read back OFF ``op_return_script``.
    record: HashMarkRecord = field(init=False)
    #: The §6.3 verdict a stranger computes, run here before anything is funded.
    attestation: AttestationResult = field(init=False)

    def __post_init__(self) -> None:
        # Before the attestation, which cannot catch it: see `network_genesis` above.
        _require_signable_genesis(self.network_genesis, allow_unknown_genesis=self.allow_unknown_genesis)
        record = decode_hashmark(self.op_return_script)
        if not record.ok:
            raise ValidationError(
                f"these bytes are not a publishable HashMark record: {record.outcome.value}"
                + (f" ({record.detail})" if record.detail else "")
            )
        if record.version != 2:
            # pyrxd writes v2 only. v1 carries no signature, so a v1 mark says WHEN and
            # never WHO — and this module's whole job is to fund a statement somebody
            # made. Reading v1 stays supported; writing one does not.
            raise ValidationError(f"pyrxd publishes v2 records only, these are v{record.version}")
        attestation = verify_attestation(record, network_genesis=self.network_genesis)
        if not attestation.valid:
            # UNVERIFIABLE lands here too, and deliberately. It means secp256k1 is
            # absent, which is the browser's case and never this one — funding a
            # transaction needs the same curve to sign the input. Broadcasting a
            # signature nothing checked would put a permanent claim on chain on the
            # strength of a missing dependency.
            raise ValidationError(
                f"refusing to plan a mark whose signature does not verify against "
                f"{self.network_genesis}: {attestation.outcome.value} ({attestation.detail})"
            )
        object.__setattr__(self, "record", record)
        object.__setattr__(self, "attestation", attestation)

    @property
    def digest_hex(self) -> str:
        """Lowercase hex of the digest this mark commits to — §5.3's one accepted spelling."""
        return self.record.digest_hex or ""

    @property
    def algorithm(self) -> str:
        return self.record.algorithm or ""

    @property
    def label(self) -> str | None:
        """The canonical label, or ``None`` when the record carries no label push.

        An absent label is a DIFFERENT signed statement from an empty one — §5.6 omits
        the key entirely rather than writing ``""`` — so this is never ``""``.
        """
        return self.record.label

    @property
    def signer_hash160_hex(self) -> str:
        """The committed signer. Equal to ``attestation.recovered_hash160_hex`` by construction."""
        return self.record.signer_hash160_hex or ""

    @property
    def size_bytes(self) -> int:
        """Size of the record on chain. §3.2 caps it at 223."""
        return len(self.op_return_script)


def plan_hashmark(
    digest: bytes,
    private_key: PrivateKey,
    *,
    label: str | None = None,
    algorithm_id: int = 0x01,
    network_genesis: str = RADIANT_MAINNET_GENESIS,
    source: str | None = None,
    allow_unknown_genesis: bool = False,
) -> MarkPlan:
    """Sign *digest* into a v2 HashMark record and check it the way a stranger will.

    A thin composition of :func:`~pyrxd.script.hashmark.encode_hashmark` and
    :class:`MarkPlan`, and the ONE supported way to get bytes into
    :func:`build_hashmark_mark`. See :class:`MarkPlan` for what holding the result
    means and :func:`~pyrxd.script.hashmark.encode_hashmark` for every refusal on the
    way in — in particular that *label* must already be canonical:
    :func:`~pyrxd.script.hashmark.canonicalize_label` produces the canonical spelling,
    and §5.4 requires the caller SHOW THE USER that spelling before it is signed, which
    is exactly the step a library cannot do for them.
    """
    script = encode_hashmark(
        digest,
        private_key,
        label=label,
        algorithm_id=algorithm_id,
        network_genesis=network_genesis,
        allow_unknown_genesis=allow_unknown_genesis,
    )
    return MarkPlan(
        op_return_script=script,
        network_genesis=network_genesis,
        source=source,
        allow_unknown_genesis=allow_unknown_genesis,
    )


def plan_hashmark_for_file(
    path: Path | str,
    private_key: PrivateKey,
    *,
    label: str | None = None,
    algorithm_id: int = 0x01,
    network_genesis: str = RADIANT_MAINNET_GENESIS,
    allow_unknown_genesis: bool = False,
) -> MarkPlan:
    """:func:`plan_hashmark` over the digest of a file, with ``source`` set to its path.

    The file's bytes do not go on chain and are not kept: only the digest is signed.
    Marking a file you have not read is a hazard the format cannot help with — a
    digest proves integrity, never that the contents are true or yours.
    """
    return plan_hashmark(
        digest_file(path, algorithm_id=algorithm_id),
        private_key,
        label=label,
        algorithm_id=algorithm_id,
        network_genesis=network_genesis,
        source=str(path),
        allow_unknown_genesis=allow_unknown_genesis,
    )


#: Modelled bytes of a mark transaction WITHOUT its OP_RETURN script, that script's
#: length varint, and any change output.
#:
#: ``4`` version + ``1`` input count + (``36`` outpoint + ``1`` script varint + ``107``
#: unlocking script + ``4`` sequence) + ``1`` output count + ``8`` value + ``4`` locktime
#: = **166**. ``107`` is :meth:`P2PKH.unlock`'s ``estimated_unlocking_byte_length`` and is
#: an upper bound on this template (the real script is 105-107 B), so this models the
#: largest transaction the builder can produce.
#:
#: READ THAT 107 PRECISELY: it is the COMPRESSED-key figure. ``P2PKH.unlock`` returns 139
#: for an uncompressed key (``script/type.py``), which this model would be 32 bytes short
#: of. Every key an ``HdWallet`` derives is compressed, so the gap is not reachable from
#: the shipped wallet — and if it ever were, the consequence is a refusal rather than an
#: under-paying broadcast: ``assert_pays_for_its_size`` measures the SIGNED bytes after
#: the fact and raises. The bar is a funding threshold, not the fee.
#:
#: The same number as :data:`pyrxd.glyph.timelock_reveal_tx.TIMELOCK_REVEAL_MODELLED_BYTES`
#: because it is the same transaction shape, spelled out again rather than imported: a
#: mark is not a Glyph operation, and borrowing a constant across that line would make a
#: later change to the reveal's shape silently resize this.
MARK_MODELLED_BYTES = 166


def hashmark_mark_funding_bar(op_return_script: bytes, fee_rate: int) -> int:
    """Photons a plain-RXD UTXO must hold to fund one mark, at *fee_rate*.

    Modelled on the **no-change** shape, for the reason
    :func:`pyrxd.glyph.transfer.nft_transfer_funding_bar` documents: ``Transaction.fee``
    drops the change output when the funding cannot also cover it, so the smallest UTXO
    that works is the one paying for the ONE-output transaction. Sizing against the
    larger shape would refuse funding that in fact relays, which is its own bug.
    """
    from .fee_sizing import required_fee

    script_len = len(op_return_script)
    len_varint = 1 if script_len < 0xFD else 3
    return required_fee(MARK_MODELLED_BYTES + len_varint + script_len, fee_rate)


@dataclass(frozen=True)
class MarkBuild:
    """A signed, un-broadcast mark transaction.

    :param tx: the signed transaction
    :param fee: photons paid, from the plain-RXD funding input
    :param plan: the checked :class:`MarkPlan` these bytes were built from — carried so
        a confirmation prompt can show what is about to be published permanently without
        re-deriving it
    :param from_address: the wallet address that funded the mark. Note this is NOT
        necessarily the signer: the key that makes the statement is chosen by whoever
        built the plan, and the fee is paid by whichever plain-RXD UTXO was large enough.
    :param has_change: ``False`` when the whole funding UTXO became the fee
    """

    tx: Transaction
    fee: int
    plan: MarkPlan
    from_address: str
    has_change: bool

    def serialize(self) -> bytes:
        """Raw transaction bytes, ready for ``await client.broadcast(...)``."""
        return bytes(self.tx.serialize())


def _client_chain_genesis(client: Any) -> str | None:
    """The genesis hash *client* says it is on, or ``None`` when it does not say.

    Read from a real :class:`~pyrxd.network.registry.NetworkProfile` only — an ``isinstance``
    check, not attribute sniffing, so a stand-in object with a ``profile`` attribute of some other
    shape is "does not say" rather than a value to compare against.
    """
    from .network.registry import NetworkProfile

    profile = getattr(client, "profile", None)
    if not isinstance(profile, NetworkProfile):
        return None
    genesis = profile.genesis_hash
    return genesis if isinstance(genesis, str) else None


async def build_hashmark_mark(
    wallet: Any,
    plan: MarkPlan,
    *,
    client: Any,
    fee_rate: int,
    allow_overpay: bool = False,
    allow_below_relay_floor: bool = False,
) -> MarkBuild:
    """Wrap a checked mark plan in a funded, signed transaction. Does not broadcast.

    Takes a :class:`MarkPlan`, never a raw script — see this module's docstring for the
    two things a ``script: bytes`` parameter would have let a caller skip. The
    ``isinstance`` guard below is what makes that annotation mean something at runtime:
    without it the one door worth closing, a caller assembling their own object with
    the right attribute names, is wide open and mypy-clean.

    The mark publishes data, not value: output 0 is the ``OP_RETURN`` at value 0 and the
    fee comes from one plain-RXD input, with change returning to the funding address.
    :func:`~pyrxd.glyph.transfer.find_plain_rxd_utxo` verifies each candidate's
    **on-chain** script is a bare P2PKH, so a token-bearing UTXO is never spent here —
    burning an NFT to publish a hash about a file would be a memorable way to close this
    issue.

    Raises:
        ~pyrxd.security.errors.ValidationError: *plan* is not a :class:`MarkPlan`, or
            *client* names a chain whose genesis is not the one the plan was signed for,
            or the fee rate is out of bounds, or the signed transaction does not pay for
            its own size.
        ~pyrxd.security.errors.InsufficientFundsError: no plain-RXD UTXO large enough.
            Raised before anything is signed.
    """
    from .fee_models import SatoshisPerKilobyte
    from .fee_sizing import assert_fee_rate_clears_relay_floor, assert_pays_for_its_size
    from .glyph.transfer import NoFeeFundingError, find_plain_rxd_utxo
    from .script.script import Script
    from .script.type import P2PKH
    from .transaction.transaction import Transaction
    from .transaction.transaction_input import TransactionInput
    from .transaction.transaction_output import TransactionOutput

    if not isinstance(plan, MarkPlan):
        raise ValidationError(
            f"build_hashmark_mark takes a MarkPlan, not {type(plan).__name__} — a plan can only come "
            f"from plan_hashmark(), which is where the label is required to be canonical and the "
            f"signature is required to verify"
        )

    # THE PLAN SAYS WHICH CHAIN THE STATEMENT IS ABOUT; THE CLIENT SAYS WHICH CHAIN IT IS ON.
    # Nothing compared them, so a plan signed for mainnet was funded and signed through a testnet
    # client without complaint — and the record, once broadcast, does not verify on the chain that
    # carries it. Compared whenever the client names its chain (a `FailoverElectrumXClient`
    # carries its `NetworkProfile`, and by default checks each server against that genesis on first
    # use). A client that names no chain cannot be compared, and is not refused for it: a plain
    # `ElectrumXClient` carries no profile, and refusing it would refuse every honest caller
    # using one.
    client_genesis = _client_chain_genesis(client)
    if client_genesis is not None and client_genesis != plan.network_genesis:
        raise ValidationError(
            f"this mark is signed for the chain with genesis {plan.network_genesis}, but the client "
            f"is on the chain with genesis {client_genesis} — published there, the record would not "
            f"verify on the chain that carries it. Plan it with network_genesis={client_genesis!r}, or "
            f"build it through a client for the chain it was signed for."
        )

    assert_fee_rate_clears_relay_floor(
        fee_rate,
        what="build_hashmark_mark",
        allow_overpay=allow_overpay,
        allow_below_relay_floor=allow_below_relay_floor,
        error_type=ValidationError,
    )

    script = plan.op_return_script
    needed = hashmark_mark_funding_bar(script, fee_rate)
    triples = await wallet.collect_spendable(client)
    fund = await find_plain_rxd_utxo(triples, client, exclude=set(), needed=needed)
    if fund is None:
        raise NoFeeFundingError(
            f"no plain-RXD UTXO large enough to fund the mark — need at least {needed:,} photons on a "
            f"single non-token UTXO (~{MARK_MODELLED_BYTES + len(script)} B at {fee_rate:,} photons/B). "
            f"The mark carries a {len(script)}-byte OP_RETURN."
        )
    fund_utxo, fund_addr, fund_key = fund
    fund_spk = P2PKH().lock(fund_addr)

    def _shim(vout: int, locking: Script, value: int, txid: str) -> Transaction:
        """A stand-in parent tx so preimage computation can index ``outputs[vout]``.

        Same shim as :func:`pyrxd.glyph.transfer.build_nft_transfer` uses, and for the
        same reason: only the txid and the output at ``vout`` are real.
        """
        outs = [TransactionOutput(Script(b""), 0) for _ in range(vout)]
        outs.append(TransactionOutput(locking, value))
        src = Transaction(tx_inputs=[], tx_outputs=outs)
        src.txid = lambda: txid  # type: ignore[method-assign]
        return src

    fund_input = TransactionInput(
        source_transaction=_shim(fund_utxo.tx_pos, fund_spk, fund_utxo.value, fund_utxo.tx_hash),
        source_txid=fund_utxo.tx_hash,
        source_output_index=fund_utxo.tx_pos,
        unlocking_script_template=P2PKH().unlock(fund_key),
    )
    fund_input.satoshis = fund_utxo.value
    fund_input.locking_script = fund_spk

    tx = Transaction(
        tx_inputs=[fund_input],
        tx_outputs=[
            TransactionOutput(Script(script), 0),  # the record — value 0, unspendable
            TransactionOutput(fund_spk, 0, change=True),
        ],
    )
    tx.fee(SatoshisPerKilobyte(fee_rate * 1000))  # type: ignore[no-untyped-call]
    tx.sign()

    raw = tx.serialize()
    fee_paid = tx.get_fee()
    assert_pays_for_its_size(
        size_bytes=len(raw),
        fee_paid=fee_paid,
        fee_rate=fee_rate,
        what="the HashMark mark",
        error_type=ValidationError,
    )
    return MarkBuild(
        tx=tx,
        fee=fee_paid,
        plan=plan,
        from_address=fund_addr,
        has_change=len(tx.outputs) > 1,
    )


async def broadcast_hashmark_mark(client: Any, build: MarkBuild) -> str:
    """Send a built mark and return the txid OF THE BYTES THAT WERE SIGNED.

    Split from :func:`build_hashmark_mark` for the reason
    :meth:`pyrxd.glyph.client.GlyphClient.broadcast_timelock_reveal` documents: a caller
    that showed someone a build must send THOSE bytes, not rebuild and send a second
    transaction after the prompt — a confirmation showing one artifact and sending
    another is worse than no confirmation, because it looks like one.

    The txid comes from ``_confirmed_txid``, which compares the server's echo against
    ``hash256`` of the signed bytes and RAISES on a mismatch. That helper is imported
    rather than re-implemented even though it lives under ``glyph``: it is structural
    (its own protocol asks only for ``.tx``) and explicitly not Glyph-specific, and a
    second copy of a "do not believe the server's txid" check is exactly the kind of
    duplicate that drifts. A mark carries no value, so the failure it prevents is not a
    lost coin — it is an operator who believes a file was marked at a height where
    nothing was ever published, which for a timestamping format is the whole product.
    """
    from .glyph.client import _confirmed_txid

    echoed = await client.broadcast(build.serialize())
    return _confirmed_txid(build, echoed)
