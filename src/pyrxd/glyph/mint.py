"""High-level, resumable Glyph mint facade — commit/reveal in two named phases.

Why this exists
---------------
Minting a Glyph is a two-transaction protocol, and every caller that has ever
driven it from the SDK has re-implemented the same ~150 lines around the
builders: fetch UTXOs, size the commit so the reveal can pay its own fee, build
and sign the commit, wait for it, rebuild the reveal against the real commit
txid, sign, broadcast. ``examples/glyph_mint_demo.py``, ``examples/ft_deploy_premine.py``
and ``examples/regtest_quickstart.py`` each carried their own copy — including
three separate copies of the reveal unlocking-script template.

Nothing here is new protocol code. :class:`~pyrxd.glyph.builder.GlyphBuilder`
already produces the scripts; :mod:`pyrxd.glyph.fees` already sizes the reveal;
:func:`pyrxd.network.confirm.wait_for_confirmation` already polls. This module is
the plumbing between them, and only that.

The hashlock, and why persistence is not optional
-------------------------------------------------
The commit output is a hashlock —
:func:`~pyrxd.glyph.script.build_commit_locking_script` emits
``OP_HASH256 <payload_hash> OP_EQUALVERIFY`` *before* the P2PKH tail. The only
way to spend it is a reveal whose scriptSig pushes CBOR bytes that hash to
``payload_hash``. There is no owner-only escape path: the key that funded the
commit cannot sweep it back.

So **losing the exact CBOR bytes between the commit and the reveal makes the
commit output permanently unspendable**, and the commit output is where the
mint's value sits. That is the single largest failure mode in this flow, and it
is a *crash* failure, not a logic failure — the process dies in the window
between broadcasting the commit and building the reveal.

That is why :class:`PendingStore` is a **required** constructor argument on
:class:`GlyphMinter` rather than an optional ``persist=None`` keyword. An
optional keyword defaults the fund-safety mechanism to OFF on the most
discoverable method in the module. A caller who genuinely does not want
persistence has to name :class:`UnsafeNullPendingStore`, which says what it is
and warns when constructed.

Is the CBOR reproducible?
~~~~~~~~~~~~~~~~~~~~~~~~~
Partly, and not reliably enough to depend on.
:func:`~pyrxd.glyph.payload.encode_payload` encodes with
``cbor2.dumps(..., canonical=True)``, so *identical* :class:`~pyrxd.glyph.types.GlyphMetadata`
does re-encode to identical bytes — the encoding itself is deterministic. But
:class:`~pyrxd.glyph.types.GlyphMetadata` carries ``created`` (a timestamp) and
``commit_outpoint``, and callers routinely build metadata with ``str(int(time.time()))``
in ``attrs``. Re-deriving the payload therefore reproduces it only if the caller
kept every input byte-stable, which is exactly the assumption a crashed process
cannot make. We store the bytes because the metadata may not be reproducible in
practice — not because the encoding is non-deterministic.

Ordering
~~~~~~~~
:class:`PendingMint` is persisted **before** the commit is broadcast, and the
write is verified by reading it back (see :meth:`GlyphMinter._persist_or_abort`).
Persisting after the broadcast would leave precisely the window this exists to
close.

What is deliberately not here
-----------------------------
* **Transfers.** ``GlyphBuilder.build_nft_transfer_tx`` / ``build_ft_transfer_tx``
  and :class:`~pyrxd.glyph.ft.FtUtxoSet` already cover them, and
  ``examples/ft_transfer_demo.py`` drives them directly. Transfers are a
  single transaction with no hashlock and no resumable middle state — none of
  this module's machinery applies.
* **Holdings/queries.** :class:`~pyrxd.glyph.scanner.GlyphScanner` is public.
* **Retargeting the CLI onto this facade.** ``pyrxd glyph mint-nft`` asks for
  confirmation twice — once before the commit and once before the reveal, the
  second after a 10+ minute wait. A facade that owns the whole flow has nowhere
  to put the second gate, so retargeting would silently drop a safety default.
  The CLI keeps its own composition on purpose; what it shares with this module
  is the sizing and fee-guard code in :mod:`pyrxd.glyph.fees`.
"""

from __future__ import annotations

import abc
import json
import os
import warnings
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, ClassVar

from ..constants import DUST_THRESHOLD_PHOTONS
from ..fee_models import SatoshisPerKilobyte
from ..network.confirm import DEFAULT_CONFIRMATION_TIMEOUT_S, wait_for_confirmation
from ..script.script import Script
from ..script.type import P2PKH, encode_pushdata, to_unlock_script_template
from ..security.errors import InsufficientFundsError, RxdSdkError, ValidationError
from ..security.types import Hex20, Txid
from ..transaction.transaction import Transaction
from ..transaction.transaction_input import TransactionInput
from ..transaction.transaction_output import TransactionOutput
from .builder import MIN_FEE_RATE, CommitParams, GlyphBuilder, RevealParams
from .fees import (
    REVEAL_SIG_PREFIX_BYTES,
    check_reveal_funding,
    commit_value_for_reveal,
    estimate_reveal_fee_for_metadata,
    measure_reveal_fee,
)
from .script import build_commit_locking_script, hash_payload
from .types import GlyphMetadata, GlyphProtocol, GlyphRef

__all__ = [
    "DEFAULT_MINT_CONFIRMATIONS",
    "NFT_CARRIER_VALUE",
    "PENDING_MINT_SCHEMA_VERSION",
    "GlyphMinter",
    "JsonFilePendingStore",
    "MintResult",
    "PendingMint",
    "PendingMintNotFound",
    "PendingStore",
    "UnsafeNullPendingStore",
    "build_reveal_unlock_template",
]


# The reveal places the NFT singleton on a small carrier output; the rest of the commit
# value comes back as change. 546 photons is a pyrxd CONVENTION (Bitcoin's dust figure),
# not a chain minimum — Radiant's floor is 1 photon, which is what every mainnet dMint
# contract singleton actually uses. Aliased from the one definition so this and
# ``pyrxd.cli.glyph_cmds`` cannot drift.
NFT_CARRIER_VALUE = DUST_THRESHOLD_PHOTONS

# Confirmations required on the commit before the reveal is built.
#
# THIS IS CONVENTION, NOT A CONSENSUS REQUIREMENT — stated plainly because the number
# looks like a protocol constant and is not one. What was checked, and what was found:
#
# * No doc, docstring or comment in this repository states a rule that the commit must
#   be mined first. Every explanation of the wait gives an operational reason instead —
#   block timing (``docs/tutorials/mint-a-glyph-nft.md``, which sizes its wait against
#   Radiant's ~5-minute target spacing — ``nPowTargetSpacing = 5 * 60`` in
#   ``Radiant-Core/src/chainparams.cpp:117`` @ v3.1.2; the tutorial used to say
#   "~2 minutes"), propagation lag, or mempool eviction
#   (``pyrxd.glyph.dmint.chain``: an unconfirmed parent risks "missing inputs" rejection
#   "when the parent tx hasn't propagated to all relays").
# * The Radiant ref rule that IS documented, in ``pyrxd.glyph.script``, is purely
#   intra-transaction: every ``OP_PUSHINPUTREF`` in an output script must also appear in
#   an input of the SAME transaction. It says nothing about height or depth. The commit
#   covenant derives its ref from the spending input's own outpoint and reads no chain
#   state at all.
# * There is on-chain counter-evidence: the mainnet dMint deploy recorded in
#   ``docs/solutions/logic-errors/dmint-deploy-reveal-hashlock-reuse.md`` has its commit
#   (a443d9df…) and the reveal that spends it (b965b32d…) in the SAME block, 228604.
# * Confirmation depth does appear elsewhere in the codebase, but always as a third-party
#   REORG gate on an already-minted token (``pyrxd.gravity.ref_authenticity``,
#   ``pyrxd.glyph.credential_binding``) — never as a mint-validity rule.
#
# So 1 is picked as a conservative default matching shipped behaviour (``pyrxd glyph
# mint-nft`` polls to depth 1 via ``pyrxd.network.confirm``), NOT because a rule was
# found requiring it. Raising it is always safe. A caller who has established that
# chained mempool spends relay on their network can drive :meth:`GlyphMinter.reveal_nft`
# directly after :meth:`GlyphMinter.commit_nft` returns — but note that reveal-with-
# unconfirmed-parent is untested here, and a commit evicted from the mempool takes the
# reveal with it.
DEFAULT_MINT_CONFIRMATIONS = 1

# Stand-in commit txid for the dry-run reveal measured before the real commit exists.
# A txid occupies 32 bytes in the input outpoint and 32 bytes in the reveal locking
# script's ref push whatever its value, so the dry run serializes to exactly the length
# of the real reveal — which is what the fee model measures.
_PLACEHOLDER_COMMIT_TXID = "00" * 32

# Bumped when the persisted shape changes. ``PendingMint.from_dict`` REJECTS anything it
# does not recognise rather than best-effort parsing it: a half-understood record on this
# path produces a reveal that cannot spend the commit.
PENDING_MINT_SCHEMA_VERSION = 1

# Protocol tags whose reveal is NOT the single-output shape this module builds. MUT and
# WAVE need a second contract output AND a second commit outpoint to seed its singleton
# ref (``prepare_mutable_reveal``), and DMINT needs the parallel contract set
# (``prepare_dmint_deploy``). Minting one of those through here would broadcast a commit
# whose reveal this module cannot build — i.e. strand it.
#
# CONTAINER is deliberately ABSENT (0.15.0). A container's reveal is the ordinary
# single-output NFT reveal — its locking script is the plain 63-byte singleton and
# container-ness lives in the envelope's ``p`` field, so ``mint_nft`` builds it
# correctly with no special case. Before 0.15.0 it was listed here because
# ``prepare_container_reveal`` could emit a 100-byte child-ref prefix; that shape was
# unspendable and has been removed.
#: Why each refused protocol is refused, and what a caller should actually do.
#:
#: The refusal used to say only "its reveal is not the single-output shape this facade
#: builds — use ``GlyphBuilder.<method>`` directly". True, and for MUT/WAVE incomplete
#: in a way that would strand funds: the reveal takes a SECOND input at
#: ``commit_txid:(commit_vout + 1)``, so the COMMIT has to carry an ordinary output
#: there, and a caller following that advice against this module's commit shape would
#: find vout 1 is the change output — which ``Transaction.fee()`` removes outright when
#: the remainder does not cover it. The commit is a hashlock with no owner-only spend
#: path, so a commit broadcast without its seed is unspendable forever.
#:
#: Extending the facade to cover them was considered and rejected; see the spike note
#: in ``docs/plans/2026-08-09-gap-closure-plan.md`` (§B2.3).
_UNSUPPORTED_PROTOCOLS = {
    GlyphProtocol.MUT: (
        "prepare_mutable_reveal",
        "Its reveal needs TWO inputs — the commit, plus a plain seed output at "
        "commit_vout + 1 whose outpoint becomes the mutable contract's ref (the covenant "
        "recomputes the token ref as mutable_ref.vout - 1, so the two cannot be the same "
        "outpoint). This module's commit puts a CHANGE output at vout 1, and "
        "Transaction.fee() drops change outputs it cannot fund, so the seed is not "
        "guaranteed to exist. Note also that pyrxd has no builder for the nftAuthScript "
        "shape a later mod/sl operation requires, so a MUT minted today cannot yet be "
        "mutated through pyrxd — see tests/test_mut_wave_regtest_e2e.py for the working "
        "transaction spelled out by hand.",
    ),
    GlyphProtocol.WAVE: (
        "prepare_wave_reveal",
        "WAVE is MUT plus a name, so it inherits the MUT reveal's two-input shape and the "
        "same seed-output requirement. pyrxd's WAVE support is deliberately parked until a "
        "concrete consumer needs it — see "
        "docs/solutions/design-decisions/wave-protocol-deferred-until-consumer.md.",
    ),
    GlyphProtocol.DMINT: (
        "prepare_dmint_deploy",
        "Its reveal emits num_contracts parallel contract UTXOs (plus a premine output when "
        "one is asked for), not one token output. Unlike MUT/WAVE this is a complete and "
        "consensus-proven path already — prepare_dmint_deploy drives both phases itself and "
        "is proven end to end against a node in tests/test_dmint_premine_regtest_e2e.py — so "
        "calling it directly is the supported way to deploy, not a workaround.",
    ),
}


class PendingMintNotFound(RxdSdkError):
    """No :class:`PendingMint` is stored under the requested commit txid.

    Module-local rather than in :mod:`pyrxd.security.errors`, matching
    :class:`~pyrxd.glyph.wave.WaveNameNotFound` and
    :class:`~pyrxd.network.rxindexer.RxinDexerNotFound`.
    """


def build_reveal_unlock_template(private_key: Any, scriptsig_suffix: bytes) -> Any:
    """Unlocking template for a Glyph reveal input: ``<sig> <pubkey>`` + the CBOR suffix.

    The commit script runs ``OP_HASH256 <payload_hash> OP_EQUALVERIFY`` and then a
    standard P2PKH tail, so the reveal's scriptSig is a normal P2PKH unlock with the
    ``'gly'``+CBOR push sequence appended.

    This was copy-pasted into all three example scripts (as ``glyph_reveal_unlock``,
    ``ft_reveal_unlock_template`` and ``_glyph_reveal_unlock``) and once more into
    ``pyrxd.cli.glyph_helpers``. Each copy restated the estimated unlocking length;
    :data:`~pyrxd.glyph.fees.REVEAL_SIG_PREFIX_BYTES` is imported here instead, because
    a copy that drifted low would make the reveal fee guard under-estimate and pass —
    which strands the commit.
    """
    if not isinstance(scriptsig_suffix, (bytes, bytearray)):
        raise ValidationError("scriptsig_suffix must be bytes")
    suffix = bytes(scriptsig_suffix)

    def sign(tx: Any, input_index: int) -> Script:
        tx_input = tx.inputs[input_index]
        signature = private_key.sign(tx.preimage(input_index))
        pubkey = private_key.public_key().serialize()
        p2pkh_part = encode_pushdata(signature + tx_input.sighash.to_bytes(1, "little")) + encode_pushdata(pubkey)
        return Script(p2pkh_part + suffix)

    def estimated_unlocking_byte_length() -> int:
        return REVEAL_SIG_PREFIX_BYTES + len(suffix)

    return to_unlock_script_template(sign, estimated_unlocking_byte_length)


# ---------------------------------------------------------------------------
# Durable state
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PendingMint:
    """A broadcast commit whose reveal has not been built yet.

    Everything needed to spend the commit output, and nothing secret. The signing key
    is *not* a field — it is re-derived from ``funding_address`` against the wallet at
    reveal time, so persisting this record can never write key material to disk.

    ``cbor_bytes`` is held as **bytes**, not a hex string. That is the house convention
    for binary in memory (see ``NegotiatedTerms.hashlock`` in
    :mod:`pyrxd.gravity.swap_state`), it is the type
    :attr:`~pyrxd.glyph.builder.CommitResult.cbor_bytes` hands over, and it is what
    :func:`~pyrxd.glyph.payload.build_reveal_scriptsig_suffix` consumes — so hex would
    mean converting twice around a value whose exactness is the whole point. Hex appears
    only at the wire boundary, in :meth:`to_dict`.

    Attributes:
        commit_txid: txid of the broadcast commit transaction.
        commit_vout: index of the commit (hashlock) output. Always 0 here.
        commit_value: photons in the commit output — the reveal's only input.
        commit_script: the commit output's locking script, re-checked at reveal time.
        cbor_bytes: the exact payload the reveal scriptSig must push. Losing these
            makes the commit output permanently unspendable.
        owner_pkh: recipient of the minted token (may differ from the spender).
        is_nft: NFT singleton reveal vs FT reveal.
        carrier_value: photons the reveal places on the token output — a dust carrier
            for an NFT, the whole premined supply for an FT.
        fee_rate: photons per byte the reveal will be fee'd at.
        funding_address: address whose key signs the reveal and receives its change.
    """

    commit_txid: str
    commit_vout: int
    commit_value: int
    commit_script: bytes
    cbor_bytes: bytes
    owner_pkh: bytes
    is_nft: bool
    carrier_value: int
    fee_rate: int
    funding_address: str

    def __post_init__(self) -> None:
        # Txid() rejects anything that is not 64 lowercase hex. This also makes the
        # value safe to use as a filename component in JsonFilePendingStore — a
        # path-traversing "txid" cannot get past here.
        Txid(self.commit_txid)
        if not isinstance(self.commit_vout, int) or isinstance(self.commit_vout, bool) or self.commit_vout < 0:
            raise ValidationError("PendingMint.commit_vout must be a non-negative int")
        if not isinstance(self.commit_value, int) or isinstance(self.commit_value, bool) or self.commit_value <= 0:
            raise ValidationError("PendingMint.commit_value must be a positive int")
        if not isinstance(self.commit_script, bytes) or not self.commit_script:
            raise ValidationError("PendingMint.commit_script must be non-empty bytes")
        if not isinstance(self.cbor_bytes, bytes) or not self.cbor_bytes:
            raise ValidationError("PendingMint.cbor_bytes must be non-empty bytes")
        if not isinstance(self.owner_pkh, bytes) or len(self.owner_pkh) != 20:
            raise ValidationError("PendingMint.owner_pkh must be 20 bytes")
        if not isinstance(self.is_nft, bool):
            raise ValidationError("PendingMint.is_nft must be a bool")
        if not isinstance(self.carrier_value, int) or isinstance(self.carrier_value, bool) or self.carrier_value <= 0:
            raise ValidationError("PendingMint.carrier_value must be a positive int")
        if not isinstance(self.fee_rate, int) or isinstance(self.fee_rate, bool) or self.fee_rate <= 0:
            raise ValidationError("PendingMint.fee_rate must be a positive int")
        if not isinstance(self.funding_address, str) or not self.funding_address:
            raise ValidationError("PendingMint.funding_address must be a non-empty str")
        if self.carrier_value >= self.commit_value:
            raise ValidationError(
                f"PendingMint.carrier_value ({self.carrier_value:,}) must be below commit_value "
                f"({self.commit_value:,}) — the reveal fee is paid out of the difference"
            )

    @property
    def ref(self) -> GlyphRef:
        """The token's permanent identity: the **commit** outpoint, not the reveal's.

        ``prepare_reveal`` embeds this into the reveal's locking script, and it is what
        ``extract_ref_from_{nft,ft}_script`` reads back.
        """
        return GlyphRef(txid=Txid(self.commit_txid), vout=self.commit_vout)

    def to_dict(self) -> dict:
        """JSON-serialisable form; bytes become hex at this boundary and only here.

        ``to_dict``/``from_dict`` rather than ``to_json``/``from_json``: that is what
        every durable type in this repo uses (``SwapRecord``, ``NegotiatedTerms``,
        ``BtcHtlcLocator``, ``EscalationState``), leaving the caller to choose the
        serializer.
        """
        return {
            "schema_version": PENDING_MINT_SCHEMA_VERSION,
            "commit_txid": self.commit_txid,
            "commit_vout": self.commit_vout,
            "commit_value": self.commit_value,
            "commit_script": self.commit_script.hex(),
            "cbor_bytes": self.cbor_bytes.hex(),
            "owner_pkh": self.owner_pkh.hex(),
            "is_nft": self.is_nft,
            "carrier_value": self.carrier_value,
            "fee_rate": self.fee_rate,
            "funding_address": self.funding_address,
        }

    @classmethod
    def from_dict(cls, d: dict) -> PendingMint:
        """Rebuild from :meth:`to_dict`, REJECTING an unrecognised ``schema_version``.

        Fail-closed on the version the way ``SwapRecord.from_dict`` dispatches on its
        own: a newer record parsed leniently by older code would yield a reveal built
        from a misread payload, and the commit output only affords one attempt at
        being spent correctly.
        """
        if not isinstance(d, dict):
            raise ValidationError("PendingMint.from_dict expects a dict")
        version = d.get("schema_version")
        if version != PENDING_MINT_SCHEMA_VERSION:
            raise ValidationError(
                f"unsupported PendingMint schema_version {version!r} "
                f"(this build understands {PENDING_MINT_SCHEMA_VERSION}) — refusing to guess at a "
                "record that decides whether a commit output can be spent"
            )
        try:
            return cls(
                commit_txid=d["commit_txid"],
                commit_vout=d["commit_vout"],
                commit_value=d["commit_value"],
                commit_script=bytes.fromhex(d["commit_script"]),
                cbor_bytes=bytes.fromhex(d["cbor_bytes"]),
                owner_pkh=bytes.fromhex(d["owner_pkh"]),
                is_nft=d["is_nft"],
                carrier_value=d["carrier_value"],
                fee_rate=d["fee_rate"],
                funding_address=d["funding_address"],
            )
        except KeyError as exc:
            raise ValidationError(f"PendingMint record is missing field {exc.args[0]!r}") from exc
        except (TypeError, ValueError) as exc:
            raise ValidationError(f"PendingMint record is malformed: {exc}") from exc


@dataclass(frozen=True)
class MintResult:
    """A completed mint — both transactions broadcast.

    Attributes:
        commit_txid: the commit transaction.
        reveal_txid: the reveal transaction.
        ref: the token's permanent :class:`~pyrxd.glyph.types.GlyphRef` (the commit
            outpoint — see :attr:`PendingMint.ref`).
        reveal_fee: photons the reveal paid, measured on the signed transaction.
        carrier_value: photons on the token output.
        owner_pkh: the recipient's 20-byte public-key hash.
    """

    commit_txid: str
    reveal_txid: str
    ref: GlyphRef
    reveal_fee: int
    carrier_value: int
    owner_pkh: bytes


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------


class PendingStore(abc.ABC):
    """Where a :class:`PendingMint` lives between the commit and the reveal.

    Required, not optional — see the module docstring. Two implementations ship:
    :class:`JsonFilePendingStore` (use this) and :class:`UnsafeNullPendingStore` (an
    explicit opt-out that a caller has to name).

    Implementations must make :meth:`save` durable before it returns.
    :meth:`GlyphMinter.commit_nft` reads the record straight back through :meth:`load`
    and compares it before broadcasting, so a store that silently drops the write is
    caught there rather than one crash later.
    """

    #: Whether :meth:`save` actually persists. :class:`GlyphMinter` skips its
    #: read-back verification (and warns) when this is ``False``; a store that
    #: sets it ``False`` while claiming to persist defeats that check.
    durable: ClassVar[bool] = True

    @abc.abstractmethod
    def save(self, pending: PendingMint) -> None:
        """Persist *pending*, overwriting any record under the same commit txid."""

    @abc.abstractmethod
    def load(self, commit_txid: str) -> PendingMint:
        """Return the stored record, or raise :class:`PendingMintNotFound`."""

    @abc.abstractmethod
    def delete(self, commit_txid: str) -> None:
        """Drop the record. Must not raise if it is already gone."""

    @abc.abstractmethod
    def list_pending(self) -> list[str]:
        """Commit txids with a stored record — the resume list after a crash."""


class JsonFilePendingStore(PendingStore):
    """One 0600 JSON file per pending mint, in a 0700 directory.

    A file per record rather than one shared file: two mints in flight would otherwise
    contend on a read-modify-write, and a torn merge on this path loses the CBOR bytes
    of whichever record lost.

    :meth:`save` follows the house atomic-write convention (``pyrxd.hd.wallet.save``,
    ``pyrxd.gravity.watch.escalation._store_state``): write a temp file opened 0600 by
    ``os.open`` — not chmod'ed afterwards, which would leave a window at the umask's
    mercy — ``fsync`` it, then ``os.replace`` onto the target. The rename is atomic on
    the same filesystem, so a reader sees either the old record or the new one, never a
    partial write. It then re-reads the file and compares before returning, because a
    write that reported success and landed corrupt is indistinguishable from a good one
    until the reveal fails, by which point the commit is already on-chain.
    """

    def __init__(self, directory: str | os.PathLike[str]) -> None:
        self._dir = Path(directory)
        self._dir.mkdir(parents=True, exist_ok=True)
        if os.name == "posix":
            # The records are not secret (no key material) but they are integrity-
            # critical: anyone who can rewrite the CBOR bytes can make the reveal
            # unspendable. Keep the directory owner-only.
            os.chmod(self._dir, 0o700)

    @property
    def directory(self) -> Path:
        """Directory holding the records."""
        return self._dir

    def _path(self, commit_txid: str) -> Path:
        # Txid() enforces 64 lowercase hex, so the value cannot contain a path
        # separator, "..", or a NUL — the filename is safe by construction.
        return self._dir / f"{Txid(commit_txid)}.json"

    def save(self, pending: PendingMint) -> None:
        if not isinstance(pending, PendingMint):
            raise ValidationError("JsonFilePendingStore.save expects a PendingMint")
        target = self._path(pending.commit_txid)
        tmp = target.with_name(target.name + ".tmp")
        body = json.dumps(pending.to_dict(), sort_keys=True).encode("utf-8")
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_CLOEXEC", 0), 0o600)
        try:
            os.write(fd, body)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, target)
        self._fsync_dir()

        # Read back through the real load path. This catches a truncated write, a
        # filesystem that lied about the fsync, and a to_dict/from_dict round-trip that
        # does not actually round-trip — all before anything is broadcast.
        if self.load(pending.commit_txid) != pending:
            raise RxdSdkError(
                f"pending mint {pending.commit_txid} did not survive the round-trip to "
                f"{target} — refusing to treat it as persisted"
            )

    def _fsync_dir(self) -> None:
        """Durably record the rename itself, not just the file contents."""
        try:
            dir_fd = os.open(str(self._dir), os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
        except OSError:  # pragma: no cover - platforms without directory fds
            return
        try:
            os.fsync(dir_fd)
        except OSError:  # pragma: no cover - e.g. some network filesystems
            pass
        finally:
            os.close(dir_fd)

    def load(self, commit_txid: str) -> PendingMint:
        path = self._path(commit_txid)
        try:
            raw = path.read_bytes()
        except FileNotFoundError as exc:
            raise PendingMintNotFound(f"no pending mint stored for {commit_txid} (looked in {self._dir})") from exc
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise ValidationError(f"pending mint record {path} is not valid JSON: {exc}") from exc
        return PendingMint.from_dict(parsed)

    def delete(self, commit_txid: str) -> None:
        self._path(commit_txid).unlink(missing_ok=True)

    def list_pending(self) -> list[str]:
        return sorted(p.stem for p in self._dir.glob("*.json"))


class UnsafeNullPendingStore(PendingStore):
    """Discards everything. Named ``Unsafe`` because it is.

    The escape hatch for callers who genuinely do not want a file written — a
    throwaway regtest run, a test, an embedding application with its own storage that
    has not been wrapped in a :class:`PendingStore` yet.

    With this store a crash between the commit broadcast and the reveal leaves the
    commit output **permanently unspendable**, along with its value. Constructing it
    emits a :class:`UserWarning` so the choice shows up in logs rather than only in the
    source.
    """

    durable: ClassVar[bool] = False

    def __init__(self) -> None:
        warnings.warn(
            "UnsafeNullPendingStore discards the CBOR payload of every pending mint. A crash "
            "between the commit broadcast and the reveal will leave the commit output "
            "permanently unspendable (it is a hashlock with no owner-only spend path), and its "
            "value with it. Use JsonFilePendingStore for anything holding real value.",
            UserWarning,
            stacklevel=2,
        )

    def save(self, pending: PendingMint) -> None:
        return None

    def load(self, commit_txid: str) -> PendingMint:
        raise PendingMintNotFound(
            f"UnsafeNullPendingStore stores nothing, so {commit_txid} cannot be resumed — "
            "this is what opting out of persistence means"
        )

    def delete(self, commit_txid: str) -> None:
        return None

    def list_pending(self) -> list[str]:
        return []


# ---------------------------------------------------------------------------
# The facade
# ---------------------------------------------------------------------------


class GlyphMinter:
    """Two-phase Glyph minting over an ElectrumX client and an HD wallet.

    ``commit_*`` broadcasts the commit and returns a persisted :class:`PendingMint`;
    ``reveal_*`` waits for the commit and broadcasts the reveal. The pair is separable
    on purpose — a caller can exit between them and resume from the store — and
    :meth:`mint_nft` / :meth:`deploy_ft` compose each pair for callers who do not need
    to.

    Usage::

        store = JsonFilePendingStore("~/.pyrxd/pending-mints")
        minter = GlyphMinter(client, wallet, store)
        result = await minter.mint_nft(metadata)

    or, resumably::

        pending = await minter.commit_nft(metadata)   # persisted, then broadcast
        ...                                           # crash, reboot, next week
        pending = store.load(commit_txid)
        result = await minter.reveal_nft(pending)

    Args:
        client: an ElectrumX-style client — ``await broadcast(hex) -> txid`` and
            ``await get_transaction_verbose(txid) -> dict``. Duck-typed, matching
            :func:`~pyrxd.network.confirm.wait_for_confirmation`.
        wallet: an :class:`~pyrxd.hd.wallet.HdWallet`. Exactly two methods are used —
            ``await collect_spendable(client) -> [(utxo, address, privkey)]`` to fund
            the commit, and ``privkey_for_address(address)`` to re-derive the reveal's
            signing key. Duck-typed like ``client``, and deliberately NOT hidden behind
            a coin-source Protocol: ``HdWallet`` is the only real implementer, and a
            one-implementer Protocol is indirection with nothing on the other side. The
            two-method surface is small enough to stand in for directly — see
            ``examples/regtest_quickstart.py``, which drives the minter from a single
            regtest key.
        store: where the :class:`PendingMint` is kept between phases. **Required.**
        fee_rate: photons per byte for both transactions.
        min_confirmations: depth required on the commit before the reveal is built.
            See :data:`DEFAULT_MINT_CONFIRMATIONS` — the default is convention.
        confirmation_timeout_s: how long ``reveal_*`` waits before raising
            :class:`~pyrxd.security.errors.ConfirmationTimeoutError`. The
            :class:`PendingMint` survives a timeout, so the reveal can be retried.
    """

    def __init__(
        self,
        client: Any,
        wallet: Any,
        store: PendingStore,
        *,
        fee_rate: int = MIN_FEE_RATE,
        min_confirmations: int = DEFAULT_MINT_CONFIRMATIONS,
        confirmation_timeout_s: float = DEFAULT_CONFIRMATION_TIMEOUT_S,
    ) -> None:
        if not isinstance(store, PendingStore):
            raise ValidationError(
                "GlyphMinter requires a PendingStore — pass JsonFilePendingStore(path), or "
                "UnsafeNullPendingStore() to explicitly opt out of crash recovery"
            )
        if not isinstance(fee_rate, int) or isinstance(fee_rate, bool) or fee_rate <= 0:
            raise ValidationError("GlyphMinter fee_rate must be a positive int")
        if not isinstance(min_confirmations, int) or isinstance(min_confirmations, bool) or min_confirmations < 1:
            raise ValidationError("GlyphMinter min_confirmations must be an int >= 1")
        self._client = client
        self._wallet = wallet
        self._store = store
        self._fee_rate = fee_rate
        self._min_confirmations = min_confirmations
        self._confirmation_timeout_s = confirmation_timeout_s
        self._builder = GlyphBuilder()

    @property
    def store(self) -> PendingStore:
        """The configured :class:`PendingStore` — resume through it after a crash."""
        return self._store

    # -- phase 1 -----------------------------------------------------------

    async def commit_nft(self, metadata: GlyphMetadata, *, owner_pkh: Hex20 | bytes | None = None) -> PendingMint:
        """Broadcast the commit for an NFT singleton mint.

        The :class:`PendingMint` is persisted and read back **before** the broadcast.

        Args:
            metadata: must carry :attr:`~pyrxd.glyph.types.GlyphProtocol.NFT` and none
                of the tags whose reveal has a different shape (MUT, WAVE, DMINT) —
                those are refused rather than committed to a reveal this module cannot
                build. ``CONTAINER`` **is** supported: a collection's reveal is this
                same single-output NFT shape.
            owner_pkh: recipient. Defaults to the funding key's own PKH.

        Raises:
            ValidationError: on an unsupported protocol mix.
            InsufficientFundsError: if no single UTXO can fund the mint, or if the
                measured reveal could not pay its fee out of the commit. Both are
                raised before anything is broadcast.
        """
        self._require_protocol(metadata, GlyphProtocol.NFT, "commit_nft")
        return await self._commit(
            metadata=metadata,
            is_nft=True,
            carrier_value=NFT_CARRIER_VALUE,
            owner_pkh=owner_pkh,
        )

    async def commit_ft(
        self,
        metadata: GlyphMetadata,
        *,
        supply: int,
        treasury_pkh: Hex20 | bytes | None = None,
    ) -> PendingMint:
        """Broadcast the commit for a fungible-token deploy with a full premine.

        Args:
            metadata: must carry :attr:`~pyrxd.glyph.types.GlyphProtocol.FT`. DMINT is
                refused — a dMint deploy emits parallel contract UTXOs and belongs to
                :meth:`~pyrxd.glyph.builder.GlyphBuilder.prepare_dmint_deploy`.
            supply: units issued, all placed on the reveal's token output. Radiant
                convention is 1 photon = 1 FT unit, so this is also that output's
                value, and it must clear pyrxd's 546-unit decimals-mistake guard
                (a pyrxd policy, not a chain limit — Radiant's output floor is 1 photon).
            treasury_pkh: who receives the premine. Defaults to the funding key's PKH.

        Raises:
            ValidationError: on an unsupported protocol mix or a sub-dust supply.
            InsufficientFundsError: as :meth:`commit_nft`.
        """
        self._require_protocol(metadata, GlyphProtocol.FT, "commit_ft")
        # 546 is a pyrxd HEURISTIC, not a chain rule: a whole FT supply below 546
        # units is almost always a decimals mistake. Radiant would accept it —
        # ``GetDustThreshold`` returns 1 satoshi, ``IsDust`` is ``nValue <= 0``
        # (Radiant-Core/src/policy/policy.cpp:19-25), and standardness is never
        # consulted (``fRequireStandard`` is hardcoded ``false``,
        # Radiant-Core/src/validation.cpp:271 and src/init.cpp:1995). The previous
        # wording, "makes the reveal's token output non-standard", asserted a rule
        # that does not exist; ``build_airdrop_tx`` in this same package correctly
        # emits 1-unit FT outputs.
        if not isinstance(supply, int) or isinstance(supply, bool) or supply < DUST_THRESHOLD_PHOTONS:
            raise ValidationError(
                f"commit_ft supply must be an int >= {DUST_THRESHOLD_PHOTONS}; got {supply!r}. This is a pyrxd guard against a "
                "decimals mistake, not a chain limit (Radiant's output floor is 1 photon) — a supply this "
                "small is usually meant to be an NFT."
            )
        return await self._commit(
            metadata=metadata,
            is_nft=False,
            carrier_value=supply,
            owner_pkh=treasury_pkh,
        )

    # -- phase 2 -----------------------------------------------------------

    async def reveal_nft(self, pending: PendingMint) -> MintResult:
        """Wait for the commit, then broadcast the NFT reveal.

        The stored record is re-validated against the commit script before anything is
        built — see :meth:`_assert_payload_still_matches`. On success the record is
        deleted from the store; on failure it is kept so the reveal can be retried.
        """
        if not isinstance(pending, PendingMint):
            raise ValidationError("reveal_nft expects a PendingMint")
        if not pending.is_nft:
            raise ValidationError(
                f"pending mint {pending.commit_txid} is an FT commit — call reveal_ft. "
                "Revealing it as an NFT would build the wrong locking script and the commit "
                "script's OP_REFTYPE_OUTPUT check would reject the spend."
            )
        return await self._reveal(pending)

    async def reveal_ft(self, pending: PendingMint) -> MintResult:
        """Wait for the commit, then broadcast the FT deploy reveal.

        Mirrors :meth:`reveal_nft`; the reveal's token output carries the whole premined
        supply recorded in :attr:`PendingMint.carrier_value`.
        """
        if not isinstance(pending, PendingMint):
            raise ValidationError("reveal_ft expects a PendingMint")
        if pending.is_nft:
            raise ValidationError(
                f"pending mint {pending.commit_txid} is an NFT commit — call reveal_nft. "
                "Revealing it as an FT would build the wrong locking script and the commit "
                "script's OP_REFTYPE_OUTPUT check would reject the spend."
            )
        return await self._reveal(pending)

    # -- both phases -------------------------------------------------------

    async def mint_nft(self, metadata: GlyphMetadata, *, owner_pkh: Hex20 | bytes | None = None) -> MintResult:
        """:meth:`commit_nft` then :meth:`reveal_nft`, waiting for the commit in between.

        Convenient, not different: the commit is persisted before broadcast here too,
        because the store is a constructor dependency rather than a per-call keyword.
        That is the reason it sits on the constructor — a single-call helper cannot
        forget to pass it.

        Note this blocks for as long as the commit takes to confirm. If that is a
        problem, drive the two phases yourself.
        """
        pending = await self.commit_nft(metadata, owner_pkh=owner_pkh)
        return await self.reveal_nft(pending)

    async def deploy_ft(
        self,
        metadata: GlyphMetadata,
        *,
        supply: int,
        treasury_pkh: Hex20 | bytes | None = None,
    ) -> MintResult:
        """:meth:`commit_ft` then :meth:`reveal_ft`. See :meth:`mint_nft`."""
        pending = await self.commit_ft(metadata, supply=supply, treasury_pkh=treasury_pkh)
        return await self.reveal_ft(pending)

    # -- internals ---------------------------------------------------------

    @staticmethod
    def _require_protocol(metadata: GlyphMetadata, required: GlyphProtocol, method: str) -> None:
        if not isinstance(metadata, GlyphMetadata):
            raise ValidationError(f"{method} expects a GlyphMetadata")
        protocol = list(metadata.protocol or [])
        if required not in protocol:
            raise ValidationError(
                f"{method} requires GlyphProtocol.{required.name} in metadata.protocol; got {protocol!r}"
            )
        for tag, (builder_method, why) in _UNSUPPORTED_PROTOCOLS.items():
            if tag in protocol:
                raise ValidationError(
                    f"{method} cannot mint a {tag.name} glyph: its reveal is not the single-output "
                    f"shape this facade builds, and committing through here would broadcast a commit "
                    f"whose reveal this module cannot construct — the commit output is a hashlock with "
                    f"no owner-only spend path, so that commit and its value would be stranded. "
                    f"Use GlyphBuilder.{builder_method} directly. {why}"
                )
        # FT/NFT mutual exclusion is not re-checked here: GlyphMetadata.__post_init__
        # already rejects that combination (and the co-protocol requirements that make
        # [NFT, DMINT] and bare [WAVE] unconstructable), so a second check would be
        # unreachable code pretending to be a guard.

    async def _commit(
        self,
        *,
        metadata: GlyphMetadata,
        is_nft: bool,
        carrier_value: int,
        owner_pkh: Hex20 | bytes | None,
    ) -> PendingMint:
        """Shared commit path. Ordering here is the fund-safety contract.

        1. size the commit from the reveal estimate (:mod:`pyrxd.glyph.fees`)
        2. select funding, build and sign the commit
        3. build a dry-run reveal and MEASURE it — the last point at which nothing
           has been spent
        4. persist the :class:`PendingMint` and read it back
        5. only then broadcast
        """
        fee_rate = self._fee_rate

        # 1. The reveal's scriptSig carries the whole CBOR payload, so its fee scales
        #    with metadata size and is paid entirely out of the commit output. Both
        #    numbers come from pyrxd.glyph.fees; nothing is re-derived here.
        estimate = estimate_reveal_fee_for_metadata(metadata, fee_rate=fee_rate)
        commit_value = commit_value_for_reveal(carrier_value, estimate)
        commit_fee_estimate = 300 * fee_rate  # ~300-byte commit
        total_required = commit_value + commit_fee_estimate + NFT_CARRIER_VALUE

        # 2. Funding.
        triples = await self._wallet.collect_spendable(self._client)
        if not triples:
            raise InsufficientFundsError(
                "no spendable UTXOs in the wallet (fund it, or refresh to discover used addresses)",
                available=0,
                required=total_required,
            )
        triples.sort(key=lambda t: t[0].value, reverse=True)
        funding = next((t for t in triples if t[0].value >= total_required), None)
        if funding is None:
            largest = triples[0][0].value
            raise InsufficientFundsError(
                f"no single UTXO is large enough to fund the mint: need >= {total_required:,} photons "
                f"in one UTXO, largest is {largest:,}. Consolidate first.",
                available=largest,
                required=total_required,
            )
        funding_utxo, funding_addr, funding_key = funding
        funding_pkh = Hex20(funding_key.public_key().hash160())
        recipient = Hex20(bytes(owner_pkh)) if owner_pkh is not None else funding_pkh

        # 3. Commit script + transaction.
        commit_result = self._builder.prepare_commit(
            CommitParams(
                metadata=metadata,
                owner_pkh=funding_pkh,
                change_pkh=funding_pkh,
                funding_satoshis=funding_utxo.value,
            )
        )
        locking = P2PKH().lock(funding_addr)
        commit_tx = _build_commit_tx(
            funding_utxo=funding_utxo,
            funding_key=funding_key,
            locking=locking,
            commit_script=commit_result.commit_script,
            commit_value=commit_value,
            fee_rate=fee_rate,
        )

        pending = PendingMint(
            # The txid is computed from the signed bytes, not taken from the broadcast
            # response — the record must be on disk BEFORE the broadcast, so there is no
            # server answer to use yet. Step 5 reconciles the two.
            commit_txid=str(commit_tx.txid()),
            commit_vout=0,
            # Read the value back off the built transaction rather than trusting the
            # target: fee() may have adjusted it.
            commit_value=commit_tx.outputs[0].satoshis,
            commit_script=commit_result.commit_script,
            cbor_bytes=commit_result.cbor_bytes,
            owner_pkh=bytes(recipient),
            is_nft=is_nft,
            carrier_value=carrier_value,
            fee_rate=fee_rate,
            funding_address=funding_addr,
        )

        # 4. The C-1 gate: build the reveal against a placeholder txid and measure the
        #    real transaction. Sizing the commit from an estimate and then re-checking
        #    that same estimate is a tautology; measuring the built reveal is an
        #    independent check that fires if the estimator's shim has stopped describing
        #    what we actually build. Still nothing spent at this point.
        dry_run = self._build_reveal_tx(replace(pending, commit_txid=_PLACEHOLDER_COMMIT_TXID), funding_key, locking)
        measured = measure_reveal_fee(dry_run, fee_rate=fee_rate, cbor_bytes_len=len(pending.cbor_bytes))
        check_reveal_funding(
            commit_value=pending.commit_value,
            carrier_value=carrier_value,
            estimate=measured,
        )

        # 5. Persist, verify, and only then spend.
        self._persist_or_abort(pending)
        broadcast_txid = str(await self._client.broadcast(commit_tx.serialize()))
        if broadcast_txid != pending.commit_txid:
            # The record is keyed by the txid computed from the bytes we signed, because
            # it has to be written BEFORE the broadcast that would reveal the server's
            # answer. If the server then names a different transaction, one of the two
            # keys is the one holding real value and we cannot tell which — so file the
            # payload under both rather than leave the other unrecoverable.
            self._store.save(replace(pending, commit_txid=broadcast_txid))
            warnings.warn(
                f"broadcast returned txid {broadcast_txid} but the signed commit hashes to "
                f"{pending.commit_txid}. The pending payload has been stored under BOTH so either "
                "can be revealed; check a block explorer to see which one landed before revealing.",
                UserWarning,
                stacklevel=2,
            )
        return pending

    def _persist_or_abort(self, pending: PendingMint) -> None:
        """Save the record and prove it is readable, before the commit is broadcast.

        The read-back happens *here* rather than only inside
        :meth:`JsonFilePendingStore.save` so the guarantee covers third-party stores
        too — a store whose ``save`` silently drops the record is caught before the
        money moves, not after.
        """
        self._store.save(pending)
        if not self._store.durable:
            return
        reloaded = self._store.load(pending.commit_txid)
        if reloaded != pending:
            raise RxdSdkError(
                f"{type(self._store).__name__} did not return the pending mint it was just given "
                f"for {pending.commit_txid} — refusing to broadcast the commit, because the CBOR "
                "payload would not be recoverable after a crash"
            )

    async def _reveal(self, pending: PendingMint) -> MintResult:
        funding_key = self._key_for_address(pending.funding_address)
        self._assert_payload_still_matches(pending, funding_key)

        await wait_for_confirmation(
            self._client,
            pending.commit_txid,
            min_confirmations=self._min_confirmations,
            timeout_s=self._confirmation_timeout_s,
        )

        locking = P2PKH().lock(pending.funding_address)
        reveal_tx = self._build_reveal_tx(pending, funding_key, locking)
        reveal_tx.fee(SatoshisPerKilobyte(pending.fee_rate * 1000))
        reveal_tx.sign()
        reveal_txid = await self._client.broadcast(reveal_tx.serialize())

        # Only now is the record redundant. Deleting earlier would drop the CBOR bytes
        # while the reveal could still fail to relay.
        self._store.delete(pending.commit_txid)
        return MintResult(
            commit_txid=pending.commit_txid,
            reveal_txid=str(reveal_txid),
            ref=pending.ref,
            reveal_fee=reveal_tx.get_fee(),
            carrier_value=pending.carrier_value,
            owner_pkh=pending.owner_pkh,
        )

    @staticmethod
    def _assert_payload_still_matches(pending: PendingMint, funding_key: Any) -> None:
        """Re-derive the commit script from the stored bytes and compare.

        This is the check that makes the store trustworthy. ``build_commit_locking_script``
        is a pure function of ``sha256d(cbor_bytes)``, the spender PKH and the refType,
        so rebuilding it from the persisted record and comparing against the persisted
        script proves three things at once, *before* a reveal is built: the CBOR bytes
        still hash to what the on-chain output committed to, the wallet re-derived the
        key that can sign the P2PKH tail, and NFT/FT was not flipped.

        A mismatch means the reveal would be rejected — better to say so than to
        broadcast a transaction that burns its fee and leaves the commit stranded
        anyway.
        """
        spender_pkh = Hex20(funding_key.public_key().hash160())
        expected = build_commit_locking_script(
            hash_payload(pending.cbor_bytes),
            spender_pkh,
            is_nft=pending.is_nft,
        )
        if expected != pending.commit_script:
            raise ValidationError(
                f"stored payload for {pending.commit_txid} does not reproduce its commit script. "
                "The CBOR bytes, the is_nft flag, or the funding address must have changed since "
                "the commit was broadcast — a reveal built from this record cannot spend the "
                "commit output, so it is refused rather than broadcast."
            )

    def _key_for_address(self, address: str) -> Any:
        """Re-derive the signing key for ``address`` from the wallet.

        The key is deliberately never persisted, so the reveal has to find it again.
        Keying on the funding address rather than the derivation path keeps wallet
        layout out of the durable record, and keeps the wallet contract to two methods.
        """
        try:
            return self._wallet.privkey_for_address(address)
        except ValidationError as exc:
            raise ValidationError(
                f"funding address {address} is not known to this wallet, so the reveal cannot be "
                "signed. Load the wallet that created the commit (or refresh it so the address is "
                "rediscovered) and retry — the pending record is left untouched."
            ) from exc

    def _build_reveal_tx(self, pending: PendingMint, funding_key: Any, change_locking: Script) -> Transaction:
        """Build the (unsigned, un-fee'd) reveal that spends the commit output.

        Shared by the pre-broadcast dry run and the real post-confirmation build so the
        two cannot diverge — a dry run that measured a *different* transaction would be
        worth no more than the tautology it replaced.
        """
        scripts = self._builder.prepare_reveal(
            RevealParams(
                commit_txid=pending.commit_txid,
                commit_vout=pending.commit_vout,
                commit_value=pending.commit_value,
                cbor_bytes=pending.cbor_bytes,
                owner_pkh=Hex20(pending.owner_pkh),
                is_nft=pending.is_nft,
            )
        )

        shim_out = TransactionOutput(Script(pending.commit_script), pending.commit_value)
        src_tx = Transaction(tx_inputs=[], tx_outputs=[shim_out])
        src_tx.txid = lambda: pending.commit_txid  # type: ignore[method-assign]

        reveal_input = TransactionInput(
            source_transaction=src_tx,
            source_output_index=pending.commit_vout,
            unlocking_script_template=build_reveal_unlock_template(funding_key, scripts.scriptsig_suffix),
        )
        reveal_input.satoshis = pending.commit_value
        reveal_input.locking_script = Script(pending.commit_script)

        # The token sits on vout[0] — a dust carrier for an NFT, the whole supply for an
        # FT premine — and the rest of the commit value returns as change rather than
        # being burned to fee.
        return Transaction(
            tx_inputs=[reveal_input],
            tx_outputs=[
                TransactionOutput(Script(scripts.locking_script), pending.carrier_value),
                TransactionOutput(change_locking, 0, change=True),
            ],
        )


def _build_commit_tx(
    *,
    funding_utxo: Any,
    funding_key: Any,
    locking: Script,
    commit_script: bytes,
    commit_value: int,
    fee_rate: int,
) -> Transaction:
    """Spend one P2PKH UTXO into the commit output plus change.

    Mirrors the composition ``pyrxd.cli.glyph_cmds`` has run on mainnet. ``change=True``
    lets ``fee()`` size the fee from the real serialized length and fill the change in;
    a hand-computed change output makes ``fee()`` divide by zero for want of a change
    output to adjust.
    """
    # Pad the source shim so the funding output sits at its real vout — the largest
    # wallet UTXO is often change at vout != 0, and both TransactionInput and fee()
    # index into source_transaction.outputs.
    src_outs = [TransactionOutput(Script(b""), 0) for _ in range(funding_utxo.tx_pos)]
    src_outs.append(TransactionOutput(locking, funding_utxo.value))
    src_tx = Transaction(tx_inputs=[], tx_outputs=src_outs)
    src_tx.txid = lambda: funding_utxo.tx_hash  # type: ignore[method-assign]

    commit_input = TransactionInput(
        source_transaction=src_tx,
        source_txid=funding_utxo.tx_hash,
        source_output_index=funding_utxo.tx_pos,
        unlocking_script_template=P2PKH().unlock(funding_key),
    )
    commit_input.satoshis = funding_utxo.value
    commit_input.locking_script = locking

    commit_tx = Transaction(
        tx_inputs=[commit_input],
        tx_outputs=[
            TransactionOutput(Script(commit_script), commit_value),
            TransactionOutput(locking, 0, change=True),
        ],
    )
    commit_tx.fee(SatoshisPerKilobyte(fee_rate * 1000))
    commit_tx.sign()
    return commit_tx
