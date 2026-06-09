"""The sign-on-behalf signing brain.

Holds an unlocked :class:`~pyrxd.hd.wallet.HdWallet` and turns a
:class:`SigningRequest` into a signed transaction. The key never leaves
this object; callers get a signed tx, never key material.

Load-bearing checks (see the plan's § "Load-bearing safety properties"):

* **C1 prevout authenticity** — each input's value+script are read from
  the *verified* source tx (hashes to the outpoint), never trusted from
  the unsigned tx the caller supplied. Defeats fake-low-value fee theft.
* **Ownership** — the derived key must actually own the prevout
  (pubkey hash == prevout owner pkh), or the request is rejected.
* **Output attribution + confirmation** — change claims are re-derived
  and verified; everything else is surfaced as an external payee, and the
  whole spend goes through a confirmation gate before signing.
* **Set-then-sign sighash** — the sighash is set on the input before the
  preimage is computed (the wire format does not carry it; see
  ``TransactionInput.from_hex``), so what is signed matches what is shown.
* **Fully-owned only (v1)** — every input must be in the request; the
  agent refuses to sign a transaction it cannot fully attribute.
"""

from __future__ import annotations

from collections.abc import Callable

from ..constants import SIGHASH
from ..hash import hash256
from ..hd.wallet import HdWallet
from ..script.type import P2PKH
from ..transaction.transaction import Transaction
from ..transaction.transaction_output import TransactionOutput
from ..utils import address_to_public_key_hash
from .errors import SignerDeclined, SignerError
from .protocol import ExternalOutput, SignedResult, SigningRequest, SpendSummary

#: Confirmation gate: given the verified spend summary, return True to sign.
ConfirmFn = Callable[[SpendSummary], bool]


def _is_p2pkh(script: bytes) -> bool:
    return len(script) == 25 and script[:3] == b"\x76\xa9\x14" and script[23:] == b"\x88\xac"


def _dest_of(out: TransactionOutput) -> str:
    """Human-displayable destination for an output (best-effort, structured)."""
    script = out.locking_script.serialize()
    if _is_p2pkh(script):
        return f"p2pkh:{script[3:23].hex()}"
    if script[:1] == b"\x6a":
        return "op_return"
    return f"script:{script[:16].hex()}…"


class AgentSigner:
    """Signs transactions on behalf of an unlocked wallet, without ever
    exposing the wallet's keys."""

    def __init__(self, wallet: HdWallet) -> None:
        self._wallet = wallet

    def sign(self, request: SigningRequest, *, confirm: ConfirmFn) -> SignedResult:
        tx = Transaction.from_hex(bytes.fromhex(request.unsigned_tx_hex))
        if tx is None:
            raise SignerError("could not parse the unsigned transaction")
        if not tx.inputs or not tx.outputs:
            raise SignerError("transaction has no inputs or no outputs")

        # v1 refuses partially-owned txs: every input must be in the request,
        # exactly once, so the agent can verify and attribute the whole tx.
        covered = [i.input_index for i in request.inputs]
        if sorted(covered) != list(range(len(tx.inputs))):
            raise SignerError(
                "agent v1 signs only fully wallet-owned transactions "
                f"(tx has {len(tx.inputs)} inputs; request covers {sorted(covered)})"
            )

        for inp in request.inputs:
            self._verify_and_prepare_input(tx, inp)

        summary = self._summarize(tx, request)
        if not confirm(summary):
            raise SignerDeclined("spend declined at the confirmation gate")

        tx.sign(bypass=True)  # signs the inputs we attached templates to

        for inp in request.inputs:
            if tx.inputs[inp.input_index].unlocking_script is None:
                raise SignerError(f"input {inp.input_index} was not signed")
        return SignedResult(signed_tx_hex=tx.serialize().hex())

    # ------------------------------------------------------------------ internals

    def _verify_and_prepare_input(self, tx: Transaction, inp) -> None:
        if not 0 <= inp.input_index < len(tx.inputs):
            raise SignerError(f"input_index {inp.input_index} out of range")
        ti = tx.inputs[inp.input_index]

        src_bytes = bytes.fromhex(inp.source_tx_hex)
        # C1: the source tx must hash to this input's outpoint txid.
        if hash256(src_bytes)[::-1].hex() != ti.source_txid:
            raise SignerError(f"source tx does not match input {inp.input_index} outpoint")
        src = Transaction.from_hex(src_bytes)
        if src is None:
            raise SignerError(f"could not parse source tx for input {inp.input_index}")
        vout = ti.source_output_index
        if not 0 <= vout < len(src.outputs):
            raise SignerError(f"input {inp.input_index} references a non-existent source output")
        prevout = src.outputs[vout]
        script = prevout.locking_script.serialize()
        if not _is_p2pkh(script):
            raise SignerError(f"input {inp.input_index} is not P2PKH (agent v1 signs P2PKH only)")

        privkey = self._wallet._privkey_for(inp.change, inp.index)
        if privkey.public_key().hash160() != script[3:23]:
            raise SignerError(
                f"derived key (change={inp.change}, index={inp.index}) does not own input {inp.input_index}"
            )

        # Bind the VERIFIED prevout value/script (not the caller's claim) and
        # set the sighash before signing so preimage == what we attribute.
        ti.satoshis = prevout.satoshis
        ti.locking_script = prevout.locking_script
        # v1 signs ONLY ALL_FORKID. NONE/SINGLE/ANYONECANPAY variants commit to
        # fewer outputs than the confirmation summary shows, so a caller could take
        # the returned signature, recombine it into a different transaction, and
        # redirect the funds — while the user approved a benign-looking spend. A
        # fully wallet-owned normal send has no legitimate use for anything else.
        # (Compared explicitly, not via SIGHASH(inp.sighash), so an out-of-enum int
        # is a clean SignerError rather than a leaked ValueError.)
        if inp.sighash != int(SIGHASH.ALL_FORKID):
            raise SignerError(
                f"input {inp.input_index}: agent v1 signs only ALL_FORKID "
                f"(0x{int(SIGHASH.ALL_FORKID):02x}); got {inp.sighash!r} — other sighash types "
                "permit fund redirection and are refused"
            )
        ti.sighash = SIGHASH.ALL_FORKID
        ti.unlocking_script_template = P2PKH().unlock(privkey)
        # ``from_hex`` leaves unlocking_script as an empty Script (not None), which
        # ``Transaction.sign(bypass=True)`` would skip — reset so this input signs.
        ti.unlocking_script = None

    def _summarize(self, tx: Transaction, request: SigningRequest) -> SpendSummary:
        # Verify each change claim by re-derivation; collect the verified set.
        change_indices: set[int] = set()
        for claim in request.change_claims:
            if not 0 <= claim.output_index < len(tx.outputs):
                raise SignerError(f"change claim output_index {claim.output_index} out of range")
            addr = self._wallet._derive_address(claim.change, claim.index)
            claim_pkh = address_to_public_key_hash(addr)
            out_script = tx.outputs[claim.output_index].locking_script.serialize()
            if not _is_p2pkh(out_script) or out_script[3:23] != claim_pkh:
                raise SignerError(
                    f"change claim for output {claim.output_index} does not verify "
                    "(output is not change to the claimed key)"
                )
            change_indices.add(claim.output_index)

        external: list[ExternalOutput] = []
        change_total = 0
        for idx, out in enumerate(tx.outputs):
            if idx in change_indices:
                change_total += out.satoshis
            else:
                external.append(ExternalOutput(output_index=idx, dest=_dest_of(out), amount=out.satoshis))

        # All inputs are verified+bound at this point (fully-owned invariant).
        input_total = sum(int(ti.satoshis) for ti in tx.inputs)
        total_external = sum(e.amount for e in external)
        fee = input_total - change_total - total_external
        if fee < 0:
            raise SignerError("transaction spends more than its inputs (negative fee)")

        return SpendSummary(
            external_outputs=tuple(external),
            total_external=total_external,
            change_total=change_total,
            input_total=input_total,
            fee=fee,
            sighash_flags=tuple(i.sighash for i in request.inputs),
        )
