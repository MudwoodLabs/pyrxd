"""Bind a swap/HTLC claim to the OWNER of a soulbound credential (anti-rental).

Problem
-------
A credential-gated swap ("only a KYC'd / reputation-bearing counterparty may
claim") is only as strong as its anti-impersonation binding. Two attacks:

* **Sale** — the counterparty buys a credential to pass the gate, then resells it.
  Defeated by *soulbound*: a genuinely non-transferable credential can't be sold.
* **Rental** — the credential's owner co-operates to let someone else pass the
  gate while keeping the credential. This is the subtle one: requiring the
  credential merely be *present* (e.g. ``OP_REQUIREINPUTREF``) proves the owner
  participated, NOT that the owner is the beneficiary.

The binding
-----------
Pin the swap's payout to the credential's owner pkh, and require the credential
to be *genuinely consensus-soulbound* (verified by reading its locking script,
not a metadata flag). The security argument:

1. The credential's locking script is a real self-replicating soulbound covenant
   (``classify_soulbound(...).is_consensus_soulbound`` — consensus-enforced,
   validated in ``tests/test_soulbound_covenant_regtest.py``). It therefore can
   NEVER move to a different owner: "owned by P" is permanent and immutable.
2. The swap covenant pins ``output[0]`` to P (the existing HTLC recipient pin —
   consensus-enforced).

Together: the asset can only land with P, and P is provably the *permanent* owner
of the credential. Rental gains the renter nothing (the payout goes to the
owner P, not the renter), and because the credential is soulbound, P cannot have
borrowed it temporarily either. So owner == claimer holds **without co-spending
the credential** — which matters, because a soulbound credential's own covenant
pins its recurrence to ``output[0]``, and the swap asset needs ``output[0]`` too;
co-spending would conflict.

This module is the off-chain gate the funder runs BEFORE locking the asset. It is
fail-closed: any doubt raises. The two load-bearing facts it composes are both
consensus-enforced; the only off-chain step is reading the credential's current
owner, and soulbound permanence makes even a stale read safe (the owner can't
change).

Limitation (documented, not yet built): this binds to the owner but does NOT
re-check the credential at claim time, so it cannot enforce *revocation* (an
authority burning the credential between funding and claim). Revocation-aware
binding needs the credential required as a spent input at claim time
(``OP_REQUIREINPUTREF``), which in turn needs a *composable* soulbound covenant
that recurs to a non-fixed output index (today's pin ``output[0]`` collides with
the asset output). That is a separate follow-up.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from pyrxd.glyph.soulbound_detect import classify_soulbound
from pyrxd.security.errors import ValidationError

__all__ = [
    "CredentialBindingError",
    "CredentialResolver",
    "ResolvedCredential",
    "assert_soulbound_credential",
    "extract_owner_pkh",
    "verify_credential_binding",
]


class CredentialBindingError(ValidationError):
    """The credential does not bind to the claimer — fail-closed; do not fund."""


@dataclass(frozen=True)
class ResolvedCredential:
    """An indexer's resolution of a credential's CURRENT on-chain UTXO.

    Unlike :class:`pyrxd.gravity.ref_authenticity.ResolvedRef` (which resolves the
    genesis), this is the credential's *live* locking script — what actually
    governs transferability right now. The owner pkh is derived FROM
    ``current_spk`` (the consensus script), never trusted as a separate field.

    Attributes
    ----------
    current_spk:
        The scriptPubKey of the credential's current (unspent) UTXO.
    confirmations:
        Confirmations on that UTXO. Negative/None is treated as fail-closed.
    bound_ref:
        The 36-byte singleton ref the credential carries, if the caller wants the
        gate to also confirm it matches a specific negotiated credential.
    """

    current_spk: bytes
    confirmations: int
    bound_ref: bytes | None = None


@runtime_checkable
class CredentialResolver(Protocol):
    """Indexer surface to resolve a credential ref to its CURRENT live UTXO.

    Mirrors :class:`pyrxd.gravity.ref_authenticity.RefAuthenticityIndexer` but
    resolves the credential's *current* (unspent) locking script — what governs
    transferability now — rather than the genesis. ``resolve_credential`` is async
    and MUST raise or return ``None`` (both fail-closed) when it cannot reach a
    definitive answer; never return an optimistic stand-in.
    """

    async def resolve_credential(self, credential_ref: bytes) -> ResolvedCredential | None:
        """Resolve ``credential_ref`` to its current UTXO, or ``None`` if unknown/spent."""
        ...


def extract_owner_pkh(spk: bytes) -> bytes | None:
    """Return the single owner pkh embedded in a soulbound covenant scriptPubKey.

    Walks ``spk`` as an opcode stream (so a ``76a914…`` byte run inside a 36-byte
    ref operand is never mistaken for a P2PKH) and collects every
    ``OP_DUP OP_HASH160 <20-byte push> OP_EQUALVERIFY (OP_CHECKSIG|OP_CHECKSIGVERIFY)``
    pattern. Returns the pkh iff all occurrences agree (the deployed covenant
    embeds it in both branches); ``None`` if there is no consistent single pkh.
    """
    found: set[bytes] = set()
    pos, n = 0, len(spk)
    while pos < n:
        op = spk[pos]
        # Skip ref opcodes (0xd0..0xd8): opcode + 36-byte operand.
        if 0xD0 <= op <= 0xD8:
            pos += 37
            continue
        # P2PKH pattern: 76 a9 14 <20> 88 (ac|ad)
        if (
            op == 0x76
            and pos + 25 <= n
            and spk[pos + 1] == 0xA9
            and spk[pos + 2] == 0x14
            and spk[pos + 23] == 0x88
            and spk[pos + 24] in (0xAC, 0xAD)
        ):
            found.add(spk[pos + 3 : pos + 23])
            pos += 25
            continue
        # Generic push skip (so push operands aren't mis-walked).
        if 0x01 <= op <= 0x4B:
            pos += 1 + op
            continue
        if op == 0x4C and pos + 1 < n:
            pos += 2 + spk[pos + 1]
            continue
        if op == 0x4D and pos + 2 < n:
            pos += 3 + int.from_bytes(spk[pos + 1 : pos + 3], "little")
            continue
        if op == 0x4E and pos + 4 < n:
            pos += 5 + int.from_bytes(spk[pos + 1 : pos + 5], "little")
            continue
        pos += 1
    if len(found) == 1:
        return next(iter(found))
    return None


def assert_soulbound_credential(
    credential: ResolvedCredential,
    *,
    min_confirmations: int,
    expected_credential_ref: bytes | None = None,
) -> bytes:
    """Fail-closed: confirm a credential is a genuine, deep-enough soulbound token;
    return its owner pkh.

    Checks (raising :class:`CredentialBindingError` on any failure):

    1. ``credential.current_spk`` is a genuine consensus-soulbound covenant
       (``classify_soulbound`` — NOT a plain NFT with an advisory metadata flag).
       This is what makes "owner is permanent" true and rental impossible.
    2. ``confirmations >= min_confirmations`` (reorg safety).
    3. if ``expected_credential_ref`` is given, the credential binds exactly it.

    Returns the credential's embedded owner pkh (so callers can bind the swap
    payout to it — either directly, or against a holder-hash pin).
    """
    cls = classify_soulbound(credential.current_spk)

    # (1) genuinely soulbound — the anti-rental / anti-resale root.
    if not cls.is_consensus_soulbound:
        raise CredentialBindingError(
            f"credential is not a consensus-soulbound covenant "
            f"(classified {cls.transferability.value}); a transferable token can be "
            "rented or resold and must not gate a swap"
        )

    # (3) the specific negotiated credential, if pinned.
    if expected_credential_ref is not None and cls.bound_ref != expected_credential_ref:
        got = cls.bound_ref.hex() if cls.bound_ref else None
        raise CredentialBindingError(f"credential binds ref {got}, expected {expected_credential_ref.hex()}")

    # (2) reorg safety.
    conf = credential.confirmations
    if not isinstance(conf, int) or isinstance(conf, bool) or conf < min_confirmations:
        raise CredentialBindingError(f"credential has {conf} confirmations, need >= {min_confirmations}")

    owner = extract_owner_pkh(credential.current_spk)
    if owner is None:
        raise CredentialBindingError("could not extract a single owner pkh from the credential script")
    return owner


def verify_credential_binding(
    credential: ResolvedCredential,
    *,
    recipient_pkh: bytes,
    min_confirmations: int,
    expected_credential_ref: bytes | None = None,
) -> None:
    """Fail-closed gate: confirm a credential binds to the swap's payout owner.

    Runs :func:`assert_soulbound_credential` (genuine soulbound + confirmations +
    optional ref) and additionally requires the credential's owner pkh to equal
    ``recipient_pkh`` (the pkh the swap pays) — so the asset lands with the
    credential owner. Call this BEFORE locking the asset.
    """
    if not isinstance(recipient_pkh, (bytes, bytearray)) or len(recipient_pkh) != 20:
        raise CredentialBindingError("recipient_pkh must be 20 bytes (hash160)")

    owner = assert_soulbound_credential(
        credential, min_confirmations=min_confirmations, expected_credential_ref=expected_credential_ref
    )
    if owner != bytes(recipient_pkh):
        raise CredentialBindingError(
            f"credential owner {owner.hex()} != swap recipient {bytes(recipient_pkh).hex()} "
            "(asset would not land with the credential owner — rental would pass the gate)"
        )
