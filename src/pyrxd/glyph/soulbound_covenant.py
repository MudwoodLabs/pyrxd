"""PROTOTYPE: a *consensus-enforced* soulbound NFT covenant for Radiant Glyphs.

Status: SPIKE — structural guards pass AND the consensus behaviour is CONFIRMED on
``radiant-core:v3.1.1`` regtest (``tests/test_soulbound_covenant_regtest.py``:
recur-to-self ACCEPTED, transfer-to-other REJECTED, burn ACCEPTED), differentially
alongside the live mainnet deployed design. Still pre-external-audit: do not use
for real value until audited.

Why this exists
---------------
Photonic Wallet's soulbound support (``packages/lib/src/soulbound.ts``) is
**advisory only**: ``soulboundNftScript`` emits a *plain* ``OP_PUSHINPUTREFSINGLETON
<ref> OP_DROP <P2PKH>`` — an ordinary, fully transferable NFT — and the
"can't transfer" behaviour lives entirely in the off-chain
``validateSoulboundTransfer`` (a string check an honest wallet runs voluntarily).
That helper is, in fact, dead code (never called by the mint path). So a
counterparty running their own software can move a "soulbound" token freely. That
makes Photonic-style soulbound useless as a trust anchor for an adversarial
cross-chain HTLC gate (compliance / reputation use cases).

Radiant *is* expressive enough to enforce non-transferability at consensus — via
a covenant that forces the singleton to recur only into a byte-identical clone of
itself (same ref + same logic + same immutable owner) OR be burned. This module
builds exactly that covenant.

The covenant (funded scriptPubKey)
----------------------------------
``scriptSig`` supplies ``<sig> <pubkey>`` (standard P2PKH spend). The locking
script then runs::

    OP_PUSHINPUTREFSINGLETON <ref>   ; assert our singleton is in the inputs; leaves <ref> on stack
    OP_REFOUTPUTCOUNT_OUTPUTS        ; consume <ref> -> count of outputs carrying it
    OP_0 OP_NUMEQUAL                 ; is the singleton being burned (0 outputs carry it)?
    OP_IF
        ;                            ; BURN branch: singleton destroyed -> allowed (owner sig still required below)
    OP_ELSE
        OP_0 OP_OUTPUTBYTECODE       ; output[0] scriptPubKey
        OP_INPUTINDEX OP_UTXOBYTECODE; THIS input's own scriptPubKey (the covenant itself)
        OP_EQUALVERIFY               ; the singleton may ONLY recur into a byte-identical clone
    OP_ENDIF
    OP_DUP OP_HASH160 <ownerPkh> OP_EQUALVERIFY OP_CHECKSIG   ; only the (immutable) owner may act

The non-transferability proof is structural: the owner pkh is baked into the
immutable locking script, and the recur branch requires ``output[0]`` to equal
this UTXO's bytecode *exactly*. A clone with a different owner pkh is a different
script, so ``OP_EQUALVERIFY`` fails. The token can therefore only ever (a) stay
with the same owner or (b) be burned. There is no transfer path. This is the
chain-side mechanism Photonic lacks.

Design choices vs alternatives
------------------------------
* **Full-bytecode self-equality** (``OP_INPUTINDEX OP_UTXOBYTECODE`` vs
  ``OP_0 OP_OUTPUTBYTECODE``) rather than the code-script-only idiom
  (``OP_CODESCRIPTBYTECODE_*``). Code-script-only equality would let the *state*
  (owner) change between hops — i.e. a transfer — so it is the wrong primitive
  for soulbinding. We pin the WHOLE script, owner included. This mirrors the
  "Contract script must exist unchanged in output" idiom proven in Photonic's
  container/vault covenants (``packages/lib/src/script.ts:305``).
* **No** ``OP_STATESEPARATOR`` — the script is fully immutable, so there is no
  mutable state to diverge.
* ``OP_ACTIVEBYTECODE`` would be more compact but its exact return semantics
  (whole script vs post-codeseparator) need their own regtest confirmation;
  ``OP_INPUTINDEX OP_UTXOBYTECODE`` is unambiguous.

Assumptions CONFIRMED on regtest (``tests/test_soulbound_covenant_regtest.py``):
  1. ``OP_INPUTINDEX OP_UTXOBYTECODE`` vs ``OP_0 OP_OUTPUTBYTECODE`` compare the two
     full scriptPubKeys byte-for-byte (recur-to-self accepted, transfer rejected).
  2. ``OP_REFOUTPUTCOUNT_OUTPUTS`` consumes the ref from ``OP_PUSHINPUTREFSINGLETON``
     and returns the OUTPUT-side carry count (burn branch fires at 0).
  3. Consensus permits destroying a singleton (burn accepted).
"""

from __future__ import annotations

from dataclasses import dataclass

from pyrxd.constants import OpCode as OP
from pyrxd.glyph.script import count_input_refs
from pyrxd.glyph.types import GlyphRef
from pyrxd.security.errors import ValidationError

__all__ = [
    "SoulboundNftCovenant",
    "build_composable_soulbound_nft_covenant",
    "build_soulbound_nft_covenant",
]

# Ref-carrying opcodes consume a 36-byte operand (used by the opcode walk).
_REF_OPS = frozenset({0xD0, 0xD1, 0xD2, 0xD3, 0xD8})


@dataclass(frozen=True)
class SoulboundNftCovenant:
    """A built soulbound-NFT covenant.

    Attributes
    ----------
    funded_spk:
        The covenant scriptPubKey the NFT singleton is locked into. The ONLY
        non-burn spend is one whose ``output[0]`` equals this byte-for-byte.
    genesis_ref:
        The 36-byte wire-format singleton ref bound by the covenant.
    owner_pkh:
        The 20-byte hash160 of the immutable owner. Changing it yields a
        different ``funded_spk`` (which is precisely why transfer is impossible).
    recur_target_spk:
        The scriptPubKey ``output[0]`` of a (non-burn) spend MUST equal. For a
        soulbound covenant this is identical to ``funded_spk`` — the self-clone.
    """

    funded_spk: bytes
    genesis_ref: bytes
    owner_pkh: bytes

    @property
    def recur_target_spk(self) -> bytes:
        # Soulbound => the only legal recurrence is an exact self-clone.
        return self.funded_spk


def _assert_no_nonminimal_push(spk: bytes) -> None:
    """Fail-closed if any data push violates MANDATORY ``MINIMALDATA``.

    The soulbound covenant only contains opcodes, the 36-byte ref operand, and a
    single 20-byte ``pkh`` direct push, so this is normally trivially satisfied —
    but we re-check the whole assembled script so a future edit that introduces a
    non-minimal push fails at build time rather than silently on-chain. Mirrors
    the equivalent guard in ``gravity/htlc_covenant.py``.
    """
    i, n = 0, len(spk)
    while i < n:
        op = spk[i]
        if op in _REF_OPS:
            i += 37  # ref opcode + 36-byte ref operand (not a data push)
            continue
        if 0x01 <= op <= 0x4B:
            if i + 1 + op > n:
                raise ValidationError(f"truncated direct push at offset {i}")
            if op == 1:
                b0 = spk[i + 1]
                if 1 <= b0 <= 16 or b0 == 0x81:
                    raise ValidationError(
                        f"non-minimal 1-byte push 0x{b0:02x} at offset {i} "
                        "(must be OP_1..OP_16 / OP_1NEGATE) — would brick the covenant"
                    )
            i += 1 + op
            continue
        if op in (0x4C, 0x4D, 0x4E):
            raise ValidationError(
                f"unexpected PUSHDATA opcode 0x{op:02x} at offset {i} (soulbound covenant uses only direct pushes)"
            )
        i += 1


def build_soulbound_nft_covenant(genesis_ref: GlyphRef, owner_pkh: bytes) -> SoulboundNftCovenant:
    """Build a consensus-enforced soulbound NFT covenant SPK.

    Parameters
    ----------
    genesis_ref:
        The Glyph singleton's genesis ref (becomes the ``d8`` singleton binding).
    owner_pkh:
        20-byte hash160 of the immutable owner. Baked into the locking script so
        that any "transfer" (clone with a different owner) is a different script
        and fails the recur ``OP_EQUALVERIFY``.

    Returns
    -------
    SoulboundNftCovenant
        With both static guards (exactly-one-ref, no-nonminimal-push) run
        fail-closed at build time.
    """
    if not isinstance(owner_pkh, (bytes, bytearray)) or len(owner_pkh) != 20:
        raise ValidationError("owner_pkh must be 20 bytes (hash160)")
    ref = genesis_ref.to_bytes()  # 36-byte wire format
    if len(ref) != 36:  # defensive; GlyphRef.to_bytes already guarantees this
        raise ValidationError("genesis ref must encode to 36 bytes")

    spk = b"".join(
        [
            # --- singleton assertion (leaves <ref> on the stack) ---
            OP.OP_PUSHINPUTREFSINGLETON,
            ref,
            # --- branch on how many OUTPUTS carry the singleton ---
            OP.OP_REFOUTPUTCOUNT_OUTPUTS,  # consume <ref> -> carry count
            OP.OP_0,
            OP.OP_NUMEQUAL,  # count == 0  ->  burn?
            OP.OP_IF,
            #   BURN branch: singleton destroyed; no structural constraint
            OP.OP_ELSE,
            #   RECUR branch: output[0] must be a byte-identical clone of THIS utxo
            OP.OP_0,
            OP.OP_OUTPUTBYTECODE,  # output[0] scriptPubKey
            OP.OP_INPUTINDEX,
            OP.OP_UTXOBYTECODE,  # this input's own scriptPubKey
            OP.OP_EQUALVERIFY,
            OP.OP_ENDIF,
            # --- immutable owner authorization (P2PKH) ---
            OP.OP_DUP,
            OP.OP_HASH160,
            bytes([20]),
            bytes(owner_pkh),
            OP.OP_EQUALVERIFY,
            OP.OP_CHECKSIG,
        ]
    )

    # --- static guards (fail-closed at build time) ---
    refs = set(count_input_refs(spk).keys())
    if refs != {ref}:
        got = sorted(r.hex() for r in refs)
        raise ValidationError(
            f"GUARD FAIL: input refs {got} != expected [{ref.hex()}] (exactly the genesis singleton ref must bind)"
        )
    _assert_no_nonminimal_push(spk)

    return SoulboundNftCovenant(funded_spk=spk, genesis_ref=ref, owner_pkh=bytes(owner_pkh))


def build_composable_soulbound_nft_covenant(genesis_ref: GlyphRef, owner_pkh: bytes) -> SoulboundNftCovenant:
    """Build a soulbound covenant that recurs to a clone at ANY output index.

    Same soulbound guarantee as :func:`build_soulbound_nft_covenant` (recur into a
    code-identical clone of itself, or burn) but **index-independent**: instead of
    pinning the clone to ``output[0]`` (``OP_0 OP_OUTPUTBYTECODE``), it requires
    *exactly one* output whose code-script-hash equals this UTXO's own — wherever
    it sits. That makes the credential **co-spendable**: it can recur to
    ``output[1]`` while a swap asset claims ``output[0]``, which the fixed-index
    covenant cannot do.

    This is the prerequisite for revocation-aware credential binding: a swap claim
    can ``OP_REQUIREINPUTREF`` the credential (forcing it to be a live input at
    claim time, so a burned/revoked credential fails the claim) only if the
    credential can ride along without fighting over ``output[0]``.

    Recur branch::

        OP_REFOUTPUTCOUNT_OUTPUTS OP_DUP OP_0 OP_NUMEQUAL OP_IF
            OP_DROP                                   ; burn (0 outputs carry the ref)
        OP_ELSE
            OP_1 OP_NUMEQUALVERIFY                    ; exactly one output carries the ref
            OP_INPUTINDEX OP_CODESCRIPTBYTECODE_UTXO OP_HASH256       ; my code-script hash
            OP_CODESCRIPTHASHOUTPUTCOUNT_OUTPUTS OP_1 OP_NUMEQUALVERIFY  ; exactly one output clones me
        OP_ENDIF
        OP_DUP OP_HASH160 <ownerPkh> OP_EQUALVERIFY OP_CHECKSIG

    Mirrors the proven code-script-hash conservation idiom used in Photonic's
    container/vault FT covenants, narrowed to a single (NFT) singleton.

    Consensus behaviour CONFIRMED on regtest
    (``tests/test_soulbound_covenant_regtest.py``: recur-to-``output[1]`` accepted,
    transfer rejected, burn accepted). Pre-external-audit; not for real value yet.
    """
    if not isinstance(owner_pkh, (bytes, bytearray)) or len(owner_pkh) != 20:
        raise ValidationError("owner_pkh must be 20 bytes (hash160)")
    ref = genesis_ref.to_bytes()
    if len(ref) != 36:
        raise ValidationError("genesis ref must encode to 36 bytes")

    spk = b"".join(
        [
            OP.OP_PUSHINPUTREFSINGLETON,
            ref,
            OP.OP_REFOUTPUTCOUNT_OUTPUTS,  # consume <ref> -> carry count
            OP.OP_DUP,
            OP.OP_0,
            OP.OP_NUMEQUAL,  # count == 0  ->  burn?
            OP.OP_IF,
            OP.OP_DROP,  #   burn: drop the dup'd count
            OP.OP_ELSE,
            OP.OP_1,
            OP.OP_NUMEQUALVERIFY,  #   recur: exactly one output carries the ref
            OP.OP_INPUTINDEX,
            OP.OP_CODESCRIPTBYTECODE_UTXO,
            OP.OP_HASH256,  #   my code-script hash
            OP.OP_CODESCRIPTHASHOUTPUTCOUNT_OUTPUTS,
            OP.OP_1,
            OP.OP_NUMEQUALVERIFY,  #   exactly one output replicates my code script
            OP.OP_ENDIF,
            OP.OP_DUP,
            OP.OP_HASH160,
            bytes([20]),
            bytes(owner_pkh),
            OP.OP_EQUALVERIFY,
            OP.OP_CHECKSIG,
        ]
    )

    refs = set(count_input_refs(spk).keys())
    if refs != {ref}:
        got = sorted(r.hex() for r in refs)
        raise ValidationError(
            f"GUARD FAIL: input refs {got} != expected [{ref.hex()}] (exactly the genesis singleton ref must bind)"
        )
    _assert_no_nonminimal_push(spk)

    return SoulboundNftCovenant(funded_spk=spk, genesis_ref=ref, owner_pkh=bytes(owner_pkh))
