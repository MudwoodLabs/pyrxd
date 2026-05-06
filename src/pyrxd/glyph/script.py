"""Glyph script construction, classification, and extraction.

Mental model — Radiant FTs are FIRST-CLASS, ON-CHAIN tokens
==============================================================

A common confusion (especially when LLMs answer questions about it) is to
treat Radiant FTs as "metadata-on-P2PKH that an off-chain indexer
interprets" — like Atomicals on Bitcoin, or Runes, or Solana SPL tokens.

**That model is wrong for Radiant.** Radiant FTs are 75-byte locking
scripts whose token semantics are enforced by consensus (the
``OP_PUSHINPUTREF`` family of opcodes). The script bytes ARE the token.
No external indexer is required to know "this UTXO holds N RBG" — the
ref is encoded in the script and conservation is enforced by the chain.

::

   ┌──────────────────────────────────┬──────────────────────────────────┐
   │ ❌ NOT how Radiant FTs work      │ ✅ How Radiant FTs ACTUALLY work │
   │ (Atomicals / Runes / SPL / ord)  │ (Glyph protocol on Radiant)      │
   ├──────────────────────────────────┼──────────────────────────────────┤
   │                                  │                                  │
   │   On-chain:                      │   On-chain:                      │
   │     plain P2PKH (25 bytes)       │     75-byte FT locking script    │
   │     76a914<pkh>88ac              │     76a914<pkh>88ac              │
   │                                  │     bdd0<ref:36>                 │
   │     ↓ off-chain indexer          │     dec0e9aa76e378e4a269e69d     │
   │       assigns FT meaning         │                                  │
   │   Off-chain database:            │   No external indexer needed:    │
   │     "this UTXO holds 100 FOO"    │     consensus enforces FT rules  │
   │                                  │     directly on the script bytes.│
   │                                  │                                  │
   │   Indexer disagreement / loss    │   No indexer. The token IS the   │
   │   = the token "vanishes."        │   script bytes.                  │
   └──────────────────────────────────┴──────────────────────────────────┘

The 75-byte FT layout in detail
-------------------------------

::

      ┌─ standard P2PKH (25 B) ─┐  ┌─ ref ──┐  ┌── FT-CSH epilogue (12 B) ─┐
      │                         │  │        │  │                            │
      76 a9 14 <pkh:20> 88 ac    bd d0 <ref:36>   de c0 e9 aa 76 e3 78 e4 a2 69 e6 9d
      ▲                         ▲       ▲             ▲
      OP_DUP                    │       │             │
      OP_HASH160                │       │             │
      PUSH(20) <pkh>            │       │             │
      OP_EQUALVERIFY            │       │             │
      OP_CHECKSIG               │       │             │
                                │       │             │
                                │       │             Hashed by the dMint contract
                                │       │             to enforce conservation:
                                │       │             sum(input ft) == sum(output ft)
                                │       │
                                │       OP_PUSHINPUTREF <36-byte wire ref>
                                │       ─ wire ref = txid_LE_reversed + vout_LE
                                │
                                OP_STATESEPARATOR

Conservation rule
-----------------

Every ``OP_PUSHINPUTREF`` (``0xd0``) ref appearing in any OUTPUT script
must also appear in some INPUT being spent::

      INPUTS                         OUTPUTS
      ──────                         ───────
      [FT lock with ref=R]   ──→     [FT lock with ref=R]   ✓ ref R survives
                                     [FT lock with ref=R]   ✓ R can split

      [P2PKH only]           ──→     [FT lock with ref=R]   ✗ REJECTED
                                                              R never came from input

The Radiant node enforces this with the consensus error
``bad-txns-inputs-outputs-invalid-transaction-reference-operations``.
Refs cannot be conjured from thin air — only carried forward.

Wallets at a single address can hold mixed UTXO shapes
------------------------------------------------------

A typical wallet address holds **both** plain P2PKH UTXOs (regular RXD
for fees) and FT lock UTXOs (token balances). They are different shapes
at the same address::

   Address ──┬── UTXO 1: P2PKH 25 bytes,   sats=39825 RXD     (RXD for fees)
             ├── UTXO 2: FT 75 bytes,       sats=5_749_199    (RBG balance)
             ├── UTXO 3: P2PKH 25 bytes,    sats=1            (RXD dust)
             └── UTXO 4: FT 75 bytes (different ref), sats=100 (a different token)

When transferring an FT, code must filter to only FT-shaped UTXOs whose
embedded ref matches the target token. Skipping the ``is_ft_script(...)``
filter and feeding a P2PKH UTXO into ``FtUtxoSet`` produces a tx that
violates the conservation rule and is rejected by the network.

See ``examples/ft_transfer_demo.py`` for the canonical filter pattern.
"""

from __future__ import annotations

import hashlib
import re

from pyrxd.security.errors import ValidationError
from pyrxd.security.types import Hex20

from .types import GlyphRef

# ---------------------------------------------------------------------------
# Classifier regexes
# ---------------------------------------------------------------------------

NFT_SCRIPT_RE = re.compile(r"^d8[0-9a-f]{72}7576a914[0-9a-f]{40}88ac$")
FT_SCRIPT_RE = re.compile(r"^76a914[0-9a-f]{40}88acbdd0[0-9a-f]{72}dec0e9aa76e378e4a269e69d$")
# NFT commit uses OP_2 (52) for SINGLETON ref type; FT commit uses OP_1 (51) for NORMAL ref type.
COMMIT_SCRIPT_NFT_RE = re.compile(r"^aa20[0-9a-f]{64}8803676c7988c0c8c0c954807eda529d76a914[0-9a-f]{40}88ac$")
COMMIT_SCRIPT_FT_RE = re.compile(r"^aa20[0-9a-f]{64}8803676c7988c0c8c0c954807eda519d76a914[0-9a-f]{40}88ac$")
# Kept for backwards compatibility — matches either variant.
COMMIT_SCRIPT_RE = re.compile(r"^aa20[0-9a-f]{64}8803676c7988c0c8c0c954807eda[0-9a-f]{2}9d76a914[0-9a-f]{40}88ac$")


# ---------------------------------------------------------------------------
# Script construction
# ---------------------------------------------------------------------------


def build_nft_locking_script(owner_pkh: Hex20, ref: GlyphRef) -> bytes:
    """Build 63-byte NFT singleton locking script."""
    script = b"\xd8" + ref.to_bytes() + b"\x75\x76\xa9\x14" + bytes(owner_pkh) + b"\x88\xac"
    if len(script) != 63:  # internal invariant
        raise RuntimeError(f"NFT locking script length invariant violated: expected 63, got {len(script)}")
    return script


def build_ft_locking_script(owner_pkh: Hex20, ref: GlyphRef) -> bytes:
    """Build 75-byte FT locking script with conservation epilogue."""
    p2pkh = b"\x76\xa9\x14" + bytes(owner_pkh) + b"\x88\xac"
    epilogue = b"\xbd\xd0" + ref.to_bytes() + b"\xde\xc0\xe9\xaa\x76\xe3\x78\xe4\xa2\x69\xe6\x9d"
    script = p2pkh + epilogue
    if len(script) != 75:  # internal invariant
        raise RuntimeError(f"FT locking script length invariant violated: expected 75, got {len(script)}")
    return script


def build_commit_locking_script(
    payload_hash: bytes,
    owner_pkh: Hex20,
    *,
    is_nft: bool = True,
) -> bytes:
    """Build commit transaction output script.

    The commit script asserts that the spending reveal tx produces an output
    of the expected refType: ``SINGLETON`` (2) for NFT, ``NORMAL`` (1) for FT.
    That single byte — ``OP_2`` vs ``OP_1`` at offset 54 — is the difference
    between an NFT-compatible and FT-compatible commit output.

    Prior versions of this function hardcoded ``OP_2`` (NFT only). Downstream
    FT mint consumers had to patch the output byte themselves, producing
    non-conservation-checked tokens on accident if the patch was wrong. Fixed
    in pyrxd 0.2.0.
    """
    if len(payload_hash) != 32:
        raise ValidationError("payload_hash must be 32 bytes")
    reftype_push = b"\x52" if is_nft else b"\x51"  # OP_2 = SINGLETON, OP_1 = NORMAL
    return (
        b"\xaa"  # OP_HASH256
        + b"\x20"
        + payload_hash  # PUSH 32 + hash
        + b"\x88"  # OP_EQUALVERIFY
        + b"\x03\x67\x6c\x79"  # PUSH 3 + "gly"
        + b"\x88"  # OP_EQUALVERIFY
        + b"\xc0\xc8\xc0\xc9"  # OP_INPUTINDEX OP_OUTPOINTTXHASH OP_INPUTINDEX OP_OUTPOINTINDEX
        + b"\x54\x80\x7e"  # OP_4 OP_NUM2BIN OP_CAT
        + b"\xda"
        + reftype_push
        + b"\x9d"  # OP_REFTYPE_OUTPUT <OP_N> OP_NUMEQUALVERIFY
        + b"\x76\xa9\x14"
        + bytes(owner_pkh)
        + b"\x88\xac"  # P2PKH tail
    )


# ---------------------------------------------------------------------------
# Hash
# ---------------------------------------------------------------------------


def hash_payload(cbor_bytes: bytes) -> bytes:
    """SHA256d of CBOR payload bytes (NOT including 'gly' marker)."""
    return hashlib.sha256(hashlib.sha256(cbor_bytes).digest()).digest()


# ---------------------------------------------------------------------------
# Classifiers
# ---------------------------------------------------------------------------


def is_nft_script(script_hex: str) -> bool:
    """Return True if script_hex matches the NFT singleton pattern."""
    return bool(NFT_SCRIPT_RE.fullmatch(script_hex.lower()))


def is_ft_script(script_hex: str) -> bool:
    """Return True if script_hex matches the FT locking pattern."""
    return bool(FT_SCRIPT_RE.fullmatch(script_hex.lower()))


def is_commit_script(script_hex: str) -> bool:
    """Return True if script_hex matches either commit pattern (NFT or FT)."""
    return bool(COMMIT_SCRIPT_RE.fullmatch(script_hex.lower()))


def is_commit_nft_script(script_hex: str) -> bool:
    """Return True if script_hex matches the NFT-variant commit pattern."""
    return bool(COMMIT_SCRIPT_NFT_RE.fullmatch(script_hex.lower()))


def is_commit_ft_script(script_hex: str) -> bool:
    """Return True if script_hex matches the FT-variant commit pattern."""
    return bool(COMMIT_SCRIPT_FT_RE.fullmatch(script_hex.lower()))


def is_dmint_contract_script(script: bytes) -> bool:
    """Return True if *script* is a dMint contract output script.

    Thin wrapper around :func:`pyrxd.glyph.dmint.DmintState.from_script`. The
    parser today raises ``ValidationError`` on every layout mismatch — every
    ``struct.unpack`` is preceded by an explicit length check, and
    ``GlyphRef.from_bytes`` is fed exactly 36 bytes by construction. We
    additionally catch ``struct.error`` and ``IndexError`` here as
    defense-in-depth: a future change that drops a length check should not
    silently break this predicate's "parses or doesn't" contract. Any other
    exception is a real bug and propagates.

    For diagnostic callers that need the parsed state, call
    ``DmintState.from_script`` directly.
    """
    # Local import — DmintState lives in glyph/dmint.py which itself imports
    # script-construction helpers from this module. Module-level import would
    # close the cycle.
    import struct

    from .dmint import DmintState

    try:
        DmintState.from_script(script)
    except (ValidationError, struct.error, IndexError):
        return False
    return True


# ---------------------------------------------------------------------------
# Extraction helpers
# ---------------------------------------------------------------------------


def extract_ref_from_nft_script(script: bytes) -> GlyphRef:
    """Extract 36-byte ref from a 63-byte NFT script."""
    if len(script) != 63 or script[0] != 0xD8:
        raise ValidationError("Not a valid NFT script")
    return GlyphRef.from_bytes(script[1:37])


def extract_ref_from_ft_script(script: bytes) -> GlyphRef:
    """Extract 36-byte ref from a 75-byte FT script."""
    if len(script) != 75 or script[25] != 0xBD or script[26] != 0xD0:
        raise ValidationError("Not a valid FT script")
    return GlyphRef.from_bytes(script[27:63])


def extract_owner_pkh_from_nft_script(script: bytes) -> Hex20:
    """Extract 20-byte owner PKH from NFT script."""
    if len(script) != 63 or script[0] != 0xD8:
        raise ValidationError("Not a valid NFT script")
    return Hex20(script[41:61])


def extract_owner_pkh_from_ft_script(script: bytes) -> Hex20:
    """Extract 20-byte owner PKH from FT script."""
    if len(script) != 75 or not FT_SCRIPT_RE.match(script.hex()):
        raise ValidationError("Not a valid FT script")
    return Hex20(script[3:23])


def extract_payload_hash_from_commit_script(script: bytes) -> bytes:
    """Extract 32-byte payload hash from a commit script (NFT or FT variant)."""
    if len(script) != 75 or not COMMIT_SCRIPT_RE.match(script.hex()):
        raise ValidationError("Not a valid commit script")
    return script[2:34]


def extract_owner_pkh_from_commit_script(script: bytes) -> Hex20:
    """Extract 20-byte owner PKH from a commit script (NFT or FT variant)."""
    if len(script) != 75 or not COMMIT_SCRIPT_RE.match(script.hex()):
        raise ValidationError("Not a valid commit script")
    return Hex20(script[53:73])


# ---------------------------------------------------------------------------
# Mutable NFT output script (V2 §5 / Glyph MUT protocol)
# ---------------------------------------------------------------------------

# Fixed 102-byte body that follows OP_PUSHINPUTREFSINGLETON + mutable_ref.
# Derived from parseMutableScript regex in Photonic Wallet script.ts.
_MUTABLE_NFT_BODY = bytes.fromhex(
    "76"  # OP_DUP
    "01207f818c54807e"  # 20 OP_SPLIT OP_BIN2NUM OP_1SUB OP_4 OP_NUM2BIN OP_CAT
    "5279e2547a"  # OP_2 OP_PICK OP_REFDATASUMMARY_OUTPUT OP_4 OP_ROLL
    "0124957f77"  # 24 OP_MUL OP_SPLIT OP_NIP
    "01247f75"  # 24 OP_SPLIT OP_DROP
    "887c"  # OP_EQUALVERIFY OP_SWAP
    "ec7b7f"  # OP_STATESCRIPTBYTECODE_OUTPUT OP_ROT OP_SPLIT
    "7701457f75"  # OP_NIP 45 OP_SPLIT OP_DROP
    "7801207e"  # OP_OVER 20 OP_CAT
    "c0ca"  # OP_INPUTINDEX OP_INPUTBYTECODE
    "a87e88"  # OP_SHA256 OP_CAT OP_EQUALVERIFY
    "5279036d6f6487"  # OP_2 OP_PICK 3 "mod" OP_EQUAL
    "63"  # OP_IF
    "78eac0e98878"  # OP_OVER OP_CODESCRIPTBYTECODE_OUTPUT OP_INPUTINDEX OP_CODESCRIPTBYTECODE_UTXO OP_EQUALVERIFY
    "ec01205579aa7e01757e88"  # OP_STATESCRIPTBYTECODE_OUTPUT 20 OP_5 OP_PICK OP_HASH256 OP_CAT 75 OP_CAT OP_EQUALVERIFY
    "67"  # OP_ELSE
    "527902736c88"  # OP_2 OP_PICK 2 "sl" OP_EQUALVERIFY
    "78cd01d852797e016a7e87"  # OP_OVER OP_OUTPUTBYTECODE d8 OP_2 OP_PICK OP_CAT 6a OP_CAT OP_EQUAL
    "78da009c9b"  # OP_OVER OP_REFTYPE_OUTPUT OP_0 OP_NUMEQUAL OP_BOOLOR
    "69"  # OP_VERIFY
    "68"  # OP_ENDIF
    "547a03676c7988"  # OP_4 OP_ROLL 3 "gly" OP_EQUALVERIFY
    "6d6d51"  # OP_2DROP OP_2DROP OP_1
)

# 174 = 1 (push32 opcode) + 32 (hash) + 1 (OP_DROP) + 1 (OP_STATESEPARATOR) +
#        1 (OP_PUSHINPUTREFSINGLETON) + 36 (ref) + 102 (body)
# Note: Photonic Wallet documents 175, but the actual script is 174 bytes per regex.
MUTABLE_NFT_SCRIPT_SIZE = 174

MUTABLE_NFT_SCRIPT_RE = re.compile(r"^20[0-9a-f]{64}75bdd8[0-9a-f]{72}" + _MUTABLE_NFT_BODY.hex() + r"$")


def build_mutable_nft_script(mutable_ref: GlyphRef, payload_hash: bytes) -> bytes:
    """Build the 175-byte mutable NFT output script.

    Layout: PUSH32 <payload_hash> OP_DROP OP_STATESEPARATOR
            OP_PUSHINPUTREFSINGLETON <mutable_ref:36> <102-byte body>

    :param mutable_ref:  The singleton ref that identifies the mutable contract.
    :param payload_hash: 32-byte SHA256d of the CBOR metadata payload.
    """
    if len(payload_hash) != 32:
        raise ValidationError("payload_hash must be 32 bytes")
    script = (
        b"\x20"
        + payload_hash  # PUSH 32 + hash
        + b"\x75"  # OP_DROP
        + b"\xbd"  # OP_STATESEPARATOR
        + b"\xd8"
        + mutable_ref.to_bytes()  # OP_PUSHINPUTREFSINGLETON + 36-byte ref
        + _MUTABLE_NFT_BODY
    )
    if len(script) != MUTABLE_NFT_SCRIPT_SIZE:
        raise RuntimeError(
            f"Mutable NFT script size invariant violated: expected {MUTABLE_NFT_SCRIPT_SIZE}, got {len(script)}"
        )
    return script


def parse_mutable_nft_script(script: bytes) -> tuple[GlyphRef, bytes] | None:
    """Parse a mutable NFT output script, returning (mutable_ref, payload_hash) or None."""
    if len(script) != MUTABLE_NFT_SCRIPT_SIZE:
        return None
    if script[0] != 0x20 or script[33] != 0x75 or script[34] != 0xBD or script[35] != 0xD8:
        return None
    if script[72:] != _MUTABLE_NFT_BODY:
        return None
    payload_hash = script[1:33]
    mutable_ref = GlyphRef.from_bytes(script[36:72])
    return mutable_ref, payload_hash
