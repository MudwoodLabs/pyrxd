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
                                │       │             The FT-CSH epilogue. This
                                │       │             output's OWN script enforces
                                │       │             conservation when it is spent:
                                │       │             sum(input ft) >= sum(output ft)
                                │       │             (0xa2 = OP_GREATERTHANOREQUAL —
                                │       │             burning is permitted, inflation
                                │       │             is not). See the walk below.
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

What the 12-byte epilogue enforces
----------------------------------

Induction (above) is a consensus rule about refs. The *amount* rule is
enforced by the FT output's own script when it is spent::

      de   OP_REFOUTPUTCOUNT_OUTPUTS            ref      -> n_ref
      c0   OP_INPUTINDEX
      e9   OP_CODESCRIPTBYTECODE_UTXO           this input's code script
      aa   OP_HASH256                                    -> csh
      76   OP_DUP
      e3   OP_CODESCRIPTHASHVALUESUM_UTXOS      csh      -> sum_in
      78   OP_OVER
      e4   OP_CODESCRIPTHASHVALUESUM_OUTPUTS    csh      -> sum_out
      a2   OP_GREATERTHANOREQUAL                         -> sum_in >= sum_out
      69   OP_VERIFY
      e6   OP_CODESCRIPTHASHOUTPUTCOUNT_OUTPUTS csh      -> n_csh
      9d   OP_NUMEQUALVERIFY                             -> n_ref == n_csh

So exactly two things hold: ``sum_in >= sum_out`` (inflation impossible,
**burning permitted** — it is ``>=``, not ``==``), and the ref appears in
exactly as many outputs as the FT code-script hash does, which is what
stops the ref being carried into an output of any other shape. The code
script hashed here is ``d0 <token_ref> || <12-byte epilogue>``, so it is
unique per token. See ``docs/reference/glyph-token-protocol-spec.md`` §9.2.

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

import re
from collections.abc import Sequence

from pyrxd.constants import REF_OPERAND_OPCODES, REF_OPERAND_WIDTH
from pyrxd.hash import hash256
from pyrxd.script.consensus import get_script_op
from pyrxd.security.errors import ValidationError
from pyrxd.security.types import Hex20

from .types import GlyphRef

# ---------------------------------------------------------------------------
# Classifier regexes
# ---------------------------------------------------------------------------

NFT_SCRIPT_RE = re.compile(r"^d8[0-9a-f]{72}7576a914[0-9a-f]{40}88ac$")
# The 100-byte shape ``prepare_container_reveal(child_ref=...)`` emitted in
# pyrxd 0.9.0 through 0.14.0. It is recognised ONLY so that a holder of one can
# be told what it is; it is NOT a token shape pyrxd builds any more, and any
# output carrying it is permanently unspendable. See
# :func:`is_legacy_container_script`.
LEGACY_CONTAINER_SCRIPT_RE = re.compile(r"^d0[0-9a-f]{72}d8[0-9a-f]{72}7576a914[0-9a-f]{40}88ac$")
LEGACY_CONTAINER_SCRIPT_SIZE = 100
FT_SCRIPT_RE = re.compile(r"^76a914[0-9a-f]{40}88acbdd0[0-9a-f]{72}dec0e9aa76e378e4a269e69d$")
# NFT commit uses OP_2 (52) for SINGLETON ref type; FT commit uses OP_1 (51) for NORMAL ref type.
COMMIT_SCRIPT_NFT_RE = re.compile(r"^aa20[0-9a-f]{64}8803676c7988c0c8c0c954807eda529d76a914[0-9a-f]{40}88ac$")
COMMIT_SCRIPT_FT_RE = re.compile(r"^aa20[0-9a-f]{64}8803676c7988c0c8c0c954807eda519d76a914[0-9a-f]{40}88ac$")
# Kept for backwards compatibility — matches either variant.
COMMIT_SCRIPT_RE = re.compile(r"^aa20[0-9a-f]{64}8803676c7988c0c8c0c954807eda[0-9a-f]{2}9d76a914[0-9a-f]{40}88ac$")

# A DAT commit carries NO OP_REFTYPE_OUTPUT block — a DAT reveal mints nothing —
# and adds a "dat" marker push ahead of "gly". 70 bytes.
DAT_COMMIT_SCRIPT_SIZE = 70
DAT_COMMIT_SCRIPT_RE = re.compile(
    r"^aa20([0-9a-f]{64})8803646174880367 6c798876a914([0-9a-f]{40})88ac$".replace(" ", "")
)

# --- Authority-gated NFT (Photonic ``packages/lib/src/authority.ts:239``) -----
# ``OP_REQUIREINPUTREF <auth_ref> OP_DROP OP_PUSHINPUTREFSINGLETON <ref> OP_DROP``
# + P2PKH. 38 + 38 + 25 = 101 bytes. See
# :func:`build_authority_gated_nft_script` for what the gate does and does NOT
# bind.
AUTHORITY_GATED_SCRIPT_SIZE = 101
AUTHORITY_GATED_SCRIPT_RE = re.compile(r"^d1([0-9a-f]{72})75d8([0-9a-f]{72})7576a914([0-9a-f]{40})88ac$")

# --- Delegate refs (Photonic ``packages/lib/src/script.ts:455-499``) ----------
# A delegate authorises a token's ``in``/``by`` claim WITHOUT the minting wallet
# holding the parent singleton. The parent refs are spent ONCE into a delegate
# BASE output; disposable delegate TOKENS point at that base; each mint spends a
# token and emits a BURN output naming the base ref. See
# :func:`build_delegate_base_script` for the full chain and why each link is
# consensus-backed rather than conventional.
DELEGATE_TOKEN_SCRIPT_SIZE = 63
DELEGATE_BURN_SCRIPT_SIZE = 42
# The 56-byte prefix ``build_commit_locking_script(delegate_ref=...)`` prepends.
DELEGATE_COMMIT_PREFIX_SIZE = 56
# A delegate token is ``OP_PUSHINPUTREF <base_ref> OP_DROP`` + P2PKH — the SAME
# 63 bytes as an NFT singleton, differing only in the first opcode (0xd0 vs
# 0xd8). It is token-bearing: spending one as ordinary funding destroys it, so
# coin selection must exclude it via ``is_token_bearing_script``.
DELEGATE_TOKEN_SCRIPT_RE = re.compile(r"^d0[0-9a-f]{72}7576a914[0-9a-f]{40}88ac$")
DELEGATE_BURN_SCRIPT_RE = re.compile(r"^d1([0-9a-f]{72})6a0364656c$")


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
    delegate_ref: GlyphRef | None = None,
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
    prefix = build_delegate_commit_prefix(delegate_ref) if delegate_ref is not None else b""
    return (
        prefix
        + b"\xaa"  # OP_HASH256
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
# DAT commit (data storage, protocol 3)
# ---------------------------------------------------------------------------


def build_dat_commit_locking_script(
    payload_hash: bytes,
    owner_pkh: Hex20,
    *,
    delegate_ref: GlyphRef | None = None,
) -> bytes:
    """Build a DAT commit output script — 70 bytes, or 126 with a delegate.

    Mirrors Photonic ``datCommitScript`` (``packages/lib/src/script.ts:298``)::

        OP_HASH256 <payload_hash> OP_EQUALVERIFY
        PUSH "dat" OP_EQUALVERIFY
        PUSH "gly" OP_EQUALVERIFY
        OP_DUP OP_HASH160 <owner_pkh> OP_EQUALVERIFY OP_CHECKSIG

    The difference from :func:`build_commit_locking_script` is the whole point:
    there is **no** ``OP_REFTYPE_OUTPUT`` block. An NFT or FT commit obliges its
    reveal to produce an output of a given ref type — that is what mints the
    token. A DAT reveal creates no token at all; it stores data, and the only
    thing the commit binds is that the revealed payload hashes to
    *payload_hash*.

    So a DAT reveal has nothing to transfer and nothing to own afterwards. The
    payload is recovered from the reveal's scriptSig, exactly as for any other
    glyph, and lives as long as the chain does.

    Note the extra ``"dat"`` push: it means a DAT reveal's scriptSig is NOT the
    one :func:`~pyrxd.glyph.payload.build_reveal_scriptsig_suffix` builds. Use
    :func:`~pyrxd.glyph.payload.build_dat_reveal_scriptsig_suffix`, which pushes
    the two markers in the order this script pops them.
    """
    if len(payload_hash) != 32:
        raise ValidationError("payload_hash must be 32 bytes")
    prefix = build_delegate_commit_prefix(delegate_ref) if delegate_ref is not None else b""
    script = (
        prefix
        + b"\xaa"  # OP_HASH256
        + b"\x20"
        + payload_hash  # PUSH 32 + hash
        + b"\x88"  # OP_EQUALVERIFY
        + b"\x03dat"  # PUSH 3 + "dat"
        + b"\x88"  # OP_EQUALVERIFY
        + b"\x03gly"  # PUSH 3 + "gly"
        + b"\x88"  # OP_EQUALVERIFY
        + b"\x76\xa9\x14"
        + bytes(owner_pkh)
        + b"\x88\xac"  # P2PKH tail
    )
    expected = DAT_COMMIT_SCRIPT_SIZE + (DELEGATE_COMMIT_PREFIX_SIZE if delegate_ref is not None else 0)
    if len(script) != expected:  # internal invariant
        raise RuntimeError(f"DAT commit script length invariant violated: expected {expected}, got {len(script)}")
    return script


def parse_dat_commit_script(script: bytes) -> tuple[bytes, Hex20] | None:
    """Return ``(payload_hash, owner_pkh)`` from a DAT commit, or ``None``.

    Fields come from the regex's capture groups rather than from hand-written
    byte offsets. The DAT layout differs from the NFT/FT commit by the extra
    ``"dat"`` push, so every offset shifts — which is exactly the kind of
    transcription the inspector got wrong first time.

    There is deliberately no ``is_dat_commit_script`` companion: ``... is not
    None`` answers the same question with strictly more information, and a
    second predicate is a second thing to keep in step with this regex.
    """
    _delegate_ref, core = split_delegate_commit_prefix(script)
    m = DAT_COMMIT_SCRIPT_RE.fullmatch(core.hex().lower())
    if m is None:
        return None
    return bytes.fromhex(m.group(1)), Hex20(bytes.fromhex(m.group(2)))


# ---------------------------------------------------------------------------
# Authority-gated NFT
# ---------------------------------------------------------------------------


def build_authority_gated_nft_script(owner_pkh: Hex20, ref: GlyphRef, authority_ref: GlyphRef) -> bytes:
    """Build the 101-byte authority-gated NFT locking script.

    Mirrors Photonic ``authorityGatedNftScript``
    (``packages/lib/src/authority.ts:239``)::

        OP_REQUIREINPUTREF <authority_ref> OP_DROP
        OP_PUSHINPUTREFSINGLETON <ref> OP_DROP
        OP_DUP OP_HASH160 <owner_pkh> OP_EQUALVERIFY OP_CHECKSIG

    What the gate binds
    -------------------

    ``OP_REQUIREINPUTREF`` is subset-checked against the transaction's inputs
    (:data:`~pyrxd.constants.INPUT_BACKED_REF_OPCODES`), so **an output carrying
    this script can only be created by a transaction whose input ref set
    contains** *authority_ref*. At genesis that means the minter held the
    issuer's authority token, which is the point: a counterfeiter without it
    cannot mint a gated item.

    What it binds, MEASURED on a node
    ---------------------------------

    All three answers below come from ``tests/test_authority_regtest_e2e.py``
    against Radiant Core v3.1.1 — not from reading the opcode table, because
    the input ref set includes refs carried by the spent inputs' own scripts and
    a gated output carries *authority_ref* in its script. Whether that counts
    when spent decides everything here, and it turns out not to:

    ================================================== ==========
    attempt                                             verdict
    ================================================== ==========
    mint a gated item without the authority as input    REJECTED
    mint a SECOND gated item from an existing one       REJECTED
    transfer to a new owner, KEEPING the gate           REJECTED
    transfer to a plain NFT script, dropping the gate   ACCEPTED
    ================================================== ==========

    Two consequences the name does not suggest:

    **It is not a mint-time rule.** Photonic calls it "creation-time
    (mint-time)". It is that, but re-creating this script in ANY later
    transaction also needs the authority ref among that transaction's inputs. So
    the holder cannot move a gated item and keep it gated without the issuer
    signing alongside them.

    **"Gated" is not a durable property of a token.** The item's own singleton
    ref survives in a plain 63-byte NFT script, so the holder can transfer to
    one — unilaterally, in a single transaction — and end up with the same ref
    and no gate. A check of the form "is this token authority-gated?" applied to
    a token's CURRENT output is therefore defeatable by its holder. Authority
    gating is a claim about an item's **genesis**, and only the genesis
    transaction establishes it. :func:`is_authority_gated_script` answers "is
    this output gated", which is a different and weaker question — see
    :func:`~pyrxd.glyph.authority.verify_authority_gate` for the one that reads
    the genesis.

    What it does buy is real: the issuer's authority token is required to bring
    any gated item into existence, and holding one gated item does not let you
    mint another. The gate IS a supply cap.

    :param ref: the item's own singleton ref (its commit outpoint).
    :param authority_ref: the issuer's authority token ref.
    :raises ValidationError: *ref* and *authority_ref* are the same outpoint —
        a token gated on itself is satisfied by its own creation and gates
        nothing, which is never what the caller meant.
    """
    if ref.txid == authority_ref.txid and ref.vout == authority_ref.vout:
        raise ValidationError(
            f"authority_ref {authority_ref.txid}:{authority_ref.vout} is the item's own ref — a token "
            "gated on itself imposes no requirement its own creation does not already satisfy."
        )
    script = (
        b"\xd1"  # OP_REQUIREINPUTREF
        + authority_ref.to_bytes()
        + b"\x75"  # OP_DROP
        + b"\xd8"  # OP_PUSHINPUTREFSINGLETON
        + ref.to_bytes()
        + b"\x75"  # OP_DROP
        + b"\x76\xa9\x14"
        + bytes(owner_pkh)
        + b"\x88\xac"  # P2PKH tail
    )
    if len(script) != AUTHORITY_GATED_SCRIPT_SIZE:  # internal invariant
        raise RuntimeError(
            f"authority-gated script length invariant violated: "
            f"expected {AUTHORITY_GATED_SCRIPT_SIZE}, got {len(script)}"
        )
    return script


def is_authority_gated_script(script_hex: str) -> bool:
    """Return True if *script_hex* is an authority-gated NFT output."""
    return bool(AUTHORITY_GATED_SCRIPT_RE.fullmatch(script_hex.lower()))


def parse_authority_gated_script(script: bytes) -> tuple[GlyphRef, GlyphRef, Hex20] | None:
    """Return ``(authority_ref, ref, owner_pkh)``, or ``None`` if not gated.

    Refs come back as :class:`~pyrxd.glyph.types.GlyphRef`, decoded from the
    little-endian script form they appear in.
    """
    m = AUTHORITY_GATED_SCRIPT_RE.fullmatch(script.hex().lower())
    if m is None:
        return None
    return (
        GlyphRef.from_bytes(bytes.fromhex(m.group(1))),
        GlyphRef.from_bytes(bytes.fromhex(m.group(2))),
        Hex20(bytes.fromhex(m.group(3))),
    )


# ---------------------------------------------------------------------------
# Delegate refs
# ---------------------------------------------------------------------------


def build_delegate_base_script(owner_pkh: Hex20, refs: Sequence[GlyphRef]) -> bytes:
    """Build the delegate BASE locking script — the one-time authorisation.

    Mirrors Photonic ``delegateBaseScript`` (``packages/lib/src/script.ts:455``).

    Layout: ``(OP_REQUIREINPUTREF <ref> OP_DROP)*N`` followed by a P2PKH tail,
    so ``38 * N + 25`` bytes.

    Why this authorises anything
    ----------------------------

    ``OP_REQUIREINPUTREF`` (``0xd1``) is one of the three opcodes Radiant
    subset-checks against the transaction's inputs
    (:data:`~pyrxd.constants.INPUT_BACKED_REF_OPCODES`; see
    :mod:`pyrxd.glyph.relationships` for why the other two ref opcodes are NOT
    authorisation). So consensus refused this output unless the transaction
    creating it actually spent every ref named here. Building a base is
    therefore the moment the container and author singletons are held — and
    the only such moment.

    The full chain, and what each link buys:

    ==== ============================================ =========================
    step transaction                                   what consensus enforces
    ==== ============================================ =========================
    1    spend container + author → base output        base's refs were held
    2    spend base → N delegate token outputs         tokens carry the base ref
    3    mint: spend a token; commit carries the       the mint held a token,
         56-byte prefix; reveal emits the burn         and burned it
    ==== ============================================ =========================

    After step 1 the singletons are free to go back to cold storage: steps 2
    and 3 never touch them again. That is the whole point — it is what lets a
    hot minting service authorise ``in``/``by`` claims without custody of the
    tokens those claims are about, and what lets N pre-minted delegate tokens
    serve N concurrent mints instead of serialising on one singleton UTXO.

    :param refs: the parent refs to authorise — container refs, author refs, or
        both. Order is preserved but carries no meaning.
    :raises ValidationError: *refs* is empty. A base authorising nothing is
        never what the caller meant, and it parses back as an ordinary P2PKH.
    """
    if not refs:
        raise ValidationError(
            "build_delegate_base_script() needs at least one ref: a base authorising nothing "
            "is indistinguishable from a plain P2PKH output and delegates nothing."
        )
    script = b""
    for ref in refs:
        script += b"\xd1" + ref.to_bytes() + b"\x75"  # OP_REQUIREINPUTREF <ref> OP_DROP
    script += b"\x76\xa9\x14" + bytes(owner_pkh) + b"\x88\xac"  # P2PKH tail
    expected = 38 * len(refs) + 25
    if len(script) != expected:  # internal invariant
        raise RuntimeError(f"delegate base script length invariant violated: expected {expected}, got {len(script)}")
    return script


def build_delegate_token_script(owner_pkh: Hex20, base_ref: GlyphRef) -> bytes:
    """Build a 63-byte delegate TOKEN locking script.

    Mirrors Photonic ``delegateTokenScript`` (``script.ts:464``):
    ``OP_PUSHINPUTREF <base_ref> OP_DROP`` + P2PKH.

    *base_ref* is the outpoint of the :func:`build_delegate_base_script` output,
    NOT a container or author ref. Spending this token carries the base ref into
    the spending transaction's input ref set, which is what the mint's commit
    prefix and burn output both require.

    The ``OP_DROP`` is load-bearing: ``OP_PUSHINPUTREF`` leaves its operand on
    the stack, and without the drop the P2PKH tail hashes the *ref* instead of
    the signature's pubkey and the output is permanently unspendable. That is
    the exact defect pyrxd shipped in its removed ``child_ref`` prefix
    (0.9.0-0.14.0) — see :func:`is_legacy_container_script` and spec §7.5.1.
    """
    script = b"\xd0" + base_ref.to_bytes() + b"\x75\x76\xa9\x14" + bytes(owner_pkh) + b"\x88\xac"
    if len(script) != DELEGATE_TOKEN_SCRIPT_SIZE:  # internal invariant
        raise RuntimeError(
            f"delegate token script length invariant violated: expected {DELEGATE_TOKEN_SCRIPT_SIZE}, got {len(script)}"
        )
    return script


def build_delegate_burn_script(base_ref: GlyphRef) -> bytes:
    """Build the 42-byte delegate BURN output script.

    Mirrors Photonic ``delegateBurnScript`` (``script.ts:471``):
    ``OP_REQUIREINPUTREF <base_ref> OP_RETURN "del"``.

    This is the marker an indexer looks for. It is unspendable (``OP_RETURN``)
    and carries no value, so give it 0 photons. Its ``OP_REQUIREINPUTREF``
    means consensus rejects the transaction unless a delegate token carrying
    *base_ref* really was spent — the claim cannot be written by someone who
    does not hold one.
    """
    script = b"\xd1" + base_ref.to_bytes() + b"\x6a" + b"\x03" + b"del"
    if len(script) != DELEGATE_BURN_SCRIPT_SIZE:  # internal invariant
        raise RuntimeError(
            f"delegate burn script length invariant violated: expected {DELEGATE_BURN_SCRIPT_SIZE}, got {len(script)}"
        )
    return script


def build_delegate_commit_prefix(delegate_ref: GlyphRef) -> bytes:
    """The 56-byte prefix a delegate-carrying commit script opens with.

    Mirrors Photonic ``addDelegateRefScript`` (``script.ts:214``), and is
    prepended by :func:`build_commit_locking_script` when ``delegate_ref`` is
    given. *delegate_ref* is the BASE ref (see
    :func:`build_delegate_token_script`).

    It is a covenant on the reveal — it runs when the commit output is SPENT,
    and asserts two things about the reveal transaction:

    1. ``OP_REFOUTPUTCOUNT_OUTPUTS == 0`` — the reveal must not carry the base
       ref forward into any output, so the authorisation is consumed rather
       than inherited by the minted token.
    2. the reveal has exactly ONE output whose code-script hash equals
       ``HASH256(OP_REQUIREINPUTREF || base_ref || OP_RETURN "del")`` — i.e. the
       burn output of :func:`build_delegate_burn_script` is present, exactly
       once. The script rebuilds that hash on the stack with ``OP_CAT`` rather
       than trusting a value from the scriptSig, so the unlocking side cannot
       influence which output satisfies it.
    """
    return (
        b"\xd0"  # OP_PUSHINPUTREF
        + delegate_ref.to_bytes()  # <base_ref>, bare 36-byte operand
        + b"\x76"  # OP_DUP
        + b"\xde"  # OP_REFOUTPUTCOUNT_OUTPUTS
        + b"\x00"  # OP_0
        + b"\x9d"  # OP_NUMEQUALVERIFY      -> base ref appears in 0 outputs
        + b"\x01\xd1"  # PUSH 1 <0xd1>          -> the burn script's first byte
        + b"\x7c"  # OP_SWAP                -> [0xd1, base_ref]
        + b"\x05\x6a\x03\x64\x65\x6c"  # PUSH 5 <OP_RETURN "del">
        + b"\x7e"  # OP_CAT                 -> [0xd1, base_ref||6a0364656c]
        + b"\x7e"  # OP_CAT                 -> [the whole burn script]
        + b"\xaa"  # OP_HASH256
        + b"\xe6"  # OP_CODESCRIPTHASHOUTPUTCOUNT_OUTPUTS
        + b"\x51"  # OP_1
        + b"\x9d"  # OP_NUMEQUALVERIFY      -> exactly one burn output
    )


def split_delegate_commit_prefix(script: bytes) -> tuple[GlyphRef | None, bytes]:
    """Split a commit script into ``(delegate_ref, core_script)``.

    A commit output built with ``delegate_ref`` is the ordinary 75-byte commit
    script behind the 56-byte prefix of
    :func:`build_delegate_commit_prefix`. Every classifier and extractor in this
    module works on the CORE, so each one calls this first; without it a
    delegate commit is 131 bytes with every fixed offset shifted by 56, and
    reads as "not a commit script" — which is how a mint built through the very
    feature that adds the prefix becomes invisible to the code that inspects it.

    Returns ``(None, script)`` unchanged when there is no prefix. The prefix is
    matched against its exact opcode layout (the ref being the only variable
    part), so a script that merely starts with ``0xd0`` is not mistaken for one.
    """
    if len(script) <= DELEGATE_COMMIT_PREFIX_SIZE or script[0] != 0xD0:
        return None, script
    head, core = script[:DELEGATE_COMMIT_PREFIX_SIZE], script[DELEGATE_COMMIT_PREFIX_SIZE:]
    ref_bytes = head[1 : 1 + REF_OPERAND_WIDTH]
    if head != build_delegate_commit_prefix(GlyphRef.from_bytes(ref_bytes)):
        return None, script
    return GlyphRef.from_bytes(ref_bytes), core


def extract_delegate_ref_from_commit_script(script: bytes) -> GlyphRef | None:
    """Return the delegate base ref a commit script carries, or ``None``.

    ``None`` means the commit authorises no ``in``/``by`` claim by delegation —
    not that the token has no relationships. A claim can equally be backed by
    the reveal spending the parent directly; see
    :mod:`pyrxd.glyph.relationships`.
    """
    delegate_ref, _core = split_delegate_commit_prefix(script)
    return delegate_ref


def parse_delegate_base_script(script: bytes) -> tuple[bytes, ...]:
    """Return the wire refs a delegate base script authorises, in script order.

    The counterpart of :func:`build_delegate_base_script`, and the read half of
    Photonic ``parseDelegateBaseScript`` (``script.ts:480``).

    Reads the LEADING run of ``OP_REQUIREINPUTREF <ref> OP_DROP`` pairs and
    stops at the first instruction that is not one, ignoring whatever tail
    follows — Photonic's regex ends in ``.*`` and does the same. Being stricter
    here (demanding a P2PKH tail, say) would refuse honest bases built by
    another wallet, which is a defect, not a safety measure.

    The walk goes through :func:`iter_script_ops_strict` rather than a regex or
    a byte scan, so a ``0xd1`` byte inside pushed data cannot be misread as an
    opcode. Returns ``()`` for any script that does not open with such a pair,
    including one that does not decode.
    """
    refs: list[bytes] = []
    try:
        ops = list(iter_script_ops_strict(script))
    except TruncatedScriptError:
        return ()
    i = 0
    while i + 1 < len(ops):
        op, nxt = ops[i], ops[i + 1]
        if op.opcode != 0xD1 or op.operand is None or nxt.opcode != 0x75:  # OP_REQUIREINPUTREF .. OP_DROP
            break
        refs.append(bytes(op.operand))
        i += 2
    return tuple(refs)


def parse_delegate_burn_script(script: bytes) -> bytes | None:
    """Return the base ref a delegate burn output names, or ``None``.

    The counterpart of :func:`build_delegate_burn_script`, and the read half of
    Photonic ``parseDelegateBurnScript`` (``script.ts:495``). The layout is
    fixed-width and fully anchored, so an exact byte comparison is both
    sufficient and unambiguous.
    """
    if len(script) != DELEGATE_BURN_SCRIPT_SIZE:
        return None
    if script[0] != 0xD1 or script[1 + REF_OPERAND_WIDTH :] != b"\x6a\x03del":
        return None
    return script[1 : 1 + REF_OPERAND_WIDTH]


def is_delegate_token_script(script_hex: str) -> bool:
    """Return True if *script_hex* is a 63-byte delegate token output.

    Note the shape collision this exists to resolve: a delegate token and an
    NFT singleton are both 63 bytes of ``<ref opcode> <ref> OP_DROP`` + P2PKH,
    differing only in the opcode (``0xd0`` vs ``0xd8``). Anything classifying
    chain outputs must test the opcode, not the length.
    """
    return bool(DELEGATE_TOKEN_SCRIPT_RE.fullmatch(script_hex.lower()))


# ---------------------------------------------------------------------------
# Hash
# ---------------------------------------------------------------------------


def hash_payload(cbor_bytes: bytes) -> bytes:
    """SHA256d of CBOR payload bytes (NOT including 'gly' marker)."""
    return hash256(cbor_bytes)


# ---------------------------------------------------------------------------
# Classifiers
# ---------------------------------------------------------------------------


def is_nft_script(script_hex: str) -> bool:
    """Return True if script_hex matches the NFT singleton pattern."""
    return bool(NFT_SCRIPT_RE.fullmatch(script_hex.lower()))


def is_ft_script(script_hex: str) -> bool:
    """Return True if script_hex matches the FT locking pattern."""
    return bool(FT_SCRIPT_RE.fullmatch(script_hex.lower()))


def is_legacy_container_script(script_hex: str) -> bool:
    """Return True for the 100-byte "CONTAINER with a child ref" script.

    ``d0 <child_ref:36> d8 <container_ref:36> 75 76 a9 14 <pkh:20> 88 ac``

    pyrxd 0.9.0–0.14.0 built this from
    ``GlyphBuilder.prepare_container_reveal(..., child_ref=...)``. It is not a
    working token and pyrxd no longer builds it. Two independent defects, both
    confirmed against a Radiant Core v3.1.1 regtest node
    (``tests/test_container_regtest_e2e.py``):

    1. **The output is permanently unspendable.** ``OP_PUSHINPUTREF`` pushes the
       child ref and nothing drops it, so the P2PKH tail runs ``OP_DUP
       OP_HASH160`` over the *ref* instead of the pubkey and
       ``OP_EQUALVERIFY`` can never succeed. Rejected with
       ``mandatory-script-verify-flag-failed (Script failed an OP_EQUALVERIFY
       operation)``. Whatever photons sit on the output are unrecoverable.
    2. **Creating one destroys the child NFT.** A ref pushed by
       ``OP_PUSHINPUTREFSINGLETON`` in one output may not appear in any sibling
       output (``CScript::GetPushRefs`` files a singleton into
       ``foundDisallowedSiblingRefs``), so the child cannot be re-created in the
       same transaction — and once the singleton has been consumed into a
       ``0xd0`` push it is absent from ``inputSingletonRefSet`` forever, so it
       can never be re-minted either.

    This predicate exists so a holder of such an output gets told that, rather
    than seeing ``unknown``. Membership now lives in the envelope's ``in``
    field; see :attr:`~pyrxd.glyph.types.GlyphMetadata.container_refs`.
    """
    return bool(LEGACY_CONTAINER_SCRIPT_RE.fullmatch(script_hex.lower()))


def parse_legacy_container_script(script: bytes) -> tuple[GlyphRef, GlyphRef, Hex20] | None:
    """Parse a legacy container script into ``(container_ref, child_ref, owner_pkh)``.

    Returns ``None`` if *script* is not that shape. See
    :func:`is_legacy_container_script` for why such an output is dead.
    """
    if len(script) != LEGACY_CONTAINER_SCRIPT_SIZE or not LEGACY_CONTAINER_SCRIPT_RE.fullmatch(script.hex()):
        return None
    child_ref = GlyphRef.from_bytes(script[1 : 1 + REF_OPERAND_WIDTH])
    container_ref = GlyphRef.from_bytes(script[38 : 38 + REF_OPERAND_WIDTH])
    owner_pkh = Hex20(script[78:98])
    return container_ref, child_ref, owner_pkh


def _commit_core_hex(script_hex: str) -> str:
    """The commit script's 75-byte core hex, with any delegate prefix removed.

    Returns the input unchanged if it is not hex — the caller's regex then
    fails, which is the same answer it would have given anyway.
    """
    try:
        raw = bytes.fromhex(script_hex)
    except ValueError:
        return script_hex.lower()
    _delegate_ref, core = split_delegate_commit_prefix(raw)
    return core.hex()


def is_commit_script(script_hex: str) -> bool:
    """Return True if script_hex matches either commit pattern (NFT or FT).

    Accepts the delegate-carrying form (:func:`build_delegate_commit_prefix`)
    as well as the bare 75-byte one.
    """
    return bool(COMMIT_SCRIPT_RE.fullmatch(_commit_core_hex(script_hex.lower())))


def is_commit_nft_script(script_hex: str) -> bool:
    """Return True if script_hex matches the NFT-variant commit pattern.

    Accepts the delegate-carrying form as well as the bare one.
    """
    return bool(COMMIT_SCRIPT_NFT_RE.fullmatch(_commit_core_hex(script_hex.lower())))


def is_commit_ft_script(script_hex: str) -> bool:
    """Return True if script_hex matches the FT-variant commit pattern.

    Accepts the delegate-carrying form as well as the bare one.
    """
    return bool(COMMIT_SCRIPT_FT_RE.fullmatch(_commit_core_hex(script_hex.lower())))


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
    return GlyphRef.from_bytes(script[1 : 1 + REF_OPERAND_WIDTH])


def extract_ref_from_ft_script(script: bytes) -> GlyphRef:
    """Extract 36-byte ref from a 75-byte FT script."""
    if len(script) != 75 or script[25] != 0xBD or script[26] != 0xD0:
        raise ValidationError("Not a valid FT script")
    return GlyphRef.from_bytes(script[27 : 27 + REF_OPERAND_WIDTH])


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
    """Extract 32-byte payload hash from a commit script (NFT or FT variant).

    Handles the delegate-carrying form by splitting the prefix off first; the
    offsets below index the 75-byte core.
    """
    _delegate_ref, core = split_delegate_commit_prefix(script)
    if len(core) != 75 or not COMMIT_SCRIPT_RE.match(core.hex()):
        raise ValidationError("Not a valid commit script")
    return core[2:34]


def extract_owner_pkh_from_commit_script(script: bytes) -> Hex20:
    """Extract 20-byte owner PKH from a commit script (NFT or FT variant).

    Handles the delegate-carrying form by splitting the prefix off first; the
    offsets below index the 75-byte core.
    """
    _delegate_ref, core = split_delegate_commit_prefix(script)
    if len(core) != 75 or not COMMIT_SCRIPT_RE.match(core.hex()):
        raise ValidationError("Not a valid commit script")
    return Hex20(core[53:73])


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

# Byte offset at which the ref operand starts: 1 (push32 opcode) + 32 (hash) +
# 1 (OP_DROP) + 1 (OP_STATESEPARATOR) + 1 (OP_PUSHINPUTREFSINGLETON).
# It equals REF_OPERAND_WIDTH by coincidence and must not be replaced with it —
# these two numbers move for entirely unrelated reasons, and folding a position
# into a width is precisely the kind of "same number, different meaning" merge
# that turns a tidy-up into a parser bug.
_MUTABLE_NFT_REF_OFFSET = 36  # not-a-ref-width: this is a position, not a width

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
    mutable_ref = GlyphRef.from_bytes(script[_MUTABLE_NFT_REF_OFFSET : _MUTABLE_NFT_REF_OFFSET + REF_OPERAND_WIDTH])
    return mutable_ref, payload_hash


# ---------------------------------------------------------------------------
# Input-ref opcode walker (shared primitive)
# ---------------------------------------------------------------------------
# The OP_PUSHINPUTREF family. Each of these opcodes, when it appears in an
# *opcode position* (not inside push-data), is followed by a 36-byte ref
# operand. This set is EXACTLY the one Radiant consensus follows with a 36-byte
# operand in ``GetScriptOp`` (Radiant-Core/src/script/script.cpp:710-716), and
# exactly the set ``CScript::GetPushRefs`` (:586-590) collects refs for:
#
#   0xd0  OP_PUSHINPUTREF
#   0xd1  OP_REQUIREINPUTREF
#   0xd2  OP_DISALLOWPUSHINPUTREF
#   0xd3  OP_DISALLOWPUSHINPUTREFSIBLING
#   0xd8  OP_PUSHINPUTREFSINGLETON
#
# It is NOT the contiguous range 0xd0–0xd8. The four opcodes in between —
# 0xd4 OP_REFHASHDATASUMMARY_UTXO, 0xd5 OP_REFHASHVALUESUM_UTXOS,
# 0xd6 OP_REFHASHDATASUMMARY_OUTPUT, 0xd7 OP_REFHASHVALUESUM_OUTPUTS
# (Radiant-Core/src/script/script.h:281-284) — are pure stack operations that
# take NO operand. Consuming 36 bytes after one of them desynchronizes the walk
# from consensus: depending on the byte the walk resumes on, it either raises
# ``TruncatedScriptError`` (fail-closed) or silently resynchronizes and reports
# a PHANTOM ref while dropping the real one. Since ``count_input_refs`` /
# ``is_token_bearing_script`` classify arbitrary chain scripts, that second case
# lets a token-bearing UTXO read as plain funding and be burned as a fee input.
#
# A bare-byte scan is wrong for a different reason: it cannot tell an
# opcode-position ref byte from a 0xd0–0xd8 byte sitting inside a pushed
# payload (e.g. ~51% of random P2PKH pubkey-hashes contain one); only an
# opcode-aware walk is correct. See
# docs/solutions/logic-errors/funding-utxo-byte-scan-dos.md and
# docs/solutions/logic-errors/ft-in-covenant-two-consensus-gates.md.
#
# Aliased from :data:`pyrxd.constants.REF_OPERAND_OPCODES` rather than re-spelled,
# because a SECOND walker (the BIP143 preimage's ``hashOutputHashes`` field, in
# ``pyrxd.transaction.transaction_preimage``) has to agree with this one byte for
# byte, and it once did not — it omitted 0xd1/0xd2/0xd3 and desynchronised on any
# output carrying an OP_REQUIREINPUTREF. One definition, two consumers.
REF_OPCODES = REF_OPERAND_OPCODES


class TruncatedScriptError(ValidationError):
    """A script ends mid-push or mid-ref-operand — its length is ambiguous.

    Raised by :func:`iter_input_refs`. Callers deciding whether a script is
    safe to spend/accept should treat this as token-bearing / refuse it (a
    malformed script of ambiguous length must not be admitted as funding).
    """


def iter_script_ops_strict(script: bytes):
    """Yield every :class:`~pyrxd.script.consensus.ScriptOp` in *script*,
    raising :class:`TruncatedScriptError` at the first instruction that will
    not decode.

    The byte-consumption rules — how far each opcode advances the walk, and
    which opcodes carry the fixed-width 36-byte ref operand — are **not**
    written here. They come from :func:`pyrxd.script.consensus.get_script_op`,
    the transcription of Radiant's ``GetScriptOp``. This function adds exactly
    one thing to :func:`pyrxd.script.consensus.iter_script_ops`: a malformed
    instruction is an *error* rather than a silent stop, because the callers
    here classify chain scripts for spend decisions and a script of ambiguous
    length must be refused, not truncated to whatever parsed.

    Every opcode-aware walk in this package goes through here — ref extraction
    (:func:`iter_input_refs`) and soulbound structural detection
    (:mod:`pyrxd.glyph.soulbound_detect`). Independent transcriptions of this
    loop produced the worst parser bugs in this repo (see :data:`REF_OPCODES`
    above); do not write another one.
    """
    pos = 0
    n = len(script)
    while pos < n:
        op = get_script_op(script, pos)
        if op is None:
            raise TruncatedScriptError(
                f"script does not decode at offset {pos} (truncated push, "
                f"truncated length prefix, or truncated {REF_OPERAND_WIDTH}-byte ref operand)"
            )
        yield op
        pos = op.next_pos


def iter_input_refs(script: bytes):
    """Yield ``(opcode, ref_operand)`` for each OP_PUSHINPUTREF-family opcode
    in *script*, walking it as an opcode stream the way Radiant consensus does
    (``GetScriptOp`` / ``CScript::GetPushRefs``).

    Push opcodes consume their payload, so a ref-range byte inside push-data is
    never mistaken for an opcode. Each ``ref_operand`` is the 36 bytes
    following the opcode. Only :data:`REF_OPCODES` carry an operand — the
    REFHASH* opcodes ``0xd4``–``0xd7`` sit in the same byte range but are
    operand-less stack operations and must advance the walk by one byte.

    Raises :class:`TruncatedScriptError` if the script ends mid-push or a ref
    opcode's 36-byte operand is truncated — the script's structure is
    ambiguous and callers should refuse it.

    A thin filter over :func:`iter_script_ops_strict`, which owns the walk.
    This is the single source of truth for ref detection; build
    :func:`count_input_refs` and ``is_token_bearing_script`` on it rather than
    re-implementing the walk.
    """
    for op in iter_script_ops_strict(script):
        if op.opcode in REF_OPCODES:
            yield op.opcode, op.operand


def count_input_refs(script: bytes) -> dict[bytes, int]:
    """Return a map of ``ref_operand -> count`` for every OP_PUSHINPUTREF-family
    opcode in *script* (opcode-aware; see :func:`iter_input_refs`).

    Use this to assert a covenant scriptPubKey carries *exactly* the refs you
    intend before broadcasting — a phantom ref (a 0xd0/0xd8 byte mis-parsed
    from embedded data) shows up here as an unexpected key. Raises
    :class:`TruncatedScriptError` on a malformed script.
    """
    counts: dict[bytes, int] = {}
    for _op, operand in iter_input_refs(script):
        counts[operand] = counts.get(operand, 0) + 1
    return counts
