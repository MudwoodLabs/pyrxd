"""Radiant HTLC covenant builders (FT / NFT / RXD) for the Gravity atomic swap.

Productizes the mainnet-proven spike (``docs/brainstorms/gravity-ref-spike/
build_htlc_covenant_spk.py``) into house style: frozen result dataclass,
``ValidationError`` (never ``assert`` in ``src/``), and BOTH static guards run
fail-closed at build time. The compiled artifact templates
(``GravityHtlcCovenant{Ft,Nft,Rxd}.artifact.json``) are bundled under
``gravity/artifacts/`` and substituted here.

These build the FUNDED covenant scriptPubKey — the UTXO the maker locks the asset
into. The spend (claim via preimage / refund via CSV) is built by the HTLC
claim/refund TX builders; the ``RadiantLeg`` composes both.

The three variants differ in how the genesis ref binds (the consensus gate):

* **FT**  — funded SPK = ``<compiled prologue> bd d0 <ref> <FT_EPILOGUE>``. The FT
  ``codeScriptHashValueSum`` conservation lives in the appended epilogue weld
  (same shape as the shipped ``build_fused_ft_spk``); the ONLY legitimate bare
  ``0xbd`` opcode is that weld at ``len(prologue)``.
* **NFT** — funded SPK = the compiled body VERBATIM (the singleton ``d8<ref>`` is
  inside it); there must be NO bare ``0xbd`` (an FT-epilogue leak would be a bug).
* **RXD** — native RXD: NO genesis ref at all, NO ``d0/d8`` prologue, NO epilogue.
  There must be NO ref ops and NO bare ``0xbd``.

Holder scripts (what ``output[0]`` of a claim/refund must equal — the covenant
pins ``hash256(holder script)``):

* FT  → 75-byte FT holder ``p2pkh + bd d0 <ref> <FT_EPILOGUE>``
* NFT → 63-byte NFT singleton ``d8 <ref> 75 + p2pkh``
* RXD → 25-byte plain P2PKH

``refundCsv`` AND the asset value param (``amount`` / ``nftCarrierValue``) MUST be
minimal-pushed (``OP_1..OP_16`` for 1..16) — a non-minimal push trips MANDATORY
``MINIMALDATA`` and bricks the covenant on BOTH the claim and refund branches
(spike ``.csv_spike.json`` for ``refundCsv``; round-5 finding F-001 for the value
param). The build-time ``_assert_minimal_pushes`` guard re-checks EVERY push in the
assembled funded SPK fail-closed, so a future non-minimal push fails at build time
rather than silently on-chain.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from pyrxd.constants import REF_OPERAND_WIDTH
from pyrxd.glyph.script import REF_OPCODES, count_input_refs
from pyrxd.glyph.types import GlyphRef
from pyrxd.hash import hash256
from pyrxd.script.consensus import has_valid_ops
from pyrxd.security.errors import ValidationError
from pyrxd.security.types import Hex20
from pyrxd.utils import decode_script_num, encode_data_push, encode_int, encode_script_num

__all__ = [
    "FT_EPILOGUE",
    "HtlcCovenant",
    "build_htlc_covenant_ft",
    "build_htlc_covenant_nft",
    "build_htlc_covenant_rxd",
    "holder_hash",
]

# The FT codeScriptHashValueSum epilogue weld (post-compile), identical to the
# shipped fused-FT covenant. Its presence as the sole bare-0xbd is guard-checked.
FT_EPILOGUE = bytes.fromhex("dec0e9aa76e378e4a269e69d")

_ARTIFACTS_DIR = Path(__file__).parent / "artifacts"

# Ref-carrying opcodes (consume a 36-byte operand): d0/d1/d2/d3/d8. Aliased to
# the shared constant so this walk cannot drift from the consensus set.
_REF_OPS = REF_OPCODES


@dataclass(frozen=True)
class HtlcCovenant:
    """A built HTLC covenant: the funded SPK + the bindings a spend must satisfy.

    Attributes
    ----------
    variant:
        "ft" | "nft" | "rxd".
    funded_spk:
        The scriptPubKey of the covenant UTXO the maker locks the asset into.
    prologue_len:
        Length of the compiled body (== ``len(funded_spk)`` for NFT/RXD; the
        offset of the FT epilogue weld for FT). The bare-0xbd guard pins to this.
    taker_holder_script / maker_holder_script:
        The holder scripts ``output[0]`` of a claim (taker) / refund (maker) must
        equal; the covenant binds ``hash256`` of each.
    expected_taker_hash / expected_maker_hash:
        ``hash256(taker_holder_script)`` / ``hash256(maker_holder_script)`` — the
        values baked into the covenant.
    genesis_ref:
        The 36-byte genesis outpoint ref (FT/NFT); ``b""`` for RXD.
    hashlock:
        The 32-byte ``H = SHA256(p)``.
    refund_csv:
        The relative-timelock block count for the refund branch.
    """

    variant: str
    funded_spk: bytes
    prologue_len: int
    taker_holder_script: bytes
    maker_holder_script: bytes
    expected_taker_hash: bytes
    expected_maker_hash: bytes
    genesis_ref: bytes
    hashlock: bytes
    refund_csv: int


# --------------------------------------------------------------------------- low-level encoders


#: CScriptNum body bytes, from the one definition in :mod:`pyrxd.utils`. This was
#: a verbatim copy of it; ``tests/test_script_encoder_consolidation.py`` keeps the
#: deleted version and asserts the two agree byte-for-byte across the range.
_scriptnum = encode_script_num


def _push(b: bytes) -> bytes:
    """Length-prefixed data push (direct / OP_PUSHDATA1 / OP_PUSHDATA2).

    The 64 KB ceiling is this module's own policy and is passed explicitly. The
    ENCODER is shared; the LIMIT is not, because the other call sites genuinely
    differ — ``btc_wallet`` caps at 255, ``glyph/dmint`` does not cap at all —
    and collapsing them onto one number would have loosened a guard somewhere.
    """
    return encode_data_push(b, max_len=0xFFFF)


#: CScriptNum is capped at 8 bytes (`maxIntegerSize`); a 9-byte body is a consensus range error.
_MAX_SCRIPT_NUM = 2**63 - 1


def _minimal_num_push(n: int) -> bytes:
    """Minimal CScriptNum push (MANDATORY MINIMALDATA): OP_0, OP_1..OP_16, else push.

    A non-minimal push of a small int (e.g. ``0x0102`` for ``2``) trips 'Data push
    larger than necessary' and bricks the covenant — ``refundCsv`` is small so this
    is load-bearing.

    The type and sign check stays local: :func:`~pyrxd.utils.encode_int` handles
    negatives perfectly well, and it is *this* call site that must refuse them.
    """
    if not isinstance(n, int) or isinstance(n, bool) or n < 0:
        raise ValidationError("refund_csv must be a non-negative int")
    if n > _MAX_SCRIPT_NUM:
        # `maxIntegerSize` is 8 bytes; a 9-byte body raises INVALID_NUMBER_RANGE_64_BIT on BOTH
        # branches, which stalls the asset permanently. Not reachable through the leg (chain supply
        # is far below this) but reachable by any direct caller with a units slip — and the cost of
        # that slip is the same permanent strand.
        raise ValidationError(f"script number {n} exceeds the 8-byte CScriptNum range ({_MAX_SCRIPT_NUM})")
    # ROUND-TRIP the NUMBER body, because push minimality and NUMBER minimality are two different
    # consensus rules
    # and this operand is subject to both. `CheckMinimalPush` governs the push opcode; a body is
    # separately re-checked by `CScriptNum::IsMinimallyEncoded` wherever it is consumed
    # numerically — under SCRIPT_VERIFY_MINIMALDATA, which is a BLOCK flag, so a violation is not
    # even miner-recoverable. A fixed-width encoding (`02 05 00` for 5, or 8-byte LE) satisfies the
    # first rule and fails the second, bricking both branches. GUARD 3 audits only the first, and
    # cannot audit the second once the script is assembled because it can no longer tell a numeric
    # operand from a 32-byte hash. Checking here, where the type IS known, is the reliable place.
    body = encode_script_num(n)
    # `decode(encode(n)) == n`, NOT `encode(decode(body)) == body`. The latter is a TAUTOLOGY —
    # `encode_script_num` is canonical by construction, so re-encoding its own output can never
    # differ, and the check could not fail for any input. (Verified by sweeping 0..300 plus the
    # 2**31 / 2**62 / 2**63-1 edges: zero values where it differs.) That is the same defect as the
    # script-level gate removed in the sibling commit, written into its replacement.
    #
    # This form can fail: it catches an encoder or decoder that disagree about a value, which is
    # the actual hazard — a mis-encoded operand bricks both covenant branches permanently.
    if len(body) > 8 or decode_script_num(body) != n:
        raise ValidationError(
            f"script number {n} does not have a minimal CScriptNum body (got {body.hex()}); a "
            "non-minimal body trips CScriptNum::IsMinimallyEncoded and permanently bricks the "
            "covenant on BOTH branches"
        )
    return encode_int(n)


_hash256 = hash256  # SHA-256d, from the one definition in pyrxd.hash


# --------------------------------------------------------------------------- holder scripts


def _ft_holder_script(pkh: bytes, ref_wire: bytes) -> bytes:
    return b"\x76\xa9\x14" + pkh + b"\x88\xac\xbd\xd0" + ref_wire + FT_EPILOGUE


def _nft_holder_script(pkh: bytes, ref_wire: bytes) -> bytes:
    return b"\xd8" + ref_wire + b"\x75\x76\xa9\x14" + pkh + b"\x88\xac"


def _rxd_holder_script(pkh: bytes) -> bytes:
    return b"\x76\xa9\x14" + pkh + b"\x88\xac"


def holder_hash(pkh: bytes, *, variant: str, genesis_ref: bytes = b"") -> bytes:
    """``hash256`` of the holder script the covenant pins for ``pkh``.

    The covenant binds ``hash256(holder_script)`` of its claim/refund destination
    (``expected_taker_hash`` / ``expected_maker_hash``). Recompute that hash for an
    arbitrary owner pkh — used to confirm a swap's pinned destination
    (``taker_dest_hash``) really pays a given party (e.g. a verified credential's
    owner), without trusting a separate pkh field.

    ``genesis_ref`` (36-byte wire) is required for ``ft``/``nft`` (the holder
    carries the asset's singleton/ref); ignored for ``rxd``.
    """
    if variant == "rxd":
        return _hash256(_rxd_holder_script(pkh))
    if len(genesis_ref) != REF_OPERAND_WIDTH:
        raise ValidationError(f"{variant} holder hash requires a {REF_OPERAND_WIDTH}-byte genesis_ref")
    if variant == "ft":
        return _hash256(_ft_holder_script(pkh, genesis_ref))
    if variant == "nft":
        return _hash256(_nft_holder_script(pkh, genesis_ref))
    raise ValidationError(f"unknown asset variant {variant!r} (expected rxd|ft|nft)")


# --------------------------------------------------------------------------- static guards


def _opcode_bd_positions(spk: bytes) -> list[int]:
    """Walk ``spk`` as an opcode stream; return every position holding a bare 0xbd.

    A 0xbd that lands in an opcode position (not inside a push operand) is the FT
    ``codeScriptHash`` boundary opcode. We must know exactly where the legitimate
    ones are: FT has one (the epilogue weld); NFT/RXD have none. A stray 0xbd inside
    the new sha256/CSV prologue would silently move the boundary and break L2
    conservation — so this walk is a fail-closed structural check, not cosmetic.
    """
    i = 0
    bds: list[int] = []
    n = len(spk)
    while i < n:
        op = spk[i]
        if op == 0xBD:
            bds.append(i)
        if op in _REF_OPS:
            i += 1 + REF_OPERAND_WIDTH  # 1 opcode + its fixed-width ref operand
            continue
        if 0x01 <= op <= 0x4B:
            i += 1 + op
            continue
        if op == 0x4C:  # OP_PUSHDATA1
            if i + 1 >= n:
                break
            i += 2 + spk[i + 1]
            continue
        if op == 0x4D:  # OP_PUSHDATA2
            if i + 2 >= n:
                break
            i += 3 + (spk[i + 1] | (spk[i + 2] << 8))
            continue
        if op == 0x4E:  # OP_PUSHDATA4
            if i + 4 >= n:
                break
            i += 5 + int.from_bytes(spk[i + 1 : i + 5], "little")
            continue
        i += 1
    return bds


def _guard_bd(funded_spk: bytes, *, expected: list[int], variant: str) -> None:
    bds = _opcode_bd_positions(funded_spk)
    if bds != expected:
        raise ValidationError(
            f"GUARD 1 FAIL ({variant}): bare-0xbd opcode positions {bds} != expected {expected} "
            "(an FT-epilogue leak or a misplaced boundary opcode would break L2 conservation)"
        )


def _guard_refs(funded_spk: bytes, *, expected_ref: bytes | None, variant: str) -> None:
    refs = set(count_input_refs(funded_spk).keys())
    expected = {expected_ref} if expected_ref is not None else set()
    if refs != expected:
        got = sorted(r.hex() for r in refs)
        want = sorted(r.hex() for r in expected)
        raise ValidationError(
            f"GUARD 2 FAIL ({variant}): input refs {got} != expected {want} "
            "(exactly the genesis ref must bind — no phantom, no missing ref)"
        )


def _assert_minimal_pushes(spk: bytes, *, variant: str) -> None:
    """GUARD 3: fail-closed if any data push in ``spk`` violates MANDATORY ``MINIMALDATA``.

    Radiant/Bitcoin enforce ``CheckMinimalPush`` on every executed push: a
    non-minimal push of a small value — e.g. a 1-byte ``0x05`` instead of ``OP_5``
    — trips 'Data push larger than necessary' and PERMANENTLY bricks the covenant
    on BOTH the claim and refund branches (round-5 finding F-001: the value param
    ``amount`` / ``nftCarrierValue`` was pushed non-minimally for values 1..16).
    This walks the WHOLE assembled funded SPK — not just one operand — so any
    non-minimal push fails at build time instead of silently on-chain. Mirrors
    Radiant-Core ``script.cpp`` ``CheckMinimalPush``. Ref operands (``d0/d8`` etc.)
    are 36-byte ref payloads, not data pushes, and are skipped.

    Runs ``HasValidOps`` first. That is a *different* question — minimality is
    about whether a push is the shortest form, ``HasValidOps`` is about whether
    the bytes decode into instructions at all — and answering the second one
    before the first matters, because a script that does not decode makes the
    minimality walk's own offsets meaningless. Both are fail-closed at build
    time: an SPK Radiant would refuse structurally must not become the
    scriptPubKey of a UTXO holding an asset.
    """
    if not has_valid_ops(spk):
        raise ValidationError(
            f"GUARD 3 FAIL ({variant}): assembled SPK is not structurally valid "
            "(CScript::HasValidOps) — it contains a byte above MAX_OPCODE, an "
            "oversized push, or an instruction whose operand runs off the end. "
            "Radiant would reject it, so the asset would be locked into a script "
            "no spend can satisfy."
        )
    i = 0
    n = len(spk)
    while i < n:
        op = spk[i]
        if op in _REF_OPS:
            i += 1 + REF_OPERAND_WIDTH  # ref opcode + its fixed-width operand (not a data push)
            continue
        if 0x01 <= op <= 0x4B:  # direct push of `op` bytes
            if i + 1 + op > n:
                raise ValidationError(f"GUARD 3 FAIL ({variant}): truncated direct push at offset {i}")
            if op == 1:
                b0 = spk[i + 1]
                if 1 <= b0 <= 16 or b0 == 0x81:
                    raise ValidationError(
                        f"GUARD 3 FAIL ({variant}): non-minimal 1-byte push 0x{b0:02x} at offset {i} "
                        "(must be OP_1..OP_16 / OP_1NEGATE) — would brick the covenant (MINIMALDATA)"
                    )
            i += 1 + op
            continue
        if op == 0x4C:  # OP_PUSHDATA1
            if i + 1 >= n:
                raise ValidationError(f"GUARD 3 FAIL ({variant}): truncated PUSHDATA1 at offset {i}")
            size = spk[i + 1]
            if size <= 75:
                raise ValidationError(
                    f"GUARD 3 FAIL ({variant}): PUSHDATA1 of {size} bytes at offset {i} "
                    "(<=75 must be a direct push) — non-minimal (MINIMALDATA)"
                )
            i += 2 + size
            continue
        if op == 0x4D:  # OP_PUSHDATA2
            if i + 2 >= n:
                raise ValidationError(f"GUARD 3 FAIL ({variant}): truncated PUSHDATA2 at offset {i}")
            size = spk[i + 1] | (spk[i + 2] << 8)
            if size <= 255:
                raise ValidationError(
                    f"GUARD 3 FAIL ({variant}): PUSHDATA2 of {size} bytes at offset {i} "
                    "(<=255 must be OP_PUSHDATA1) — non-minimal (MINIMALDATA)"
                )
            i += 3 + size
            continue
        if op == 0x4E:  # OP_PUSHDATA4
            if i + 4 >= n:
                raise ValidationError(f"GUARD 3 FAIL ({variant}): truncated PUSHDATA4 at offset {i}")
            size = int.from_bytes(spk[i + 1 : i + 5], "little")
            if size <= 0xFFFF:
                raise ValidationError(
                    f"GUARD 3 FAIL ({variant}): PUSHDATA4 of {size} bytes at offset {i} "
                    "(<=65535 must be OP_PUSHDATA2) — non-minimal (MINIMALDATA)"
                )
            i += 5 + size
            continue
        i += 1


# --------------------------------------------------------------------------- artifact loading


def _load_template(name: str) -> str:
    """Load a bundled HTLC artifact template's hex by stem name (path-guarded)."""
    path = (_ARTIFACTS_DIR / f"{name}.artifact.json").resolve()
    artifacts_root = _ARTIFACTS_DIR.resolve()
    if not str(path).startswith(str(artifacts_root) + "/"):
        raise ValidationError(f"artifact name {name!r} resolves outside the bundled artifacts directory")
    if not path.exists():
        raise FileNotFoundError(f"HTLC artifact {name!r} not bundled")
    hex_str = json.loads(path.read_text()).get("hex")
    if not isinstance(hex_str, str):
        raise ValidationError(f"artifact {name!r} has no 'hex' string")
    return hex_str


def _substitute(template_hex: str, subs: dict[str, bytes], *, variant: str) -> bytes:
    spk_hex = template_hex
    for name, value in subs.items():
        spk_hex = spk_hex.replace(f"<{name}>", value.hex())
    if "<" in spk_hex:
        unfilled = spk_hex[spk_hex.index("<") :][:40]
        raise ValidationError(f"unfilled covenant placeholder ({variant}): {unfilled}")
    return bytes.fromhex(spk_hex)


# --------------------------------------------------------------------------- validation helpers


def _validate_common(
    hashlock: bytes, refund_csv: int, taker_pkh: bytes, maker_pkh: bytes
) -> tuple[bytes, bytes, bytes]:
    if not isinstance(hashlock, (bytes, bytearray)) or len(hashlock) != 32:
        raise ValidationError("hashlock must be 32 bytes (H = SHA256(p))")
    if not isinstance(refund_csv, int) or isinstance(refund_csv, bool) or refund_csv < 1:
        raise ValidationError("refund_csv must be a positive int (a 0 CSV is a no-op timelock)")
    # F-002: refund_csv is the BIP68 relative-BLOCK count — it is both the covenant
    # CSV operand and the refund spend's nSequence (low 16 bits). A value > 0xFFFF
    # would not round-trip through nSequence (the block count is masked to 16 bits),
    # silently producing a different on-chain timelock than the covenant pins.
    if refund_csv > 0xFFFF:
        raise ValidationError("refund_csv must fit in 16 bits (BIP68 block count <= 0xFFFF)")
    tp = bytes(Hex20(taker_pkh))
    mp = bytes(Hex20(maker_pkh))
    return bytes(hashlock), tp, mp


def _ref_wire(genesis_txid: str, genesis_vout: int) -> bytes:
    return GlyphRef(txid=genesis_txid, vout=genesis_vout).to_bytes()


# --------------------------------------------------------------------------- builders


def build_htlc_covenant_ft(
    *,
    genesis_txid: str,
    genesis_vout: int,
    amount: int,
    taker_pkh: bytes,
    maker_pkh: bytes,
    hashlock: bytes,
    refund_csv: int,
) -> HtlcCovenant:
    """Build the FT-variant HTLC covenant (genesis ref bound via the FT epilogue weld)."""
    h, tp, mp = _validate_common(hashlock, refund_csv, taker_pkh, maker_pkh)
    if not isinstance(amount, int) or isinstance(amount, bool) or amount <= 0:
        raise ValidationError("FT amount must be a positive int")
    ref = _ref_wire(genesis_txid, genesis_vout)
    taker_holder = _ft_holder_script(tp, ref)
    maker_holder = _ft_holder_script(mp, ref)
    et, em = _hash256(taker_holder), _hash256(maker_holder)
    prologue = _substitute(
        _load_template("GravityHtlcCovenantFt"),
        {
            "REF": ref,
            "hashlock": _push(h),
            "refundCsv": _minimal_num_push(refund_csv),
            "amount": _minimal_num_push(amount),
            "expectedTakerFtHash": _push(et),
            "expectedMakerFtHash": _push(em),
        },
        variant="ft",
    )
    funded = prologue + b"\xbd\xd0" + ref + FT_EPILOGUE
    _guard_bd(funded, expected=[len(prologue)], variant="ft")
    _guard_refs(funded, expected_ref=ref, variant="ft")
    _assert_minimal_pushes(funded, variant="ft")
    return HtlcCovenant(
        variant="ft",
        funded_spk=funded,
        prologue_len=len(prologue),
        taker_holder_script=taker_holder,
        maker_holder_script=maker_holder,
        expected_taker_hash=et,
        expected_maker_hash=em,
        genesis_ref=ref,
        hashlock=h,
        refund_csv=refund_csv,
    )


def build_htlc_covenant_nft(
    *,
    genesis_txid: str,
    genesis_vout: int,
    nft_carrier_value: int,
    taker_pkh: bytes,
    maker_pkh: bytes,
    hashlock: bytes,
    refund_csv: int,
) -> HtlcCovenant:
    """Build the NFT-variant HTLC covenant (singleton ``d8<ref>`` inside the body)."""
    h, tp, mp = _validate_common(hashlock, refund_csv, taker_pkh, maker_pkh)
    if not isinstance(nft_carrier_value, int) or isinstance(nft_carrier_value, bool) or nft_carrier_value <= 0:
        raise ValidationError("nft_carrier_value must be a positive int")
    ref = _ref_wire(genesis_txid, genesis_vout)
    taker_holder = _nft_holder_script(tp, ref)
    maker_holder = _nft_holder_script(mp, ref)
    et, em = _hash256(taker_holder), _hash256(maker_holder)
    funded = _substitute(
        _load_template("GravityHtlcCovenantNft"),
        {
            "REF": ref,
            "hashlock": _push(h),
            "refundCsv": _minimal_num_push(refund_csv),
            "nftCarrierValue": _minimal_num_push(nft_carrier_value),
            "expectedTakerNftHash": _push(et),
            "expectedMakerNftHash": _push(em),
        },
        variant="nft",
    )
    # NFT funded UTXO IS the compiled script verbatim — no FT epilogue, no bare 0xbd.
    _guard_bd(funded, expected=[], variant="nft")
    _guard_refs(funded, expected_ref=ref, variant="nft")
    _assert_minimal_pushes(funded, variant="nft")
    return HtlcCovenant(
        variant="nft",
        funded_spk=funded,
        prologue_len=len(funded),
        taker_holder_script=taker_holder,
        maker_holder_script=maker_holder,
        expected_taker_hash=et,
        expected_maker_hash=em,
        genesis_ref=ref,
        hashlock=h,
        refund_csv=refund_csv,
    )


def build_htlc_covenant_rxd(
    *,
    amount: int,
    taker_pkh: bytes,
    maker_pkh: bytes,
    hashlock: bytes,
    refund_csv: int,
) -> HtlcCovenant:
    """Build the RXD-variant HTLC covenant (native RXD: NO genesis ref, NO ref ops)."""
    h, tp, mp = _validate_common(hashlock, refund_csv, taker_pkh, maker_pkh)
    if not isinstance(amount, int) or isinstance(amount, bool) or amount <= 0:
        raise ValidationError("RXD amount must be a positive int")
    taker_holder = _rxd_holder_script(tp)
    maker_holder = _rxd_holder_script(mp)
    et, em = _hash256(taker_holder), _hash256(maker_holder)
    funded = _substitute(
        _load_template("GravityHtlcCovenantRxd"),
        {
            "hashlock": _push(h),
            "refundCsv": _minimal_num_push(refund_csv),
            "amount": _minimal_num_push(amount),
            "expectedTakerHash": _push(et),
            "expectedMakerHash": _push(em),
        },
        variant="rxd",
    )
    # Native RXD: NO ref op and NO FT epilogue — there must be NO bare 0xbd and NO refs.
    _guard_bd(funded, expected=[], variant="rxd")
    _guard_refs(funded, expected_ref=None, variant="rxd")
    _assert_minimal_pushes(funded, variant="rxd")
    return HtlcCovenant(
        variant="rxd",
        funded_spk=funded,
        prologue_len=len(funded),
        taker_holder_script=taker_holder,
        maker_holder_script=maker_holder,
        expected_taker_hash=et,
        expected_maker_hash=em,
        genesis_ref=b"",
        hashlock=h,
        refund_csv=refund_csv,
    )
