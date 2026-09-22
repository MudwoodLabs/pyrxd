"""dMint DAA resync to canonical Photonic (ASERT-v2 / LWMA-v2) — byte-match, frozen legacy,
generation detection, no-brick, mint-builder byte-verify, defaults and payload keys.

WHAT CHANGED AND WHY (2026-09-16)
---------------------------------
pyrxd byte-matched Photonic's dMint V2 covenant on 2026-06-16 (#228–#238). Upstream then
replaced the ASERT retarget with a fractional fixed-point formula on 2026-06-19 (Photonic
``ed53cd41``) and the LWMA retarget with the same damped formula on 2026-06-20 (``c90e6506``).
pyrxd did not follow, so for three months its ASERT/LWMA deploys carried bytecode a Photonic
miner would not recognise, and its default half-life (3600) was not the value Photonic's
Mint UI and miner assume when a deploy omits it (240). This file guards the resync:

* **Golden byte-match** — an INDEPENDENT transcription of ``buildAsertDaaBytecode`` /
  ``buildLinearDaaBytecode`` (hex-string arrays copied from ``packages/lib/src/script.ts``
  at Photonic commit ``becf41a731e78ab98fdd88652527d7dda12784c6``, plus a port of its
  ``pushMinimal``) must equal what pyrxd's builders emit, across half-lives that hit every
  minimal-push edge (1..16 are single opcodes; 128/255/256/32767/32768/65535/65536 change
  payload width or need a sign byte). Two vectors are typed out by hand as literal hex so
  the match does not route through the port at all.
* **Legacy frozen** — the pre-resync builders' bytes, pinned to what ``origin/main`` emitted
  on 2026-09-16 BEFORE this change (captured by running that tree). A covenant's bytecode
  is immutable; "fixing" these makes every contract deployed under them unmineable by
  pyrxd and repairs nothing on chain.
* **Detection** — every legacy and v2 fragment is classified from the code bytes; a
  contract matching neither is REPORTED (``UnrecognizedDaaBytecodeError``), not guessed
  (the Radiant-Core fork this was ported from classified anything without the v2
  signature as legacy: ``_asert_version_of_code`` was ``return 2 if sig else 1``).
* **No-brick** — legacy ASERT and legacy LWMA contracts (both LWMA variants, including the
  2026-06-16 pre-floor bytecode of the mainnet deploy ``dea3beb9…``) are detected as legacy
  and the PRODUCTION mint builder recomputes their target with the legacy formula, on inputs
  where legacy and v2 give different answers. The mainnet LWMA deploy is anchored to the
  CHAIN: its vout[0] script (fetched from a Radiant mainnet node on 2026-09-16) and the
  vout[0] script of its on-chain mint ``e7b52f16…`` are pinned, and ``build_dmint_mint_tx``
  on the deploy UTXO at that mint's nLockTime must recreate the mint's script byte-for-byte.
* **Mint-builder byte-verify** — the supplied ``half_life`` is checked against the bytecode
  baked into the contract for BOTH generations, before any PoW grind; the honest path passes.
* **Defaults** — ``half_life`` defaults to 240 (``DEFAULT_ASERT_HALFLIFE``) everywhere it used
  to be 3600: ``DmintDeployParams``, ``DmintV2DeployParams``, ``build_dmint_mint_tx``,
  ``_build_part_b``, and both CLI ``--half-life`` options.
* **Payload keys** — ``DmintCborPayload`` mirrors Photonic ``DmintPayload`` (``types.ts`` at the
  same commit): ``asymptote``, ``epochLength``, ``maxAdjustment``, ``schedule`` are emitted only
  when set, so payloads that do not set them are byte-identical to before.

Every assertion here was planted against (the defect it names was reintroduced, the test
failed, the plant was removed) before this file was committed.
"""

from __future__ import annotations

import inspect
import time

import pytest

from pyrxd.glyph.builder import DmintV2DeployParams, GlyphBuilder
from pyrxd.glyph.dmint import (
    ASERT_V2_DRIFT_CLAMP,
    ASERT_V2_MAX_TARGET_DIV4,
    ASERT_V2_RADIX,
    DAA_MODES_READING_DEPLOY_LAST_TIME,
    DAA_MODES_READING_LAST_TIME,
    DEFAULT_ASERT_HALFLIFE,
    MAX_SHA256D_TARGET,
    DaaBytecodeVersion,
    DaaMode,
    DmintAlgo,
    DmintCborPayload,
    DmintContractUtxo,
    DmintDeployParams,
    DmintMinerFundingUtxo,
    DmintState,
    build_dmint_code_script,
    build_dmint_contract_script,
    build_dmint_mint_tx,
    compute_next_target_asert,
    compute_next_target_asert_legacy,
    compute_next_target_asert_v2,
    compute_next_target_linear,
    compute_next_target_linear_legacy,
    compute_next_target_linear_v2,
    detect_contract_daa_bytecode,
    detect_daa_bytecode,
    is_minimal_4byte_scriptnum,
    is_readable_last_time,
)
from pyrxd.glyph.dmint.builders import (
    _DAA_BODY_OFFSET_IN_CODE,
    _PART_A,
    _PART_B1,
    _PART_B2,
    _PART_B4,
    _V2_EXCESS_PREAMBLE,
    _build_asert_daa_legacy,
    _build_asert_daa_v2,
    _build_linear_daa_legacy,
    _build_linear_daa_legacy_prefloor,
    _build_linear_daa_v2,
    _build_part_b,
    _build_part_c,
    _daa_bytes_for,
    _middle_literal,
    _push_minimal,
    build_dmint_state_script,
)
from pyrxd.glyph.dmint.types import _OP_STATESEPARATOR
from pyrxd.glyph.types import GlyphMetadata, GlyphProtocol, GlyphRef
from pyrxd.security.errors import UnrecognizedDaaBytecodeError, ValidationError
from pyrxd.security.types import Hex20

#: Radiant-Core/Photonic-Wallet commit the transcriptions below were copied from. The on-disk
#: sources were sha256-verified against raw.githubusercontent.com at this commit before use.
PHOTONIC_SHA = "becf41a731e78ab98fdd88652527d7dda12784c6"

_CONTRACT_REF = GlyphRef.from_bytes(bytes.fromhex("aa" * 36))
_TOKEN_REF = GlyphRef.from_bytes(bytes.fromhex("bb" * 36))
_LAST = 1_700_000_000
_MAX = MAX_SHA256D_TARGET


# ═══════════════════════════════════════════════════════════════════════════════
# An independent transcription of the Photonic builders (script.ts @ PHOTONIC_SHA)
# ═══════════════════════════════════════════════════════════════════════════════


def _photonic_push_minimal(n: int) -> str:
    """Port of script.ts ``pushMinimal`` (+ libauth ``bigIntToVmNumber``/``encodeDataPush``).

    Written from the TypeScript, NOT imported from pyrxd, so a shared encoding bug cannot
    make the two sides agree by construction.
    """
    if n == 0:
        return "00"
    if n == -1:
        return "4f"
    if 1 <= n <= 16:
        return f"{0x50 + n:02x}"
    negative = n < 0
    magnitude = -n if negative else n
    out = bytearray()
    while magnitude:
        out.append(magnitude & 0xFF)
        magnitude >>= 8
    if out[-1] & 0x80:
        out.append(0x80 if negative else 0x00)
    elif negative:
        out[-1] |= 0x80
    assert len(out) < 0x4C, "encodeDataPush direct-push branch"
    return f"{len(out):02x}" + out.hex()


_ASERT_V2_RADIX_TS = 65536  # script.ts: const ASERT_V2_RADIX = 65536n
_ASERT_V2_DRIFT_CLAMP_TS = _ASERT_V2_RADIX_TS >> 2  # script.ts: ASERT_V2_RADIX >> 2n = 16384
_PUSH_QUARTER_MAX_TARGET_TS = "08ffffffffffffff1f"  # script.ts: const PUSH_QUARTER_MAX_TARGET


def _photonic_build_asert_daa_bytecode(half_life: int) -> str:
    """Verbatim array from ``buildAsertDaaBytecode`` (script.ts @ PHOTONIC_SHA), joined."""
    half_life_push = _photonic_push_minimal(half_life)
    radix_push = _photonic_push_minimal(_ASERT_V2_RADIX_TS)  # "03000001"
    clamp_push = _photonic_push_minimal(_ASERT_V2_DRIFT_CLAMP_TS)  # 16384
    neg_clamp_push = _photonic_push_minimal(-_ASERT_V2_DRIFT_CLAMP_TS)  # -16384
    return "".join(
        [
            "c5",  # OP_TXLOCKTIME → currentTime
            "5279",  # OP_2 PICK lastTime
            "94",  # OP_SUB → timeDelta
            "5379",  # OP_3 PICK targetTime
            "94",  # OP_SUB → excess
            radix_push,  # push RADIX
            "95",  # OP_MUL → excess * RADIX
            half_life_push,  # push halfLife
            "96",  # OP_DIV → driftFp
            clamp_push,  # push +16384
            "a3",  # OP_MIN
            neg_clamp_push,  # push -16384
            "a4",  # OP_MAX
            "7c",  # OP_SWAP
            _PUSH_QUARTER_MAX_TARGET_TS,  # push MAX_TARGET/4
            "a3",  # OP_MIN → t
            "76",  # OP_DUP t
            radix_push,  # push RADIX
            "96",  # OP_DIV → t / RADIX
            "7b",  # OP_ROT
            "95",  # OP_MUL → delta
            "93",  # OP_ADD → newTarget
            _PUSH_QUARTER_MAX_TARGET_TS,  # push MAX_TARGET/4
            "a3",  # OP_MIN
            "76519f",  # DUP OP_1 LT
            "63",  # IF
            "7551",  #   DROP, push 1
            "68",  # ENDIF
        ]
    )


def _photonic_build_linear_daa_bytecode() -> str:
    """Verbatim array from ``buildLinearDaaBytecode`` (script.ts @ PHOTONIC_SHA), joined."""
    radix_push = _photonic_push_minimal(_ASERT_V2_RADIX_TS)
    clamp_push = _photonic_push_minimal(_ASERT_V2_DRIFT_CLAMP_TS)
    neg_clamp_push = _photonic_push_minimal(-_ASERT_V2_DRIFT_CLAMP_TS)
    return "".join(
        [
            "c5",
            "5279",
            "94",
            "5379",
            "94",
            radix_push,
            "95",
            "5379",  # OP_3 PICK targetTime  (the gain divisor — distinguishes LWMA from ASERT)
            "96",
            clamp_push,
            "a3",
            neg_clamp_push,
            "a4",
            "7c",
            _PUSH_QUARTER_MAX_TARGET_TS,
            "a3",
            "76",
            radix_push,
            "96",
            "7b",
            "95",
            "93",
            _PUSH_QUARTER_MAX_TARGET_TS,
            "a3",
            "76519f",
            "63",
            "7551",
            "68",
        ]
    )


#: Typed by hand from the script.ts arrays (NOT produced by the port above): halfLife 240 →
#: pushMinimal = 02 f0 00 (0xF0 needs a sign byte), RADIX → 03 00 00 01, clamps 02 00 40 /
#: 02 00 c0. If the port and the builder shared a bug, these two literals would still catch it.
_ASERT_V2_HL240_HEX = (
    "c5527994537994"  # excess preamble
    "0300000195"  # <RADIX> OP_MUL
    "02f00096"  # <240> OP_DIV
    "020040a3"  # <16384> OP_MIN
    "0200c0a4"  # <-16384> OP_MAX
    "7c08ffffffffffffff1fa3"  # SWAP <MAX/4> OP_MIN
    "760300000196"  # DUP <RADIX> OP_DIV
    "7b9593"  # ROT MUL ADD
    "08ffffffffffffff1fa3"  # <MAX/4> OP_MIN
    "76519f637551 68".replace(" ", "")
)
_LWMA_V2_HEX = (
    "c5527994537994"
    "0300000195"
    "537996"  # OP_3 PICK OP_DIV  (gain = targetTime)
    "020040a3"
    "0200c0a4"
    "7c08ffffffffffffff1fa3"
    "760300000196"
    "7b9593"
    "08ffffffffffffff1fa3"
    "76519f63755168"
)

#: Minimal-push edge cases: 1..16 single opcodes; 17/127 one payload byte; 128/255 need a
#: sign byte; 256 two bytes; 32767/32768 two-byte boundary + sign byte; 65535/65536 three
#: bytes (65536 = RADIX itself, whose push equals the v2 discriminator's push bytes).
HALF_LIVES = [1, 2, 15, 16, 17, 127, 128, 240, 255, 256, 600, 3600, 32767, 32768, 65535, 65536, 86400, 2**31 - 1]


class TestGoldenByteMatchAgainstUpstream:
    """pyrxd's v2 builders must emit exactly what Photonic's builders emit at PHOTONIC_SHA."""

    @pytest.mark.parametrize("half_life", HALF_LIVES)
    def test_asert_v2_matches_photonic_transcription(self, half_life: int) -> None:
        assert _build_asert_daa_v2(half_life).hex() == _photonic_build_asert_daa_bytecode(half_life)

    def test_lwma_v2_matches_photonic_transcription(self) -> None:
        assert _build_linear_daa_v2().hex() == _photonic_build_linear_daa_bytecode()

    def test_asert_v2_hl240_matches_hand_typed_vector(self) -> None:
        assert _build_asert_daa_v2(240).hex() == _ASERT_V2_HL240_HEX
        assert _photonic_build_asert_daa_bytecode(240) == _ASERT_V2_HL240_HEX  # the port agrees with the literal too

    def test_lwma_v2_matches_hand_typed_vector(self) -> None:
        assert _build_linear_daa_v2().hex() == _LWMA_V2_HEX
        assert _photonic_build_linear_daa_bytecode() == _LWMA_V2_HEX

    def test_constants_match_script_ts(self) -> None:
        assert ASERT_V2_RADIX == 65536
        assert ASERT_V2_DRIFT_CLAMP == 16384
        assert ASERT_V2_MAX_TARGET_DIV4 == 0x1FFFFFFFFFFFFFFF  # dmintDaaV2.ts ASERT_V2_MAX_TARGET >> 2n
        assert DEFAULT_ASERT_HALFLIFE == 240  # script.ts export const DEFAULT_ASERT_HALFLIFE = 240
        # The literal pushes the script.ts comments spell out.
        assert _photonic_push_minimal(65536) == "03000001"
        assert _photonic_push_minimal(16384) == "020040"
        assert _photonic_push_minimal(-16384) == "0200c0"

    def test_lwma_v2_is_asert_v2_with_target_time_as_gain(self) -> None:
        """script.ts: LWMA-v2 is the ASERT-v2 template with ``5379`` (OP_3 PICK targetTime)
        where ASERT pushes its half-life constant — and nothing else differs."""
        asert = _build_asert_daa_v2(240)
        lwma = _build_linear_daa_v2()
        cut = 12  # preamble(7) + RADIX push(4) + OP_MUL(1)
        assert asert[:cut] == lwma[:cut]
        assert asert[cut : cut + 3] == bytes.fromhex("02f000") and lwma[cut : cut + 2] == bytes.fromhex("5379")
        assert asert[cut + 3 :] == lwma[cut + 2 :]

    def test_v2_builder_refuses_half_life_below_one(self) -> None:
        """script.ts throws ``halfLife must be an integer >= 1``; a 0 would bake OP_DIV by zero."""
        for bad in (0, -1):
            with pytest.raises(ValidationError, match=">= 1"):
                _build_asert_daa_v2(bad)

    def test_new_deploys_route_to_v2(self) -> None:
        """The production entry point (``build_dmint_code_script``) carries the v2 fragment."""
        for mode, frag in ((DaaMode.ASERT, _build_asert_daa_v2(240)), (DaaMode.LWMA, _build_linear_daa_v2())):
            code = build_dmint_code_script(_params(mode, half_life=240))
            assert code[_DAA_BODY_OFFSET_IN_CODE : _DAA_BODY_OFFSET_IN_CODE + len(frag)] == frag
            assert _build_asert_daa_legacy(240) not in code and _build_linear_daa_legacy() not in code


# ═══════════════════════════════════════════════════════════════════════════════
# Legacy builders: FROZEN to what origin/main emitted before this change
# ═══════════════════════════════════════════════════════════════════════════════

#: Captured 2026-09-16 by running ``_build_asert_daa(h)`` on origin/main @ 8611cab (the last
#: commit before the resync) — the bytecode every pyrxd ASERT deploy from 2026-06-16 to
#: 2026-09-15 carries. The half-life push is the only variable part; the 4×2MUL/4×2DIV body
#: is constant.
_LEGACY_ASERT_BODY_HEX = (
    "7654a06375546876548f9f6375548f687600a0637600a0638c7c7608ffffffffffffff3fa0637508ffffffff"
    "ffffff7f678d687c687600a0638c7c7608ffffffffffffff3fa0637508ffffffffffffff7f678d687c687600"
    "a0638c7c7608ffffffffffffff3fa0637508ffffffffffffff7f678d687c687600a0638c7c7608ffffffffff"
    "ffff3fa0637508ffffffffffffff7f678d687c68756776009f638f7600a0638c7c8e7c687600a0638c7c8e7c"
    "687600a0638c7c8e7c687600a0638c7c8e7c68756775686876519f63755168"
)
_LEGACY_ASERT_HEX = {
    1: "c552799453799451" + "96" + _LEGACY_ASERT_BODY_HEX,
    16: "c552799453799460" + "96" + _LEGACY_ASERT_BODY_HEX,
    17: "c55279945379940111" + "96" + _LEGACY_ASERT_BODY_HEX,
    128: "c5527994537994028000" + "96" + _LEGACY_ASERT_BODY_HEX,
    240: "c552799453799402f000" + "96" + _LEGACY_ASERT_BODY_HEX,
    600: "c5527994537994025802" + "96" + _LEGACY_ASERT_BODY_HEX,
    3600: "c552799453799402100e" + "96" + _LEGACY_ASERT_BODY_HEX,
    65536: "c552799453799403000001" + "96" + _LEGACY_ASERT_BODY_HEX,
    86400: "c552799453799403805101" + "96" + _LEGACY_ASERT_BODY_HEX,
}
#: ``_build_linear_daa()`` on origin/main @ 8611cab (2026-06-17 → 2026-09-15 deploys).
_LEGACY_LWMA_HEX = "c552799453795495a300a47c08ffffffffffffff1fa35379969508ffffffffffffff7fa376519f63755168"
#: The same builder at pyrxd commit d75dec5 (2026-06-16, before Photonic#2's ``00 a4`` floor):
#: the bytecode of the mainnet LWMA deploy ``dea3beb9…`` (git show d75dec5:tests/test_dmint_v2_canonical.py).
_LEGACY_LWMA_PREFLOOR_HEX = "c552799453795495a37c08ffffffffffffff1fa35379969508ffffffffffffff7fa376519f63755168"

#: Full legacy contract goldens: the ASERT/LWMA vectors of tests/test_dmint_v2_canonical.py as
#: they stood on origin/main @ 8611cab (those vectors now pin the v2 bytes; these pin what a
#: pre-resync deploy looks like end to end). contractRef aa*36, tokenRef bb*36, SHA256d.
_LEGACY_CONTRACT_GOLDEN: dict[str, tuple[dict, DaaBytecodeVersion, str]] = {
    "asert_h0_hl3600": (
        dict(
            height=0, max_height=100, reward=1000, difficulty=10, daa_mode=DaaMode.ASERT, target_time=60, half_life=3600
        ),
        DaaBytecodeVersion.LEGACY,
        "00d8aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "d0bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb01"
        "6402e8030052013c040000000008cccccccccccccc0cbdc0c859797ea85d795d797ea87e5e7a"
        "7eaabc01147f77587f040000000088817600a26951797ca269c552799453799402100e967654"
        "a06375546876548f9f6375548f687600a0637600a0638c7c7608ffffffffffffff3fa0637508"
        "ffffffffffffff7f678d687c687600a0638c7c7608ffffffffffffff3fa0637508ffffffffff"
        "ffff7f678d687c687600a0638c7c7608ffffffffffffff3fa0637508ffffffffffffff7f678d"
        "687c687600a0638c7c7608ffffffffffffff3fa0637508ffffffffffffff7f678d687c687567"
        "76009f638f7600a0638c7c8e7c687600a0638c7c8e7c687600a0638c7c8e7c687600a0638c7c"
        "8e7c68756775686876519f637551686b75757575577ae500a069567ae600a06901d053797e0c"
        "dec0e9aa76e378e4a269e69d7eaa76e47b9d547a818b76537a9c537ade789181547ae6939d63"
        "6c755279cd01d853797e016a7e886778de519d7676009c63750100677660a163015093518067"
        "827c7e68684c53d8aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaad0bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        "bbbbbbbbbb016402e8030052013c7ec55480547c7e7e6c76009c63750100677660a163015093"
        "518067827c7e68687e5379ec78885379eac0e9885379cc519d75686d7551",
    ),
    "asert_h5_hl600": (
        dict(
            height=5, max_height=100, reward=1000, difficulty=4, daa_mode=DaaMode.ASERT, target_time=120, half_life=600
        ),
        DaaBytecodeVersion.LEGACY,
        "55d8aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "d0bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb01"
        "6402e80300520178040000000008ffffffffffffff1fbdc0c859797ea85d795d797ea87e5e7a"
        "7eaabc01147f77587f040000000088817600a26951797ca269c5527994537994025802967654"
        "a06375546876548f9f6375548f687600a0637600a0638c7c7608ffffffffffffff3fa0637508"
        "ffffffffffffff7f678d687c687600a0638c7c7608ffffffffffffff3fa0637508ffffffffff"
        "ffff7f678d687c687600a0638c7c7608ffffffffffffff3fa0637508ffffffffffffff7f678d"
        "687c687600a0638c7c7608ffffffffffffff3fa0637508ffffffffffffff7f678d687c687567"
        "76009f638f7600a0638c7c8e7c687600a0638c7c8e7c687600a0638c7c8e7c687600a0638c7c"
        "8e7c68756775686876519f637551686b75757575577ae500a069567ae600a06901d053797e0c"
        "dec0e9aa76e378e4a269e69d7eaa76e47b9d547a818b76537a9c537ade789181547ae6939d63"
        "6c755279cd01d853797e016a7e886778de519d7676009c63750100677660a163015093518067"
        "827c7e68684c53d8aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaad0bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        "bbbbbbbbbb016402e803005201787ec55480547c7e7e6c76009c63750100677660a163015093"
        "518067827c7e68687e5379ec78885379eac0e9885379cc519d75686d7551",
    ),
    "lwma_h0": (
        dict(height=0, max_height=100, reward=1000, difficulty=4, daa_mode=DaaMode.LWMA, target_time=60),
        DaaBytecodeVersion.LEGACY,
        "00d8aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "d0bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb01"
        "6402e8030053013c040000000008ffffffffffffff1fbdc0c859797ea85d795d797ea87e5e7a"
        "7eaabc01147f77587f040000000088817600a26951797ca269c552799453795495a300a47c08"
        "ffffffffffffff1fa35379969508ffffffffffffff7fa376519f637551686b75757575577ae5"
        "00a069567ae600a06901d053797e0cdec0e9aa76e378e4a269e69d7eaa76e47b9d547a818b76"
        "537a9c537ade789181547ae6939d636c755279cd01d853797e016a7e886778de519d7676009c"
        "63750100677660a163015093518067827c7e68684c53d8aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad0bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb016402e8030053013c7ec55480547c7e7e6c"
        "76009c63750100677660a163015093518067827c7e68687e5379ec78885379eac0e9885379cc"
        "519d75686d7551",
    ),
    # The 2026-06-16 shape (git show d75dec5:tests/test_dmint_v2_canonical.py "lwma_h0"):
    # identical to lwma_h0 above minus the `00a4` floor — what the mainnet dea3beb9… deploy is.
    "lwma_h0_prefloor": (
        dict(height=0, max_height=100, reward=1000, difficulty=4, daa_mode=DaaMode.LWMA, target_time=60),
        DaaBytecodeVersion.LEGACY_LWMA_PREFLOOR,
        "00d8aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "d0bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb01"
        "6402e8030053013c040000000008ffffffffffffff1fbdc0c859797ea85d795d797ea87e5e7a"
        "7eaabc01147f77587f040000000088817600a26951797ca269c552799453795495a37c08ffff"
        "ffffffffff1fa35379969508ffffffffffffff7fa376519f637551686b75757575577ae500a0"
        "69567ae600a06901d053797e0cdec0e9aa76e378e4a269e69d7eaa76e47b9d547a818b76537a"
        "9c537ade789181547ae6939d636c755279cd01d853797e016a7e886778de519d7676009c6375"
        "0100677660a163015093518067827c7e68684c53d8aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad0bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb016402e8030053013c7ec55480547c7e7e6c7600"
        "9c63750100677660a163015093518067827c7e68687e5379ec78885379eac0e9885379cc519d"
        "75686d7551",
    ),
}


def _params(daa_mode: DaaMode, **kw) -> DmintDeployParams:
    base = dict(
        contract_ref=_CONTRACT_REF,
        token_ref=_TOKEN_REF,
        max_height=100,
        reward=1000,
        difficulty=8,
        algo=DmintAlgo.SHA256D,
        daa_mode=daa_mode,
        target_time=60,
        height=0,
        last_time=_LAST,
    )
    base.update(kw)
    return DmintDeployParams(**base)


def _contract_script(params: DmintDeployParams, version: DaaBytecodeVersion) -> bytes:
    """Assemble a contract under a chosen DAA generation — what a pre-resync deploy produced.

    Only Part B differs between generations; state, Part A, powHashOp and Part C are the
    production builders. For ``V2`` this equals ``build_dmint_contract_script`` exactly.
    """
    part_b = _build_part_b(
        params.daa_mode,
        params.half_life,
        epoch_length=params.epoch_length,
        max_adjustment_log2=params.max_adjustment_log2,
        schedule=params.schedule,
        daa_bytecode_version=version,
    )
    code = _PART_A + b"\xaa" + part_b + _build_part_c(_middle_literal(params))
    return build_dmint_state_script(params) + _OP_STATESEPARATOR + code


def _utxo(script: bytes) -> DmintContractUtxo:
    return DmintContractUtxo(txid="dd" * 32, vout=0, value=1, script=script, state=DmintState.from_script(script))


_FUNDING = DmintMinerFundingUtxo(
    txid="cc" * 32, vout=0, value=50_000_000, script=b"\x76\xa9\x14" + b"\x11" * 20 + b"\x88\xac"
)
_PKH = b"\x22" * 20


class TestLegacyBuildersAreFrozen:
    @pytest.mark.parametrize("half_life", sorted(_LEGACY_ASERT_HEX))
    def test_legacy_asert_bytes_pinned(self, half_life: int) -> None:
        assert _build_asert_daa_legacy(half_life).hex() == _LEGACY_ASERT_HEX[half_life]

    def test_legacy_lwma_bytes_pinned(self) -> None:
        assert _build_linear_daa_legacy().hex() == _LEGACY_LWMA_HEX
        assert _build_linear_daa_legacy_prefloor().hex() == _LEGACY_LWMA_PREFLOOR_HEX

    def test_prefloor_is_floored_minus_exactly_the_floor(self) -> None:
        assert len(_LEGACY_LWMA_HEX) - len(_LEGACY_LWMA_PREFLOOR_HEX) == 4  # "00a4"
        assert _LEGACY_LWMA_HEX.replace("a300a4", "a3", 1) == _LEGACY_LWMA_PREFLOOR_HEX

    @pytest.mark.parametrize("label", list(_LEGACY_CONTRACT_GOLDEN))
    def test_legacy_full_contract_goldens(self, label: str) -> None:
        kwargs, version, golden = _LEGACY_CONTRACT_GOLDEN[label]
        params = DmintDeployParams(contract_ref=_CONTRACT_REF, token_ref=_TOKEN_REF, algo=DmintAlgo.SHA256D, **kwargs)
        assert _contract_script(params, version).hex() == golden

    def test_v2_assembly_helper_equals_production_builder(self) -> None:
        """The helper the legacy goldens use is not a second builder: under V2 it is byte-equal
        to ``build_dmint_contract_script`` — so what it says about legacy is about the same
        state/PartA/PartC the production path emits."""
        for mode in (DaaMode.ASERT, DaaMode.LWMA):
            p = _params(mode, half_life=240)
            assert _contract_script(p, DaaBytecodeVersion.V2) == build_dmint_contract_script(p)

    @pytest.mark.parametrize("half_life", HALF_LIVES)
    def test_legacy_and_v2_asert_never_coincide(self, half_life: int) -> None:
        assert _build_asert_daa_legacy(half_life) != _build_asert_daa_v2(half_life)


# ═══════════════════════════════════════════════════════════════════════════════
# Detection
# ═══════════════════════════════════════════════════════════════════════════════


class TestDetection:
    def test_daa_offset_matches_the_bytes_actually_emitted(self) -> None:
        """Verified against the builder's output, not assumed: Part A (16) + powHashOp (1)
        + B1 (18) + B2 (5) = 40, and the fragment sits exactly there in every mode."""
        assert _DAA_BODY_OFFSET_IN_CODE == 40 == len(_PART_A) + 1 + len(_PART_B1) + len(_PART_B2)
        for mode, frag in (
            (DaaMode.ASERT, _build_asert_daa_v2(240)),
            (DaaMode.LWMA, _build_linear_daa_v2()),
            (DaaMode.FIXED, b""),
        ):
            code = build_dmint_code_script(_params(mode, half_life=240))
            assert code[:16] == _PART_A and code[16:17] == b"\xaa"
            assert code[17:40] == _PART_B1 + _PART_B2
            assert code[40 : 40 + len(frag) + 5] == frag + _PART_B4

    @pytest.mark.parametrize("half_life", HALF_LIVES)
    def test_v2_asert_detected_with_half_life(self, half_life: int) -> None:
        code = build_dmint_code_script(_params(DaaMode.ASERT, half_life=half_life))
        d = detect_daa_bytecode(code, DaaMode.ASERT)
        assert (d.version, d.half_life, d.daa_bytes) == (
            DaaBytecodeVersion.V2,
            half_life,
            _build_asert_daa_v2(half_life),
        )

    @pytest.mark.parametrize("half_life", HALF_LIVES)
    def test_legacy_asert_detected_with_half_life(self, half_life: int) -> None:
        p = _params(DaaMode.ASERT, half_life=half_life)
        d = detect_contract_daa_bytecode(_contract_script(p, DaaBytecodeVersion.LEGACY))
        assert (d.version, d.half_life) == (DaaBytecodeVersion.LEGACY, half_life)
        assert d.daa_bytes == _build_asert_daa_legacy(half_life)

    def test_legacy_asert_with_half_life_65536_is_not_mistaken_for_v2(self) -> None:
        """Adversarial: a legacy half-life of 65536 pushes the SAME bytes as the v2 RADIX
        (``03000001``). The next byte is what separates them — OP_DIV (96) vs OP_MUL (95)."""
        legacy = _build_asert_daa_legacy(65536)
        assert legacy[7:11] == bytes.fromhex("03000001") and legacy[11] == 0x96
        d = detect_daa_bytecode(_PART_A + b"\xaa" + _PART_B1 + _PART_B2 + legacy + _PART_B4 + b"\x51", DaaMode.ASERT)
        assert d.version == DaaBytecodeVersion.LEGACY and d.half_life == 65536

    @pytest.mark.parametrize(
        "version,frag",
        [
            (DaaBytecodeVersion.V2, _build_linear_daa_v2()),
            (DaaBytecodeVersion.LEGACY, _build_linear_daa_legacy()),
            (DaaBytecodeVersion.LEGACY_LWMA_PREFLOOR, _build_linear_daa_legacy_prefloor()),
        ],
    )
    def test_every_lwma_generation_detected(self, version: DaaBytecodeVersion, frag: bytes) -> None:
        d = detect_contract_daa_bytecode(_contract_script(_params(DaaMode.LWMA), version))
        assert (d.version, d.half_life, d.daa_bytes) == (version, None, frag)

    def test_three_lwma_generations_are_pairwise_distinct(self) -> None:
        frags = {_build_linear_daa_v2(), _build_linear_daa_legacy(), _build_linear_daa_legacy_prefloor()}
        assert len(frags) == 3

    def test_contract_with_neither_signature_is_reported_not_guessed(self) -> None:
        """A fragment that is not any known generation must raise, naming the bytes — the fork
        this was ported from returned LEGACY for anything without the v2 signature, so a
        corrupt contract would have been mined under a guessed formula."""
        prefix = _PART_A + b"\xaa" + _PART_B1 + _PART_B2
        bogus = prefix + bytes.fromhex("c5527994537994") + bytes.fromhex("5395") + _PART_B4 + b"\x51"  # OP_3 OP_MUL
        with pytest.raises(UnrecognizedDaaBytecodeError, match="does not recognise") as exc:
            detect_daa_bytecode(bogus, DaaMode.ASERT)
        assert "c5527994537994" in str(exc.value)  # the offending bytes are in the report
        with pytest.raises(UnrecognizedDaaBytecodeError):
            detect_daa_bytecode(bogus, DaaMode.LWMA)
        # The error is BOTH a DmintError-family and a ValidationError, so existing handlers see it.
        assert issubclass(UnrecognizedDaaBytecodeError, ValidationError)

    def test_mode_mismatch_between_state_and_code_is_reported(self) -> None:
        """State says ASERT, code carries LWMA-v2 (or vice versa): not classified as anything."""
        asert_code = build_dmint_code_script(_params(DaaMode.ASERT, half_life=240))
        lwma_code = build_dmint_code_script(_params(DaaMode.LWMA))
        with pytest.raises(UnrecognizedDaaBytecodeError):
            detect_daa_bytecode(asert_code, DaaMode.LWMA)
        with pytest.raises(UnrecognizedDaaBytecodeError):
            detect_daa_bytecode(lwma_code, DaaMode.ASERT)

    def test_single_byte_corruption_of_v2_fragment_is_reported(self) -> None:
        """Rebuild-and-compare, not a prefix sniff: flipping ONE byte past the signature
        (the drift clamp's OP_MIN → OP_MAX) is refused, though the signature still matches."""
        code = bytearray(build_dmint_code_script(_params(DaaMode.ASERT, half_life=240)))
        # preamble+signature (12) + <240> push (3) + OP_DIV (1) + <16384> push (3) → the OP_MIN.
        clamp_min_at = _DAA_BODY_OFFSET_IN_CODE + 12 + 3 + 1 + 3
        assert code[clamp_min_at - 4 : clamp_min_at] == bytes.fromhex("96020040")  # OP_DIV <16384>
        assert code[clamp_min_at] == 0xA3
        code[clamp_min_at] = 0xA4
        with pytest.raises(UnrecognizedDaaBytecodeError, match="diverges"):
            detect_daa_bytecode(bytes(code), DaaMode.ASERT)

    def test_non_minimal_half_life_push_is_reported(self) -> None:
        """A half-life pushed as ``01 05`` instead of OP_5 is not a contract pyrxd can mine
        (MINIMALDATA is consensus-mandatory on Radiant) — report, do not classify."""
        frag = bytes.fromhex("c5527994537994") + bytes.fromhex("0300000195") + bytes.fromhex("0105") + b"\x96"
        code = _PART_A + b"\xaa" + _PART_B1 + _PART_B2 + frag + b"\x00" * 60
        with pytest.raises(UnrecognizedDaaBytecodeError, match="half-life push unreadable"):
            detect_daa_bytecode(code, DaaMode.ASERT)

    def test_truncated_code_is_reported(self) -> None:
        code = build_dmint_code_script(_params(DaaMode.ASERT, half_life=240))[:50]
        with pytest.raises(UnrecognizedDaaBytecodeError):
            detect_daa_bytecode(code, DaaMode.ASERT)
        with pytest.raises(UnrecognizedDaaBytecodeError):
            detect_daa_bytecode(b"", DaaMode.LWMA)

    def test_single_generation_modes_are_refused_by_name(self) -> None:
        code = build_dmint_code_script(_params(DaaMode.FIXED))
        with pytest.raises(ValueError, match="single bytecode generation"):
            detect_daa_bytecode(code, DaaMode.FIXED)
        with pytest.raises(ValidationError, match="single bytecode generation"):
            detect_contract_daa_bytecode(build_dmint_contract_script(_params(DaaMode.FIXED)))

    def test_v1_contract_is_refused(self) -> None:
        from pyrxd.glyph.dmint import build_dmint_v1_contract_script

        v1 = build_dmint_v1_contract_script(0, _CONTRACT_REF, _TOKEN_REF, 100, 1000, _MAX // 10)
        with pytest.raises(ValidationError, match="V1"):
            detect_contract_daa_bytecode(v1)


# ═══════════════════════════════════════════════════════════════════════════════
# No-brick: legacy contracts keep mining under the legacy formula, through the real builder
# ═══════════════════════════════════════════════════════════════════════════════


class TestNoBrick:
    """``build_dmint_mint_tx`` — the production entry point — on legacy vs v2 contracts.

    Inputs are chosen where the two formulas DISAGREE, so a dispatch to the wrong one is
    visible: a 30 s-early block under half_life 3600 is inside the legacy dead zone
    (drift = trunc(-30/3600) = 0 → unchanged) while v2 lowers the target by
    driftFp = trunc(-30·65536/3600) = -546 sixty-five-thousand-five-hundred-and-thirty-sixths.
    """

    def test_legacy_asert_contract_mints_under_legacy_formula(self) -> None:
        p = _params(DaaMode.ASERT, half_life=3600)
        utxo = _utxo(_contract_script(p, DaaBytecodeVersion.LEGACY))
        ct = _LAST + 30
        res = build_dmint_mint_tx(utxo, b"\x00" * 8, _PKH, ct, funding_utxo=_FUNDING, half_life=3600)
        legacy = compute_next_target_asert_legacy(p.initial_target, _LAST, ct, 60, 3600)
        v2 = compute_next_target_asert_v2(p.initial_target, _LAST, ct, 60, 3600)
        assert legacy != v2, "inputs must separate the formulas or the test proves nothing"
        assert res.updated_state.target == legacy == p.initial_target
        # The recreated contract keeps the legacy code section byte-for-byte.
        assert res.contract_script.endswith(utxo.script[utxo.script.index(_OP_STATESEPARATOR) :])

    def test_v2_asert_contract_mints_under_v2_formula(self) -> None:
        p = _params(DaaMode.ASERT, half_life=3600)
        utxo = _utxo(build_dmint_contract_script(p))
        ct = _LAST + 30
        res = build_dmint_mint_tx(utxo, b"\x00" * 8, _PKH, ct, funding_utxo=_FUNDING, half_life=3600)
        v2 = compute_next_target_asert_v2(p.initial_target, _LAST, ct, 60, 3600)
        assert res.updated_state.target == v2 != compute_next_target_asert_legacy(p.initial_target, _LAST, ct, 60, 3600)
        # -30 s under half_life 3600 → driftFp = trunc(-30·65536/3600) = trunc(-546.13) = -546
        # (a floor would give -547 and a different target). t = MAX/8 is below the MAX/4 cap.
        assert v2 == p.initial_target - (p.initial_target // 65536) * 546

    @pytest.mark.parametrize("version", [DaaBytecodeVersion.LEGACY, DaaBytecodeVersion.LEGACY_LWMA_PREFLOOR])
    def test_legacy_lwma_contracts_mint_under_legacy_formula(self, version: DaaBytecodeVersion) -> None:
        p = _params(DaaMode.LWMA)
        utxo = _utxo(_contract_script(p, version))
        ct = _LAST + 30
        res = build_dmint_mint_tx(utxo, b"\x00" * 8, _PKH, ct, funding_utxo=_FUNDING)
        legacy = compute_next_target_linear_legacy(p.initial_target, _LAST, ct, 60)
        assert legacy != compute_next_target_linear_v2(p.initial_target, _LAST, ct, 60)
        assert res.updated_state.target == legacy == (p.initial_target // 60) * 30

    def test_v2_lwma_contract_mints_under_v2_formula(self) -> None:
        p = _params(DaaMode.LWMA)
        utxo = _utxo(build_dmint_contract_script(p))
        ct = _LAST + 30
        res = build_dmint_mint_tx(utxo, b"\x00" * 8, _PKH, ct, funding_utxo=_FUNDING)
        assert res.updated_state.target == compute_next_target_linear_v2(p.initial_target, _LAST, ct, 60)
        assert res.updated_state.target == p.initial_target - (p.initial_target // 65536) * 16384  # clamped -25%

    def test_bare_names_still_compute_the_legacy_formula(self) -> None:
        """No silent change for existing callers: the historical names ARE the legacy functions."""
        assert compute_next_target_asert is compute_next_target_asert_legacy
        assert compute_next_target_linear is compute_next_target_linear_legacy


# ═══════════════════════════════════════════════════════════════════════════════
# No-brick, anchored to Radiant MAINNET: the dea3beb9… LWMA deploy and its e7b52f16… mint
# ═══════════════════════════════════════════════════════════════════════════════

#: vout[0] scriptPubKey of mainnet tx dea3beb9fc0387128d03457b3e07a143a06ec4e567f5a2b13e3648e73f9144f3
#: (block 438485, 2026-06-16) — the first adaptive-difficulty V2 dMint deploy on Radiant mainnet,
#: made by pyrxd @ d75dec5 with the pre-floor LWMA bytecode. Fetched 2026-09-16 via
#: ``radiant-cli getrawtransaction <txid> 1`` on a mainnet node (Radiant Core 3.1.x).
_MAINNET_LWMA_DEPLOY_TXID = "dea3beb9fc0387128d03457b3e07a143a06ec4e567f5a2b13e3648e73f9144f3"
_MAINNET_LWMA_DEPLOY_SPK_HEX = (
    "00d8fd010ccf424bf79fcd05dd49101597276dc7a1dd475ad9550bad71b715f7c14001000000d0fd010ccf424b"
    "f79fcd05dd49101597276dc7a1dd475ad9550bad71b715f7c140000000005a02e8030053013c0400f1536508ff"
    "ffffffffffff7fbdc0c859797ea85d795d797ea87e5e7a7eaabc01147f77587f040000000088817600a2695179"
    "7ca269c552799453795495a37c08ffffffffffffff1fa35379969508ffffffffffffff7fa376519f637551686b"
    "75757575577ae500a069567ae600a06901d053797e0cdec0e9aa76e378e4a269e69d7eaa76e47b9d547a818b76"
    "537a9c537ade789181547ae6939d636c755279cd01d853797e016a7e886778de519d7676009c63750100677660"
    "a163015093518067827c7e68684c52d8fd010ccf424bf79fcd05dd49101597276dc7a1dd475ad9550bad71b715"
    "f7c14001000000d0fd010ccf424bf79fcd05dd49101597276dc7a1dd475ad9550bad71b715f7c140000000005a"
    "02e8030053013c7ec55480547c7e7e6c76009c63750100677660a163015093518067827c7e68687e5379ec7888"
    "5379eac0e9885379cc519d75686d7551"
)
#: The mint that spent it: tx e7b52f169b74759f018f9eb00ce44eb7e0f04eb4ef17629f3d60c090054e9d73
#: (same block), nLockTime 1700000030 against the deploy's lastTime 1700000000 (a 30 s "block"
#: under targetTime 60). Its vout[0] is the recreated contract at height 1 with the target the
#: covenant computed ON CHAIN: 1152921504606846960 = (MAX/4 // 60) × 30 — the legacy formula.
_MAINNET_LWMA_MINT_TXID = "e7b52f169b74759f018f9eb00ce44eb7e0f04eb4ef17629f3d60c090054e9d73"
_MAINNET_LWMA_MINT_LOCKTIME = 1_700_000_030
_MAINNET_LWMA_MINT_SPK_HEX = (
    "51d8fd010ccf424bf79fcd05dd49101597276dc7a1dd475ad9550bad71b715f7c14001000000d0fd010ccf424b"
    "f79fcd05dd49101597276dc7a1dd475ad9550bad71b715f7c140000000005a02e8030053013c041ef1536508f0"
    "ffffffffffff0fbdc0c859797ea85d795d797ea87e5e7a7eaabc01147f77587f040000000088817600a2695179"
    "7ca269c552799453795495a37c08ffffffffffffff1fa35379969508ffffffffffffff7fa376519f637551686b"
    "75757575577ae500a069567ae600a06901d053797e0cdec0e9aa76e378e4a269e69d7eaa76e47b9d547a818b76"
    "537a9c537ade789181547ae6939d636c755279cd01d853797e016a7e886778de519d7676009c63750100677660"
    "a163015093518067827c7e68684c52d8fd010ccf424bf79fcd05dd49101597276dc7a1dd475ad9550bad71b715"
    "f7c14001000000d0fd010ccf424bf79fcd05dd49101597276dc7a1dd475ad9550bad71b715f7c140000000005a"
    "02e8030053013c7ec55480547c7e7e6c76009c63750100677660a163015093518067827c7e68687e5379ec7888"
    "5379eac0e9885379cc519d75686d7551"
)


class TestMainnetLwmaAnchor:
    """The one adaptive-difficulty contract pyrxd has on mainnet, verified against the chain.

    Every other legacy fixture in this file is DERIVED from git history; this one is the
    bytes a Radiant node served. If detection or the legacy mirror ever drifts, this is the
    test that says a real, funded contract became unmineable.
    """

    _deploy = bytes.fromhex(_MAINNET_LWMA_DEPLOY_SPK_HEX)
    _mint = bytes.fromhex(_MAINNET_LWMA_MINT_SPK_HEX)

    def test_deploy_is_the_prefloor_legacy_lwma_byte_for_byte(self) -> None:
        st = DmintState.from_script(self._deploy)
        assert (st.daa_mode, st.height, st.target_time, st.last_time, st.target) == (DaaMode.LWMA, 0, 60, _LAST, _MAX)
        d = detect_contract_daa_bytecode(self._deploy)
        assert d.version == DaaBytecodeVersion.LEGACY_LWMA_PREFLOOR
        # The whole code section is what the frozen builders emit — not just the DAA fragment.
        params = DmintDeployParams(
            contract_ref=st.contract_ref,
            token_ref=st.token_ref,
            max_height=st.max_height,
            reward=st.reward,
            difficulty=1,
            algo=st.algo,
            daa_mode=st.daa_mode,
            target_time=st.target_time,
            height=st.height,
            last_time=st.last_time,
        )
        assert _contract_script(params, DaaBytecodeVersion.LEGACY_LWMA_PREFLOOR) == self._deploy
        # ...and is NOT what the current builder emits (LWMA-v2) nor the floored legacy variant.
        assert build_dmint_contract_script(params) != self._deploy
        assert _contract_script(params, DaaBytecodeVersion.LEGACY) != self._deploy

    def test_mint_builder_recreates_the_on_chain_mint_byte_for_byte(self) -> None:
        """PRODUCTION path: ``build_dmint_mint_tx`` on the deploy UTXO at the real mint's
        nLockTime must produce exactly the contract script the mainnet mint carries."""
        st = DmintState.from_script(self._deploy)
        utxo = DmintContractUtxo(txid=_MAINNET_LWMA_DEPLOY_TXID, vout=0, value=1, script=self._deploy, state=st)
        res = build_dmint_mint_tx(utxo, b"\x00" * 8, _PKH, _MAINNET_LWMA_MINT_LOCKTIME, funding_utxo=_FUNDING)
        assert res.contract_script == self._mint
        on_chain = DmintState.from_script(self._mint)
        assert (on_chain.height, on_chain.last_time) == (1, _MAINNET_LWMA_MINT_LOCKTIME)
        assert on_chain.target == res.updated_state.target == 1152921504606846960
        # The inputs separate the formulas: v2 would have recreated a different state.
        legacy = compute_next_target_linear_legacy(_MAX, _LAST, _MAINNET_LWMA_MINT_LOCKTIME, 60)
        v2 = compute_next_target_linear_v2(_MAX, _LAST, _MAINNET_LWMA_MINT_LOCKTIME, 60)
        assert on_chain.target == legacy == (_MAX // 4 // 60) * 30
        assert v2 != legacy


# ═══════════════════════════════════════════════════════════════════════════════
# Mint-builder byte-verify of half_life against the baked bytecode (both generations)
# ═══════════════════════════════════════════════════════════════════════════════


class TestMintBuilderVerifiesHalfLifeAgainstBytecode:
    @pytest.mark.parametrize("version", [DaaBytecodeVersion.V2, DaaBytecodeVersion.LEGACY])
    @pytest.mark.parametrize("baked", [1, 240, 3600, 65536])
    def test_honest_half_life_passes(self, version: DaaBytecodeVersion, baked: int) -> None:
        utxo = _utxo(_contract_script(_params(DaaMode.ASERT, half_life=baked), version))
        res = build_dmint_mint_tx(utxo, b"\x00" * 8, _PKH, _LAST + 90, funding_utxo=_FUNDING, half_life=baked)
        assert res.updated_state.height == 1

    @pytest.mark.parametrize("version", [DaaBytecodeVersion.V2, DaaBytecodeVersion.LEGACY])
    def test_wrong_half_life_refused_before_grind_naming_the_baked_value(self, version: DaaBytecodeVersion) -> None:
        utxo = _utxo(_contract_script(_params(DaaMode.ASERT, half_life=3600), version))
        with pytest.raises(ValidationError, match=r"bakes half_life=3600") as exc:
            build_dmint_mint_tx(utxo, b"\x00" * 8, _PKH, _LAST + 90, funding_utxo=_FUNDING, half_life=240)
        assert "half_life=240 was supplied" in str(exc.value)
        assert version.name in str(exc.value)

    @pytest.mark.parametrize(
        ("version", "delta"),
        # The delta has to be one at which 3600 and 240 actually disagree, and that is a
        # DIFFERENT delta per generation: the v2 fractional drift saturates its ±16384 clamp
        # long before the legacy integer stepper leaves 0. Picking one number for both makes
        # the test vacuous for one of them — the non-vacuity assertion below caught exactly
        # that when this test was first written with delta=90 for both.
        [(DaaBytecodeVersion.V2, 120), (DaaBytecodeVersion.LEGACY, 3660)],
    )
    def test_omitted_half_life_uses_the_contracts_own_baked_value(
        self, version: DaaBytecodeVersion, delta: int
    ) -> None:
        """The HONEST path for a contract on the retired 3600 default: omitting half_life mints.

        The builder has already read 3600 out of the bytecode by the time it needs the value,
        so demanding the caller restate it could only refuse work that is legitimate — which
        is what happened when the deploy-side default moved 3600 → 240 and every previously
        working invocation against an older contract began failing.

        The assertion that carries the weight is the TARGET: it must equal the 3600 mirror and
        differ from the 240 one, which proves the detected value was used rather than a default
        that happened to be harmless.
        """
        utxo = _utxo(_contract_script(_params(DaaMode.ASERT, half_life=3600), version))
        res = build_dmint_mint_tx(utxo, b"\x00" * 8, _PKH, _LAST + delta, funding_utxo=_FUNDING)
        mirror = compute_next_target_asert_v2 if version is DaaBytecodeVersion.V2 else compute_next_target_asert_legacy
        baked = mirror(utxo.state.target, _LAST, _LAST + delta, 60, 3600)
        default_240 = mirror(utxo.state.target, _LAST, _LAST + delta, 60, 240)
        assert baked != default_240, "fixture is vacuous: 3600 and 240 retarget to the same value here"
        assert res.updated_state.target == baked

    def test_unrecognized_bytecode_refused_before_grind(self) -> None:
        p = _params(DaaMode.ASERT, half_life=240)
        script = bytearray(build_dmint_contract_script(p))
        state_len = script.index(_OP_STATESEPARATOR)
        at = state_len + 1 + _DAA_BODY_OFFSET_IN_CODE + 12 + 3 + 1 + 3  # the clamp OP_MIN (after <240> OP_DIV <16384>)
        assert script[at - 4 : at] == bytes.fromhex("96020040")
        assert script[at] == 0xA3
        script[at] = 0xA4
        with pytest.raises(UnrecognizedDaaBytecodeError):
            build_dmint_mint_tx(
                _utxo(bytes(script)), b"\x00" * 8, _PKH, _LAST + 90, funding_utxo=_FUNDING, half_life=240
            )


# ═══════════════════════════════════════════════════════════════════════════════
# Defaults: 3600 → 240 everywhere
# ═══════════════════════════════════════════════════════════════════════════════


class TestHalfLifeDefaultIsCanonical:
    def test_deploy_params_default(self) -> None:
        assert _params(DaaMode.ASERT).half_life == 240 == DEFAULT_ASERT_HALFLIFE

    def test_v2_deploy_params_default(self) -> None:
        meta = GlyphMetadata(protocol=[GlyphProtocol.FT, GlyphProtocol.DMINT], ticker="T", name="t", decimals=0)
        p = DmintV2DeployParams(
            metadata=meta, owner_pkh="11" * 20, num_contracts=1, max_height=10, reward_photons=1, difficulty=1
        )
        assert p.half_life == 240

    def test_mint_builder_and_part_b_defaults(self) -> None:
        # The MINT builder's default is None — "read it off the contract", not "assume 240".
        # A concrete default there is a guard refusing honest work (see
        # TestMintBuilderVerifiesHalfLifeAgainstBytecode). _build_part_b has no contract to
        # read, so the canonical constant stays its default.
        assert inspect.signature(build_dmint_mint_tx).parameters["half_life"].default is None
        assert inspect.signature(_build_part_b).parameters["half_life"].default == 240
        assert _build_part_b(DaaMode.ASERT) == _build_part_b(DaaMode.ASERT, 240)
        assert _build_part_b(DaaMode.ASERT) != _build_part_b(DaaMode.ASERT, 3600)

    def test_deploy_cli_half_life_default_is_canonical(self) -> None:
        from pyrxd.cli import glyph_cmds

        (opt,) = [p for p in glyph_cmds.deploy_dmint_cmd.params if p.name == "half_life"]
        assert opt.default == 240

    def test_claim_cli_half_life_default_is_read_from_the_contract(self) -> None:
        """The CLAIM side must not default to a number: the contract's bytecode decides.

        A concrete default here is what broke every claim against a contract deployed on the
        retired 3600 default — the user was asked to restate a value pyrxd had already read.
        """
        from pyrxd.cli import glyph_cmds

        (opt,) = [p for p in glyph_cmds.claim_dmint_cmd.params if p.name == "half_life"]
        assert opt.default is None

    def test_default_deploy_bakes_240_and_the_default_claim_mints_it(self) -> None:
        """Round trip through the two production entry points with NO half_life anywhere."""
        utxo = _utxo(build_dmint_contract_script(_params(DaaMode.ASERT)))
        assert detect_contract_daa_bytecode(utxo.script).half_life == 240
        res = build_dmint_mint_tx(utxo, b"\x00" * 8, _PKH, _LAST + 90, funding_utxo=_FUNDING)
        assert res.updated_state.target == compute_next_target_asert_v2(utxo.state.target, _LAST, _LAST + 90, 60, 240)


# ═══════════════════════════════════════════════════════════════════════════════
# CBOR payload: Photonic DmintPayload keys, emitted only when set
# ═══════════════════════════════════════════════════════════════════════════════


class TestDmintCborPayloadMirrorsPhotonic:
    _BASE = dict(algo=DmintAlgo.SHA256D, num_contracts=1, max_height=1000, reward=10, premine=0, diff=4)

    def test_fixed_asert_lwma_payloads_unchanged_when_new_keys_unset(self) -> None:
        """Pinned dicts: exactly what to_cbor_dict emitted before the keys existed."""
        fixed = DmintCborPayload(**self._BASE)
        assert fixed.to_cbor_dict() == {
            "algo": 0,
            "numContracts": 1,
            "maxHeight": 1000,
            "reward": 10,
            "premine": 0,
            "diff": 4,
        }
        asert = DmintCborPayload(**self._BASE, daa_mode=DaaMode.ASERT, target_block_time=60, half_life=240)
        assert asert.to_cbor_dict()["daa"] == {"mode": 2, "targetBlockTime": 60, "halfLife": 240}
        lwma = DmintCborPayload(**self._BASE, daa_mode=DaaMode.LWMA, target_block_time=60, window_size=144)
        assert lwma.to_cbor_dict()["daa"] == {"mode": 3, "targetBlockTime": 60, "windowSize": 144}

    def test_new_keys_emitted_only_when_set_and_round_trip(self) -> None:
        asert = DmintCborPayload(**self._BASE, daa_mode=DaaMode.ASERT, target_block_time=60, half_life=240, asymptote=7)
        assert asert.to_cbor_dict()["daa"] == {"mode": 2, "targetBlockTime": 60, "halfLife": 240, "asymptote": 7}
        epoch = DmintCborPayload(
            **self._BASE, daa_mode=DaaMode.EPOCH, target_block_time=60, epoch_length=2016, max_adjustment=4
        )
        assert epoch.to_cbor_dict()["daa"] == {
            "mode": 1,
            "targetBlockTime": 60,
            "epochLength": 2016,
            "maxAdjustment": 4,
        }
        sched = DmintCborPayload(**self._BASE, daa_mode=DaaMode.SCHEDULE, schedule=((100, 4), (1000, 8)))
        assert sched.to_cbor_dict()["daa"] == {
            "mode": 4,
            "targetBlockTime": 60,
            "schedule": [{"height": 100, "difficulty": 4}, {"height": 1000, "difficulty": 8}],
        }
        for payload in (asert, epoch, sched):
            assert DmintCborPayload.from_cbor_dict(payload.to_cbor_dict()) == payload

    def test_round_trips_through_the_real_cbor_encoder(self) -> None:
        from pyrxd.glyph.payload import decode_payload, encode_payload

        sched = DmintCborPayload(**self._BASE, daa_mode=DaaMode.SCHEDULE, schedule=((100, 4), (1000, 8)))
        meta = GlyphMetadata(
            protocol=[GlyphProtocol.FT, GlyphProtocol.DMINT], ticker="S", name="s", decimals=0, v=2, dmint_params=sched
        )
        raw, _ = encode_payload(meta)
        assert decode_payload(raw).dmint_params == sched

    def test_legacy_payload_without_new_keys_still_parses(self) -> None:
        d = {
            "algo": 0,
            "maxHeight": 10,
            "reward": 1,
            "diff": 1,
            "daa": {"mode": 2, "targetBlockTime": 60, "halfLife": 3600},
        }
        p = DmintCborPayload.from_cbor_dict(d)
        assert (p.half_life, p.asymptote, p.epoch_length, p.max_adjustment, p.schedule) == (3600, 0, 0, 0, ())

    def test_schedule_entry_without_difficulty_is_refused_by_name(self) -> None:
        d = {
            "algo": 0,
            "maxHeight": 10,
            "reward": 1,
            "diff": 1,
            "daa": {"mode": 4, "schedule": [{"height": 1, "target": 5}]},
        }
        with pytest.raises(ValidationError, match=r"schedule\[0\]"):
            DmintCborPayload.from_cbor_dict(d)

    def test_max_adjustment_accepts_exactly_what_photonic_accepts(self) -> None:
        """``script.ts`` ``maxAdjustmentToLog2`` (becf41a7) accepts 1..4 as a log2 shift count and
        8/16 as multipliers and throws on anything else, so a Photonic-built token can carry
        {1, 2, 3, 4, 8, 16} and nothing else. A payload read off chain with 3 (= 8× there) must
        PARSE — refusing it would make ``decode_payload`` choke on a valid foreign token."""
        for ok in (1, 2, 3, 4, 8, 16):
            p = DmintCborPayload(**self._BASE, daa_mode=DaaMode.EPOCH, epoch_length=10, max_adjustment=ok)
            assert DmintCborPayload.from_cbor_dict(p.to_cbor_dict()).max_adjustment == ok
        for bad in (5, 6, 32, 7):
            with pytest.raises(ValidationError, match="maxAdjustmentToLog2"):
                DmintCborPayload(**self._BASE, daa_mode=DaaMode.EPOCH, epoch_length=10, max_adjustment=bad)
        with pytest.raises(ValidationError, match="difficulty must be >= 1"):
            DmintCborPayload(**self._BASE, daa_mode=DaaMode.SCHEDULE, schedule=((0, 0),))


# ═══════════════════════════════════════════════════════════════════════════════
# The off-chain v2 mirrors, by hand
# ═══════════════════════════════════════════════════════════════════════════════


class TestV2MirrorsByHand:
    def test_reference_examples(self) -> None:
        t = _MAX // 8
        # early by 30 s, half_life 240: driftFp = -30*65536/240 = -8192 → delta = (t//65536)*-8192
        assert compute_next_target_asert_v2(t, _LAST, _LAST + 30, 60, 240) == t + (t // 65536) * -8192
        # late by 60 s, half_life 240: driftFp = 60*65536/240 = 16384 = the clamp → +25%
        assert compute_next_target_asert_v2(t, _LAST, _LAST + 120, 60, 240) == t + (t // 65536) * 16384
        # very late: clamped to +25% too
        assert compute_next_target_asert_v2(t, _LAST, _LAST + 86400, 60, 240) == t + (t // 65536) * 16384
        # on target: unchanged
        assert compute_next_target_asert_v2(t, _LAST, _LAST + 60, 60, 240) == t

    def test_truncation_toward_zero_not_floor(self) -> None:
        """excess = -1, half_life 240: trunc(-65536/240) = -273; a floor would give -274 and
        recreate a target the covenant does not."""
        t = 1 << 40
        got = compute_next_target_asert_v2(t, _LAST, _LAST + 59, 60, 240)
        assert got == t + (t // 65536) * -273
        assert got != t + (t // 65536) * -274

    def test_lwma_v2_is_asert_v2_with_gain_target_time(self) -> None:
        t = _MAX // 8
        for delta in (-30, 0, 10, 70, 100_000):
            assert compute_next_target_linear_v2(t, _LAST, _LAST + delta, 60) == compute_next_target_asert_v2(
                t, _LAST, _LAST + delta, 60, 60
            )
        # +10 s late under gain 60: driftFp = trunc(10*65536/60) = 10922 (not a clamp value)
        assert compute_next_target_linear_v2(t, _LAST, _LAST + 70, 60) == t + (t // 65536) * 10922

    def test_target_pre_cap_and_floor(self) -> None:
        # target above MAX/4 is capped to MAX/4 before the step; on-target leaves it at the cap
        assert compute_next_target_asert_v2(_MAX, _LAST, _LAST + 60, 60, 240) == ASERT_V2_MAX_TARGET_DIV4
        # +25% of the cap is re-capped at MAX/4
        assert compute_next_target_asert_v2(_MAX, _LAST, _LAST + 600, 60, 240) == ASERT_V2_MAX_TARGET_DIV4
        # tiny targets (t // RADIX == 0) never move and never drop below 1
        assert compute_next_target_asert_v2(1, _LAST, _LAST, 60, 1) == 1
        assert compute_next_target_asert_v2(65535, _LAST, _LAST - 1, 60, 1) == 65535
        assert compute_next_target_asert_v2(65536, _LAST, _LAST - 1, 60, 1) == 65536 - 16384

    def test_int64_abort_is_mirrored_not_mispredicted(self) -> None:
        """excess * RADIX must stay in int64: |excess| >= 2^47 makes the on-chain OP_MUL abort
        (INVALID_NUMBER_RANGE_64_BIT), so the mirror raises instead of returning a value."""
        tt_ok = (1 << 47) - 1  # excess = -(2^47 - 1) → -(2^63 - 2^16): representable
        compute_next_target_asert_v2(_MAX // 8, _LAST, _LAST, tt_ok, 240)
        tt_bad = 1 << 47  # excess = -2^47 → -2^63 = INT64_MIN, which valid64BitRange excludes
        with pytest.raises(ValidationError, match="OP_MUL"):
            compute_next_target_asert_v2(_MAX // 8, _LAST, _LAST, tt_bad, 240)
        with pytest.raises(ValidationError, match="OP_MUL"):
            compute_next_target_linear_v2(_MAX // 8, _LAST, _LAST, tt_bad)

    def test_invalid_operands_refused(self) -> None:
        with pytest.raises(ValidationError, match="half_life"):
            compute_next_target_asert_v2(1000, _LAST, _LAST, 60, 0)
        with pytest.raises(ValidationError, match="target_time"):
            compute_next_target_linear_v2(1000, _LAST, _LAST, 0)
        with pytest.raises(ValidationError, match="script number"):
            compute_next_target_asert_v2(_MAX + 1, _LAST, _LAST, 60, 240)  # a 256-bit target cannot run on chain


# ═══════════════════════════════════════════════════════════════════════════════
# lastTime: the deploy path must not emit a contract that is unmineable from birth
# ═══════════════════════════════════════════════════════════════════════════════
#
# The V2 state pushes lastTime as a fixed `04 <4B LE>`, and ASERT/LWMA read it back as
# a script number on the FIRST mint. MINIMALDATA sits in radiant-core's
# MANDATORY_SCRIPT_VERIFY_FLAGS, so a non-minimal operand is a CONSENSUS abort, not a
# standardness complaint — and `00000000` (the old implicit default) is non-minimal.
# Measured on a real node: last_time=8388608 accepted, 8388607 rejected.


def _v2_deploy_params(**kw) -> DmintV2DeployParams:
    base = dict(
        metadata=GlyphMetadata(protocol=[GlyphProtocol.FT, GlyphProtocol.DMINT], name="t", ticker="T", decimals=0),
        owner_pkh=Hex20(bytes(20)),
        num_contracts=1,
        max_height=100,
        reward_photons=1_000,
        difficulty=8,
        target_time=60,
    )
    base.update(kw)
    return DmintV2DeployParams(**base)


class TestLastTimeMinimalityIsDerived:
    def test_the_threshold_is_derived_from_the_cscriptnum_rule_not_typed(self) -> None:
        """2**23 is a RESULT of the minimality rule, not a constant anyone wrote down.

        Exhaustive below 2**24; sampled above. The node agreed: 8388608 accepted,
        8388607 rejected with mandatory-script-verify-flag-failed.
        """
        assert min(n for n in range(1 << 24) if is_minimal_4byte_scriptnum(n)) == 1 << 23
        # Nothing in the rest of the locktime range is non-minimal, so a guard keyed to
        # this predicate cannot refuse a plausible timestamp — the honest-path half.
        assert all(is_minimal_4byte_scriptnum(n) for n in range(1 << 23, 0x7FFFFFFF, 7919))
        assert is_minimal_4byte_scriptnum(0x7FFFFFFF)
        # Bit 31 set encodes a negative script number whose top byte is bare sign.
        assert not is_minimal_4byte_scriptnum(0x80000000)
        assert not is_minimal_4byte_scriptnum(-1)

    def test_the_guarded_mode_set_is_derived_from_the_bytecode_each_mode_emits(self) -> None:
        """Which modes need the guard is read OUT of the fragments, not hand-kept.

        A mode qualifies when its DAA fragment opens with the excess preamble
        (OP_TXLOCKTIME OP_2 OP_PICK OP_SUB …), i.e. reads lastTime unconditionally on the
        first mint. EPOCH also reads lastTime, but only inside a branch gated on
        `height > 0`, which height 0 cannot take; SCHEDULE and FIXED never read it. If a
        future mode starts reading it unconditionally, this fails until it is listed.
        """
        examined = {}
        for mode in DaaMode:
            frag = _daa_bytes_for(
                mode,
                DEFAULT_ASERT_HALFLIFE,
                epoch_length=2016,
                max_adjustment_log2=2,
                schedule=((100, 4),),
                daa_bytecode_version=DaaBytecodeVersion.V2,
            )
            examined[mode] = frag.startswith(_V2_EXCESS_PREAMBLE)
        assert len(examined) == 5, "the derivation must see every DaaMode, not a subset"
        derived = frozenset(m for m, unconditional in examined.items() if unconditional)
        assert derived, "derivation found nothing — the preamble constant or the builders moved"
        assert derived == DAA_MODES_READING_DEPLOY_LAST_TIME
        # EPOCH reads lastTime too, just not at height 0; that is the exemption being
        # claimed, so pin the shape it rests on rather than only the prose.
        epoch = _daa_bytes_for(
            DaaMode.EPOCH,
            DEFAULT_ASERT_HALFLIFE,
            epoch_length=2016,
            max_adjustment_log2=2,
            schedule=(),
            daa_bytecode_version=DaaBytecodeVersion.V2,
        )
        assert _V2_EXCESS_PREAMBLE[:3] in epoch, "EPOCH stopped reading lastTime — re-check the exemption"
        assert not epoch.startswith(_V2_EXCESS_PREAMBLE), "EPOCH now reads lastTime unconditionally"
        assert epoch.index(_V2_EXCESS_PREAMBLE[:3]) > epoch.index(b"\x63"), "the OP_IF gate is gone from EPOCH"


class TestDeployRefusesAnUnmineableLastTime:
    @pytest.mark.parametrize("mode", sorted(DAA_MODES_READING_DEPLOY_LAST_TIME, key=lambda m: m.value))
    @pytest.mark.parametrize("bad", [0, 1, (1 << 23) - 1])
    def test_refused_on_the_params_the_caller_typed(self, mode: DaaMode, bad: int) -> None:
        with pytest.raises(ValidationError, match="NON-MINIMAL"):
            _v2_deploy_params(daa_mode=mode, last_time=bad)

    @pytest.mark.parametrize("mode", sorted(DAA_MODES_READING_DEPLOY_LAST_TIME, key=lambda m: m.value))
    def test_accepted_at_the_threshold_and_at_a_real_timestamp(self, mode: DaaMode) -> None:
        """The honest half: the guard must not refuse work that mines."""
        assert _v2_deploy_params(daa_mode=mode, last_time=1 << 23).last_time == 1 << 23
        assert _v2_deploy_params(daa_mode=mode, last_time=_LAST).last_time == _LAST

    @pytest.mark.parametrize("mode", [DaaMode.FIXED, DaaMode.EPOCH, DaaMode.SCHEDULE])
    def test_modes_that_never_read_it_at_height_zero_still_accept_zero(self, mode: DaaMode) -> None:
        """The other honest half: these three do not read lastTime at height 0, so
        refusing 0 for them would be a guard refusing valid work (and would break the
        conformance vectors, which carry 0 for exactly these three)."""
        kw = {"difficulty": 32768} if mode is DaaMode.EPOCH else {}
        if mode is DaaMode.SCHEDULE:
            kw["schedule"] = ((100, 4),)
        params = _v2_deploy_params(daa_mode=mode, last_time=0, **kw)
        result = GlyphBuilder().prepare_dmint_deploy(params)
        state = DmintState.from_script(result.build_reveal_outputs("dd" * 32).contract_scripts[0])
        assert state.last_time == 0

    @pytest.mark.parametrize("mode", sorted(DAA_MODES_READING_DEPLOY_LAST_TIME, key=lambda m: m.value))
    def test_the_production_deploy_path_emits_a_mineable_last_time(self, mode: DaaMode) -> None:
        """Through the SHIPPED entry point, with no last_time supplied at all.

        This is the case the branch's own regtest could not see: its helper set a
        timestamp the production path had no field for, so every contract the shipped
        API actually produced carried `04 00000000` and aborted on its first retarget.
        """
        before = int(time.time())
        result = GlyphBuilder().prepare_dmint_deploy(_v2_deploy_params(daa_mode=mode))
        after = int(time.time())
        assert before <= result.last_time <= after

        scripts = result.build_reveal_outputs("dd" * 32).contract_scripts
        assert len(scripts) == 1
        state_script = build_dmint_state_script(
            DmintDeployParams(
                contract_ref=GlyphRef(txid="dd" * 32, vout=1),
                token_ref=GlyphRef(txid="dd" * 32, vout=0),
                max_height=100,
                reward=1_000,
                difficulty=8,
                daa_mode=mode,
                target_time=60,
                last_time=result.last_time,
            )
        )
        assert scripts[0].startswith(state_script)
        # And the bytes themselves, not just the parse: the lastTime push must be a
        # minimal script number, which is what the covenant's CScriptNum demands.
        parsed = DmintState.from_script(scripts[0])
        assert parsed.last_time == result.last_time
        assert is_minimal_4byte_scriptnum(parsed.last_time)
        assert state_script[-len(_push_minimal(parsed.target)) - 5 :][:5] == b"\x04" + parsed.last_time.to_bytes(
            4, "little"
        )
        assert parsed.last_time.to_bytes(4, "little") != b"\x00\x00\x00\x00"

    @pytest.mark.parametrize("mode", sorted(DAA_MODES_READING_DEPLOY_LAST_TIME, key=lambda m: m.value))
    def test_build_reveal_outputs_refuses_a_result_rebuilt_with_a_dead_last_time(self, mode: DaaMode) -> None:
        """The second door. Commit and reveal are separate transactions, so a caller may
        rebuild the result object in a later process rather than keep the one
        prepare_dmint_deploy returned — that path must not be able to emit the bytes."""
        result = GlyphBuilder().prepare_dmint_deploy(_v2_deploy_params(daa_mode=mode))
        result.last_time = 0  # what a hand-rebuilt / deserialized result would carry
        with pytest.raises(ValidationError, match="NON-MINIMAL"):
            result.build_reveal_outputs("dd" * 32)


# ═══════════════════════════════════════════════════════════════════════════════
# lastTime at MINT time: pyrxd never writes one the next retarget cannot read, and never
# grinds against a state whose lastTime this mint's retarget cannot read
# ═══════════════════════════════════════════════════════════════════════════════
#
# The evaluator-backed halves (which modes read lastTime, where the 2**23 threshold sits in
# each fragment, which backwards locktimes the bytecode survives) live beside the int64
# evaluator in tests/test_dmint_daa_offchain_onchain_differential.py. These are the
# builder-level refusals and their honest neighbours, through build_dmint_mint_tx.


def _mint(utxo: DmintContractUtxo, current_time: int):
    st = utxo.state
    kw: dict = {}
    if st.daa_mode is DaaMode.EPOCH:
        kw = {"epoch_length": 10, "max_adjustment_log2": 2}
    elif st.daa_mode is DaaMode.SCHEDULE:
        kw = {"schedule": ((100, 4),)}
    return build_dmint_mint_tx(utxo, b"\x00" * 8, _PKH, current_time, funding_utxo=_FUNDING, **kw)


def _mode_params(mode: DaaMode, **kw) -> DmintDeployParams:
    extra: dict = {}
    if mode is DaaMode.EPOCH:
        extra = {"difficulty": 32768, "epoch_length": 10, "max_adjustment_log2": 2}
    elif mode is DaaMode.SCHEDULE:
        extra = {"schedule": ((100, 4),)}
    extra.update(kw)
    return _params(mode, **extra)


def _reading_modes() -> list[DaaMode]:
    return sorted(DAA_MODES_READING_LAST_TIME, key=int)


class TestReadableLastTime:
    def test_the_predicate_is_minimality_plus_a_clear_sign_bit(self) -> None:
        assert min(n for n in range(1 << 24) if is_readable_last_time(n)) == 1 << 23
        assert is_readable_last_time(0x7FFFFFFF)
        # Minimal but NEGATIVE: the encoding rule alone says yes, the reader says no.
        for n in (0x80800000, 0xFFFFFFFF):
            assert is_minimal_4byte_scriptnum(n) and not is_readable_last_time(n)
        for n in (-1, 0, (1 << 23) - 1, 0x80000000, 1 << 32):
            assert not is_readable_last_time(n)


class TestTheMintBuilderNeverWritesAnUnreadableLastTime:
    @pytest.mark.parametrize("mode", _reading_modes())
    @pytest.mark.parametrize("bad", [0, 1, (1 << 23) - 1])
    def test_a_non_minimal_locktime_is_refused(self, mode: DaaMode, bad: int) -> None:
        # EPOCH at height 5 of 10: not a boundary, so only the WRITE guard can refuse this.
        utxo = _utxo(build_dmint_contract_script(_mode_params(mode, height=5)))
        with pytest.raises(ValidationError, match="not a minimally encoded script number"):
            _mint(utxo, bad)

    @pytest.mark.parametrize("mode", _reading_modes())
    def test_a_bit_31_locktime_is_refused(self, mode: DaaMode) -> None:
        utxo = _utxo(build_dmint_contract_script(_mode_params(mode, height=5)))
        with pytest.raises(ValidationError, match="0x7FFFFFFF"):
            _mint(utxo, 0xFFFFFFFF)

    @pytest.mark.parametrize("mode", _reading_modes())
    @pytest.mark.parametrize("edge", [1 << 23, 0x7FFFFFFF])
    def test_the_edges_of_the_readable_range_build(self, mode: DaaMode, edge: int) -> None:
        """The honest neighbours: 2**23 exactly (a BACKWARDS locktime here — the state says
        1.7e9 — which the v2 fragments and EPOCH clamp) and 0x7FFFFFFF exactly."""
        utxo = _utxo(build_dmint_contract_script(_mode_params(mode, height=5)))
        res = _mint(utxo, edge)
        assert res.updated_state.last_time == res.tx.locktime == edge

    @pytest.mark.parametrize("mode", [DaaMode.FIXED, DaaMode.SCHEDULE])
    def test_modes_that_never_read_it_still_accept_zero(self, mode: DaaMode) -> None:
        """Refusing 0 here would be a guard refusing valid work: neither fragment reads it."""
        utxo = _utxo(build_dmint_contract_script(_mode_params(mode, height=5)))
        assert _mint(utxo, 0).updated_state.last_time == 0


class TestAContractThatCanNoLongerBeMintedIsNotGroundAgainst:
    @pytest.mark.parametrize(
        ("mode", "version"),
        [
            (DaaMode.ASERT, DaaBytecodeVersion.V2),
            (DaaMode.ASERT, DaaBytecodeVersion.LEGACY),
            (DaaMode.LWMA, DaaBytecodeVersion.V2),
            (DaaMode.LWMA, DaaBytecodeVersion.LEGACY),
            (DaaMode.LWMA, DaaBytecodeVersion.LEGACY_LWMA_PREFLOOR),
        ],
    )
    @pytest.mark.parametrize("height", [0, 7])
    def test_asert_and_lwma_with_last_time_zero(self, mode: DaaMode, version: DaaBytecodeVersion, height: int) -> None:
        utxo = _utxo(_contract_script(_params(mode, height=height, last_time=0), version))
        with pytest.raises(ValidationError, match="can no longer be minted"):
            _mint(utxo, _LAST + 60)

    def test_epoch_at_a_boundary_with_last_time_zero(self) -> None:
        utxo = _utxo(build_dmint_contract_script(_mode_params(DaaMode.EPOCH, height=10, last_time=0)))
        with pytest.raises(ValidationError, match="can no longer be minted"):
            _mint(utxo, _LAST + 60)

    @pytest.mark.parametrize("height", [0, 5, 9, 11])
    def test_epoch_off_a_boundary_with_last_time_zero_still_mints(self, height: int) -> None:
        """The honest neighbour, and the recovery path: an EPOCH contract deployed with
        lastTime 0 (every pyrxd EPOCH deploy before 2026-09-22, and the conformance vector)
        does not read it off a boundary, and the next mint writes a readable one."""
        utxo = _utxo(build_dmint_contract_script(_mode_params(DaaMode.EPOCH, height=height, last_time=0)))
        res = _mint(utxo, _LAST + 60)
        assert is_readable_last_time(res.updated_state.last_time)

    @pytest.mark.parametrize("mode", [DaaMode.FIXED, DaaMode.SCHEDULE])
    def test_modes_that_never_read_it_mint_with_last_time_zero(self, mode: DaaMode) -> None:
        utxo = _utxo(build_dmint_contract_script(_mode_params(mode, height=10, last_time=0)))
        _mint(utxo, _LAST + 60)

    @pytest.mark.parametrize("last_time", [0x80800000, 0xFFFFFFFF])
    def test_a_negative_last_time_is_refused_not_mirrored(self, last_time: int) -> None:
        utxo = _utxo(build_dmint_contract_script(_params(DaaMode.ASERT, last_time=last_time)))
        with pytest.raises(ValidationError, match="bit 31 set"):
            _mint(utxo, _LAST)

    def test_negative_zero_is_non_minimal_and_reported_as_unmineable(self) -> None:
        utxo = _utxo(build_dmint_contract_script(_params(DaaMode.ASERT, last_time=0x80000000)))
        with pytest.raises(ValidationError, match="can no longer be minted"):
            _mint(utxo, _LAST)

    @pytest.mark.parametrize("last_time", [1 << 23, 0x7FFFFFFF])
    def test_the_edges_of_the_readable_range_mint(self, last_time: int) -> None:
        utxo = _utxo(build_dmint_contract_script(_params(DaaMode.ASERT, last_time=last_time)))
        _mint(utxo, _LAST)  # 0x7FFFFFFF -> a backwards locktime; ASERT-v2 clamps it


class TestBackwardsIsRefusedOnlyWhereTheBytecodeFails:
    def test_prefloor_lwma_backwards_is_refused_with_the_true_reason(self) -> None:
        utxo = _utxo(_contract_script(_params(DaaMode.LWMA), DaaBytecodeVersion.LEGACY_LWMA_PREFLOOR))
        with pytest.raises(ValidationError, match="does not floor the time delta") as exc:
            _mint(utxo, _LAST - 30)
        assert "overflow" not in str(exc.value)

    @pytest.mark.parametrize(
        ("mode", "version"),
        [
            (DaaMode.ASERT, DaaBytecodeVersion.V2),
            (DaaMode.ASERT, DaaBytecodeVersion.LEGACY),
            (DaaMode.LWMA, DaaBytecodeVersion.V2),
        ],
    )
    def test_backwards_builds_for_the_generations_that_clamp(self, mode: DaaMode, version: DaaBytecodeVersion) -> None:
        utxo = _utxo(_contract_script(_params(mode, half_life=240), version))
        assert _mint(utxo, _LAST - 3600).updated_state.last_time == _LAST - 3600


class TestLegacyLwmaNeverWritesTargetOne:
    @pytest.mark.parametrize("version", [DaaBytecodeVersion.LEGACY, DaaBytecodeVersion.LEGACY_LWMA_PREFLOOR])
    def test_a_zero_delta_is_refused(self, version: DaaBytecodeVersion) -> None:
        utxo = _utxo(_contract_script(_params(DaaMode.LWMA), version))
        assert compute_next_target_linear_legacy(utxo.state.target, _LAST, _LAST, 60) == 1
        with pytest.raises(ValidationError, match="target would be 1") as exc:
            _mint(utxo, _LAST)
        assert "later than the contract's last_time" in str(exc.value)

    def test_floored_legacy_backwards_is_refused_as_target_one(self) -> None:
        utxo = _utxo(_contract_script(_params(DaaMode.LWMA), DaaBytecodeVersion.LEGACY))
        with pytest.raises(ValidationError, match="target would be 1"):
            _mint(utxo, _LAST - 30)

    def test_a_target_already_below_target_time_says_no_time_helps(self) -> None:
        utxo = _utxo(_contract_script(_params(DaaMode.LWMA, difficulty=_MAX // 59), DaaBytecodeVersion.LEGACY))
        assert utxo.state.target < utxo.state.target_time
        with pytest.raises(ValidationError, match="no current_time avoids this"):
            _mint(utxo, _LAST + 60)

    def test_v2_lwma_at_a_zero_delta_is_an_ordinary_retarget(self) -> None:
        """The honest neighbour: the damped v2 formula moves the target 25%, not to 1."""
        utxo = _utxo(build_dmint_contract_script(_params(DaaMode.LWMA)))
        assert _mint(utxo, _LAST).updated_state.target > 1


class TestDeployRefusesANegativeLastTime:
    @pytest.mark.parametrize("mode", sorted(DAA_MODES_READING_DEPLOY_LAST_TIME, key=lambda m: m.value))
    @pytest.mark.parametrize("bad", [0x80800000, 0xFFFFFFFF])
    def test_refused_on_the_params_and_at_the_reveal(self, mode: DaaMode, bad: int) -> None:
        with pytest.raises(ValidationError, match="bit 31 set"):
            _v2_deploy_params(daa_mode=mode, last_time=bad)
        result = GlyphBuilder().prepare_dmint_deploy(_v2_deploy_params(daa_mode=mode))
        result.last_time = bad
        with pytest.raises(ValidationError, match="bit 31 set"):
            result.build_reveal_outputs("dd" * 32)

    @pytest.mark.parametrize("mode", sorted(DAA_MODES_READING_DEPLOY_LAST_TIME, key=lambda m: m.value))
    def test_0x7fffffff_is_accepted(self, mode: DaaMode) -> None:
        result = GlyphBuilder().prepare_dmint_deploy(_v2_deploy_params(daa_mode=mode, last_time=0x7FFFFFFF))
        state = DmintState.from_script(result.build_reveal_outputs("dd" * 32).contract_scripts[0])
        assert state.last_time == 0x7FFFFFFF
