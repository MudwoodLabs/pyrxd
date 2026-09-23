"""V1 dMint targets are pushed minimally, as Photonic builds them, and read at any width.

The defect: ``build_dmint_v1_state_script`` pushed the target as a fixed ``08`` + 8 bytes. The
V1 epilogue compares that item with the proof-of-work number as it was pushed
(``… 81 76 00 a2 69 a2 69``: OP_BIN2NUM normalises the hash window, never the target), and
Radiant reads an ``OP_GREATERTHANOREQUAL`` operand with minimal encoding required. Below
``2**55`` (difficulty 256 or more) an 8-byte push is not minimal, so every V1 contract pyrxd
deployed at such a difficulty aborts on every mint. Photonic's V1-era builder uses
``pushMinimal(target)``; so does pyrxd now.

The parser had the mirror defect: it demanded the ``08`` push, so it could not read the V1
contracts Photonic deployed at difficulty 256 or more — mainnet contracts, two of which
(pinned below) had been minted over a thousand times each.

Checked against evidence, not against pyrxd's own earlier output:

* a transcription of Photonic's V1-era ``dMintScript`` (``packages/lib/src/script.ts`` at
  :data:`PHOTONIC_V1_SHA`, its SHA256d/FIXED branch) and of the three ``@bitauth/libauth``
  3.0.0 helpers it calls, written from their source — not imported from pyrxd;
* mainnet V1 contract scripts, pinned byte for byte;
* the int64/MINIMALDATA evaluator in ``tests/test_dmint_daa_offchain_onchain_differential.py``.
"""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from pyrxd.glyph.builder import DmintV1DeployParams, GlyphBuilder
from pyrxd.glyph.dmint import (
    DmintContractUtxo,
    DmintMinerFundingUtxo,
    DmintState,
    build_dmint_mint_tx,
    build_dmint_v1_contract_script,
    difficulty_to_target,
)
from pyrxd.glyph.dmint.builders import _push_minimal, build_dmint_v1_state_script
from pyrxd.glyph.dmint.chain import _parse_dmint_script
from pyrxd.glyph.dmint.miner import _unreadable_target_reason
from pyrxd.glyph.dmint.types import MAX_SCRIPT_NUM, MAX_SHA256D_TARGET
from pyrxd.glyph.types import GlyphMetadata, GlyphProtocol, GlyphRef
from pyrxd.security.errors import ValidationError
from pyrxd.security.types import RADIANT_MAX_PHOTONS, Hex20
from tests.test_dmint_daa_offchain_onchain_differential import _Abort, _num, _run

#: Radiant-Core/Photonic-Wallet commit of the V1-era builder transcribed below (2026-02-13). Its
#: ``packages/lib/src/script.ts`` hashes to sha256 a2122feae7b115e58af0cdc2e8f7708f91e0d28586b3
#: 11ed4ee5f1ac42e02fa1 in the local clone it was read from. Current upstream is V2-only.
PHOTONIC_V1_SHA = "c8540a60fca39b93407e1037185600f2691cd06f"

# ═══════════════════════════════════════════════════════════════════════════════════════
# The transcription: script.ts @ PHOTONIC_V1_SHA, and the @bitauth/libauth 3.0.0 functions it
# imports (read from the published 3.0.0 tarball: build/lib/vm/instruction-sets/common/push.js,
# .../instruction-sets-utils.js, build/lib/format/number.js).
# ═══════════════════════════════════════════════════════════════════════════════════════


def _libauth_big_int_to_vm_number(n: int) -> bytes:
    """libauth ``bigIntToVmNumber``: little-endian magnitude, sign in the top bit, 0 → empty."""
    if n == 0:
        return b""
    out = bytearray()
    remaining = -n if n < 0 else n
    while remaining > 0:
        out.append(remaining & 0xFF)
        remaining >>= 8
    if out[-1] & 0x80:
        out.append(0x80 if n < 0 else 0x00)
    elif n < 0:
        out[-1] |= 0x80
    return bytes(out)


def _libauth_encode_data_push(data: bytes) -> bytes:
    """libauth ``encodeDataPush``: the minimal push — OP_0, OP_1..OP_16, OP_1NEGATE, direct, PUSHDATA."""
    if len(data) <= 75:
        if len(data) == 0:
            return b"\x00"
        if len(data) == 1:
            if data[0] != 0 and data[0] <= 16:
                return bytes([data[0] + 80])
            if data[0] == 129:
                return b"\x4f"
            return bytes([1]) + data
        return bytes([len(data)]) + data
    if len(data) <= 255:
        return bytes([76, len(data)]) + data
    raise AssertionError("no V1 state item reaches PUSHDATA2")


def _libauth_number_to_bin_uint32_le_clamped(n: int) -> bytes:
    """libauth ``numberToBinUint32LEClamped`` for the heights a V1 state can carry."""
    assert 0 <= n < 1 << 32
    return n.to_bytes(4, "little")


def _photonic_push_minimal(n: int) -> str:
    """script.ts ``pushMinimal`` at PHOTONIC_V1_SHA: ``encodeDataPush(bigIntToVmNumber(BigInt(n)))``."""
    return _libauth_encode_data_push(_libauth_big_int_to_vm_number(n)).hex()


def _photonic_push4bytes(n: int) -> str:
    """script.ts ``push4bytes``: ``encodeDataPush(numberToBinUint32LEClamped(n))``."""
    return _libauth_encode_data_push(_libauth_number_to_bin_uint32_le_clamped(n)).hex()


_PHOTONIC_MAX_TARGET = 0x7FFFFFFFFFFFFFFF  # script.ts: const MAX_TARGET = 0x7fffffffffffffffn
_PHOTONIC_PART_A = "5175c0c855797ea8597959797ea87e5a7a7e"
_PHOTONIC_PART_B = (
    "bc01147f77587f040000000088817600a269a269577ae500a069567ae600a06901d053797e0cdec0e9aa76e378e4a269e6"
    "9d7eaa76e47b9d547a818b76537a9c537ade789181547ae6939d635279cd01d853797e016a7e886778de519d547854807e"
    "c0eb557f777e5379ec78885379eac0e9885379cc519d75686d7551"
)


def _photonic_diff_to_target(difficulty: int) -> int:
    """script.ts ``dMintDiffToTarget``: ``MAX_TARGET / BigInt(difficulty)`` (BigInt division truncates)."""
    return _PHOTONIC_MAX_TARGET // difficulty


def _photonic_v1_script(
    height: int, contract_ref: str, token_ref: str, max_height: int, reward: int, target: int
) -> bytes:
    """script.ts ``dMintScript(...)`` with ``algorithm = 'sha256d'``, ``daaMode = 'fixed'`` — the V1 branch.

    ``contract_ref``/``token_ref`` are the 36-byte refs as the hex Photonic passes in (the
    little-endian wire form, "All ref inputs for script functions must be little-endian").
    """
    return bytes.fromhex(
        f"{_photonic_push4bytes(height)}d8{contract_ref}d0{token_ref}{_photonic_push_minimal(max_height)}"
        f"{_photonic_push_minimal(reward)}{_photonic_push_minimal(target)}bd{_PHOTONIC_PART_A}aa{_PHOTONIC_PART_B}"
    )


# ═══════════════════════════════════════════════════════════════════════════════════════
# Shared fixtures
# ═══════════════════════════════════════════════════════════════════════════════════════

_COMMIT = "dd" * 32
_C = GlyphRef(txid="aa" * 32, vout=1)
_T = GlyphRef(txid="aa" * 32, vout=0)

#: The difficulties the fix is checked at: every push-width boundary of MAX_SHA256D_TARGET // d
#: (8 → 7 bytes between 255 and 256), the OP_N region, and the extremes.
_DIFFICULTIES = [1, 2, 16, 17, 127, 128, 255, 256, 257, 5000, 2**32, MAX_SHA256D_TARGET]


def _v1_params(difficulty: int, **kw: object) -> DmintV1DeployParams:
    base: dict = {
        "metadata": GlyphMetadata(protocol=[GlyphProtocol.FT, GlyphProtocol.DMINT], name="t", ticker="T"),
        "owner_pkh": Hex20(bytes(20)),
        "num_contracts": 2,
        "max_height": 100,
        "reward_photons": 1000,
        "difficulty": difficulty,
    }
    base.update(kw)
    return DmintV1DeployParams(**base)


def _deployed(difficulty: int, **kw: object) -> tuple[bytes, ...]:
    """The V1 contract scripts the production deploy path puts in a reveal."""
    result = GlyphBuilder().prepare_dmint_deploy(_v1_params(difficulty, **kw))
    return result.build_reveal_outputs(_COMMIT).contract_scripts


def legacy_v1_contract_script(difficulty: int) -> bytes:
    """A V1 contract exactly as pyrxd built one before 2026-09-23: today's bytes with the target
    push swapped for the fixed ``08`` + 8-byte form the old builder always wrote."""
    target = MAX_SHA256D_TARGET // difficulty
    state = build_dmint_v1_state_script(0, _C, _T, max_height=100, reward=1000, target=target)
    minimal = _push_minimal(target)
    assert state.endswith(minimal)
    today = build_dmint_v1_contract_script(0, _C, _T, max_height=100, reward=1000, target=target)
    return state[: -len(minimal)] + b"\x08" + target.to_bytes(8, "little") + today[len(state) :]


def _funding(reward: int = 0) -> DmintMinerFundingUtxo:
    """A plain-RXD funding UTXO that covers ``reward`` plus a generous fee."""
    return DmintMinerFundingUtxo(
        txid="ee" * 32, vout=0, value=reward + 50_000_000, script=b"\x76\xa9\x14" + bytes(20) + b"\x88\xac"
    )


def _utxo(script: bytes) -> DmintContractUtxo:
    return DmintContractUtxo(txid="cc" * 32, vout=0, value=1, script=script, state=DmintState.from_script(script))


# ═══════════════════════════════════════════════════════════════════════════════════════
# 1. Parity with Photonic's V1 builder
# ═══════════════════════════════════════════════════════════════════════════════════════


class TestPhotonicV1Parity:
    @pytest.mark.parametrize("difficulty", _DIFFICULTIES)
    def test_the_production_deploy_path_builds_photonics_bytes(self, difficulty: int) -> None:
        target = _photonic_diff_to_target(difficulty)
        scripts = _deployed(difficulty)
        assert len(scripts) == 2
        for i, script in enumerate(scripts):
            cref = GlyphRef(txid=_COMMIT, vout=i + 1).to_bytes().hex()
            tref = GlyphRef(txid=_COMMIT, vout=0).to_bytes().hex()
            assert script == _photonic_v1_script(0, cref, tref, 100, 1000, target)
            assert DmintState.from_script(script).target == target

    @pytest.mark.parametrize(
        "target", [*range(1, 18), 127, 128, 255, 256, 0x7FFF, 0x8000, (1 << 55) - 1, 1 << 55, MAX_SHA256D_TARGET]
    )
    def test_every_push_width_matches_photonic(self, target: int) -> None:
        """OP_1..OP_16 for 1..16, then 1 to 8 bytes — each boundary, both sides."""
        ours = build_dmint_v1_contract_script(7, _C, _T, max_height=100, reward=1000, target=target)
        assert ours == _photonic_v1_script(7, _C.to_bytes().hex(), _T.to_bytes().hex(), 100, 1000, target)
        assert DmintState.from_script(ours).target == target

    @given(
        # heights a V1 contract can reach: its 4-byte height field tops out at 0x7FFFFFFF
        height=st.integers(min_value=0, max_value=0x7FFFFFFE),
        extra=st.integers(min_value=1, max_value=MAX_SCRIPT_NUM - 0x7FFFFFFF),
        reward=st.integers(min_value=1, max_value=RADIANT_MAX_PHOTONS),
        difficulty=st.integers(min_value=1, max_value=MAX_SHA256D_TARGET),
    )
    @settings(max_examples=1500, deadline=None)
    def test_any_parameters_match_photonic(self, height: int, extra: int, reward: int, difficulty: int) -> None:
        max_height = height + extra
        target = _photonic_diff_to_target(difficulty)
        ours = build_dmint_v1_contract_script(height, _C, _T, max_height=max_height, reward=reward, target=target)
        theirs = _photonic_v1_script(height, _C.to_bytes().hex(), _T.to_bytes().hex(), max_height, reward, target)
        assert ours == theirs
        parsed = DmintState.from_script(ours)
        assert (parsed.height, parsed.max_height, parsed.reward, parsed.target) == (height, max_height, reward, target)

    @pytest.mark.parametrize("difficulty", _DIFFICULTIES)
    def test_control_the_comparison_can_see_the_old_push(self, difficulty: int) -> None:
        """The old fixed 8-byte push equals Photonic's exactly where it is minimal (difficulty
        255 or less) and differs everywhere else — so the parity tests above would have failed on
        the old builder at every difficulty from 256 up."""
        target = MAX_SHA256D_TARGET // difficulty
        old = "08" + target.to_bytes(8, "little").hex()
        assert (old == _photonic_push_minimal(target)) is (difficulty <= 255)


# ═══════════════════════════════════════════════════════════════════════════════════════
# 2. The covenant can read what the deploy path writes
# ═══════════════════════════════════════════════════════════════════════════════════════


class TestTheCovenantReadsTheDeployedTarget:
    @pytest.mark.parametrize("difficulty", [1, 255, 256, 5000, MAX_SHA256D_TARGET])
    def test_the_epilogues_comparison_reads_the_deployed_target(self, difficulty: int) -> None:
        """Through ``prepare_dmint_deploy``: the target push is minimal, and the V1 epilogue's
        ``OP_GREATERTHANOREQUAL`` (target >= hash number), run by the MINIMALDATA evaluator on the
        push exactly as deployed, reads it and compares — at, below and above the target."""
        target = MAX_SHA256D_TARGET // difficulty
        for script in _deployed(difficulty):
            _state, push = _parse_dmint_script(script)
            assert push == _push_minimal(target)
            assert _unreadable_target_reason(script) is None
            cases = [(target, 1), (0, 1)] + ([(target + 1, 0)] if target < MAX_SCRIPT_NUM else [])
            for hash_num, verdict in cases:
                assert _num(_run(push + _push_minimal(hash_num) + b"\xa2", [], 0)[-1]) == verdict

    @pytest.mark.parametrize("difficulty", [256, 5000, MAX_SHA256D_TARGET])
    def test_control_the_old_push_aborts_that_comparison(self, difficulty: int) -> None:
        _state, push = _parse_dmint_script(legacy_v1_contract_script(difficulty))
        assert push[0] == 0x08
        with pytest.raises(_Abort, match="non-minimal script number"):
            _run(push + b"\x00" + b"\xa2", [], 0)

    @pytest.mark.parametrize("difficulty", [1, 256, 5000, MAX_SHA256D_TARGET])
    def test_a_deployed_contract_builds_a_mint(self, difficulty: int) -> None:
        """The mint funnel accepts what the deploy path builds, and recreates the contract the
        way the covenant does: ``04 <height + 1>`` then the spent state's bytes after the height."""
        script = _deployed(difficulty)[0]
        mint = build_dmint_mint_tx(_utxo(script), b"\x00" * 4, b"\x22" * 20, 0, funding_utxo=_funding())
        assert mint.contract_script == b"\x04" + (1).to_bytes(4, "little") + script[5:]


# ═══════════════════════════════════════════════════════════════════════════════════════
# 3. Mainnet V1 contracts, pinned
# ═══════════════════════════════════════════════════════════════════════════════════════

#: V1 contract scripts from Radiant mainnet (outpoint of the output that carries the script).
#: Each rebuilds byte for byte from its parsed fields at its own difficulty. The ones at
#: difficulty 256 or more have a target shorter than 8 bytes, which pyrxd's parser refused before
#: 2026-09-23. They are minted like any other: RABO and BTC sat at heights 1,404 and 2,495 when
#: read (2026-09-22), and the G22K contract was spent by its final mint.
_MAINNET_V1 = {
    # difficulty 22,000, 7-byte target; height 1 of max 2. Spent on mainnet by the contract's
    # final mint bc15c1119b44b51d8c3839472f7856b416c54d74c03dec5303ca7102e837a921.
    "G22K": (
        "c0a9acafb525dc5d2dc0f84304fb6a646192df48de7f4fa8b119386022f2231a:0",
        "0401000000d86b7eda989bff81f61dd7a9cfa9a171460b968f832dc0086d5859eb3d709d0bb601000000d06b7eda989bff81f61d"
        "d7a9cfa9a171460b968f832dc0086d5859eb3d709d0bb600000000525107169ba1e44c7d01",
    ),
    # difficulty 256: target 2**55 - 1, the widest 7-byte push. height 1,404.
    "RABO": (
        "8f3156923f40a3bf6b0ec501be4bed39d8bc12da197cfcecfc3dfa00127343e0:0",
        "047c050000d862902d045e8ae122c78f15be8da6b570494f8042c4505554f8b4fe607226369f03000000d062902d045e8ae122c7"
        "8f15be8da6b570494f8042c4505554f8b4fe607226369f0000000003f0b31a5107ffffffffffff7f",
    ),
    # difficulty 349, 7-byte target. height 2,495.
    "BTC": (
        "b6f5132d9354da163aaa2d2e765736f6c251cbb34d9a5dd62f46c5d4ae0201bf:0",
        "04bf090000d831ae75bb50ac2511ae0e393b77cf1fe37484754e93858651333a77422430a5fa04000000d031ae75bb50ac2511ae"
        "0e393b77cf1fe37484754e93858651333a77422430a5fa0000000002453301320734186b4620e45d",
    ),
    # difficulty 300, 7-byte target, max height 80,000,000. height 1.
    "GTC": (
        "b787634ae174fd6737bde4dbd296f697fa2a8b42bcebfdd541f8f0fa1e5502f4:0",
        "0401000000d8370a6e7bc8521f39afbec465d121b0a7e669685729071a6933ffbc3bc57e6c1301000000d0370a6e7bc8521f39af"
        "bec465d121b0a7e669685729071a6933ffbc3bc57e6c13000000000400b4c4045a073a6da0d3063a6d",
    ),
    # difficulty 1,000,000, 6-byte target; max height and reward 1 (OP_1). Undeployed height 0.
    "1": (
        "5644fc10a44cdd3127454b946e7f719d08f1b0d9d296722653efe724a386d684:0",
        "0400000000d886b417b12991b23aa7ec4476fb293ca8ffab42e80ee0c4ad89bcb8694a75853001000000d086b417b12991b23aa7"
        "ec4476fb293ca8ffab42e80ee0c4ad89bcb8694a75853000000000515106f65ad07b6308",
    ),
    # difficulty 100,000, 6-byte target; reward 1,000,000,000,000 photons. Height 0.
    "MPrawn": (
        "d6ed224f0d68fa84824a0cb84e7e951f84338c80d8e4ecc7d997d66d5de00a1b:0",
        "0400000000d8f58b0e4f13ba97986e8f23415cc04e747e5f60cad2b86665e62152e29cecd78c01000000d0f58b0e4f13ba97986e"
        "8f23415cc04e747e5f60cad2b86665e62152e29cecd78c00000000022c01060010a5d4e80006a38d23d6e253",
    ),
    # difficulty 241, 8-byte target; max height 696,969,000,000. Height 0.
    "$BRO": (
        "62c45716b39519ead11681116079cef1c54a59931772ffedfad320d30f16dba3:0",
        "0400000000d80b09600835fc6b11e2db3b44331378a8e3369dc70c634f3050486c3e85f417c901000000d00b09600835fc6b11e2"
        "db3b44331378a8e3369dc70c634f3050486c3e85f417c9000000000640f49646a20051088780f78780f78700",
    ),
    # difficulty 100, 8-byte target; max height 300,000,000. Height 2.
    "$RBG": (
        "67f34fe394897079adbbd130c15d082769136885ba24195af9073bb2cdb21e3c:0",
        "0402000000d8967c9662a3dd2ff511952b276dcdb6f08451ffc43452f009c98ac820e9edf66605000000d0967c9662a3dd2ff511"
        "952b276dcdb6f08451ffc43452f009c98ac820e9edf666000000000400a3e111014508ae47e17a14ae4701",
    ),
    # difficulty 1, 8-byte target; reward 888,888,888 photons. Height 3,183.
    "Pepe": (
        "a86ad22450bf3f778590a49e1d2c1e1e5f70e531f8ec87701dd2fde8f5d9c71e:0",
        "046f0c0000d816552c9361e96a777ab5303564d327446ef1d08bb4e065cd3b2aeb95e590d8bf18000000d016552c9361e96a777a"
        "b5303564d327446ef1d08bb4e065cd3b2aeb95e590d8bf0000000003385b0104385efb3408ffffffffffffff7f",
    ),
}
#: Every pinned contract is SHA256d; the epilogue is the same 145 bytes for all of them.
_V1_SHA256D_EPILOGUE = "bd" + _PHOTONIC_PART_A + "aa" + _PHOTONIC_PART_B


def _mainnet(name: str) -> bytes:
    return bytes.fromhex(_MAINNET_V1[name][1] + _V1_SHA256D_EPILOGUE)


class TestMainnetV1Contracts:
    @pytest.mark.parametrize("name", sorted(_MAINNET_V1))
    def test_each_rebuilds_byte_for_byte_and_is_mintable(self, name: str) -> None:
        script = _mainnet(name)
        st_ = DmintState.from_script(script)
        assert st_.is_v1
        difficulty = MAX_SHA256D_TARGET // st_.target
        assert _photonic_diff_to_target(difficulty) == st_.target  # its own difficulty gives its target
        rebuilt = build_dmint_v1_contract_script(
            st_.height, st_.contract_ref, st_.token_ref, st_.max_height, st_.reward, difficulty_to_target(difficulty)
        )
        assert rebuilt == script
        cref, tref = st_.contract_ref.to_bytes().hex(), st_.token_ref.to_bytes().hex()
        assert _photonic_v1_script(st_.height, cref, tref, st_.max_height, st_.reward, st_.target) == script
        assert _unreadable_target_reason(script) is None
        # The honest path of every new V1 check in the mint funnel: it builds. (Not for a
        # contract one mint from its end: pyrxd's V1 builder does not build the final mint.)
        if st_.height + 1 < st_.max_height:
            mint = build_dmint_mint_tx(_utxo(script), b"\x00" * 4, b"\x22" * 20, 0, funding_utxo=_funding(st_.reward))
            assert mint.contract_script == b"\x04" + (st_.height + 1).to_bytes(4, "little") + script[5:]

    def test_the_pins_span_the_widths_the_parser_used_to_refuse(self) -> None:
        """Non-vacuity: the pinned set includes targets narrower than 8 bytes, the ones the
        ``08``-only parser could not read, and 8-byte ones it could."""
        widths = {_parse_dmint_script(_mainnet(n))[1][0] for n in _MAINNET_V1}
        assert {0x06, 0x07, 0x08} <= widths

    @pytest.mark.parametrize("name", ["MPrawn", "1"])
    def test_undeployed_contracts_rebuild_through_the_production_deploy_path(self, name: str) -> None:
        """``DmintV1DeployParams`` → ``prepare_dmint_deploy`` → ``build_reveal_outputs`` rebuilds a
        height-0 mainnet contract exactly — including a value the old 0xFFFFFF "3-byte ceiling"
        refused (MPrawn's reward) and a 6-byte target. ($BRO, also at height 0, is not here: its
        max height is above 2**31, which pyrxd no longer deploys; ``tests/test_dmint_state_judgement.py``
        checks it is refused as a deploy and still parses and mints.)"""
        script = _mainnet(name)
        st_ = DmintState.from_script(script)
        assert st_.height == 0
        difficulty = MAX_SHA256D_TARGET // st_.target
        assert MAX_SHA256D_TARGET // difficulty == st_.target  # the declared difficulty round-trips
        params = _v1_params(
            difficulty, num_contracts=st_.contract_ref.vout, max_height=st_.max_height, reward_photons=st_.reward
        )
        result = GlyphBuilder().prepare_dmint_deploy(params)
        assert result.build_reveal_outputs(st_.token_ref.txid).contract_scripts[st_.contract_ref.vout - 1] == script

    @pytest.mark.parametrize(("name", "field"), [("$RBG", "max_height"), ("Pepe", "reward")])
    def test_values_above_the_old_3_byte_ceiling_are_accepted(self, name: str, field: str) -> None:
        st_ = DmintState.from_script(_mainnet(name))
        assert getattr(st_, field) > 0xFFFFFF
        _v1_params(1, max_height=st_.max_height, reward_photons=st_.reward)


# ═══════════════════════════════════════════════════════════════════════════════════════
# 4. A contract carrying a non-minimal target is refused as unmintable
# ═══════════════════════════════════════════════════════════════════════════════════════


class TestANonMinimalTargetIsRefused:
    @pytest.mark.parametrize("difficulty", [256, 5000, MAX_SHA256D_TARGET])
    def test_a_legacy_pyrxd_v1_contract_is_refused_by_the_mint_funnel(self, difficulty: int) -> None:
        legacy = legacy_v1_contract_script(difficulty)
        st_ = DmintState.from_script(legacy)  # it parses, to the number the covenant would see
        assert st_.target == MAX_SHA256D_TARGET // difficulty
        reason = _unreadable_target_reason(legacy)
        assert reason is not None and "can never be minted: its target is pushed as 08" in reason
        with pytest.raises(ValidationError, match="can never be minted: its target is pushed as 08"):
            build_dmint_mint_tx(_utxo(legacy), b"\x00" * 4, b"\x22" * 20, 0, funding_utxo=_funding())
        # The honest neighbour: the same parameters as the deploy path builds them today.
        today = build_dmint_v1_contract_script(0, _C, _T, max_height=100, reward=1000, target=st_.target)
        build_dmint_mint_tx(_utxo(today), b"\x00" * 4, b"\x22" * 20, 0, funding_utxo=_funding())

    @pytest.mark.parametrize("difficulty", [1, 100, 241, 255])
    def test_an_8_byte_push_that_is_minimal_is_not_refused(self, difficulty: int) -> None:
        """Where the old builder's push WAS minimal (difficulty 255 or less — the form most mainnet
        V1 contracts carry), it is the same bytes as today's, and nothing refuses it."""
        legacy = legacy_v1_contract_script(difficulty)
        assert legacy == build_dmint_v1_contract_script(
            0, _C, _T, max_height=100, reward=1000, target=MAX_SHA256D_TARGET // difficulty
        )
        assert _unreadable_target_reason(legacy) is None

    def test_a_v1_state_that_does_not_round_trip_is_refused_before_any_grind(self) -> None:
        """The V1 covenant copies the spent state's bytes after the height into the next state;
        pyrxd rebuilds them from the parsed fields. The mint builder refuses where the two could
        differ: a script whose numbers are pushed non-canonically (since 2026-09-23 refused
        first, by name, by the judgement every mint crosses: a non-minimal maxHeight is a number
        the covenant cannot read), and a DmintContractUtxo whose state does not match its script
        (the round-trip check)."""
        today = build_dmint_v1_contract_script(0, _C, _T, max_height=100, reward=1000, target=MAX_SHA256D_TARGET)
        i = today.index(_push_minimal(100), 79)
        padded = today[:i] + b"\x02\x64\x00" + today[i + 2 :]  # max_height 100 as 2 bytes
        assert DmintState.from_script(padded).max_height == 100
        assert _unreadable_target_reason(padded) is None  # the target is fine; the maxHeight is not
        with pytest.raises(ValidationError, match="its maxHeight is pushed as 026400"):
            build_dmint_mint_tx(_utxo(padded), b"\x00" * 4, b"\x22" * 20, 0, funding_utxo=_funding())
        other = build_dmint_v1_contract_script(0, _C, _T, max_height=101, reward=1000, target=MAX_SHA256D_TARGET)
        stale = DmintContractUtxo(txid="cc" * 32, vout=0, value=1, script=today, state=DmintState.from_script(other))
        with pytest.raises(ValidationError, match="does not match the state contract_utxo.script carries"):
            build_dmint_mint_tx(stale, b"\x00" * 4, b"\x22" * 20, 0, funding_utxo=_funding())
        build_dmint_mint_tx(_utxo(today), b"\x00" * 4, b"\x22" * 20, 0, funding_utxo=_funding())

    def test_a_negative_target_is_refused(self) -> None:
        """An 8-byte push with the top bit set is a negative number to the covenant (the parser
        used to read V1 targets unsigned, as 2**64 - 1 here). Readable, but no hash meets it."""
        today = build_dmint_v1_contract_script(0, _C, _T, max_height=100, reward=1000, target=MAX_SHA256D_TARGET)
        i = today.index(_push_minimal(MAX_SHA256D_TARGET), 79)
        negative = today[:i] + b"\x08" + b"\xff" * 8 + today[i + 9 :]
        assert DmintState.from_script(negative).target == -MAX_SHA256D_TARGET
        reason = _unreadable_target_reason(negative)
        assert reason is not None and "a negative number" in reason
        assert _unreadable_target_reason(today) is None

    def test_the_judgement_covers_v2_too(self) -> None:
        """The check is on the push, not on V1: a V2 state whose target push is not minimal is
        refused the same way (pyrxd never built one; the guard does not depend on who did)."""
        from pyrxd.glyph.dmint import DmintDeployParams, build_dmint_contract_script
        from pyrxd.glyph.dmint.builders import build_dmint_state_script

        params = DmintDeployParams(
            contract_ref=_C, token_ref=_T, max_height=100, reward=1000, difficulty=5000, last_time=1_700_000_000
        )
        honest = build_dmint_contract_script(params)
        state_len = len(build_dmint_state_script(params))
        minimal = _push_minimal(params.initial_target)
        assert honest[state_len - len(minimal) : state_len] == minimal
        padded = (
            honest[: state_len - len(minimal)]
            + b"\x08"
            + params.initial_target.to_bytes(8, "little")
            + honest[state_len:]
        )
        assert DmintState.from_script(padded).target == params.initial_target
        reason = _unreadable_target_reason(padded)
        assert reason is not None and "is not a minimally encoded script number" in reason
        assert _unreadable_target_reason(honest) is None
