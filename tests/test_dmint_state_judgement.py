"""What pyrxd judges from a dMint contract's script before it mints, deploys or estimates.

1. **The V1 height ceiling.** A V1 contract's height is a 4-byte field that every mint but the
   last rewrites as ``04 || NUM2BIN(height + 1, 4)``. ``2**31`` does not fit, so ``max_height =
   2**31`` is the largest whose last mint is reachable. ``DmintV1DeployParams`` and
   ``deploy-dmint`` accepted up to ``2**63 - 1``, and at height ``2**31 - 1`` with a larger
   ``max_height`` pyrxd judged the contract mintable and built a mint the covenant cannot accept.
   The boundary is checked here by running the V1 epilogue's own height bytes on a port of the
   vendored interpreter's ``OP_BIN2NUM`` / ``OP_NUM2BIN`` (``tests/vendor/radiant_core/``), and
   the port is pinned to that source text.
2. **A V1 height with bit 31 set.** The epilogue reads the height field with ``OP_BIN2NUM``, as a
   signed number; pyrxd read it unsigned, judged such a contract mintable, and built the wrong
   next height. No mint from a height below ``2**31`` writes one. The parser now refuses it.
3. **Bytes after the V1 epilogue.** The parser matched the 145-byte epilogue and ignored what
   followed; pyrxd then recreated the contract without those bytes, which the covenant rejects
   after the grind. The parser now refuses them.
"""

from __future__ import annotations

import dataclasses
from pathlib import Path

import pytest

from pyrxd.glyph.builder import DmintV1DeployParams
from pyrxd.glyph.dmint import (
    DmintContractUtxo,
    DmintMinerFundingUtxo,
    DmintState,
    build_dmint_mint_tx,
    build_dmint_v1_contract_script,
)
from pyrxd.glyph.dmint.builders import _V1_EPILOGUE_SUFFIX
from pyrxd.glyph.dmint.miner import _unmintable_reason
from pyrxd.glyph.dmint.types import MAX_SHA256D_TARGET, MAX_V1_MAX_HEIGHT
from pyrxd.glyph.types import GlyphMetadata, GlyphProtocol, GlyphRef
from pyrxd.security.errors import ValidationError
from pyrxd.security.types import Hex20
from tests.test_dmint_daa_offchain_onchain_differential import _cs_decode, _cs_encode, _is_minimal_num
from tests.test_dmint_v1_target_push import _mainnet

_C = GlyphRef(txid="aa" * 32, vout=1)
_T = GlyphRef(txid="aa" * 32, vout=0)
_VENDOR = Path(__file__).parent / "vendor" / "radiant_core"


def _v1(height: int, max_height: int, *, reward: int = 1000, target: int = 1 << 40) -> bytes:
    return build_dmint_v1_contract_script(height, _C, _T, max_height=max_height, reward=reward, target=target)


def _utxo(script: bytes) -> DmintContractUtxo:
    return DmintContractUtxo(txid="cc" * 32, vout=0, value=1, script=script, state=DmintState.from_script(script))


def _funding(reward: int = 0) -> DmintMinerFundingUtxo:
    return DmintMinerFundingUtxo(
        txid="ee" * 32, vout=0, value=reward + 50_000_000, script=b"\x76\xa9\x14" + bytes(20) + b"\x88\xac"
    )


def _mint(script: bytes):
    st = DmintState.from_script(script)
    return build_dmint_mint_tx(_utxo(script), b"\x00" * 4, b"\x22" * 20, 0, funding_utxo=_funding(st.reward))


# =====================================================================================
# 1. The V1 height ceiling
# =====================================================================================


class _Abort(Exception):
    pass


def _minimally_encode(data: bytes) -> bytes:
    """``CScriptNum::MinimallyEncode`` (``script.cpp``), line for line."""
    d = bytearray(data)
    if not d:
        return b""
    last = d[-1]
    if last & 0x7F:
        return bytes(d)
    if len(d) == 1:
        return b""
    if d[-2] & 0x80:
        return bytes(d)
    for i in range(len(d) - 1, 0, -1):
        if d[i - 1] != 0:
            if d[i - 1] & 0x80:
                d[i] = last
                i += 1
            else:
                d[i - 1] |= last
            return bytes(d[:i])
    return b""


def _bin2num(item: bytes) -> bytes:
    """``OP_BIN2NUM`` (``interpreter.cpp``): minimally encode, then require an in-range number."""
    n = _minimally_encode(item)
    if len(n) > 8 or not _is_minimal_num(n):
        raise _Abort("BIN2NUM: out of range")
    return n


def _num2bin(item: bytes, size: int) -> bytes:
    """``OP_NUM2BIN`` (``interpreter.cpp``): minimally encode; abort if that is longer than
    ``size``; otherwise pad with zeros, moving the sign bit to the new last byte."""
    raw = bytearray(_minimally_encode(item))
    if len(raw) > size:
        raise _Abort("IMPOSSIBLE_ENCODING")
    if len(raw) == size:
        return bytes(raw)
    sign = 0
    if raw:
        sign = raw[-1] & 0x80
        raw[-1] &= 0x7F
    while len(raw) < size - 1:
        raw.append(0)
    raw.append(sign)
    return bytes(raw)


def _num(item: bytes) -> int:
    if len(item) > 8 or not _is_minimal_num(item):
        raise _Abort("not a readable script number")
    return _cs_decode(item)


#: The epilogue's own bytes, sliced out of pyrxd's constant (each occurs exactly once):
#: ``OP_4 OP_ROLL OP_BIN2NUM OP_1ADD OP_DUP OP_3 OP_ROLL OP_NUMEQUAL`` computes isLast, and the
#: continue branch's ``OP_4 OP_OVER OP_4 OP_NUM2BIN OP_CAT`` writes the next height push.
_IS_LAST = bytes.fromhex("547a818b76537a9c")
_NEXT_HEIGHT = bytes.fromhex("547854807e")


def _run(code: bytes, stack: list[bytes]) -> list[bytes]:
    """The opcodes in the two slices above, over byte-string stack items (top = last)."""
    for op in code:
        if 0x51 <= op <= 0x60:
            stack.append(_cs_encode(op - 0x50))
        elif op == 0x7A:  # OP_ROLL
            n = _num(stack.pop())
            stack.append(stack.pop(-1 - n))
        elif op == 0x76:  # OP_DUP
            stack.append(stack[-1])
        elif op == 0x78:  # OP_OVER
            stack.append(stack[-2])
        elif op == 0x81:  # OP_BIN2NUM
            stack.append(_bin2num(stack.pop()))
        elif op == 0x8B:  # OP_1ADD
            stack.append(_cs_encode(_num(stack.pop()) + 1))
        elif op == 0x9C:  # OP_NUMEQUAL
            b, a = _num(stack.pop()), _num(stack.pop())
            stack.append(_cs_encode(int(a == b)))
        elif op == 0x80:  # OP_NUM2BIN
            size = _num(stack.pop())
            stack.append(_num2bin(stack.pop(), size))
        elif op == 0x7E:  # OP_CAT
            b, a = stack.pop(), stack.pop()
            stack.append(a + b)
        else:
            raise AssertionError(f"opcode {op:#x} is not ported")
    return stack


def _covenant_mint_step(height: int, max_height: int) -> str:
    """What the V1 epilogue does with the height on a mint: "final" (the burn branch, which
    writes no height), the next height push it requires, or the abort."""
    # the state items OP_4 OP_ROLL reaches: height under the refs, maxHeight and a stand-in on top
    stack = [height.to_bytes(4, "little"), b"C" * 36, b"T" * 36, _cs_encode(max_height), b"H" * 32]
    _run(_IS_LAST, stack)
    if _num(stack.pop()):
        return "final"
    try:
        return _run(_NEXT_HEIGHT, [stack[-1]])[-1].hex()  # the continue branch's OP_OVER reads h + 1
    except _Abort as exc:
        return f"abort: {exc}"


def _flat(path: Path) -> str:
    return " ".join(path.read_text(encoding="utf-8").split())


class TestTheV1HeightCeiling:
    def test_the_port_is_the_vendored_source(self) -> None:
        """The two opcodes the ceiling rests on, as the vendored interpreter has them: NUM2BIN
        aborts when the minimally encoded number is longer than the size asked for; BIN2NUM
        minimally encodes. If the vendored text moves, this fails rather than the port drifting."""
        interp, script = _flat(_VENDOR / "interpreter.cpp"), _flat(_VENDOR / "script.cpp")
        num2bin = interp[interp.index("case OP_NUM2BIN: {") :][:3000]
        assert (
            "CScriptNum::MinimallyEncode(rawnum); if (rawnum.size() > size) { // We definitively cannot. "
            "return set_error(serror, ScriptError::IMPOSSIBLE_ENCODING); }" in num2bin
        )
        assert "signbit = rawnum.back() & 0x80; rawnum[rawnum.size() - 1] &= 0x7f;" in num2bin
        bin2num = interp[interp.index("case OP_BIN2NUM: {") :][:1200]
        assert "CScriptNum::MinimallyEncode(n);" in bin2num
        assert "bool CScriptNum::MinimallyEncode(std::vector<uint8_t> &data) {" in script
        # the slices run above are the epilogue's own bytes, once each
        assert _V1_EPILOGUE_SUFFIX.count(_IS_LAST) == 1 and _V1_EPILOGUE_SUFFIX.count(_NEXT_HEIGHT) == 1

    def test_num2bin_fits_2_31_minus_1_in_4_bytes_and_not_2_31(self) -> None:
        assert _num2bin(_cs_encode(2**31 - 1), 4) == bytes.fromhex("ffffff7f")
        with pytest.raises(_Abort, match="IMPOSSIBLE_ENCODING"):
            _num2bin(_cs_encode(2**31), 4)
        # control: the port pads and carries the sign as the node does
        assert _num2bin(_cs_encode(5), 4) == bytes.fromhex("05000000")
        assert _num2bin(_cs_encode(-5), 4) == bytes.fromhex("05000080")

    def test_at_max_height_2_31_the_last_mint_is_reached(self) -> None:
        assert _covenant_mint_step(2**31 - 2, 2**31) == "04ffffff7f"
        assert _covenant_mint_step(2**31 - 1, 2**31) == "final"

    def test_above_it_the_contract_stops_at_2_31_minus_1(self) -> None:
        for max_height in (2**31 + 1, 696_969_000_000, 2**63 - 1):
            assert _covenant_mint_step(2**31 - 2, max_height) == "04ffffff7f"  # still mints up to here
            assert _covenant_mint_step(2**31 - 1, max_height) == "abort: IMPOSSIBLE_ENCODING"

    def test_the_constant_is_that_boundary(self) -> None:
        assert _covenant_mint_step(MAX_V1_MAX_HEIGHT - 1, MAX_V1_MAX_HEIGHT) == "final"
        assert _covenant_mint_step(MAX_V1_MAX_HEIGHT - 1, MAX_V1_MAX_HEIGHT + 1).startswith("abort")


def _v1_deploy(max_height: int) -> DmintV1DeployParams:
    return DmintV1DeployParams(
        metadata=GlyphMetadata(protocol=[GlyphProtocol.FT, GlyphProtocol.DMINT], name="t", ticker="T"),
        owner_pkh=Hex20(bytes(20)),
        num_contracts=1,
        max_height=max_height,
        reward_photons=1000,
        difficulty=1,
    )


class TestV1DeploysStopAt2_31:
    def test_2_31_deploys_and_one_more_is_refused(self) -> None:
        assert _v1_deploy(2**31).max_height == 2**31
        with pytest.raises(ValidationError, match=r"max_height must be <= 2,147,483,648 \(a V1 contract's height"):
            _v1_deploy(2**31 + 1)

    def test_bro_is_refused_as_a_deploy_but_parses_and_mints(self) -> None:
        """$BRO (max height 696,969,000,000) is a real mainnet V1 contract. pyrxd will not deploy
        another like it, and still reads and mints this one like any other contract."""
        bro = _mainnet("$BRO")
        st = DmintState.from_script(bro)
        assert st.max_height == 696_969_000_000 and st.height == 0
        with pytest.raises(ValidationError, match="max_height must be <= 2,147,483,648"):
            _v1_deploy(st.max_height)
        assert _unmintable_reason(bro) is None
        assert _mint(bro).contract_script == b"\x04" + (1).to_bytes(4, "little") + bro[5:]


class TestTheStuckHeightIsRefusedBeforeTheGrind:
    @pytest.mark.parametrize("max_height", [2**31 + 1, 696_969_000_000])
    def test_height_2_31_minus_1_with_mints_left_is_refused(self, max_height: int) -> None:
        stuck = _v1(2**31 - 1, max_height)
        reason = _unmintable_reason(stuck)
        assert reason is not None and "cannot be minted further" in reason
        with pytest.raises(ValidationError, match="cannot be minted further"):
            _mint(stuck)

    def test_bro_at_the_stuck_height_is_refused(self) -> None:
        bro = _mainnet("$BRO")
        stuck = b"\x04" + (2**31 - 1).to_bytes(4, "little") + bro[5:]
        assert DmintState.from_script(stuck).height == 2**31 - 1
        assert "cannot be minted further" in (_unmintable_reason(stuck) or "")

    def test_the_heights_either_side_are_not(self) -> None:
        """Honest neighbours: one height lower mints (and writes 2**31 - 1), and at max_height
        2**31 the same height is the last mint, which the covenant takes by the burn branch."""
        below = _v1(2**31 - 2, 2**31 + 1)
        assert _unmintable_reason(below) is None
        assert _mint(below).contract_script[:5] == bytes.fromhex("04ffffff7f")
        assert _unmintable_reason(_v1(2**31 - 1, 2**31)) is None

    @pytest.mark.parametrize("name", ["$BRO", "$RBG", "Pepe"])
    def test_mainnet_contracts_still_build_at_their_real_heights(self, name: str) -> None:
        script = _mainnet(name)
        st = DmintState.from_script(script)
        assert _unmintable_reason(script) is None
        assert _mint(script).contract_script == b"\x04" + (st.height + 1).to_bytes(4, "little") + script[5:]


def test_the_ceiling_and_the_difficulty_bound_are_independent() -> None:
    """Control: a deploy at the ceiling with the hardest difficulty is accepted (both bounds at
    their limit at once), so neither check is swallowing the other."""
    p = DmintV1DeployParams(
        metadata=GlyphMetadata(protocol=[GlyphProtocol.FT, GlyphProtocol.DMINT], name="t", ticker="T"),
        owner_pkh=Hex20(bytes(20)),
        num_contracts=1,
        max_height=2**31,
        reward_photons=1,
        difficulty=MAX_SHA256D_TARGET,
    )
    assert (p.max_height, p.difficulty) == (2**31, MAX_SHA256D_TARGET)


# =====================================================================================
# 2. A V1 height with bit 31 set
# =====================================================================================


def _with_height_field(script: bytes, field: int) -> bytes:
    return b"\x04" + field.to_bytes(4, "little") + script[5:]


class TestAV1HeightWithBit31Set:
    def test_2_31_minus_1_is_read(self) -> None:
        script = _with_height_field(_v1(0, 2**31), 0x7FFFFFFF)
        assert DmintState.from_script(script).height == 0x7FFFFFFF
        assert _unmintable_reason(script) is None  # at max_height 2**31 its next mint is the last

    @pytest.mark.parametrize("field", [0x80000000, 0x80000001, 0xFFFFFFFF])
    def test_bit_31_is_refused_where_the_script_is_read(self, field: int) -> None:
        """The covenant reads 0x80000000 as 0 and 0x80000001 as -1 (the port above agrees), so
        its next heights are 1 and 0; pyrxd would have written 0x80000001 and 0x80000002."""
        script = _with_height_field(_v1(0, 2**40), field)
        with pytest.raises(ValidationError, match="has bit 31 set"):
            DmintState.from_script(script)
        with pytest.raises(ValidationError, match="has bit 31 set"):
            _unmintable_reason(script)
        # the mint builder refuses it too, even handed a state built without the parser
        state = dataclasses.replace(DmintState.from_script(_v1(0, 2**40)), height=field)
        utxo = DmintContractUtxo(txid="cc" * 32, vout=0, value=1, script=script, state=state)
        with pytest.raises(ValidationError, match="has bit 31 set"):
            build_dmint_mint_tx(utxo, b"\x00" * 4, b"\x22" * 20, 0, funding_utxo=_funding(1000))

    def test_the_port_reads_those_fields_as_the_covenant_does(self) -> None:
        assert _bin2num(bytes.fromhex("00000080")) == b""  # 0
        assert _cs_decode(_bin2num(bytes.fromhex("01000080"))) == -1
        assert _covenant_mint_step(0x80000000, 2**40) == "0401000000"
        assert _covenant_mint_step(0x80000001, 2**40) == "0400000000"


# =====================================================================================
# 3. Bytes after the V1 epilogue
# =====================================================================================


class TestBytesAfterTheV1Epilogue:
    @pytest.mark.parametrize("tail", [b"\x61", b"\x51\x75"])  # OP_NOP; OP_1 OP_DROP
    def test_are_refused_where_the_script_is_read(self, tail: bytes) -> None:
        control = _v1(0, 100)
        script = control + tail
        with pytest.raises(ValidationError, match=r"byte\(s\) follow the 145-byte V1 code epilogue"):
            DmintState.from_script(script)
        with pytest.raises(ValidationError, match="follow the 145-byte V1 code epilogue"):
            _unmintable_reason(script)
        utxo = DmintContractUtxo(txid="cc" * 32, vout=0, value=1, script=script, state=DmintState.from_script(control))
        with pytest.raises(ValidationError, match="follow the 145-byte V1 code epilogue"):
            build_dmint_mint_tx(utxo, b"\x00" * 4, b"\x22" * 20, 0, funding_utxo=_funding(1000))

    def test_a_mainnet_contract_with_a_byte_appended_is_refused_and_without_it_is_not(self) -> None:
        rbg = _mainnet("$RBG")
        assert DmintState.from_script(rbg).is_v1 and _unmintable_reason(rbg) is None
        with pytest.raises(ValidationError, match="1 byte\\(s\\) follow"):
            DmintState.from_script(rbg + b"\x61")
