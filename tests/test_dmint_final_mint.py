"""The FINAL mint of a dMint contract: the one whose new height equals ``max_height``.

The covenant's output-validation block (V2 Part C, and the V1 epilogue, which carries the same
bytes here) branches on ``newHeight == maxHeight``. Every other mint takes the ELSE branch and
must recreate the contract; the final mint takes the IF branch, which instead requires the
output at the contract's index to be exactly ``d8 <contractRef> 6a`` — the contract singleton
pushed into an ``OP_RETURN`` — and requires the token ref in the FT reward outputs only.

Before this file pyrxd could not build that mint. The V2 builder recreated the contract at
height == max_height anyway, which the covenant rejects, and only after the whole PoW grind;
the V1 builder asked the state builder for a contract at that height and was refused as
"born-exhausted", so it built nothing at all.

What is proven where:

* here, offline — the shape ``build_dmint_mint_tx`` produces for the final mint, for V1 and V2;
  that the guards which exist to protect a RECREATED contract are not applied to a mint that
  recreates none, with each one's refusal still in force one mint earlier; and a transcription
  of the output-validation block's opcodes, run over the real contract bytes against the real
  transaction, accepting the final mint and rejecting the shape pyrxd used to build.
* on a real Radiant Core node — ``tests/test_dmint_v2_regtest_e2e.py::…final_mint…`` and
  ``tests/test_dmint_v1_regtest_e2e.py::TestDmintV1FinalMintOnConsensus``: the final mint is
  accepted and mined and the contract output is gone, a non-final mint through the same
  builder is still accepted, and the old shape with the SAME nonce is rejected on the script.
  The node is the ground truth; the transcription below is how a pull request sees this
  without one.
* against the chain — ``tests/test_dmint_final_mint_mainnet.py``: real mainnet V1 final mints,
  rebuilt from their real spent contracts, byte for byte. The transcription cannot catch a
  parse that is wrong in the same way for the builder and for itself (see
  :func:`_validate_outputs`); the chain's own transactions can.
"""

from __future__ import annotations

import dataclasses
import hashlib

import pytest
from test_dmint_daa_offchain_onchain_differential import _cs_decode, _cs_encode

from pyrxd.glyph.dmint import (
    DaaMode,
    DmintContractUtxo,
    DmintDeployParams,
    DmintMinerFundingUtxo,
    DmintState,
    build_dmint_contract_burn_script,
    build_dmint_contract_script,
    build_dmint_mint_tx,
    build_dmint_v1_contract_script,
    build_dmint_v1_ft_output_script,
)
from pyrxd.glyph.dmint.builders import _PART_A
from pyrxd.glyph.dmint.types import MAX_SHA256D_TARGET
from pyrxd.glyph.types import GlyphRef
from pyrxd.keys import PrivateKey
from pyrxd.script.script import Script
from pyrxd.security.errors import ContractExhaustedError, ValidationError

_CONTRACT_REF = GlyphRef(txid="c1" * 32, vout=1)
_TOKEN_REF = GlyphRef(txid="70" * 32, vout=0)
_REWARD = 1000
_LOCKTIME = 1_790_000_060
_OP_RETURN_MSG = b"pyrxd-final"


def _pkh() -> bytes:
    return bytes(PrivateKey().public_key().hash160())  # a fresh key, never hand-written material


_MINER_PKH = _pkh()
_FUNDING = DmintMinerFundingUtxo(
    txid="fa" * 32, vout=0, value=50_000_000, script=b"\x76\xa9\x14" + _pkh() + b"\x88\xac"
)


def _v2(height: int, max_height: int, *, value: int = 1, **kw) -> DmintContractUtxo:
    kw.setdefault("daa_mode", DaaMode.FIXED)
    kw.setdefault("difficulty", 1)
    kw.setdefault("last_time", 1_790_000_000)
    params = DmintDeployParams(
        contract_ref=_CONTRACT_REF,
        token_ref=_TOKEN_REF,
        max_height=max_height,
        reward=_REWARD,
        height=height,
        **kw,
    )
    script = build_dmint_contract_script(params)
    return DmintContractUtxo(txid="dd" * 32, vout=0, value=value, script=script, state=DmintState.from_script(script))


def _deployed_elsewhere(height: int, max_height: int, daa_mode: DaaMode, **fields) -> DmintContractUtxo:
    """A V2 contract carrying state values pyrxd's own deploy path need not accept.

    Nothing stops another deployer writing any value the state layout can hold, and the mint
    builder is what meets that contract. ``fields`` are set after ``DmintDeployParams`` is
    constructed, deliberately, so this keeps modelling such a contract whatever bounds the
    deploy parameters come to enforce.
    """
    params = DmintDeployParams(
        contract_ref=_CONTRACT_REF,
        token_ref=_TOKEN_REF,
        max_height=max_height,
        reward=_REWARD,
        difficulty=1,
        height=height,
        last_time=1_790_000_000,
        daa_mode=daa_mode,
    )
    for name, value in fields.items():
        object.__setattr__(params, name, value)
    script = build_dmint_contract_script(params)
    state = DmintState.from_script(script)
    for name, value in fields.items():
        assert getattr(state, name) == value, f"{name} did not reach the contract's state"
    return DmintContractUtxo(txid="dd" * 32, vout=0, value=1, script=script, state=state)


#: What each mode needs to deploy at all, and to be minted: EPOCH caps its target at 2**48
#: (difficulty 32768 and up), and EPOCH/SCHEDULE bake parameters the mint must restate.
_MODE_DEPLOY = {
    DaaMode.EPOCH: {"difficulty": 1 << 15, "epoch_length": 2016, "max_adjustment_log2": 2},
    DaaMode.SCHEDULE: {"schedule": ((0, 1 << 40),)},
}
_MODE_MINT = {
    DaaMode.EPOCH: {"epoch_length": 2016, "max_adjustment_log2": 2},
    DaaMode.SCHEDULE: {"schedule": ((0, 1 << 40),)},
}


def _v1(height: int, max_height: int, *, value: int = 1) -> DmintContractUtxo:
    script = build_dmint_v1_contract_script(
        height=height,
        contract_ref=_CONTRACT_REF,
        token_ref=_TOKEN_REF,
        max_height=max_height,
        reward=_REWARD,
        target=MAX_SHA256D_TARGET,
    )
    return DmintContractUtxo(txid="dd" * 32, vout=0, value=value, script=script, state=DmintState.from_script(script))


def _mint(contract: DmintContractUtxo, **kw):
    v1 = contract.state.is_v1
    kw.setdefault("current_time", 0 if v1 else _LOCKTIME)
    return build_dmint_mint_tx(
        contract,
        b"\x00" * (4 if v1 else 8),
        _MINER_PKH,
        funding_utxo=_FUNDING,
        op_return_msg=_OP_RETURN_MSG,
        **kw,
    )


def _outs(result) -> list[tuple[bytes, int]]:
    return [(o.locking_script.serialize(), o.satoshis) for o in result.tx.outputs]


_BUILDERS = pytest.mark.parametrize("make", [_v1, _v2], ids=["V1", "V2"])

#: The burn, spelled here independently of the builder under test: the IF branch assembles
#: ``0xd8 || <the contract ref from the state> || 0x6a`` and OP_EQUALVERIFYs output 0 against it.
_BURN = b"\xd8" + _CONTRACT_REF.to_bytes() + b"\x6a"


# ---------------------------------------------------------------------------------------------
# The shape
# ---------------------------------------------------------------------------------------------


class TestTheFinalMintBuildsTheBurn:
    @_BUILDERS
    def test_output_zero_is_the_contract_burn(self, make) -> None:
        res = _mint(make(1, 2))
        assert res.is_final_mint
        assert _outs(res)[0] == (_BURN, 0)
        assert res.contract_script == _BURN == build_dmint_contract_burn_script(_CONTRACT_REF)
        assert res.updated_state.height == 2 and res.updated_state.is_exhausted

    @_BUILDERS
    def test_the_honest_neighbour_one_mint_earlier_recreates_the_contract(self, make) -> None:
        contract = make(0, 2)
        res = _mint(contract)
        assert not res.is_final_mint and not contract.state.next_mint_is_final
        script, value = _outs(res)[0]
        assert value == 1 and script == res.contract_script
        recreated = DmintState.from_script(script)
        assert (recreated.height, recreated.max_height) == (1, 2)
        assert recreated.next_mint_is_final

    @_BUILDERS
    def test_the_reward_and_op_return_are_those_of_any_other_mint(self, make) -> None:
        final, earlier = _outs(_mint(make(1, 2))), _outs(_mint(make(0, 2)))
        ft = build_dmint_v1_ft_output_script(_MINER_PKH, _TOKEN_REF)
        assert final[1] == earlier[1] == (ft, _REWARD)
        assert final[2] == earlier[2] and final[2][0].startswith(b"\x6a")
        assert len(final) == len(earlier) == 4

    @_BUILDERS
    def test_the_token_ref_is_in_the_reward_only_and_the_contract_ref_in_the_burn_only(self, make) -> None:
        outs = _outs(_mint(make(1, 2)))
        assert [i for i, (s, _) in enumerate(outs) if _TOKEN_REF.to_bytes() in s] == [1]
        assert [i for i, (s, _) in enumerate(outs) if _CONTRACT_REF.to_bytes() in s] == [0]

    @_BUILDERS
    def test_the_contract_photon_goes_to_change(self, make) -> None:
        for contract in (make(1, 2), make(0, 2)):
            res = _mint(contract)
            spent = contract.value + _FUNDING.value
            assert sum(v for _, v in _outs(res)) + res.fee == spent

    @_BUILDERS
    def test_a_max_height_one_contract_is_final_on_its_first_mint(self, make) -> None:
        res = _mint(make(0, 1))
        assert res.is_final_mint and _outs(res)[0] == (_BURN, 0)

    @_BUILDERS
    def test_a_contract_already_at_max_height_is_still_refused(self, make) -> None:
        contract = make(0, 2)
        exhausted = dataclasses.replace(contract, state=dataclasses.replace(contract.state, height=2))
        with pytest.raises(ContractExhaustedError, match="exhausted"):
            _mint(exhausted)

    @pytest.mark.parametrize("mode", list(DaaMode), ids=lambda m: m.name)
    def test_every_v2_final_mint_sets_nlocktime_to_current_time(self, mode) -> None:
        """pyrxd sets nLockTime on every V2 mint, the final one included, in every mode. Which
        modes' covenants READ it on the final mint is a different question, derived from the
        bytes in :meth:`TestWhichModesReadTheLocktimeOnTheFinalMint`."""
        res = _mint(_v2(1, 2, daa_mode=mode, **_MODE_DEPLOY.get(mode, {})), **_MODE_MINT.get(mode, {}))
        assert res.is_final_mint and res.tx.locktime == _LOCKTIME


class TestWhichModesReadTheLocktimeOnTheFinalMint:
    """The final mint's Part C takes the burn branch, which does not execute OP_TXLOCKTIME (the
    continue branch does: it rebuilds the next lastTime from it). So on the final mint only
    Part B's retarget fragment can read the locktime. This is derived from each mode's bytes, so
    the comment beside the locktime in ``build_dmint_mint_tx`` cannot drift from them unseen."""

    def test_part_b_executes_op_txlocktime_only_in_the_adaptive_modes(self) -> None:
        reads: dict[DaaMode, set[int]] = {}
        for mode in DaaMode:
            code = _code(_v2(1, 2, daa_mode=mode, **_MODE_DEPLOY.get(mode, {})).script)
            part_b = code[len(_PART_A) + 1 : code.index(_OUTPUT_BLOCK_MARKER)]  # after Part A + powHashOp
            depth, depths = 0, set()
            for op, _data, _after in _walk(part_b):
                depth += {0x63: 1, 0x64: 1, 0x68: -1}.get(op, 0)
                if op == 0xC5:
                    depths.add(depth)
            reads[mode] = depths
        # {IF depth of each OP_TXLOCKTIME}: 0 = on every mint; 1 = behind EPOCH's boundary gate.
        assert reads == {
            DaaMode.FIXED: set(),
            DaaMode.SCHEDULE: set(),
            DaaMode.ASERT: {0},
            DaaMode.LWMA: {0},
            DaaMode.EPOCH: {1},
        }

    def test_the_burn_branch_does_not_execute_it_and_the_continue_branch_does(self) -> None:
        final, earlier = _v2(1, 2), _v2(0, 2)
        assert 0xC5 not in _validate_outputs(final, _mint(final))
        assert 0xC5 in _validate_outputs(earlier, _mint(earlier))


# ---------------------------------------------------------------------------------------------
# The guards that protect a RECREATED contract, and only those, are skipped
# ---------------------------------------------------------------------------------------------


class TestOnlyTheRecreatedContractGuardsAreSkipped:
    """Each guard below exists for the contract output a mint recreates. The final mint
    recreates none, so refusing it for these reasons refuses a mint the covenant accepts. Each
    is paired with the same inputs one mint earlier, where the refusal must still fire."""

    @_BUILDERS
    def test_a_carrier_other_than_one_photon(self, make) -> None:
        with pytest.raises(ValidationError, match="1-photon singleton"):
            _mint(make(0, 2, value=5))
        res = _mint(make(1, 2, value=5))
        assert _outs(res)[0] == (_BURN, 0)
        assert sum(v for _, v in _outs(res)) + res.fee == 5 + _FUNDING.value

    @pytest.mark.parametrize("mode", [DaaMode.ASERT, DaaMode.LWMA])
    def test_a_locktime_whose_lastTime_the_next_retarget_could_not_read(self, mode) -> None:
        with pytest.raises(ValidationError, match="is below 2\\*\\*23"):
            _mint(_v2(0, 2, daa_mode=mode), current_time=1_000_000)
        res = _mint(_v2(1, 2, daa_mode=mode), current_time=1_000_000)
        assert res.is_final_mint and res.tx.locktime == 1_000_000

    def test_a_retarget_to_target_1(self) -> None:
        sched = ((0, 1),)  # from height 0 on, the schedule's target is 1
        with pytest.raises(ValidationError, match="target would be 1"):
            _mint(_v2(0, 2, daa_mode=DaaMode.SCHEDULE, schedule=sched), schedule=sched)
        res = _mint(_v2(1, 2, daa_mode=DaaMode.SCHEDULE, schedule=sched), schedule=sched)
        assert res.is_final_mint and _outs(res)[0] == (_BURN, 0)

    def test_what_the_covenant_still_evaluates_is_still_checked(self) -> None:
        """Part B runs on the final mint too, so its inputs are still verified before a grind."""
        c = _v2(1, 2, daa_mode=DaaMode.ASERT, half_life=240)
        with pytest.raises(ValidationError, match="bakes half_life=240"):
            _mint(c, half_life=3600)
        with pytest.raises(ValidationError, match="SCHEDULE mint requires the schedule"):
            _mint(_v2(1, 2, daa_mode=DaaMode.SCHEDULE, schedule=((0, 1),)))


class TestPartBStillRefusesTheFinalMint:
    """Part B runs before Part C on every spend, so a retarget the contract cannot evaluate fails
    the final mint exactly as it fails any other: the final branch drops Part B's result, but an
    abort inside Part B has already failed the script. pyrxd keeps both refusals below on the
    final mint, before any grind. Each is paired with the honest final mint beside it.

    Until these tests, either one could be removed from the final mint (the retarget skipped,
    or the spent state's lastTime left unchecked) with no test failing.
    """

    #: current_time - last_time on every mint here: _LOCKTIME - 1_790_000_000.
    _TIME_DELTA = 60

    def test_a_retarget_whose_arithmetic_leaves_int64(self) -> None:
        """ASERT's fragment computes ``(timeDelta - targetTime) * RADIX`` (RADIX = 2**16), and
        the covenant aborts outside ``[-(2**63 - 1), 2**63 - 1]``. With timeDelta = 60 that is
        reached exactly at ``targetTime = 2**47 + 60``."""
        edge = 2**47 + self._TIME_DELTA
        for target_time in (edge, 2**63 - 1):
            contract = _deployed_elsewhere(1, 2, DaaMode.ASERT, target_time=target_time)
            assert contract.state.next_mint_is_final
            with pytest.raises(ValidationError, match=r"OP_MUL \(excess \* RADIX\) would leave the int64 range"):
                _mint(contract)
        # One second of targetTime below the edge the product fits, and the final mint is built.
        res = _mint(_deployed_elsewhere(1, 2, DaaMode.ASERT, target_time=edge - 1))
        assert res.is_final_mint and _outs(res)[0] == (_BURN, 0)

    @pytest.mark.parametrize("mode", [DaaMode.ASERT, DaaMode.LWMA], ids=lambda m: m.name)
    def test_a_state_last_time_the_retarget_cannot_read(self, mode) -> None:
        """ASERT and LWMA read the spent state's lastTime on every mint, the final one included,
        and ``04 00000000`` is not a minimally encoded script number."""
        with pytest.raises(ValidationError, match="can no longer be minted"):
            _mint(_v2(1, 2, daa_mode=mode, last_time=0))
        with pytest.raises(ValidationError, match="can no longer be minted"):
            _mint(_v2(0, 2, daa_mode=mode, last_time=0))  # and one mint earlier, as before
        res = _mint(_v2(1, 2, daa_mode=mode))  # the honest final mint: a readable lastTime
        assert res.is_final_mint and _outs(res)[0] == (_BURN, 0)

    @pytest.mark.parametrize("mode", [DaaMode.FIXED, DaaMode.SCHEDULE], ids=lambda m: m.name)
    def test_a_mode_that_never_reads_last_time_is_not_refused_for_it(self, mode) -> None:
        """The lastTime refusal is scoped to the modes whose fragment reads it."""
        contract = _v2(1, 2, daa_mode=mode, last_time=0, **_MODE_DEPLOY.get(mode, {}))
        res = _mint(contract, **_MODE_MINT.get(mode, {}))
        assert res.is_final_mint and _outs(res)[0] == (_BURN, 0)


# ---------------------------------------------------------------------------------------------
# The output-validation block, transcribed, run against the real bytes
# ---------------------------------------------------------------------------------------------
#
# Opcode semantics transcribed from tests/vendor/radiant_core/interpreter.cpp (v3.1.2):
# OP_REFOUTPUTCOUNT_OUTPUTS, OP_CODESCRIPTHASHVALUESUM_OUTPUTS,
# OP_CODESCRIPTHASHOUTPUTCOUNT_UTXOS/_OUTPUTS, OP_CODESCRIPTBYTECODE_UTXO/_OUTPUT,
# OP_STATESCRIPTBYTECODE_OUTPUT/_UTXO, OP_OUTPUTVALUE, OP_OUTPUTBYTECODE, NUM2BIN, BIN2NUM;
# push refs per script.cpp (0xd0 and 0xd8 register one; the code script starts after 0xbd).
# ONE ASSUMPTION the vendored files cannot settle: a code-script hash is HASH256 of the bytes
# after the state separator, the hash the FT covenant computes with
# ``OP_CODESCRIPTBYTECODE_UTXO OP_HASH256`` and compares against these same opcodes. That is
# why the node tests exist; this is what a pull request sees without a node.

_OUTPUT_BLOCK_MARKER = bytes.fromhex("577ae500a069567ae600a069")


class _Abort(Exception):
    pass


def _h256(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def _walk(script: bytes):
    i = 0
    while i < len(script):
        op = script[i]
        i += 1
        data = b""
        if 1 <= op <= 0x4B:
            data, i = script[i : i + op], i + op
        elif op == 0x4C:
            n = script[i]
            data, i = script[i + 1 : i + 1 + n], i + 1 + n
        elif op == 0x4D:
            n = int.from_bytes(script[i : i + 2], "little")
            data, i = script[i + 2 : i + 2 + n], i + 2 + n
        elif op in (0xD0, 0xD1, 0xD2, 0xD3, 0xD8):
            data, i = script[i : i + 36], i + 36
        yield op, data, i


def _code_start(script: bytes) -> int:
    return next((after for op, _, after in _walk(script) if op == 0xBD), 0)


def _code(script: bytes) -> bytes:
    return script[_code_start(script) :]


def _state(script: bytes) -> bytes:
    i = _code_start(script)
    return script[: i - 1] if i else b""


def _push_refs(script: bytes) -> set[bytes]:
    return {d for op, d, _ in _walk(script) if op in (0xD0, 0xD8)}


def _num(b: bytes) -> int:
    if len(b) > 8:
        raise _Abort("number > 8 bytes")
    if b and (b[-1] & 0x7F) == 0 and (len(b) == 1 or not (b[-2] & 0x80)):
        raise _Abort(f"non-minimal number {b.hex()}")
    return _cs_decode(b)


def _run(
    code: bytes, stack: list, alt: list, ins: list[bytes], outs: list[tuple[bytes, int]], locktime: int
) -> list[int]:
    """Execute ``code``; return the opcodes it executed (so a caller can see WHICH branch ran)."""
    executed: list[int] = []
    ex: list[bool] = []

    def push(n: int) -> None:
        stack.append(_cs_encode(n))

    i = 0
    while i < len(code):
        op = code[i]
        i += 1
        data = None
        if 1 <= op <= 0x4B:
            data, i = code[i : i + op], i + op
        elif op == 0x4C:
            n = code[i]
            data, i = code[i + 1 : i + 1 + n], i + 1 + n
        if op in (0x63, 0x64):
            ex.append((_num(stack.pop()) != 0) if all(ex) else False)
            continue
        if op == 0x67:
            ex[-1] = not ex[-1]
            continue
        if op == 0x68:
            ex.pop()
            continue
        if not all(ex):
            continue
        executed.append(op)
        if data is not None:
            stack.append(data)
            continue
        if op == 0x00:
            stack.append(b"")
        elif 0x51 <= op <= 0x60:
            push(op - 0x50)
        elif op == 0x69:
            if _num(stack.pop()) == 0:
                raise _Abort(f"OP_VERIFY at {i - 1}")
        elif op == 0x6B:
            alt.append(stack.pop())
        elif op == 0x6C:
            stack.append(alt.pop())
        elif op == 0x6D:
            del stack[-2:]
        elif op == 0x75:
            stack.pop()
        elif op == 0x76:
            stack.append(stack[-1])
        elif op == 0x77:
            del stack[-2]
        elif op == 0x78:
            stack.append(stack[-2])
        elif op == 0x79:
            n = _num(stack.pop())
            stack.append(stack[-1 - n])
        elif op == 0x7A:
            n = _num(stack.pop())
            stack.append(stack.pop(-1 - n))
        elif op == 0x7B:
            stack[-3], stack[-2], stack[-1] = stack[-2], stack[-1], stack[-3]
        elif op == 0x7C:
            stack[-1], stack[-2] = stack[-2], stack[-1]
        elif op == 0x7E:
            b = stack.pop()
            stack.append(stack.pop() + b)
        elif op == 0x7F:
            n, x = _num(stack.pop()), stack.pop()
            if not 0 <= n <= len(x):
                raise _Abort("OP_SPLIT range")
            stack.extend((x[:n], x[n:]))
        elif op == 0x80:
            size, raw = _num(stack.pop()), bytearray(_cs_encode(_cs_decode(stack.pop())))
            if len(raw) > size:
                raise _Abort("NUM2BIN impossible encoding")
            if len(raw) < size:
                sign = 0
                if raw:
                    sign, raw[-1] = raw[-1] & 0x80, raw[-1] & 0x7F
                raw += b"\x00" * (size - 1 - len(raw)) + bytes([sign])
            stack.append(bytes(raw))
        elif op == 0x81:
            stack.append(_cs_encode(_cs_decode(stack.pop())))
        elif op == 0x82:
            push(len(stack[-1]))  # OP_SIZE leaves its operand in place
        elif op in (0x87, 0x88):
            b, a = stack.pop(), stack.pop()
            if op == 0x88 and a != b:
                raise _Abort(f"OP_EQUALVERIFY at {i - 1}")
            if op == 0x87:
                push(int(a == b))
        elif op == 0x8B:
            push(_num(stack.pop()) + 1)
        elif op == 0x91:
            push(int(_num(stack.pop()) == 0))
        elif op in (0x93, 0x9C, 0x9D, 0xA0, 0xA1, 0xA2):
            b, a = _num(stack.pop()), _num(stack.pop())
            if op == 0x9D:
                if a != b:
                    raise _Abort(f"OP_NUMEQUALVERIFY at {i - 1}: {a} != {b}")
                continue
            push({0x93: a + b, 0x9C: int(a == b), 0xA0: int(a > b), 0xA1: int(a <= b), 0xA2: int(a >= b)}[op])
        elif op == 0xAA:
            stack.append(_h256(stack.pop()))
        elif op == 0xC0:
            push(0)  # OP_INPUTINDEX: the contract is input 0
        elif op == 0xC5:
            push(locktime)
        elif op == 0xCC:
            push(outs[_num(stack.pop())][1])
        elif op == 0xCD:
            stack.append(outs[_num(stack.pop())][0])
        elif op == 0xDE:
            ref = stack.pop()
            push(sum(1 for s, _ in outs if ref in _push_refs(s)))
        elif op == 0xE4:
            h = stack.pop()
            push(sum(v for s, v in outs if _h256(_code(s)) == h))
        elif op == 0xE5:
            h = stack.pop()
            push(sum(1 for s in ins if _h256(_code(s)) == h))
        elif op == 0xE6:
            h = stack.pop()
            push(sum(1 for s, _ in outs if _h256(_code(s)) == h))
        elif op == 0xE9:
            stack.append(_code(ins[_num(stack.pop())]))
        elif op == 0xEA:
            stack.append(_code(outs[_num(stack.pop())][0]))
        elif op == 0xEB:
            stack.append(_state(ins[_num(stack.pop())]))
        elif op == 0xEC:
            stack.append(_state(outs[_num(stack.pop())][0]))
        else:
            raise _Abort(f"opcode {op:#x} is not transcribed")  # fail loudly, never skip
    if stack[-1:] != [_cs_encode(1)]:
        raise _Abort(f"did not end on TRUE: {[x.hex() for x in stack]}")
    return executed


def _validate_outputs(contract: DmintContractUtxo, res) -> list[int]:
    """Run the contract's own output-validation block over ``res.tx``'s outputs, from the stack
    Parts A/B leave it: ``[inHash, outHash, outIdx, height, cRef, tRef, maxHeight, reward]``,
    plus the retargeted target on the alt stack for V2 (a FIXED target is unchanged).

    What this can NOT catch, by construction:

    * It starts at the output-validation marker (``577ae500a069…``). Parts A and B are not
      executed; the stack above is what they WOULD leave, assembled here. The PoW check, the
      retarget and anything else before the marker are outside it.
    * ``height``, ``maxHeight``, the refs and the reward are seeded from ``contract.state``,
      the state pyrxd parsed, not read out of the script by the covenant's own pushes. The
      builder decides the final mint from that same parsed state, so the block's ``isFinal``
      agrees with the builder's by construction: a parse that got height or maxHeight wrong
      would move both together, and this would still accept.

    What can catch that is a comparison with transactions the chain accepted:
    ``tests/test_dmint_final_mint_mainnet.py`` rebuilds real mainnet final mints from their
    real spent contracts and compares the bytes.
    """
    code = _code(contract.script)
    assert code.count(_OUTPUT_BLOCK_MARKER) == 1, "the output-validation block was not found exactly once"
    block = code[code.index(_OUTPUT_BLOCK_MARKER) :]
    st, outs = contract.state, _outs(res)
    height = st.height.to_bytes(4, "little") if st.is_v1 else _cs_encode(st.height)
    stack = [
        _h256(_code(_FUNDING.script)),  # the scriptSig's inputHash: the funding input's code
        _h256(_code(outs[2][0])),  # the scriptSig's outputHash: the OP_RETURN the preimage binds
        b"",  # outIdx: the scriptSig's OP_0
        height,
        st.contract_ref.to_bytes(),
        st.token_ref.to_bytes(),
        _cs_encode(st.max_height),
        _cs_encode(st.reward),
    ]
    alt = [] if st.is_v1 else [_cs_encode(st.target)]
    return _run(block, stack, alt, [contract.script, _FUNDING.script], outs, res.tx.locktime)


class TestTheOutputValidationBlockAcceptsIt:
    @_BUILDERS
    def test_the_final_mint_takes_the_burn_branch_and_is_accepted(self, make) -> None:
        contract = make(1, 2)
        executed = _validate_outputs(contract, _mint(contract))
        assert 0xCD in executed and 0xEC not in executed  # OUTPUTBYTECODE ran; the rebuild did not

    @_BUILDERS
    def test_the_non_final_control_takes_the_continue_branch_and_is_accepted(self, make) -> None:
        contract = make(0, 2)
        executed = _validate_outputs(contract, _mint(contract))
        assert 0xEC in executed and 0xCD not in executed

    def test_the_shape_pyrxd_used_to_build_is_rejected(self, monkeypatch) -> None:
        """The V2 builder used to recreate the contract at height == max_height on the final
        mint. Rebuilt that way, the block rejects it: the token ref now sits in one output
        more than the final branch allows."""
        contract = _v2(1, 2)
        monkeypatch.setattr(DmintState, "next_mint_is_final", property(lambda self: False))
        old = _mint(contract)
        monkeypatch.undo()
        assert DmintState.from_script(_outs(old)[0][0]).height == 2
        with pytest.raises(_Abort, match="OP_NUMEQUALVERIFY"):
            _validate_outputs(contract, old)

    @pytest.mark.parametrize(
        "burn",
        [
            b"\xd8" + _TOKEN_REF.to_bytes() + b"\x6a",  # the token ref, not the contract ref
            _BURN + b"\x00",  # one byte too many
            b"\xd0" + _CONTRACT_REF.to_bytes() + b"\x6a",  # a normal ref push, not the singleton
        ],
        ids=["token-ref", "trailing-byte", "d0-push"],
    )
    def test_a_near_miss_burn_is_rejected(self, burn: bytes) -> None:
        """The transcription is not vacuous: each near miss of the burn fails it."""
        contract = _v2(1, 2)
        res = _mint(contract)
        res.tx.outputs[0].locking_script = Script(burn)
        with pytest.raises(_Abort):
            _validate_outputs(contract, res)


# ---------------------------------------------------------------------------------------------
# The state the builder decides from must be the state the spent script carries
# ---------------------------------------------------------------------------------------------


class TestTheStateMustBeTheScripts:
    """``build_dmint_mint_tx`` decides everything from ``contract_utxo.state``, above all whether
    this is the final mint. A state that disagrees with ``contract_utxo.script`` builds a mint of
    a contract that is not the one being spent: one height ahead, it builds the burn a mint early,
    which the covenant rejects after the grind. V2 has refused this since its state bytes are
    rebuilt and matched against the script; V1 now re-parses the script and compares."""

    @pytest.mark.parametrize(
        "forge",
        [
            {"height": 1},  # one ahead: the builder would take this for the final mint
            {"max_height": 1},  # the same mistake from the other side
            {"contract_ref": _TOKEN_REF},  # a burn naming a ref the covenant does not
        ],
        ids=["height", "max_height", "contract_ref"],
    )
    @_BUILDERS
    def test_a_state_that_is_not_the_scripts_is_refused(self, make, forge) -> None:
        contract = make(0, 2)
        forged = dataclasses.replace(contract, state=dataclasses.replace(contract.state, **forge))
        with pytest.raises(ValidationError, match="does not (match the state|round-trip to)"):
            _mint(forged)
        assert not _mint(contract).is_final_mint  # the honest state of the same script

    def test_a_v1_state_parsed_from_its_own_script_is_accepted_at_every_height(self) -> None:
        for height in (0, 1):
            res = _mint(_v1(height, 2))
            assert res.is_final_mint is (height == 1)
