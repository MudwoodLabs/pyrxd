"""V2 dMint deploys pyrxd builds must be mintable: one target formula, and upper bounds.

Two defects of one class — a V2 contract that no transaction can ever spend:

1. **BLAKE3/K12 targets.** ``DmintDeployParams.initial_target`` returned
   ``(2**256 - 1) // difficulty`` for BLAKE3 and K12: a 32-byte number. Part B2 reads the
   target as a script number, and Radiant's ``CScriptNum`` aborts on an operand wider than
   8 bytes, so every such deploy (any difficulty below 2**192) was unmintable. Canonical
   Photonic ``dMintDiffToTarget`` is ``MAX_TARGET / difficulty`` with no algorithm argument,
   and Part B1 cuts the same 8-byte window out of the PoW hash whatever the hash opcode.
2. **No upper bounds.** ``max_height``, ``reward``, ``target_time``, ``half_life``,
   ``epoch_length`` and SCHEDULE heights were unbounded above: past 2**63 - 1 each becomes a
   9-byte push the covenant cannot read; a ``target_time`` near 2**47 overflows the ASERT/LWMA
   retarget's multiply; a ``reward`` above Radiant's money supply can never be paid.

The fixes are checked against evidence, not against pyrxd's own earlier output: Photonic's
``pushMinimal`` (transcribed below) and ``dMintDiffToTarget``, the real BLAKE3/K12 V2 deploys
on mainnet (pinned below, byte for byte), and the int64 evaluator in
``tests/test_dmint_daa_offchain_onchain_differential.py``.
"""

from __future__ import annotations

import pytest
from click.testing import CliRunner
from hypothesis import given, settings
from hypothesis import strategies as st

from pyrxd.cli.main import cli
from pyrxd.glyph.builder import DmintV2DeployParams
from pyrxd.glyph.dmint import (
    DaaMode,
    DmintAlgo,
    DmintContractUtxo,
    DmintDeployParams,
    DmintMinerFundingUtxo,
    DmintState,
    build_dmint_contract_script,
    build_dmint_mint_tx,
)
from pyrxd.glyph.dmint.builders import (
    _PART_A,
    _POW_HASH_OP,
    _build_asert_daa_v2,
    _build_epoch_daa,
    _build_linear_daa_v2,
    _push_minimal,
    build_dmint_code_script,
    build_dmint_state_script,
    build_dmint_v1_state_script,
)
from pyrxd.glyph.dmint.types import (
    _PART_B1,
    _PART_B2,
    MAX_SCRIPT_NUM,
    MAX_SCRIPT_NUM_BYTES,
    MAX_SHA256D_TARGET,
    MAX_V2_TARGET_256,
    MAX_V2_TARGET_TIME,
    target_for_difficulty,
)
from pyrxd.glyph.types import GlyphMetadata, GlyphProtocol, GlyphRef
from pyrxd.security.errors import ValidationError
from pyrxd.security.types import RADIANT_MAX_PHOTONS, Hex20
from tests.test_dmint_daa_offchain_onchain_differential import _Abort, _cs_encode, _daa_stack, _num, _result, _run

_C = GlyphRef(txid="aa" * 32, vout=1)
_T = GlyphRef(txid="aa" * 32, vout=0)
_LAST = 1_700_000_000


def _params(**kw: object) -> DmintDeployParams:
    base: dict = {"contract_ref": _C, "token_ref": _T, "max_height": 100, "reward": 1000, "difficulty": 10}
    base.update(kw)
    return DmintDeployParams(**base)


def _v2(**kw: object) -> DmintV2DeployParams:
    base: dict = {
        "metadata": GlyphMetadata(protocol=[GlyphProtocol.FT, GlyphProtocol.DMINT], name="t", ticker="T", decimals=0),
        "owner_pkh": Hex20(bytes(20)),
        "num_contracts": 1,
        "max_height": 100,
        "reward_photons": 1000,
        "difficulty": 10,
        "last_time": _LAST,
    }
    base.update(kw)
    return DmintV2DeployParams(**base)


# =====================================================================================
# 1. One target formula for every algorithm
# =====================================================================================


class TestOneTargetFormulaForEveryAlgorithm:
    @pytest.mark.parametrize("algo", list(DmintAlgo))
    @pytest.mark.parametrize("difficulty", [1, 2, 10, 5000, 32768, 1 << 40, MAX_SHA256D_TARGET])
    def test_the_target_is_max_sha256d_target_over_difficulty(self, algo: DmintAlgo, difficulty: int) -> None:
        p = _params(algo=algo, difficulty=difficulty)
        assert p.initial_target == MAX_SHA256D_TARGET // difficulty == target_for_difficulty(difficulty)
        assert DmintState.from_script(build_dmint_contract_script(p)).target == MAX_SHA256D_TARGET // difficulty

    def test_the_algorithm_changes_exactly_three_bytes_of_a_contract(self) -> None:
        """Why one formula is right, derived from the bytes: the algorithm selects the hash
        opcode and the algoId the state records (once in the state, once in Part C's copy of
        it) — nothing else. In particular Part B1, which extracts the 8-byte hash window
        Part B2 compares with the target, is the same bytes after every hash opcode."""
        scripts = {algo: build_dmint_contract_script(_params(algo=algo, last_time=_LAST)) for algo in DmintAlgo}
        base = scripts[DmintAlgo.SHA256D]
        for algo, script in scripts.items():
            assert len(script) == len(base)
            assert len([i for i in range(len(base)) if base[i] != script[i]]) == (0 if algo is DmintAlgo.SHA256D else 3)
            code = build_dmint_code_script(_params(algo=algo, last_time=_LAST))
            assert code[len(_PART_A) : len(_PART_A) + 1] == _POW_HASH_OP[algo]
            assert code[len(_PART_A) + 1 :].startswith(_PART_B1 + _PART_B2)

    @pytest.mark.parametrize("algo", [DmintAlgo.BLAKE3, DmintAlgo.K12])
    def test_the_production_deploy_path_writes_the_8_byte_target(self, algo: DmintAlgo) -> None:
        """Through the entry point a deployer uses — ``prepare_dmint_deploy`` then
        ``build_reveal_outputs`` — both the fee placeholders and the real reveal contracts."""
        from pyrxd.glyph.builder import GlyphBuilder

        result = GlyphBuilder().prepare_dmint_deploy(_v2(algo=algo, difficulty=10, num_contracts=2))
        scripts = (*result.placeholder_contract_scripts, *result.build_reveal_outputs("dd" * 32).contract_scripts)
        assert len(scripts) == 4
        for script in scripts:
            st_ = DmintState.from_script(script)
            assert st_.algo is algo
            assert st_.target == MAX_SHA256D_TARGET // 10

    @pytest.mark.parametrize("algo", list(DmintAlgo))
    def test_part_b2_can_read_the_deploy_target(self, algo: DmintAlgo) -> None:
        """Part B2 (``OP_1 OP_PICK OP_SWAP OP_GREATERTHANOREQUAL OP_VERIFY``) run under the int64
        evaluator on the target a deploy writes: it reads, and it compares."""
        compare = _PART_B2[:-1]  # without the final OP_VERIFY, so the verdict stays on the stack
        target = _params(algo=algo, difficulty=1).initial_target
        item = _push_minimal(target)[1:]
        for hash_num, verdict in ((target, 1), (target - 1, 1), (0, 1)):
            assert _num(_run(compare, [item, _cs_encode(hash_num)], 0)[-1]) == verdict

    def test_the_old_blake3_target_is_one_part_b2_cannot_read(self) -> None:
        """The defect, executed: the formula BLAKE3/K12 used to get aborts the comparison."""
        old = (MAX_V2_TARGET_256 // 1).to_bytes(33, "little")  # 32 x 0xff + the sign pad
        with pytest.raises(_Abort, match="longer than 8 bytes"):
            _run(_PART_B2[:-1], [old, _cs_encode(12345)], 0)

    # BLAKE3/K12 V2 contracts on mainnet, as their reveals put them on chain (vout 0 of each
    # reveal), with the difficulty each reveal's CBOR declares (``dmint.diff``). DM03 (K12) and
    # VGM (BLAKE3) have since been MINTED — DM03 to height 3 by
    # 20d9e4f2c7c0e22c2e7ba2a9dd10fa90d3d1f64d8ace00709222aa25cbcc1b75 and VGM's first contract
    # to height 29 by 181186177124320cebc4e8c1a3d310b176fbf4a6510fda305be0b72b60e27bf6 (both
    # read back from the chain 2026-09-23) — so these are targets the covenant has accepted a
    # proof of work against.
    _MAINNET = {
        # K12 FIXED, reveal d93833836ca15fbc897e6549a7e01a4451d31d19bc86796cbd7faa7d5072c794, diff 2
        "DM03": (
            2,
            None,
            "00d8bcc4e2fb212f5a1c666769333c36726a5e39cbb50529649d65740fbc0c6959e401000000d0bcc4e2fb212f5a1c666769333c3"
            "6726a5e39cbb50529649d65740fbc0c6959e40000000001645a5200013c045578166a08ffffffffffffff3fbdc0c859797ea85d795d"
            "797ea87e5e7a7eefbc01147f77587f040000000088817600a26951797ca2696b75757575577ae500a069567ae600a06901d05379"
            "7e0cdec0e9aa76e378e4a269e69d7eaa76e47b9d547a818b76537a9c537ade789181547ae6939d636c755279cd01d853797e016a"
            "7e886778de519d7676009c63750100677660a163015093518067827c7e68684c51d8bcc4e2fb212f5a1c666769333c36726a5e39"
            "cbb50529649d65740fbc0c6959e401000000d0bcc4e2fb212f5a1c666769333c36726a5e39cbb50529649d65740fbc0c6959e400"
            "00000001645a5200013c7ec55480547c7e7e6c76009c63750100677660a163015093518067827c7e68687e5379ec78885379eac0"
            "e9885379cc519d75686d7551",
        ),
        # BLAKE3 FIXED, reveal da0416b4f25fa8abba09b862bf269036a68cd74937404c3a6baeba03c105acfa, diff 5000
        "RXD2026": (
            5000,
            None,
            "00d82c19907279794c9c7a2a46e7f4fd30b56811a54d052e4988bafe62e8cc85541901000000d02c19907279794c9c7a2a46e7f4f"
            "d30b56811a54d052e4988bafe62e8cc855419000000000164515100013c0437ce376a07cb10c7bab88d06bdc0c859797ea85d795d"
            "797ea87e5e7a7eeebc01147f77587f040000000088817600a26951797ca2696b75757575577ae500a069567ae600a06901d05379"
            "7e0cdec0e9aa76e378e4a269e69d7eaa76e47b9d547a818b76537a9c537ade789181547ae6939d636c755279cd01d853797e016a"
            "7e886778de519d7676009c63750100677660a163015093518067827c7e68684c51d82c19907279794c9c7a2a46e7f4fd30b56811"
            "a54d052e4988bafe62e8cc85541901000000d02c19907279794c9c7a2a46e7f4fd30b56811a54d052e4988bafe62e8cc85541900"
            "0000000164515100013c7ec55480547c7e7e6c76009c63750100677660a163015093518067827c7e68687e5379ec78885379eac0"
            "e9885379cc519d75686d7551",
        ),
        # BLAKE3 ASERT (v2 retarget, halfLife 240), reveal
        # 16cc7c53a207d907a170318e551c4a3a2e30626347285c620bf421242497ab40, diff 10
        "VGM": (
            10,
            240,
            "00d871374ae74de382c3c50493962694f9fc0a7cc00b2da1d10d08f733051c26bb9101000000d071374ae74de382c3c504939626"
            "94f9fc0a7cc00b2da1d10d08f733051c26bb91000000000210275a5152013c04a2f7426a08cccccccccccccc0cbdc0c859797ea8"
            "5d795d797ea87e5e7a7eeebc01147f77587f040000000088817600a26951797ca269c5527994537994030000019502f000960200"
            "40a30200c0a47c08ffffffffffffff1fa37603000001967b959308ffffffffffffff1fa376519f637551686b75757575577ae500"
            "a069567ae600a06901d053797e0cdec0e9aa76e378e4a269e69d7eaa76e47b9d547a818b76537a9c537ade789181547ae6939d63"
            "6c755279cd01d853797e016a7e886778de519d7676009c63750100677660a163015093518067827c7e68684c52d871374ae74de3"
            "82c3c50493962694f9fc0a7cc00b2da1d10d08f733051c26bb9101000000d071374ae74de382c3c50493962694f9fc0a7cc00b2d"
            "a1d10d08f733051c26bb91000000000210275a5152013c7ec55480547c7e7e6c76009c63750100677660a163015093518067827c"
            "7e68687e5379ec78885379eac0e9885379cc519d75686d7551",
        ),
    }

    @pytest.mark.parametrize("name", sorted(_MAINNET))
    def test_mainnet_blake3_and_k12_deploys_rebuild_byte_for_byte(self, name: str) -> None:
        diff, half_life, pinned_hex = self._MAINNET[name]
        pinned = bytes.fromhex(pinned_hex)
        st_ = DmintState.from_script(pinned)
        assert st_.algo is not DmintAlgo.SHA256D  # these anchors are here for BLAKE3/K12
        kw: dict = {"half_life": half_life} if half_life is not None else {}
        p = DmintDeployParams(
            contract_ref=st_.contract_ref,
            token_ref=st_.token_ref,
            max_height=st_.max_height,
            reward=st_.reward,
            difficulty=diff,
            algo=st_.algo,
            daa_mode=st_.daa_mode,
            target_time=st_.target_time,
            last_time=st_.last_time,
            **kw,
        )
        assert st_.target == p.initial_target == MAX_SHA256D_TARGET // diff
        assert build_dmint_contract_script(p) == pinned


# =====================================================================================
# 2. Upper bounds on the numeric deploy parameters
# =====================================================================================

#: (field on DmintDeployParams, field on DmintV2DeployParams, first refused value, mode it bakes in)
_CAPS = [
    ("max_height", "max_height", MAX_SCRIPT_NUM + 1, DaaMode.FIXED),
    ("reward", "reward_photons", RADIANT_MAX_PHOTONS + 1, DaaMode.FIXED),
    ("difficulty", "difficulty", MAX_SHA256D_TARGET + 1, DaaMode.FIXED),
    ("target_time", "target_time", MAX_V2_TARGET_TIME + 1, DaaMode.ASERT),
    ("target_time", "target_time", MAX_V2_TARGET_TIME + 1, DaaMode.FIXED),
    ("half_life", "half_life", MAX_SCRIPT_NUM + 1, DaaMode.ASERT),
    ("epoch_length", "epoch_length", MAX_SCRIPT_NUM + 1, DaaMode.EPOCH),
]


def _mode_kw(mode: DaaMode) -> dict:
    return {"daa_mode": mode, "difficulty": 32768} if mode is DaaMode.EPOCH else {"daa_mode": mode}


class TestUpperBounds:
    @pytest.mark.parametrize(("field", "v2_field", "value", "mode"), _CAPS)
    def test_one_past_each_cap_is_refused_by_both_param_types(self, field, v2_field, value, mode) -> None:
        kw = _mode_kw(mode)
        with pytest.raises(ValidationError, match=rf"DmintDeployParams: {field} must be <="):
            _params(**{**kw, field: value})
        with pytest.raises(ValidationError, match=rf"DmintV2DeployParams: {v2_field} must be <="):
            _v2(**{**kw, v2_field: value})

    @pytest.mark.parametrize(("field", "v2_field", "value", "mode"), _CAPS)
    def test_each_cap_itself_is_accepted_and_builds_a_readable_contract(self, field, v2_field, value, mode) -> None:
        """The honest neighbour of every refusal: the cap is IN range, and the contract built
        at it carries no number wider than the covenant can read."""
        kw = {**_mode_kw(mode), field: value - 1, "last_time": _LAST}
        if field == "max_height":
            kw["height"] = 0
        _v2(**{**_mode_kw(mode), v2_field: value - 1})
        state = build_dmint_state_script(_params(**kw))
        assert DmintState.from_script(build_dmint_contract_script(_params(**kw)))  # parses
        # every numeric push in the state is at most 8 bytes (refs are OP_PUSHINPUTREF operands)
        i, widths = 0, []
        while i < len(state):
            op = state[i]
            if op in (0xD0, 0xD8):
                i += 37
                continue
            n = op if 1 <= op <= 0x4B else 0
            widths.append(n)
            i += 1 + n
        assert max(widths) <= MAX_SCRIPT_NUM_BYTES

    def test_schedule_heights_are_capped_too(self) -> None:
        sched_ok = ((MAX_SCRIPT_NUM, 4),)
        sched_bad = ((MAX_SCRIPT_NUM + 1, 4),)
        _params(daa_mode=DaaMode.SCHEDULE, schedule=sched_ok)
        _v2(daa_mode=DaaMode.SCHEDULE, schedule=sched_ok)
        with pytest.raises(ValidationError, match="schedule entry 0 height must be <="):
            _params(daa_mode=DaaMode.SCHEDULE, schedule=sched_bad)
        with pytest.raises(ValidationError, match="schedule entry 0 height must be <="):
            _v2(daa_mode=DaaMode.SCHEDULE, schedule=sched_bad)

    def test_mode_specific_caps_do_not_refuse_values_a_mode_never_bakes(self) -> None:
        """half_life is only baked by ASERT and epoch_length only by EPOCH: an out-of-range
        value on another mode emits nothing, so refusing it would refuse a valid deploy."""
        for mode in (DaaMode.FIXED, DaaMode.LWMA, DaaMode.SCHEDULE):
            sched = ((5, 4),) if mode is DaaMode.SCHEDULE else ()
            _params(daa_mode=mode, half_life=MAX_SCRIPT_NUM + 1, epoch_length=MAX_SCRIPT_NUM + 1, schedule=sched)

    @pytest.mark.parametrize("mode", [DaaMode.ASERT, DaaMode.LWMA, DaaMode.EPOCH])
    def test_at_the_target_time_cap_every_retarget_stays_inside_int64(self, mode: DaaMode) -> None:
        """THE REASON FOR THE target_time CAP, EXECUTED. At ``MAX_V2_TARGET_TIME`` each retarget
        fragment runs to a result for every pair of 32-bit timestamps a V2 state and mint can
        carry — including the extremes both ways — and one far past it (near 2**47, where the
        unbounded parameter used to be accepted) aborts the script."""
        tt = MAX_V2_TARGET_TIME
        frag = {
            DaaMode.ASERT: _build_asert_daa_v2(240),
            DaaMode.LWMA: _build_linear_daa_v2(),
            DaaMode.EPOCH: _build_epoch_daa(1, 4),
        }[mode]
        target = 1 << 40
        for last_time in (1 << 23, _LAST, 0x7FFFFFFF):
            for locktime in (1 << 23, _LAST, 0x7FFFFFFF):
                stack = _daa_stack(int(mode), tt, last_time, target, height=1)
                assert 1 <= _result(_run(frag, stack, locktime)) <= MAX_SHA256D_TARGET
        if mode is not DaaMode.EPOCH:  # ASERT/LWMA scale (timeDelta - targetTime) by 2**16
            with pytest.raises(_Abort, match="int64"):
                _run(frag, _daa_stack(int(mode), (1 << 47) + 121, _LAST, target), _LAST + 120)

    def test_the_reward_cap_is_also_a_readable_script_number(self) -> None:
        assert RADIANT_MAX_PHOTONS < MAX_SCRIPT_NUM
        assert len(_push_minimal(RADIANT_MAX_PHOTONS)) - 1 <= MAX_SCRIPT_NUM_BYTES

    # Every numeric parameter value on a V2 dMint deploy found on mainnet by a 2026-09-22 scan
    # (41 contracts, read from their state scripts and, for ASERT, the half-life baked into the
    # bytecode), plus the ranges Photonic's Mint form offers (targetBlockTime 10..3600, ASERT
    # halfLife 1..1,000,000, difficulty up to 1,000,000). A cap that refused any of them would
    # be a guard refusing valid work.
    _REAL = {
        "max_height": [5, 10, 100, 1000, 10_000, 30_000, 210_000, 1_000_000, 1_111_111],
        "reward_photons": [1, 3, 10, 21, 100, 1000, 1200],
        "target_time": [10, 12, 33, 60, 3600],
        "half_life": [1, 30, 100, 240, 1000, 1_000_000],
        "difficulty": [1, 2, 3, 4, 5, 10, 12, 5000, 1_000_000],
    }

    @pytest.mark.parametrize("field", sorted(_REAL))
    def test_every_value_real_deploys_use_is_accepted(self, field: str) -> None:
        for value in self._REAL[field]:
            for algo in DmintAlgo:
                p = _v2(daa_mode=DaaMode.ASERT, algo=algo, **{field: value})
                assert getattr(p, field) == value


# =====================================================================================
# 3. The encoder refuses what no covenant can read — and changes nothing else
# =====================================================================================


def _photonic_push_minimal(n: int) -> bytes:
    """Photonic ``pushMinimal`` (script.ts at becf41a7): OP_0 / OP_1NEGATE / OP_1..16, else
    ``encodeDataPush(bigIntToVmNumber(n))`` — CScriptNum serialization, any width."""
    if n == 0:
        return b"\x00"
    if n == -1:
        return b"\x4f"
    if 1 <= n <= 16:
        return bytes([0x50 + n])
    a, body = abs(n), bytearray()
    while a:
        body.append(a & 0xFF)
        a >>= 8
    if body[-1] & 0x80:
        body.append(0x80 if n < 0 else 0x00)
    elif n < 0:
        body[-1] |= 0x80
    return (bytes([len(body)]) if len(body) < 0x4C else b"\x4c" + bytes([len(body)])) + bytes(body)


class TestTheEncoderGuard:
    @given(st.integers(min_value=-MAX_SCRIPT_NUM, max_value=MAX_SCRIPT_NUM))
    @settings(max_examples=2000, deadline=None)
    def test_in_range_output_is_photonics_byte_for_byte(self, n: int) -> None:
        assert _push_minimal(n) == _photonic_push_minimal(n)

    @pytest.mark.parametrize(
        "n", [0, 1, 16, 17, -1, -2, 127, 128, 255, 256, 0x7FFF, 0x8000, 1 << 55, MAX_SCRIPT_NUM, -MAX_SCRIPT_NUM]
    )
    def test_the_boundaries_are_photonics_too(self, n: int) -> None:
        assert _push_minimal(n) == _photonic_push_minimal(n)

    @pytest.mark.parametrize("n", [MAX_SCRIPT_NUM + 1, -(MAX_SCRIPT_NUM + 1), 1 << 64, MAX_V2_TARGET_256])
    def test_a_number_wider_than_8_bytes_is_refused(self, n: int) -> None:
        assert len(_photonic_push_minimal(n)) > 1 + MAX_SCRIPT_NUM_BYTES  # Photonic would emit it
        with pytest.raises(ValidationError, match="script number"):
            _push_minimal(n)

    def test_the_encoder_refuses_even_when_the_params_check_is_bypassed(self) -> None:
        """The guard is the narrowest point every numeric push crosses, so a caller that gets
        past the params check (here by mutating a frozen instance) still cannot emit it — in
        the V2 state, the V2 code (Part C's copy), and the V1 state builder."""
        p = _params(last_time=_LAST)
        object.__setattr__(p, "max_height", MAX_SCRIPT_NUM + 1)
        with pytest.raises(ValidationError, match="script number"):
            build_dmint_contract_script(p)
        with pytest.raises(ValidationError, match="script number"):
            build_dmint_code_script(p)
        with pytest.raises(ValidationError, match="script number"):
            build_dmint_v1_state_script(0, _C, _T, max_height=MAX_SCRIPT_NUM + 1, reward=1, target=1)

    def test_a_contract_carrying_the_old_blake3_target_is_refused_before_any_grind(self) -> None:
        """A V2 contract whose state holds a >8-byte target — what pyrxd deployed for BLAKE3/K12
        before this fix — can never be minted, and the mint builder now says so before a PoW
        grind starts: rebuilding its state crosses the same encoder."""
        honest = build_dmint_contract_script(_params(algo=DmintAlgo.BLAKE3, difficulty=1, last_time=_LAST))
        state_len = len(build_dmint_state_script(_params(algo=DmintAlgo.BLAKE3, difficulty=1, last_time=_LAST)))
        old_target = MAX_V2_TARGET_256
        wide = old_target.to_bytes(33, "little")
        target_push = _push_minimal(MAX_SHA256D_TARGET)
        assert honest[state_len - len(target_push) : state_len] == target_push
        script = honest[: state_len - len(target_push)] + bytes([len(wide)]) + wide + honest[state_len:]
        st_ = DmintState.from_script(script)  # it parses — the reader takes any width
        assert st_.target == old_target
        utxo = DmintContractUtxo(txid="dd" * 32, vout=0, value=1, script=script, state=st_)
        funding = DmintMinerFundingUtxo(
            txid="ee" * 32, vout=0, value=50_000_000, script=b"\x76\xa9\x14" + bytes(20) + b"\x88\xac"
        )
        with pytest.raises(ValidationError, match="script number"):
            build_dmint_mint_tx(utxo, b"\x00" * 8, b"\x22" * 20, _LAST + 60, funding_utxo=funding)


# =====================================================================================
# 4. The CLI inherits the bounds, and refuses before any wallet or network work
# =====================================================================================


class TestDeployDmintCliBounds:
    def _run(self, tmp_path, *extra: str):
        meta = tmp_path / "m.json"
        meta.write_text('{"name": "T", "description": "t", "protocol": ["FT", "DMINT"], "ticker": "TT", "decimals": 0}')
        args = ["--wallet", str(tmp_path / "none.dat"), "glyph", "deploy-dmint", str(meta), "--v2", *extra]
        return CliRunner().invoke(cli, args)

    @pytest.mark.parametrize(
        ("flag", "refused", "accepted", "named"),
        [
            ("--reward", RADIANT_MAX_PHOTONS + 1, RADIANT_MAX_PHOTONS, "reward_photons"),
            ("--max-height", MAX_SCRIPT_NUM + 1, MAX_SCRIPT_NUM, "max_height"),
            ("--target-time", MAX_V2_TARGET_TIME + 1, MAX_V2_TARGET_TIME, "target_time"),
        ],
    )
    def test_the_cap_is_enforced_at_the_parameter_gate(self, tmp_path, flag, refused, accepted, named) -> None:
        base = {"--max-height": "100", "--reward": "1000"}
        base.pop(flag, None)
        fixed = [x for kv in base.items() for x in kv]
        bad = self._run(tmp_path, *fixed, flag, str(refused))
        assert bad.exit_code != 0
        assert "invalid dMint deploy parameters" in bad.output
        assert f"{named} must be <=" in bad.output
        # Honest path: the cap itself passes the gate and reaches the next stage (the wallet).
        good = self._run(tmp_path, *fixed, flag, str(accepted))
        assert "invalid dMint deploy parameters" not in good.output
        assert "no wallet at" in good.output, good.output
