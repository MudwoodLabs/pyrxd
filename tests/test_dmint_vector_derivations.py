"""dMint V2 contract-script derivation tests against the published
conformance vectors (``conformance/dmint-v2-contract-vectors.json``).

The existing ``test_dmint_conformance_vectors.py`` regression-locks the
builder to the committed bytes. This file adds the *derivation* nets the
lock alone can't provide, each asserting against the vector JSON or the
documented layout — never against the builder's own prior output:

1. **Vector bytes → state fields**: the independent state parser
   (``DmintState.from_script``, the code the miner trusts to re-derive
   on-chain state) must recover every JSON param from the committed
   contract bytes — including the mainnet-anchored vector. The expected
   ``target`` is derived in-test from the documented formula
   ``MAX_SHA256D_TARGET // difficulty`` with the constant inlined.
2. **Builder ↔ parser round-trip property**: for Hypothesis-generated
   valid deploy params across all five DAA modes, parsing the built
   contract recovers every state field.
3. **State-layout byte check**: the state prefix (before the 0xbd
   OP_STATESEPARATOR) of a built contract is re-read with a test-local
   reader implementing the documented 10-slot layout (canonical redesign
   §4.2) and Bitcoin MINIMALDATA push rules — heights/targets must use
   minimal pushes (the non-minimal height push was rejected by radiantd's
   mempool policy on mainnet), refs must be raw ``d8/d0 + 36B`` outpoint
   bytes (txid LE + vout LE4).
"""

from __future__ import annotations

import json
import os
import struct
from pathlib import Path

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from pyrxd.glyph.dmint import (
    DaaMode,
    DmintAlgo,
    DmintDeployParams,
    build_dmint_contract_script,
)
from pyrxd.glyph.dmint.chain import DmintState
from pyrxd.glyph.types import GlyphRef

_BUDGET_MULT = int(os.environ.get("FUZZ_BUDGET_MULTIPLIER", "1"))


def _budget(n: int) -> int:
    return n * _BUDGET_MULT


_VECTORS = Path(__file__).resolve().parent.parent / "conformance" / "dmint-v2-contract-vectors.json"

# Documented target formula constants (types.py cites the canonical redesign;
# inlined here so the assertion does not route through the code under test).
_MAX_SHA256D_TARGET = 0x7FFFFFFFFFFFFFFF
_MAX_256BIT_TARGET = (1 << 256) - 1
_EPOCH_MAX_SAFE_TARGET = 1 << 48


def _params_from_json(p: dict) -> DmintDeployParams:
    return DmintDeployParams(
        contract_ref=GlyphRef(txid=p["contract_ref"]["txid"], vout=p["contract_ref"]["vout"]),
        token_ref=GlyphRef(txid=p["token_ref"]["txid"], vout=p["token_ref"]["vout"]),
        max_height=p["max_height"],
        reward=p["reward"],
        difficulty=p["difficulty"],
        algo=DmintAlgo[p["algo"]],
        daa_mode=DaaMode[p["daa_mode"]],
        target_time=p["target_time"],
        half_life=p["half_life"],
        height=p["height"],
        last_time=p["last_time"],
        epoch_length=p["epoch_length"],
        max_adjustment_log2=p["max_adjustment_log2"],
        schedule=tuple(tuple(x) for x in p["schedule"]),
    )


# ═══════════════════════════════════════════════════════════════════════════════
# 1. Committed vector bytes re-parse to their own JSON params
# ═══════════════════════════════════════════════════════════════════════════════


def test_committed_vector_bytes_reparse_to_their_params():
    doc = json.loads(_VECTORS.read_text())
    assert doc["vectors"], "no conformance vectors"
    for v in doc["vectors"]:
        p = v["params"]
        st_ = DmintState.from_script(bytes.fromhex(v["contract_script_hex"]))
        ctx = f"vector {v['id']!r}"
        assert not st_.is_v1, ctx
        assert st_.height == p["height"], ctx
        assert st_.contract_ref.txid == p["contract_ref"]["txid"], ctx
        assert st_.contract_ref.vout == p["contract_ref"]["vout"], ctx
        assert st_.token_ref.txid == p["token_ref"]["txid"], ctx
        assert st_.token_ref.vout == p["token_ref"]["vout"], ctx
        assert st_.max_height == p["max_height"], ctx
        assert st_.reward == p["reward"], ctx
        assert st_.algo.name == p["algo"], ctx
        assert st_.daa_mode.name == p["daa_mode"], ctx
        assert st_.target_time == p["target_time"], ctx
        assert st_.last_time == p["last_time"], ctx
        max_target = _MAX_SHA256D_TARGET if p["algo"] == "SHA256D" else _MAX_256BIT_TARGET
        assert st_.target == max_target // p["difficulty"], ctx


# ═══════════════════════════════════════════════════════════════════════════════
# 2. Builder ↔ parser round-trip over generated params
# ═══════════════════════════════════════════════════════════════════════════════

_txid = st.binary(min_size=32, max_size=32).map(bytes.hex)
_ref = st.builds(GlyphRef, txid=_txid, vout=st.integers(min_value=0, max_value=0xFFFFFFFF))


@st.composite
def _deploy_params(draw) -> DmintDeployParams:
    daa_mode = draw(st.sampled_from(list(DaaMode)))
    algo = draw(st.sampled_from(list(DmintAlgo)))
    if daa_mode == DaaMode.EPOCH:
        # EPOCH caps the initial target at 2^48 (OP_MUL overflow guard), so
        # difficulty must be at least maxTarget / 2^48.
        max_target = _MAX_SHA256D_TARGET if algo == DmintAlgo.SHA256D else _MAX_256BIT_TARGET
        min_diff = max_target // _EPOCH_MAX_SAFE_TARGET + 1
        difficulty = draw(st.integers(min_value=min_diff, max_value=min_diff * 1024))
    else:
        difficulty = draw(st.integers(min_value=1, max_value=2**40))
    if daa_mode == DaaMode.SCHEDULE:
        heights = draw(st.lists(st.integers(min_value=0, max_value=10**6), min_size=1, max_size=10, unique=True))
        targets = draw(
            st.lists(
                st.integers(min_value=1, max_value=_MAX_SHA256D_TARGET),
                min_size=len(heights),
                max_size=len(heights),
            )
        )
        schedule = tuple(zip(sorted(heights), targets))
    else:
        schedule = ()
    max_height = draw(st.integers(min_value=1, max_value=10**9))
    return DmintDeployParams(
        contract_ref=draw(_ref),
        token_ref=draw(_ref),
        max_height=max_height,
        reward=draw(st.integers(min_value=1, max_value=10**12)),
        difficulty=difficulty,
        algo=algo,
        daa_mode=daa_mode,
        target_time=draw(st.integers(min_value=1, max_value=86_400)),
        half_life=draw(st.integers(min_value=1, max_value=10**6)),
        height=draw(st.integers(min_value=0, max_value=max_height)),
        last_time=draw(st.integers(min_value=0, max_value=0x7FFFFFFF)),
        epoch_length=draw(st.integers(min_value=1, max_value=10**5)),
        max_adjustment_log2=draw(st.sampled_from([1, 2, 3, 4])),
        schedule=schedule,
    )


@given(p=_deploy_params())
@settings(max_examples=_budget(200), deadline=None, suppress_health_check=[HealthCheck.too_slow])
def test_builder_parser_roundtrip(p):
    """The miner re-derives contract state from on-chain bytes with
    DmintState.from_script; every deploy-params field encoded into the state
    must survive build → parse exactly."""
    st_ = DmintState.from_script(build_dmint_contract_script(p))
    assert not st_.is_v1
    assert st_.height == p.height
    assert st_.contract_ref == p.contract_ref
    assert st_.token_ref == p.token_ref
    assert st_.max_height == p.max_height
    assert st_.reward == p.reward
    assert st_.algo == p.algo
    assert st_.daa_mode == p.daa_mode
    assert st_.target_time == p.target_time
    assert st_.last_time == p.last_time
    max_target = _MAX_SHA256D_TARGET if p.algo == DmintAlgo.SHA256D else _MAX_256BIT_TARGET
    assert st_.target == max_target // p.difficulty


# ═══════════════════════════════════════════════════════════════════════════════
# 3. State-layout byte check (documented layout + MINIMALDATA rules)
# ═══════════════════════════════════════════════════════════════════════════════


def _read_minimal_number(script: bytes, i: int) -> tuple[int, int]:
    """Read one MINIMALDATA-compliant script-number push at offset i.

    Returns (value, next_offset). Fails the test on any non-minimal
    encoding — rules per the Bitcoin/Radiant MINIMALDATA policy:
    0 → OP_0; 1..16 → OP_1..OP_16; -1 → OP_1NEGATE; otherwise the
    shortest little-endian signed-magnitude byte string.
    """
    op = script[i]
    if op == 0x00:
        return 0, i + 1
    if 0x51 <= op <= 0x60:
        return op - 0x50, i + 1
    assert 1 <= op <= 0x4B, f"expected direct push at offset {i}, got opcode {op:#x}"
    data = script[i + 1 : i + 1 + op]
    assert len(data) == op, "truncated push"
    # minimality: single bytes 1..16 / 0x81 must have used OP_N / OP_1NEGATE
    assert not (op == 1 and (1 <= data[0] <= 16 or data[0] == 0x81)), "non-minimal single-byte push"
    # minimality: a trailing 0x00 is only allowed to clear a sign bit
    if op > 1 and data[-1] == 0x00:
        assert data[-2] & 0x80, "non-minimal number: redundant trailing zero byte"
    negative = bool(data[-1] & 0x80)
    magnitude = bytes(data[:-1]) + bytes([data[-1] & 0x7F])
    value = int.from_bytes(magnitude, "little")
    return (-value if negative else value), i + 1 + op


def _read_state_slots(contract: bytes, p: DmintDeployParams) -> None:
    """Walk the documented 10-slot state layout and compare every slot."""
    i = 0
    height, i = _read_minimal_number(contract, i)
    assert height == p.height
    assert contract[i] == 0xD8, "slot 2 must be OP_PUSHINPUTREFSINGLETON"
    ref = contract[i + 1 : i + 37]
    assert ref == bytes.fromhex(p.contract_ref.txid)[::-1] + struct.pack("<I", p.contract_ref.vout)
    i += 37
    assert contract[i] == 0xD0, "slot 3 must be OP_PUSHINPUTREF"
    ref = contract[i + 1 : i + 37]
    assert ref == bytes.fromhex(p.token_ref.txid)[::-1] + struct.pack("<I", p.token_ref.vout)
    i += 37
    max_height, i = _read_minimal_number(contract, i)
    assert max_height == p.max_height
    reward, i = _read_minimal_number(contract, i)
    assert reward == p.reward
    algo, i = _read_minimal_number(contract, i)
    assert algo == int(p.algo)
    daa, i = _read_minimal_number(contract, i)
    assert daa == int(p.daa_mode)
    target_time, i = _read_minimal_number(contract, i)
    assert target_time == p.target_time
    # slot 9: lastTime is documented as a fixed 4-byte push (Part C rebuilds
    # it with 04 || NUM2BIN(4, locktime))
    assert contract[i] == 0x04, "lastTime must be a 4-byte push"
    assert contract[i + 1 : i + 5] == struct.pack("<I", p.last_time)
    i += 5
    target, i = _read_minimal_number(contract, i)
    max_target = _MAX_SHA256D_TARGET if p.algo == DmintAlgo.SHA256D else _MAX_256BIT_TARGET
    assert target == max_target // p.difficulty
    assert contract[i] == 0xBD, "state must end at OP_STATESEPARATOR"


@given(p=_deploy_params())
@settings(max_examples=_budget(150), deadline=None, suppress_health_check=[HealthCheck.too_slow])
def test_state_script_layout_and_minimality(p):
    _read_state_slots(build_dmint_contract_script(p), p)


def test_mainnet_anchored_vector_state_layout():
    """The same byte-level walk over the mainnet-anchored committed vector."""
    doc = json.loads(_VECTORS.read_text())
    anchored = [v for v in doc["vectors"] if v["source"].startswith("mainnet:")]
    assert anchored, "no mainnet-anchored vector in the suite"
    for v in anchored:
        _read_state_slots(bytes.fromhex(v["contract_script_hex"]), _params_from_json(v["params"]))
