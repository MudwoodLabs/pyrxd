"""Differential property tests for the Radiant FORKID sighash preimage.

An INDEPENDENT reference implementation of the preimage — written from the
specification, not from ``pyrxd.transaction.transaction_preimage`` — is
compared byte-for-byte against the production builder over Hypothesis-generated
transaction shapes. A sighash preimage bug means signing something other than
what the node verifies (fund loss), so this layer earns a differential net
beyond the fixed golden vectors in ``tests/test_preimage.py``.

Specification sources for the reference implementation:

* BIP143 field order as used by the BCH/BSV FORKID sighash algorithm
  (nVersion, hashPrevouts, hashSequence, outpoint, scriptCode, value,
  nSequence, hashOutputs, nLockTime, sighash type), including the
  ANYONECANPAY / SINGLE / NONE zero-field rules.
* Radiant's extension: a ``hashOutputHashes`` field inserted before
  ``hashOutputs`` — per Radiant-Core ``src/primitives/transaction.h``
  (``GetHashOutputHashes`` / ``getRefHashDataSummary`` /
  ``writeOutputDataSummaryVector``) and radiantjs
  ``lib/transaction/sighash.js``. Per output: value (8 LE) +
  hash256(script) + ref count (4 LE) + (hash256(sorted refs) or 32 zero
  bytes); the concatenation is hash256'd.
* Refs sort ascending by the **uint288 numeric value** of the 36-byte ref,
  which is little-endian (byte[35] most significant), and are
  **deduplicated** — Radiant collects them into a ``std::set<uint288>``.
  The reference sorts *integers* (``int.from_bytes(ref, "little")``),
  deliberately a different derivation than the production code's byte-wise
  sort key, so a sort-order regression cannot hide in shared code.

The reference is itself anchored to the radiantjs-generated golden vectors
committed in ``tests/test_preimage.py`` (verified against mainnet reveal tx
dac1e2df…b407) — see ``TestReferenceAnchoredToRadiantjsVectors``. The
property tests then assert production == reference over generated shapes;
they never assert the production code against its own prior output.
"""

from __future__ import annotations

import os
import struct

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from pyrxd.constants import SIGHASH
from pyrxd.hash import hash256
from pyrxd.script.script import Script
from pyrxd.transaction.transaction_input import TransactionInput
from pyrxd.transaction.transaction_output import TransactionOutput
from pyrxd.transaction.transaction_preimage import tx_preimage, tx_preimages
from tests.consensus_oracle import push_ref_opcodes, ref_operand_opcodes, ref_operand_width

_BUDGET_MULT = int(os.environ.get("FUZZ_BUDGET_MULTIPLIER", "1"))


def _budget(n: int) -> int:
    return n * _BUDGET_MULT


# ═══════════════════════════════════════════════════════════════════════════════
# Reference implementation (from the spec — see module docstring for sources)
# ═══════════════════════════════════════════════════════════════════════════════

_ANYONECANPAY = 0x80
_BASE_MASK = 0x1F
_SINGLE = 0x03
_NONE = 0x02

# Ref rules come from the vendored Radiant Core sources (tests/consensus_oracle.py),
# never from pyrxd and never hand-typed here.
#
# They used to be hand-typed, as `_PUSHREF_OPS = (0xD0, 0xD8)`, and that is how
# this differential missed the sighash bug it was built to catch: the reference
# walked only those two opcodes, exactly like the defective production code, so
# the two agreed and the test passed. "Independent of the implementation" is not
# the same property as "correct", and only the second one catches a shared
# misreading of the spec. Anchoring to the C++ gives both.
_OPERAND_OPS = ref_operand_opcodes()  # {0xd0,0xd1,0xd2,0xd3,0xd8} — WALKED
_PUSHREF_OPS = push_ref_opcodes()  # {0xd0,0xd8}                   — COLLECTED
_OPERAND_WIDTH = ref_operand_width()  # 36


def _ref_compactsize(n: int) -> bytes:
    """Bitcoin CompactSize (varint) — independent of pyrxd.utils."""
    if n < 0xFD:
        return struct.pack("<B", n)
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    if n <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)


def _ref_scan_refs(script: bytes) -> list[bytes]:
    """Collect pushref payloads, dedup, and sort by uint288 numeric value.

    The sort is done on INTEGERS decoded little-endian and the bytes are
    reconstructed with ``to_bytes(36, "little")`` — the literal reading of
    "std::set<uint288> iteration order".

    All five operand-carrying opcodes are WALKED; only the two in
    ``_PUSHREF_OPS`` are COLLECTED. Those are different sets and conflating
    them desynchronises the scan inside the ref bytes — the sighash bug.
    """
    values: set[int] = set()
    i, n = 0, len(script)
    while i < n:
        op = script[i]
        i += 1
        if op in _OPERAND_OPS:
            assert i + _OPERAND_WIDTH <= n, "generator must only emit well-formed pushrefs"
            if op in _PUSHREF_OPS:
                values.add(int.from_bytes(script[i : i + _OPERAND_WIDTH], "little"))
            i += _OPERAND_WIDTH
        elif 0x01 <= op <= 0x4B:
            i += op
        elif op == 0x4C:
            i += 1 + script[i]
        elif op == 0x4D:
            i += 2 + int.from_bytes(script[i : i + 2], "little")
        elif op == 0x4E:
            i += 4 + int.from_bytes(script[i : i + 4], "little")
    return [v.to_bytes(36, "little") for v in sorted(values)]


def _ref_output_data_summary(value: int, script: bytes) -> bytes:
    """One output's entry in the hashOutputHashes blob."""
    refs = _ref_scan_refs(script)
    entry = struct.pack("<Q", value) + hash256(script) + struct.pack("<I", len(refs))
    entry += hash256(b"".join(refs)) if refs else b"\x00" * 32
    return entry


def _ref_hash_output_hashes(outputs: list[tuple[int, bytes]]) -> bytes:
    return hash256(b"".join(_ref_output_data_summary(v, s) for v, s in outputs))


def _ref_serialize_output(value: int, script: bytes) -> bytes:
    return struct.pack("<Q", value) + _ref_compactsize(len(script)) + script


def _ref_preimage(
    input_index: int,
    inputs: list[dict],
    outputs: list[tuple[int, bytes]],
    version: int,
    locktime: int,
) -> bytes:
    """Radiant FORKID sighash preimage, assembled per BIP143 + Radiant ext.

    ``inputs`` entries: dicts with txid (bytes, display order), vout,
    script (scriptCode bytes), value, sequence, sighash.
    """
    me = inputs[input_index]
    sighash = me["sighash"]
    base = sighash & _BASE_MASK
    acp = bool(sighash & _ANYONECANPAY)

    if acp:
        hash_prevouts = b"\x00" * 32
    else:
        hash_prevouts = hash256(b"".join(i["txid"][::-1] + struct.pack("<I", i["vout"]) for i in inputs))

    if not acp and base != _SINGLE and base != _NONE:
        hash_sequence = hash256(b"".join(struct.pack("<I", i["sequence"]) for i in inputs))
    else:
        hash_sequence = b"\x00" * 32

    if base != _SINGLE and base != _NONE:
        hash_outputs = hash256(b"".join(_ref_serialize_output(v, s) for v, s in outputs))
        hash_output_hashes = _ref_hash_output_hashes(outputs)
    elif base == _SINGLE and input_index < len(outputs):
        hash_outputs = hash256(_ref_serialize_output(*outputs[input_index]))
        hash_output_hashes = _ref_hash_output_hashes([outputs[input_index]])
    else:
        hash_outputs = b"\x00" * 32
        hash_output_hashes = b"\x00" * 32

    return (
        struct.pack("<I", version)
        + hash_prevouts
        + hash_sequence
        + me["txid"][::-1]
        + struct.pack("<I", me["vout"])
        + _ref_compactsize(len(me["script"]))
        + me["script"]
        + struct.pack("<Q", me["value"])
        + struct.pack("<I", me["sequence"])
        + hash_output_hashes
        + hash_outputs
        + struct.pack("<I", locktime)
        + struct.pack("<I", sighash)
    )


# ═══════════════════════════════════════════════════════════════════════════════
# Anchor the reference to the external radiantjs vectors
# ═══════════════════════════════════════════════════════════════════════════════

_P2PKH_AA = bytes.fromhex("76a914" + "aa" * 20 + "88ac")
_P2PKH_BB = bytes.fromhex("76a914" + "bb" * 20 + "88ac")
_REF_HEX = "b73ea8b33a8d8f15b25d25b9e6892926f893a7fdb6a97695d029732aa4ae01cd00000000"
_NFT_SCRIPT = bytes.fromhex("d8" + _REF_HEX + "7576a914" + "cc" * 20 + "88ac")


class TestReferenceAnchoredToRadiantjsVectors:
    """The reference impl must reproduce the radiantjs-generated golden
    hashes (tests/test_preimage.py, verified against mainnet reveal tx
    dac1e2df…b407). This pins the reference to an implementation the
    production code never shared a line with."""

    def test_two_p2pkh_outputs(self):
        got = _ref_hash_output_hashes([(100_000, _P2PKH_AA), (50_000, _P2PKH_BB)])
        assert got.hex() == "131577023e4b1972c69b79fe851412e64390576ea90514ed5b83e9bfcc261304"

    def test_single_p2pkh_output(self):
        got = _ref_hash_output_hashes([(546, _P2PKH_AA)])
        assert got.hex() == "42053adc8c31d4299864f45101c180c7397471cd13b2ac0451217754649b33cf"

    def test_nft_singleton_output(self):
        got = _ref_hash_output_hashes([(442_546, _NFT_SCRIPT)])
        assert got.hex() == "148f582c4c97db5fe686d68a5ed054a4b6946c0f498051a5f9df0040af48e791"

    def test_nft_plus_p2pkh(self):
        got = _ref_hash_output_hashes([(442_546, _NFT_SCRIPT), (100_000, _P2PKH_AA)])
        assert got.hex() == "049613e42ad3c0e25a8bfa55065d8481e35633dd9df743c7e98914d401edf4b2"

    def test_single_index_1(self):
        got = _ref_hash_output_hashes([(100_000, _P2PKH_AA)])
        assert got.hex() == "d3a62446cf608f656518faa07460984194bb21a7c43e5af8584e4b6a70228ae4"


# ═══════════════════════════════════════════════════════════════════════════════
# Script-shape strategies
# ═══════════════════════════════════════════════════════════════════════════════

# A ref pool with crafted LE-sort stressors: pairs that order differently
# under uint288-LE vs raw-lexicographic comparison, plus refs sharing bytes
# to exercise dedup.
_REF_POOL = [
    b"\xff" + bytes(35),  # huge first byte, tiny uint288
    bytes(35) + b"\x01",  # tiny bytes, huge uint288
    b"\x01" + bytes(35),
    bytes(35) + b"\xff",
    bytes.fromhex(_REF_HEX),
    bytes(range(36)),
]

_ref_strategy = st.one_of(
    st.sampled_from(_REF_POOL),
    st.binary(min_size=36, max_size=36),
)

# Non-push single-byte opcodes. Never an operand-carrying opcode — those are
# emitted only as well-formed <op><36-byte ref> elements by _pushref below.
#
# 0xd4-0xd7 (the REFHASH* stack ops) are included deliberately: they sit inside
# the 0xd0-0xd8 range but carry NO operand, and a walker that treats that range
# as contiguous swallows the following 36 bytes and invents a ref out of them.
_plain_opcodes = st.sampled_from(
    [
        b"\x00",
        b"\x4f",
        b"\x51",
        b"\x60",
        b"\x61",
        b"\x69",
        b"\x75",
        b"\x76",
        b"\x87",
        b"\x88",
        b"\xa9",
        b"\xac",
        b"\xbd",
        b"\xd4",
        b"\xd5",
        b"\xd6",
        b"\xd7",  # operand-less, mid-ref-range
    ]
)

# Data pushes across all four encodings. Payloads may contain 0xd0/0xd8
# bytes on purpose: a correct scanner must skip push payloads, never
# interpret them as pushref opcodes.
_direct_push = st.binary(min_size=0, max_size=0x4B).map(lambda d: (bytes([len(d)]) + d) if d else b"\x00")
_pushdata1 = st.binary(min_size=0, max_size=80).map(lambda d: b"\x4c" + bytes([len(d)]) + d)
_pushdata2 = st.binary(min_size=0, max_size=80).map(lambda d: b"\x4d" + struct.pack("<H", len(d)) + d)
_pushdata4 = st.binary(min_size=0, max_size=80).map(lambda d: b"\x4e" + struct.pack("<I", len(d)) + d)
# Every operand-carrying opcode, not just the two that contribute refs. Emitting
# only 0xd0/0xd8 here is what made this differential blind to the sighash bug:
# no generated script ever contained a 0xd1/0xd2/0xd3, so the shared defect in
# the reference could never be exercised.
_pushref = st.tuples(st.sampled_from([bytes([o]) for o in sorted(_OPERAND_OPS)]), _ref_strategy).map(
    lambda t: t[0] + t[1]
)

# Biased at the two that actually contribute refs, so sort/dedup paths stay
# well covered now that the alphabet is wider.
_collected_pushref = st.tuples(st.sampled_from([bytes([o]) for o in sorted(_PUSHREF_OPS)]), _ref_strategy).map(
    lambda t: t[0] + t[1]
)

_script_element = st.one_of(_plain_opcodes, _direct_push, _pushdata1, _pushdata2, _pushdata4, _pushref)

_script_strategy = st.lists(_script_element, min_size=0, max_size=8).map(b"".join)

# Scripts guaranteed to carry 2+ COLLECTED refs, biasing toward the interesting
# sort/dedup paths. Built from _collected_pushref rather than _pushref so that
# widening the operand alphabet above cannot quietly turn these into scripts
# with zero refs, which would stop exercising sort order at all.
_multi_ref_script = st.lists(_collected_pushref, min_size=2, max_size=5).map(b"".join)


# 2+ collected refs with walked-but-not-collected opcodes and operand-less
# REFHASH* ops shuffled in: the shape where the sort order and the walk have to
# be right at the same time. This is the Photonic nftAuthScript case
# (OP_REQUIREINPUTREF <ref> … OP_PUSHINPUTREFSINGLETON <ref>) generalised.
@st.composite
def _multi_ref_with_noise(draw):
    parts = draw(st.lists(_collected_pushref, min_size=2, max_size=4))
    noise = draw(st.lists(st.one_of(_pushref, _plain_opcodes, _direct_push), min_size=1, max_size=4))
    combined = parts + noise
    return b"".join(draw(st.permutations(combined)))


_sighash_strategy = st.sampled_from(
    [
        int(SIGHASH.ALL_FORKID),
        int(SIGHASH.NONE_FORKID),
        int(SIGHASH.SINGLE_FORKID),
        int(SIGHASH.ALL_ANYONECANPAY_FORKID),
        int(SIGHASH.NONE_ANYONECANPAY_FORKID),
        int(SIGHASH.SINGLE_ANYONECANPAY_FORKID),
    ]
)

_input_strategy = st.fixed_dictionaries(
    {
        "txid": st.binary(min_size=32, max_size=32),
        "vout": st.integers(min_value=0, max_value=0xFFFFFFFF),
        "script": _script_strategy,
        "value": st.integers(min_value=0, max_value=2**63 - 1),
        "sequence": st.integers(min_value=0, max_value=0xFFFFFFFF),
        "sighash": _sighash_strategy,
    }
)


@st.composite
def _tx_shape(draw, output_scripts=_script_strategy):
    inputs = draw(st.lists(_input_strategy, min_size=1, max_size=4))
    outputs = draw(
        st.lists(
            st.tuples(st.integers(min_value=0, max_value=2**63 - 1), output_scripts),
            min_size=0,
            max_size=4,
        )
    )
    version = draw(st.integers(min_value=0, max_value=0x7FFFFFFF))
    locktime = draw(st.integers(min_value=0, max_value=0xFFFFFFFF))
    return inputs, outputs, version, locktime


def _to_pyrxd(inputs: list[dict], outputs: list[tuple[int, bytes]]):
    tx_ins = []
    for i in inputs:
        tx_in = TransactionInput(
            source_txid=i["txid"].hex(),
            source_output_index=i["vout"],
            sequence=i["sequence"],
            sighash=i["sighash"],
        )
        tx_in.locking_script = Script(i["script"])
        tx_in.satoshis = i["value"]
        tx_ins.append(tx_in)
    tx_outs = [TransactionOutput(Script(s), v) for v, s in outputs]
    return tx_ins, tx_outs


# ═══════════════════════════════════════════════════════════════════════════════
# Differential properties
# ═══════════════════════════════════════════════════════════════════════════════


@given(shape=_tx_shape())
@settings(max_examples=_budget(300), deadline=None, suppress_health_check=[HealthCheck.too_slow])
def test_preimage_matches_reference(shape):
    """tx_preimage (per-index path) == spec-derived reference, byte-for-byte,
    for every input index of every generated transaction shape."""
    inputs, outputs, version, locktime = shape
    tx_ins, tx_outs = _to_pyrxd(inputs, outputs)
    for idx in range(len(inputs)):
        got = tx_preimage(idx, tx_ins, tx_outs, version, locktime)
        want = _ref_preimage(idx, inputs, outputs, version, locktime)
        assert got == want, f"preimage diverges from spec reference at input {idx}"


@given(shape=_tx_shape())
@settings(max_examples=_budget(200), deadline=None, suppress_health_check=[HealthCheck.too_slow])
def test_preimages_batch_matches_reference(shape):
    """tx_preimages (batch path with cached hashes) must agree with the
    reference too — it is a separate implementation of the same derivation
    and has historically been where caching shortcuts would hide."""
    inputs, outputs, version, locktime = shape
    tx_ins, tx_outs = _to_pyrxd(inputs, outputs)
    got = tx_preimages(tx_ins, tx_outs, version, locktime)
    want = [_ref_preimage(i, inputs, outputs, version, locktime) for i in range(len(inputs))]
    assert got == want


@given(shape=_tx_shape(output_scripts=_multi_ref_script))
@settings(max_examples=_budget(200), deadline=None, suppress_health_check=[HealthCheck.too_slow])
def test_preimage_matches_reference_multi_ref_outputs(shape):
    """Force every output to carry 2+ pushrefs so the consensus-required
    uint288-LE sort + dedup path is exercised on every example (the ~50%
    dMint signing failure of PR #228 lived exactly here)."""
    inputs, outputs, version, locktime = shape
    tx_ins, tx_outs = _to_pyrxd(inputs, outputs)
    for idx in range(len(inputs)):
        got = tx_preimage(idx, tx_ins, tx_outs, version, locktime)
        want = _ref_preimage(idx, inputs, outputs, version, locktime)
        assert got == want


@given(shape=_tx_shape(output_scripts=_multi_ref_with_noise()))
@settings(max_examples=_budget(200), deadline=None, suppress_health_check=[HealthCheck.too_slow])
def test_preimage_matches_reference_with_walked_but_uncollected_ops(shape):
    """Outputs mixing collected refs with operand-carrying opcodes that
    contribute none (0xd1/0xd2/0xd3) and operand-less ops in the same byte
    range (0xd4-0xd7).

    This is the shape the generators could not previously produce, which is why
    this differential passed while the sighash bug it was built to catch was
    live in production.
    """
    inputs, outputs, version, locktime = shape
    tx_ins, tx_outs = _to_pyrxd(inputs, outputs)
    for idx in range(len(inputs)):
        got = tx_preimage(idx, tx_ins, tx_outs, version, locktime)
        want = _ref_preimage(idx, inputs, outputs, version, locktime)
        assert got == want


class TestReferenceWalksAllOperandOpcodes:
    """Direct regression on the reference implementation itself.

    The reference used to walk only 0xd0/0xd8 — the same mistake production
    made — so the two agreed and the differential reported green. These cases
    fail against that old reference.
    """

    def test_require_input_ref_operand_is_skipped_not_scanned(self):
        script = bytes([0xD1]) + bytes.fromhex(_REF_HEX) + bytes([0xD8]) + bytes.fromhex(_REF_HEX)
        assert _ref_scan_refs(script) == [bytes.fromhex(_REF_HEX)]

    def test_operand_bytes_that_look_like_pushrefs_are_not_refs(self):
        """A 0xd3 whose operand is 36 bytes of 0xd0. A walker that does not
        consume the operand reports a ref made of 0xd0 bytes and loses the
        real one that follows."""
        script = bytes([0xD3]) + bytes([0xD0]) * 36 + bytes([0xD0]) + bytes.fromhex(_REF_HEX)
        assert _ref_scan_refs(script) == [bytes.fromhex(_REF_HEX)]

    @pytest.mark.parametrize("op", [0xD1, 0xD2, 0xD3])
    def test_walked_operand_opcodes_contribute_no_refs(self, op):
        assert _ref_scan_refs(bytes([op]) + bytes(36)) == []

    @pytest.mark.parametrize("op", [0xD4, 0xD5, 0xD6, 0xD7])
    def test_refhash_ops_take_no_operand(self, op):
        script = bytes([op]) + bytes([0xD0]) + bytes.fromhex(_REF_HEX)
        assert _ref_scan_refs(script) == [bytes.fromhex(_REF_HEX)]

    def test_reference_rules_come_from_the_vendored_cpp(self):
        assert {0xD0, 0xD1, 0xD2, 0xD3, 0xD8} == _OPERAND_OPS
        assert {0xD0, 0xD8} == _PUSHREF_OPS
        assert _OPERAND_WIDTH == 36
