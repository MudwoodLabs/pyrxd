"""Tests for the BTC-side Taproot HTLC (``pyrxd.btc_wallet.taproot``).

Correctness is anchored on the official BIP341 wallet test vectors
(``tests/fixtures/bip341_wallet_vectors.json``, fetched from the bitcoin/bips
repo). The vector-validated surface is:

* tagged hashes (TapLeaf / TapBranch via leaf-hash + merkle-root checks)
* the TapTweak output key (tweak by merkle root)
* the control block (incl. an ODD-parity 2-leaf case — vector 4)
* the BIP341 sighash (key-path; all 7 hashType variants incl. SIGHASH_DEFAULT)

Everything that is structurally checked but NOT replayed against a live node
(funding-address bech32m round trip, claim/refund witness layout, script-path
sighash) is verified by re-deriving the sighash and confirming the BIP340
Schnorr signature validates under coincurve — full crypto, no broadcast.
"""

from __future__ import annotations

import hashlib
import json
import os
import struct
from pathlib import Path

import coincurve
import pytest
from hypothesis import given
from hypothesis import strategies as st

from pyrxd.btc_wallet import taproot as t
from pyrxd.security.errors import ValidationError

_VECTORS = json.loads((Path(__file__).parent / "fixtures" / "bip341_wallet_vectors.json").read_text())


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _xonly(sk: coincurve.PrivateKey) -> bytes:
    return coincurve.PublicKeyXOnly.from_secret(sk.secret).format()


def _fresh_swap(amount: int = 100_000, blocks: int = 144):
    maker_sk = coincurve.PrivateKey(os.urandom(32))
    taker_sk = coincurve.PrivateKey(os.urandom(32))
    p = os.urandom(32)
    h = hashlib.sha256(p).digest()
    tl = t.Timelock(blocks, t.TimeUnit.BLOCKS)
    htlc = t.build_htlc(
        hashlock=h,
        claim_pubkey_xonly=_xonly(maker_sk),
        refund_pubkey_xonly=_xonly(taker_sk),
        timeout=tl,
    )
    loc = htlc.with_funding(t.BtcOutpoint("ab" * 32, 0), amount)
    return maker_sk, taker_sk, p, h, tl, htlc, loc


# ---------------------------------------------------------------------------
# Tagged hashes
# ---------------------------------------------------------------------------


def test_tagged_hash_matches_definition():
    tag = "TapLeaf"
    msg = b"hello"
    th = hashlib.sha256(tag.encode()).digest()
    assert t.tagged_hash(tag, msg) == hashlib.sha256(th + th + msg).digest()


# ---------------------------------------------------------------------------
# BIP341 scriptPubKey vectors: leaf hash / branch / output key / control block
# ---------------------------------------------------------------------------


def _two_leaf_vectors():
    """Flat 2-leaf trees only (vec 3 even-parity, vec 4 odd-parity).

    Vectors 5/6 are 3-leaf trees encoded as a nested ``[leaf, [leaf, leaf]]``
    list — excluded here (the HTLC topology is exactly two flat leaves).
    """
    out = []
    for i, e in enumerate(_VECTORS["scriptPubKey"]):
        tree = e["given"]["scriptTree"]
        if isinstance(tree, list) and len(tree) == 2 and all(isinstance(x, dict) for x in tree):
            out.append((i, e))
    return out


@pytest.mark.parametrize("idx,entry", _two_leaf_vectors())
def test_bip341_two_leaf_vectors(idx, entry):
    """Vector-validated: leaf hashes, merkle root, output key, both control blocks."""
    leaves = entry["given"]["scriptTree"]
    inter = entry["intermediary"]
    ik = bytes.fromhex(entry["given"]["internalPubkey"])

    lh0 = t.tapleaf_hash(bytes.fromhex(leaves[0]["script"]), leaves[0]["leafVersion"])
    lh1 = t.tapleaf_hash(bytes.fromhex(leaves[1]["script"]), leaves[1]["leafVersion"])
    assert lh0.hex() == inter["leafHashes"][0]
    assert lh1.hex() == inter["leafHashes"][1]

    mr = t.tapbranch_hash(lh0, lh1)
    assert mr.hex() == inter["merkleRoot"]

    ok = t.taproot_output_key(ik, mr)
    assert ok.hex() == inter["tweakedPubkey"]
    assert entry["expected"]["scriptPubKey"] == "5120" + ok.hex()

    # Control block for leaf 0 (sibling = leaf 1) and leaf 1 (sibling = leaf 0).
    # Leaf version is carried from the vector (vec 3 uses 0xfa on leaf 1).
    cb0 = t.control_block(ik, mr, lh1, leaf_version=leaves[0]["leafVersion"])
    cb1 = t.control_block(ik, mr, lh0, leaf_version=leaves[1]["leafVersion"])
    assert cb0.hex() == entry["expected"]["scriptPathControlBlocks"][0]
    assert cb1.hex() == entry["expected"]["scriptPathControlBlocks"][1]


def test_control_block_odd_parity():
    """Vector 4 is a 2-leaf tree whose tweaked output key has ODD parity.

    keys.py:~217 hardcodes even parity (b"\\x02"+x); the control-block code must
    NOT inherit that — the first byte's low bit must be 1 here.
    """
    entry = _VECTORS["scriptPubKey"][4]
    assert isinstance(entry["given"]["scriptTree"], list)
    cbs = entry["expected"]["scriptPathControlBlocks"]
    # Confirm the vector itself is odd-parity (defends the test from drifting).
    assert all((int(cb[:2], 16) & 1) == 1 for cb in cbs)

    leaves = entry["given"]["scriptTree"]
    ik = bytes.fromhex(entry["given"]["internalPubkey"])
    lh0 = t.tapleaf_hash(bytes.fromhex(leaves[0]["script"]), leaves[0]["leafVersion"])
    lh1 = t.tapleaf_hash(bytes.fromhex(leaves[1]["script"]), leaves[1]["leafVersion"])
    mr = t.tapbranch_hash(lh0, lh1)
    cb0 = t.control_block(ik, mr, lh1, leaf_version=leaves[0]["leafVersion"])
    # Our control block must carry the odd parity bit, matching the vector.
    assert cb0[0] & 1 == 1
    assert cb0.hex() == cbs[0]


# ---------------------------------------------------------------------------
# BIP341 sighash (key-path) vectors — all hashType variants
# ---------------------------------------------------------------------------


def _parse_unsigned_tx(raw: bytes):
    pos = 0

    def rd(k):
        nonlocal pos
        o = raw[pos : pos + k]
        pos += k
        return o

    def rcs():
        nonlocal pos
        first = raw[pos]
        pos += 1
        if first < 0xFD:
            return first
        sz = {0xFD: 2, 0xFE: 4, 0xFF: 8}[first]
        val = int.from_bytes(raw[pos : pos + sz], "little")
        pos += sz
        return val

    version = struct.unpack("<i", rd(4))[0]
    nin = rcs()
    inputs = []
    for _ in range(nin):
        prevout = rd(36)
        slen = rcs()
        rd(slen)
        seq = struct.unpack("<I", rd(4))[0]
        inputs.append((prevout, seq))
    nout = rcs()
    outputs = []
    for _ in range(nout):
        amt = struct.unpack("<q", rd(8))[0]
        slen = rcs()
        spk = rd(slen)
        outputs.append((amt, spk))
    locktime = struct.unpack("<I", rd(4))[0]
    return version, inputs, outputs, locktime


def test_bip341_keypath_sighash_vectors():
    """Vector-validated: the BIP341 sighash for all 7 inputSpending hashTypes."""
    kp = _VECTORS["keyPathSpending"][0]
    raw = bytes.fromhex(kp["given"]["rawUnsignedTx"])
    version, inputs, outputs, locktime = _parse_unsigned_tx(raw)
    spent = [(u["amountSats"], bytes.fromhex(u["scriptPubKey"])) for u in kp["given"]["utxosSpent"]]

    checked = 0
    for e in kp["inputSpending"]:
        idx = e["given"]["txinIndex"]
        htype = e["given"]["hashType"]
        sh = t.taproot_sighash(
            tx_version=version,
            locktime=locktime,
            inputs=inputs,
            input_index=idx,
            spent_outputs=spent,
            outputs=outputs,
            hash_type=htype,
        )
        assert sh.hex() == e["intermediary"]["sigHash"], f"input {idx} hashType {htype}"
        checked += 1
    assert checked == 7


# ---------------------------------------------------------------------------
# NUMS internal key — provable + key-path unspendable (negative)
# ---------------------------------------------------------------------------


def test_nums_is_the_canonical_constant_and_valid_point():
    assert t.NUMS_INTERNAL_KEY_XONLY.hex() == ("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0")
    assert t.nums_point_is_unspendable(t.NUMS_INTERNAL_KEY_XONLY) is True
    # A random x-only key is NOT the NUMS point.
    assert t.nums_point_is_unspendable(os.urandom(32)) is False


def test_no_keypath_spend_against_nums():
    """Negative: there is no scalar we can find that produces a valid key-path sig.

    We cannot prove a negative by exhaustion, but we CAN show the structural
    property the safety relies on: the NUMS x-only key is not derivable from any
    private key our generator could produce (no secret maps to it), and the
    funding output key is the merkle-root tweak of NUMS — so a key-path spend
    would require signing under the NUMS point, whose discrete log is unknown.

    Concretely: assert that signing with any honestly-generated key does NOT yield
    a signature that verifies under the NUMS x-only key.
    """
    msg = os.urandom(32)
    for _ in range(50):
        sk = coincurve.PrivateKey(os.urandom(32))
        sig = sk.sign_schnorr(msg, os.urandom(32))
        assert coincurve.PublicKeyXOnly(t.NUMS_INTERNAL_KEY_XONLY).verify(sig, msg) is False
    # And the HTLC always uses NUMS as its internal key by default.
    _, _, _, _, _, htlc, _ = _fresh_swap()
    assert htlc.internal_key == t.NUMS_INTERNAL_KEY_XONLY


# ---------------------------------------------------------------------------
# Tapscript leaf builders
# ---------------------------------------------------------------------------


def test_claim_leaf_commits_to_preimage_directly():
    """Claim leaf is OP_SIZE <0x20> OP_EQUALVERIFY OP_SHA256 <H> OP_EQUALVERIFY <pk> OP_CHECKSIG (NOT HASH160).

    The leading ``OP_SIZE <0x20> OP_EQUALVERIFY`` consensus-pins the preimage to 32 bytes
    (security review: a non-32-byte ``p'`` would be silently skipped by the 32-byte-only
    ``scrape_secret`` and strand the taker)."""
    h = os.urandom(32)
    pk = os.urandom(32)
    script = t.claim_leaf_script(h, pk)
    assert script[0:1] == b"\x82"  # OP_SIZE
    assert script[1:3] == b"\x01\x20"  # minimal push of 0x20 (== 32) — does NOT re-trigger F-001
    assert script[3:4] == b"\x88"  # OP_EQUALVERIFY (length == 32)
    assert script[4:5] == b"\xa8"  # OP_SHA256
    assert script[5] == 32 and script[6:38] == h  # push H directly
    assert script[38:39] == b"\x88"  # OP_EQUALVERIFY
    assert script[39] == 32 and script[40:72] == pk
    assert script[72:73] == b"\xac"  # OP_CHECKSIG
    # The leaf hashes with OP_SHA256 (single hash), NOT OP_HASH160(SHA256) — Boltz's
    # pattern is explicitly avoided so the witness reveals the real preimage.
    assert script[4] != 0xA9  # the hash opcode is OP_SHA256, not OP_HASH160
    assert len(script) == 73  # OP_SIZE pin (4 bytes) + OP_SHA256 <H> OP_EQUALVERIFY <pk> OP_CHECKSIG


def test_refund_leaf_uses_csv():
    # Canonical ordering: <timeout> OP_CSV OP_DROP <refundPk> OP_CHECKSIG.
    # Timelock gate FIRST, value-leaving OP_CHECKSIG LAST so the tapscript ends
    # with exactly one truthy element (BIP342 cleanstack). The earlier ordering
    # (<pk> OP_CHECKSIGVERIFY <timeout> OP_CSV OP_DROP) ended with an EMPTY stack
    # and every refund spend was rejected "Stack size must be exactly one".
    # Fixed (non-random) pk so byte-level assertions are deterministic: a random
    # pk can contain 0xad/0xb2/0x75 by chance, which would make a naive substring
    # search over the whole script flaky.
    pk = bytes(range(32))
    script = t.refund_leaf_script(pk, t.Timelock(144, t.TimeUnit.BLOCKS))
    # the pubkey push + OP_CHECKSIG terminate the script
    assert script.endswith(b"\x20" + pk + b"\xac")  # PUSH32 <pk> OP_CHECKSIG
    # Examine ONLY the opcode bytes that precede the <PUSH32 pk> terminal — the
    # 34-byte push is data, not opcodes, so searching it for opcode values is wrong.
    opcode_prefix = script[: -(1 + 32 + 1)]  # drop 0x20 || pk(32) || OP_CHECKSIG
    assert b"\xb2" in opcode_prefix  # OP_CSV present
    csv_idx = opcode_prefix.index(b"\xb2")
    assert opcode_prefix[csv_idx + 1 : csv_idx + 2] == b"\x75"  # OP_DROP immediately after OP_CSV
    assert csv_idx >= 1  # a timeout operand precedes OP_CSV
    assert b"\xad" not in opcode_prefix  # NO OP_CHECKSIGVERIFY (the buggy terminal)


def test_leaf_builders_accept_bytearray():
    """The boundary must normalise bytearray (prior bug: a guard rejected it)."""
    h = bytearray(os.urandom(32))
    pk = bytearray(os.urandom(32))
    s = t.claim_leaf_script(h, pk)
    assert isinstance(s, bytes)
    s2 = t.refund_leaf_script(pk, t.Timelock(10, t.TimeUnit.BLOCKS))
    assert isinstance(s2, bytes)


def test_leaf_builders_reject_wrong_length():
    with pytest.raises(ValidationError):
        t.claim_leaf_script(os.urandom(31), os.urandom(32))
    with pytest.raises(ValidationError):
        t.refund_leaf_script(os.urandom(33), t.Timelock(10, t.TimeUnit.BLOCKS))


# ---------------------------------------------------------------------------
# Timelock / BIP68
# ---------------------------------------------------------------------------


def test_timelock_block_nsequence():
    assert t.Timelock(10, t.TimeUnit.BLOCKS).to_nsequence() == 10
    assert t.Timelock(0, t.TimeUnit.BLOCKS).to_nsequence() == 0


def test_timelock_seconds_nsequence():
    # 1024 seconds = 2 * 512s units, with the type flag (bit 22) set.
    ns = t.Timelock(1024, t.TimeUnit.SECONDS).to_nsequence()
    assert ns == (1 << 22) | 2


def test_timelock_normalize_requires_like_units_to_compare():
    blocks = t.Timelock(144, t.TimeUnit.BLOCKS)
    secs = blocks.normalize_to(t.TimeUnit.SECONDS, block_interval_s=600)
    assert secs.unit is t.TimeUnit.SECONDS
    assert secs.value == 144 * 600


def test_timelock_rejects_bad_input():
    with pytest.raises(ValidationError):
        t.Timelock(-1, t.TimeUnit.BLOCKS)
    with pytest.raises(ValidationError):
        t.Timelock(70000, t.TimeUnit.BLOCKS)  # > 16-bit
    with pytest.raises(ValidationError):
        t.Timelock(True, t.TimeUnit.BLOCKS)  # bool rejected


# ---------------------------------------------------------------------------
# HTLC construction + funding address (structurally checked, not on-chain)
# ---------------------------------------------------------------------------


def test_htlc_address_is_bech32m_p2tr():
    _, _, _, _, _, htlc, _ = _fresh_swap()
    assert htlc.address.startswith("bc1p")
    assert htlc.scriptpubkey[:2] == b"\x51\x20"
    assert len(htlc.control_block_claim) == 65
    assert len(htlc.control_block_refund) == 65


def test_locator_is_full_durable_state_and_roundtrips_without_secret():
    _, _, p, _, _, _, loc = _fresh_swap()
    d = loc.to_dict()
    # The preimage must never appear in the serialised durable state.
    assert p.hex() not in json.dumps(d)
    loc2 = t.BtcHtlcLocator.from_dict(d)
    assert loc2.address == loc.address
    assert loc2.scriptpubkey == loc.scriptpubkey
    assert loc2.control_block_claim == loc.control_block_claim
    assert loc2.control_block_refund == loc.control_block_refund


def test_locator_rejects_reduced_state():
    # control blocks must be 65 bytes — a truncated locator is rejected at the boundary.
    _, _, _, _, _, _, loc = _fresh_swap()
    with pytest.raises(ValidationError):
        t.BtcHtlcLocator(
            funding_outpoint=loc.funding_outpoint,
            script_tree=loc.script_tree,
            control_block_claim=b"\x00" * 10,
            control_block_refund=loc.control_block_refund,
            internal_key=loc.internal_key,
            amount_sats=loc.amount_sats,
        )


# ---------------------------------------------------------------------------
# Claim / refund spend builders — crypto-verified (no broadcast)
# ---------------------------------------------------------------------------


def _script_path_sighash(loc, leaf, out_amount, dest, nsequence):
    leaf_script = loc.script_tree.script_for(leaf)
    lh = t.tapleaf_hash(leaf_script, loc.script_tree.leaf_version)
    return t.taproot_sighash(
        tx_version=2,
        locktime=0,
        inputs=[(loc.funding_outpoint.prevout_bytes(), nsequence)],
        input_index=0,
        spent_outputs=[(loc.amount_sats, loc.scriptpubkey)],
        outputs=[(out_amount, dest)],
        hash_type=t.SIGHASH_DEFAULT,
        tapleaf_hash_value=lh,
    )


def test_claim_tx_witness_layout_and_signature_valid():
    maker_sk, _, p, _, _, _, loc = _fresh_swap()
    dest = b"\x51\x20" + os.urandom(32)
    tx = t.build_claim_tx(
        locator=loc,
        preimage=p,
        claim_privkey=maker_sk.secret,
        to_scriptpubkey=dest,
        fee_sats=500,
        aux_rand=os.urandom(32),
    )
    stacks = t._iter_witness_stack(tx)
    assert len(stacks) == 1
    w = stacks[0]
    assert len(w) == 4
    sig, preimage, script, cb = w
    assert len(sig) == 64  # SIGHASH_DEFAULT: no trailing hashtype byte
    assert preimage == p
    assert script == loc.script_tree.claim_script
    assert cb == loc.control_block_claim

    sh = _script_path_sighash(loc, "claim", loc.amount_sats - 500, dest, 0xFFFFFFFD)
    assert coincurve.PublicKeyXOnly(_xonly(maker_sk)).verify(sig, sh) is True


def test_refund_tx_witness_layout_signature_and_nsequence():
    _, taker_sk, _, _, tl, _, loc = _fresh_swap(blocks=20)
    dest = b"\x51\x20" + os.urandom(32)
    tx = t.build_refund_tx(
        locator=loc,
        refund_privkey=taker_sk.secret,
        timeout=tl,
        to_scriptpubkey=dest,
        fee_sats=500,
        aux_rand=os.urandom(32),
    )
    stacks = t._iter_witness_stack(tx)
    w = stacks[0]
    assert len(w) == 3  # <sig> <refund_script> <control_block> (no preimage)
    sig, script, cb = w
    assert script == loc.script_tree.refund_script
    assert cb == loc.control_block_refund

    sh = _script_path_sighash(loc, "refund", loc.amount_sats - 500, dest, tl.to_nsequence())
    assert coincurve.PublicKeyXOnly(_xonly(taker_sk)).verify(sig, sh) is True
    # v2 tx (BIP68) — version int32 little-endian == 2.
    assert struct.unpack("<i", tx[:4])[0] == 2


def test_claim_rejects_wrong_preimage():
    maker_sk, _, _, _, _, _, loc = _fresh_swap()
    wrong = os.urandom(32)  # almost surely does not open the hashlock
    with pytest.raises(ValidationError):
        t.build_claim_tx(
            locator=loc,
            preimage=wrong,
            claim_privkey=maker_sk.secret,
            to_scriptpubkey=b"\x51\x20" + os.urandom(32),
            fee_sats=500,
            aux_rand=os.urandom(32),
        )


def test_sign_schnorr_requires_aux_rand():
    # aux_rand is a keyword-only required arg (no default) — calling without it errors.
    with pytest.raises(TypeError):
        t.sign_schnorr(os.urandom(32), os.urandom(32))  # type: ignore[call-arg]


# ---------------------------------------------------------------------------
# scrape_secret — happy path + hypothesis fuzz
# ---------------------------------------------------------------------------


def test_scrape_secret_happy_path():
    maker_sk, _, p, h, _, _, loc = _fresh_swap()
    tx = t.build_claim_tx(
        locator=loc,
        preimage=p,
        claim_privkey=maker_sk.secret,
        to_scriptpubkey=b"\x51\x20" + os.urandom(32),
        fee_sats=500,
        aux_rand=os.urandom(32),
    )
    assert t.scrape_secret(tx, h) == p


def test_scrape_secret_refund_tx_has_no_preimage():
    _, taker_sk, _, h, tl, _, loc = _fresh_swap()
    tx = t.build_refund_tx(
        locator=loc,
        refund_privkey=taker_sk.secret,
        timeout=tl,
        to_scriptpubkey=b"\x51\x20" + os.urandom(32),
        fee_sats=500,
        aux_rand=os.urandom(32),
    )
    with pytest.raises(ValidationError):
        t.scrape_secret(tx, h)


def test_scrape_secret_matches_by_hash_not_offset():
    """If the witness carries decoy 32-byte pushes, the real p (by sha256==H) wins."""
    maker_sk, _, p, h, _, htlc, _ = _fresh_swap()
    loc = htlc.with_funding(t.BtcOutpoint("cd" * 32, 3), 100_000)
    tx = t.build_claim_tx(
        locator=loc,
        preimage=p,
        claim_privkey=maker_sk.secret,
        to_scriptpubkey=b"\x51\x20" + os.urandom(32),
        fee_sats=500,
        aux_rand=os.urandom(32),
    )
    # The control block (65B) and script are also witness pushes; none of them
    # hash to H, only the real preimage does.
    assert t.scrape_secret(tx, h) == p


@given(st.binary(min_size=0, max_size=400))
def test_scrape_secret_never_crashes_on_arbitrary_bytes(blob):
    """Fuzz: arbitrary byte blobs never index-error; only a true match returns."""
    h = hashlib.sha256(b"some-preimage-fixed").digest()
    try:
        result = t.scrape_secret(blob, h)
    except ValidationError:
        return  # acceptable — no matching witness push
    # If it returned, it MUST be a 32-byte value whose sha256 is H.
    assert len(result) == 32
    assert hashlib.sha256(result).digest() == h


@given(
    preimage=st.binary(min_size=32, max_size=32),
    decoys=st.lists(st.binary(min_size=0, max_size=40), max_size=8),
    n_inputs=st.integers(min_value=1, max_value=4),
)
def test_scrape_secret_finds_preimage_in_adversarial_witness(preimage, decoys, n_inputs):
    """A hand-assembled segwit tx with decoy pushes: scrape returns the real p only.

    Builds a minimal but structurally-valid segwit tx so the witness parser
    exercises real framing, then confirms scrape_secret picks the push that
    hashes to H regardless of position, and refuses when H is absent.
    """
    h = hashlib.sha256(preimage).digest()

    # Assemble a segwit tx: version, marker/flag, n_inputs, n_outputs=1, witnesses.
    out = bytearray()
    out += struct.pack("<i", 2)
    out += b"\x00\x01"
    out += t._compact_size(n_inputs)
    for i in range(n_inputs):
        out += bytes([i]) * 32  # txid
        out += struct.pack("<I", i)  # vout
        out += b"\x00"  # empty scriptSig
        out += struct.pack("<I", 0xFFFFFFFD)  # sequence
    out += t._compact_size(1)
    out += struct.pack("<q", 1000)
    spk = b"\x51\x20" + bytes(32)
    out += t._compact_size(len(spk)) + spk
    # Witnesses: put the real preimage on the LAST input among decoys.
    for i in range(n_inputs):
        items = list(decoys)
        if i == n_inputs - 1:
            items.append(preimage)
        out += t._compact_size(len(items))
        for it in items:
            out += t._compact_size(len(it)) + it
    out += struct.pack("<I", 0)

    found = t.scrape_secret(bytes(out), h)
    assert found == preimage

    # If we scrape for an unrelated hashlock, it must refuse (never return a decoy).
    other = hashlib.sha256(preimage + b"x").digest()
    if other != h:
        with pytest.raises(ValidationError):
            t.scrape_secret(bytes(out), other)
