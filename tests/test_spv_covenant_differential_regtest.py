"""Live-regtest validation of the differential-test covenant semantics.

Resolves the "needs live-regtest" skip-marked / NOT-modelled questions in
``tests/test_spv_covenant_differential_deployed.py`` against REAL Radiant
consensus via ``testmempoolaccept`` on an isolated ``radiant-core:v2.3.0`` regtest
node — the only way to pin behaviour that depends on the compiled script
interpreter (8-byte OP_BIN2NUM, nBits exponent ceiling, output introspection,
the claimDeadline floor, sentinel-branch handling).

CHECKPOINT SCOPE (this commit): the regtest harness + helpers + the **S-1 CRITICAL
baseline** — the canonical happy-path finalize MUST be ACCEPTED. Every Direction-A
"covenant rejects" result is only trustworthy once this baseline is green, so it
is built and confirmed first; the full case matrix (V/NB/M/S groups) follows.

Plan: docs/brainstorms/gravity-ref-spike/REGTEST_VALIDATION_PLAN_2026-05-30.md.

Gating (matches test_htlc_regtest_e2e.py): ``@pytest.mark.integration`` +
``RADIANT_REGTEST=1`` opt-in; skips (never fails) without docker / the image.
Run: ``RADIANT_REGTEST=1 pytest tests/test_spv_covenant_differential_regtest.py -m integration -s``

NEVER touches a mainnet node; isolated throwaway container; every covenant verdict
comes from ``testmempoolaccept`` (no broadcast of any covenant spend).
"""

from __future__ import annotations

import pytest

from pyrxd.gravity.codehash import compute_p2sh_code_hash, compute_p2sh_script_pubkey
from pyrxd.gravity.covenant import build_gravity_offer
from pyrxd.gravity.transactions import build_finalize_tx
from pyrxd.keys import PrivateKey
from pyrxd.spv.payment import P2WPKH
from pyrxd.spv.pow import hash256, verify_header_pow
from pyrxd.spv.proof import CovenantParams, SpvProofBuilder

# Reuse the isolated-regtest harness wholesale (node fixture spins up + tears down
# a throwaway radiant-core:v2.3.0 container; accepts() == testmempoolaccept).
from tests.test_htlc_regtest_e2e import _pay_to_spk, _RegtestNode, node  # noqa: F401  (node = fixture)

# Reuse the PROVEN, model-faithful BTC-tx builder + output-offset helper + constants
# from the differential test, so the funding-tx shape exactly matches the covenant
# model the deployed test diffs against.
from tests.test_spv_covenant_differential_deployed import (
    _SPK,
    MAKER20,
    SATS,
    _build,
    _output0_offset,
)

pytestmark = pytest.mark.integration

# Relaxed-target nBits: exponent 0x1d (Python's Nbits accepts <= 0x1d) so a regtest
# header grinds in ~hundreds of nonces while still satisfying verify_header_pow.
_NBITS = b"\xff\xff\x7f\x1d"
_ANCHOR = b"\x99" * 32
_ANCHOR_HEIGHT = 800_000
_HEADER_SLOTS = 12  # MakerCovenantFlat12x20 ABI
_CLAIM_DEADLINE = 1_900_000_000  # year 2030; > the covenant's baked 1774427796 floor + now+24h
_PHOTONS = 10_000_000  # 0.1 RXD locked in the MakerClaimed UTXO
_FEE_SATS = 30_000_000  # 0.3 RXD — covers the ~12 KB finalize tx at the regtest relayfee (~0.01 RXD/kB)


def _grind_relaxed_header(prev_hash: bytes, merkle_root_le: bytes) -> bytes:
    """Grind one relaxed-target (nBits 0x1d) 80-byte header that passes verify_header_pow.

    Loose pre-gate (BE top byte == 0) keeps the grind to ~hundreds of nonces; the
    real target check is verify_header_pow.
    """
    base = b"\x00\x00\x00\x20" + prev_hash + merkle_root_le + b"\x00\x00\x00\x00" + _NBITS
    for nonce in range(120_000_000):
        h = base + nonce.to_bytes(4, "little")
        d = hash256(h)
        # ffff7f1d target_be = 00 00 00 7f ff ff 00... -> need the top 3 BE bytes (LE 29..31) zero
        # (the 2^24 pre-gate the proven differential grinder uses), then verify_header_pow.
        if d[29] == 0 and d[30] == 0 and d[31] == 0:
            try:
                verify_header_pow(h)
                return h
            except Exception:
                continue
    raise AssertionError("could not grind relaxed header")


def _build_anchored_proof(payment_spk: bytes, btc_satoshis: int = SATS):
    """Build a 12-header anchored chain whose h1 commits a single-input/single-output
    BTC payment tx (empty scriptSig) at pos=1, and Python-verify it into an SpvProof.

    Returns (spv_proof, txid_be, raw_hex). h2..h12 carry junk roots (tx is only in h1);
    they exist to fill the covenant's 12 header slots and chain by PoW.
    """
    raw_tx = _build([b""], [(btc_satoshis, payment_spk)])  # single input, empty scriptSig, output-0 = payment
    assert len(raw_tx) > 64
    txid_le = hash256(raw_tx)
    txid_be = txid_le[::-1].hex()
    sib_le = b"\xab" * 32
    sib_be = sib_le[::-1].hex()
    h1_root = hash256(sib_le + txid_le)  # pos=1: H(sibling || txid)

    # The chain is fully determined by the tx (h1_root) + the static anchor/nbits, so
    # cache it to disk — the ~3 min 12-header grind then runs ONCE, and debug iterations
    # of the finalize/covenant path are instant.
    import json as _json
    import os as _os

    _cache = f"/tmp/regtest_spv_chain_{txid_le.hex()}.json"
    if _os.path.exists(_cache):
        with open(_cache) as _f:
            headers = [bytes.fromhex(x) for x in _json.load(_f)["headers_hex"]]
    else:
        headers = []
        prev = _ANCHOR
        for i in range(_HEADER_SLOTS):
            root = h1_root if i == 0 else b"\x77" * 32  # the tx is committed only in h1
            hdr = _grind_relaxed_header(prev, root)
            headers.append(hdr)
            prev = hash256(hdr)
        with open(_cache, "w") as _f:
            _json.dump({"headers_hex": [h.hex() for h in headers]}, _f)

    output_offset = _output0_offset(raw_tx)
    assert output_offset is not None
    params = CovenantParams(
        btc_receive_hash=MAKER20,
        btc_receive_type=P2WPKH,
        btc_satoshis=btc_satoshis,
        chain_anchor=_ANCHOR,
        anchor_height=_ANCHOR_HEIGHT,
        merkle_depth=1,
        expected_nbits=_NBITS,
    )
    spv = SpvProofBuilder(params).build(
        txid_be=txid_be,
        raw_tx_hex=raw_tx.hex(),
        headers_hex=[h.hex() for h in headers],
        merkle_be=[sib_be],
        pos=1,
        output_offset=output_offset,
        tx_block_height=_ANCHOR_HEIGHT + 1,  # tx is in h1
    )
    return spv, txid_be, raw_tx.hex()


def _make_offer(maker_key: PrivateKey, taker_key: PrivateKey, *, btc_satoshis: int = SATS, photons: int = _PHOTONS):
    """Build a MakerCovenantFlat12x20 offer bound to these keys (regtest difficulty)."""
    taker_radiant_pkh = taker_key.public_key().hash160()
    return build_gravity_offer(
        maker_pkh=maker_key.public_key().hash160(),
        maker_pk=maker_key.public_key().serialize(),
        taker_pk=taker_key.public_key().serialize(),
        taker_radiant_pkh=taker_radiant_pkh,
        btc_receive_hash=MAKER20,
        btc_receive_type="p2wpkh",
        btc_satoshis=btc_satoshis,
        btc_chain_anchor=_ANCHOR,
        expected_nbits=_NBITS,
        anchor_height=_ANCHOR_HEIGHT,
        merkle_depth=1,
        claim_deadline=_CLAIM_DEADLINE,
        photons_offered=photons,
        reject_low_difficulty=False,  # regtest relaxed nBits (ffff7f1d) — opt out of the F-02 floor
    )


def _deploy_claimed_utxo(rnode: _RegtestNode, offer) -> tuple[str, int, int]:
    """Fund the MakerClaimed P2SH UTXO on regtest (the single missing deploy primitive).

    finalize() inspects only the SPENDING tx + the SPV data, not how the claimed UTXO
    was created, so paying the P2SH directly is a faithful shortcut. Returns (txid, 0, value).
    """
    claimed_redeem = bytes.fromhex(offer.claimed_redeem_hex)
    # offline consistency check before any node call
    assert compute_p2sh_code_hash(claimed_redeem) == bytes.fromhex(offer.expected_code_hash_hex)
    claimed_spk = compute_p2sh_script_pubkey(claimed_redeem)
    carrier = offer.photons_offered + _FEE_SATS  # so output-0 floor + fee both hold
    txid = _pay_to_spk(rnode, claimed_spk, carrier)
    return txid, 0, carrier


# ============================================================================ S-1
def test_s1_happy_path_finalize_accepted(node: _RegtestNode):
    """S-1 (CRITICAL baseline): the canonical empty-scriptSig finalize is ACCEPTED by
    the deployed covenant on real regtest consensus. If this fails the covenant is
    non-functional for the native-segwit payment it is built around — and no
    Direction-A reject elsewhere is trustworthy until this is green."""
    maker_key = PrivateKey(b"\x11" * 32)
    taker_key = PrivateKey(b"\x22" * 32)
    offer = _make_offer(maker_key, taker_key)

    funding_txid, funding_vout, funding_photons = _deploy_claimed_utxo(node, offer)

    spv, _txid_be, _raw_hex = _build_anchored_proof(_SPK[P2WPKH](MAKER20))
    fin = build_finalize_tx(
        spv_proof=spv,
        claimed_redeem_hex=offer.claimed_redeem_hex,
        funding_txid=funding_txid,
        funding_vout=funding_vout,
        funding_photons=funding_photons,
        to_address=taker_key.address(),
        fee_sats=_FEE_SATS,
        minimum_output_photons=offer.photons_offered,
        header_slots=_HEADER_SLOTS,
        branch_slots=20,
    )

    res = node.accepts(fin.tx_hex)
    assert res.get("allowed") is True, f"S-1 baseline finalize REJECTED: {res.get('reject-reason')!r} | {res}"
