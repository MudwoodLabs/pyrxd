#!/usr/bin/env python3
"""Gravity full trade flow — broadcast MakerOffer, then claim via SPV.

Four modes selected by GRAVITY_MODE env var:

  GRAVITY_MODE=offer  (default)
    - Derives Maker keys from MAKER_RXD_WIF
    - Generates fresh Taker keypair (RXD + BTC testnet)
    - Builds GravityOffer with real covenant bytecode
    - Broadcasts MakerOffer tx on RXD mainnet
    - Persists all trade state to GRAVITY_STATE_FILE (default: gravity_trade_state.json)
    - Prints the BTC testnet address to fund

  GRAVITY_MODE=claim
    - Loads trade state from GRAVITY_STATE_FILE
    - Checks if BTC testnet address has been funded and confirmed
    - Builds SPV proof of the BTC payment
    - Broadcasts build_claim_tx on RXD mainnet (MakerOffer → MakerClaimed)
    - Broadcasts build_finalize_tx on RXD mainnet (MakerClaimed → Taker's RXD address)

  GRAVITY_MODE=forfeit
    - Loads trade state from GRAVITY_STATE_FILE
    - Waits until claim_deadline has passed
    - Broadcasts build_forfeit_tx to reclaim photons to Maker's address
    - Fee is capped at (claimed_photons - photons_offered) to guarantee positive output

  GRAVITY_MODE=cancel
    - Loads trade state from GRAVITY_STATE_FILE
    - Cancels a MakerOffer that was never claimed (Maker sig, no deadline)
    - Broadcasts build_cancel_tx to reclaim offer photons to Maker's address

Usage:
  MAKER_RXD_WIF=<wif> GRAVITY_MODE=offer python3 examples/gravity_full_trade.py
  GRAVITY_MODE=claim python3 examples/gravity_full_trade.py
  MAKER_RXD_WIF=<wif> GRAVITY_MODE=forfeit python3 examples/gravity_full_trade.py
  MAKER_RXD_WIF=<wif> GRAVITY_MODE=cancel python3 examples/gravity_full_trade.py
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import sys
import time
from pathlib import Path

# ─── Config ────────────────────────────────────────────────────────────────────

GRAVITY_MODE: str = os.environ.get("GRAVITY_MODE", "offer")
GRAVITY_STATE_FILE: str = os.environ.get("GRAVITY_STATE_FILE", "gravity_trade_state.json")

RXD_ELECTRUMX_URL: str = os.environ.get("RXD_ELECTRUMX_URL", "wss://electrumx.radiant4people.com:50022/")
BTC_API_URL: str = os.environ.get("BTC_API_URL", "https://blockstream.info/api")
BTC_NETWORK: str = os.environ.get("BTC_NETWORK", "bc")  # "bc" = mainnet, "tb" = testnet

# Fee rate — 10,000 photons/byte
FEE_RATE_PH_PER_BYTE = 10_000
MAKER_OFFER_TX_BYTES = 200  # P2PKH → P2SH
CLAIM_TX_BYTES = 300  # P2SH unlock with offer redeem + sig
FINALIZE_TX_BYTES = 12_500  # sentinel artifact: ~10.2KB redeem + 12×80B headers + 20×33B branch + 113B rawTx + overhead
RXD_FEE = FEE_RATE_PH_PER_BYTE * MAKER_OFFER_TX_BYTES  # deducted at offer time
CLAIM_FEE = FEE_RATE_PH_PER_BYTE * CLAIM_TX_BYTES  # 3,000,000 photons
FINALIZE_FEE = FEE_RATE_PH_PER_BYTE * FINALIZE_TX_BYTES  # 55,000,000 photons

BTC_SATOSHIS = int(os.environ.get("BTC_SATOSHIS", "1500"))  # sats to pay on BTC side
BTC_FEE_SATS = int(os.environ.get("BTC_FEE_SATS", "500"))  # BTC tx fee

EXPECTED_HOT_WALLET_ADDR = os.environ.get("EXPECTED_MAKER_ADDR", "")
HOT_WALLET_PKH_HEX = os.environ.get("EXPECTED_MAKER_PKH_HEX", "")

# ─── Helpers ───────────────────────────────────────────────────────────────────


def _hr(label: str) -> None:
    pad = (68 - len(label) - 2) // 2
    print(f"\n{'─' * pad} {label} {'─' * pad}")


def _ok(msg: str) -> None:
    print(f"  [OK]  {msg}")


def _info(msg: str) -> None:
    print(f"  [..]  {msg}")


def _warn(msg: str) -> None:
    print(f"  [!!]  {msg}", file=sys.stderr)


def _fail(msg: str) -> None:
    print(f"  [FAIL] {msg}", file=sys.stderr)
    sys.exit(1)


def _hash256(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def _load_state() -> dict:
    p = Path(GRAVITY_STATE_FILE)
    if not p.exists():
        _fail(f"State file not found: {GRAVITY_STATE_FILE}. Run with GRAVITY_MODE=offer first.")
    return json.loads(p.read_text())


def _save_state(state: dict) -> None:
    Path(GRAVITY_STATE_FILE).write_text(json.dumps(state, indent=2))
    _ok(f"Trade state saved → {GRAVITY_STATE_FILE}")


# ─── Mode: offer ───────────────────────────────────────────────────────────────


async def mode_offer() -> None:
    """Broadcast MakerOffer and persist all state needed for claim/forfeit."""
    import coincurve

    from pyrxd.btc_wallet.keys import generate_keypair
    from pyrxd.gravity.covenant import build_gravity_offer
    from pyrxd.gravity.transactions import build_maker_offer_tx
    from pyrxd.network.bitcoin import BlockstreamSource
    from pyrxd.security.secrets import PrivateKeyMaterial
    from pyrxd.security.types import BlockHeight

    _hr("Gravity Trade — OFFER mode")

    # ── Maker keys ──────────────────────────────────────────────────────────────
    maker_wif = os.environ.get("MAKER_RXD_WIF")
    if not maker_wif:
        _fail("Set MAKER_RXD_WIF to your Radiant hot wallet WIF.")
    maker_pk_mat = PrivateKeyMaterial.from_wif(maker_wif)
    maker_wif = None
    maker_raw = maker_pk_mat.unsafe_raw_bytes()
    maker_pub = coincurve.PrivateKey(maker_raw).public_key.format(compressed=True)
    maker_pkh = hashlib.new("ripemd160", hashlib.sha256(maker_pub).digest()).digest()
    from pyrxd.base58 import base58check_encode

    maker_addr = base58check_encode(b"\x00" + maker_pkh)
    if EXPECTED_HOT_WALLET_ADDR and maker_addr != EXPECTED_HOT_WALLET_ADDR:
        _fail(f"WIF derives {maker_addr}, expected {EXPECTED_HOT_WALLET_ADDR}")
    _ok(f"Maker address: {maker_addr}")

    # ── Taker keys ──────────────────────────────────────────────────────────────
    taker_rxd_mat = PrivateKeyMaterial.generate()
    taker_raw = taker_rxd_mat.unsafe_raw_bytes()
    taker_pub = coincurve.PrivateKey(taker_raw).public_key.format(compressed=True)
    taker_pkh = hashlib.new("ripemd160", hashlib.sha256(taker_pub).digest()).digest()
    taker_btc = generate_keypair(network=BTC_NETWORK)
    _ok(f"Taker RXD PKH: {taker_pkh.hex()}")
    _ok(f"Taker BTC p2wpkh: {taker_btc.p2wpkh_address}")

    # ── BTC anchor ──────────────────────────────────────────────────────────────
    _info("Fetching BTC anchor block...")
    btc = BlockstreamSource(base_url=BTC_API_URL)
    try:
        tip = int(await btc.get_tip_height())
        anchor_height = tip - 6  # a few blocks back for stability
        anchor_header_bytes = await btc.get_block_header_hex(BlockHeight(anchor_height))
        chain_anchor = _hash256(anchor_header_bytes)
        _ok(f"BTC anchor height: {anchor_height}, anchor: {chain_anchor.hex()[:16]}...")
    finally:
        await btc.close()

    # ── Fetch live UTXO ─────────────────────────────────────────────────────────
    import websockets as _ws

    _info("Fetching Maker UTXO from ElectrumX...")
    async with _ws.connect(RXD_ELECTRUMX_URL) as ws:
        script = bytes.fromhex("76a914" + HOT_WALLET_PKH_HEX + "88ac")
        script_hash_le = hashlib.sha256(script).digest()[::-1].hex()
        await ws.send(json.dumps({"id": 1, "method": "blockchain.scripthash.listunspent", "params": [script_hash_le]}))
        resp = json.loads(await ws.recv())
    utxos = sorted(resp.get("result", []), key=lambda u: u["value"], reverse=True)
    if not utxos:
        _fail("No UTXOs on hot wallet.")
    utxo = utxos[0]
    _ok(f"UTXO: {utxo['tx_hash']}:{utxo['tx_pos']} = {utxo['value']} photons")
    total_needed = RXD_FEE + CLAIM_FEE + FINALIZE_FEE + 10_000  # +10k min output
    if utxo["value"] < total_needed:
        _fail(
            f"UTXO too small ({utxo['value']:,}) — need {total_needed:,} photons "
            f"({total_needed / 1e8:.4f} RXD) to cover all tx fees"
        )

    # P2SH UTXO value = utxo - offer_fee.
    # photons_offered (covenant threshold) = P2SH value - claim_fee - finalize_fee.
    # Claim tx output = P2SH value - claim_fee    (must be >= photons_offered) ✓
    # Finalize output = claim output - finalize_fee = photons_offered         ✓
    p2sh_value = utxo["value"] - RXD_FEE
    photons_offered = p2sh_value - CLAIM_FEE - FINALIZE_FEE
    _info(f"P2SH UTXO value: {p2sh_value:,}  photons_offered threshold: {photons_offered:,}")
    claim_deadline = int(time.time()) + 25 * 3600  # 25h

    # ── Build offer ─────────────────────────────────────────────────────────────
    # Use the actual nBits from the anchor block — the finalize tx will present
    # headers from a nearby block which will have the same nBits unless a
    # difficulty adjustment crosses the gap (every 2016 blocks ≈ 2 weeks).
    # Anchor header LE bytes: version(4) + prevHash(32) + merkle(32) + time(4) + bits(4) + nonce(4)
    expected_nbits = anchor_header_bytes[72:76]  # bits field, 4 bytes LE
    _ok(f"Expected nBits: {expected_nbits.hex()}")
    offer = build_gravity_offer(
        maker_pkh=maker_pkh,
        maker_pk=maker_pub,
        taker_pk=taker_pub,
        taker_radiant_pkh=taker_pkh,
        btc_receive_hash=taker_btc.pkh,
        btc_receive_type="p2wpkh",
        btc_satoshis=BTC_SATOSHIS,
        btc_chain_anchor=chain_anchor,
        expected_nbits=expected_nbits,
        anchor_height=anchor_height,
        merkle_depth=20,  # unified covenant supports depth 1-20; actual depth determined at claim time
        claim_deadline=claim_deadline,
        photons_offered=photons_offered,
        covenant_artifact_name="maker_covenant_unified_p2wpkh",
    )
    _ok(
        f"GravityOffer built — offer_redeem: {len(offer.offer_redeem_hex) // 2}B, "
        f"claimed_redeem: {len(offer.claimed_redeem_hex) // 2}B"
    )

    # ── Build & broadcast MakerOffer tx ─────────────────────────────────────────
    result = build_maker_offer_tx(
        offer=offer,
        funding_txid=utxo["tx_hash"],
        funding_vout=utxo["tx_pos"],
        funding_photons=utxo["value"],
        fee_sats=RXD_FEE,
        maker_privkey=maker_pk_mat,
    )
    _ok(f"MakerOffer tx: {result.txid}  ({result.tx_size}B)")
    _ok(f"MakerOffer P2SH: {result.offer_p2sh}")
    _ok(f"Photons locked: {result.output_photons}")

    async with _ws.connect(RXD_ELECTRUMX_URL) as ws:
        await ws.send(json.dumps({"id": 2, "method": "blockchain.transaction.broadcast", "params": [result.tx_hex]}))
        resp = json.loads(await ws.recv())
    if resp.get("error"):
        _fail(f"Broadcast failed: {resp['error']}")
    returned_txid = resp.get("result", "")
    if returned_txid != result.txid:
        _warn(f"Returned txid {returned_txid!r} != computed {result.txid!r}")
    _ok(f"MakerOffer broadcast SUCCESS: {returned_txid}")

    # ── Persist state ────────────────────────────────────────────────────────────
    state = {
        "maker_offer_txid": result.txid,
        "maker_offer_vout": 0,
        "maker_offer_photons": result.output_photons,
        "maker_offer_p2sh": result.offer_p2sh,
        "offer_redeem_hex": offer.offer_redeem_hex,
        "claimed_redeem_hex": offer.claimed_redeem_hex,
        "expected_code_hash_hex": offer.expected_code_hash_hex,
        "btc_receive_address": taker_btc.p2wpkh_address,
        "btc_receive_pkh": taker_btc.pkh.hex(),
        "btc_receive_type": "p2wpkh",
        "btc_satoshis": BTC_SATOSHIS,
        "btc_anchor_height": anchor_height,
        "btc_chain_anchor": chain_anchor.hex(),
        "expected_nbits": expected_nbits.hex(),
        "claim_deadline": claim_deadline,
        "taker_rxd_privkey_hex": taker_rxd_mat.unsafe_raw_bytes().hex(),
        "taker_rxd_pkh": taker_pkh.hex(),
        "maker_rxd_pkh": maker_pkh.hex(),
        "maker_rxd_address": maker_addr,
        "photons_offered": photons_offered,
        "rxd_fee": RXD_FEE,
        "btc_satoshis_min": BTC_SATOSHIS,
        "anchor_height": anchor_height,
        "merkle_depth": 20,  # unified covenant; actual depth determined at claim time from merkle proof
        "btc_receive_hash": taker_btc.pkh.hex(),
        "chain_anchor": chain_anchor.hex(),
    }
    _save_state(state)

    print()
    print("=" * 70)
    print("  NEXT STEP: Fund the BTC address with at least")
    print(f"  {BTC_SATOSHIS} sats, then wait for 1 confirmation, then run:")
    print()
    print(f"    BTC address: {taker_btc.p2wpkh_address}")
    print(f"    Min sats:    {BTC_SATOSHIS}")
    print()
    print("  Then: GRAVITY_MODE=claim python3 examples/gravity_full_trade.py")
    print(f"  Forfeit window opens: {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(claim_deadline))}")
    print("=" * 70)


# ─── Mode: claim ───────────────────────────────────────────────────────────────


async def mode_claim() -> None:
    """Build SPV proof of BTC payment and broadcast claim + finalize txs."""
    import coincurve
    import websockets as _ws

    from pyrxd.base58 import base58check_encode
    from pyrxd.gravity.trade import _find_output_zero_offset
    from pyrxd.gravity.transactions import build_claim_tx, build_finalize_tx
    from pyrxd.gravity.types import GravityOffer
    from pyrxd.network.bitcoin import BlockstreamSource
    from pyrxd.security.secrets import PrivateKeyMaterial
    from pyrxd.security.types import BlockHeight, Txid
    from pyrxd.spv.proof import CovenantParams, SpvProofBuilder
    from pyrxd.spv.witness import strip_witness

    _hr("Gravity Trade — CLAIM mode")
    s = _load_state()

    # Reconstruct GravityOffer from persisted state
    offer = GravityOffer(
        btc_receive_hash=bytes.fromhex(s["btc_receive_hash"]),
        btc_receive_type=s["btc_receive_type"],
        btc_satoshis=s["btc_satoshis"],
        chain_anchor=bytes.fromhex(s["chain_anchor"]),
        anchor_height=s["anchor_height"],
        merkle_depth=s["merkle_depth"],
        taker_radiant_pkh=bytes.fromhex(s["taker_rxd_pkh"]),
        claim_deadline=s["claim_deadline"],
        photons_offered=s["photons_offered"],
        offer_redeem_hex=s["offer_redeem_hex"],
        claimed_redeem_hex=s["claimed_redeem_hex"],
        expected_code_hash_hex=s["expected_code_hash_hex"],
    )
    _ok(
        f"Loaded offer — photons: {offer.photons_offered}, deadline: "
        f"{time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(offer.claim_deadline))}"
    )

    taker_privkey = PrivateKeyMaterial(bytes.fromhex(s["taker_rxd_privkey_hex"]))
    taker_raw = taker_privkey.unsafe_raw_bytes()
    coincurve.PrivateKey(taker_raw).public_key.format(compressed=True)
    taker_pkh = bytes.fromhex(s["taker_rxd_pkh"])
    taker_rxd_addr = base58check_encode(b"\x00" + taker_pkh)
    _ok(f"Taker RXD address (finalize destination): {taker_rxd_addr}")

    # ── Find the BTC payment tx ──────────────────────────────────────────────────
    _info(f"Checking BTC address for payment: {s['btc_receive_address']}")
    btc = BlockstreamSource(base_url=BTC_API_URL)
    try:
        import aiohttp

        async with aiohttp.ClientSession() as session:
            url = f"{BTC_API_URL.rstrip('/')}/address/{s['btc_receive_address']}/txs"
            async with session.get(url) as r:
                addr_txs = json.loads(await r.read())

        if not addr_txs:
            _fail(
                f"No transactions found for {s['btc_receive_address']}. "
                f"Fund it with at least {s['btc_satoshis']} sats and wait for confirmation."
            )

        # Find a confirmed tx paying to our address
        btc_txid = None
        btc_height = None
        for tx in addr_txs:
            if tx.get("status", {}).get("confirmed"):
                btc_txid = tx["txid"]
                btc_height = tx["status"]["block_height"]
                break

        if not btc_txid:
            _fail("Found transactions but none confirmed yet. Wait for 1 BTC confirmation.")

        _ok(f"Found confirmed BTC payment: {btc_txid} at height {btc_height}")

        # ── Fetch raw tx + merkle proof ──────────────────────────────────────────
        raw_tx = await btc.get_raw_tx(Txid(btc_txid), min_confirmations=1)
        stripped = strip_witness(bytes(raw_tx))
        _ok(f"Raw tx: {len(raw_tx)} bytes, stripped: {len(stripped)} bytes")

        merkle_hashes, pos = await btc.get_merkle_proof(Txid(btc_txid), BlockHeight(btc_height))
        _ok(f"Merkle proof: {len(merkle_hashes)} hashes, pos={pos}")

        # ── Parse output[0] to find our payment ─────────────────────────────────
        output_offset = _find_output_zero_offset(stripped)
        out_value = int.from_bytes(stripped[output_offset : output_offset + 8], "little")
        script_len = stripped[output_offset + 8]
        out_script = stripped[output_offset + 9 : output_offset + 9 + script_len]
        _ok(f"Output[0]: {out_value} sats, script: {out_script.hex()}")

        if out_value < s["btc_satoshis"]:
            _fail(f"Payment {out_value} sats < required {s['btc_satoshis']} sats")

        # ── Header chain ─────────────────────────────────────────────────────────
        anchor_height = s["btc_anchor_height"]
        anchor_header_bytes = await btc.get_block_header_hex(BlockHeight(anchor_height))
        chain_anchor_check = _hash256(anchor_header_bytes)
        if chain_anchor_check.hex() != s["btc_chain_anchor"]:
            _warn(
                "Chain anchor mismatch — anchor block may have been reorged. "
                "The covenant's btc_chain_anchor is baked in; proceeding anyway."
            )

        # Covenant ABI requires exactly HEADER_SLOTS chained headers starting
        # at anchor+1. If not enough BTC blocks have mined yet past the
        # payment block, fail with a clear wait-longer message.
        HEADER_SLOTS = 12  # unified covenant ABI
        tip_height = int(await btc.get_tip_height())
        if tip_height < anchor_height + HEADER_SLOTS:
            _fail(
                f"BTC tip is at {tip_height}; need {anchor_height + HEADER_SLOTS} "
                f"({HEADER_SLOTS} blocks past anchor {anchor_height}) before "
                "finalize can build a full header chain. Wait for "
                f"{anchor_height + HEADER_SLOTS - tip_height} more BTC blocks "
                "and re-run GRAVITY_MODE=claim."
            )
        headers_raw = await btc.get_header_chain(
            BlockHeight(anchor_height + 1),
            HEADER_SLOTS,
        )
        _ok(f"Fetched {len(headers_raw)} BTC block headers ({anchor_height + 1}–{anchor_height + HEADER_SLOTS})")

        # ── Build SPV proof ──────────────────────────────────────────────────────
        covenant_params = CovenantParams(
            btc_receive_hash=bytes.fromhex(s["btc_receive_hash"]),
            btc_receive_type=s["btc_receive_type"],
            btc_satoshis=1,  # any value <= actual satisfies
            chain_anchor=bytes.fromhex(s["btc_chain_anchor"]),
            anchor_height=anchor_height,
            merkle_depth=len(merkle_hashes),
        )
        builder = SpvProofBuilder(covenant_params)
        proof = builder.build(
            txid_be=btc_txid,
            raw_tx_hex=stripped.hex(),
            headers_hex=[h.hex() for h in headers_raw],
            merkle_be=merkle_hashes,
            pos=pos,
            output_offset=output_offset,
        )
        _ok(f"SPV proof verified — headers: {len(proof.headers)}, branch: {len(proof.branch)}B, pos: {proof.pos}")

    finally:
        await btc.close()

    # ── Claim tx (MakerOffer → MakerClaimed) ────────────────────────────────────
    _hr("Broadcasting claim tx (MakerOffer → MakerClaimed)")

    if s.get("claimed_txid"):
        # Idempotency: claim already broadcast on a prior run; reuse state and
        # skip straight to finalize. This lets a mid-flow failure be retried
        # without double-broadcasting (which would hit "txn-mempool-conflict"
        # or "missing-inputs" if the prior claim already confirmed).
        _ok(f"Claim already broadcast on prior run: {s['claimed_txid']}")
        _ok(f"  claimed output photons: {s['claimed_photons']}")

        class _ClaimShim:
            txid = s["claimed_txid"]
            output_photons = s["claimed_photons"]

        claim = _ClaimShim()
    else:
        claim = build_claim_tx(
            offer=offer,
            funding_txid=s["maker_offer_txid"],
            funding_vout=s["maker_offer_vout"],
            funding_photons=s["maker_offer_photons"],
            fee_sats=CLAIM_FEE,
            taker_privkey=taker_privkey,
            accept_short_deadline=True,
        )
        _ok(f"Claim tx: {claim.txid}  ({claim.tx_size}B)")
        _ok(f"  offer P2SH:   {claim.offer_p2sh}")
        _ok(f"  claimed P2SH: {claim.claimed_p2sh}")
        _ok(f"  output photons: {claim.output_photons}")

        async with _ws.connect(RXD_ELECTRUMX_URL) as ws:
            await ws.send(json.dumps({"id": 3, "method": "blockchain.transaction.broadcast", "params": [claim.tx_hex]}))
            resp = json.loads(await ws.recv())
        if resp.get("error"):
            _fail(f"Claim broadcast failed: {resp['error']}")
        _ok(f"Claim broadcast SUCCESS: {resp.get('result')}")

        # Persist MakerClaimed UTXO info so forfeit path can find it if finalize fails.
        s["claimed_txid"] = claim.txid
        s["claimed_photons"] = claim.output_photons
        _save_state(s)

    # ── Finalize tx (MakerClaimed → Taker's RXD address) ────────────────────────
    _hr("Broadcasting finalize tx (MakerClaimed → Taker RXD)")

    finalize = build_finalize_tx(
        spv_proof=proof,
        claimed_redeem_hex=s["claimed_redeem_hex"],
        funding_txid=claim.txid,
        funding_vout=0,
        funding_photons=claim.output_photons,
        to_address=taker_rxd_addr,
        fee_sats=FINALIZE_FEE,
        minimum_output_photons=offer.photons_offered,
        header_slots=12,  # covenant ABI bakes in 12 header slots
        branch_slots=20,  # sentinel-aware artifact: fixed depth-20, pads shorter proofs
    )
    _ok(f"Finalize tx: {finalize.txid}  ({finalize.tx_size}B)")
    _ok(f"  output photons: {finalize.output_photons} → {taker_rxd_addr}")

    async with _ws.connect(RXD_ELECTRUMX_URL) as ws:
        await ws.send(json.dumps({"id": 4, "method": "blockchain.transaction.broadcast", "params": [finalize.tx_hex]}))
        resp = json.loads(await ws.recv())
    if resp.get("error"):
        _fail(f"Finalize broadcast failed: {resp['error']}")
    _ok(f"Finalize broadcast SUCCESS: {resp.get('result')}")

    print()
    print("=" * 70)
    print("  GRAVITY TRADE COMPLETE")
    print(f"  {finalize.output_photons} photons delivered to {taker_rxd_addr}")
    print("=" * 70)


# ─── Mode: forfeit ─────────────────────────────────────────────────────────────


async def mode_forfeit() -> None:
    """Reclaim photons after claim_deadline passes.

    - If claim has already run: forfeit the MakerClaimed UTXO (deadline-gated).
    - If never claimed: cancel the MakerOffer UTXO (Maker sig only, no deadline).
    """
    import websockets as _ws

    from pyrxd.gravity.transactions import build_forfeit_tx
    from pyrxd.gravity.types import GravityOffer

    _hr("Gravity Trade — FORFEIT/CANCEL mode")
    s = _load_state()

    offer = GravityOffer(
        btc_receive_hash=bytes.fromhex(s["btc_receive_hash"]),
        btc_receive_type=s["btc_receive_type"],
        btc_satoshis=s["btc_satoshis"],
        chain_anchor=bytes.fromhex(s["chain_anchor"]),
        anchor_height=s["anchor_height"],
        merkle_depth=s["merkle_depth"],
        taker_radiant_pkh=bytes.fromhex(s["taker_rxd_pkh"]),
        claim_deadline=s["claim_deadline"],
        photons_offered=s["photons_offered"],
        offer_redeem_hex=s["offer_redeem_hex"],
        claimed_redeem_hex=s["claimed_redeem_hex"],
        expected_code_hash_hex=s["expected_code_hash_hex"],
    )

    maker_wif = os.environ.get("MAKER_RXD_WIF")
    if not maker_wif:
        _fail("Set MAKER_RXD_WIF to sign the forfeit/cancel tx.")
    from pyrxd.security.secrets import PrivateKeyMaterial as _PKM

    _PKM.from_wif(maker_wif)
    maker_wif = None

    if s.get("claimed_txid"):
        # MakerClaimed exists — deadline-gated forfeit()
        now = int(time.time())
        deadline = s["claim_deadline"]
        if deadline > now:
            remaining = deadline - now
            _fail(
                f"Claim deadline not yet reached. Wait {remaining}s "
                f"({remaining // 3600}h {(remaining % 3600) // 60}m). "
                f"Opens at {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(deadline))}"
            )
        funding_txid = s["claimed_txid"]
        funding_vout = 0
        funding_photons = s["claimed_photons"]
        _info(f"Forfeiting MakerClaimed UTXO: {funding_txid}:0 = {funding_photons:,}")
        # Fee must cover the full forfeit tx size (redeem script ~4.5KB dominates).
        # Use FORFEIT_FEE env var to override; default scales by redeem size.
        redeem_size = len(bytes.fromhex(s["claimed_redeem_hex"]))
        forfeit_tx_size = 86 + 4 + redeem_size  # overhead + OP_1+PUSHDATA2 + redeem
        forfeit_fee = int(os.environ.get("FORFEIT_FEE", forfeit_tx_size * FEE_RATE_PH_PER_BYTE))
        max_forfeit_fee = s["claimed_photons"] - s["photons_offered"]
        if forfeit_fee > max_forfeit_fee:
            _info(f"  capping fee at {max_forfeit_fee:,} (claimed - offered; would have been {forfeit_fee:,})")
            forfeit_fee = max_forfeit_fee
        _info(f"  forfeit fee: {forfeit_fee:,} photons ({forfeit_tx_size}B × {FEE_RATE_PH_PER_BYTE}/byte)")
        result = build_forfeit_tx(
            offer=offer,
            funding_txid=funding_txid,
            funding_vout=funding_vout,
            funding_photons=funding_photons,
            maker_address=s["maker_rxd_address"],
            fee_sats=forfeit_fee,
        )
        _ok(f"Forfeit tx: {result.txid}  ({result.tx_size}B)")
    else:
        # Never claimed — fall through to cancel path
        _fail("MakerOffer was never claimed — use GRAVITY_MODE=cancel to reclaim.")

    _ok(f"  output photons: {result.output_photons} → {s['maker_rxd_address']}")

    async with _ws.connect(RXD_ELECTRUMX_URL) as ws:
        await ws.send(json.dumps({"id": 5, "method": "blockchain.transaction.broadcast", "params": [result.tx_hex]}))
        resp = json.loads(await ws.recv())
    if resp.get("error"):
        _fail(f"Broadcast failed: {resp['error']}")
    _ok(f"Broadcast SUCCESS: {resp.get('result')}")
    _ok(f"Photons reclaimed to {s['maker_rxd_address']}")


# ─── Mode: cancel ──────────────────────────────────────────────────────────────


async def mode_cancel() -> None:
    """Reclaim a MakerOffer UTXO that was never claimed.

    Requires MAKER_RXD_WIF. No deadline — cancel() is gated only by Maker sig.
    Use CANCEL_FEE env var to override the default fee (offer_redeem size × rate).
    """
    import websockets as _ws

    from pyrxd.gravity.transactions import build_cancel_tx
    from pyrxd.gravity.types import GravityOffer

    _hr("Gravity Trade — CANCEL mode")
    s = _load_state()

    if s.get("claimed_txid"):
        _fail("MakerClaimed UTXO exists — use GRAVITY_MODE=forfeit, not cancel.")

    offer = GravityOffer(
        btc_receive_hash=bytes.fromhex(s["btc_receive_hash"]),
        btc_receive_type=s["btc_receive_type"],
        btc_satoshis=s["btc_satoshis"],
        chain_anchor=bytes.fromhex(s["chain_anchor"]),
        anchor_height=s["anchor_height"],
        merkle_depth=s["merkle_depth"],
        taker_radiant_pkh=bytes.fromhex(s["taker_rxd_pkh"]),
        claim_deadline=s["claim_deadline"],
        photons_offered=s["photons_offered"],
        offer_redeem_hex=s["offer_redeem_hex"],
        claimed_redeem_hex=s["claimed_redeem_hex"],
        expected_code_hash_hex=s["expected_code_hash_hex"],
    )

    maker_wif = os.environ.get("MAKER_RXD_WIF")
    if not maker_wif:
        _fail("Set MAKER_RXD_WIF to sign the cancel tx.")
    from pyrxd.security.secrets import PrivateKeyMaterial as _PKM

    maker_pk_mat = _PKM.from_wif(maker_wif)
    maker_wif = None

    funding_txid = s["offer_txid"]
    funding_vout = 0
    funding_photons = s["photons_offered"]
    _info(f"Cancelling MakerOffer UTXO: {funding_txid}:0 = {funding_photons:,}")

    redeem_size = len(bytes.fromhex(s["offer_redeem_hex"]))
    cancel_tx_size = 86 + 2 + redeem_size  # overhead + OP_0+PUSHDATA2 + redeem
    cancel_fee = int(os.environ.get("CANCEL_FEE", cancel_tx_size * FEE_RATE_PH_PER_BYTE))
    _info(f"  cancel fee: {cancel_fee:,} photons ({cancel_tx_size}B × {FEE_RATE_PH_PER_BYTE}/byte)")

    result = build_cancel_tx(
        offer=offer,
        funding_txid=funding_txid,
        funding_vout=funding_vout,
        funding_photons=funding_photons,
        maker_address=s["maker_rxd_address"],
        fee_sats=cancel_fee,
        maker_privkey=maker_pk_mat,
    )
    _ok(f"Cancel tx: {result.txid}  ({result.tx_size}B)")
    _ok(f"  output photons: {result.output_photons} → {s['maker_rxd_address']}")

    async with _ws.connect(RXD_ELECTRUMX_URL) as ws:
        await ws.send(json.dumps({"id": 5, "method": "blockchain.transaction.broadcast", "params": [result.tx_hex]}))
        resp = json.loads(await ws.recv())
    if resp.get("error"):
        _fail(f"Broadcast failed: {resp['error']}")
    _ok(f"Broadcast SUCCESS: {resp.get('result')}")
    _ok(f"Photons reclaimed to {s['maker_rxd_address']}")


# ─── Entry point ───────────────────────────────────────────────────────────────


async def run() -> None:
    print()
    print("=" * 70)
    print(f"  Gravity Full Trade  —  mode: {GRAVITY_MODE}")
    print("=" * 70)
    if GRAVITY_MODE == "offer":
        await mode_offer()
    elif GRAVITY_MODE == "claim":
        await mode_claim()
    elif GRAVITY_MODE == "forfeit":
        await mode_forfeit()
    elif GRAVITY_MODE == "cancel":
        await mode_cancel()
    else:
        _fail(f"Unknown GRAVITY_MODE={GRAVITY_MODE!r}. Use offer / claim / forfeit / cancel.")


if __name__ == "__main__":
    asyncio.run(run())
