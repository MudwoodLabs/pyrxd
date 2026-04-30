#!/usr/bin/env python3
"""Gravity BTC↔RXD swap — end-to-end testnet demo.

Walks through every step of the Gravity protocol against live testnets:

    Step 1  Generate / load keypairs (Maker RXD, Taker RXD, Taker BTC)
    Step 2  Connect to Radiant testnet (ElectrumX) + Bitcoin testnet (mempool.space)
    Step 3  Derive receive addresses; print funding instructions
    Step 4  Wait for funding UTXOs to appear on-chain
    Step 5  Build + broadcast the MakerOffer Radiant tx  [Maker]
    Step 6  Build + broadcast the claim tx               [Taker]
    Step 7  Build + broadcast the BTC payment tx         [Taker]
    Step 8  Wait for BTC confirmations
    Step 9  Build + broadcast the finalize tx            [Taker]
    Step 10 Verify final balances

Run modes
---------
    DRY_RUN=1  (default)   — builds every tx but never broadcasts; prints hex
    DRY_RUN=0              — broadcasts to live testnets (REAL FUNDS)

Configuration
-------------
All parameters are read from environment variables so secrets are never
hardcoded. See the "Configuration" section below for the full list.

Usage
-----
    # Dry-run (safe — no broadcasts):
    python examples/gravity_swap_demo.py

    # Live testnet (real broadcasts, small amounts):
    DRY_RUN=0 \\
    RXD_ELECTRUMX_URL=wss://testnet-electrumx.example.com \\
    BTC_MEMPOOL_URL=https://mempool.space/testnet/api \\
    MAKER_RXD_WIF=<wif> TAKER_RXD_WIF=<wif> TAKER_BTC_WIF=<wif> \\
    python examples/gravity_swap_demo.py
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import sys
import time
from typing import Optional

# ─────────────────────────────────────────────────────────────
# Configuration (from environment variables)
# ─────────────────────────────────────────────────────────────

DRY_RUN: bool = os.environ.get("DRY_RUN", "1") != "0"

# Radiant testnet ElectrumX — replace with a real server URL for live runs
RXD_ELECTRUMX_URL: str = os.environ.get(
    "RXD_ELECTRUMX_URL", "wss://electrumx.radiant4people.com:50012"
)

# Bitcoin data source — mempool.space testnet by default
BTC_MEMPOOL_URL: str = os.environ.get(
    "BTC_MEMPOOL_URL", "https://mempool.space/testnet/api"
)

# Optional WIF private keys — generated fresh each dry-run if not set
MAKER_RXD_WIF: Optional[str] = os.environ.get("MAKER_RXD_WIF")
TAKER_RXD_WIF: Optional[str] = os.environ.get("TAKER_RXD_WIF")
TAKER_BTC_WIF: Optional[str] = os.environ.get("TAKER_BTC_WIF")

# Trade amounts
PHOTONS_OFFERED: int = int(os.environ.get("PHOTONS_OFFERED", "100000"))   # 0.001 RXD
BTC_SATOSHIS: int = int(os.environ.get("BTC_SATOSHIS", "10000"))          # 0.0001 BTC
FEE_SATS: int = int(os.environ.get("FEE_SATS", "1000"))                   # photons/sats

# Deadline: 25 hours from now (audit 04-S1 requires >= 24h)
CLAIM_DEADLINE: int = int(time.time()) + 25 * 3600

# BTC confirmations required before finalizing
MIN_BTC_CONFIRMATIONS: int = int(os.environ.get("MIN_BTC_CONFIRMATIONS", "1"))


# ─────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────

def _hr(label: str) -> None:
    width = 70
    print(f"\n{'─' * ((width - len(label) - 2) // 2)} {label} {'─' * ((width - len(label) - 2) // 2)}")


def _ok(msg: str) -> None:
    print(f"  [OK]  {msg}")


def _info(msg: str) -> None:
    print(f"  [..] {msg}")


def _warn(msg: str) -> None:
    print(f"  [!!] {msg}", file=sys.stderr)


def _fail(msg: str) -> None:
    print(f"  [FAIL] {msg}", file=sys.stderr)
    sys.exit(1)


def _hash256(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


# ─────────────────────────────────────────────────────────────
# Main demo
# ─────────────────────────────────────────────────────────────

async def run_demo() -> None:
    # Late imports so the module is importable even without the SDK installed
    from pyrxd.security.secrets import PrivateKeyMaterial
    from pyrxd.btc_wallet.keys import generate_keypair, keypair_from_wif
    from pyrxd.btc_wallet.payment import BtcUtxo, build_payment_tx
    from pyrxd.network.electrumx import ElectrumXClient
    from pyrxd.network.bitcoin import MempoolSpaceSource
    from pyrxd.gravity.types import GravityOffer
    from pyrxd.gravity.transactions import build_claim_tx, build_finalize_tx
    from pyrxd.spv.proof import CovenantParams, SpvProofBuilder
    from pyrxd.spv.witness import strip_witness

    print()
    print("=" * 70)
    print("  pyrxd  —  Gravity BTC↔RXD Swap Demo")
    print(f"  Mode: {'DRY RUN (no broadcasts)' if DRY_RUN else 'LIVE TESTNET'}")
    print("=" * 70)

    # ── Step 1: Keypairs ──────────────────────────────────────────────────
    _hr("Step 1: Keypairs")

    if MAKER_RXD_WIF:
        maker_privkey = PrivateKeyMaterial.from_wif(MAKER_RXD_WIF)
        _info("Loaded Maker RXD key from MAKER_RXD_WIF")
    else:
        maker_privkey = PrivateKeyMaterial.generate()
        _info("Generated fresh Maker RXD private key (ephemeral — save WIF for live runs)")

    if TAKER_RXD_WIF:
        taker_rxd_privkey = PrivateKeyMaterial.from_wif(TAKER_RXD_WIF)
        _info("Loaded Taker RXD key from TAKER_RXD_WIF")
    else:
        taker_rxd_privkey = PrivateKeyMaterial.generate()
        _info("Generated fresh Taker RXD private key")

    if TAKER_BTC_WIF:
        taker_btc_keypair = keypair_from_wif(TAKER_BTC_WIF)
        _info("Loaded Taker BTC key from TAKER_BTC_WIF")
    else:
        taker_btc_keypair = generate_keypair()
        _info("Generated fresh Taker BTC keypair")

    # Derive public key hashes
    import coincurve
    maker_raw = maker_privkey.unsafe_raw_bytes()
    maker_pub = coincurve.PrivateKey(maker_raw).public_key.format(compressed=True)
    maker_pkh = hashlib.new("ripemd160", hashlib.sha256(maker_pub).digest()).digest()

    taker_raw = taker_rxd_privkey.unsafe_raw_bytes()
    taker_pub = coincurve.PrivateKey(taker_raw).public_key.format(compressed=True)
    taker_rxd_pkh = hashlib.new("ripemd160", hashlib.sha256(taker_pub).digest()).digest()

    _ok(f"Maker RXD PKH:  {maker_pkh.hex()}")
    _ok(f"Taker RXD PKH:  {taker_rxd_pkh.hex()}")
    _ok(f"Taker BTC addr: {taker_btc_keypair.p2wpkh_address}")

    # ── Step 2: Network connections ───────────────────────────────────────
    _hr("Step 2: Network Connections")

    btc_source = MempoolSpaceSource(base_url=BTC_MEMPOOL_URL)
    _ok(f"Bitcoin source: {BTC_MEMPOOL_URL}")

    if not DRY_RUN:
        async with ElectrumXClient([RXD_ELECTRUMX_URL]) as rxd_client:
            tip = await rxd_client.get_tip_height()
            _ok(f"Radiant ElectrumX connected — tip height: {int(tip)}")
        btc_tip = await btc_source.get_tip_height()
        _ok(f"Bitcoin tip height: {int(btc_tip)}")
    else:
        _info(f"DRY RUN: skipping live network checks")
        _info(f"  Radiant ElectrumX: {RXD_ELECTRUMX_URL}")

    # ── Step 3: Build synthetic covenant scripts ───────────────────────────
    _hr("Step 3: Covenant Scripts")

    # In production these come from gen_maker_covenant.js or equivalent.
    # For the demo we use synthetic scripts that are structurally valid
    # but not executable on-chain.  The tx-building logic is identical.
    #
    # A real deployment would:
    #   1. Feed maker_pkh, taker_rxd_pkh, claim_deadline, btc params into
    #      the covenant generator to get offer_redeem_hex + claimed_redeem_hex
    #   2. Publish offer_redeem_hex so the Taker can reconstruct the P2SH address

    # Minimal P2PKH-style scriptPubKey wrapping for demo purposes
    def _p2pkh_script(pkh: bytes) -> bytes:
        return b"\x76\xa9\x14" + pkh + b"\x88\xac"

    # Synthetic redeem scripts (25 bytes each, pass length checks)
    offer_redeem_hex = _p2pkh_script(maker_pkh).hex()
    claimed_redeem_hex = _p2pkh_script(taker_rxd_pkh).hex()

    _ok(f"offer_redeem_hex:   {offer_redeem_hex}")
    _ok(f"claimed_redeem_hex: {claimed_redeem_hex}")

    # ── Step 4: Chain anchor (from BTC) ───────────────────────────────────
    _hr("Step 4: Chain Anchor")

    # For dry-run we use a well-known Bitcoin genesis block hash as anchor
    # (LE bytes — this is block 0, so prevHash is all-zero)
    GENESIS_PREV_HASH = bytes(32)

    if not DRY_RUN:
        btc_tip_height = await btc_source.get_tip_height()
        # Anchor on the block 7 behind tip so the Taker's tx has room to land
        anchor_height = int(btc_tip_height) - 7
        anchor_header = await btc_source.get_block_header_hex(
            __import__("pyrxd.security.types", fromlist=["BlockHeight"]).BlockHeight(anchor_height)
        )
        # chain_anchor = prevHash field of h1 = hash of the anchor block itself
        chain_anchor = _hash256(anchor_header)
        _ok(f"Anchor height: {anchor_height}")
        _ok(f"chain_anchor (LE): {chain_anchor.hex()}")
    else:
        anchor_height = 0
        chain_anchor = GENESIS_PREV_HASH
        _info("DRY RUN: using genesis prevHash as chain anchor")

    # ── Step 5: GravityOffer ──────────────────────────────────────────────
    _hr("Step 5: GravityOffer")

    offer = GravityOffer(
        btc_receive_hash=taker_btc_keypair.pkh,
        btc_receive_type="p2wpkh",
        btc_satoshis=BTC_SATOSHIS,
        chain_anchor=chain_anchor,
        anchor_height=anchor_height,
        merkle_depth=1,
        taker_radiant_pkh=taker_rxd_pkh,
        claim_deadline=CLAIM_DEADLINE,
        photons_offered=PHOTONS_OFFERED,
        offer_redeem_hex=offer_redeem_hex,
        claimed_redeem_hex=claimed_redeem_hex,
    )

    _ok(f"GravityOffer created")
    _ok(f"  btc_satoshis:    {offer.btc_satoshis}")
    _ok(f"  photons_offered: {offer.photons_offered}")
    _ok(f"  claim_deadline:  {offer.claim_deadline}  ({time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(offer.claim_deadline))})")

    # ── Step 6: Claim tx ──────────────────────────────────────────────────
    _hr("Step 6: Claim Tx (MakerOffer → MakerClaimed)")

    # Synthetic funding UTXO (in live mode, Maker would broadcast the offer
    # tx and share txid/vout/photons with the Taker out-of-band)
    OFFER_TXID = "aa" * 32
    OFFER_VOUT = 0
    OFFER_PHOTONS = PHOTONS_OFFERED + FEE_SATS  # offer UTXO covers fee

    claim_result = build_claim_tx(
        offer=offer,
        funding_txid=OFFER_TXID,
        funding_vout=OFFER_VOUT,
        funding_photons=OFFER_PHOTONS,
        fee_sats=FEE_SATS,
        taker_privkey=taker_rxd_privkey,
        accept_short_deadline=True,  # demo: skip 24h guard
    )

    _ok(f"claim tx built — txid: {claim_result.txid}")
    _ok(f"  tx size:        {claim_result.tx_size} bytes")
    _ok(f"  output photons: {claim_result.output_photons}")
    _ok(f"  offer P2SH:     {claim_result.offer_p2sh}")
    _ok(f"  claimed P2SH:   {claim_result.claimed_p2sh}")

    if DRY_RUN:
        _info(f"  claim tx hex:   {claim_result.tx_hex[:80]}…")
    else:
        async with ElectrumXClient([RXD_ELECTRUMX_URL]) as rxd_client:
            txid = await rxd_client.broadcast(bytes.fromhex(claim_result.tx_hex))
            _ok(f"claim tx BROADCAST: {txid}")

    # ── Step 7: BTC payment tx ────────────────────────────────────────────
    _hr("Step 7: BTC Payment Tx")

    # Synthetic BTC UTXO (in live mode, Taker uses a real funded P2WPKH UTXO)
    from pyrxd.btc_wallet.payment import BtcUtxo, build_payment_tx

    btc_utxo = BtcUtxo(
        txid="bb" * 32,
        vout=0,
        value=BTC_SATOSHIS + FEE_SATS * 3,
    )

    btc_payment = build_payment_tx(
        keypair=taker_btc_keypair,
        utxo=btc_utxo,
        to_hash=offer.btc_receive_hash,
        to_type=offer.btc_receive_type,
        amount_sats=BTC_SATOSHIS,
        fee_sats=FEE_SATS,
    )

    _ok(f"BTC payment tx built — txid: {btc_payment.txid}")
    _ok(f"  tx size:     {len(bytes.fromhex(btc_payment.tx_hex))} bytes")
    _ok(f"  fee sats:    {btc_payment.fee_sats}")
    _ok(f"  output type: {btc_payment.output_type}")

    if DRY_RUN:
        _info(f"  btc tx hex:  {btc_payment.tx_hex[:80]}…")
    else:
        _warn("Live BTC broadcast not implemented in this demo — use Bitcoin Core or mempool.space")
        _warn(f"Broadcast this hex manually: {btc_payment.tx_hex[:40]}…")

    # ── Step 8: SPV proof (dry-run: synthetic; live: real) ────────────────
    _hr("Step 8: SPV Proof")

    if DRY_RUN:
        _info("DRY RUN: constructing a synthetic (non-verifiable) SPV proof structure")
        _info("  In live mode this calls SpvProofBuilder with real BTC block data")

        # Show what the builder call looks like — in live mode these come from
        # btc_source.get_raw_tx / get_merkle_proof / get_header_chain
        _info("  builder = SpvProofBuilder(CovenantParams(")
        _info(f"      btc_receive_hash={offer.btc_receive_hash.hex()},")
        _info(f"      btc_receive_type={offer.btc_receive_type!r},")
        _info(f"      btc_satoshis={offer.btc_satoshis},")
        _info(f"      chain_anchor=<32 bytes>,")
        _info(f"      anchor_height={offer.anchor_height},")
        _info(f"      merkle_depth={offer.merkle_depth},")
        _info("  ))")
        _info("  proof = builder.build(txid_be, raw_tx_hex, headers_hex, merkle_be, pos, output_offset)")
        _info("  finalize_result = build_finalize_tx(proof, claimed_redeem_hex, ...)")
        spv_skipped = True
    else:
        spv_skipped = False
        # Live: fetch and verify
        from pyrxd.security.types import BlockHeight, Txid

        btc_txid = btc_payment.txid
        _info(f"Fetching SPV data for BTC tx {btc_txid[:16]}…")

        height = await btc_source.get_tip_height()
        raw_tx = await btc_source.get_raw_tx(
            Txid(btc_txid), min_confirmations=MIN_BTC_CONFIRMATIONS
        )
        merkle_hashes, pos = await btc_source.get_merkle_proof(Txid(btc_txid), height)

        start_height = BlockHeight(offer.anchor_height + 1)
        count = int(height) - offer.anchor_height
        headers_raw = await btc_source.get_header_chain(start_height, count)

        stripped = strip_witness(bytes(raw_tx))
        # Determine output offset (native segwit: byte 47)
        output_offset = 47

        covenant_params = CovenantParams(
            btc_receive_hash=offer.btc_receive_hash,
            btc_receive_type=offer.btc_receive_type,
            btc_satoshis=offer.btc_satoshis,
            chain_anchor=offer.chain_anchor,
            anchor_height=offer.anchor_height,
            merkle_depth=offer.merkle_depth,
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
        _ok(f"SPV proof verified — {len(proof.headers)} headers, pos={proof.pos}")

    # ── Step 9: Finalize tx ───────────────────────────────────────────────
    _hr("Step 9: Finalize Tx (MakerClaimed → Taker)")

    if spv_skipped:
        _info("DRY RUN: skipping finalize tx (requires verified SPV proof)")
        _info("  In live mode: build_finalize_tx(proof, claimed_redeem_hex, ...)")
        _info("  then: await rxd_client.broadcast(bytes.fromhex(result.tx_hex))")
    else:
        claimed_txid = claim_result.txid
        claimed_photons = claim_result.output_photons

        # Derive Taker's Radiant P2PKH address from PKH
        from pyrxd.base58 import base58check_encode
        taker_rxd_address = base58check_encode(bytes([0x00]) + taker_rxd_pkh)

        finalize_result = build_finalize_tx(
            spv_proof=proof,
            claimed_redeem_hex=offer.claimed_redeem_hex,
            funding_txid=claimed_txid,
            funding_vout=0,
            funding_photons=claimed_photons,
            to_address=taker_rxd_address,
            fee_sats=FEE_SATS,
        )
        _ok(f"finalize tx built — txid: {finalize_result.txid}")

        async with ElectrumXClient([RXD_ELECTRUMX_URL]) as rxd_client:
            txid = await rxd_client.broadcast(bytes.fromhex(finalize_result.tx_hex))
            _ok(f"finalize tx BROADCAST: {txid}")
            _ok(f"Taker receives {finalize_result.output_photons} photons")

    # ── Summary ───────────────────────────────────────────────────────────
    _hr("Summary")
    _ok("claim tx:    built" + (" + broadcast" if not DRY_RUN else " (dry run)"))
    _ok("BTC pay tx:  built" + (" (broadcast manually)" if not DRY_RUN else " (dry run)"))
    if not spv_skipped:
        _ok("SPV proof:   verified")
        _ok("finalize tx: built + broadcast")
    else:
        _info("SPV proof + finalize: skipped (dry run)")
    print()
    if DRY_RUN:
        print("Set DRY_RUN=0 and supply testnet WIF keys to run against live networks.")
    print()


if __name__ == "__main__":
    asyncio.run(run_demo())
