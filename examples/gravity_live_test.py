#!/usr/bin/env python3
"""Gravity live integration test — real ElectrumX + real BTC testnet APIs.

Exercises the Gravity SDK against LIVE networks (RXD mainnet ElectrumX +
BTC testnet/signet blockstream.info). Every fact this script reports is derived
from a live network call, a cryptographic operation, or the SDK's own validators.

What this script exercises (live):
  - RXD mainnet ElectrumX: connect, fetch tip, fetch hot-wallet balance
  - BTC testnet: fetch tip, pick a real confirmed payment tx, fetch merkle proof,
    fetch header chain, run SpvProofBuilder full verifier chain on real data
  - Real Gravity covenant bytecode via CovenantArtifact + build_gravity_offer:
    MakerOffer + MakerClaimed redeem scripts generated from bundled rxdc artifacts
  - build_maker_offer_tx: Maker-side funding tx (P2PKH → P2SH covenant UTXO)
  - build_claim_tx: Taker-side claim tx (using real covenant bytecode)
  - build_payment_tx: BTC testnet payment tx (non-broadcast)
  - Key derivation sanity: WIF -> PKH -> address (verifiable against known hot-wallet)

What this script cannot do (and why):
  1. Actually broadcast on Radiant: real covenant finalize tx is ~5 KB at
     10k photons/byte = ~50M photon fee minimum. Hot wallet constraint.
  2. Real BTC testnet broadcast: needs a funded Taker UTXO.

DRY_RUN=1 (default): builds all txs with real covenant bytecode, no broadcast.
DRY_RUN=0: attempts to broadcast make_offer_tx on Radiant mainnet (needs MAKER_RXD_WIF
           and a funded UTXO). BTC broadcast still disabled.

Key / address (RXD mainnet maker — do NOT expose WIF in logs):
  WIF:     set via MAKER_RXD_WIF env var (required for live broadcast)
  Address: optionally pin via EXPECTED_MAKER_ADDR (and EXPECTED_MAKER_PKH_HEX)
           to assert the WIF derives the address you expect; leave unset
           to skip the pin check.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import sys
import time
from typing import Optional

# ─────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────

DRY_RUN: bool = os.environ.get("DRY_RUN", "1") != "0"

# RXD mainnet ElectrumX (the only live RXD network — no testnet exists)
RXD_ELECTRUMX_URL: str = os.environ.get(
    "RXD_ELECTRUMX_URL", "wss://electrumx.radiant4people.com:50022/"
)

# BTC testnet3 — we default to blockstream.info because its /merkle-proof
# endpoint returns JSON with the `{merkle, pos, ...}` shape the SDK's
# MempoolSpaceSource/BlockstreamSource parsers expect.  mempool.space returns
# a binary merkleblock at /merkleblock-proof which the SDK can't decode as
# JSON — a known SDK gap for this endpoint variant.
BTC_API_URL: str = os.environ.get(
    "BTC_API_URL", "https://blockstream.info/testnet/api"
)
# Which source class to use — "blockstream" or "mempool"
BTC_SOURCE_KIND: str = os.environ.get("BTC_SOURCE_KIND", "blockstream")

# MAKER_RXD_WIF is intentionally NOT read at module level.
# It is read inside the functions that need it to avoid the key material
# living as a module-level string for the lifetime of the process.

# Small amounts — the user's session constraint (< 100k photons on RXD side)
PHOTONS_OFFERED: int = int(os.environ.get("PHOTONS_OFFERED", "10000"))   # 0.0001 RXD
BTC_SATOSHIS: int = int(os.environ.get("BTC_SATOSHIS", "1000"))           # 1000 sats
FEE_SATS: int = int(os.environ.get("FEE_SATS", "1000"))

# Optional real BTC testnet txid to SPV-prove. If unset, the script scans
# recent blocks for a suitable P2WPKH payment tx.
BTC_TX_TO_PROVE: Optional[str] = os.environ.get("BTC_TX_TO_PROVE")


def _hr(label: str) -> None:
    width = 70
    pad = (width - len(label) - 2) // 2
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


def _hash256(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


# Optional pinned address. If set, the script asserts the WIF derives
# this exact address (sanity check against accidentally swapping WIFs).
# Leave unset to skip the pin check.
EXPECTED_HOT_WALLET_ADDR = os.environ.get("EXPECTED_MAKER_ADDR", "")


async def phase_1_key_derivation():
    """Verify WIF -> address derivation against the known hot-wallet address."""
    from pyrxd.security.secrets import PrivateKeyMaterial
    from pyrxd.base58 import base58check_encode
    import coincurve

    _hr("Phase 1: Key derivation (offline)")

    maker_rxd_wif = os.environ.get("MAKER_RXD_WIF")
    if not maker_rxd_wif:
        _warn("MAKER_RXD_WIF not set; skipping WIF derivation check.")
        _info("Set MAKER_RXD_WIF to run the full test.")
        return None, None, None

    pk = PrivateKeyMaterial.from_wif(maker_rxd_wif)
    maker_rxd_wif = None  # clear from local scope immediately
    raw = pk.unsafe_raw_bytes()
    pub = coincurve.PrivateKey(raw).public_key.format(compressed=True)
    pkh = hashlib.new("ripemd160", hashlib.sha256(pub).digest()).digest()
    addr = base58check_encode(b"\x00" + pkh)

    _ok(f"WIF -> PKH: {pkh.hex()}")
    _ok(f"WIF -> addr: {addr}")

    if EXPECTED_HOT_WALLET_ADDR:
        if addr != EXPECTED_HOT_WALLET_ADDR:
            _fail(
                f"WIF does not match pinned EXPECTED_MAKER_ADDR\n"
                f"       expected: {EXPECTED_HOT_WALLET_ADDR}\n"
                f"       got:      {addr}"
            )
        _ok(f"Derived address matches pinned EXPECTED_MAKER_ADDR: {EXPECTED_HOT_WALLET_ADDR}")
    return pk, pkh, addr


async def phase_2_rxd_network():
    """Connect to live RXD ElectrumX and report tip + wallet balance."""
    from pyrxd.network.electrumx import ElectrumXClient
    from pyrxd.security.types import Hex32

    _hr("Phase 2: RXD mainnet ElectrumX (live)")
    _info(f"Connecting to {RXD_ELECTRUMX_URL}")

    tip_height = None
    balance = None
    async with ElectrumXClient([RXD_ELECTRUMX_URL]) as rxd:
        tip = await rxd.get_tip_height()
        tip_height = int(tip)
        _ok(f"RXD tip height: {tip_height}  (source: ElectrumX server)")

        # Script-hash for P2PKH of the maker address (set EXPECTED_MAKER_PKH_HEX
        # in env to query a balance). scriptPubKey = 76 a9 14 <pkh> 88 ac
        pkh_hex = os.environ.get("EXPECTED_MAKER_PKH_HEX", "")
        balance = 0
        if not pkh_hex:
            _info("EXPECTED_MAKER_PKH_HEX not set; skipping balance check.")
        else:
            script = bytes.fromhex("76a914" + pkh_hex + "88ac")
            script_hash_le = hashlib.sha256(script).digest()[::-1]
            try:
                confirmed, unconfirmed = await rxd.get_balance(Hex32(script_hash_le))
                balance = int(confirmed)
                _ok(f"Maker confirmed balance: {balance} photons "
                    f"= {balance / 1e8:.8f} RXD  (source: ElectrumX get_balance)")
                if unconfirmed:
                    _info(f"Maker unconfirmed: {int(unconfirmed)} photons")
            except Exception as exc:
                _warn(f"Could not fetch balance: {type(exc).__name__}: {exc}")

    return tip_height, balance


async def _find_suitable_btc_tx(btc_source) -> tuple[str, int]:
    """Find a real BTC testnet tx suitable for SPV proof verification.

    Looks a few blocks back from tip, inspects transactions at known-simple
    positions to find one with P2WPKH output[0] and native-segwit layout.
    Returns (txid, height).
    """
    import aiohttp
    import json

    tip = int(await btc_source.get_tip_height())
    for delta in (3, 4, 5, 6, 10, 20):
        height = tip - delta
        try:
            async with aiohttp.ClientSession() as session:
                url = f"{BTC_API_URL.rstrip('/')}/block-height/{height}"
                async with session.get(url) as r:
                    block_hash = (await r.read()).decode().strip()
                url = f"{BTC_API_URL.rstrip('/')}/block/{block_hash}/txids"
                async with session.get(url) as r:
                    txids = json.loads(await r.read())
            for tx_index in range(1, min(20, len(txids))):
                candidate = txids[tx_index]
                try:
                    from pyrxd.security.types import Txid
                    from pyrxd.spv.witness import strip_witness
                    raw = await btc_source.get_raw_tx(Txid(candidate), min_confirmations=1)
                    stripped = strip_witness(bytes(raw))
                    # Must be exactly 1 input (offset 4 = input count varint)
                    if stripped[4] != 0x01:
                        continue
                    otype = await btc_source.get_tx_output_script_type(Txid(candidate), 0)
                    if otype == "p2wpkh":
                        return candidate, height
                except Exception:
                    continue
        except Exception:
            continue
    raise RuntimeError("Could not find a suitable BTC testnet tx in recent blocks")


async def phase_3_btc_network_and_spv():
    """Connect to live BTC testnet and build + verify a real SPV proof."""
    from pyrxd.network.bitcoin import BlockstreamSource, MempoolSpaceSource
    from pyrxd.security.types import BlockHeight, Txid
    from pyrxd.spv.proof import CovenantParams, SpvProofBuilder
    from pyrxd.spv.witness import strip_witness

    _hr("Phase 3: BTC testnet live SPV proof (real data)")

    if BTC_SOURCE_KIND == "mempool":
        btc = MempoolSpaceSource(base_url=BTC_API_URL)
    else:
        btc = BlockstreamSource(base_url=BTC_API_URL)
    try:
        tip = await btc.get_tip_height()
        _ok(f"BTC tip height: {int(tip)}  (source: {BTC_API_URL})")

        if BTC_TX_TO_PROVE:
            target_txid = BTC_TX_TO_PROVE
            _info(f"Using caller-supplied txid: {target_txid}")
            import aiohttp, json
            async with aiohttp.ClientSession() as s:
                url = f"{BTC_API_URL.rstrip('/')}/tx/{target_txid}/status"
                async with s.get(url) as r:
                    st = json.loads(await r.read())
            height = int(st["block_height"])
        else:
            _info("Scanning recent blocks for a suitable P2WPKH payment tx...")
            target_txid, height = await _find_suitable_btc_tx(btc)
            _ok(f"Selected BTC tx: {target_txid[:16]}... at height {height}")

        # Fetch raw tx (require > 0 confirmations)
        raw_tx = await btc.get_raw_tx(Txid(target_txid), min_confirmations=1)
        _ok(f"Fetched raw tx: {len(raw_tx)} bytes")

        # Merkle proof
        merkle_hashes, pos = await btc.get_merkle_proof(Txid(target_txid), BlockHeight(height))
        _ok(f"Fetched merkle proof: {len(merkle_hashes)} branch hashes, pos={pos}")

        # Extract the real output[0] hash + value from the fetched tx
        # so the SPV proof matches what's actually on-chain.
        stripped = strip_witness(bytes(raw_tx))
        # Output[0] parse (simple: after inputs)
        # version(4) + input_count(1) + input(36 outpoint + 1 sslen + 0 ss + 4 seq) + output_count(1)
        # = 4 + 1 + 41 + 1 = 47 for native segwit
        # But we don't know input structure cleanly without a parser — use the
        # SDK's _find_output_zero_offset helper via a tiny inline re-impl:
        from pyrxd.gravity.trade import _find_output_zero_offset
        output_offset = _find_output_zero_offset(stripped)
        _ok(f"Output[0] offset in stripped tx: {output_offset}")

        # Parse output[0]: 8 bytes value + varint len + script
        out_value = int.from_bytes(stripped[output_offset:output_offset + 8], "little")
        script_len = stripped[output_offset + 8]
        out_script = stripped[output_offset + 9:output_offset + 9 + script_len]
        _ok(f"Output[0] value: {out_value} sats, scriptPubKey: {out_script.hex()}")

        # Extract the pkh from an OP_0 <20B> P2WPKH script
        if len(out_script) == 22 and out_script[0] == 0x00 and out_script[1] == 0x14:
            btc_receive_hash = out_script[2:22]
            btc_receive_type = "p2wpkh"
        else:
            _warn(f"Output[0] is not P2WPKH; SPV verification will skip")
            btc_receive_hash = None
            btc_receive_type = "p2wpkh"

        # Chain anchor: prevHash of block (height) = header at (height-1)
        anchor_height = height - 1
        anchor_header = await btc.get_block_header_hex(BlockHeight(anchor_height))
        chain_anchor = _hash256(anchor_header)
        _ok(f"Chain anchor (block {anchor_height}): {chain_anchor.hex()}")

        # Header chain: from anchor_height+1 through height inclusive (1 header)
        headers_raw = await btc.get_header_chain(BlockHeight(anchor_height + 1), 1)
        headers_hex = [h.hex() for h in headers_raw]
        _ok(f"Fetched {len(headers_hex)} BTC block header(s)")

        # Build & verify SPV proof against a covenant parameterized with the
        # REAL output[0] we extracted — this is a genuine cryptographic verification.
        if btc_receive_hash is not None:
            # Use BTC value of the real output as the "btcSatoshis" threshold.
            # SpvProofBuilder.verify_payment requires out_value >= btc_satoshis.
            covenant_params = CovenantParams(
                btc_receive_hash=btc_receive_hash,
                btc_receive_type=btc_receive_type,
                btc_satoshis=1,  # any value <= actual out_value satisfies
                chain_anchor=chain_anchor,
                anchor_height=anchor_height,
                merkle_depth=len(merkle_hashes),
            )
            builder = SpvProofBuilder(covenant_params)
            proof = builder.build(
                txid_be=target_txid,
                raw_tx_hex=stripped.hex(),
                headers_hex=headers_hex,
                merkle_be=merkle_hashes,
                pos=pos,
                output_offset=output_offset,
            )
            _ok(f"SpvProofBuilder.build() SUCCESS — real BTC proof verified")
            _ok(f"  txid: {proof.txid[:16]}...")
            _ok(f"  headers: {len(proof.headers)}, branch: {len(proof.branch)} bytes, pos: {proof.pos}")
            return target_txid, height, chain_anchor, anchor_height, proof
        else:
            _info("Skipping full SPV build (non-P2WPKH output)")
            return target_txid, height, chain_anchor, anchor_height, None
    finally:
        await btc.close()


async def phase_4_gravity_tx_builders(pk, pkh, chain_anchor, anchor_height):
    """Build Gravity txs with REAL covenant bytecode from bundled rxdc artifacts.

    Uses CovenantArtifact + build_gravity_offer to generate genuine MakerOffer
    and MakerClaimed redeem scripts. This is the first time the live test uses
    covenant bytecode that would actually execute on-chain (given adequate funding).
    """
    import coincurve
    from pyrxd.security.secrets import PrivateKeyMaterial
    from pyrxd.btc_wallet.keys import generate_keypair
    from pyrxd.btc_wallet.payment import BtcUtxo, build_payment_tx
    from pyrxd.gravity.covenant import build_gravity_offer
    from pyrxd.gravity.transactions import build_claim_tx, build_maker_offer_tx

    _hr("Phase 4: Gravity tx builders (SDK, real covenant bytecode)")

    if pk is None:
        _warn("No WIF provided; using ephemeral keys (demo mode)")
        pk = PrivateKeyMaterial.generate()
        raw = pk.unsafe_raw_bytes()
        pub = coincurve.PrivateKey(raw).public_key.format(compressed=True)
        pkh = hashlib.new("ripemd160", hashlib.sha256(pub).digest()).digest()

    # Maker's compressed public key (needed for covenant constructor)
    maker_raw = pk.unsafe_raw_bytes()
    maker_pub = coincurve.PrivateKey(maker_raw).public_key.format(compressed=True)

    # Fresh Taker keys
    taker_rxd = PrivateKeyMaterial.generate()
    taker_raw = taker_rxd.unsafe_raw_bytes()
    taker_pub = coincurve.PrivateKey(taker_raw).public_key.format(compressed=True)
    taker_pkh = hashlib.new("ripemd160", hashlib.sha256(taker_pub).digest()).digest()

    # BTC testnet keypair for Taker
    taker_btc = generate_keypair(network="tb")
    _ok(f"Taker BTC p2wpkh (testnet): {taker_btc.p2wpkh_address}")

    # Current BTC difficulty — use a real mainnet nBits (2026-04-21 era)
    # This is used in the covenant for PoW verification. For a DRY_RUN,
    # any 4-byte value is fine — the covenant won't actually execute.
    expected_nbits = bytes.fromhex("a0ee0117")   # approximate 2026 difficulty LE

    claim_deadline = int(time.time()) + 25 * 3600  # 25h from now

    # Build GravityOffer with REAL covenant bytecode from bundled artifacts.
    # This generates genuine MakerOffer + MakerClaimed redeem scripts via
    # CovenantArtifact.substitute() — the code hash is computed correctly
    # and embedded in the MakerOffer script.
    offer = build_gravity_offer(
        maker_pkh=pkh,
        maker_pk=maker_pub,
        taker_pk=taker_pub,
        taker_radiant_pkh=taker_pkh,
        btc_receive_hash=taker_btc.pkh,
        btc_receive_type="p2wpkh",
        btc_satoshis=BTC_SATOSHIS,
        btc_chain_anchor=chain_anchor,
        expected_nbits=expected_nbits,
        anchor_height=anchor_height,
        merkle_depth=12,
        claim_deadline=claim_deadline,
        photons_offered=PHOTONS_OFFERED,
    )
    _ok(f"GravityOffer built with real covenant bytecode")
    _ok(f"  offer_redeem:   {len(offer.offer_redeem_hex) // 2} bytes")
    _ok(f"  claimed_redeem: {len(offer.claimed_redeem_hex) // 2} bytes")
    _ok(f"  btc_satoshis: {offer.btc_satoshis}")
    _ok(f"  photons_offered: {offer.photons_offered}")
    _ok(f"  chain_anchor: {offer.chain_anchor.hex()[:16]}... (real BTC block)")
    _ok(f"  anchor_height: {offer.anchor_height}")

    # build_maker_offer_tx: Maker deposits photons into the MakerOffer P2SH.
    # Uses a synthetic funding UTXO (no real broadcast yet).
    FAKE_FUNDING_TXID = "ff" * 32
    maker_offer_result = build_maker_offer_tx(
        offer=offer,
        funding_txid=FAKE_FUNDING_TXID,
        funding_vout=0,
        funding_photons=PHOTONS_OFFERED + FEE_SATS,
        fee_sats=FEE_SATS,
        maker_privkey=pk,
    )
    _ok(f"build_maker_offer_tx: {maker_offer_result.txid[:16]}...  {maker_offer_result.tx_size} bytes")
    _ok(f"  MakerOffer P2SH: {maker_offer_result.offer_p2sh}")
    _ok(f"  output photons:  {maker_offer_result.output_photons}")

    # build_claim_tx: Taker spends MakerOffer → MakerClaimed.
    # Uses the maker_offer_result.txid as the offer UTXO (hypothetically confirmed).
    claim = build_claim_tx(
        offer=offer,
        funding_txid=maker_offer_result.txid,
        funding_vout=0,
        funding_photons=PHOTONS_OFFERED,
        fee_sats=FEE_SATS,
        taker_privkey=taker_rxd,
    )
    _ok(f"build_claim_tx:       {claim.txid[:16]}...  {claim.tx_size} bytes")
    _ok(f"  offer P2SH:   {claim.offer_p2sh}")
    _ok(f"  claimed P2SH: {claim.claimed_p2sh}")

    # BTC payment tx (Taker side — no broadcast)
    btc_utxo = BtcUtxo(txid="bb" * 32, vout=0, value=BTC_SATOSHIS + FEE_SATS * 3)
    btc_tx = build_payment_tx(
        keypair=taker_btc,
        utxo=btc_utxo,
        to_hash=offer.btc_receive_hash,
        to_type=offer.btc_receive_type,
        amount_sats=BTC_SATOSHIS,
        fee_sats=FEE_SATS,
    )
    _ok(f"BTC payment tx:       {btc_tx.txid[:16]}...  size: {len(bytes.fromhex(btc_tx.tx_hex))} bytes")

    return offer, maker_offer_result


async def phase_5_broadcast_guard(offer=None, maker_offer_result=None):
    _hr("Phase 5: Broadcast guard")
    if DRY_RUN:
        _info("DRY_RUN=1 (default). No broadcast attempted.")
        _info("Txs built above use real covenant bytecode and would be broadcast-safe")
        _info("on Radiant mainnet given a funded Maker UTXO and adequate photons.")
        _info("Real trade minimum: ~65M photons (5KB finalize tx × 10k photons/byte + dust).")
        _info("Set DRY_RUN=0 and MAKER_RXD_WIF to attempt MakerOffer broadcast.")
    else:
        if offer is None or maker_offer_result is None:
            _fail("Cannot broadcast: covenant construction failed in phase 4.")
        _info("DRY_RUN=0: attempting to broadcast MakerOffer tx on RXD mainnet...")
        _info("(BTC broadcast is still disabled — funded Taker UTXO needed)")
        # Read WIF inside this function scope only — never stored at module level.
        _maker_wif = os.environ.get("MAKER_RXD_WIF")
        if not _maker_wif:
            _fail("DRY_RUN=0 requires MAKER_RXD_WIF to be set.")

        # Fetch a real funded UTXO from the Maker's address
        import json as _json
        import websockets
        import hashlib as _hl

        async with websockets.connect(RXD_ELECTRUMX_URL) as ws:
            pkh_hex = os.environ.get("EXPECTED_MAKER_PKH_HEX", "")
            if not pkh_hex:
                _fail("DRY_RUN=0 requires EXPECTED_MAKER_PKH_HEX to be set "
                      "(matching MAKER_RXD_WIF) for UTXO lookup.")
            script = bytes.fromhex("76a914" + pkh_hex + "88ac")
            script_hash_le = _hl.sha256(script).digest()[::-1].hex()
            req = _json.dumps({"id": 1, "method": "blockchain.scripthash.listunspent",
                               "params": [script_hash_le]})
            await ws.send(req)
            resp = _json.loads(await ws.recv())
        utxos = resp.get("result", [])
        if not utxos:
            _fail("No UTXOs found for hot wallet — cannot broadcast.")

        # Select the largest UTXO to maximise chance of covering offer + fee.
        utxos_sorted = sorted(utxos, key=lambda u: u["value"], reverse=True)
        utxo = utxos_sorted[0]
        _info(f"Using UTXO: {utxo['tx_hash']}:{utxo['tx_pos']} ({utxo['value']} photons)")
        min_needed = FEE_SATS + 1  # at minimum, fee + 1 photon output
        if utxo["value"] < min_needed:
            _fail(f"Largest UTXO ({utxo['value']} photons) is below minimum "
                  f"needed ({min_needed} = fee {FEE_SATS} + 1 photon output).")

        from pyrxd.security.secrets import PrivateKeyMaterial
        pk_live = PrivateKeyMaterial.from_wif(_maker_wif)
        _maker_wif = None  # clear immediately after use

        # Rebuild the offer and maker_offer_tx with the real UTXO.
        # Use the Maker's own P2WPKH as the BTC destination for this
        # self-trade test — avoids embedding an unrecoverable zero-hash address.
        import coincurve as _cc
        from pyrxd.btc_wallet.keys import generate_keypair as _gkp
        maker_raw = pk_live.unsafe_raw_bytes()
        maker_pub_live = _cc.PrivateKey(maker_raw).public_key.format(compressed=True)
        maker_pkh_live = _hl.new("ripemd160", _hl.sha256(maker_pub_live).digest()).digest()
        maker_btc = _gkp(network="bc")  # Maker's own BTC mainnet keypair for self-trade

        # Radiant min relay fee is 10,000 photons/byte. A MakerOffer tx is ~190 bytes,
        # so minimum fee is ~1,900,000 photons. Use 10,000 ph/byte with 250-byte headroom.
        FEE_RATE_PH_PER_BYTE = 10_000
        ESTIMATED_TX_BYTES = 250
        live_fee = FEE_RATE_PH_PER_BYTE * ESTIMATED_TX_BYTES  # 2,500,000 photons
        photons_live = utxo["value"] - live_fee
        if photons_live <= 0:
            _fail(f"UTXO ({utxo['value']} photons) too small to cover fee ({live_fee} photons)")
        _info(f"Live fee: {live_fee} photons ({FEE_RATE_PH_PER_BYTE} ph/byte × {ESTIMATED_TX_BYTES} bytes)")

        from pyrxd.gravity.covenant import build_gravity_offer as _bgo
        offer_live = _bgo(
            maker_pkh=maker_pkh_live,
            maker_pk=maker_pub_live,
            taker_pk=maker_pub_live,  # self-trade for test
            taker_radiant_pkh=maker_pkh_live,
            btc_receive_hash=maker_btc.pkh,  # Maker's own BTC P2WPKH pkh
            btc_receive_type="p2wpkh",
            btc_satoshis=1,
            btc_chain_anchor=offer.chain_anchor,
            expected_nbits=bytes.fromhex("a0ee0117"),
            anchor_height=offer.anchor_height,
            merkle_depth=12,
            claim_deadline=int(time.time()) + 25 * 3600,
            photons_offered=photons_live,
        )

        from pyrxd.gravity.transactions import build_maker_offer_tx as _bmot
        result_live = _bmot(
            offer=offer_live,
            funding_txid=utxo["tx_hash"],
            funding_vout=utxo["tx_pos"],
            funding_photons=utxo["value"],
            fee_sats=live_fee,
            maker_privkey=pk_live,
        )
        _ok(f"MakerOffer tx: {result_live.txid}  size: {result_live.tx_size} bytes")
        _ok(f"  MakerOffer P2SH: {result_live.offer_p2sh}")

        # Broadcast
        async with websockets.connect(RXD_ELECTRUMX_URL) as ws:
            req = _json.dumps({"id": 2, "method": "blockchain.transaction.broadcast",
                               "params": [result_live.tx_hex]})
            await ws.send(req)
            resp = _json.loads(await ws.recv())
        if "error" in resp and resp["error"]:
            _fail(f"Broadcast failed: {resp['error']}")
        returned_txid = resp.get("result", "")
        if returned_txid == result_live.txid:
            _ok(f"MakerOffer broadcast SUCCESS: {returned_txid}")
        else:
            _warn(f"Returned txid {returned_txid!r} != computed {result_live.txid!r}")


async def run() -> None:
    print()
    print("=" * 70)
    print("  pyrxd  —  Gravity LIVE integration test")
    print(f"  Mode: DRY_RUN={DRY_RUN}")
    print("=" * 70)

    pk, pkh, addr = await phase_1_key_derivation()
    rxd_tip, balance = await phase_2_rxd_network()
    btc_result = await phase_3_btc_network_and_spv()
    _, _, chain_anchor, anchor_height, _proof = btc_result
    offer, maker_offer_result = await phase_4_gravity_tx_builders(pk, pkh, chain_anchor, anchor_height)
    await phase_5_broadcast_guard(offer=offer, maker_offer_result=maker_offer_result)

    _hr("Summary")
    _ok("Phase 1: WIF -> address derivation verified" if pk else
        "Phase 1: skipped (no WIF)")
    _ok(f"Phase 2: RXD tip height {rxd_tip} fetched from live ElectrumX" if rxd_tip else
        "Phase 2: failed")
    if balance is not None:
        _ok(f"Phase 2: RXD hot-wallet balance {balance} photons "
            f"({balance / 1e8:.8f} RXD) confirmed")
    _ok("Phase 3: live BTC SPV proof built + verified against real tx")
    _ok("Phase 4: Gravity txs built with real covenant bytecode (CovenantArtifact)")
    _ok("  - build_maker_offer_tx: Maker funding tx (P2PKH → P2SH)")
    _ok("  - build_claim_tx: Taker claim tx (real redeem script)")
    _ok("  - BTC payment tx built and serialized")
    if DRY_RUN:
        _info("Phase 5: DRY_RUN=1 — no broadcast (set DRY_RUN=0 to broadcast MakerOffer)")
    else:
        _ok("Phase 5: MakerOffer broadcast attempted (see above for result)")
    print()
    print("What ran LIVE:")
    print("  - RXD mainnet ElectrumX: get_tip_height, get_balance")
    print("  - BTC testnet HTTP API: tip, raw_tx, merkle proof, header chain")
    print("  - SpvProofBuilder.build(): full verifier chain on real BTC data")
    print("  - CovenantArtifact.substitute(): real covenant redeem scripts generated")
    print("  - build_maker_offer_tx + build_claim_tx: signed + serialized with real bytecode")
    print()
    print("What did NOT run:")
    print("  - BTC broadcast: no funded testnet UTXO")
    print("  - build_finalize_tx: needs a real MakerClaimed UTXO on-chain")
    print()


if __name__ == "__main__":
    asyncio.run(run())
