#!/usr/bin/env python3
"""OPS RUNNER (not the shipped package): drive a DUST real-value BTC↔RXD HTLC swap.

Wires the UNCHANGED production SwapCoordinator + legs to the MAINNET/SIGNET transports
and walks the MAKER_SECRET_TAKER_LOCKS_BTC_FIRST runbook, confirming before EVERY
irreversible broadcast and recording a provenance-tracked report.

It DELIBERATELY crosses the audit gate (operator accepts dust loss). The external audit
remains the hard gate for any product claim. Use ONLY for a capped, supervised run.

Staging (--stage), each gating the next (see docs/plans/2026-05-26-...-dust-mainnet-trade-plan.md):
  dry-run : build the real txs + read-only sanity, NO broadcast. (Honest: mempool.space
            has no testmempoolaccept, so the BTC leg gets no consensus rehearsal here —
            signet is that.)
  signet  : real BTC SIGNET (free faucet) ↔ RXD mainnet. First end-to-end run of the new
            broadcaster + the P-SAFE-2 txid serializer + live conf reads against real
            Bitcoin. MANDATORY before any mainnet BTC.
  dust    : real DUST on BTC mainnet ↔ RXD mainnet. Requires --i-accept-dust-loss.

Single-process, interactive: the operator plays BOTH maker and taker (their funds on
both sides), so one orchestrator holding all keys is correct (mirrors
tests/test_xchain_swap_regtest_e2e.py). Run under supervision — the maker-stall steal is
the most likely real loss path; do NOT walk away while BOTH_LOCKED.

  python scripts/dust_swap_run.py --stage signet \
      --btc-claim-payout <addr-spk-hex> --btc-refund-payout <addr-spk-hex>
  python scripts/dust_swap_run.py --stage dust --i-accept-dust-loss --btc-sats 600 ...
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import struct
import sys
import time
from pathlib import Path

import coincurve

from pyrxd.btc_wallet import taproot as bt
from pyrxd.btc_wallet.htlc_leg import BitcoinTaprootLeg
from pyrxd.btc_wallet.keys import generate_keypair
from pyrxd.btc_wallet.payment import BtcUtxo
from pyrxd.gravity.htlc_covenant import build_htlc_covenant_rxd
from pyrxd.gravity.radiant_leg import RadiantChainIO, RadiantCovenantLeg
from pyrxd.gravity.swap_coordinator import (
    CoordinatorConfig,
    SwapCoordinator,
    measure_margin_from_btc_block_times,
)
from pyrxd.gravity.swap_state import NegotiatedTerms, SwapRecord, SwapState
from pyrxd.keys import PrivateKey
from pyrxd.network.bitcoin import (
    MempoolSpaceBroadcaster,
    MempoolSpaceFundingReader,
    MempoolSpaceSource,
)
from pyrxd.security.secrets import SecretBytes
from pyrxd.security.types import Hex20, Txid

sys.path.insert(0, str(Path(__file__).resolve().parent))
from radiant_mainnet_chainio import SshTrRadiantClient

# Per-stage endpoints. signet uses the "tb" HRP + the mempool.space signet API.
_STAGES = {
    "dry-run": {"btc_network": "bc", "btc_base_url": "https://mempool.space/api", "broadcast": False},
    "signet": {"btc_network": "tb", "btc_base_url": "https://mempool.space/signet/api", "broadcast": True},
    "dust": {"btc_network": "bc", "btc_base_url": "https://mempool.space/api", "broadcast": True},
}
_MAINNET_BTC_API = "https://mempool.space/api"


# --------------------------------------------------------------------------- inline report (NOT a module)


class StepReport:
    """Append-only provenance report -> JSON. NEVER records the preimage p."""

    def __init__(self, stage: str, margin_provenance: dict) -> None:
        self._t0 = time.monotonic()
        self.doc: dict = {
            "stage": stage,
            "started_unix": int(time.time()),
            "margin_provenance": margin_provenance,  # measured-vs-chosen (P-SAFE-1b)
            "steps": [],
        }

    def step(self, *, name: str, chain: str, **fields) -> None:
        entry = {"step": name, "chain": chain, "wall_clock_s": round(time.monotonic() - self._t0, 1), **fields}
        self.doc["steps"].append(entry)
        print(f"  [report] {json.dumps(entry)}")

    def dump(self, path: str) -> None:
        Path(path).write_text(json.dumps(self.doc, indent=2))
        print(f"\nReport -> {path}")


def _confirm(prompt: str, *, auto_yes: bool) -> None:
    """Block on operator confirmation before an irreversible broadcast.

    Called before EACH broadcast — approval never carries to the next.
    """
    print(f"\n  >>> IRREVERSIBLE: {prompt}")
    if auto_yes:
        print("  >>> (--yes) proceeding")
        return
    if input("  >>> type 'broadcast' to proceed, anything else ABORTS: ").strip() != "broadcast":
        raise SystemExit("operator aborted before broadcast")


# --------------------------------------------------------------------------- measured margin


async def _measured_margin(args: argparse.Namespace):
    """Read recent MAINNET BTC header timestamps and build a MEASURED MarginPolicy.

    Timing always comes from MAINNET BTC data (signet timing != mainnet), so the header
    fetch hits the mainnet API regardless of stage.
    """
    src = MempoolSpaceSource(base_url=_MAINNET_BTC_API)
    try:
        tip = int(await src.get_tip_height())
        timestamps: list[int] = []
        for h in range(tip - args.margin_sample_blocks + 1, tip + 1):
            header = await src.get_block_header_hex(h)  # type: ignore[arg-type]
            timestamps.append(struct.unpack("<I", header[68:72])[0])  # BTC header time = bytes[68:72] LE
    finally:
        await src.close()
    return measure_margin_from_btc_block_times(
        btc_block_timestamps=timestamps,
        btc_tail_percentile=args.btc_tail_percentile,
        btc_claim_reorg_depth_blocks=args.btc_claim_reorg_depth,
        rxd_claim_burial_blocks=args.rxd_claim_burial,
        rxd_block_interval_s=args.rxd_block_interval_s,
    )


# --------------------------------------------------------------------------- RXD fee source


class _SshTrFeeSource:
    """FeeSource that carves a plain-RXD fee UTXO via the ssh-tr wallet (real run)."""

    def __init__(self, client: SshTrRadiantClient, fee_amount_photons: int) -> None:
        self._client = client
        self._amount = fee_amount_photons

    def next_fee_input(self):
        return self._client.carve_fee_input(self._amount)


class _CapturingBroadcaster:
    """Wraps a BtcBroadcaster, recording the last raw tx broadcast.

    The coordinator's maker_claims_btc broadcasts the claim but returns no bytes, and
    the taker must read the claim off-chain to scrape p. Capturing the last raw here
    lets the harness derive the claim txid locally (btc_txid_from_raw) and fetch the
    on-chain copy, without trusting any out-of-band txid.
    """

    def __init__(self, inner) -> None:
        self._inner = inner
        self.last_raw: bytes | None = None

    async def broadcast(self, raw_tx: bytes) -> str:
        self.last_raw = bytes(raw_tx)
        return await self._inner.broadcast(raw_tx)


class _InMemSeen:
    def __init__(self) -> None:
        self._s: set[bytes] = set()

    def has_seen(self, hsh: bytes) -> bool:
        return bytes(hsh) in self._s

    def mark_seen(self, hsh: bytes) -> None:
        self._s.add(bytes(hsh))


# --------------------------------------------------------------------------- the run


async def run_dust_swap(args: argparse.Namespace) -> None:
    stage = _STAGES[args.stage]
    btc_network, do_broadcast = stage["btc_network"], stage["broadcast"]
    audit_cleared = args.i_accept_dust_loss

    print(f"=== Gravity DUST swap runner — stage={args.stage} broadcast={do_broadcast} ===")
    if args.stage == "dust" and not audit_cleared:
        raise SystemExit("stage=dust requires --i-accept-dust-loss (you are moving REAL mainnet value)")
    btc_claim_payout = bytes.fromhex(args.btc_claim_payout)
    btc_refund_payout = bytes.fromhex(args.btc_refund_payout)

    policy, provenance = await _measured_margin(args)
    report = StepReport(args.stage, provenance)
    print(f"  measured margin: {json.dumps(provenance)}")

    # ---- terms ----
    p_secret = SecretBytes(os.urandom(32))
    p = p_secret.unsafe_raw_bytes()
    h = hashlib.sha256(p).digest()
    margin_blocks = policy.margin.normalize_to(bt.TimeUnit.BLOCKS, block_interval_s=policy.block_interval_s).value
    t_rxd = bt.Timelock(args.t_rxd_blocks, bt.TimeUnit.BLOCKS)
    t_btc = bt.Timelock(args.t_rxd_blocks + margin_blocks + 4, bt.TimeUnit.BLOCKS)  # > t_rxd + margin

    maker_btc = coincurve.PrivateKey(os.urandom(32))
    taker_btc_kp = generate_keypair(btc_network)
    claim_xo = coincurve.PublicKeyXOnly.from_secret(maker_btc.secret).format()
    refund_xo = coincurve.PublicKeyXOnly.from_secret(bytes(taker_btc_kp._privkey.unsafe_raw_bytes())).format()

    taker_rxd, maker_rxd = PrivateKey(os.urandom(32)), PrivateKey(os.urandom(32))
    taker_pkh = bytes(Hex20(taker_rxd.public_key().hash160()))
    maker_pkh = bytes(Hex20(maker_rxd.public_key().hash160()))
    cov = build_htlc_covenant_rxd(
        amount=args.rxd_photons, taker_pkh=taker_pkh, maker_pkh=maker_pkh, hashlock=h, refund_csv=t_rxd.value
    )
    terms = NegotiatedTerms(
        hashlock=h, btc_sats=args.btc_sats, radiant_amount=args.rxd_photons, t_btc=t_btc, t_rxd=t_rxd,
        asset_variant="rxd", genesis_ref=b"", taker_dest_hash=cov.expected_taker_hash,
        maker_dest_hash=cov.expected_maker_hash, btc_claim_pubkey_xonly=claim_xo, btc_refund_pubkey_xonly=refund_xo,
    )
    htlc = bt.build_htlc(hashlock=h, claim_pubkey_xonly=claim_xo, refund_pubkey_xonly=refund_xo,
                         timeout=t_btc, network=btc_network)
    print(f"  terms: btc_sats={args.btc_sats} rxd_photons={args.rxd_photons} "
          f"t_btc={t_btc.value} t_rxd={t_rxd.value} margin={margin_blocks}")
    print(f"  BTC HTLC funding address ({btc_network}): {htlc.address}")
    print(f"  RXD covenant SPK (fund this as the maker): {cov.funded_spk.hex()}")

    if not do_broadcast:
        # dry-run: build the txs, report the addresses/terms, stop before any broadcast.
        report.step(name="dry_run_built", chain="both", btc_htlc_address=htlc.address,
                    rxd_covenant_spk=cov.funded_spk.hex(), t_btc=t_btc.value, t_rxd=t_rxd.value)
        report.dump(args.report_out)
        print("\n  DRY-RUN complete: real txs are buildable; nothing broadcast. "
              "Next: SIGNET stage for the first real BTC consensus check.")
        return

    # ---- transports (broadcast stages) ----
    btc_reader = MempoolSpaceFundingReader(base_url=stage["btc_base_url"])
    _btc_bcast = MempoolSpaceBroadcaster(base_url=stage["btc_base_url"])
    btc_broadcaster = _CapturingBroadcaster(_btc_bcast)  # capture the claim raw for scraping
    btc_chain_reader = MempoolSpaceSource(base_url=stage["btc_base_url"])  # to fetch the maker claim tx
    rxd_client = SshTrRadiantClient(rpcwallet=args.rxd_wallet)
    rxd_client.register_spk(cov.funded_spk)

    print(f"\n  Fund the taker BTC address from your {btc_network} wallet (amount + fee), 1 conf:")
    print(f"    {taker_btc_kp.p2wpkh_address}")
    _confirm(f"look up the funding UTXO at {taker_btc_kp.p2wpkh_address}", auto_yes=args.yes)
    utxos = await btc_reader.list_address_utxos(taker_btc_kp.p2wpkh_address)
    need = args.btc_sats + args.btc_fee_sats
    confirmed = [u for u in utxos if u["confirmed"] and u["value_sats"] >= need]
    if not confirmed:
        raise SystemExit(f"no confirmed funding UTXO >= {need} sats at the taker address yet")
    fu = confirmed[0]
    funding_utxo = BtcUtxo(txid=fu["txid"], vout=fu["vout"], value=fu["value_sats"])

    btc_leg = BitcoinTaprootLeg(
        network=btc_network, taker_keypair=taker_btc_kp, funding_utxo=funding_utxo,
        maker_claim_pubkey_xonly=claim_xo, broadcaster=btc_broadcaster, funding_reader=btc_reader,
        refund_to_scriptpubkey=btc_refund_payout, claim_to_scriptpubkey=btc_claim_payout,
        fee_sats=args.btc_fee_sats, min_confirmations=1, funding_input_type="p2wpkh",
        maker_claim_privkey=maker_btc.secret, audit_cleared=audit_cleared,
    )
    rxd_leg = RadiantCovenantLeg(
        network=args.rxd_network, taker_pkh=taker_pkh, maker_pkh=maker_pkh,
        chain_io=RadiantChainIO(rxd_client), fee_source=_SshTrFeeSource(rxd_client, args.rxd_fee_photons),
        min_confirmations=1, audit_cleared=audit_cleared,
    )
    coord = SwapCoordinator(
        record=SwapRecord(state=SwapState.NEGOTIATED, terms=terms), btc_leg=btc_leg, radiant_leg=rxd_leg,
        indexer=None, seen_store=_InMemSeen(), config=CoordinatorConfig(margin_policy=policy),
    )

    # 1. Taker funds the BTC HTLC.
    _confirm(f"taker_funds_btc: broadcast the {btc_network} P2TR HTLC funding tx", auto_yes=args.yes)
    rec = await coord.taker_funds_btc(terms)
    report.step(name="taker_funds_btc", chain="btc", state=rec.state.value,
                txid=rec.btc_locator.funding_outpoint.txid, amount_sats=rec.btc_locator.amount_sats)
    print(f"  -> {rec.state.value} (HTLC funded: {rec.btc_locator.funding_outpoint.txid})")

    # 2. Maker locks the RXD covenant (operator pays the SPK), taker re-validates.
    # Capture the RXD height at/just-before the asset lock — the t_rxd refund window is
    # measured from here, so a conservative (slightly-low) value is safe (it can only make
    # the reorg-gate squeeze MORE cautious, never less). The covenant is funded at-or-after
    # this height. Mirrors the regtest harness's rxd_locked_at = getblockcount()-before-fund.
    rxd_locked_at = int(json.loads(_rxd_blockcount(rxd_client)))
    _confirm("you have funded the RXD covenant SPK on mainnet and it has >= 1 conf", auto_yes=args.yes)
    rec = await coord.post_asset_lock_revalidate(cov.funded_spk)
    report.step(name="post_asset_lock_revalidate", chain="rxd", state=rec.state.value,
                covenant_outpoint=rec.radiant_covenant_outpoint)
    print(f"  -> {rec.state.value}")
    if rec.state is not SwapState.BOTH_LOCKED:
        report.dump(args.report_out)
        raise SystemExit(f"covenant mismatch -> {rec.state.value}; refund the BTC HTLC after t_btc (taker_refund_btc)")

    print("\n  *** MONITORING WINDOW (BOTH_LOCKED): poll maybe_refund_asset_on_maker_stall well inside "
          "maker_stall_safety_window_blocks. Do NOT walk away — the maker-stall steal is the real loss path. ***")

    # 3. Maker claims BTC, revealing p.
    _confirm("maker_claims_btc: broadcast the BTC claim (reveals p on-chain)", auto_yes=args.yes)
    rec = await coord.maker_claims_btc(p_secret)
    report.step(name="maker_claims_btc", chain="btc", state=rec.state.value)
    if btc_broadcaster.last_raw is None:
        raise SystemExit("did not capture the BTC claim bytes; cannot proceed to the taker claim")
    btc_claim_txid = Txid(bt.btc_txid_from_raw(btc_broadcaster.last_raw))  # LOCAL derivation, never trusted input
    print(f"  -> {rec.state.value} (BTC claim txid {btc_claim_txid})")

    # 4. Taker reads the maker's claim off the BTC chain, runs the REORG GATE, claims RXD.
    print(f"\n  Waiting for the BTC claim to bury to {policy.btc_claim_reorg_depth.value} confs "
          "before the reorg gate returns SAFE (poll loop).")
    while True:
        claim_raw = await btc_chain_reader.get_raw_tx(btc_claim_txid, min_confirmations=0)
        now_rxd = int(json.loads(_rxd_blockcount(rxd_client)))
        rec = await coord.taker_scrape_and_claim_asset(
            bytes(claim_raw), now_rxd_height=now_rxd, asset_locked_at_height=rxd_locked_at,
        )
        if rec.state is SwapState.COMPLETED:
            report.step(name="taker_scrape_and_claim_asset", chain="rxd", state=rec.state.value,
                        covenant_outpoint=rec.radiant_covenant_outpoint, btc_claim_txid=str(btc_claim_txid))
            print(f"  -> {rec.state.value} — CROSS-CHAIN SWAP COMPLETE")
            break
        # WAIT (still SECRET_REVEALED): the claim isn't deep enough yet. Poll again.
        print(f"  reorg gate: WAIT (BTC claim not yet {policy.btc_claim_reorg_depth.value}-deep); retrying...")
        report.step(name="reorg_gate_wait", chain="btc", state=rec.state.value)
        await asyncio.sleep(args.poll_interval_s)

    await btc_reader.close()
    await _btc_bcast._http.close()
    await btc_chain_reader.close()
    report.dump(args.report_out)


def _rxd_blockcount(client: SshTrRadiantClient) -> str:
    return json.dumps(client._run_sync("getblockcount"))


def _parse_args(argv: list[str]) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Drive a dust BTC<->RXD HTLC swap (ops runner).")
    ap.add_argument("--stage", choices=list(_STAGES), required=True)
    ap.add_argument("--i-accept-dust-loss", action="store_true", help="REQUIRED for --stage dust (sets audit_cleared)")
    ap.add_argument("--yes", action="store_true", help="skip interactive confirms (DANGEROUS — supervised only)")
    ap.add_argument("--btc-sats", type=int, default=600)
    ap.add_argument("--rxd-photons", type=int, default=1000)
    ap.add_argument("--btc-fee-sats", type=int, default=400, help="flat BTC fee (under-fee claim = SAFETY issue)")
    ap.add_argument("--rxd-fee-photons", type=int, default=2_000_000, help="flat RXD fee (relayfee 0.10/kB)")
    ap.add_argument("--btc-claim-payout", default="", help="scriptPubKey hex the maker's BTC claim pays out to")
    ap.add_argument("--btc-refund-payout", default="", help="scriptPubKey hex the taker's BTC refund pays out to")
    ap.add_argument("--t-rxd-blocks", type=int, default=20)
    ap.add_argument("--rxd-network", default="bc", help="RXD audit-gate network tag")
    ap.add_argument("--rxd-wallet", default="", help="RXD wallet name on tr; empty = the single loaded wallet")
    ap.add_argument("--margin-sample-blocks", type=int, default=144)
    ap.add_argument("--btc-tail-percentile", type=float, default=90.0)
    ap.add_argument("--btc-claim-reorg-depth", type=int, default=2)
    ap.add_argument("--rxd-claim-burial", type=int, default=2)
    ap.add_argument("--rxd-block-interval-s", type=float, default=300.0)
    ap.add_argument("--poll-interval-s", type=float, default=60.0)
    ap.add_argument("--report-out", default="dust_swap_report.json")
    args = ap.parse_args(argv)
    if _STAGES[args.stage]["broadcast"] and (not args.btc_claim_payout or not args.btc_refund_payout):
        ap.error("--btc-claim-payout and --btc-refund-payout (scriptPubKey hex) are required for broadcast stages")
    return args


if __name__ == "__main__":
    asyncio.run(run_dust_swap(_parse_args(sys.argv[1:])))
