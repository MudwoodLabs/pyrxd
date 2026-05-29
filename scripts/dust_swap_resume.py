#!/usr/bin/env python3
"""RESUME a dust BTC<->RXD HTLC swap from a persisted run-keys file.

The forward runner (dust_swap_run.py) crashed AFTER both legs were funded+confirmed
on-chain (a transport bug, since fixed). Re-running it from scratch would mint fresh
keys and try to re-fund spent UTXOs. This script instead reconstructs the SAME
coordinator object graph from the mode-600 keys file (which now also persists the
preimage p) + on-chain truth, seeds the record at BTC_LOCKED, and drives the remaining
steps: post_asset_lock_revalidate -> maker_claims_btc -> taker scrape+claim (reorg
gate). Confirms before each irreversible broadcast.

Only valid when BOTH legs are already funded + confirmed (BTC HTLC + RXD covenant).
Reads the BTC locator from the confirmed HTLC funding tx; reads the covenant UTXO via
the ssh-tr shim. p is loaded from the keys file (single-operator trust domain).
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import sys
import time
from pathlib import Path

import coincurve

from pyrxd.btc_wallet import taproot as bt
from pyrxd.btc_wallet.htlc_leg import BitcoinTaprootLeg, FundingPolicy
from pyrxd.btc_wallet.keys import keypair_from_wif
from pyrxd.btc_wallet.payment import BtcUtxo
from pyrxd.gravity.htlc_covenant import build_htlc_covenant_rxd
from pyrxd.gravity.radiant_leg import RadiantChainIO, RadiantCovenantLeg
from pyrxd.gravity.swap_coordinator import (
    CoordinatorConfig,
    SwapCoordinator,
)
from pyrxd.gravity.swap_state import NegotiatedTerms, SwapRecord, SwapState
from pyrxd.keys import PrivateKey
from pyrxd.network.bitcoin import (
    MempoolSpaceBroadcaster,
    MempoolSpaceFundingReader,
    MempoolSpaceSource,
)
from pyrxd.security.errors import InsufficientConfirmationsError
from pyrxd.security.secrets import SecretBytes
from pyrxd.security.types import Hex20, Txid

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _dust_swap_shared import (
    CapturingBroadcaster,
    InMemSeen,
    SshTrFeeSource,
    confirm,
    measured_margin_from_mainnet,
    rxd_blockcount,
    validated_resume_deadline_s,
)
from radiant_mainnet_chainio import SshTrRadiantClient

_MAINNET_BTC_API = "https://mempool.space/api"


async def resume(args) -> None:
    keys = json.loads(Path(args.keys_out).expanduser().read_text())
    btc_network = keys["btc_network"]
    h = bytes.fromhex(keys["hashlock_H"])
    p_secret = SecretBytes(bytes.fromhex(keys["preimage_p_hex"]))
    # raise (not assert) — python -O strips asserts, and this is a value-moving path.
    if hashlib.sha256(p_secret.unsafe_raw_bytes()).digest() != h:
        raise SystemExit("preimage in keys file does not hash to H — wrong/tampered keys file")

    # AUDIT GATE (review of cbd5fc0): the forward runner enforces --i-accept-dust-loss
    # for mainnet broadcast; the resume MUST mirror that gate, otherwise a stale keys
    # file is a one-up-arrow bypass. We pass audit_cleared through to BOTH legs
    # explicitly instead of hardcoding True.
    _AUDIT_CLEARED_NETWORKS = ("bcrt", "regtest", "tb", "signet")
    # rxd_network MUST be in the keys file — red-team finding NEW #3 on 44707a3.
    # A silent default of "bc" would let a keys file written before this fix bypass
    # any check that depends on the actual network in use.
    if "rxd_network" not in keys:
        raise SystemExit(
            "keys file is missing rxd_network — was it written by a pre-fixup forward "
            "runner? Re-run forward with the current dust_swap_run.py"
        )
    rxd_network = keys["rxd_network"]
    needs_audit_optin = (btc_network not in _AUDIT_CLEARED_NETWORKS) or (rxd_network not in _AUDIT_CLEARED_NETWORKS)
    if needs_audit_optin and not args.i_accept_dust_loss:
        raise SystemExit(
            f"resume targets a value-bearing network (btc={btc_network!r}, rxd={rxd_network!r}); "
            "pass --i-accept-dust-loss to confirm you are moving REAL value"
        )
    audit_cleared = bool(args.i_accept_dust_loss)

    # Reconstruct keys.
    maker_btc = coincurve.PrivateKey(bytes.fromhex(keys["maker_btc_wif_raw_hex"]))
    taker_btc_kp = keypair_from_wif(keys["taker_btc_wif"], btc_network)
    claim_xo = coincurve.PublicKeyXOnly.from_secret(maker_btc.secret).format()
    refund_xo = coincurve.PublicKeyXOnly.from_secret(bytes(taker_btc_kp._privkey.unsafe_raw_bytes())).format()
    taker_rxd = PrivateKey(keys["taker_rxd_wif"])
    maker_rxd = PrivateKey(keys["maker_rxd_wif"])
    taker_pkh = bytes(Hex20(taker_rxd.public_key().hash160()))
    maker_pkh = bytes(Hex20(maker_rxd.public_key().hash160()))

    # MEASURED MARGIN is informational only on resume — the t_btc/t_rxd are LOADED from
    # the keys file (the run that locked the chain pinned them; re-deriving here could
    # produce different values and silently mismatch the on-chain refund leaf).
    # Resume MUST use the keys-file timelocks; we sample margin for the reorg-gate
    # policy and the report, but NEVER recompute t_btc from it.
    policy, provenance = await measured_margin_from_mainnet(args)
    print(f"  measured margin (informational): {json.dumps(provenance)}")
    if "t_btc_blocks" not in keys or "t_rxd_blocks" not in keys or "btc_htlc_address" not in keys:
        raise SystemExit(
            "keys file is from a pre-fixup run (missing t_btc_blocks/t_rxd_blocks/btc_htlc_address); "
            "this resume requires a keys file written by dust_swap_run.py post-cbd5fc0 — re-run forward"
        )
    t_rxd = bt.Timelock(int(keys["t_rxd_blocks"]), bt.TimeUnit.BLOCKS)
    t_btc = bt.Timelock(int(keys["t_btc_blocks"]), bt.TimeUnit.BLOCKS)

    cov = build_htlc_covenant_rxd(
        amount=args.rxd_photons, taker_pkh=taker_pkh, maker_pkh=maker_pkh, hashlock=h, refund_csv=t_rxd.value
    )
    if cov.funded_spk.hex() != keys["rxd_covenant_spk"]:
        raise SystemExit("rebuilt RXD covenant SPK != persisted; wrong/tampered keys file")

    btc_claim_payout = bytes.fromhex(keys["btc_claim_payout_spk"])
    btc_refund_payout = bytes.fromhex(keys["btc_refund_payout_spk"])

    terms = NegotiatedTerms(
        hashlock=h,
        btc_sats=args.btc_sats,
        radiant_amount=args.rxd_photons,
        t_btc=t_btc,
        t_rxd=t_rxd,
        asset_variant="rxd",
        genesis_ref=b"",
        taker_dest_hash=cov.expected_taker_hash,
        maker_dest_hash=cov.expected_maker_hash,
        btc_claim_pubkey_xonly=claim_xo,
        btc_refund_pubkey_xonly=refund_xo,
    )

    # ---- transports ----
    btc_reader = MempoolSpaceFundingReader(base_url=_MAINNET_BTC_API)
    _btc_bcast = MempoolSpaceBroadcaster(base_url=_MAINNET_BTC_API)
    btc_broadcaster = CapturingBroadcaster(_btc_bcast)
    btc_chain_reader = MempoolSpaceSource(base_url=_MAINNET_BTC_API)
    rxd_client = SshTrRadiantClient(rpcwallet=keys.get("rxd_wallet", ""))
    rxd_client.register_spk(cov.funded_spk)

    # ---- reconstruct the BTC locator from the CONFIRMED on-chain HTLC funding tx ----
    htlc = bt.build_htlc(
        hashlock=h, claim_pubkey_xonly=claim_xo, refund_pubkey_xonly=refund_xo, timeout=t_btc, network=btc_network
    )
    # Cross-check the BTC side too: the rebuilt taproot output address must match what
    # was persisted at run time (catches a margin/timelock drift that would otherwise
    # silently swap the refund leaf for a non-matching one — kieran-python C1).
    if htlc.address != keys["btc_htlc_address"]:
        raise SystemExit(
            f"rebuilt HTLC address {htlc.address} != persisted {keys['btc_htlc_address']}; "
            "t_btc/keys drift — refusing to operate on the wrong taproot key"
        )
    funding_txid = args.btc_htlc_funding_txid
    on_chain_amount = await btc_reader.read_output_amount_sats(funding_txid, 0, min_confirmations=1)
    if on_chain_amount != terms.btc_sats:
        raise SystemExit(f"on-chain HTLC amount {on_chain_amount} != terms {terms.btc_sats}")
    # Bind the funding txid to the EXPECTED SPK on-chain — without this, any P2TR
    # output of the same amount passes the amount-only check, and a typo lands us on
    # an unrelated UTXO whose maker-claim would fail-closed but whose poll loop hangs.
    # Reuses the funding reader's HTTP client (already has the right base URL).
    funding_tx_json = await btc_reader._http.tx_json(Txid(funding_txid))
    onchain_spk_hex = funding_tx_json["vout"][0]["scriptpubkey"]
    if onchain_spk_hex != htlc.scriptpubkey.hex():
        raise SystemExit(
            f"funding tx vout[0] SPK {onchain_spk_hex} != expected HTLC SPK {htlc.scriptpubkey.hex()}; "
            "refusing to operate on the wrong UTXO"
        )
    locator = htlc.with_funding(bt.BtcOutpoint(txid=funding_txid, vout=0), on_chain_amount)
    print(f"  BTC HTLC locator reconstructed: {funding_txid}:0 = {on_chain_amount} sats (SPK verified)")

    # The funding_utxo arg to the leg is the now-SPENT taker UTXO; the leg only uses it
    # for fund(), which we never call on resume. Pass a placeholder spent ref.
    btc_leg = BitcoinTaprootLeg(
        network=btc_network,
        taker_keypair=taker_btc_kp,
        funding_utxo=BtcUtxo(txid="00" * 32, vout=0, value=on_chain_amount),
        maker_claim_pubkey_xonly=claim_xo,
        broadcaster=btc_broadcaster,
        funding_reader=btc_reader,
        refund_to_scriptpubkey=btc_refund_payout,
        claim_to_scriptpubkey=btc_claim_payout,
        # Resume never calls fund() (BTC HTLC is already on-chain), so the poll
        # knobs stay at defaults — no broadcast→readback timing knot to manage here.
        policy=FundingPolicy(fee_sats=args.btc_fee_sats, min_confirmations=1, funding_input_type="p2wpkh"),
        maker_claim_privkey=maker_btc.secret,
        audit_cleared=audit_cleared,
    )
    rxd_leg = RadiantCovenantLeg(
        network=rxd_network,
        taker_pkh=taker_pkh,
        maker_pkh=maker_pkh,
        chain_io=RadiantChainIO(rxd_client),
        fee_source=SshTrFeeSource(rxd_client, args.rxd_fee_photons),
        min_confirmations=1,
        audit_cleared=audit_cleared,
    )
    record = SwapRecord(state=SwapState.NEGOTIATED, terms=terms).with_btc_lock(locator).with_state(SwapState.BTC_LOCKED)
    coord = SwapCoordinator(
        record=record,
        btc_leg=btc_leg,
        radiant_leg=rxd_leg,
        indexer=None,
        seen_store=InMemSeen(),
        config=CoordinatorConfig(margin_policy=policy),
    )
    print(f"  coordinator seeded at {coord.record.state.value}")

    # All transports + the WAIT loop run inside try/finally so a mid-flight exception
    # never leaks aiohttp sessions (an unclosed-connector warning during a value-moving
    # decision is exactly when an operator needs CLEAN output, not noise).
    try:
        # ---- step: post_asset_lock_revalidate -> BOTH_LOCKED ----
        # F-008: the reorg-finality gate needs the covenant's ACTUAL fund height, not
        # the current tip. Using the tip makes refund_opens_at = tip + t_rxd, hiding
        # however much of the t_rxd window already elapsed since the covenant confirmed
        # — silently neutralising the gate on every crash-recovery. Derive the true
        # fund height from the covenant UTXO's on-chain confirmation depth instead
        # (the shim reports confs in UtxoRecord.height): fund_height = tip - confs + 1.
        _cov_op, _cov_val, cov_confs = await rxd_leg.chain_io.find_covenant_utxo(
            cov.funded_spk, expected_value=args.rxd_photons
        )
        if cov_confs < 1:
            raise SystemExit("covenant UTXO has 0 confirmations; cannot derive its fund height (fail-closed)")
        rxd_locked_at = rxd_blockcount(rxd_client) - cov_confs + 1
        print(f"  covenant fund height = {rxd_locked_at} (derived from {cov_confs} on-chain confs)")
        rec = await coord.post_asset_lock_revalidate(cov.funded_spk)
        print(f"  post_asset_lock_revalidate -> {rec.state.value}")
        if rec.state is not SwapState.BOTH_LOCKED:
            raise SystemExit(f"covenant mismatch -> {rec.state.value}; refund both legs after their timelocks")

        print("\n  *** BOTH_LOCKED. Proceeding to maker_claims_btc (reveals p on-chain). ***")

        # ---- step: maker claims BTC, revealing p ----
        confirm("maker_claims_btc: broadcast the BTC claim (reveals p on-chain)", auto_yes=args.yes)
        rec = await coord.maker_claims_btc(p_secret)
        if btc_broadcaster.last_raw is None:
            raise SystemExit("did not capture the BTC claim bytes; cannot proceed")
        btc_claim_txid = Txid(bt.btc_txid_from_raw(btc_broadcaster.last_raw))
        print(f"  -> {rec.state.value} (BTC claim txid {btc_claim_txid})")

        # ---- step: taker reorg-gated claim of the RXD covenant ----
        # Bounded by a SAFE deadline derived from t_rxd: a deadline LONGER than t_rxd
        # would let the loop stall past the refund window and forfeit the asset. The
        # validator enforces 0 < deadline <= 0.5 × t_rxd_seconds (sec-sentinel H-1 +
        # red-team #3 residual on 44707a3) and rejects non-finite operator inputs.
        deadline_s = validated_resume_deadline_s(
            operator_value=args.resume_deadline_s,
            t_rxd_blocks=t_rxd.value,
            rxd_block_interval_s=args.rxd_block_interval_s,
        )
        print(
            f"\n  Waiting for the BTC claim to bury to {policy.btc_claim_reorg_depth.value} confs "
            f"(reorg gate); deadline {deadline_s:.0f}s."
        )
        deadline = time.monotonic() + deadline_s
        while True:
            if time.monotonic() >= deadline:
                raise SystemExit(
                    f"resume deadline ({deadline_s:.0f}s) exceeded — operator must intervene "
                    f"(p is public on-chain; covenant claim still pending). claim txid {btc_claim_txid}"
                )
            # get_raw_tx fail-closes on an UNCONFIRMED tx (won't return a 0-conf mempool
            # tx even at min_confirmations=0). The just-broadcast claim is 0-conf;
            # that's the same as the reorg gate's WAIT — sleep and retry until it
            # confirms. Catch InsufficientConfirmationsError (the typed exception)
            # instead of substring-matching.
            try:
                claim_raw = await btc_chain_reader.get_raw_tx(btc_claim_txid, min_confirmations=0)
            except InsufficientConfirmationsError:
                print(f"  BTC claim still unconfirmed; retrying in {args.poll_interval_s}s...")
                await asyncio.sleep(args.poll_interval_s)
                continue
            now_rxd = rxd_blockcount(rxd_client)
            rec = await coord.taker_scrape_and_claim_asset(
                bytes(claim_raw),
                now_rxd_height=now_rxd,
                asset_locked_at_height=rxd_locked_at,
            )
            if rec.state is SwapState.COMPLETED:
                print(f"  -> {rec.state.value} — CROSS-CHAIN SWAP COMPLETE")
                break
            if rec.state is SwapState.SECRET_REVEALED:
                print(
                    f"  reorg gate: WAIT (BTC claim not yet {policy.btc_claim_reorg_depth.value}-deep); "
                    f"retrying in {args.poll_interval_s}s..."
                )
                await asyncio.sleep(args.poll_interval_s)
                continue
            if rec.state is SwapState.ASSET_VULNERABLE:
                # F-006: SQUEEZED -> ASSET_VULNERABLE. p is public; winner-take-all is an
                # explicit decision. Never re-enter the SECRET_REVEALED-only method (crash)
                # and never silently treat this as WAIT.
                print("  reorg gate SQUEEZED -> ASSET_VULNERABLE; attempting winner-take-all claim ...")
                confirm(
                    "taker_claim_asset_from_vulnerable: best-effort winner-take-all asset claim "
                    "(accepts the residual reorg risk the gate flagged)",
                    auto_yes=args.yes,
                )
                rec = await coord.taker_claim_asset_from_vulnerable(bytes(claim_raw))
                print(f"  -> {rec.state.value} (winner-take-all claim attempted; residual reorg risk accepted)")
                break
            raise SystemExit(
                f"unexpected state {rec.state.value} from the reorg-gated claim — operator must "
                f"intervene (p is public on-chain; claim txid {btc_claim_txid})"
            )

        print("\n  DONE.")
    finally:
        # close() on every transport unconditionally — exceptions in the run shouldn't
        # leak aiohttp sessions. MempoolSpaceBroadcaster grew a public close() in the
        # post-cbd5fc0 fix-up; both readers already had one.
        await btc_reader.close()
        await _btc_bcast.close()
        await btc_chain_reader.close()


def _parse_args(argv):
    ap = argparse.ArgumentParser(description="Resume a dust BTC<->RXD HTLC swap from persisted keys.")
    ap.add_argument("--keys-out", required=True, help="the run-keys file (must contain preimage_p_hex)")
    ap.add_argument("--btc-htlc-funding-txid", required=True, help="the confirmed HTLC funding txid")
    ap.add_argument(
        "--i-accept-dust-loss",
        action="store_true",
        help="REQUIRED to resume on any value-bearing network (e.g. mainnet bc); mirrors the "
        "forward runner's audit-gate flag — resume MUST NOT silently broadcast mainnet value "
        "just because a stale keys file exists.",
    )
    ap.add_argument("--yes", action="store_true")
    ap.add_argument("--btc-sats", type=int, default=1260)
    ap.add_argument("--rxd-photons", type=int, default=1000)
    ap.add_argument("--btc-fee-sats", type=int, default=600)
    ap.add_argument("--rxd-fee-photons", type=int, default=4_000_000)
    ap.add_argument(
        "--t-rxd-blocks",
        type=int,
        default=20,
        help="DEPRECATED post-cbd5fc0 fixup — t_rxd is now LOADED from the keys file; this arg is ignored",
    )
    ap.add_argument("--margin-sample-blocks", type=int, default=144)
    ap.add_argument("--btc-tail-percentile", type=float, default=90.0)
    ap.add_argument("--btc-claim-reorg-depth", type=int, default=2)
    ap.add_argument("--rxd-claim-burial", type=int, default=2)
    ap.add_argument("--rxd-block-interval-s", type=float, default=300.0)
    ap.add_argument("--poll-interval-s", type=float, default=30.0)
    ap.add_argument(
        "--resume-deadline-s",
        type=float,
        default=None,
        help="hard upper bound on the WAIT-for-claim-confirmation loop. If omitted the "
        "value is auto-computed from the loaded t_rxd (0.5 × t_rxd × rxd_block_interval_s, "
        "floored at 600s) so the deadline always sits INSIDE the refund window. Past "
        "maker_claims_btc, p is public — a hostile/flaky mempool source MUST NOT stall "
        "the loop past t_rxd (red-team finding 2B). Operator-supplied values are capped "
        "to the same upper bound and must be finite + positive (no inf/nan footgun).",
    )
    return ap.parse_args(argv)


if __name__ == "__main__":
    asyncio.run(resume(_parse_args(sys.argv[1:])))
