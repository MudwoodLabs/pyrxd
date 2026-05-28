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
import sys
import time
from pathlib import Path

import coincurve

from pyrxd.btc_wallet import taproot as bt
from pyrxd.btc_wallet.htlc_leg import BitcoinTaprootLeg, FundingPolicy
from pyrxd.btc_wallet.keys import generate_keypair
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
    StepReport,
    atomic_write_mode_600,
    confirm,
    measured_margin_from_mainnet,
    rxd_blockcount,
    validated_resume_deadline_s,
)
from radiant_mainnet_chainio import SshTrRadiantClient

# Per-stage endpoints. signet uses the "tb" HRP + the mempool.space signet API.
_STAGES = {
    "dry-run": {"btc_network": "bc", "btc_base_url": "https://mempool.space/api", "broadcast": False},
    "signet": {"btc_network": "tb", "btc_base_url": "https://mempool.space/signet/api", "broadcast": True},
    "dust": {"btc_network": "bc", "btc_base_url": "https://mempool.space/api", "broadcast": True},
}
_MAINNET_BTC_API = "https://mempool.space/api"


# Helpers (CapturingBroadcaster, InMemSeen, SshTrFeeSource, StepReport, confirm,
# atomic_write_mode_600, rxd_blockcount, measured_margin_from_mainnet) live in
# _dust_swap_shared so the resume runner builds the SAME object graph. Imported at the
# top of this file.


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

    policy, provenance = await measured_margin_from_mainnet(args)
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
    # Build the BTC HTLC up-front so we can persist its address (resume must reconstruct
    # the same taproot output key; persisting it lets resume detect a margin-drift bug
    # that would otherwise silently swap the refund leaf for a non-matching one).
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
    htlc = bt.build_htlc(
        hashlock=h, claim_pubkey_xonly=claim_xo, refund_pubkey_xonly=refund_xo, timeout=t_btc, network=btc_network
    )

    # PERSIST ALL RUN STATE NOW (before any address is printed/funded). On a real run
    # these hold real value: the taker BTC key receives your funding + signs the refund;
    # the maker BTC key signs the claim; the RXD keys + covenant SPK locate/spend the
    # RXD leg. A crash after you fund but before completion would STRAND the value
    # without these WIFs. Written mode-600 ATOMICALLY (O_EXCL avoids a write-then-chmod
    # race that would expose the file at umask-default mode for a few microseconds —
    # a window plex/clamav/any same-group reader could win).
    #
    # The preimage p IS persisted here — in a SINGLE-OPERATOR run this file already
    # holds maker_btc_wif (the claim key) and every key that can move every output, so
    # it is already the single point of total compromise; withholding p from the SAME
    # file buys no secrecy yet costs crash-resilience (a crash before p is revealed
    # on-chain would otherwise lose it permanently, forcing a timelock refund — exactly
    # the failure we hit on the first run). p stays out of the report and the logs; this
    # mode-600 recovery file is its only on-disk home. Delete the whole file after sweep.
    keys_payload = {
        "created_unix": int(time.time()),
        "stage": args.stage,
        "btc_network": btc_network,
        "rxd_network": args.rxd_network,
        "hashlock_H": h.hex(),
        "preimage_p_hex": p.hex(),  # recovery only; same trust domain as the WIFs below
        "taker_btc_wif": taker_btc_kp.unsafe_wif(),
        "taker_btc_p2wpkh": taker_btc_kp.p2wpkh_address,
        "maker_btc_wif_raw_hex": maker_btc.secret.hex(),
        "taker_rxd_wif": taker_rxd.wif(),
        "maker_rxd_wif": maker_rxd.wif(),
        "rxd_covenant_spk": cov.funded_spk.hex(),
        "btc_claim_payout_spk": args.btc_claim_payout,
        "btc_refund_payout_spk": args.btc_refund_payout,
        # Persist the SCALARS the resume needs to rebuild the SAME taproot output key
        # (and assert the rebuild matches). Without these, resume re-measures the margin
        # and could derive a different t_btc -> different refund leaf -> taproot key
        # that doesn't match the on-chain HTLC. Found by review of cbd5fc0.
        "t_btc_blocks": t_btc.value,
        "t_rxd_blocks": t_rxd.value,
        "margin_blocks": margin_blocks,
        "btc_htlc_address": htlc.address,
        "note": "ALL run state for recovery/sweep incl preimage p. Single point of total "
        "compromise — mode 600, delete after sweep.",
    }
    keys_path = Path(args.keys_out).expanduser()
    atomic_write_mode_600(keys_path, json.dumps(keys_payload, indent=2))
    print(f"  run keys persisted -> {keys_path} (mode 600) — for recovery/sweep")
    print(
        f"  terms: btc_sats={args.btc_sats} rxd_photons={args.rxd_photons} "
        f"t_btc={t_btc.value} t_rxd={t_rxd.value} margin={margin_blocks}"
    )
    print(f"  BTC HTLC funding address ({btc_network}): {htlc.address}")
    print(f"  RXD covenant SPK (fund this as the maker): {cov.funded_spk.hex()}")

    if not do_broadcast:
        # dry-run: build the txs, report the addresses/terms, stop before any broadcast.
        report.step(
            name="dry_run_built",
            chain="both",
            btc_htlc_address=htlc.address,
            rxd_covenant_spk=cov.funded_spk.hex(),
            t_btc=t_btc.value,
            t_rxd=t_rxd.value,
        )
        report.dump(args.report_out)
        print(
            "\n  DRY-RUN complete: real txs are buildable; nothing broadcast. "
            "Next: SIGNET stage for the first real BTC consensus check."
        )
        return

    # ---- transports (broadcast stages) ----
    btc_reader = MempoolSpaceFundingReader(base_url=stage["btc_base_url"])
    _btc_bcast = MempoolSpaceBroadcaster(base_url=stage["btc_base_url"])
    btc_broadcaster = CapturingBroadcaster(_btc_bcast)  # capture the claim raw for scraping
    btc_chain_reader = MempoolSpaceSource(base_url=stage["btc_base_url"])  # to fetch the maker claim tx
    rxd_client = SshTrRadiantClient(rpcwallet=args.rxd_wallet)
    rxd_client.register_spk(cov.funded_spk)

    print(f"\n  Fund the taker BTC address from your {btc_network} wallet (amount + fee), 1 conf:")
    print(f"    {taker_btc_kp.p2wpkh_address}")
    confirm(f"look up the funding UTXO at {taker_btc_kp.p2wpkh_address}", auto_yes=args.yes)
    utxos = await btc_reader.list_address_utxos(taker_btc_kp.p2wpkh_address)
    need = args.btc_sats + args.btc_fee_sats
    confirmed = [u for u in utxos if u["confirmed"] and u["value_sats"] >= need]
    if not confirmed:
        raise SystemExit(f"no confirmed funding UTXO >= {need} sats at the taker address yet")
    fu = confirmed[0]
    funding_utxo = BtcUtxo(txid=fu["txid"], vout=fu["vout"], value=fu["value_sats"])

    btc_leg = BitcoinTaprootLeg(
        network=btc_network,
        taker_keypair=taker_btc_kp,
        funding_utxo=funding_utxo,
        maker_claim_pubkey_xonly=claim_xo,
        broadcaster=btc_broadcaster,
        funding_reader=btc_reader,
        refund_to_scriptpubkey=btc_refund_payout,
        claim_to_scriptpubkey=btc_claim_payout,
        # FundingPolicy groups the operational knobs: fee, conf depth, input type, AND
        # the post-broadcast readback poll. The poll is the bug-1 fix — on mainnet the
        # just-broadcast HTLC funding tx is 0-conf when fund() reads back its amount,
        # so we wait up to fund_confirm_timeout_s instead of failing instantly.
        policy=FundingPolicy(
            fee_sats=args.btc_fee_sats,
            min_confirmations=1,
            funding_input_type="p2wpkh",
            fund_confirm_poll_s=args.poll_interval_s,
            fund_confirm_timeout_s=args.fund_confirm_timeout_s,
        ),
        maker_claim_privkey=maker_btc.secret,
        audit_cleared=audit_cleared,
    )
    rxd_leg = RadiantCovenantLeg(
        network=args.rxd_network,
        taker_pkh=taker_pkh,
        maker_pkh=maker_pkh,
        chain_io=RadiantChainIO(rxd_client),
        fee_source=SshTrFeeSource(rxd_client, args.rxd_fee_photons),
        min_confirmations=1,
        audit_cleared=audit_cleared,
    )
    coord = SwapCoordinator(
        record=SwapRecord(state=SwapState.NEGOTIATED, terms=terms),
        btc_leg=btc_leg,
        radiant_leg=rxd_leg,
        indexer=None,
        seen_store=InMemSeen(),
        config=CoordinatorConfig(margin_policy=policy),
    )

    try:
        # 1. Taker funds the BTC HTLC.
        confirm(f"taker_funds_btc: broadcast the {btc_network} P2TR HTLC funding tx", auto_yes=args.yes)
        rec = await coord.taker_funds_btc(terms)
        report.step(
            name="taker_funds_btc",
            chain="btc",
            state=rec.state.value,
            txid=rec.btc_locator.funding_outpoint.txid,
            amount_sats=rec.btc_locator.amount_sats,
        )
        print(f"  -> {rec.state.value} (HTLC funded: {rec.btc_locator.funding_outpoint.txid})")

        # 2. Maker locks the RXD covenant (operator pays the SPK), taker re-validates.
        # Capture the RXD height at/just-before the asset lock — the t_rxd refund window is
        # measured from here, so a conservative (slightly-low) value is safe (it can only make
        # the reorg-gate squeeze MORE cautious, never less). The covenant is funded at-or-after
        # this height. Mirrors the regtest harness's rxd_locked_at = getblockcount()-before-fund.
        rxd_locked_at = rxd_blockcount(rxd_client)
        confirm("you have funded the RXD covenant SPK on mainnet and it has >= 1 conf", auto_yes=args.yes)
        rec = await coord.post_asset_lock_revalidate(cov.funded_spk)
        report.step(
            name="post_asset_lock_revalidate",
            chain="rxd",
            state=rec.state.value,
            covenant_outpoint=rec.radiant_covenant_outpoint,
        )
        print(f"  -> {rec.state.value}")
        if rec.state is not SwapState.BOTH_LOCKED:
            raise SystemExit(
                f"covenant mismatch -> {rec.state.value}; refund the BTC HTLC after t_btc (taker_refund_btc)"
            )

        print(
            "\n  *** MONITORING WINDOW (BOTH_LOCKED): poll maybe_refund_asset_on_maker_stall well inside "
            "maker_stall_safety_window_blocks. Do NOT walk away — the maker-stall steal is the real loss path. ***"
        )

        # 3. Maker claims BTC, revealing p.
        confirm("maker_claims_btc: broadcast the BTC claim (reveals p on-chain)", auto_yes=args.yes)
        rec = await coord.maker_claims_btc(p_secret)
        report.step(name="maker_claims_btc", chain="btc", state=rec.state.value)
        if btc_broadcaster.last_raw is None:
            raise SystemExit("did not capture the BTC claim bytes; cannot proceed to the taker claim")
        btc_claim_txid = Txid(bt.btc_txid_from_raw(btc_broadcaster.last_raw))  # LOCAL — never trusted input
        print(f"  -> {rec.state.value} (BTC claim txid {btc_claim_txid})")

        # 4. Taker reads the maker's claim off the BTC chain, runs the REORG GATE, claims RXD.
        # Bounded by a SAFE deadline derived from t_rxd (validator rejects inf/nan and
        # caps any operator value at 0.5 × t_rxd_seconds — a deadline LONGER than t_rxd
        # would let the loop forfeit the asset). Past maker_claims_btc, p is public.
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
                    f"deadline ({deadline_s:.0f}s) exceeded — operator must intervene "
                    f"(p is public on-chain; covenant claim still pending). claim txid {btc_claim_txid}"
                )
            try:
                claim_raw = await btc_chain_reader.get_raw_tx(btc_claim_txid, min_confirmations=0)
            except InsufficientConfirmationsError:
                print(f"  BTC claim still unconfirmed; retrying in {args.poll_interval_s}s...")
                report.step(name="claim_unconfirmed", chain="btc", state=rec.state.value)
                await asyncio.sleep(args.poll_interval_s)
                continue
            now_rxd = rxd_blockcount(rxd_client)
            rec = await coord.taker_scrape_and_claim_asset(
                bytes(claim_raw),
                now_rxd_height=now_rxd,
                asset_locked_at_height=rxd_locked_at,
            )
            if rec.state is SwapState.COMPLETED:
                report.step(
                    name="taker_scrape_and_claim_asset",
                    chain="rxd",
                    state=rec.state.value,
                    covenant_outpoint=rec.radiant_covenant_outpoint,
                    btc_claim_txid=str(btc_claim_txid),
                )
                print(f"  -> {rec.state.value} — CROSS-CHAIN SWAP COMPLETE")
                break
            # WAIT (still SECRET_REVEALED): the claim isn't deep enough yet. Poll again.
            print(f"  reorg gate: WAIT (BTC claim not yet {policy.btc_claim_reorg_depth.value}-deep); retrying...")
            report.step(name="reorg_gate_wait", chain="btc", state=rec.state.value)
            await asyncio.sleep(args.poll_interval_s)
    finally:
        # ALWAYS dump the report + close transports, even on exception — operator needs
        # the partial state. MempoolSpaceBroadcaster grew a public close() in the
        # post-cbd5fc0 fix-up; previous version reached into _http directly.
        report.dump(args.report_out)
        await btc_reader.close()
        await _btc_bcast.close()
        await btc_chain_reader.close()


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
    ap.add_argument(
        "--resume-deadline-s",
        type=float,
        default=None,
        help="hard upper bound on the taker WAIT-for-claim-confirmation loop after the maker "
        "reveals p on-chain. If omitted the value is auto-computed from t_rxd (0.5 × t_rxd "
        "× rxd_block_interval_s, floored at 600s) so the deadline always sits INSIDE the "
        "refund window. Operator-supplied values are capped to the same upper bound and "
        "must be finite + positive (no inf/nan footgun).",
    )
    ap.add_argument(
        "--fund-confirm-timeout-s",
        type=float,
        default=7200.0,
        help="max wait for the HTLC funding tx to reach 1 conf before fund() gives up (default 2h)",
    )
    ap.add_argument("--report-out", default="dust_swap_report.json")
    ap.add_argument(
        "--keys-out",
        default="~/.gravity_dust_run_keys.json",
        help="mode-600 file holding ALL run state INCLUDING preimage p — single point of "
        "total compromise. Default lives in $HOME (mode-700 dir). Delete after sweep.",
    )
    args = ap.parse_args(argv)
    if _STAGES[args.stage]["broadcast"] and (not args.btc_claim_payout or not args.btc_refund_payout):
        ap.error("--btc-claim-payout and --btc-refund-payout (scriptPubKey hex) are required for broadcast stages")
    return args


if __name__ == "__main__":
    asyncio.run(run_dust_swap(_parse_args(sys.argv[1:])))
