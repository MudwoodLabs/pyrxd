#!/usr/bin/env python3
"""REAL-VALUE griefing run (S1) — maker STALLS, the honest taker recovers via mutual_refund.

The companion to eth_swap_run.py (happy path). Here the MAKER deliberately stalls (never claims the
ETH, never reveals p) — the griefing / free-option attack. The honest taker recovers via
mutual_refund, which refunds BOTH legs: the taker's ETH back to the taker AND the RXD covenant back
to the maker (the covenant CSV-refund branch pays the MAKER, not the taker — verified 2026-06-02).
Safety property demonstrated: a stalling maker cannot make the honest taker suffer a one-sided loss.

Real value: ETH on SEPOLIA (free testnet) + RXD on MAINNET (tiny real dust + ~0.1 RXD in fees for
the covenant fund + CSV refund). Requires --i-accept-dust-loss + the ETH creds. Confirm-before-every-
broadcast (no --yes for the real run). Reuses eth_swap_run.py's building blocks + the ssh-tr transport.

Timing: mutual_refund needs BOTH legs matured — the RXD covenant buried t_rxd deep (BIP68 CSV) AND
the ETH timeout passed. Margin components are set SMALL here (this is a deliberate dust test, not a
production swap) so the ETH timeout is reachable in ~10-15 min rather than ~1 h. The cross-clock gate
still runs (eth_timeout > rxd_refund_open + margin); we just size the margin for a fast demo.

Example:
  python scripts/eth_swap_grief_run.py --i-accept-dust-loss \
      --eth-rpc-url https://gateway.tenderly.co/public/sepolia --eth-key-hex <taker-key> \
      --eth-claim-to 0x<maker> --eth-refund-to 0x<taker> --rxd-wallet ''
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _dust_swap_shared import InMemSeen, SshTrFeeSource, StepReport, atomic_write_mode_600, confirm
from eth_swap_run import _build_terms_and_covenant, _eth_leg
from radiant_mainnet_chainio import SshTrRadiantClient

from pyrxd.btc_wallet import taproot as bt
from pyrxd.gravity.eth_rxd_timelock import CrossClockMargin
from pyrxd.gravity.radiant_leg import RadiantChainIO, RadiantCovenantLeg
from pyrxd.gravity.swap_coordinator import CoordinatorConfig, MarginPolicy, SwapCoordinator
from pyrxd.gravity.swap_state import NegotiatedTerms, SwapRecord, SwapState  # noqa: F401


def _margin(args) -> CrossClockMargin:
    # SMALL margin for a fast dust demo (not production sizing).
    return CrossClockMargin(
        eth_reorg_finality_s=args.eth_finalization_window_s,
        rxd_claim_burial_s=args.rxd_claim_burial_s,
        rxd_confirm_slack_s=args.rxd_confirm_slack_s,
        rounding_slack_s=args.rounding_slack_s,
    )


def _policy(args) -> MarginPolicy:
    return MarginPolicy(
        margin=bt.Timelock(args.margin_blocks, bt.TimeUnit.BLOCKS),
        block_interval_s=args.btc_block_interval_s,
        is_measured=False,
        rxd_block_interval_s=args.rxd_block_interval_s,
        eth_finalization_window_s=args.eth_finalization_window_s,
        cross_clock_margin=_margin(args),
        max_covenant_confirm_wait_s=args.max_covenant_confirm_wait_s,
    )


async def run(args) -> None:
    if not args.i_accept_dust_loss:
        raise SystemExit("requires --i-accept-dust-loss (you are moving REAL mainnet RXD)")
    for req in ("eth_rpc_url", "eth_key_hex", "eth_claim_to", "eth_refund_to"):
        if not getattr(args, req):
            raise SystemExit(f"requires --{req.replace('_', '-')}")
    rxd_network = SshTrRadiantClient.NETWORK
    print(f"=== ETH↔RXD GRIEFING run (S1) — ETH=sepolia, RXD={rxd_network} mainnet ===")
    print("    maker STALLS; the honest taker recovers via mutual_refund (no one-sided loss).")

    eth_timeout = int(time.time()) + args.eth_timeout_s
    terms, cov, p_secret, h, rkeys = _build_terms_and_covenant(args, eth_timeout=eth_timeout)
    report = StepReport(
        "grief-run", {"scenario": "S1 maker-stall -> mutual_refund", "eth_chain": "sepolia", "rxd_network": rxd_network}
    )

    keys_path = Path(args.keys_out).expanduser()
    atomic_write_mode_600(
        keys_path,
        json.dumps(
            {
                "created_unix": int(time.time()),
                "scenario": "grief-S1",
                "hashlock_H": h.hex(),
                "preimage_p_hex": p_secret.unsafe_raw_bytes().hex(),
                "eth_key_hex": args.eth_key_hex,
                "eth_claim_to": args.eth_claim_to,
                "eth_refund_to": args.eth_refund_to,
                "eth_timeout_unix_s": eth_timeout,
                "eth_amount_wei": args.eth_amount_wei,
                "taker_rxd_wif": rkeys[0].wif(),
                "maker_rxd_wif": rkeys[1].wif(),
                "rxd_covenant_spk": cov.funded_spk.hex(),
                "t_rxd_blocks": terms.t_rxd.value,
                "note": "grief run recovery; mode 600 — delete after the refunds confirm.",
            },
            indent=2,
        ),
    )
    print(f"  run keys persisted -> {keys_path} (mode 600)")

    rpc, eth_leg = _eth_leg(
        args,
        rpc_url=args.eth_rpc_url,
        chain_id=args.eth_chain_id,
        key_hex=args.eth_key_hex,
        claim_to=args.eth_claim_to,
        refund_to=args.eth_refund_to,
        eth_timeout=eth_timeout,
        network="sepolia",
    )
    rxd_client = SshTrRadiantClient(rpcwallet=args.rxd_wallet)
    rxd_client.register_spk(cov.funded_spk)
    rxd_leg = RadiantCovenantLeg(
        network=rxd_network,
        taker_pkh=rkeys[2],
        maker_pkh=rkeys[3],
        chain_io=RadiantChainIO(rxd_client),
        fee_source=SshTrFeeSource(rxd_client, args.rxd_fee_photons),
        min_confirmations=1,
        audit_cleared=True,
    )
    coord = SwapCoordinator(
        record=SwapRecord(state=SwapState.NEGOTIATED, terms=terms),
        counter_leg=eth_leg,
        radiant_leg=rxd_leg,
        indexer=None,
        seen_store=InMemSeen(),
        # accept_estimated_eth_margins: operator-gated DUST griefing run; consciously accepts
        # estimated-margin risk on negligible value (MEDIUM-1). Non-dust value → measured policy.
        config=CoordinatorConfig(
            margin_policy=_policy(args), accept_nondurable_seen=True, accept_estimated_eth_margins=True
        ),
    )

    try:
        # 1. Taker funds the ETH HTLC on Sepolia.
        confirm("taker_funds: deploy+fund the ETH HTLC on SEPOLIA", auto_yes=args.yes)
        rec = await coord.taker_funds_btc(terms, now_unix_s=int(time.time()))
        report.step(
            name="taker_funds_eth",
            chain="eth",
            state=rec.state.value,
            contract=rec.counterchain_locator.contract_address,
        )
        print(f"  -> {rec.state.value} (ETH HTLC {rec.counterchain_locator.contract_address})")

        # 2. Maker locks the RXD covenant on MAINNET (operator funds the SPK).
        print(f"\n  Fund the RXD covenant SPK on MAINNET (the maker lock; >= 1 conf):\n    {cov.funded_spk.hex()}")
        confirm("you have funded the RXD covenant SPK on mainnet and it has >= 1 conf", auto_yes=args.yes)
        rec = await coord.post_asset_lock_revalidate(cov.funded_spk, now_unix_s=int(time.time()))
        report.step(
            name="post_asset_lock_revalidate",
            chain="rxd",
            state=rec.state.value,
            covenant_outpoint=rec.radiant_covenant_outpoint,
        )
        print(f"  -> {rec.state.value}")
        if rec.state is not SwapState.BOTH_LOCKED:
            raise SystemExit(f"not BOTH_LOCKED ({rec.state.value}); recover manually")

        # 3. The MAKER STALLS — it deliberately does NOT claim the ETH. (The griefing deviation.)
        print("\n  *** MAKER STALLS: deliberately NOT claiming the ETH (the griefing attack). ***")
        print("  Waiting for BOTH legs to mature so the honest taker can mutual_refund:")
        print(f"    - the RXD covenant must bury {terms.t_rxd.value} blocks deep (BIP68 CSV)")
        print(f"    - the ETH timeout must pass (eth_timeout = {eth_timeout}, ~{args.eth_timeout_s}s out)")

        # 4. mutual_refund once both are mature (operator times the wait; we just gate the broadcast).
        confirm(
            "BOTH matured (RXD covenant t_rxd-deep AND past the ETH timeout)? mutual_refund refunds "
            "the taker's ETH + CSV-refunds the covenant to the maker",
            auto_yes=args.yes,
        )
        rec = await coord.mutual_refund()
        report.step(
            name="mutual_refund", chain="both", state=rec.state.value, covenant_outpoint=rec.radiant_covenant_outpoint
        )
        print(f"  -> {rec.state.value}")
        if rec.state is SwapState.MUTUAL_REFUND:
            print("\n  S1 PROVEN ON REAL CHAINS: the stalling maker caused NO one-sided loss —")
            print("    the taker's ETH refunded to the taker; the RXD covenant CSV-refunded to the maker.")
    finally:
        report.dump(args.report_out)
        print(f"  report -> {args.report_out}")
        await rpc.close()


def _args():
    ap = argparse.ArgumentParser(description="ETH↔RXD griefing run (S1: maker stall -> mutual_refund)")
    ap.add_argument("--i-accept-dust-loss", action="store_true")
    ap.add_argument("--yes", action="store_true", help="auto-confirm (UNATTENDED only)")
    ap.add_argument("--eth-rpc-url", default="")
    ap.add_argument("--eth-key-hex", default="")
    ap.add_argument("--eth-chain-id", type=int, default=11155111)
    ap.add_argument("--eth-amount-wei", type=int, default=10**14)
    ap.add_argument("--eth-claim-to", default="")
    ap.add_argument("--eth-refund-to", default="")
    ap.add_argument(
        "--eth-artifact", default=str(Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "EthHtlc.json")
    )
    ap.add_argument("--eth-timeout-s", type=int, default=1800)  # 30 min — clears the 768s finality floor + margin
    ap.add_argument("--rxd-photons", type=int, default=1000)
    ap.add_argument("--rxd-fee-photons", type=int, default=5_000_000)
    ap.add_argument("--rxd-wallet", default="")
    ap.add_argument("--t-rxd-blocks", type=int, default=3)  # small CSV so it matures fast on mainnet
    # Margin kept lean for a fast dust demo, EXCEPT eth-finalization-window-s, which is hard-floored at
    # 768s (~2 post-Merge epochs) by MarginPolicy — finalization genuinely takes 2 epochs, not reducible.
    ap.add_argument("--margin-blocks", type=int, default=2)
    ap.add_argument("--btc-block-interval-s", type=float, default=600.0)
    ap.add_argument("--rxd-block-interval-s", type=float, default=120.0)
    ap.add_argument("--eth-finalization-window-s", type=int, default=768)  # hard floor (2 epochs)
    ap.add_argument("--rxd-claim-burial-s", type=int, default=60)
    ap.add_argument("--rxd-confirm-slack-s", type=int, default=60)
    ap.add_argument("--rounding-slack-s", type=int, default=120)
    ap.add_argument("--max-covenant-confirm-wait-s", type=int, default=120)
    ap.add_argument("--report-out", default="/tmp/eth_grief_report.json")  # noqa: S108
    ap.add_argument("--keys-out", default="~/.eth_grief_run_keys.json")
    return ap.parse_args()


if __name__ == "__main__":
    asyncio.run(run(_args()))
