#!/usr/bin/env python3
"""ETH↔RXD dust swap runner — the Sepolia(ETH)↔RXD-mainnet analog of dust_swap_run.py.

Wires the UNCHANGED production SwapCoordinator + EthLeg + RadiantCovenantLeg to real transports
and walks the MAKER_SECRET_TAKER_LOCKS_BTC_FIRST runbook (here the counter leg is ETH, not BTC),
confirming before EVERY irreversible broadcast and writing a mode-600 recovery file + a
provenance-tracked report. The RXD side is IDENTICAL to dust_swap_run.py (the ssh-tr mainnet
transport); only the counter leg differs (EthLeg deploying the real EthHtlc.sol on Ethereum).

Stages (--stage), each gating the next:
  dry-run     : spin a LOCAL anvil, build the swap, DEPLOY+verify the ETH HTLC on anvil + build
                the RXD covenant — proves the harness's ETH wiring end-to-end with NO real value.
                (The full cross-chain run is covered by tests/test_xchain_eth_swap_regtest_e2e.py.)
  sepolia-dust: ETH on SEPOLIA (free testnet) ↔ RXD on MAINNET (tiny real value). The taker
                deploys+funds the ETH HTLC on Sepolia; you fund the RXD covenant on mainnet; the
                maker claims ETH (reveals p); the taker scrapes p + claims the RXD covenant once
                the ETH claim is FINAL (real post-Merge finality). Requires --i-accept-dust-loss.

Examples:
  python scripts/eth_swap_run.py --stage dry-run
  python scripts/eth_swap_run.py --stage sepolia-dust --i-accept-dust-loss \
      --eth-rpc-url https://sepolia.infura.io/v3/KEY --eth-key-hex <funded-sepolia-key> \
      --eth-claim-to 0x<maker> --eth-refund-to 0x<taker> --rxd-wallet gravity
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

# scripts/ siblings (same import style as dust_swap_run.py / dust_swap_resume.py)
sys.path.insert(0, str(Path(__file__).resolve().parent))
from _dust_swap_shared import (
    InMemSeen,
    SshTrFeeSource,
    StepReport,
    atomic_write_mode_600,
    confirm,
    rxd_blockcount,
)
from _glyph_mainnet import (  # scripts/ sibling (NFT + FT paths)
    load_minted_ft,
    load_minted_nft,
    lock_ft_into_covenant,
    lock_singleton_into_covenant,
    mint_ft_inline,
    mint_nft_inline,
    wait_genesis_mature,
)
from _glyph_ref_http import SshTrHttpRefAdapter  # scripts/ sibling (mainnet REST REF gate)
from radiant_mainnet_chainio import SshTrRadiantClient

from pyrxd.btc_wallet import taproot as bt
from pyrxd.eth_wallet.htlc_leg import EthHtlcContractLeg, load_artifact
from pyrxd.eth_wallet.rpc import EthRpc
from pyrxd.glyph.types import GlyphRef
from pyrxd.gravity.eth_leg import EthLeg
from pyrxd.gravity.eth_rxd_timelock import CrossClockMargin
from pyrxd.gravity.htlc_covenant import build_htlc_covenant_ft, build_htlc_covenant_nft, build_htlc_covenant_rxd
from pyrxd.gravity.radiant_leg import RadiantChainIO, RadiantCovenantLeg, RxinDexerRefAdapter
from pyrxd.gravity.swap_coordinator import CoordinatorConfig, MarginPolicy, SwapCoordinator
from pyrxd.gravity.swap_state import NegotiatedTerms, SwapRecord, SwapState
from pyrxd.keys import PrivateKey
from pyrxd.network.electrumx import ElectrumXClient
from pyrxd.network.rxindexer import RxinDexerClient
from pyrxd.security.secrets import PrivateKeyMaterial, SecretBytes
from pyrxd.security.types import Hex20

_DEFAULT_ARTIFACT = Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "EthHtlc.json"
_SEPOLIA_CHAIN_ID = 11155111
_ANVIL_KEY = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"  # anvil acct 0 (public devnet)
_ANVIL_ADDR0 = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
_ANVIL_ADDR1 = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"


class _CapturingEthLeg:
    """Wraps EthLeg to capture the maker's claim tx hash (the coordinator drives claim() but
    discards its return; the taker's scrape step needs it). Mirrors CapturingBroadcaster."""

    def __init__(self, inner: EthLeg) -> None:
        self._inner = inner
        self.last_claim_tx = None

    def __getattr__(self, name):
        return getattr(self._inner, name)

    async def claim(self, locator, preimage):
        self.last_claim_tx = await self._inner.claim(locator, preimage)
        return self.last_claim_tx


def _cross_clock_margin(args: argparse.Namespace) -> CrossClockMargin:
    return CrossClockMargin(
        eth_reorg_finality_s=args.eth_finalization_window_s,
        rxd_claim_burial_s=args.rxd_claim_burial_s,
        rxd_confirm_slack_s=args.rxd_confirm_slack_s,
        rounding_slack_s=args.rounding_slack_s,
    )


def _policy(args: argparse.Namespace) -> MarginPolicy:
    return MarginPolicy(
        margin=bt.Timelock(args.margin_blocks, bt.TimeUnit.BLOCKS),
        block_interval_s=args.btc_block_interval_s,
        is_measured=False,
        rxd_block_interval_s=args.rxd_block_interval_s,
        eth_finalization_window_s=args.eth_finalization_window_s,
        cross_clock_margin=_cross_clock_margin(args),
        max_covenant_confirm_wait_s=args.max_covenant_confirm_wait_s,
        # Dust harness: value below the Radiant reorg cost → opt out of value-scaled burial.
        accept_flat_burial=True,
    )


def _anvil_rpc(url, method, params=None):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params or []}).encode()
    req = urllib.request.Request(url, data=body, headers={"content-type": "application/json"})  # noqa: S310
    return json.loads(urllib.request.urlopen(req, timeout=5).read())  # noqa: S310 — local anvil RPC only


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _build_terms_and_covenant(args, *, eth_timeout: int, minted=None):
    """Build the HTLC covenant + negotiated terms. ``minted`` (a MintedNft) is REQUIRED for the
    NFT variant — the covenant binds the genesis ref ``reveal_txid:0`` of the freshly-minted NFT."""
    p_secret = SecretBytes(os.urandom(32))
    h = hashlib.sha256(p_secret.unsafe_raw_bytes()).digest()
    t_rxd = bt.Timelock(args.t_rxd_blocks, bt.TimeUnit.BLOCKS)
    t_btc = bt.Timelock(args.t_rxd_blocks + args.margin_blocks + 4, bt.TimeUnit.BLOCKS)  # decorative for ETH
    taker_rxd, maker_rxd = PrivateKey(os.urandom(32)), PrivateKey(os.urandom(32))
    taker_pkh = bytes(Hex20(taker_rxd.public_key().hash160()))
    maker_pkh = bytes(Hex20(maker_rxd.public_key().hash160()))
    if args.asset_variant == "nft":
        if minted is None:
            raise SystemExit("internal: the NFT path must mint the singleton before building the covenant")
        # Bind the covenant to the TRUE genesis ref the singleton carries (the commit outpoint,
        # parsed from its d8<ref>) — NOT reveal_txid:0 (the singleton's current location). Binding the
        # wrong ref makes the covenant require a singleton that does not exist -> NFT permanently stranded.
        cov = build_htlc_covenant_nft(
            genesis_txid=minted.genesis_txid,
            genesis_vout=minted.genesis_vout,
            nft_carrier_value=args.nft_carrier_photons,
            taker_pkh=taker_pkh,
            maker_pkh=maker_pkh,
            hashlock=h,
            refund_csv=t_rxd.value,
        )
        asset_variant = "nft"
        genesis_ref = GlyphRef(txid=minted.genesis_txid, vout=minted.genesis_vout).to_bytes()
        radiant_amount = args.nft_carrier_photons
    elif args.asset_variant == "ft":
        if minted is None:
            raise SystemExit("internal: the FT path must mint the FT before building the covenant")
        # FT covenant: the FT VALUE flows whole into the covenant (conservation), so radiant_amount ==
        # the minted FT amount — NOT an independent carrier. Genesis ref = the commit outpoint.
        cov = build_htlc_covenant_ft(
            genesis_txid=minted.genesis_txid,
            genesis_vout=minted.genesis_vout,
            amount=minted.ft_amount,
            taker_pkh=taker_pkh,
            maker_pkh=maker_pkh,
            hashlock=h,
            refund_csv=t_rxd.value,
        )
        asset_variant = "ft"
        genesis_ref = GlyphRef(txid=minted.genesis_txid, vout=minted.genesis_vout).to_bytes()
        radiant_amount = minted.ft_amount
    else:
        cov = build_htlc_covenant_rxd(
            amount=args.rxd_photons, taker_pkh=taker_pkh, maker_pkh=maker_pkh, hashlock=h, refund_csv=t_rxd.value
        )
        asset_variant, genesis_ref, radiant_amount = "rxd", b"", args.rxd_photons
    terms = NegotiatedTerms(
        hashlock=h,
        btc_sats=radiant_amount,
        radiant_amount=radiant_amount,
        t_btc=t_btc,
        t_rxd=t_rxd,
        asset_variant=asset_variant,
        genesis_ref=genesis_ref,
        taker_dest_hash=cov.expected_taker_hash,
        maker_dest_hash=cov.expected_maker_hash,
        btc_claim_pubkey_xonly=b"\x00" * 32,
        btc_refund_pubkey_xonly=b"\x00" * 32,
        counter_chain="eth",
        value_amount=args.eth_amount_wei,
        eth_timeout_unix_s=eth_timeout,
    )
    return terms, cov, p_secret, h, (taker_rxd, maker_rxd, taker_pkh, maker_pkh)


def _eth_leg(args, *, rpc_url, chain_id, key_hex, claim_to, refund_to, eth_timeout, network):
    rpc = EthRpc(rpc_url, expected_chain_id=chain_id)
    artifact = load_artifact(args.eth_artifact)
    contract_leg = EthHtlcContractLeg(
        rpc=rpc, signing_key=PrivateKeyMaterial(bytes.fromhex(key_hex)), chain_id=chain_id, artifact=artifact
    )
    leg = EthLeg(
        contract_leg=contract_leg,
        network=network,
        claim_to=claim_to,
        refund_to=refund_to,
        eth_timeout_unix_s=eth_timeout,
        audit_cleared=True,  # operator opts in (pre-audit dust validation)
    )
    return rpc, _CapturingEthLeg(leg)


# --------------------------------------------------------------------------- dry-run (anvil)


async def run_dry(args: argparse.Namespace) -> None:
    print("=== ETH↔RXD swap runner — stage=dry-run (local anvil; NO real value) ===")
    if "anvil" not in _which("anvil"):
        raise SystemExit("anvil not found on PATH — install foundry (the dry-run deploys on a local anvil)")
    port = _free_port()
    url = f"http://127.0.0.1:{port}"
    proc = subprocess.Popen(
        ["anvil", "--port", str(port), "--chain-id", "31337", "--slots-in-an-epoch", "1", "--silent"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        for _ in range(100):
            try:
                _anvil_rpc(url, "eth_chainId")
                break
            except Exception:
                time.sleep(0.1)
        now = int(_anvil_rpc(url, "eth_getBlockByNumber", ["latest", False])["result"]["timestamp"], 16)
        eth_timeout = now + args.eth_timeout_s
        terms, cov, _p_secret, _h, _keys = _build_terms_and_covenant(args, eth_timeout=eth_timeout)
        rpc, eth_leg = _eth_leg(
            args,
            rpc_url=url,
            chain_id=31337,
            key_hex=_ANVIL_KEY,
            claim_to=_ANVIL_ADDR1,
            refund_to=_ANVIL_ADDR0,
            eth_timeout=eth_timeout,
            network="anvil",
        )
        try:
            # Prove the harness's ETH wiring: EthLeg.fund deploys the real EthHtlc on anvil AND
            # runs verify_funded internally (immutables-by-getter + EOA + balance bind to terms).
            locator = await eth_leg.fund(terms)
            print(f"  ETH HTLC deployed + verified on anvil: {locator.contract_address}  ({locator.amount_wei} wei)")
            print(f"  RXD covenant SPK (would be funded by the maker on mainnet): {cov.funded_spk.hex()}")
            print(
                f"  terms: eth_wei={args.eth_amount_wei} rxd_photons={args.rxd_photons} "
                f"t_rxd={terms.t_rxd.value} eth_timeout=+{args.eth_timeout_s}s"
            )
            print(
                "\n  DRY-RUN OK: the ETH leg deploys+verifies against a real EVM and the covenant builds. "
                "Full cross-chain run: tests/test_xchain_eth_swap_regtest_e2e.py. Next: --stage sepolia-dust."
            )
        finally:
            await rpc.close()
    finally:
        proc.terminate()


def _which(name: str) -> str:
    import shutil

    return shutil.which(name) or ""


# --------------------------------------------------------------------------- sepolia-dust


async def run_sepolia_dust(args: argparse.Namespace) -> None:
    if not args.i_accept_dust_loss:
        raise SystemExit("stage=sepolia-dust requires --i-accept-dust-loss (you are moving REAL mainnet RXD)")
    for req in ("eth_rpc_url", "eth_key_hex", "eth_claim_to", "eth_refund_to"):
        if not getattr(args, req):
            raise SystemExit(f"stage=sepolia-dust requires --{req.replace('_', '-')}")
    # Pre-flight: refuse BEFORE minting if the recovery file already exists (atomic_write_mode_600 is
    # O_EXCL). A leftover file from a prior/aborted run would otherwise crash the keys-persist step
    # AFTER the (real-value) mint — wasting the mint. Fail cheap, up front.
    if Path(args.keys_out).expanduser().exists():
        raise SystemExit(
            f"recovery file already exists: {Path(args.keys_out).expanduser()} — move/delete it or pass a "
            f"fresh --keys-out before a new run (refusing to mint over a stale recovery file)"
        )
    # Pin the RXD network to the transport's true network (mainnet) — fail-closed like dust_swap_run.
    rxd_network = SshTrRadiantClient.NETWORK
    print(f"=== ETH↔RXD DUST swap — stage=sepolia-dust  (ETH=sepolia, RXD={rxd_network} mainnet) ===")

    policy = _policy(args)
    provenance = {
        "stage": "sepolia-dust",
        "eth_finalization_window_s": args.eth_finalization_window_s,
        "cross_clock_margin_total_s": _cross_clock_margin(args).total_s(),
        "max_covenant_confirm_wait_s": args.max_covenant_confirm_wait_s,
        "is_measured": False,
        "NOTE": "ESTIMATED margins — pre-external-audit dust validation; operator accepts dust loss",
    }
    report = StepReport("sepolia-dust", provenance)

    rxd_client = SshTrRadiantClient(rpcwallet=args.rxd_wallet)
    minted = None
    if args.asset_variant == "nft":
        if args.nft_reuse_reveal_txid:
            if not args.nft_owner_wif:
                raise SystemExit("--nft-reuse-reveal-txid requires --nft-owner-wif (to spend the singleton)")
            print(f"\n  --- NFT path: REUSING already-minted NFT at reveal {args.nft_reuse_reveal_txid} (no mint) ---")
            minted = load_minted_nft(rxd_client, reveal_txid=args.nft_reuse_reveal_txid, owner_wif=args.nft_owner_wif)
        else:
            print("\n  --- NFT path: minting a fresh throwaway NFT on RXD MAINNET (commit→reveal, real-value) ---")
            minted = mint_nft_inline(
                rxd_client,
                name=args.nft_name,
                commit_photons=args.nft_commit_photons,
                fee_photons=args.rxd_mint_fee_photons,
                confirm_fn=lambda m: confirm(m, auto_yes=args.yes),
                poll_s=args.confirm_poll_s,
            )
        print(f"  minted NFT genesis ref: {minted.ref_str}")
    elif args.asset_variant == "ft":
        if args.ft_reuse_reveal_txid:
            if not args.ft_owner_wif:
                raise SystemExit("--ft-reuse-reveal-txid requires --ft-owner-wif (to spend the FT)")
            print(f"\n  --- FT path: REUSING already-minted FT at reveal {args.ft_reuse_reveal_txid} (no mint) ---")
            minted = load_minted_ft(rxd_client, reveal_txid=args.ft_reuse_reveal_txid, owner_wif=args.ft_owner_wif)
        else:
            print("\n  --- FT path: minting a fresh throwaway Glyph FT on RXD MAINNET (commit→reveal premine) ---")
            minted = mint_ft_inline(
                rxd_client,
                name=args.ft_name,
                ticker=args.ft_ticker,
                premine_amount=args.ft_premine_photons,
                fee_photons=args.rxd_mint_fee_photons,
                confirm_fn=lambda m: confirm(m, auto_yes=args.yes),
                poll_s=args.confirm_poll_s,
            )
        print(f"  minted FT genesis ref: {minted.ref_str}  ({minted.ft_amount} units)")
    # eth_timeout starts AFTER the (slow, multi-block) mint, so the full window is available for the swap.
    eth_timeout = int(time.time()) + args.eth_timeout_s
    terms, cov, p_secret, h, _rkeys = _build_terms_and_covenant(args, eth_timeout=eth_timeout, minted=minted)

    # Persist ALL run state (mode 600) BEFORE any broadcast — recovery/sweep. Holds the preimage p
    # + the ETH signing key + the RXD keys + the covenant SPK; single point of total compromise.
    keys_path = Path(args.keys_out).expanduser()
    atomic_write_mode_600(
        keys_path,
        json.dumps(
            {
                "created_unix": int(time.time()),
                "stage": "sepolia-dust",
                "eth_chain": "sepolia",
                "rxd_network": rxd_network,
                "hashlock_H": h.hex(),
                "preimage_p_hex": p_secret.unsafe_raw_bytes().hex(),  # recovery only; same trust domain as keys
                "eth_key_hex": args.eth_key_hex,
                "eth_claim_to": args.eth_claim_to,
                "eth_refund_to": args.eth_refund_to,
                "eth_timeout_unix_s": eth_timeout,
                "eth_amount_wei": args.eth_amount_wei,
                "taker_rxd_wif": _rkeys[0].wif(),
                "maker_rxd_wif": _rkeys[1].wif(),
                "rxd_covenant_spk": cov.funded_spk.hex(),
                "t_rxd_blocks": terms.t_rxd.value,
                "asset_variant": args.asset_variant,
                "asset_genesis_ref": minted.ref_str if minted else None,
                "asset_owner_wif": minted.owner_key.wif() if minted else None,
                # NFT carries reveal_value; FT carries ft_amount — persist whichever the mint produced.
                "asset_reveal_value": getattr(minted, "reveal_value", None) if minted else None,
                "asset_ft_amount": getattr(minted, "ft_amount", None) if minted else None,
                "note": "ALL run state for recovery/sweep incl preimage p. mode 600 — delete after sweep.",
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
    rxd_client.register_spk(cov.funded_spk)
    rxd_leg = RadiantCovenantLeg(
        network=rxd_network,
        taker_pkh=_rkeys[2],
        maker_pkh=_rkeys[3],
        chain_io=RadiantChainIO(rxd_client),
        fee_source=SshTrFeeSource(rxd_client, args.rxd_fee_photons),
        min_confirmations=1,
        audit_cleared=True,
    )
    # NFT/FT both carry a genesis ref → the REAL RXinDexer is the genesis-ref authenticity oracle
    # (R1 fake-singleton defense). Plain RXD has no ref → no indexer needed. Default to the REST
    # adapter over ssh-tr (the mainnet deployment runs only the HTTP api, no glyph electrumx ws);
    # use the electrumx-ws adapter only when a --rxd-indexer-ws is explicitly given.
    indexer = None
    if args.asset_variant in ("nft", "ft"):
        chain_io = RadiantChainIO(rxd_client)
        if args.rxd_indexer_ws:
            ex = ElectrumXClient(urls=[args.rxd_indexer_ws], allow_insecure=args.rxd_indexer_insecure)
            indexer = RxinDexerRefAdapter(RxinDexerClient(ex), chain_io)
            print(f"  REF gate: electrumx-ws RxinDexerRefAdapter @ {args.rxd_indexer_ws}")
        else:
            indexer = SshTrHttpRefAdapter(chain_io=chain_io, ssh_host=args.rxd_ssh_host, api_base=args.rxd_api_base)
            print(f"  REF gate: REST SshTrHttpRefAdapter via ssh {args.rxd_ssh_host} -> {args.rxd_api_base}")
    # accept_estimated_eth_margins: this is an operator-gated DUST run that consciously
    # accepts estimated-margin risk (is_measured=False) on negligible value (MEDIUM-1). A
    # real (non-dust) value-bearing ETH swap MUST use MarginPolicy.measured(...) instead.
    cfg = CoordinatorConfig(margin_policy=policy, accept_nondurable_seen=True, accept_estimated_eth_margins=True)
    coord = SwapCoordinator(
        record=SwapRecord(state=SwapState.NEGOTIATED, terms=terms),
        counter_leg=eth_leg,
        radiant_leg=rxd_leg,
        indexer=indexer,
        seen_store=InMemSeen(),
        config=cfg,
    )

    # Before funding the counter-leg, wait for the NFT genesis to reach the REF-gate reorg depth
    # (the pre-lock gate fails CLOSED on a shallow genesis). No-op for plain RXD (no genesis ref).
    if minted is not None:
        wait_genesis_mature(
            rxd_client, minted.genesis_txid, need_confs=cfg.min_ref_confirmations, poll_s=args.confirm_poll_s
        )

    try:
        # 1. Taker deploys + funds the ETH HTLC on Sepolia.
        confirm("taker_funds_btc: deploy+fund the ETH HTLC on SEPOLIA (taker pays sepolia gas)", auto_yes=args.yes)
        rec = await coord.taker_funds_btc(terms, now_unix_s=int(time.time()))
        report.step(
            name="taker_funds_eth",
            chain="eth",
            state=rec.state.value,
            contract=rec.counterchain_locator.contract_address,
        )
        print(f"  -> {rec.state.value} (ETH HTLC: {rec.counterchain_locator.contract_address})")

        # 1b. MAKER verifies the taker-deployed ETH HTLC binds to terms BEFORE locking RXD
        #     (red-team CRITICAL/HIGH). In a real TWO-PARTY flow this is the maker's go/no-go gate —
        #     it fails closed if the taker deployed claimant=self / underfunded / bad timeout, so the
        #     maker never locks RXD for nothing. (Here, single-operator, taker_funds_btc already set
        #     the locator and post_asset_lock_revalidate re-verifies pinned to finality as a backstop;
        #     we still run it explicitly to exercise the gate and document the two-party step.)
        confirm("maker_verify_counter_funding: verify the on-chain ETH HTLC pays the maker", auto_yes=args.yes)
        rec = await coord.maker_verify_counter_funding(rec.counterchain_locator.contract_address)
        report.step(name="maker_verify_counter_funding", chain="eth", state=rec.state.value)
        print("  -> verified (claimant=maker, refundee=taker, H, timeout, funded)")

        # 2. Maker locks the ASSET on MAINNET, then the taker re-validates (incl. the genesis-ref
        #    authenticity gate for an NFT). NFT: spend the minted singleton INTO the covenant SPK
        #    (harness-driven, confirm-each). RXD: the operator funds the SPK out-of-band.
        rxd_locked_at = rxd_blockcount(rxd_client)
        if args.asset_variant == "nft":
            lock_singleton_into_covenant(
                rxd_client,
                minted=minted,
                covenant_spk=cov.funded_spk,
                carrier_photons=args.nft_carrier_photons,
                fee_photons=args.rxd_mint_fee_photons,
                confirm_fn=lambda m: confirm(m, auto_yes=args.yes),
                poll_s=args.confirm_poll_s,
            )
        elif args.asset_variant == "ft":
            lock_ft_into_covenant(
                rxd_client,
                minted=minted,
                covenant_spk=cov.funded_spk,
                fee_photons=args.rxd_mint_fee_photons,
                confirm_fn=lambda m: confirm(m, auto_yes=args.yes),
                poll_s=args.confirm_poll_s,
            )
        else:
            print(f"\n  Fund the RXD covenant SPK on MAINNET as the maker (>= 1 conf):\n    {cov.funded_spk.hex()}")
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
            raise SystemExit(f"covenant/timing mismatch -> {rec.state.value}; refund the ETH HTLC after the timeout")

        print(
            "\n  *** MONITORING WINDOW (BOTH_LOCKED): a maker stall (maker never claims the ETH, so p "
            "is never revealed) is the real loss path. Recovery in THIS runbook is coord.mutual_refund() "
            "AFTER BOTH timeouts elapse (t_eth -> taker's ETH HTLC; t_rxd/CSV -> maker's RXD covenant); "
            "it refunds BOTH legs, so neither side takes one-sided loss. Do NOT use "
            "maybe_refund_asset_on_maker_stall here OR on the BTC<->RXD runbook — the MAKER owns the RXD "
            "covenant in BOTH (CLAIM->taker, CSV-refund->maker), so as a TAKER it strands you (FSM finding #2). "
            "Do NOT walk away before both refunds confirm. ***"
        )

        # 3. Maker claims the ETH, revealing p on Ethereum.
        confirm("maker_claims_btc: broadcast the ETH claim on SEPOLIA (reveals p)", auto_yes=args.yes)
        rec = await coord.maker_claims_btc(p_secret)
        claim_tx = eth_leg.last_claim_tx
        if not claim_tx:
            raise SystemExit("did not capture the ETH claim tx hash; cannot proceed to the taker claim")
        report.step(name="maker_claims_eth", chain="eth", state=rec.state.value, claim_tx=claim_tx)
        print(f"  -> {rec.state.value} (ETH claim tx {claim_tx})")

        # 4. Taker waits for the ETH claim to FINALIZE (real post-Merge finality), runs the reorg
        #    gate, and claims the RXD covenant. Past maker_claims, p is public on-chain.
        deadline = time.monotonic() + args.resume_deadline_s
        print(f"\n  Waiting for the ETH claim to FINALIZE + the reorg gate; deadline {args.resume_deadline_s:.0f}s.")
        while True:
            if time.monotonic() >= deadline:
                raise SystemExit(
                    f"deadline ({args.resume_deadline_s:.0f}s) exceeded — operator must intervene "
                    f"(p is public; covenant claim pending). ETH claim {claim_tx}"
                )
            now_rxd = rxd_blockcount(rxd_client)
            rec = await coord.taker_scrape_and_claim_asset(
                claim_tx, now_rxd_height=now_rxd, asset_locked_at_height=rxd_locked_at
            )
            if rec.state is SwapState.COMPLETED:
                report.step(
                    name="taker_scrape_and_claim_asset",
                    chain="rxd",
                    state=rec.state.value,
                    covenant_outpoint=rec.radiant_covenant_outpoint,
                    eth_claim_tx=claim_tx,
                )
                print(f"  -> {rec.state.value} — CROSS-CHAIN SWAP COMPLETE")
                break
            if rec.state is SwapState.SECRET_REVEALED:
                print("  reorg gate: WAIT (ETH claim not yet FINAL); retrying...")
                report.step(name="reorg_gate_wait", chain="eth", state=rec.state.value)
                await asyncio.sleep(args.poll_interval_s)
                continue
            if rec.state is SwapState.ASSET_VULNERABLE:
                print("  reorg gate SQUEEZED -> ASSET_VULNERABLE; p is public and the t_rxd window is closing.")
                report.step(name="reorg_gate_squeezed", chain="rxd", state=rec.state.value)
                confirm(
                    "taker_claim_asset_from_vulnerable: best-effort winner-take-all (accepts residual reorg risk)",
                    auto_yes=args.yes,
                )
                rec = await coord.taker_claim_asset_from_vulnerable(claim_tx)
                report.step(name="taker_claim_asset_from_vulnerable", chain="rxd", state=rec.state.value)
                print(f"  -> {rec.state.value} (winner-take-all attempted; residual reorg risk accepted)")
                break
            raise SystemExit(f"unexpected state {rec.state.value} from the reorg-gated claim — operator must intervene")
    finally:
        report.dump(args.report_out)
        print(f"  report -> {args.report_out}")
        await rpc.close()


def _args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="ETH↔RXD dust swap runner (Sepolia↔RXD-mainnet)")
    ap.add_argument("--stage", choices=["dry-run", "sepolia-dust"], required=True)
    ap.add_argument("--i-accept-dust-loss", action="store_true")
    ap.add_argument("--yes", action="store_true", help="auto-confirm broadcasts (dry-run / unattended only)")
    # ETH
    ap.add_argument("--eth-rpc-url", default="")
    ap.add_argument("--eth-key-hex", default="")
    ap.add_argument("--eth-chain-id", type=int, default=_SEPOLIA_CHAIN_ID)
    ap.add_argument("--eth-amount-wei", type=int, default=10**14)  # 0.0001 ETH dust
    ap.add_argument("--eth-claim-to", default="")
    ap.add_argument("--eth-refund-to", default="")
    ap.add_argument("--eth-artifact", default=str(_DEFAULT_ARTIFACT))
    ap.add_argument("--eth-timeout-s", type=int, default=86_400)  # 1 day ETH refund deadline
    # RXD
    ap.add_argument("--rxd-photons", type=int, default=1000)
    ap.add_argument("--rxd-fee-photons", type=int, default=5_000_000)
    ap.add_argument("--rxd-wallet", default="")
    ap.add_argument("--t-rxd-blocks", type=int, default=60)
    # asset: plain RXD (default) or a freshly-minted NFT Glyph (Glyph↔ETH).
    ap.add_argument("--asset-variant", choices=("rxd", "nft", "ft"), default="rxd")
    ap.add_argument("--ft-name", default="ETH-RXD-REAL-FT")
    ap.add_argument("--ft-ticker", default="ERFT")
    ap.add_argument(
        "--ft-premine-photons", type=int, default=10_000_000
    )  # FT supply = covenant-locked amount (1 photon = 1 unit)
    ap.add_argument(
        "--ft-reuse-reveal-txid", default="", help="reuse an already-minted FT at this reveal txid (skip minting)"
    )
    ap.add_argument(
        "--ft-owner-wif", default="", help="owner WIF for --ft-reuse-reveal-txid (spends the FT into the covenant)"
    )
    ap.add_argument(
        "--rxd-indexer-ws",
        default="",
        help="OPTIONAL glyph-enabled ElectrumX ws/wss URL for the NFT REF gate; if omitted, resolve via the REST api over ssh-tr",
    )
    ap.add_argument("--rxd-indexer-insecure", action="store_true", help="allow a non-TLS RXinDexer ws")
    ap.add_argument("--rxd-ssh-host", default="tr", help="ssh host for the RXinDexer REST REF gate (default tr)")
    ap.add_argument("--rxd-api-base", default="http://127.0.0.1:8000", help="RXinDexer REST api base on the ssh host")
    ap.add_argument(
        "--nft-reuse-reveal-txid", default="", help="reuse an already-minted NFT at this reveal txid (skip minting)"
    )
    ap.add_argument(
        "--nft-owner-wif",
        default="",
        help="owner WIF for --nft-reuse-reveal-txid (spends the singleton into the covenant)",
    )
    ap.add_argument("--nft-name", default="ETH-RXD-REAL-NFT")
    ap.add_argument("--nft-carrier-photons", type=int, default=1_000_000)  # carrier the covenant pins
    ap.add_argument("--nft-commit-photons", type=int, default=20_000_000)  # mint commit funding
    ap.add_argument("--rxd-mint-fee-photons", type=int, default=5_000_000)  # per mint/lock tx (mainnet 0.10 RXD/kB)
    ap.add_argument("--confirm-poll-s", type=float, default=30.0, help="mainnet confirmation poll interval")
    # margin / cross-clock
    ap.add_argument("--margin-blocks", type=int, default=36)
    ap.add_argument("--btc-block-interval-s", type=float, default=600.0)
    ap.add_argument("--rxd-block-interval-s", type=float, default=300.0)
    # Default (None) → resolved from the EVM chain registry by --eth-chain-id in _args() below, so a
    # known chain gets its VETTED finalization window (e.g. Base 900s, not Ethereum's 768s); an
    # operator value always overrides. Realizes the registry's fail-closed per-chain safety.
    ap.add_argument("--eth-finalization-window-s", type=int, default=None)
    ap.add_argument("--rxd-claim-burial-s", type=int, default=1800)
    ap.add_argument("--rxd-confirm-slack-s", type=int, default=600)
    ap.add_argument("--rounding-slack-s", type=int, default=300)
    ap.add_argument("--max-covenant-confirm-wait-s", type=int, default=600)
    # ops
    ap.add_argument("--poll-interval-s", type=float, default=30.0)
    ap.add_argument("--resume-deadline-s", type=float, default=3600.0)
    ap.add_argument("--report-out", default="/tmp/eth_swap_report.json")  # noqa: S108 — operator-overridable
    ap.add_argument("--keys-out", default="~/.eth_swap_run_keys.json")
    args = ap.parse_args()
    # Wire the EVM chain registry (audit follow-up): when the operator does not pin the finalization
    # window, take the vetted per-chain value for --eth-chain-id (Base 900s, Ethereum/Sepolia 768s);
    # an unvetted chain (e.g. the 31337 dry-run anvil) fail-SOFTs to the consensus 2-epoch floor.
    if args.eth_finalization_window_s is None:
        from pyrxd.eth_wallet.chains import evm_chain_by_id
        from pyrxd.gravity.swap_coordinator import _MIN_ETH_FINALIZATION_WINDOW_S
        from pyrxd.security.errors import ValidationError

        try:
            args.eth_finalization_window_s = evm_chain_by_id(args.eth_chain_id).finalization_window_s
        except ValidationError:
            args.eth_finalization_window_s = _MIN_ETH_FINALIZATION_WINDOW_S
    return args


def main() -> None:
    args = _args()
    if args.stage == "dry-run":
        asyncio.run(run_dry(args))
    else:
        asyncio.run(run_sepolia_dust(args))


if __name__ == "__main__":
    main()
