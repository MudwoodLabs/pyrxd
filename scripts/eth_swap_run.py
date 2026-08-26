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
import math
import os
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

# scripts/ siblings (same import style as dust_swap_run.py / dust_swap_resume.py)
from pyrxd.gravity.seen_store import DurableSeenStore

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _dust_swap_shared import (
    SshTrFeeSource,
    StepReport,
    atomic_write_mode_600,
    confirm,
    merge_into_mode_600,
    rxd_blockcount,
    wait_for_covenant_funding,
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
from pyrxd.eth_wallet.chains import evm_chain_by_id
from pyrxd.eth_wallet.erc20_leg import Erc20HtlcLeg
from pyrxd.eth_wallet.htlc_leg import EthHtlcContractLeg, load_artifact
from pyrxd.eth_wallet.multi_rpc import MultiSourceEthRpc
from pyrxd.eth_wallet.rpc import EthRpc
from pyrxd.eth_wallet.tokens import KNOWN_TOKENS, token_for
from pyrxd.glyph.types import GlyphRef
from pyrxd.gravity.eth_leg import EthLeg
from pyrxd.gravity.eth_rxd_timelock import CrossClockMargin
from pyrxd.gravity.htlc_covenant import build_htlc_covenant_ft, build_htlc_covenant_nft, build_htlc_covenant_rxd
from pyrxd.gravity.radiant_leg import RadiantChainIO, RadiantCovenantLeg, RxinDexerRefAdapter
from pyrxd.gravity.record_sink import FileFundLock, JsonFileRecordSink
from pyrxd.gravity.swap_coordinator import CoordinatorConfig, MarginPolicy, SwapCoordinator
from pyrxd.gravity.swap_state import NegotiatedTerms, SwapRecord, SwapState
from pyrxd.keys import PrivateKey
from pyrxd.network.electrumx import ElectrumXClient
from pyrxd.network.rxindexer import RxinDexerClient
from pyrxd.security.secrets import PrivateKeyMaterial, SecretBytes
from pyrxd.security.types import Hex20

_DEFAULT_ARTIFACT = Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "EthHtlc.json"
_DEFAULT_ERC20_ARTIFACT = Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "Erc20Htlc.json"
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
    """The cross-clock margin, including the ETH finality STALL budget.

    `eth_finality_stall_tolerance_s` defaulted to 0 and the runner had no flag for it at all, so
    a measured policy refused at setup: real-value mode requires >= 3600s, because the taker waits
    for ETH FINALITY before claiming RXD and the RXD refund must not open until it has had a
    stall-tolerant window. The May-2023 mainnet stall ran about an hour. Sizing this against
    happy-path finality is precisely the bug a stall triggers, which is why it is an explicit
    operator number rather than something derived from the finalization window.
    """
    return CrossClockMargin(
        eth_reorg_finality_s=args.eth_finalization_window_s,
        rxd_claim_burial_s=args.rxd_claim_burial_s,
        rxd_confirm_slack_s=args.rxd_confirm_slack_s,
        rounding_slack_s=args.rounding_slack_s,
        eth_finality_stall_tolerance_s=args.eth_finality_stall_tolerance_s,
    )


def _evm_is_value_bearing(chain_id: int) -> bool:
    """Whether the EVM leg's coins are real — read from the chain registry, never from the stage
    name and never from the audit tag.

    A first version asked whether the `network` tag was outside `AUDIT_CLEARED_NETWORKS`, matching
    the coordinator's `_leg_is_value_bearing`. That is the right rule for the AUDIT gate and the
    wrong one here: the cleared set holds Bitcoin-family tags, so every EVM chain reads as
    value-bearing — Base Sepolia included. It forced measured margins and a two-endpoint quorum
    onto a faucet-money rehearsal, which is a guard refusing honest work. The runner's own wiring
    tests caught it.

    `is_testnet` states it per registry entry instead. The two questions genuinely differ: nothing
    here is audit-cleared, and only some of it is worth anything.
    """
    return not evm_chain_by_id(int(chain_id)).is_testnet


def _policy(args: argparse.Namespace) -> MarginPolicy:
    """Estimated margins for a throwaway EVM chain; MEASURED once the token leg is real.

    is_measured=False disables two defences on the ETH path — the verify->lock `finalized` reorg
    pin (it re-verifies at `latest` instead, which cannot catch a reorg re-deploying a different
    contract at the same CREATE address in that window) and the proactive-refund N-floor. On a
    Sepolia counter leg that is an accepted dust trade, because the ETH side is faucet money and
    only the RXD side can be lost. With USDT on L1 BOTH legs are real, so the same opt-in would be
    buying the weak mode of two defences with actual value behind them.
    """
    common: dict = dict(
        margin=bt.Timelock(args.margin_blocks, bt.TimeUnit.BLOCKS),
        block_interval_s=args.btc_block_interval_s,
        rxd_block_interval_s=args.rxd_block_interval_s,
        eth_finalization_window_s=args.eth_finalization_window_s,
        cross_clock_margin=_cross_clock_margin(args),
        max_covenant_confirm_wait_s=args.max_covenant_confirm_wait_s,
        # Dust harness: value below the Radiant reorg cost → opt out of value-scaled burial.
        accept_flat_burial=True,
    )
    if not _token_leg_is_real(args):
        return MarginPolicy(is_measured=False, **common)
    if args.eth_finality_stall_tolerance_s < 3600:
        raise SystemExit(
            "a real-value token counter leg needs --eth-finality-stall-tolerance-s >= 3600. The "
            "taker waits for ETH finality before claiming RXD, so the RXD refund must not open "
            "until it has had a stall-tolerant window; the May-2023 mainnet stall ran about an "
            "hour. Sizing this against happy-path finality is the bug a stall triggers."
        )
    _assert_t_rxd_covers_the_takers_wait(args)
    _assert_t_rxd_opens_before_the_eth_deadline(args)
    if not args.rxd_block_interval_fast_s:
        raise SystemExit(
            "a real-value token counter leg needs --rxd-block-interval-fast-s (the MEASURED p10 "
            "Radiant inter-block, seconds). Reserves DIVIDE by it, so a stale-high value silently "
            "under-counts blocks. Measure it against a mainnet node for THIS run — it was 43s on "
            "2026-06-02 and 36s on 2026-08-26, and the drift is in the under-counting direction."
        )
    return MarginPolicy(
        is_measured=True,
        require_measured=True,
        rxd_block_interval_fast_s=float(args.rxd_block_interval_fast_s),
        **common,
    )


def _assert_t_rxd_covers_the_takers_wait(args: argparse.Namespace) -> None:
    """The RXD refund must not open before the taker has finished waiting for ETH finality.

    `--t-rxd-blocks` is an operator flag on this runner, not a derived value, and NOTHING on this
    path checks it against the ETH deadline. The one gate that runs — `assert_covenant_confirms_
    before_eth_deadline` — is a PUNCTUALITY check (does the covenant confirm when the sizing
    assumed), and its own docstring says it is "not a slow-chain defence"; the interval cancels out
    of its arithmetic entirely.

    So the unsafe direction is unguarded, and the default is on the wrong side of it. t_rxd is a
    RELATIVE CSV in blocks: measure it at the FAST tail, because fast Radiant blocks are what
    SHRINK the taker's window. At the measured p10 of 36s the default 60 blocks matures in 36
    minutes, while the cross-clock margin the taker must sit through — ETH finality, the stall
    budget, claim burial, slack — is about two hours. The maker could refund the asset while the
    taker was still, correctly, waiting.

    A slow chain is the harmless direction: it only lengthens the maker's lock, which is a liveness
    cost and gives the taker MORE time. `eth_rxd_timelock` states that split explicitly.

    Only enforced for a real token leg. Sepolia keeps its existing defaults exactly.
    """
    fast = float(args.rxd_block_interval_fast_s or 0)
    if fast <= 0:
        return  # the missing-measurement refusal below is the better error
    margin_s = _cross_clock_margin(args).total_s()
    need = math.ceil(margin_s / fast)
    have = int(args.t_rxd_blocks)
    if have >= need:
        return
    raise SystemExit(
        f"--t-rxd-blocks {have} is too SHORT for a real-value run. At the measured fast tail of "
        f"{fast:.0f}s/block it matures in {have * fast / 3600:.2f} h, but the taker must first sit "
        f"through {margin_s}s ({margin_s / 3600:.2f} h) of cross-clock margin — ETH finality, the "
        f"stall budget, claim burial and slack. The maker could refund the asset while the taker "
        f"was still waiting.\n"
        f"  minimum: --t-rxd-blocks {need}\n"
        f"  Size it at the FAST tail, not the median: fast blocks are what shrink the taker's "
        f"window. A slow chain only lengthens the maker's lock, which costs liveness, not safety."
    )


def _assert_t_rxd_opens_before_the_eth_deadline(args: argparse.Namespace) -> None:
    """The RXD refund must OPEN before the ETH deadline minus the margin — the upper bound.

    Learned the expensive way. The lower bound above divides the margin by the FAST tail, because
    fast blocks shrink the taker's window. The coordinator's punctuality gate then projects the
    same t_rxd forward by MULTIPLYING by the NOMINAL interval. Those two only cancel when both use
    the same interval — `assert_covenant_confirms_before_eth_deadline` says so in as many words —
    and sizing with 36s while the gate multiplies by 300s inflates the projection by ~8x.

    A t_rxd of 2203, correct against the lower bound, projected the RXD refund 7.6 DAYS out against
    a 22h budget. The gate caught it and refused to lock, which is the system working — but it
    caught it AFTER the covenant had been funded, because nothing checked it at argument-parse
    time. This does, so the operator learns the valid RANGE before spending a fee.
    """
    nominal = float(args.rxd_block_interval_s)
    # RESERVE the covenant-confirm window. The gate anchors the projection on the covenant's
    # CONFIRMATION time, not on the runner's start, so however long funding-and-mining takes comes
    # straight out of the budget. Sizing against `now` silently assumes instant funding: a run that
    # took ~740s to fund and mine overshot by 607s and was refused AFTER the covenant was paid for.
    # `max_covenant_confirm_wait_s` is precisely the allowance for that delay, so spend it here.
    budget_s = int(args.eth_timeout_s) - _cross_clock_margin(args).total_s() - int(args.max_covenant_confirm_wait_s)
    hi = math.floor(budget_s / nominal)
    have = int(args.t_rxd_blocks)
    if have <= hi:
        return
    fast = float(args.rxd_block_interval_fast_s or 0)
    lo = math.ceil(_cross_clock_margin(args).total_s() / fast) if fast > 0 else 1
    raise SystemExit(
        f"--t-rxd-blocks {have} is too LONG. The coordinator projects the RXD refund forward at the "
        f"NOMINAL {nominal:.0f}s interval, giving {have * nominal / 86400:.1f} days against a "
        f"{budget_s / 3600:.1f} h budget (--eth-timeout-s minus the {_cross_clock_margin(args).total_s()}s "
        f"cross-clock margin AND the {args.max_covenant_confirm_wait_s}s covenant-confirm reserve). "
        f"The maker could not refund before the ETH deadline.\n"
        f"  valid range: --t-rxd-blocks {lo}..{hi}   (use {hi} — the largest gives the taker the most window)\n"
        f"  the LOWER bound divides the margin by the FAST tail; this UPPER bound multiplies by the "
        f"NOMINAL one. Both are real, and they are not the same number."
    )


def _token_leg_is_real(args: argparse.Namespace) -> bool:
    """A token counter leg on a value-bearing chain — the case where both legs carry value.

    Native ETH on Sepolia is deliberately NOT this: the chain is value-bearing by tag, but the
    asset is faucet money, which is the whole premise of the sepolia-dust stage.
    """
    return args.counter_asset != "native" and _evm_is_value_bearing(args.eth_chain_id)


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


def _build_terms_and_covenant(args, *, eth_timeout: int, minted=None, restore: dict | None = None):
    """Build the HTLC covenant + negotiated terms. ``minted`` (a MintedNft) is REQUIRED for the
    NFT variant — the covenant binds the genesis ref ``reveal_txid:0`` of the freshly-minted NFT``.

    ``restore`` is the recovery file, and it makes ``--resume`` mean what it says. Without it,
    resume MINTED A FRESH SWAP: a new preimage, new RXD keys and a new eth_timeout, which builds a
    DIFFERENT covenant with a different hashlock and silently abandons the funded one. That was
    only ever caught because the O_EXCL write of the recovery file failed afterwards — the
    protection was accidental, and on a different --keys-out it would not have fired at all.
    Nothing drives this script in tests, which is the same reason three runners sat broken from
    HZ-1 until a real run found them.
    """
    if restore is not None:
        p_secret = SecretBytes(bytes.fromhex(restore["preimage_p_hex"]))
        h = hashlib.sha256(p_secret.unsafe_raw_bytes()).digest()
        if h.hex() != restore["hashlock_H"]:
            raise SystemExit("recovery file is inconsistent: sha256(p) != recorded hashlock_H")
        taker_rxd, maker_rxd = PrivateKey(restore["taker_rxd_wif"]), PrivateKey(restore["maker_rxd_wif"])
    else:
        p_secret = SecretBytes(os.urandom(32))
        h = hashlib.sha256(p_secret.unsafe_raw_bytes()).digest()
        taker_rxd, maker_rxd = PrivateKey(os.urandom(32)), PrivateKey(os.urandom(32))
    t_rxd = bt.Timelock(args.t_rxd_blocks, bt.TimeUnit.BLOCKS)
    t_btc = bt.Timelock(args.t_rxd_blocks + args.margin_blocks + 4, bt.TimeUnit.BLOCKS)  # decorative for ETH
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
        value_amount=_counter_value(args),
        token_address=(_counter_token(args).address if _counter_token(args) else ""),
        eth_timeout_unix_s=eth_timeout,
    )
    return terms, cov, p_secret, h, (taker_rxd, maker_rxd, taker_pkh, maker_pkh)


def _counter_token(args):
    """The ERC-20 this run swaps against, or None for a native-ETH counter leg.

    Resolved from the PINNED registry by (symbol, chain id) rather than from an address on the
    command line. A mistyped address that happens to be a live contract is a token nobody priced,
    and `USDC` on the wrong chain id is a different contract entirely — the registry makes both
    unrepresentable instead of merely unlikely.
    """
    if args.counter_asset == "native":
        return None
    return token_for(args.counter_asset.upper(), int(args.eth_chain_id))


def _counter_value(args):
    """The counter-leg amount, in whatever units that leg denominates.

    Native: wei. ERC-20: the token's BASE UNITS (USDC is 6-decimal, so 1_000_000 == 1.00 USDC).
    The record is chain-tagged precisely so a later reader cannot mistake the second for the first.
    """
    return int(args.eth_amount_wei) if args.counter_asset == "native" else int(args.token_amount)


def _eth_rpc(args, *, rpc_url: str, chain_id: int):
    """One endpoint, or a QUORUM of them once the token leg carries real value.

    `--eth-rpc-url` takes a comma-separated list. One URL keeps today's behaviour exactly; two or
    more build a `MultiSourceEthRpc`, so the reads a swap cannot take back — is the counter leg
    funded, is this address frozen, is the claim final — stop resting on one endpoint's word.

    A real token leg REQUIRES at least two, and that is a deliberate constraint on the operator
    rather than a default. The single-source read defends a failing provider, not a lying one, and
    the lagging case is the common one: a load-balanced provider serving a stale node is already
    recorded in this codebase as having refused a claim and nearly killed a secret.

    Independence is the operator's job and this code cannot check it. Three URLs at one provider
    share one operator and one outage, and would satisfy the count while providing nothing.
    """
    urls = [u.strip() for u in str(rpc_url).split(",") if u.strip()]
    if not urls:
        raise SystemExit("--eth-rpc-url is required")
    if len(urls) == 1:
        if _token_leg_is_real(args):
            raise SystemExit(
                "a real-value token counter leg requires at least TWO independent --eth-rpc-url "
                "endpoints (comma-separated), so no irreversible step rests on one endpoint's "
                "word. Working L1 endpoints measured 2026-08-26: ethereum-rpc.publicnode.com. "
                "Use providers with DIFFERENT operators — several URLs from one provider share a "
                "single failure and satisfy nothing."
            )
        return EthRpc(urls[0], expected_chain_id=chain_id)
    return MultiSourceEthRpc([EthRpc(u, expected_chain_id=chain_id) for u in urls])


def _eth_leg(args, *, rpc_url, chain_id, key_hex, claim_to, refund_to, eth_timeout, network):
    rpc = _eth_rpc(args, rpc_url=rpc_url, chain_id=chain_id)
    token = _counter_token(args)
    artifact = load_artifact(args.eth_artifact if token is None else args.erc20_artifact)
    key = PrivateKeyMaterial(bytes.fromhex(key_hex))
    if token is None:
        contract_leg = EthHtlcContractLeg(rpc=rpc, signing_key=key, chain_id=chain_id, artifact=artifact)
    else:
        # The ERC-20 fund is TWO transactions (deploy, then a plain transfer — no approve, so no
        # allowance race). That is why the coordinator refuses to run one without a durable record.
        contract_leg = Erc20HtlcLeg(token=token, rpc=rpc, signing_key=key, chain_id=chain_id, artifact=artifact)
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
    if args.counter_asset != "native":
        # A plain anvil has no token contracts, and this stage runs one at chain 31337 rather than
        # a fork of the chain the token is pinned on. Deploying a MOCK token to close that gap
        # would test a fiction: the properties most likely to be wrong on this path are runtime
        # behaviours of the real bytecode — Tether's `transfer` returns no bool, its freeze
        # predicate is spelled `isBlackListed`, and USDC is 6-decimal — and a mock reproduces
        # exactly the ones someone remembered to write down.
        #
        # Without this the failure is a confusing "no pinned USDT on chain id 11155111", which
        # blames the registry for a stage limitation.
        raise SystemExit(
            f"stage=dry-run is native-ETH only; --counter-asset {args.counter_asset} needs a chain "
            "that actually has the token on it. The token-path rehearsal is the fork lifecycle "
            "suite, which drives the production SwapCoordinator against the REAL token contract:\n"
            "  XCHAIN_ERC20_E2E=1 PYRXD_ETH_FORK_RPC=https://ethereum-rpc.publicnode.com \\\n"
            "      .venv/bin/pytest tests/test_xchain_erc20_usdc_lifecycle_e2e.py -m integration\n"
            "It covers USDC and USDT on a mainnet fork, including the freeze gates."
        )
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
    if args.resume:
        # A resume REQUIRES the recovery file a fresh run refuses to overwrite: it holds the keys
        # the interrupted run minted, and the swap record sits beside it.
        if not Path(args.keys_out).expanduser().exists():
            raise SystemExit(
                f"--resume needs the recovery file from the interrupted run, and "
                f"{Path(args.keys_out).expanduser()} does not exist. Without it the keys are gone "
                "and the deployed contract can only be refunded by hand after its timeout."
            )
    elif Path(args.keys_out).expanduser().exists():
        raise SystemExit(
            f"recovery file already exists: {Path(args.keys_out).expanduser()} — move/delete it or pass a "
            f"fresh --keys-out before a new run (refusing to mint over a stale recovery file)"
        )
    # Pin the RXD network to the transport's true network (mainnet) — fail-closed like dust_swap_run.
    rxd_network = SshTrRadiantClient.NETWORK
    _eth_chain = evm_chain_by_id(int(args.eth_chain_id))
    _asset = "ETH" if args.counter_asset == "native" else args.counter_asset.upper()
    print(
        f"=== {_asset}↔RXD DUST swap — stage=sepolia-dust  "
        f"(counter={_eth_chain.name} chain_id={_eth_chain.chain_id}, RXD={rxd_network} mainnet) ==="
    )

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
    restore = None
    if args.resume:
        restore = json.loads(Path(args.keys_out).expanduser().read_text())
        # The eth_timeout is part of the SWAP'S IDENTITY — it is an immutable of the deployed HTLC
        # and it anchors every margin. Recomputing it on resume would silently re-time the swap.
        eth_timeout = int(restore["eth_timeout_unix_s"])
    else:
        eth_timeout = int(time.time()) + args.eth_timeout_s
    terms, cov, p_secret, h, _rkeys = _build_terms_and_covenant(
        args, eth_timeout=eth_timeout, minted=minted, restore=restore
    )
    if restore is not None:
        # THE load-bearing check. If any restored input is wrong the rebuilt covenant will not be
        # the one that holds the money, and continuing would fund a second swap while the first
        # stays stranded. Compare the actual script, not the inputs that produced it.
        if cov.funded_spk.hex() != restore["rxd_covenant_spk"]:
            raise SystemExit(
                "resume rebuilt a DIFFERENT covenant than the funded one — refusing.\n"
                f"  funded : {restore['rxd_covenant_spk']}\n"
                f"  rebuilt: {cov.funded_spk.hex()}\n"
                "  the run's parameters (t-rxd-blocks, asset, amounts) must match the original."
            )
        print(f"  RESUMED: rebuilt covenant matches the funded SPK, eth_timeout pinned at {eth_timeout}")

    # Persist ALL run state (mode 600) BEFORE any broadcast — recovery/sweep. Holds the preimage p
    # + the ETH signing key + the RXD keys + the covenant SPK; single point of total compromise.
    keys_path = Path(args.keys_out).expanduser()
    if restore is None:
        atomic_write_mode_600(
            keys_path,
            json.dumps(
                {
                    "created_unix": int(time.time()),
                    "stage": "sepolia-dust",
                    # The CHAIN and the AMOUNT, recorded as they actually are rather than as the stage
                    # name assumes. Both were wrong for a token run on L1: "sepolia" was hardcoded, and
                    # the amount logged `--eth-amount-wei` (the NATIVE flag, untouched at its 0.0001 ETH
                    # default) instead of the token base units actually locked. The run itself was
                    # unaffected — the coordinator takes `_counter_value(args)` — but this file is the
                    # RECOVERY path, and a hand-recovery driven from it would have had the wrong chain,
                    # an amount off by ~10^8, and no idea which token the HTLC even holds.
                    "eth_chain": evm_chain_by_id(int(args.eth_chain_id)).name,
                    "eth_chain_id": int(args.eth_chain_id),
                    "counter_asset": args.counter_asset,
                    "token_address": (None if _counter_token(args) is None else _counter_token(args).address),
                    "token_decimals": (None if _counter_token(args) is None else _counter_token(args).decimals),
                    "rxd_network": rxd_network,
                    "hashlock_H": h.hex(),
                    "preimage_p_hex": p_secret.unsafe_raw_bytes().hex(),  # recovery only; same trust domain as keys
                    "eth_key_hex": args.eth_key_hex,
                    "eth_claim_to": args.eth_claim_to,
                    "eth_refund_to": args.eth_refund_to,
                    "eth_timeout_unix_s": eth_timeout,
                    # Base units for a token leg, wei for native — the same value the coordinator locks.
                    "counter_amount": _counter_value(args),
                    "eth_amount_wei": args.eth_amount_wei,  # the native flag, kept for older readers
                    "taker_rxd_wif": _rkeys[0].wif(),
                    "maker_rxd_wif": _rkeys[1].wif(),
                    "rxd_covenant_spk": cov.funded_spk.hex(),
                    "t_rxd_blocks": terms.t_rxd.value,
                    # The covenant's `amount`/`nftCarrierValue` PARAMETER — the covenant SPK is
                    # built from it, so the cold builders (`pyrxd swap build-claim`/`build-refund`)
                    # need it to rebuild the covenant they spend. Nothing used to persist it.
                    "rxd_covenant_amount": terms.radiant_amount,
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
        # Derived from the chain id, never hardcoded. This string is what the coordinator reads to
        # decide whether the leg is value-bearing, and the stage is named for Sepolia while the
        # chain is a parameter — so a Base Sepolia run used to announce itself as Sepolia. Two
        # names for one chain is how a per-chain constant gets applied to the wrong chain.
        network=evm_chain_by_id(int(args.eth_chain_id)).network,
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
    # accept_estimated_eth_margins stays (a separate ETH-margin dust opt-in, MEDIUM-1);
    # accept_nondurable_seen is dropped — the seen-store below is durable-by-default.
    cfg = CoordinatorConfig(
        maker_stall_safety_window_blocks=args.maker_stall_safety_window_blocks,
        margin_policy=policy,
        # Only for a throwaway token leg. With a real one the policy above is MEASURED, so this
        # opt-in is not merely unnecessary — passing it would re-disable the two defences the
        # measured policy just switched on, and it would do so silently.
        accept_estimated_eth_margins=not _token_leg_is_real(args),
        # Exclusive across processes: `reserve(H)` was the only mutual exclusion in the funding
        # path, and resuming an interrupted fund skips it.
        fund_lock=FileFundLock(str(Path(args.keys_out).expanduser())),
    )
    # RESUME FROM THE PERSISTED STATE, not from NEGOTIATED. The sink has always had `load_record`
    # and nothing called it: the coordinator was constructed fresh every time, so a resumed run
    # believed the swap had not started while the durable record said otherwise. That is why
    # `resume_interrupted_fund` was the ONLY resumable point — anything past the fund had a record
    # the coordinator never read, and the run could not continue from it.
    _sink = JsonFileRecordSink(str(Path(args.keys_out).expanduser()) + ".swaprec.json")
    _loaded = _sink.load_record() if args.resume else None
    if _loaded is not None:
        print(f"  RESUMED record: state={_loaded.state.value}")
        if _loaded.terms.hashlock != terms.hashlock:
            raise SystemExit(
                "the persisted record is for a DIFFERENT swap (hashlock mismatch) — refusing to "
                "drive it with these terms."
            )
    coord = SwapCoordinator(
        record=_loaded if _loaded is not None else SwapRecord(state=SwapState.NEGOTIATED, terms=terms),
        counter_leg=eth_leg,
        radiant_leg=rxd_leg,
        indexer=indexer,
        # Durable (SQLite) H-freshness store co-located with the mode-600 recovery file,
        # so the SEEN-1 reservation survives a restart / second process (was InMemSeen).
        seen_store=DurableSeenStore(str(Path(args.keys_out).expanduser()) + ".seen.sqlite"),
        # An ETH contract address depends on the deployer's nonce and exists nowhere until the
        # deploy receipt returns, so this hook is the ONLY thing that makes a mid-fund crash
        # recoverable. The coordinator refuses an ETH counter-leg without it.
        persist=_sink,
        config=cfg,
    )

    # Before funding the counter-leg, wait for the NFT genesis to reach the REF-gate reorg depth
    # (the pre-lock gate fails CLOSED on a shallow genesis). No-op for plain RXD (no genesis ref).
    if minted is not None:
        wait_genesis_mature(
            rxd_client, minted.genesis_txid, need_confs=cfg.min_ref_confirmations, poll_s=args.confirm_poll_s
        )

    try:
        # 1. MAKER LOCKS THE RADIANT ASSET FIRST. This ordering is the protocol, not a preference:
        #    the maker is the party that knows p, so a maker who locks SECOND holds a free option —
        #    it can watch the taker fund and walk away having risked nothing. HZ-1 enforces it from
        #    the other side, refusing `taker_funds_btc` until the covenant is verified ON CHAIN.
        #
        #    This runner used to do the reverse: fund the counter leg at step 1 and print "fund the
        #    RXD covenant" at step 2. That order predates HZ-1 (#392) and the gate has refused it
        #    ever since — the runner has been unable to complete a swap, and nothing reported it
        #    because exercising it costs real mainnet value.
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
            await wait_for_covenant_funding(
                rxd_client,
                covenant_spk=cov.funded_spk,
                expected_photons=args.rxd_photons,
                poll_s=args.confirm_poll_s,
            )

        # 2. TAKER funds the counter leg. The pre-lock gate re-reads the covenant off the chain
        #    itself; the wait above only means we do not ask it to check something not there yet.
        confirm(
            f"taker_funds_btc: deploy+fund the {_asset} HTLC on {_eth_chain.name} (taker pays gas)",
            auto_yes=args.yes,
        )
        _swaprec = Path(str(Path(args.keys_out).expanduser()) + ".swaprec.json")
        _already_funded = (
            _loaded is not None
            and _loaded.state != SwapState.NEGOTIATED
            and (getattr(_loaded, "counterchain_locator", None) is not None)
        )
        if _already_funded:
            # The counter leg is already funded and its locator is on the record. Neither fund path
            # applies: the forward one would deploy a SECOND HTLC, and resume_interrupted_fund
            # rightly refuses a record with no pending deploy. Continue from where the swap is.
            rec = _loaded
            print(f"  counter leg already funded ({rec.counterchain_locator.contract_address}) — skipping the fund")
        elif args.resume and not _swaprec.exists():
            # RESUME MEANS "continue from wherever this swap actually is", and that is not always
            # mid-fund. The covenant can be funded while the ETH fund never started — which is
            # exactly what happens when the pre-lock gate refuses a shallow covenant and you come
            # back after it buries. There is no record to resume because nothing was deployed, so
            # the forward path is correct; `resume_interrupted_fund` rightly refuses that state
            # ("resuming into a fresh fund would deploy a second HTLC").
            print("  --resume: covenant funded, ETH fund never started -> taking the FORWARD path")
            rec = await coord.taker_funds_btc(terms, now_unix_s=int(time.time()))
        elif args.resume and _swaprec.exists():
            # THE READ SIDE. Loads the record the interrupted run persisted and completes the fund
            # it describes — reusing the deployed contract and the pinned nonce, so a retry cannot
            # deploy a second HTLC or send a second transfer. Without this entry point the durable
            # record was written and never read, and every guard on the resume path was unreachable.
            rec = await coord.resume_interrupted_fund(
                terms,
                sink=JsonFileRecordSink(str(Path(args.keys_out).expanduser()) + ".swaprec.json"),
                now_unix_s=int(time.time()),
            )
        else:
            rec = await coord.taker_funds_btc(terms, now_unix_s=int(time.time()))
        report.step(
            name="taker_funds_eth",
            chain="eth",
            state=rec.state.value,
            contract=rec.counterchain_locator.contract_address,
        )
        print(f"  -> {rec.state.value} ({_asset} HTLC: {rec.counterchain_locator.contract_address})")
        # PERSIST the per-swap contract address now that it exists. It is the ETH-side
        # provenance anchor (`pyrxd swap recover-preimage --eth-contract`): only artifacts
        # bound to THIS address may be scraped for p. Previously only eth_swap_two_host.py
        # wrote it, so a crash here left the address on the console alone.
        merge_into_mode_600(keys_path, {"eth_contract_address": rec.counterchain_locator.contract_address})

        # 3. Taker re-validates the covenant pinned to finality -> BOTH_LOCKED.
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

        # 4. MAKER verifies the counter leg binds to terms BEFORE revealing p (red-team CRITICAL).
        #    It used to sit before the RXD lock, as the maker's go/no-go on whether to lock at all.
        #    Under maker-locks-first that placement is impossible — the contract does not exist yet —
        #    so the gate moves to the other irreversible moment it protects: publishing the preimage.
        #    Fails closed on claimant=self / underfunded / wrong timeout, before p is public.
        confirm("maker_verify_counter_funding: verify the on-chain HTLC pays the maker", auto_yes=args.yes)
        rec = await coord.maker_verify_counter_funding(rec.counterchain_locator.contract_address)
        report.step(name="maker_verify_counter_funding", chain="eth", state=rec.state.value)
        print("  -> verified (claimant=maker, refundee=taker, H, timeout, funded)")

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
        # Say what is ACTUALLY being broadcast, on the actual chain, for the actual asset. This
        # line read "maker_claims_btc: broadcast the ETH claim on SEPOLIA" during a real Ethereum
        # MAINNET USDT swap — three misnomers in one sentence, at the single most irreversible
        # moment in the protocol. `maker_claims_btc` is a legacy FSM name (the state machine was
        # built for BTC<->RXD and the EVM legs reuse it), but an operator reading "SEPOLIA" while
        # real value moves is being actively misled, not merely confused.
        confirm(
            f"maker claims the {_asset} on {_eth_chain.name} (chain {args.eth_chain_id}) — "
            "THIS PUBLISHES THE PREIMAGE and commits the Radiant side",
            auto_yes=args.yes,
        )
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
    ap.add_argument(
        "--resume",
        action="store_true",
        help=(
            "COMPLETE an interrupted fund instead of starting a fresh one. Loads the persisted "
            "swap record written beside --keys-out and finishes the counter-leg funding it "
            "describes, reusing the deployed contract and the pinned push nonce rather than "
            "deploying a second HTLC. Requires the existing --keys-out (which a fresh run refuses)."
        ),
    )
    # ETH
    ap.add_argument(
        "--eth-rpc-url",
        default="",
        help=(
            "EVM endpoint. Comma-separated for a QUORUM, which a real token counter leg requires: "
            "safety-critical reads then need agreement instead of one endpoint's word. Use "
            "independent providers — several URLs from one provider share a single failure."
        ),
    )
    ap.add_argument("--eth-key-hex", default="")
    ap.add_argument("--eth-chain-id", type=int, default=_SEPOLIA_CHAIN_ID)
    ap.add_argument("--eth-amount-wei", type=int, default=10**14)  # 0.0001 ETH dust
    ap.add_argument("--eth-claim-to", default="")
    ap.add_argument("--eth-refund-to", default="")
    ap.add_argument("--eth-artifact", default=str(_DEFAULT_ARTIFACT))
    ap.add_argument("--erc20-artifact", default=str(_DEFAULT_ERC20_ARTIFACT))
    ap.add_argument(
        "--counter-asset",
        # DERIVED from the registry, never hand-listed. A hardcoded ("native", "usdc") left USDT
        # pinned-but-unreachable the moment it was added — the same reachability gap the ERC-20 leg
        # itself had. A new pinned symbol is now selectable the day it lands.
        choices=("native", *sorted({sym.lower() for sym, _ in KNOWN_TOKENS})),
        default="native",
        help="what the counter leg pays: native ETH, or an ERC-20 resolved from the pinned registry",
    )
    ap.add_argument(
        "--token-amount",
        type=int,
        default=1_000_000,
        help="ERC-20 amount in BASE UNITS (USDC is 6-decimal: 1_000_000 == 1.00 USDC). Not wei.",
    )
    ap.add_argument("--eth-timeout-s", type=int, default=86_400)  # 1 day ETH refund deadline
    # RXD
    ap.add_argument("--rxd-photons", type=int, default=1000)
    # >= min-relay for a covenant spend at 0.10 RXD/kB plus the claim urgency premium (A1).
    ap.add_argument("--rxd-fee-photons", type=int, default=20_000_000)
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
    ap.add_argument(
        "--rxd-block-interval-fast-s",
        type=float,
        default=0.0,
        help=(
            "MEASURED p10 Radiant inter-block (seconds). Required once the token counter leg is "
            "real. Reserves DIVIDE by this, so a stale-high value under-counts blocks; measure it "
            "per run rather than inheriting a number."
        ),
    )
    # Default (None) → resolved from the EVM chain registry by --eth-chain-id in _args() below, so a
    # known chain gets its VETTED finalization window (e.g. Base 900s, not Ethereum's 768s); an
    # operator value always overrides. Realizes the registry's fail-closed per-chain safety.
    ap.add_argument("--eth-finalization-window-s", type=int, default=None)
    ap.add_argument(
        "--eth-finality-stall-tolerance-s",
        type=int,
        default=0,
        help=(
            "ADDITIONAL budget for an ETH finality STALL, seconds. Real-value mode requires "
            ">= 3600 (the May-2023 mainnet stall ran about an hour). 0 keeps the existing "
            "testnet behaviour; a measured policy refuses it."
        ),
    )
    ap.add_argument(
        "--maker-stall-safety-window-blocks",
        type=int,
        default=6,
        help=(
            "N: the squeeze window the taker must be able to act inside. The coordinator enforces "
            "a floor of ceil(eth_finalization_window_s / FAST-tail interval) + burial - 1, which on "
            "L1 with a measured 36s fast tail is 27 — well above this default of 6. Raise it for a "
            "real ETH counter leg; the default suits a chain whose finality window is small."
        ),
    )
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
