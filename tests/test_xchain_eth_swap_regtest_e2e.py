"""END-TO-END ETH↔RXD atomic swap on real chains — the first proof the two legs COMPOSE.

The BTC↔RXD e2e (``test_xchain_swap_regtest_e2e.py``) proves the BTC leg + Radiant leg through
the real coordinator. This is its ETH twin: a REAL ``EthLeg`` (deploying the real ``EthHtlc.sol``
on a local Anvil) + the REAL ``RadiantCovenantLeg`` (radiant-core regtest) driven through the
mature ``SwapCoordinator`` from NEGOTIATED → COMPLETED, plus the mutual-refund failure path.
Until this existed, "ETH↔RXD works" was an assembly of separately-proven parts; this is the
whole.

Anvil's ``finalized`` checkpoint is stuck at 0 by default (no consensus layer), so the ETH-claim
finality verdict would never be FINAL and the reorg gate would never return SAFE. We run anvil
with ``--slots-in-an-epoch 1`` (finalized tracks latest-2) and mine a few blocks after the maker's
claim so it finalizes — the realistic post-Merge "claim is reorg-safe" condition the gate needs.

Reuses the Radiant-side helpers from the BTC e2e (one source of truth). Moves no real value:
Anvil is a local devnet (public deterministic keys), Radiant is a self-managed regtest container.

Run it:  XCHAIN_ETH_REGTEST=1 pytest tests/test_xchain_eth_swap_regtest_e2e.py -m integration -s
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import shutil
import socket
import subprocess
import time
import urllib.request

import pytest

pytest.importorskip("web3")
pytest.importorskip("eth_keys")

from pyrxd.btc_wallet import taproot as bt
from pyrxd.glyph.types import GlyphRef
from pyrxd.gravity.eth_leg import EthLeg
from pyrxd.gravity.eth_rxd_timelock import CrossClockMargin
from pyrxd.gravity.htlc_covenant import build_htlc_covenant_ft, build_htlc_covenant_nft, build_htlc_covenant_rxd
from pyrxd.gravity.radiant_leg import RadiantChainIO, RadiantCovenantLeg
from pyrxd.gravity.swap_coordinator import CoordinatorConfig, MarginPolicy, SwapCoordinator
from pyrxd.gravity.swap_state import NegotiatedTerms, SwapRecord, SwapState
from pyrxd.gravity.watch import ChainObserver, DedupAlerter, EthClaimStatus, Intent, Reconciler, Severity
from pyrxd.keys import PrivateKey
from pyrxd.script.script import Script
from pyrxd.security.secrets import PrivateKeyMaterial, SecretBytes
from pyrxd.security.types import Hex20
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_input import TransactionInput
from pyrxd.transaction.transaction_output import TransactionOutput

# A fake ref-authenticity indexer (resolves a genesis ref to a clean ResolvedRef — gly marker,
# deep confs, genesis-outpoint == ref). For FT/NFT the coordinator's pre-lock gate requires one;
# a REAL RXinDexer is the separate production-integration gap. (NB the on-chain covenant uses a
# fake singleton per R1: consensus enforces ref UNIQUENESS, not mint PROVENANCE.)
from tests.test_swap_coordinator import FakeIndexer

# Reuse the BTC e2e's Radiant-side helpers (no value moved; one source of truth).
from tests.test_xchain_swap_regtest_e2e import (
    _RXD_RELAY_FEE,
    _FeeSource,
    _LiveRecordStore,
    _p2pkh_unlock,
    _RadiantCliClient,
    _RecordingChannel,
    _RegtestRxdChainSource,
    _rxd_pay,
    _src,
)

pytestmark = pytest.mark.integration

_RXD_IMAGE = "radiant-core:v2.3.0-amd64"
_RXD_CT = "xchain-eth-rxd-pytest"
_CHAIN_ID = 31337
# Anvil's deterministic PUBLIC dev keys (local devnet only — no real value).
_KEY = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"  # acct 0 — funds/claims/refunds
_ADDR_TAKER = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"  # acct 0 (refundee)
_ADDR_MAKER = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"  # acct 1 (claimant; anyone-can-claim pays it)
_ETH_AMOUNT_WEI = 10**15

import pathlib

_ARTIFACT = json.loads((pathlib.Path(__file__).parent / "fixtures" / "EthHtlc.json").read_text())


# --------------------------------------------------------------------------- radiant-only node


class _RxdNode:
    """A single self-managed radiantd regtest node (the Radiant half of the BTC e2e's _Nodes)."""

    def __init__(self) -> None:
        self.rpass = secrets.token_hex(12)
        self.raddr = ""

    def _cli(self, wallet, args):
        base = ["docker", "exec", _RXD_CT, "radiant-cli", "-regtest", "-rpcuser=rt_user", f"-rpcpassword={self.rpass}"]
        if wallet:
            base.append(f"-rpcwallet={wallet}")
        r = subprocess.run(base + list(args), capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            raise RuntimeError(f"radiant-cli {args[0]} failed: {r.stderr.strip()}")
        out = r.stdout.strip()
        try:
            return json.loads(out)
        except json.JSONDecodeError:
            return out

    def rxd(self, *a, wallet=None):
        return self._cli(wallet, a)

    def rxd_mine(self, n=1):
        self.rxd("generatetoaddress", str(n), self.raddr, wallet="gravity")

    def start(self) -> None:
        subprocess.run(["docker", "rm", "-f", _RXD_CT], capture_output=True)
        up = subprocess.run(
            [
                "docker",
                "run",
                "-d",
                "--name",
                _RXD_CT,
                "--entrypoint",
                "radiantd",
                _RXD_IMAGE,
                "-regtest",
                "-server",
                "-txindex=1",
                "-disablewallet=0",
                "-fallbackfee=0.001",
                "-rpcuser=rt_user",
                f"-rpcpassword={self.rpass}",
                "-rpcbind=0.0.0.0",
                "-rpcallowip=0.0.0.0/0",
            ],
            capture_output=True,
            text=True,
        )
        if up.returncode != 0:
            raise RuntimeError(f"radiantd start failed: {up.stderr.strip()}")
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            try:
                if isinstance(self.rxd("getblockchaininfo"), dict):
                    break
            except RuntimeError:
                time.sleep(0.5)
        else:
            raise RuntimeError("radiantd RPC did not become ready")
        assert self.rxd("getblockchaininfo")["chain"] == "regtest"
        self.rxd("createwallet", "gravity")
        self.raddr = str(self.rxd("getnewaddress", wallet="gravity"))
        self.rxd_mine(101)

    def stop(self) -> None:
        subprocess.run(["docker", "rm", "-f", _RXD_CT], capture_output=True)


# --------------------------------------------------------------------------- anvil + helpers


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _anvil_rpc(url, method, params=None):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params or []}).encode()
    req = urllib.request.Request(url, data=body, headers={"content-type": "application/json"})
    return json.loads(urllib.request.urlopen(req, timeout=3).read())


def _anvil_mine(url, n=1):
    for _ in range(n):
        _anvil_rpc(url, "evm_mine")


def _anvil_now(url) -> int:
    blk = _anvil_rpc(url, "eth_getBlockByNumber", ["latest", False])["result"]
    return int(blk["timestamp"], 16)


class _RecordingEthLeg:
    """Wraps EthLeg to capture the claim tx hash (the coordinator drives claim() but ignores
    its return; the taker's scrape step needs the hash)."""

    def __init__(self, inner: EthLeg) -> None:
        self._inner = inner
        self.last_claim_tx = None

    def __getattr__(self, name):
        return getattr(self._inner, name)

    async def claim(self, locator, preimage):
        self.last_claim_tx = await self._inner.claim(locator, preimage)
        return self.last_claim_tx


class _MemSeen:
    def __init__(self):
        self._s = set()

    def reserve(self, h):
        b = bytes(h)
        ok = b not in self._s
        self._s.add(b)
        return ok

    def has_seen(self, h):
        return bytes(h) in self._s

    def mark_seen(self, h):
        self._s.add(bytes(h))


@pytest.fixture(scope="module")
def env():
    if not os.environ.get("XCHAIN_ETH_REGTEST"):
        pytest.skip("XCHAIN_ETH_REGTEST not set (opt-in for the ETH↔RXD e2e)")
    if shutil.which("docker") is None:
        pytest.skip("docker not available")
    if shutil.which("anvil") is None:
        pytest.skip("anvil not available")
    if subprocess.run(["docker", "image", "inspect", _RXD_IMAGE], capture_output=True).returncode != 0:
        pytest.skip(f"{_RXD_IMAGE} image not available")
    node = _RxdNode()
    node.start()
    port = _free_port()
    url = f"http://127.0.0.1:{port}"
    anvil = subprocess.Popen(
        ["anvil", "--port", str(port), "--chain-id", str(_CHAIN_ID), "--slots-in-an-epoch", "1", "--silent"],
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
        else:
            pytest.fail("anvil did not become ready")
        yield node, url
    finally:
        anvil.terminate()
        node.stop()


def _eth_policy():
    return MarginPolicy(
        margin=bt.Timelock(36, bt.TimeUnit.BLOCKS),
        block_interval_s=600.0,
        is_measured=False,
        rxd_block_interval_s=300.0,
        eth_finalization_window_s=768,
        cross_clock_margin=CrossClockMargin(
            eth_reorg_finality_s=768, rxd_claim_burial_s=1800, rxd_confirm_slack_s=600, rounding_slack_s=300
        ),
        max_covenant_confirm_wait_s=600,
    )


def _fund_spending_ref(node, dest_spk: bytes, amount: int, ref_utxo: dict) -> str:
    """Fund ``dest_spk`` by spending EXACTLY ``ref_utxo`` (so its outpoint enters the input-ref
    set — the R1 mechanism that makes consensus accept the FT/NFT singleton; consensus enforces
    ref UNIQUENESS, not mint PROVENANCE)."""
    u = ref_utxo
    key = PrivateKey(str(node.rxd("dumpprivkey", u["address"], wallet="gravity")))
    pkh = bytes(Hex20(key.public_key().hash160()))
    spk = bytes.fromhex(u["scriptPubKey"])
    in_sats = round(u["amount"] * 1e8)
    fin = TransactionInput(
        source_transaction=_src(u["txid"], int(u["vout"]), spk, in_sats),
        source_txid=u["txid"],
        source_output_index=int(u["vout"]),
        unlocking_script_template=_p2pkh_unlock(key),
    )
    fin.satoshis = in_sats
    fin.locking_script = Script(spk)
    change_spk = b"\x76\xa9\x14" + pkh + b"\x88\xac"
    tx = Transaction(
        tx_inputs=[fin],
        tx_outputs=[
            TransactionOutput(Script(dest_spk), amount),
            TransactionOutput(Script(change_spk), in_sats - amount - _RXD_RELAY_FEE),
        ],
    )
    tx.sign()
    txid = node.rxd("sendrawtransaction", tx.serialize().hex())
    node.rxd_mine(1)
    return str(txid)


def _build(node, url, *, t_rxd_blocks, asset_variant="rxd"):
    """Build the covenant, the real legs, and the coordinator for an ETH↔(RXD|FT-glyph|NFT-glyph)
    swap. Returns (coord, cov, p_secret, eth_leg, rpc, ref_utxo) — ref_utxo is None for rxd, else
    the wallet UTXO that funds the singleton (the maker spends it to lock the asset)."""
    p_secret = SecretBytes(os.urandom(32))
    h = hashlib.sha256(p_secret.unsafe_raw_bytes()).digest()
    # rxd swaps the photons; ft/nft swap a small token carrier (the singleton/FT amount).
    carrier = 100_000 if asset_variant == "rxd" else 1000
    t_rxd = bt.Timelock(t_rxd_blocks, bt.TimeUnit.BLOCKS)
    t_btc = bt.Timelock(t_rxd_blocks + 40, bt.TimeUnit.BLOCKS)  # decorative for ETH; kept > t_rxd
    eth_timeout = _anvil_now(url) + 50_000  # clears the cross-clock projection; future for claim()

    taker_rxd, maker_rxd = PrivateKey(os.urandom(32)), PrivateKey(os.urandom(32))
    taker_pkh = bytes(Hex20(taker_rxd.public_key().hash160()))
    maker_pkh = bytes(Hex20(maker_rxd.public_key().hash160()))

    ref_utxo = None
    genesis_ref = b""
    indexer = None
    if asset_variant == "rxd":
        cov = build_htlc_covenant_rxd(
            amount=carrier, taker_pkh=taker_pkh, maker_pkh=maker_pkh, hashlock=h, refund_csv=t_rxd.value
        )
    else:
        # A plain wallet UTXO as the genesis ref (a "fake singleton" — R1). A real swap binds a
        # genuinely-minted Glyph + a real RXinDexer; the off-chain ref-authenticity gate (the
        # FakeIndexer here) is the only mint-provenance check, so this proves the SWAP MECHANISM.
        ref_utxo = max(node.rxd("listunspent", "1", "9999999", wallet="gravity"), key=lambda x: x["amount"])
        ref_txid, ref_vout = ref_utxo["txid"], int(ref_utxo["vout"])
        if asset_variant == "nft":
            cov = build_htlc_covenant_nft(
                genesis_txid=ref_txid,
                genesis_vout=ref_vout,
                nft_carrier_value=carrier,
                taker_pkh=taker_pkh,
                maker_pkh=maker_pkh,
                hashlock=h,
                refund_csv=t_rxd.value,
            )
        else:  # ft
            cov = build_htlc_covenant_ft(
                genesis_txid=ref_txid,
                genesis_vout=ref_vout,
                amount=carrier,
                taker_pkh=taker_pkh,
                maker_pkh=maker_pkh,
                hashlock=h,
                refund_csv=t_rxd.value,
            )
        genesis_ref = GlyphRef(txid=ref_txid, vout=ref_vout).to_bytes()
        indexer = FakeIndexer()  # resolves the ref to a clean ResolvedRef (gly marker, deep confs)

    terms = NegotiatedTerms(
        hashlock=h,
        btc_sats=100_000,
        radiant_amount=carrier,
        t_btc=t_btc,
        t_rxd=t_rxd,
        asset_variant=asset_variant,
        genesis_ref=genesis_ref,
        taker_dest_hash=cov.expected_taker_hash,
        maker_dest_hash=cov.expected_maker_hash,
        btc_claim_pubkey_xonly=b"\x00" * 32,
        btc_refund_pubkey_xonly=b"\x00" * 32,
        counter_chain="eth",
        value_amount=_ETH_AMOUNT_WEI,
        eth_timeout_unix_s=eth_timeout,
    )

    from pyrxd.eth_wallet.htlc_leg import EthHtlcContractLeg
    from pyrxd.eth_wallet.rpc import EthRpc

    rpc = EthRpc(url, expected_chain_id=_CHAIN_ID)
    contract_leg = EthHtlcContractLeg(
        rpc=rpc, signing_key=PrivateKeyMaterial(bytes.fromhex(_KEY)), chain_id=_CHAIN_ID, artifact=_ARTIFACT
    )
    eth_leg = _RecordingEthLeg(
        EthLeg(
            contract_leg=contract_leg,
            network="anvil",
            claim_to=_ADDR_MAKER,
            refund_to=_ADDR_TAKER,
            eth_timeout_unix_s=eth_timeout,
            audit_cleared=True,
        )
    )

    rxd_client = _RadiantCliClient(node)
    rxd_client.register_spk(cov.funded_spk)
    rxd_leg = RadiantCovenantLeg(
        network="bcrt",
        taker_pkh=taker_pkh,
        maker_pkh=maker_pkh,
        chain_io=RadiantChainIO(rxd_client),
        fee_source=_FeeSource(node),
        min_confirmations=1,
    )

    coord = SwapCoordinator(
        record=SwapRecord(state=SwapState.NEGOTIATED, terms=terms),
        counter_leg=eth_leg,
        radiant_leg=rxd_leg,
        indexer=indexer,
        seen_store=_MemSeen(),
        # anvil is treated as value-bearing (it can fork mainnet); accept the in-process seen
        # store for this single-process, single-shot, fresh-H-per-run e2e (the documented hatch).
        config=CoordinatorConfig(margin_policy=_eth_policy(), accept_nondurable_seen=True),
    )
    return coord, cov, p_secret, eth_leg, rpc, ref_utxo


# --------------------------------------------------------------------------- watchtower observation
#
# The alert-only watchtower (v3) watches the SAME ETH↔RXD swap the coordinator drives and PAGES the
# operator with the due action — it broadcasts nothing, holds no key, never touches p. A thin
# READ-ONLY EthChainSource backs the PRODUCTION ChainObserver against anvil: claim detection via
# eth_getLogs (the Claimed event), finality delegated UNCHANGED to the audited
# EthHtlcContractLeg.claim_finality_verdict (post-Merge `finalized` checkpoint, not a depth). decide(),
# ChainObserver and DedupAlerter run UNCHANGED, so a green run proves the real ETH decision core emits
# the correct Intent on real anvil+regtest consensus.
#
# With _eth_policy(): rxd_claim_burial = 6 (default), counter_reserve = ceil(768/300) = 3, so the gate
# reduces to blocks_left = t_rxd - cov_confs + 1 with: FINAL → SAFE iff blocks_left >= 6; NOT_YET_FINAL
# → WAIT iff blocks_left >= 9, else SQUEEZED; a maker stall pages mutual_refund once blocks_left <= 6.


def _claimed_topic0() -> str:
    from web3 import Web3

    return Web3.to_hex(Web3.keccak(text="Claimed(bytes32)"))


class _AnvilEthChainSource:
    """``EthChainSource`` backed by anvil (read-only). Detects the maker's claim from the on-chain
    ``Claimed`` event log (not the broadcaster's memory) and delegates the finalized-checkpoint verdict
    to the audited ``EthHtlcContractLeg.claim_finality_verdict``."""

    def __init__(self, url: str, contract_leg) -> None:
        self._url = url
        self._leg = contract_leg
        self._topic0 = _claimed_topic0()

    async def claim_status(self, contract_address, deploy_tx_hash) -> EthClaimStatus:
        res = _anvil_rpc(
            self._url,
            "eth_getLogs",
            [{"address": contract_address, "fromBlock": "0x0", "toBlock": "latest", "topics": [self._topic0]}],
        )
        logs = res.get("result", [])
        if not logs:
            return EthClaimStatus(claimed=False)
        return EthClaimStatus(claimed=True, claim_tx_hash=str(logs[-1]["transactionHash"]))

    async def claim_finality_verdict(self, claim_tx_hash):
        return await self._leg.claim_finality_verdict(claim_tx_hash)


def _eth_watchtower(node, url, coord, rpc):
    """Wire the PRODUCTION reconciler (real decide/ChainObserver/DedupAlerter) to observe ``coord``'s
    ETH↔RXD swap on anvil + the regtest node, with the SAME policy + safety window the coordinator runs.
    Reuses ``rpc`` for a read-only contract leg (finality verdict only — no signing)."""
    from pyrxd.eth_wallet.htlc_leg import EthHtlcContractLeg

    contract_leg = EthHtlcContractLeg(
        rpc=rpc, signing_key=PrivateKeyMaterial(bytes.fromhex(_KEY)), chain_id=_CHAIN_ID, artifact=_ARTIFACT
    )
    channel = _RecordingChannel()
    reconciler = Reconciler(
        store=_LiveRecordStore(coord),
        observer=ChainObserver(
            eth=_AnvilEthChainSource(url, contract_leg),
            rxd=_RegtestRxdChainSource(node),
            rxd_corroborated=False,  # v1/v3: RXD (and ETH RPC) single-source → every page low-corroboration
        ),
        alerter=DedupAlerter(channel=channel),
        policy=coord.config.margin_policy,
        safety_window_blocks=coord.config.maker_stall_safety_window_blocks,
    )
    return reconciler, channel


async def _setup_eth_both_locked(node, url, *, t_rxd_blocks):
    """Drive an ETH↔RXD (rxd) swap to BOTH_LOCKED on real anvil + regtest. Returns (coord, p_secret, rpc)."""
    coord, cov, p_secret, _eth_leg, rpc, _ref = _build(node, url, t_rxd_blocks=t_rxd_blocks)
    terms = coord.record.terms
    rec = await coord.taker_funds_btc(terms, now_unix_s=_anvil_now(url))
    assert rec.state is SwapState.BTC_LOCKED
    _rxd_pay(node, cov.funded_spk, terms.radiant_amount)
    rec = await coord.post_asset_lock_revalidate(cov.funded_spk, now_unix_s=_anvil_now(url))
    assert rec.state is SwapState.BOTH_LOCKED
    return coord, p_secret, rpc


class TestWatchtowerEthIntentSequence:
    """The alert-only watchtower observes the ETH↔RXD swap the coordinator drives and emits the correct
    Intent SEQUENCE for happy / maker-stall / closing-window on real anvil+regtest consensus — and NEVER
    pages PAGE_CLAIM against a not-yet-finalized (WAIT) verdict. It broadcasts nothing; the production
    decide()/ChainObserver/DedupAlerter run unchanged (ETH finalized-checkpoint finality, mutual_refund
    on stall)."""

    async def _tick(self, reconciler):
        results = await reconciler.tick()
        assert len(results) == 1, "exactly one swap is being watched"
        return results[0]

    async def test_eth_happy_watch_then_wait_then_page_claim(self, env):
        node, url = env
        coord, p_secret, rpc = await _setup_eth_both_locked(node, url, t_rxd_blocks=60)
        reconciler, channel = _eth_watchtower(node, url, coord, rpc)

        # 1. maker hasn't revealed p, deadline far → WATCH (no page).
        r = await self._tick(reconciler)
        assert r.decision.intent is Intent.WATCH
        assert channel.pages == []

        # 2. maker claims ETH (reveals p, emits Claimed(p)); the claim is mined but anvil has NOT
        #    finalized it yet (finalized = latest-2) → verdict NOT_YET_FINAL_LIVE → gate WAIT → the tower
        #    must keep WATCHING and must NOT page a claim on a not-yet-reorg-safe reveal.
        rec = await coord.maker_claims_btc(p_secret)
        assert rec.state is SwapState.SECRET_REVEALED
        r = await self._tick(reconciler)
        assert r.decision.intent is Intent.WATCH, "must not PAGE_CLAIM against a not-yet-finalized (WAIT) verdict"
        assert channel.pages == []

        # 3. finalize the ETH claim (anvil --slots-in-an-epoch 1: finalized = latest-2) → gate SAFE → PAGE_CLAIM.
        _anvil_mine(url, 3)
        r = await self._tick(reconciler)
        assert r.decision.intent is Intent.PAGE_CLAIM
        assert r.decision.recommended_action == "taker_scrape_and_claim_asset"
        assert r.decision.deadline_rxd_height is not None
        assert r.alert_delivered is True
        assert len(channel.pages) == 1
        page = channel.pages[0]
        assert page.intent is Intent.PAGE_CLAIM
        assert page.severity is Severity.CRITICAL
        assert page.low_corroboration is True  # single-source ETH RPC + RXD

        # Dedup: re-ticking the same SAFE situation does not re-page.
        r = await self._tick(reconciler)
        assert r.decision.intent is Intent.PAGE_CLAIM
        assert len(channel.pages) == 1, "DedupAlerter must not re-page an unchanged situation"
        await rpc.close()

    async def test_eth_maker_stall_watch_then_page_mutual_refund(self, env):
        node, url = env
        coord, _p_secret, rpc = await _setup_eth_both_locked(node, url, t_rxd_blocks=20)
        reconciler, channel = _eth_watchtower(node, url, coord, rpc)

        # 1. just locked, refund window not near → WATCH.
        r = await self._tick(reconciler)
        assert r.decision.intent is Intent.WATCH
        assert channel.pages == []

        # 2. maker never claims; advance RXD to within the safety window of t_rxd maturity
        #    (cov_confs 1→15 ⇒ now >= maturity - 6) → PAGE_REFUND naming mutual_refund (NOT the RXD-only
        #    maybe_refund_asset_on_maker_stall, which is forbidden on the ETH stall path).
        node.rxd_mine(14)
        r = await self._tick(reconciler)
        assert r.decision.intent is Intent.PAGE_REFUND
        assert r.decision.recommended_action == "mutual_refund"
        assert r.alert_delivered is True
        assert len(channel.pages) == 1
        assert channel.pages[0].severity is Severity.WARN  # a stall refund is recoverable, not a race
        assert channel.pages[0].low_corroboration is True
        await rpc.close()

    async def test_eth_reveal_with_closing_window_pages_squeezed(self, env):
        node, url = env
        coord, p_secret, rpc = await _setup_eth_both_locked(node, url, t_rxd_blocks=8)
        reconciler, channel = _eth_watchtower(node, url, coord, rpc)

        # 1. pre-reveal, window not yet near → WATCH.
        r = await self._tick(reconciler)
        assert r.decision.intent is Intent.WATCH
        assert channel.pages == []

        # 2. maker reveals p but the claim is NOT finalized and t_rxd is too tight to wait
        #    (blocks_left 8 < the 9 a WAIT needs: 8 - reserve 3 < burial 6) → SQUEEZED → PAGE_SQUEEZED.
        rec = await coord.maker_claims_btc(p_secret)
        assert rec.state is SwapState.SECRET_REVEALED
        r = await self._tick(reconciler)
        assert r.decision.intent is Intent.PAGE_SQUEEZED
        assert r.alert_delivered is True
        assert len(channel.pages) == 1
        assert channel.pages[0].intent is Intent.PAGE_SQUEEZED
        assert channel.pages[0].severity is Severity.CRITICAL
        await rpc.close()


class TestEthRxdSwap:
    @pytest.mark.parametrize("asset_variant", ["rxd", "nft", "ft"])
    async def test_happy_path_completes(self, env, asset_variant):
        """ETH↔(RXD | NFT-glyph | FT-glyph) settles end-to-end. The NFT/FT cases bind a Glyph
        token (genesis ref) into the covenant — proving the swap of a Glyph asset, not just RXD."""
        node, url = env
        coord, cov, p_secret, eth_leg, rpc, ref_utxo = _build(node, url, t_rxd_blocks=60, asset_variant=asset_variant)
        terms = coord.record.terms
        now_unix = _anvil_now(url)

        # 1. Taker deploys + funds the ETH HTLC on Anvil.
        rec = await coord.taker_funds_btc(terms, now_unix_s=now_unix)
        assert rec.state is SwapState.BTC_LOCKED
        assert rec.counterchain_locator.amount_wei == _ETH_AMOUNT_WEI

        # 2. Maker locks the asset covenant on regtest; taker re-validates SPK + ref + cross-clock.
        asset_locked_at = int(node.rxd("getblockcount"))
        if ref_utxo is None:  # rxd: native photons
            _rxd_pay(node, cov.funded_spk, terms.radiant_amount)
        else:  # nft/ft: spend the genesis-ref UTXO into the covenant (the singleton)
            _fund_spending_ref(node, cov.funded_spk, terms.radiant_amount, ref_utxo)
        rec = await coord.post_asset_lock_revalidate(cov.funded_spk, now_unix_s=_anvil_now(url))
        assert rec.state is SwapState.BOTH_LOCKED

        # 3. Maker claims the ETH (reveals p on Anvil, emits Claimed(p)).
        rec = await coord.maker_claims_btc(p_secret)
        assert rec.state is SwapState.SECRET_REVEALED
        claim_tx = eth_leg.last_claim_tx
        assert claim_tx is not None

        # Finalize the ETH claim (anvil --slots-in-an-epoch 1: finalized = latest-2).
        _anvil_mine(url, 3)

        # 4. Taker scrapes p from the ETH claim and claims the RXD asset (FINAL → SAFE).
        now_rxd = int(node.rxd("getblockcount"))
        rec = await coord.taker_scrape_and_claim_asset(
            claim_tx, now_rxd_height=now_rxd, asset_locked_at_height=asset_locked_at
        )
        assert rec.state is SwapState.COMPLETED

        cov_txid = rec.radiant_covenant_outpoint.split(":")[0]
        assert node.rxd("gettxout", cov_txid, "0") in (None, ""), (
            f"{asset_variant} asset covenant should be spent after the taker's claim"
        )
        await rpc.close()

    async def test_mutual_refund_when_maker_never_claims(self, env):
        node, url = env
        coord, cov, _p_secret, _eth_leg, rpc, _ref = _build(node, url, t_rxd_blocks=3)
        terms = coord.record.terms
        now_unix = _anvil_now(url)

        rec = await coord.taker_funds_btc(terms, now_unix_s=now_unix)
        assert rec.state is SwapState.BTC_LOCKED
        _rxd_pay(node, cov.funded_spk, terms.radiant_amount)
        rec = await coord.post_asset_lock_revalidate(cov.funded_spk, now_unix_s=_anvil_now(url))
        assert rec.state is SwapState.BOTH_LOCKED

        # Maker never claims. Mature the RXD CSV; warp anvil past the ETH timeout for the ETH refund.
        node.rxd_mine(terms.t_rxd.value)
        _anvil_rpc(url, "evm_setNextBlockTimestamp", [terms.eth_timeout_unix_s + 1])
        _anvil_mine(url, 1)

        rec = await coord.mutual_refund()
        assert rec.state is SwapState.MUTUAL_REFUND
        rxd_spent = node.rxd("gettxout", coord.record.radiant_covenant_outpoint.split(":")[0], "0")
        assert rxd_spent in (None, ""), "RXD covenant should be refunded (spent) on mutual refund"
        await rpc.close()
