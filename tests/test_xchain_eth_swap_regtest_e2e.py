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
from pyrxd.gravity.eth_leg import EthLeg
from pyrxd.gravity.eth_rxd_timelock import CrossClockMargin
from pyrxd.gravity.htlc_covenant import build_htlc_covenant_rxd
from pyrxd.gravity.radiant_leg import RadiantChainIO, RadiantCovenantLeg
from pyrxd.gravity.swap_coordinator import CoordinatorConfig, MarginPolicy, SwapCoordinator
from pyrxd.gravity.swap_state import NegotiatedTerms, SwapRecord, SwapState
from pyrxd.security.secrets import PrivateKeyMaterial, SecretBytes

# Reuse the BTC e2e's Radiant-side helpers (no value moved; one source of truth).
from tests.test_xchain_swap_regtest_e2e import _FeeSource, _RadiantCliClient, _rxd_pay

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


def _build(node, url, *, t_rxd_blocks):
    """Build the covenant, the real legs, and the coordinator for an ETH↔RXD swap."""
    p_secret = SecretBytes(os.urandom(32))
    h = hashlib.sha256(p_secret.unsafe_raw_bytes()).digest()
    rxd_photons = 100_000
    t_rxd = bt.Timelock(t_rxd_blocks, bt.TimeUnit.BLOCKS)
    t_btc = bt.Timelock(t_rxd_blocks + 40, bt.TimeUnit.BLOCKS)  # decorative for ETH; kept > t_rxd
    eth_timeout = _anvil_now(url) + 50_000  # clears the cross-clock projection; future for claim()

    from pyrxd.keys import PrivateKey
    from pyrxd.security.types import Hex20

    taker_rxd, maker_rxd = PrivateKey(os.urandom(32)), PrivateKey(os.urandom(32))
    taker_pkh = bytes(Hex20(taker_rxd.public_key().hash160()))
    maker_pkh = bytes(Hex20(maker_rxd.public_key().hash160()))
    cov = build_htlc_covenant_rxd(
        amount=rxd_photons, taker_pkh=taker_pkh, maker_pkh=maker_pkh, hashlock=h, refund_csv=t_rxd.value
    )

    terms = NegotiatedTerms(
        hashlock=h,
        btc_sats=rxd_photons,
        radiant_amount=rxd_photons,
        t_btc=t_btc,
        t_rxd=t_rxd,
        asset_variant="rxd",
        genesis_ref=b"",
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
        indexer=None,
        seen_store=_MemSeen(),
        # anvil is treated as value-bearing (it can fork mainnet); accept the in-process seen
        # store for this single-process, single-shot, fresh-H-per-run e2e (the documented hatch).
        config=CoordinatorConfig(margin_policy=_eth_policy(), accept_nondurable_seen=True),
    )
    return coord, cov, p_secret, eth_leg, rpc


class TestEthRxdSwap:
    async def test_happy_path_completes(self, env):
        node, url = env
        coord, cov, p_secret, eth_leg, rpc = _build(node, url, t_rxd_blocks=60)
        terms = coord.record.terms
        now_unix = _anvil_now(url)

        # 1. Taker deploys + funds the ETH HTLC on Anvil.
        rec = await coord.taker_funds_btc(terms, now_unix_s=now_unix)
        assert rec.state is SwapState.BTC_LOCKED
        assert rec.counterchain_locator.amount_wei == _ETH_AMOUNT_WEI

        # 2. Maker locks the RXD covenant on regtest; taker re-validates SPK + cross-clock timing.
        asset_locked_at = int(node.rxd("getblockcount"))
        _rxd_pay(node, cov.funded_spk, terms.radiant_amount)
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
        assert node.rxd("gettxout", cov_txid, "0") in (None, ""), "RXD covenant should be spent after the taker's claim"
        await rpc.close()

    async def test_mutual_refund_when_maker_never_claims(self, env):
        node, url = env
        coord, cov, _p_secret, _eth_leg, rpc = _build(node, url, t_rxd_blocks=3)
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
