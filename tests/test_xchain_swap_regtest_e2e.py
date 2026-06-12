"""Coordinator-driven cross-chain HTLC swap on TWO real regtest nodes (T7 capstone).

The end-to-end proof that the production :class:`SwapCoordinator` drives a complete
BTC<->RXD atomic swap across REAL consensus on both chains — not fakes. All paths
branch from the same BOTH_LOCKED state (``_setup_locked_swap``):

  taker_funds_btc            -> NEGOTIATED -> BTC_LOCKED   (BtcLeg funds P2TR HTLC)
  post_asset_lock_revalidate -> BOTH_LOCKED                (maker locks RXD covenant;
                                                            RadiantLeg locates it,
                                                            coordinator re-validates SPK)

* HAPPY PATH: maker_claims_btc -> SECRET_REVEALED (reveals p); then
  taker_scrape_and_claim_asset -> COMPLETED (scrapes p, claims the RXD covenant).
* MUTUAL REFUND (maker never claims): both CSV timeouts elapse -> mutual_refund
  refunds BOTH legs -> MUTUAL_REFUND. No one-sided loss.
* MAKER STALL: taker proactively refunds the RXD asset via CSV before relying on the
  swap -> ASSET_REFUNDED_TAKER_ACTS. Taker never loses both.

These prove the swap is safe whether it completes OR fails — the FSM's terminal
paths all settle correctly on real consensus.

Both legs hit real nodes via thin shims (the production legs are unchanged):
* BtcLeg -> bitcoind regtest (BtcCliBroadcaster + BtcCliFundingReader).
* RadiantLeg -> radiantd regtest (RadiantCliClient implementing RadiantChainIO's
  broadcast / get_transaction_verbose / get_utxos, the last via scantxoutset +
  a SPK registry since radiant-cli has no scripthash index).

RXD asset variant, so the REF-authenticity gate is a no-op (no live indexer).

Gating: ``@pytest.mark.integration`` (deselected by default) + opt-in
``XCHAIN_REGTEST=1``. Skips if docker or either image is unavailable. Self-manages
TWO isolated regtest containers (NEVER a mainnet node), funds throwaway wallets,
mines its own blocks, tears both down after. Moves no real value.

Run it:  XCHAIN_REGTEST=1 pytest tests/test_xchain_swap_regtest_e2e.py -m integration -s
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import shutil
import subprocess
import time

import coincurve
import pytest

from pyrxd.btc_wallet import taproot as bt
from pyrxd.btc_wallet.htlc_leg import BitcoinTaprootLeg
from pyrxd.btc_wallet.keys import generate_keypair
from pyrxd.btc_wallet.payment import BtcUtxo
from pyrxd.gravity.htlc_covenant import build_htlc_covenant_rxd
from pyrxd.gravity.htlc_spend import FeeInput
from pyrxd.gravity.radiant_leg import RadiantChainIO, RadiantCovenantLeg
from pyrxd.gravity.swap_coordinator import CoordinatorConfig, MarginPolicy, SwapCoordinator
from pyrxd.gravity.swap_state import NegotiatedTerms, SwapRecord, SwapState
from pyrxd.gravity.watch.alerts import DedupAlerter, Page, Severity
from pyrxd.gravity.watch.decide import Intent
from pyrxd.gravity.watch.quorum import BtcClaimStatus, ChainObserver
from pyrxd.gravity.watch.reconciler import Reconciler
from pyrxd.keys import PrivateKey
from pyrxd.network.electrumx import UtxoRecord
from pyrxd.script.script import Script
from pyrxd.script.type import encode_pushdata, to_unlock_script_template
from pyrxd.security.errors import NetworkError
from pyrxd.security.secrets import SecretBytes
from pyrxd.security.types import Hex20
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_input import TransactionInput
from pyrxd.transaction.transaction_output import TransactionOutput

pytestmark = pytest.mark.integration

_RXD_IMAGE = "radiant-core:v3.1.1-amd64"
_BTC_IMAGE = "ruimarinho/bitcoin-core:24"
_RXD_CT = "xchain-rxd-pytest"
_BTC_CT = "xchain-btc-pytest"
_RXD_RELAY_FEE = 1_000_000  # 0.01 RXD per sub-kB tx


# --------------------------------------------------------------------------- node mgmt


class _Nodes:
    """Two self-managed isolated regtest nodes (radiantd + bitcoind)."""

    def __init__(self) -> None:
        self.rpass = secrets.token_hex(12)
        self.bpass = secrets.token_hex(12)
        self.raddr = ""
        self.baddr = ""

    def _cli(self, ct, binary, user, pw, wallet, args):
        base = ["docker", "exec", ct, binary, "-regtest", f"-rpcuser={user}", f"-rpcpassword={pw}"]
        if wallet:
            base.append(f"-rpcwallet={wallet}")
        r = subprocess.run(base + list(args), capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            raise RuntimeError(f"{binary} {args[0]} failed: {r.stderr.strip()}")
        out = r.stdout.strip()
        try:
            return json.loads(out)
        except json.JSONDecodeError:
            return out

    def rxd(self, *a, wallet=None):
        return self._cli(_RXD_CT, "radiant-cli", "rt_user", self.rpass, wallet, a)

    def btc(self, *a, wallet=None):
        return self._cli(_BTC_CT, "bitcoin-cli", "btc_user", self.bpass, wallet, a)

    def rxd_mine(self, n=1):
        self.rxd("generatetoaddress", str(n), self.raddr, wallet="gravity")

    def btc_mine(self, n=1):
        self.btc("generatetoaddress", str(n), self.baddr, wallet="btcw")

    def _wait(self, fn):
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            try:
                if fn():
                    return
            except RuntimeError:
                time.sleep(0.5)
        raise RuntimeError("regtest RPC did not become ready")

    def start(self) -> None:
        for ct in (_RXD_CT, _BTC_CT):
            subprocess.run(["docker", "rm", "-f", ct], capture_output=True)
        rxd_up = subprocess.run(
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
        if rxd_up.returncode != 0:
            raise RuntimeError(f"radiantd start failed: {rxd_up.stderr.strip()}")
        btc_up = subprocess.run(
            [
                "docker",
                "run",
                "-d",
                "--name",
                _BTC_CT,
                _BTC_IMAGE,
                "-regtest",
                "-server",
                "-txindex=1",
                "-fallbackfee=0.0002",
                "-rpcuser=btc_user",
                f"-rpcpassword={self.bpass}",
                "-rpcbind=0.0.0.0",
                "-rpcallowip=0.0.0.0/0",
            ],
            capture_output=True,
            text=True,
        )
        if btc_up.returncode != 0:
            raise RuntimeError(f"bitcoind start failed: {btc_up.stderr.strip()}")
        self._wait(
            lambda: (
                isinstance(self.rxd("getblockchaininfo"), dict) and self.rxd("getblockchaininfo")["chain"] == "regtest"
            )
        )
        self._wait(
            lambda: (
                isinstance(self.btc("getblockchaininfo"), dict) and self.btc("getblockchaininfo")["chain"] == "regtest"
            )
        )
        assert self.rxd("getblockchaininfo")["chain"] == "regtest"
        assert self.btc("getblockchaininfo")["chain"] == "regtest"
        self.rxd("createwallet", "gravity")
        self.raddr = str(self.rxd("getnewaddress", wallet="gravity"))
        self.rxd_mine(101)
        self.btc("createwallet", "btcw")
        self.baddr = str(self.btc("getnewaddress", wallet="btcw"))
        self.btc_mine(101)

    def stop(self) -> None:
        for ct in (_RXD_CT, _BTC_CT):
            subprocess.run(["docker", "rm", "-f", ct], capture_output=True)


@pytest.fixture(scope="module")
def nodes():
    if not os.environ.get("XCHAIN_REGTEST"):
        pytest.skip("XCHAIN_REGTEST not set (opt-in for the cross-chain e2e)")
    if shutil.which("docker") is None:
        pytest.skip("docker not available")
    for img in (_RXD_IMAGE, _BTC_IMAGE):
        if subprocess.run(["docker", "image", "inspect", img], capture_output=True).returncode != 0:
            if img == _BTC_IMAGE:
                if subprocess.run(["docker", "pull", img], capture_output=True, timeout=300).returncode != 0:
                    pytest.skip(f"could not obtain {img}")
            else:
                pytest.skip(f"{img} image not available")
    n = _Nodes()
    n.start()
    try:
        yield n
    finally:
        n.stop()


# --------------------------------------------------------------------------- chain-IO shims


class _RadiantCliClient:
    """radiant-cli ElectrumX-like client for RadiantChainIO (scantxoutset + SPK registry)."""

    def __init__(self, nodes: _Nodes) -> None:
        self._n = nodes
        self._spk_by_hash: dict[bytes, bytes] = {}

    def register_spk(self, spk: bytes) -> None:
        self._spk_by_hash[hashlib.sha256(bytes(spk)).digest()[::-1]] = bytes(spk)

    async def broadcast(self, raw_tx: bytes) -> str:
        return self._n.rxd("sendrawtransaction", bytes(raw_tx).hex())

    async def get_transaction_verbose(self, txid) -> dict:
        return self._n.rxd("getrawtransaction", str(txid), "true")

    async def get_utxos(self, script_hash):
        spk = self._spk_by_hash.get(bytes(script_hash))
        if spk is None:
            return []
        res = self._n.rxd("scantxoutset", "start", json.dumps([{"desc": f"raw({spk.hex()})"}]))
        tip = int(self._n.rxd("getblockcount"))
        out = []
        for u in res.get("unspents", []):
            h = int(u.get("height", 0))
            out.append(
                UtxoRecord(
                    tx_hash=u["txid"],
                    tx_pos=int(u["vout"]),
                    value=round(u["amount"] * 1e8),
                    height=(tip - h + 1 if h else 0),
                )
            )
        return out


class _BtcBroadcaster:
    def __init__(self, nodes: _Nodes) -> None:
        self._n = nodes
        self.last_raw: dict[str, bytes] = {}

    async def broadcast(self, raw_tx: bytes) -> str:
        txid = self._n.btc("sendrawtransaction", bytes(raw_tx).hex())
        self.last_raw[txid] = bytes(raw_tx)
        self._n.btc_mine(1)
        return txid


class _BtcFundingReader:
    def __init__(self, nodes: _Nodes) -> None:
        self._n = nodes

    async def read_output_amount_sats(self, txid, vout, *, min_confirmations) -> int:
        info = self._n.btc("getrawtransaction", str(txid), "true")
        if int(info.get("confirmations", 0)) < min_confirmations:
            raise NetworkError("insufficient confirmations")
        return round(info["vout"][vout]["value"] * 1e8)

    async def confirmations(self, txid) -> int:
        info = self._n.btc("getrawtransaction", str(txid), "true")
        return int(info.get("confirmations", 0) or 0)

    async def txid_of(self, raw_tx: bytes) -> str:
        # Node-authoritative txid (never a local segwit parse).
        decoded = self._n.btc("decoderawtransaction", bytes(raw_tx).hex())
        return str(decoded["txid"])


# --------------------------------------------------------------------------- RXD tx helpers


def _src(txid, vout, spk, val):
    outs = [TransactionOutput(Script(b"\x00"), 0) for _ in range(vout)]
    outs.append(TransactionOutput(Script(spk), val))
    t = Transaction(tx_inputs=[], tx_outputs=outs)
    t.txid = lambda: txid  # type: ignore[method-assign]
    return t


def _p2pkh_unlock(key: PrivateKey):
    pub = key.public_key().serialize()

    def _u(tx, idx):
        inp = tx.inputs[idx]
        sig = key.sign(tx.preimage(idx))
        return Script(encode_pushdata(sig + inp.sighash.to_bytes(1, "little")) + encode_pushdata(pub))

    return to_unlock_script_template(_u, lambda: 110)


def _rxd_pay(nodes: _Nodes, dest_spk: bytes, amount: int) -> str:
    """Pay ``amount`` to ``dest_spk`` at vout 0 from the RXD wallet (hand-assembled)."""
    u = max(nodes.rxd("listunspent", "1", "9999999", wallet="gravity"), key=lambda x: x["amount"])
    wif = str(nodes.rxd("dumpprivkey", u["address"], wallet="gravity"))
    key = PrivateKey(wif)
    pkh = bytes(Hex20(key.public_key().hash160()))
    spk = bytes.fromhex(u["scriptPubKey"])
    in_sats = round(u["amount"] * 1e8)
    fin = TransactionInput(
        source_transaction=_src(u["txid"], u["vout"], spk, in_sats),
        source_txid=u["txid"],
        source_output_index=u["vout"],
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
    txid = nodes.rxd("sendrawtransaction", tx.serialize().hex())
    nodes.rxd_mine(1)
    return str(txid)


class _FeeSource:
    def __init__(self, nodes: _Nodes) -> None:
        self._n = nodes

    def next_fee_input(self) -> FeeInput:
        u = max(self._n.rxd("listunspent", "1", "9999999", wallet="gravity"), key=lambda x: x["amount"])
        wif = str(self._n.rxd("dumpprivkey", u["address"], wallet="gravity"))
        pkh = bytes(Hex20(PrivateKey(wif).public_key().hash160()))
        out_spk = b"\x76\xa9\x14" + pkh + b"\x88\xac"
        txid = _rxd_pay(self._n, out_spk, 5_000_000)
        return FeeInput(txid=txid, vout=0, value=5_000_000, scriptpubkey=out_spk, wif=wif)


class _Seen:
    def __init__(self) -> None:
        self._s: set[bytes] = set()

    def reserve(self, h) -> bool:
        b = bytes(h)
        if b in self._s:
            return False
        self._s.add(b)
        return True

    def has_seen(self, h) -> bool:
        return bytes(h) in self._s

    def mark_seen(self, h) -> None:
        self._s.add(bytes(h))


# --------------------------------------------------------------------------- swap setup


class _LockedSwap:
    """A swap driven to BOTH_LOCKED on both real chains, ready for any terminal path."""

    def __init__(self, *, coord, cov, p_secret, broadcaster, t_btc, t_rxd, rxd_locked_at, rxd_amount):
        self.coord = coord
        self.cov = cov
        self.p_secret = p_secret
        self.broadcaster = broadcaster
        self.t_btc = t_btc
        self.t_rxd = t_rxd
        self.rxd_locked_at = rxd_locked_at
        self.rxd_amount = rxd_amount


async def _setup_locked_swap(nodes: _Nodes, *, t_rxd_blocks: int = 3) -> _LockedSwap:
    """Fund the BTC HTLC + the RXD covenant and drive the coordinator to BOTH_LOCKED.

    Shared by the happy path and the failure paths — all terminal scenarios branch
    from the same locked state. ``t_rxd_blocks`` is per-scenario (see below).
    """
    p_secret = SecretBytes(os.urandom(32))
    h = hashlib.sha256(p_secret.unsafe_raw_bytes()).digest()
    btc_sats = rxd_photons = 100_000
    # t_rxd_blocks varies by scenario: small (fast CSV maturity) for the refund paths,
    # large (window survives the reorg-gate wait + mined harness blocks) for the happy
    # path. t_btc keeps the >= 36-block ESTIMATED margin above t_rxd in either case.
    t_rxd = bt.Timelock(t_rxd_blocks, bt.TimeUnit.BLOCKS)
    t_btc = bt.Timelock(t_rxd_blocks + 40, bt.TimeUnit.BLOCKS)

    maker_btc = coincurve.PrivateKey(os.urandom(32))
    taker_btc_kp = generate_keypair("bcrt")
    claim_xo = coincurve.PublicKeyXOnly.from_secret(maker_btc.secret).format()
    refund_xo = coincurve.PublicKeyXOnly.from_secret(bytes(taker_btc_kp._privkey.unsafe_raw_bytes())).format()

    taker_rxd, maker_rxd = PrivateKey(os.urandom(32)), PrivateKey(os.urandom(32))
    taker_pkh = bytes(Hex20(taker_rxd.public_key().hash160()))
    maker_pkh = bytes(Hex20(maker_rxd.public_key().hash160()))
    cov = build_htlc_covenant_rxd(
        amount=rxd_photons, taker_pkh=taker_pkh, maker_pkh=maker_pkh, hashlock=h, refund_csv=t_rxd.value
    )

    terms = NegotiatedTerms(
        hashlock=h,
        btc_sats=btc_sats,
        radiant_amount=rxd_photons,
        t_btc=t_btc,
        t_rxd=t_rxd,
        asset_variant="rxd",
        genesis_ref=b"",
        taker_dest_hash=cov.expected_taker_hash,
        maker_dest_hash=cov.expected_maker_hash,
        btc_claim_pubkey_xonly=claim_xo,
        btc_refund_pubkey_xonly=refund_xo,
    )

    # Fund the taker's BTC p2wpkh from the bitcoind wallet (no dumpprivkey needed).
    nodes.btc("sendtoaddress", taker_btc_kp.p2wpkh_address, "0.01", wallet="btcw")
    nodes.btc_mine(1)
    bu = nodes.btc("scantxoutset", "start", json.dumps([{"desc": f"addr({taker_btc_kp.p2wpkh_address})"}]))["unspents"][
        0
    ]
    funding_utxo = BtcUtxo(txid=bu["txid"], vout=int(bu["vout"]), value=round(bu["amount"] * 1e8))

    broadcaster = _BtcBroadcaster(nodes)
    maker_payout = bytes.fromhex(
        nodes.btc("getaddressinfo", nodes.btc("getnewaddress", wallet="btcw"), wallet="btcw")["scriptPubKey"]
    )
    taker_payout = bytes.fromhex(
        nodes.btc("getaddressinfo", nodes.btc("getnewaddress", wallet="btcw"), wallet="btcw")["scriptPubKey"]
    )
    btc_leg = BitcoinTaprootLeg(
        network="bcrt",
        taker_keypair=taker_btc_kp,
        funding_utxo=funding_utxo,
        maker_claim_pubkey_xonly=claim_xo,
        broadcaster=broadcaster,
        funding_reader=_BtcFundingReader(nodes),
        refund_to_scriptpubkey=taker_payout,
        claim_to_scriptpubkey=maker_payout,
        fee_sats=2_000,
        min_confirmations=1,
        funding_input_type="p2wpkh",
        maker_claim_privkey=maker_btc.secret,
    )

    rxd_client = _RadiantCliClient(nodes)
    rxd_client.register_spk(cov.funded_spk)
    rxd_leg = RadiantCovenantLeg(
        network="bcrt",
        taker_pkh=taker_pkh,
        maker_pkh=maker_pkh,
        chain_io=RadiantChainIO(rxd_client),
        fee_source=_FeeSource(nodes),
        min_confirmations=1,
    )

    coord = SwapCoordinator(
        record=SwapRecord(state=SwapState.NEGOTIATED, terms=terms),
        btc_leg=btc_leg,
        radiant_leg=rxd_leg,
        indexer=None,
        seen_store=_Seen(),
        config=CoordinatorConfig(margin_policy=MarginPolicy.estimated()),
    )

    # 1. Taker funds the BTC HTLC.
    rec = await coord.taker_funds_btc(terms)
    assert rec.state is SwapState.BTC_LOCKED
    assert rec.btc_locator.amount_sats == btc_sats

    # 2. Maker locks the RXD asset; taker re-validates the on-chain covenant SPK.
    rxd_locked_at = int(nodes.rxd("getblockcount"))
    _rxd_pay(nodes, cov.funded_spk, rxd_photons)
    rec = await coord.post_asset_lock_revalidate(cov.funded_spk)
    assert rec.state is SwapState.BOTH_LOCKED

    return _LockedSwap(
        coord=coord,
        cov=cov,
        p_secret=p_secret,
        broadcaster=broadcaster,
        t_btc=t_btc,
        t_rxd=t_rxd,
        rxd_locked_at=rxd_locked_at,
        rxd_amount=rxd_photons,
    )


# --------------------------------------------------------------------------- the swaps


class TestCrossChainSwap:
    async def test_happy_path_completes(self, nodes):
        """Maker claims BTC (reveals p), taker scrapes p and claims the RXD asset."""
        # Large t_rxd so the reorg-gate wait (bury the BTC claim) + the harness's own
        # mined RXD blocks still leave the t_rxd window open -> the gate returns SAFE.
        s = await _setup_locked_swap(nodes, t_rxd_blocks=60)
        coord = s.coord

        # 3. Maker claims the BTC, revealing p on the Bitcoin chain.
        rec = await coord.maker_claims_btc(s.p_secret)
        assert rec.state is SwapState.SECRET_REVEALED
        claim_raw = list(s.broadcaster.last_raw.values())[-1]

        # Reorg gate: bury the maker's BTC claim to the policy's reorg-safe depth
        # before the taker relies on the revealed p (t_rxd window has ample room).
        nodes.btc_mine(coord.config.margin_policy.btc_claim_reorg_depth.value)

        # 4. Taker scrapes p from the BTC claim and claims the RXD asset (SAFE).
        now = int(nodes.rxd("getblockcount"))
        rec = await coord.taker_scrape_and_claim_asset(
            claim_raw, now_rxd_height=now, asset_locked_at_height=s.rxd_locked_at
        )
        assert rec.state is SwapState.COMPLETED

        cov_txid = rec.radiant_covenant_outpoint.split(":")[0]
        assert nodes.rxd("gettxout", cov_txid, "0") in (None, ""), (
            "RXD covenant should be spent after the taker's claim"
        )

    async def test_reorg_gate_waits_for_shallow_btc_claim_then_claims_when_deep(self, nodes):
        """Reorg gate on real nodes: a shallow maker BTC claim returns WAIT (no asset
        claim, state unchanged); burying it to the reorg-safe depth flips it to SAFE
        and the asset settles. This is the D4 protection against a BTC-claim reorg
        after p is public."""
        s = await _setup_locked_swap(nodes, t_rxd_blocks=60)
        coord = s.coord
        depth = coord.config.margin_policy.btc_claim_reorg_depth.value

        # Maker claims BTC. The broadcaster mines 1 block, so the claim is ~1 conf —
        # shallower than the reorg-safe depth.
        rec = await coord.maker_claims_btc(s.p_secret)
        assert rec.state is SwapState.SECRET_REVEALED
        claim_raw = list(s.broadcaster.last_raw.values())[-1]

        # WAIT: shallow claim, but the t_rxd window still has room -> do NOT claim;
        # the record stays SECRET_REVEALED (retryable).
        now = int(nodes.rxd("getblockcount"))
        rec = await coord.taker_scrape_and_claim_asset(
            claim_raw, now_rxd_height=now, asset_locked_at_height=s.rxd_locked_at
        )
        assert rec.state is SwapState.SECRET_REVEALED, "shallow BTC claim must not settle the asset"

        # Bury the BTC claim to the reorg-safe depth; now the gate returns SAFE.
        nodes.btc_mine(depth)
        now = int(nodes.rxd("getblockcount"))
        rec = await coord.taker_scrape_and_claim_asset(
            claim_raw, now_rxd_height=now, asset_locked_at_height=s.rxd_locked_at
        )
        assert rec.state is SwapState.COMPLETED
        cov_txid = rec.radiant_covenant_outpoint.split(":")[0]
        assert nodes.rxd("gettxout", cov_txid, "0") in (None, ""), "asset should settle once the BTC claim is deep"

    async def test_mutual_refund_when_maker_never_claims(self, nodes):
        """The guaranteed-safe failure: maker never claims, both timeouts elapse, both
        legs refund via CSV — neither party suffers one-sided loss."""
        s = await _setup_locked_swap(nodes)
        coord = s.coord
        loc = coord.record.btc_locator

        # Maker never claims. Mature BOTH relative timelocks (BTC t_btc, RXD t_rxd).
        nodes.btc_mine(s.t_btc.value)
        nodes.rxd_mine(s.t_rxd.value)

        rec = await coord.mutual_refund()
        assert rec.state is SwapState.MUTUAL_REFUND

        # Both locked UTXOs are now spent (refunded) on their chains.
        btc_spent = nodes.btc("gettxout", loc.funding_outpoint.txid, str(loc.funding_outpoint.vout))
        rxd_spent = nodes.rxd("gettxout", coord.record.radiant_covenant_outpoint.split(":")[0], "0")
        assert btc_spent in (None, ""), "BTC HTLC should be refunded (spent)"
        assert rxd_spent in (None, ""), "RXD covenant should be refunded (spent)"

    async def test_maker_stall_asset_only_refund_mechanics(self, nodes):
        """Exercises the maybe_refund_asset_on_maker_stall MECHANICS (the helper still exists as a
        maker-side primitive). NOTE: its CSV refund pays the MAKER, not the taker — see
        TestMakerStallAssetOnlyRefundIsTakerLoss for why this is NOT a taker recovery. The watchtower
        no longer routes a taker here (FSM finding #2); the safe taker recovery is mutual_refund."""
        s = await _setup_locked_swap(nodes)
        coord = s.coord

        # Mature the RXD CSV so the proactive asset refund is spendable.
        nodes.rxd_mine(s.t_rxd.value)
        now = int(nodes.rxd("getblockcount"))

        rec = await coord.maybe_refund_asset_on_maker_stall(
            now_block_height=now, asset_locked_at_height=s.rxd_locked_at, maker_has_claimed_btc=False
        )
        assert rec.state is SwapState.ASSET_REFUNDED_TAKER_ACTS

        rxd_spent = nodes.rxd("gettxout", coord.record.radiant_covenant_outpoint.split(":")[0], "0")
        assert rxd_spent in (None, ""), "the covenant CSV refund was broadcast (covenant spent) — pays the MAKER"


def _scan_value_for_spk(nodes: _Nodes, spk: bytes) -> int:
    """Total confirmed UTXO value (sats) currently paying ``spk`` on the RXD chain."""
    res = nodes.rxd("scantxoutset", "start", json.dumps([{"desc": f"raw({bytes(spk).hex()})"}]))
    return round(sum(u["amount"] for u in res.get("unspents", [])) * 1e8)


class TestMakerStallAssetOnlyRefundIsTakerLoss:
    """ADVERSARIAL (FSM finding #2, 2026-06-09): on the BTC<->RXD runbook the asset-only
    proactive refund (:meth:`maybe_refund_asset_on_maker_stall`) is NOT a taker defense — its
    CSV refund pays the MAKER. If a taker is driven to run it on a maker stall (which the BTC
    watchtower/runbook recommends: decide.py:311-349 + dust_swap_run.py:327), it DESTROYS the
    taker's only recourse (the claimable covenant) while the taker's own BTC is still locked
    until ``t_btc``. The maker, still privately holding ``p``, then claims the BTC (claim leaf is
    maker-only, valid until ``t_btc``) and takes BOTH legs.

    Contrast :meth:`TestCrossChainSwap.test_mutual_refund_when_maker_never_claims`, which unwinds
    BOTH legs safely — the recovery the ETH path already mandates (decide.py:508-542)."""

    async def test_asset_only_refund_gifts_asset_to_maker_then_maker_takes_btc(self, nodes):
        # Small t_rxd (fast CSV), t_btc = t_rxd + 40 so the taker's BTC refund leaf is NOWHERE
        # near open when the asset-only refund fires — the crux of the asymmetry.
        s = await _setup_locked_swap(nodes, t_rxd_blocks=3)
        coord = s.coord
        loc = coord.record.btc_locator
        cov_value = s.rxd_amount

        # Sanity: before the refund, the asset sits in the covenant; neither party's holder
        # script holds it yet.
        assert _scan_value_for_spk(nodes, s.cov.maker_holder_script) == 0
        assert _scan_value_for_spk(nodes, s.cov.taker_holder_script) == 0

        # 1. Maker stalls (never claims BTC; p stays private). The taker is driven to the
        #    asset-only proactive refund. Mature the RXD CSV so the refund is BIP68-spendable.
        nodes.rxd_mine(s.t_rxd.value)
        now = int(nodes.rxd("getblockcount"))
        rec = await coord.maybe_refund_asset_on_maker_stall(
            now_block_height=now, asset_locked_at_height=s.rxd_locked_at, maker_has_claimed_btc=False
        )
        assert rec.state is SwapState.ASSET_REFUNDED_TAKER_ACTS
        nodes.rxd_mine(1)  # confirm the refund tx so scantxoutset sees the new output

        # 2. THE BUG: the "taker's" proactive refund paid the MAKER, not the taker. The asset is
        #    now back with the maker and the taker has NO covenant left to claim.
        maker_got = _scan_value_for_spk(nodes, s.cov.maker_holder_script)
        taker_got = _scan_value_for_spk(nodes, s.cov.taker_holder_script)
        assert maker_got == cov_value, "the asset-only CSV refund pays the MAKER (maker_holder_script)"
        assert taker_got == 0, "the taker recovered NOTHING from the covenant — its recourse is gone"

        # 3. The taker's own BTC is STILL LOCKED: t_btc has not elapsed, so the refund leaf is not
        #    open. The taker cannot recover the BTC yet.
        funding_confs = int(nodes.btc("getrawtransaction", loc.funding_outpoint.txid, "true").get("confirmations", 0))
        assert funding_confs < s.t_btc.value, "precondition: taker's BTC refund leaf must NOT be open yet"

        # 4. The adversarial maker, still holding p, claims the BTC directly (bypassing the honest
        #    coordinator — the FSM is terminal). The claim leaf is maker-only and valid until t_btc.
        claim_txid = await coord.btc_leg.claim(loc, s.p_secret.unsafe_raw_bytes())
        claim_decoded = nodes.btc("decoderawtransaction", s.broadcaster.last_raw[claim_txid].hex())

        # 5. The maker now holds BOTH legs; the taker holds neither (one-sided taker loss).
        btc_spent = nodes.btc("gettxout", loc.funding_outpoint.txid, str(loc.funding_outpoint.vout))
        assert btc_spent in (None, ""), "maker claimed the taker's BTC HTLC (spent)"
        assert claim_decoded["vout"], "the maker's BTC claim produced an output (to its own payout SPK)"
        # The maker ends with the asset (RXD) AND the BTC; the taker is wiped out.
        assert maker_got == cov_value and btc_spent in (None, "")


# --------------------------------------------------------------------------- watchtower observation
#
# The alert-only watchtower (v1) watches the SAME regtest swap the coordinator drives and PAGES the
# operator with the due action — it broadcasts nothing, holds no key, never touches p. These thin,
# READ-ONLY chain sources back the PRODUCTION ChainObserver against the two regtest nodes; decide(),
# ChainObserver and DedupAlerter all run UNCHANGED, so a green run proves the real decision core emits
# the correct Intent on real consensus (not a fake).
#
#   * _RegtestBtcClaimSource — maker-claim detection (is the HTLC funding outpoint spent?) + the
#     claim's confirmation depth (the reorg-gate input), both derived purely from block data.
#   * _RegtestRxdChainSource — RXD tip + covenant confirmation depth (→ asset-lock height).
#
# Estimated policy (the harness default): btc_claim_reorg_depth = rxd_claim_burial = 6, safety window
# = 6, so the gate reduces to blocks_left = t_rxd - cov_confs + 1, where a SAFE claim needs the BTC
# claim >= 6 deep AND blocks_left >= 6; a shallow claim WAITs only while blocks_left >= 18, else
# SQUEEZES; a maker stall pages a refund once blocks_left <= 6.


def _find_btc_spender(nodes: _Nodes, funding_txid: str, vout: int) -> str | None:
    """The txid that spent ``funding_txid:vout`` (the maker's claim), found purely from block data —
    no reliance on the broadcaster's memory or an address index (regtest has no Esplora outspend)."""
    info = nodes.btc("getrawtransaction", funding_txid, "true")
    bh = info.get("blockhash") if isinstance(info, dict) else None
    start = int(nodes.btc("getblock", bh)["height"]) if bh else 0
    tip = int(nodes.btc("getblockcount"))
    for h in range(start, tip + 1):
        blk = nodes.btc("getblock", str(nodes.btc("getblockhash", str(h))), "2")
        for tx in blk.get("tx", []):
            for vin in tx.get("vin", []):
                if vin.get("txid") == funding_txid and int(vin.get("vout", -1)) == vout:
                    return str(tx["txid"])
    return None


class _RegtestBtcClaimSource:
    """``BtcClaimSource`` backed by the regtest bitcoind (read-only)."""

    def __init__(self, nodes: _Nodes) -> None:
        self._n = nodes

    async def claim_status(self, funding_txid: str, funding_vout: int) -> BtcClaimStatus:
        utxo = self._n.btc("gettxout", funding_txid, str(funding_vout))
        if isinstance(utxo, dict):  # still in the UTXO set -> unspent -> maker has NOT claimed
            return BtcClaimStatus(claimed=False)
        spender = _find_btc_spender(self._n, funding_txid, funding_vout)
        if spender is None:
            # Spent but the spender is unfindable: surface it so the gate fails closed, rather than
            # reporting "not claimed" (which would silently drop a revealed swap into WATCH).
            raise NetworkError(f"funding {funding_txid}:{funding_vout} is spent but its spender was not found")
        return BtcClaimStatus(claimed=True, claim_txid=spender)

    async def confirmations(self, claim_txid: str) -> int:
        info = self._n.btc("getrawtransaction", claim_txid, "true")
        return int(info.get("confirmations", 0) or 0) if isinstance(info, dict) else 0

    async def funding_confirmations(self, funding_txid: str) -> int | None:
        info = self._n.btc("getrawtransaction", funding_txid, "true")
        return int(info.get("confirmations", 0) or 0) if isinstance(info, dict) else None


class _RegtestRxdChainSource:
    """``RxdChainSource`` backed by the regtest radiantd (single-source → low-corroboration in v1)."""

    def __init__(self, nodes: _Nodes) -> None:
        self._n = nodes

    async def tip_height(self) -> int:
        return int(self._n.rxd("getblockcount"))

    async def covenant_confirmations(self, outpoint: str) -> int | None:
        info = self._n.rxd("getrawtransaction", outpoint.split(":")[0], "true")
        confs = int(info.get("confirmations", 0) or 0) if isinstance(info, dict) else 0
        return confs if confs >= 1 else None


class _LiveRecordStore:
    """Feeds the coordinator's LIVE record to the reconciler each tick (read-only; v1 never writes)."""

    def __init__(self, coord: SwapCoordinator, swap_id: str = "wt-e2e") -> None:
        self._coord = coord
        self._id = swap_id

    async def list_active(self) -> list[tuple[str, SwapRecord]]:
        return [(self._id, self._coord.record)]


class _RecordingChannel:
    """Captures delivered Pages so the test can assert the alert payload (the shell's real channel
    is authenticated; here we only need to observe what the alerter routed)."""

    def __init__(self) -> None:
        self.pages: list[Page] = []

    async def send(self, page: Page) -> None:
        self.pages.append(page)


def _watchtower(nodes: _Nodes, coord: SwapCoordinator) -> tuple[Reconciler, _RecordingChannel]:
    """Wire the PRODUCTION reconciler (real decide/ChainObserver/DedupAlerter) to observe ``coord``'s
    swap on the two regtest nodes, with the SAME policy + safety window the coordinator runs."""
    channel = _RecordingChannel()
    reconciler = Reconciler(
        store=_LiveRecordStore(coord),
        observer=ChainObserver(
            btc=_RegtestBtcClaimSource(nodes),
            rxd=_RegtestRxdChainSource(nodes),
            rxd_corroborated=False,  # v1: RXD is single-source → every page is flagged low-corroboration
        ),
        alerter=DedupAlerter(channel=channel),
        policy=coord.config.margin_policy,
        safety_window_blocks=coord.config.maker_stall_safety_window_blocks,
    )
    return reconciler, channel


class TestWatchtowerIntentSequence:
    """The alert-only watchtower observes the regtest swap the coordinator drives and emits the
    correct Intent SEQUENCE for happy / reorg-WAIT / maker-stall / SQUEEZED — and NEVER pages
    PAGE_CLAIM against a WAIT/SQUEEZED gate verdict (plan AC 2026-06-03, :109). It broadcasts
    nothing: the production decide()/ChainObserver/DedupAlerter run unchanged against real consensus
    on both chains. (blocks_left = t_rxd - cov_confs + 1; estimated policy → reorg depth 6, burial 6,
    safety window 6.)"""

    async def _tick_one(self, reconciler: Reconciler):
        results = await reconciler.tick()
        assert len(results) == 1, "exactly one swap is being watched"
        return results[0]

    async def test_happy_path_watch_then_wait_then_page_claim(self, nodes):
        """Wide t_rxd window: pre-reveal WATCH → maker reveals shallow (gate WAIT → still WATCH, the
        headline 'never claim on a reorg-unsafe BTC claim' invariant) → bury deep (gate SAFE) →
        PAGE_CLAIM with the deadline + the named coordinator step."""
        s = await _setup_locked_swap(nodes, t_rxd_blocks=60)
        coord = s.coord
        reconciler, channel = _watchtower(nodes, coord)
        depth = coord.config.margin_policy.btc_claim_reorg_depth.value

        # 1. Both legs locked, maker has not revealed p, deadline far → WATCH (no page).
        r = await self._tick_one(reconciler)
        assert r.decision.intent is Intent.WATCH
        assert r.alert_delivered is None
        assert channel.pages == []

        # 2. Maker claims the BTC (reveals p); the broadcaster mines 1 block → ~1 conf, shallower
        #    than the reorg-safe depth. The gate is WAIT → the tower must keep WATCHING and must NOT
        #    page a claim on a reorg-unsafe BTC claim (the headline safety invariant).
        rec = await coord.maker_claims_btc(s.p_secret)
        assert rec.state is SwapState.SECRET_REVEALED
        r = await self._tick_one(reconciler)
        assert r.decision.intent is Intent.WATCH, "must not PAGE_CLAIM against a WAIT gate verdict"
        assert channel.pages == []

        # 3. Bury the BTC claim to the reorg-safe depth → gate SAFE → PAGE_CLAIM.
        nodes.btc_mine(depth)
        r = await self._tick_one(reconciler)
        assert r.decision.intent is Intent.PAGE_CLAIM
        assert r.decision.recommended_action == "taker_scrape_and_claim_asset"
        assert r.decision.deadline_rxd_height is not None
        assert r.alert_delivered is True
        assert len(channel.pages) == 1
        page = channel.pages[0]
        assert page.intent is Intent.PAGE_CLAIM
        assert page.severity is Severity.CRITICAL
        assert page.low_corroboration is True  # RXD single-source in v1
        assert page.deadline_rxd_height == r.decision.deadline_rxd_height

        # Dedup: re-ticking the same SAFE situation does not re-page (still 1).
        r = await self._tick_one(reconciler)
        assert r.decision.intent is Intent.PAGE_CLAIM
        assert len(channel.pages) == 1, "DedupAlerter must not re-page an unchanged situation"

    async def test_maker_stall_watch_then_page_refund(self, nodes):
        """Maker locks the asset then stalls (never reveals p). As t_rxd nears, the tower pages the
        safe both-legs recovery — mutual_refund (WARN — recoverable, not a race), NOT the asset-only
        refund that pays the maker (FSM finding #2). The page names the coordinator step."""
        s = await _setup_locked_swap(nodes, t_rxd_blocks=30)
        coord = s.coord
        reconciler, channel = _watchtower(nodes, coord)

        # 1. Just locked: blocks_left = 30 (>> safety window 6) → WATCH.
        r = await self._tick_one(reconciler)
        assert r.decision.intent is Intent.WATCH
        assert channel.pages == []

        # 2. Advance RXD toward t_rxd maturity (cov_confs → 28 ⇒ blocks_left = 3 ≤ 6) → PAGE_REFUND.
        nodes.rxd_mine(27)
        r = await self._tick_one(reconciler)
        assert r.decision.intent is Intent.PAGE_REFUND
        assert r.decision.recommended_action == "mutual_refund"
        assert r.decision.deadline_rxd_height is not None
        assert r.alert_delivered is True
        assert len(channel.pages) == 1
        assert channel.pages[0].severity is Severity.WARN  # a stall refund is recoverable, not a race
        assert channel.pages[0].low_corroboration is True

    async def test_reveal_with_closing_window_pages_squeezed(self, nodes):
        """Tight t_rxd window + a shallow reveal: there is no longer room to wait for a reorg-safe
        burial before the maker's CSV refund opens → the gate SQUEEZES → a decision-required
        PAGE_SQUEEZED (winner-take-all vs accept loss), never a silent claim or a silent wait."""
        s = await _setup_locked_swap(nodes, t_rxd_blocks=10)
        coord = s.coord
        reconciler, channel = _watchtower(nodes, coord)

        # 1. Pre-reveal, window not yet near → WATCH.
        r = await self._tick_one(reconciler)
        assert r.decision.intent is Intent.WATCH
        assert channel.pages == []

        # 2. Maker reveals p with ~1 conf and blocks_left = 10 (< the 18 a WAIT requires): SQUEEZED.
        rec = await coord.maker_claims_btc(s.p_secret)
        assert rec.state is SwapState.SECRET_REVEALED
        r = await self._tick_one(reconciler)
        assert r.decision.intent is Intent.PAGE_SQUEEZED
        assert r.alert_delivered is True
        assert len(channel.pages) == 1
        assert channel.pages[0].intent is Intent.PAGE_SQUEEZED
        assert channel.pages[0].severity is Severity.CRITICAL
        assert channel.pages[0].low_corroboration is True


# ---------------------------------------------------------------------------------------------------
# v2 AUTONOMOUS refund (capped, keyless, dormant-by-construction) — REAL bitcoind consensus.
#
# Proves the two facts the pure/property suite cannot: (1) the production RefundExecutor broadcasts an
# operator-PRE-SIGNED refund that actually SPENDS the funding outpoint on real consensus once the CSV
# matures; (2) an EARLY broadcast is REJECTED by BIP68 (the consensus backstop the design relies on).
# Through the real executor; it holds no key, never rebuilds, broadcasts only the stored bytes.
# ---------------------------------------------------------------------------------------------------


class TestWatchtowerAutonomousRefundRegtest:
    async def test_auto_refund_spends_outpoint_after_maturity_and_early_is_rejected(self, nodes, tmp_path):
        from pyrxd.gravity.watch import Decision, ExecOutcome, PresignedRefund, RefundExecutor

        t_btc = bt.Timelock(6, bt.TimeUnit.BLOCKS)
        t_rxd = bt.Timelock(3, bt.TimeUnit.BLOCKS)
        h = hashlib.sha256(os.urandom(32)).digest()
        maker_btc = coincurve.PrivateKey(os.urandom(32))
        taker_kp = generate_keypair("bcrt")
        refund_priv = bytes(taker_kp._privkey.unsafe_raw_bytes())
        refund_xo = coincurve.PublicKeyXOnly.from_secret(refund_priv).format()
        claim_xo = coincurve.PublicKeyXOnly.from_secret(maker_btc.secret).format()
        htlc = bt.build_htlc(
            hashlock=h, claim_pubkey_xonly=claim_xo, refund_pubkey_xonly=refund_xo, timeout=t_btc, network="bcrt"
        )

        # Fund the HTLC address on bitcoind regtest, find the funding outpoint.
        btc_sats = 200_000
        nodes.btc("sendtoaddress", htlc.address, f"{btc_sats / 1e8:.8f}", wallet="btcw")
        nodes.btc_mine(1)
        scan = nodes.btc("scantxoutset", "start", json.dumps([{"desc": f"raw({htlc.scriptpubkey.hex()})"}]))
        u = scan["unspents"][0]
        loc = htlc.with_funding(bt.BtcOutpoint(u["txid"], int(u["vout"])), round(u["amount"] * 1e8))

        # Operator pre-signs the refund (ONCE, online) to a fresh payout address; tower will pin this SPK.
        dest = bytes.fromhex(
            nodes.btc("getaddressinfo", nodes.btc("getnewaddress", wallet="btcw"), wallet="btcw")["scriptPubKey"]
        )
        raw = bt.build_refund_tx(
            locator=loc,
            refund_privkey=refund_priv,
            timeout=t_btc,
            to_scriptpubkey=dest,
            fee_sats=2_000,
            aux_rand=os.urandom(32),
        )
        blob = PresignedRefund(raw_tx=raw, swap_id="auto1")
        (tmp_path / "auto1.refund.json").write_text(json.dumps(blob.to_dict()))

        # (1) NEGATIVE — broadcasting BEFORE the CSV matures is rejected by BIP68 (consensus backstop).
        with pytest.raises(RuntimeError) as ei:
            nodes.btc("sendrawtransaction", raw.hex())
        assert "non-BIP68-final" in str(ei.value) or "non-final" in str(ei.value)

        # Mature the relative CSV to EXACTLY t_btc confirmations (the empirically-verified BIP68 boundary:
        # bitcoind accepts the relative-N refund at confs == N, rejects at N-1). Funding is at 1 conf, so
        # mine t_btc.value - 1 more → confs == t_btc.value. This pins decide()'s `confs >= N` gate as correct.
        nodes.btc_mine(t_btc.value - 1)
        assert int(nodes.btc("getrawtransaction", loc.funding_outpoint.txid, "true")["confirmations"]) == t_btc.value

        # (2) POSITIVE — the production executor broadcasts the stored bytes; the outpoint is spent.
        terms = NegotiatedTerms(
            hashlock=h,
            btc_sats=btc_sats,
            radiant_amount=1,
            t_btc=t_btc,
            t_rxd=t_rxd,
            asset_variant="rxd",
            genesis_ref=b"",
            taker_dest_hash=b"\x11" * 32,
            maker_dest_hash=b"\x22" * 32,
            btc_claim_pubkey_xonly=claim_xo,
            btc_refund_pubkey_xonly=refund_xo,
        )
        rec = SwapRecord(state=SwapState.BTC_LOCKED, terms=terms, counterchain_locator=loc)
        ex = RefundExecutor(
            broadcaster=_BtcBroadcaster(nodes),
            blobs_dir=tmp_path,
            network="bcrt",
            cap_sats=btc_sats,
            refund_spk=dest,
            accept_single_source=True,
        )
        dec = Decision(
            Intent.PAGE_REFUND,
            reason="matured BTC refund due",
            recommended_action="taker_refund_btc",
            autonomous_btc_refund=True,
            low_corroboration=True,
        )
        out = await ex.execute("auto1", rec, dec)
        assert out is ExecOutcome.BROADCAST
        spent = nodes.btc("gettxout", loc.funding_outpoint.txid, str(loc.funding_outpoint.vout))
        assert spent in (None, ""), "funding outpoint must be SPENT by the auto-broadcast refund on real consensus"


# scripts/ on path for the operator dust-run harness (used by the proof below).
import sys as _sys
from pathlib import Path as _Path

_HARNESS_SCRIPTS = str(_Path(__file__).resolve().parent.parent / "scripts")
if _HARNESS_SCRIPTS not in _sys.path:
    _sys.path.insert(0, _HARNESS_SCRIPTS)


class TestWatchtowerDustHarnessRegtest:
    """Prove the GO-GATED dust harness (scripts/watchtower_dust_run.py) end-to-end on real bitcoind: its
    setup→record→presign artifacts, loaded FROM DISK by the keyless production executor, broadcast a
    refund that real consensus accepts and that lands the dust at the operator's pinned refund
    scriptPubKey. This is the consensus backstop for the stranded-dust fix — it proves the funded HTLC
    is refundable from the persisted state ALONE (no in-memory carry-over, no key in the tower)."""

    async def test_harness_artifacts_drive_a_real_keyless_refund_to_the_pinned_spk(self, nodes, tmp_path):
        import watchtower_dust_run as harness

        from pyrxd.gravity.watch import Decision, ExecOutcome, PresignedRefund, RefundExecutor

        records = tmp_path / "records"
        records.mkdir()
        state_file = tmp_path / "run.state.json"
        swap_id, btc_sats, t_btc, t_rxd, fee = "dust1", 50_000, 6, 3, 2_000

        # The operator's pinned refund address (a fresh node address) → its scriptPubKey.
        dest = bytes.fromhex(
            nodes.btc("getaddressinfo", nodes.btc("getnewaddress", wallet="btcw"), wallet="btcw")["scriptPubKey"]
        )

        # STEP setup — the harness self-tests reconstruction-from-disk BEFORE printing the funding address.
        assert (
            harness.main(
                [
                    "setup",
                    "--state-file",
                    str(state_file),
                    "--swap-id",
                    swap_id,
                    "--network",
                    "bcrt",
                    "--btc-sats",
                    str(btc_sats),
                    "--t-btc",
                    str(t_btc),
                    "--t-rxd",
                    str(t_rxd),
                    "--refund-spk",
                    dest.hex(),
                ]
            )
            == 0
        )
        s = json.loads(state_file.read_text())
        fund_address, fund_spk = s["htlc_address"], s["htlc_spk"]

        # Fund the address the harness emitted; locate the outpoint.
        nodes.btc("sendtoaddress", fund_address, f"{btc_sats / 1e8:.8f}", wallet="btcw")
        nodes.btc_mine(1)
        u = nodes.btc("scantxoutset", "start", json.dumps([{"desc": f"raw({fund_spk})"}]))["unspents"][0]
        ftxid, fvout, fsats = u["txid"], int(u["vout"]), round(u["amount"] * 1e8)
        assert fsats == btc_sats

        # STEP record + STEP presign — produce the production SwapRecord + keyless sidecar on disk.
        assert (
            harness.main(
                [
                    "record",
                    "--state-file",
                    str(state_file),
                    "--funding-txid",
                    ftxid,
                    "--funding-vout",
                    str(fvout),
                    "--funding-sats",
                    str(fsats),
                    "--records-dir",
                    str(records),
                ]
            )
            == 0
        )
        assert (
            harness.main(
                ["presign", "--state-file", str(state_file), "--records-dir", str(records), "--fee-sats", str(fee)]
            )
            == 0
        )

        # ---- From here ONLY the on-disk artifacts are used (no key, no in-memory HTLC). ----
        rec = SwapRecord.from_dict(json.loads((records / f"{swap_id}.json").read_text()))
        loc = rec.btc_locator
        sidecar = PresignedRefund.from_dict(json.loads((records / f"{swap_id}.refund.json").read_text()))

        # NEGATIVE — broadcasting before the CSV matures is BIP68-rejected (consensus backstop).
        with pytest.raises(RuntimeError) as ei:
            nodes.btc("sendrawtransaction", sidecar.raw_tx.hex())
        assert "non-BIP68-final" in str(ei.value) or "non-final" in str(ei.value)

        # Mature to EXACTLY t_btc confs (funding at 1 conf → mine t_btc - 1 more).
        nodes.btc_mine(t_btc - 1)
        assert int(nodes.btc("getrawtransaction", loc.funding_outpoint.txid, "true")["confirmations"]) == t_btc

        # POSITIVE — the keyless production executor reads the SAME records dir, binds, and broadcasts.
        ex = RefundExecutor(
            broadcaster=_BtcBroadcaster(nodes),
            blobs_dir=records,
            network="bcrt",
            cap_sats=btc_sats,
            refund_spk=dest,
            accept_single_source=True,
        )
        dec = Decision(
            Intent.PAGE_REFUND,
            reason="matured BTC refund due (maker never locked)",
            recommended_action="taker_refund_btc",
            autonomous_btc_refund=True,
            low_corroboration=True,
        )
        assert await ex.execute(swap_id, rec, dec) is ExecOutcome.BROADCAST

        # The funding outpoint is SPENT and the dust LANDS at the pinned refund SPK (refundability proven).
        assert nodes.btc("gettxout", loc.funding_outpoint.txid, str(loc.funding_outpoint.vout)) in (None, "")
        decoded = nodes.btc("getrawtransaction", sidecar.txid, "true")
        assert bytes.fromhex(decoded["vout"][0]["scriptPubKey"]["hex"]) == dest
        assert round(decoded["vout"][0]["value"] * 1e8) == btc_sats - fee
