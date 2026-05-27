"""Coordinator-driven cross-chain HTLC swap on TWO real regtest nodes (T7 capstone).

The end-to-end proof that the production :class:`SwapCoordinator` drives a complete
BTC<->RXD atomic swap across REAL consensus on both chains — not fakes:

  taker_funds_btc            -> NEGOTIATED -> BTC_LOCKED   (BtcLeg funds P2TR HTLC)
  post_asset_lock_revalidate -> BOTH_LOCKED                (maker locks RXD covenant;
                                                            RadiantLeg locates it,
                                                            coordinator re-validates SPK)
  maker_claims_btc           -> SECRET_REVEALED            (maker claims BTC, reveals p)
  taker_scrape_and_claim_asset -> COMPLETED                (taker scrapes p from the BTC
                                                            claim, claims the RXD covenant)

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

_RXD_IMAGE = "radiant-core:v2.3.0-amd64"
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

    def has_seen(self, h) -> bool:
        return bytes(h) in self._s

    def mark_seen(self, h) -> None:
        self._s.add(bytes(h))


# --------------------------------------------------------------------------- the swap


class TestCrossChainSwap:
    async def test_coordinator_drives_full_btc_rxd_swap_to_completed(self, nodes):
        p_secret = SecretBytes(os.urandom(32))
        p = p_secret.unsafe_raw_bytes()
        h = hashlib.sha256(p).digest()
        btc_sats = rxd_photons = 100_000
        t_btc = bt.Timelock(40, bt.TimeUnit.BLOCKS)  # t_btc - t_rxd >= 36 (ESTIMATED margin)
        t_rxd = bt.Timelock(3, bt.TimeUnit.BLOCKS)

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
        scan = nodes.btc("scantxoutset", "start", json.dumps([{"desc": f"addr({taker_btc_kp.p2wpkh_address})"}]))
        bu = scan["unspents"][0]
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
        _rxd_pay(nodes, cov.funded_spk, rxd_photons)
        rec = await coord.post_asset_lock_revalidate(cov.funded_spk)
        assert rec.state is SwapState.BOTH_LOCKED

        # 3. Maker claims the BTC, revealing p on the Bitcoin chain.
        rec = await coord.maker_claims_btc(p_secret)
        assert rec.state is SwapState.SECRET_REVEALED
        claim_raw = list(broadcaster.last_raw.values())[-1]

        # 4. Taker scrapes p from the BTC claim and claims the RXD asset.
        rec = await coord.taker_scrape_and_claim_asset(claim_raw)
        assert rec.state is SwapState.COMPLETED

        # The Radiant covenant UTXO is spent — the swap settled on both chains.
        cov_txid = rec.radiant_covenant_outpoint.split(":")[0]
        assert nodes.rxd("gettxout", cov_txid, "0") in (None, ""), (
            "RXD covenant should be spent after the taker's claim"
        )
