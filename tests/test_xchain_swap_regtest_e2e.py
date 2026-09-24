"""Coordinator-driven cross-chain HTLC swap on TWO real regtest nodes (T7 capstone).

The end-to-end proof that the production :class:`SwapCoordinator` drives a complete
BTC<->RXD atomic swap across REAL consensus on both chains — not fakes. All paths
branch from the same BOTH_LOCKED state (``_setup_locked_swap``):

  maker funds the RXD covenant, mined                      (HZ-1: the taker MUST NOT lock
                                                            BTC against an unfunded maker)
  taker_funds_btc            -> NEGOTIATED -> BTC_LOCKED   (BtcLeg funds P2TR HTLC, only
                                                            after the HZ-1 gate reads the
                                                            covenant on the Radiant chain)
  post_asset_lock_revalidate -> BOTH_LOCKED                (RadiantLeg locates the covenant,
                                                            coordinator re-validates SPK)

* HAPPY PATH: maker_claims_btc -> SECRET_REVEALED (reveals p); then
  taker_scrape_and_claim_asset -> COMPLETED (scrapes p, claims the RXD covenant).
* MUTUAL REFUND (maker never claims): the taker's BTC refund opens FIRST (``t_btc``), the
  maker's Radiant refund LAST (``t_rxd``); once both have matured, mutual_refund refunds
  BOTH legs -> MUTUAL_REFUND. No one-sided loss.
* MAKER STALL (mechanics): ``maybe_refund_asset_on_maker_stall`` fires near ``t_rxd`` and
  CSV-refunds the covenant -> ASSET_REFUNDED_TAKER_ACTS. That refund pays the MAKER, so it is a
  maker-side primitive, not a taker recovery (see TestMakerStallAssetOnlyRefundIsTakerLoss).

THE TIMELOCKS ARE DERIVED, NEVER TYPED (see ``_derive_timelocks``). #482 inverted the required
ordering: the maker holds ``p`` and LOCKS the Radiant leg, so ``t_rxd`` is the LONGER leg in wall
clock and ``t_btc`` (the leg the maker CLAIMS) the shorter. This suite built ``t_btc = t_rxd + 40``
by hand, which is the exploitable pre-#482 layout; ``NegotiatedTerms`` refuses it at construction,
so every test in this file failed on every nightly run from 2026-09-01. The pair now comes from
the same derivation the production runners use, against the coordinator's own policy.

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
import math
import os
import secrets
import shutil
import subprocess
import sys
import time
from pathlib import Path

import coincurve
import pytest

# scripts/ on path: the ONE canonical counter-leg derivation (`derive_counter_timelock`) lives there,
# and the production runners import it from there too. Also used by the dust-harness proof below.
_HARNESS_SCRIPTS = str(Path(__file__).resolve().parent.parent / "scripts")
if _HARNESS_SCRIPTS not in sys.path:
    sys.path.insert(0, _HARNESS_SCRIPTS)

from _dust_swap_shared import derive_counter_timelock, elapsed_reserve_blocks

from pyrxd.btc_wallet import taproot as bt
from pyrxd.btc_wallet.htlc_leg import BitcoinTaprootLeg
from pyrxd.btc_wallet.keys import generate_keypair
from pyrxd.btc_wallet.payment import BtcUtxo
from pyrxd.devnet import RegtestNode
from pyrxd.gravity.finality import CounterClaimFinality
from pyrxd.gravity.htlc_covenant import build_htlc_covenant_rxd
from pyrxd.gravity.htlc_spend import FeeInput
from pyrxd.gravity.radiant_leg import RadiantChainIO, RadiantCovenantLeg
from pyrxd.gravity.swap_coordinator import (
    ClaimFinality,
    CoordinatorConfig,
    MarginPolicy,
    SwapCoordinator,
    assert_timelock_margin,
    assess_claim_finality,
)
from pyrxd.gravity.swap_state import NegotiatedTerms, SwapRecord, SwapRole, SwapState
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

#: Derived, never spelled. `scripts/refresh_radiant_core_vendor.py --check` reads
#: `DEFAULT_RADIANT_VERSION`; a literal here could drift from it and the check would
#: still pass while this lane ran a different node.
_RXD_IMAGE = RegtestNode.IMAGE
# Bitcoin-family chain knob (Tier 2.3): XCHAIN_BTC_FAMILY=ltc runs this SAME coordinator
# e2e with Litecoin Core as the counter chain (the Taproot-HTLC leg is chain-agnostic
# across the family; counter_chain stays "btc" — the PoW-depth FAMILY — and the network
# HRP + block interval pin the concrete chain). Default: Bitcoin.
_BTC_FAMILY = os.environ.get("XCHAIN_BTC_FAMILY", "btc")
if _BTC_FAMILY == "ltc":
    _BTC_IMAGE = "litecoin-core:v0.21.5.5-amd64"  # built from docker/litecoin-regtest.Dockerfile
    _BTC_CLI = "litecoin-cli"
    _BTC_HRP = "rltc"
    _BTC_INTERVAL_S = 150.0  # Litecoin 2.5-min target (see pyrxd.btc_wallet.chains)
else:
    _BTC_IMAGE = "ruimarinho/bitcoin-core:24"
    _BTC_CLI = "bitcoin-cli"
    _BTC_HRP = "bcrt"
    _BTC_INTERVAL_S = 600.0
_RXD_CT = "xchain-rxd-pytest"
_BTC_CT = "xchain-btc-pytest"
_RXD_RELAY_FEE = 1_000_000  # 0.01 RXD per sub-kB tx

#: The Radiant relay floor this suite's fees are sized for, in RXD/kB — the LEGACY 0.01,
#: a tenth of mainnet's. Passed to `radiantd` and asserted back below rather than
#: inherited from the node's default, so `_RXD_RELAY_FEE` cannot silently stop clearing
#: the rate the node enforces. (The shared Radiant harness in `test_htlc_regtest_e2e`
#: runs at the MAINNET floor; this suite proves cross-chain HTLC *sequencing*, and its
#: carriers are sized around `_RXD_RELAY_FEE`. The Radiant-side fee floors themselves are
#: proven at the mainnet rate in `tests/test_fee_floor_boundary_regtest_e2e.py` and
#: `tests/test_remaining_builder_floors_regtest_e2e.py`.)
_RXD_MIN_RELAY_RXD_PER_KB = "0.01"


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
        return self._cli(_BTC_CT, _BTC_CLI, "btc_user", self.bpass, wallet, a)

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
                f"-minrelaytxfee={_RXD_MIN_RELAY_RXD_PER_KB}",
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
        # The rate `_RXD_RELAY_FEE` is sized for, confirmed by the node itself before
        # anything is proved against it. `effective_minrelaytxfee`, not `minrelaytxfee`:
        # only the first is what AcceptToMemoryPool checks GetTotalSize() against.
        _rxd_floor = float(self.rxd("getmempoolinfo")["effective_minrelaytxfee"])
        assert _rxd_floor == float(_RXD_MIN_RELAY_RXD_PER_KB), (
            f"radiantd advertises effective_minrelaytxfee {_rxd_floor} RXD/kB, not the "
            f"{_RXD_MIN_RELAY_RXD_PER_KB} this suite's fees are sized for"
        )
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
            if img == _BTC_IMAGE and _BTC_FAMILY == "ltc":
                # Local-only image; build it from the committed Dockerfile.
                repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                dockerfile = os.path.join(repo_root, "docker", "litecoin-regtest.Dockerfile")
                if (
                    subprocess.run(
                        ["docker", "build", "-f", dockerfile, "-t", img, repo_root], capture_output=True, timeout=600
                    ).returncode
                    != 0
                ):
                    pytest.skip(f"could not build {img}")
            elif img == _BTC_IMAGE:
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

    async def read_confirmed_unspent_output(self, txid, vout) -> tuple[bytes, int]:
        # The maker-side counter-funding gate's read: the CONFIRMED UTXO set only
        # (include_mempool=false), so a spent/unconfirmed/unknown outpoint returns null -> raise.
        res = self._n.btc("gettxout", str(txid), str(int(vout)), "false")
        if not isinstance(res, dict):
            raise NetworkError("gettxout returned null — spent, unconfirmed, or unknown; fail-closed")
        return bytes.fromhex(res["scriptPubKey"]["hex"]), round(res["value"] * 1e8)

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
        # 0.2 RXD: the whole input is the miner fee (single-output covenant, no change),
        # and the leg enforces min-relay + up to a 3x deadline-urgency premium on a claim.
        txid = _rxd_pay(self._n, out_spk, 20_000_000)
        return FeeInput(txid=txid, vout=0, value=20_000_000, scriptpubkey=out_spk, wif=wif)


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


# --------------------------------------------------------------------------- the negotiated timelocks


def _policy() -> MarginPolicy:
    """The policy every swap here is BOTH negotiated against and gated by.

    One constructor, so the terms and the coordinator that judges them cannot come from two
    different policies. ESTIMATED (test-only) — the coordinator's documented test defaults.
    """
    return MarginPolicy.estimated(block_interval_s=_BTC_INTERVAL_S)


def _derive_timelocks(policy: MarginPolicy, *, t_rxd_blocks: int) -> tuple[bt.Timelock, bt.Timelock]:
    """``(t_btc, t_rxd)`` for a Radiant window of ``t_rxd_blocks``, derived as the BTC runners derive it.

    ``t_btc`` comes from ``derive_counter_timelock`` — the shared definition
    ``scripts/btc_swap_two_host.py`` negotiates with — fed THIS policy's margin, both chains'
    intervals, and the elapsed-depth reserve coupled to the policy's claim burial.

    The result is then put to the production gate at every elapsed depth that reserve covers —
    the call ``pre_btc_lock_check`` really makes (step 7 passes ``elapsed_blocks=cov_confs``) — so
    a fixture that drifts from the invariant fails HERE, with the gate's own reason, instead of as
    a refusal deep inside a swap.
    """
    for name in ("margin", "rxd_claim_burial"):
        if getattr(policy, name).unit is not bt.TimeUnit.BLOCKS:
            raise AssertionError(f"policy.{name} must be BLOCKS-tagged for the block-count derivation")
    reserve = elapsed_reserve_blocks(rxd_claim_burial_blocks=policy.rxd_claim_burial.value)
    t_btc = bt.Timelock(
        derive_counter_timelock(
            t_rxd_blocks=t_rxd_blocks,
            margin_blocks=policy.margin.value,
            rxd_block_interval_s=policy.rxd_block_interval_s,
            btc_block_interval_s=policy.block_interval_s,
            elapsed_reserve_blocks=reserve,
        ),
        bt.TimeUnit.BLOCKS,
    )
    t_rxd = bt.Timelock(t_rxd_blocks, bt.TimeUnit.BLOCKS)
    for elapsed in range(reserve + 1):
        assert_timelock_margin(t_btc, t_rxd, policy, elapsed_blocks=elapsed)
    return t_btc, t_rxd


def _shortest_t_rxd_blocks(policy: MarginPolicy) -> int:
    """The shortest Radiant window whose derived counter leg is LONGER than the BTC reorg depth.

    A MEASURED maker does not reveal ``p`` until the taker's BTC funding is
    ``btc_claim_reorg_depth`` deep (``SwapCoordinator._btc_counter_funding_depth``). A counter leg
    no longer than that depth has its refund spendable by the time such a maker may reveal, so its
    claim would race the taker's refund; one block more is the shortest leg in which the maker's
    claim, mined in the next block, confirms before the refund becomes spendable.

    Found by asking the derivation for each candidate rather than by inverting it here, so this
    and ``derive_counter_timelock`` cannot disagree. Short on purpose: every refund scenario has to
    mine the whole window on regtest.
    """
    need = policy.btc_claim_reorg_depth.value + 1
    for t_rxd_blocks in range(1, 10_000):
        try:
            t_btc, _t_rxd = _derive_timelocks(policy, t_rxd_blocks=t_rxd_blocks)
        except SystemExit:  # derive_counter_timelock's "no room for a counter leg"
            continue
        if t_btc.value >= need:
            return t_rxd_blocks
    raise AssertionError(f"no t_rxd below 10000 derives a counter leg of {need} blocks under {policy}")


def _fewest_blocks_left_that_wait(policy: MarginPolicy, shallow: CounterClaimFinality | None = None) -> int:
    """The fewest Radiant blocks before the maker's refund at which the coordinator still WAITs on a
    not-yet-final counter-leg claim (by default a 1-confirmation BTC claim) — asked of
    ``assess_claim_finality`` itself, so a test that squeezes "just under the floor" cannot drift
    from the gate that decides it."""
    if shallow is None:
        shallow = CounterClaimFinality.from_btc_depth(1, policy.btc_claim_reorg_depth.value)
    for blocks_left in range(1, 10_000):
        verdict = assess_claim_finality(
            counter_claim_finality=shallow,
            now_rxd_height=0,
            asset_locked_at_height=0,
            t_rxd=bt.Timelock(blocks_left, bt.TimeUnit.BLOCKS),
            policy=policy,
        )
        if verdict is ClaimFinality.WAIT:
            return blocks_left
    raise AssertionError(f"assess_claim_finality never WAITs below 10000 blocks under {policy}")


def _btc_blocks_during(policy: MarginPolicy, rxd_blocks: int) -> int:
    """BTC blocks at the policy's nominal interval in the wall clock ``rxd_blocks`` Radiant blocks take.

    FLOORED: use it where the assertion that follows is "the BTC leg has ALREADY matured", so
    rounding can only make that assertion harder to pass.
    """
    return int(rxd_blocks * policy.rxd_block_interval_s // policy.block_interval_s)


def _rxd_blocks_during(policy: MarginPolicy, btc_blocks: int) -> int:
    """Radiant blocks at the policy's nominal interval in the wall clock ``btc_blocks`` BTC blocks take.

    CEILED: use it where the assertion that follows is "the Radiant leg has NOT yet matured", so
    rounding can only make that assertion harder to pass.
    """
    return math.ceil(btc_blocks * policy.block_interval_s / policy.rxd_block_interval_s)


def _btc_confs(nodes: _Nodes, txid: str) -> int:
    return int(nodes.btc("getrawtransaction", txid, "true").get("confirmations", 0) or 0)


def _rxd_confs(nodes: _Nodes, txid: str) -> int:
    return int(nodes.rxd("getrawtransaction", txid, "true").get("confirmations", 0) or 0)


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


async def _setup_locked_swap(nodes: _Nodes, *, role=None) -> _LockedSwap:
    """Fund the BTC HTLC + the RXD covenant and drive the coordinator to BOTH_LOCKED.

    Shared by the happy path and the failure paths — all terminal scenarios branch from the same
    locked state, with the same derived timelocks. A scenario that needs a CLOSING Radiant window
    mines towards it from here rather than negotiating a smaller ``t_rxd``: a window short enough
    to be closing at the reveal cannot also carry the margin, and the gate refuses it before any
    lock.
    """
    p_secret = SecretBytes(os.urandom(32))
    h = hashlib.sha256(p_secret.unsafe_raw_bytes()).digest()
    btc_sats = rxd_photons = 100_000
    policy = _policy()
    t_btc, t_rxd = _derive_timelocks(policy, t_rxd_blocks=_shortest_t_rxd_blocks(policy))

    maker_btc = coincurve.PrivateKey(os.urandom(32))
    taker_btc_kp = generate_keypair(_BTC_HRP)
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
        network=_BTC_HRP,
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
        network=_BTC_HRP,
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
        config=CoordinatorConfig(margin_policy=policy, role=role),
    )

    # 1. MAKER locks the RXD asset FIRST, and it is mined (HZ-1). The taker's pre-BTC-lock
    #    gate reads the Radiant chain for this exact covenant SPK, binds its on-chain value to
    #    terms.radiant_amount, and requires min_confirmations of burial — so an unfunded or
    #    mempool-only covenant refuses to let step 2 fund anything. ``_rxd_pay`` mines a block,
    #    which satisfies the leg's min_confirmations=1 (the estimated test policy defers the
    #    depth to the leg). Ordering per docs/htlc-handshake-wire-format.md HZ-1 and
    #    scripts/btc_swap_two_host.py; the FSM still records the taker's lock as the first
    #    TRANSITION, because the requirement is a precondition on that transition, not an edge.
    rxd_locked_at = int(nodes.rxd("getblockcount"))
    _rxd_pay(nodes, cov.funded_spk, rxd_photons)

    # 2. Taker funds the BTC HTLC — this now runs the HZ-1 gate against a genuinely funded,
    #    mined covenant (twice: once in pre_btc_lock_check, once re-run inside taker_funds_btc
    #    immediately before the broadcast, which is what closes the verify->lock TOCTOU).
    rec = await coord.taker_funds_btc(terms)
    assert rec.state is SwapState.BTC_LOCKED
    assert rec.btc_locator.amount_sats == btc_sats

    # 3. Taker re-validates the on-chain covenant SPK and advances to BOTH_LOCKED.
    rec = await coord.post_asset_lock_revalidate(cov.funded_spk)
    assert rec.state is SwapState.BOTH_LOCKED

    # Not a fiction: BOTH_LOCKED is where the maker may reveal p, and under the #482 ordering the
    # counter leg is the SHORT one. A fixture whose BTC refund were already spendable here would have
    # every scenario below reveal p into an open refund race without saying so.
    assert _btc_confs(nodes, rec.btc_locator.funding_outpoint.txid) < t_btc.value, (
        "fixture: the taker's BTC refund must still be closed when the swap reaches BOTH_LOCKED"
    )

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
        s = await _setup_locked_swap(nodes)
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
        s = await _setup_locked_swap(nodes)
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
        assert isinstance(nodes.rxd("gettxout", rec.radiant_covenant_outpoint.split(":")[0], "0"), dict), (
            "WAIT must broadcast nothing: the covenant is still unspent"
        )

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
        """The guaranteed-safe failure: the maker never claims, and BOTH legs refund.

        In the order the #482 ordering produces: the taker's BTC refund (``t_btc``, the short leg)
        becomes spendable while the maker's Radiant refund (``t_rxd``) is still locked, with both
        chains advanced in step at the policy's nominal block intervals so the two readings are taken
        at the same wall clock. Only once ``t_rxd`` has also matured does ``mutual_refund`` run, and it
        refunds both legs -> MUTUAL_REFUND. Neither party suffers a one-sided loss.

        ``mutual_refund`` is called once, after BOTH have matured. Called between the two maturities
        it refunds the counter leg, fails on the covenant and leaves the record at BOTH_LOCKED, which
        is why the two-host runner's refund phase checks both timeouts before broadcasting anything.
        """
        s = await _setup_locked_swap(nodes)
        coord = s.coord
        policy = coord.config.margin_policy
        loc = coord.record.btc_locator
        cov_txid = coord.record.radiant_covenant_outpoint.split(":")[0]

        # 1. The maker never claims. Advance BTC to the block the taker's refund matures at, and
        #    Radiant by the same wall clock.
        btc_to_go = s.t_btc.value - _btc_confs(nodes, loc.funding_outpoint.txid)
        nodes.btc_mine(btc_to_go)
        nodes.rxd_mine(_rxd_blocks_during(policy, btc_to_go))
        assert _btc_confs(nodes, loc.funding_outpoint.txid) >= s.t_btc.value, "the taker's BTC refund is open"
        # ...while the maker's Radiant refund is still closed: the production leg's own maturity check
        # refuses it, before it takes a fee input or broadcasts anything.
        assert _rxd_confs(nodes, cov_txid) < s.t_rxd.value
        with pytest.raises(NetworkError, match="not yet mature"):
            await coord.radiant_leg.refund_asset(coord.record)
        assert isinstance(nodes.rxd("gettxout", cov_txid, "0"), dict), "the covenant is still unspent"

        # 2. The maker's Radiant refund matures last; now mutual_refund unwinds BOTH legs.
        nodes.rxd_mine(s.t_rxd.value - _rxd_confs(nodes, cov_txid))
        rec = await coord.mutual_refund()
        assert rec.state is SwapState.MUTUAL_REFUND

        # Both locked UTXOs are now spent (refunded) on their chains.
        btc_spent = nodes.btc("gettxout", loc.funding_outpoint.txid, str(loc.funding_outpoint.vout))
        rxd_spent = nodes.rxd("gettxout", cov_txid, "0")
        assert btc_spent in (None, ""), "BTC HTLC should be refunded (spent)"
        assert rxd_spent in (None, ""), "RXD covenant should be refunded (spent)"

    async def test_maker_stall_asset_only_refund_mechanics(self, nodes):
        """Exercises the maybe_refund_asset_on_maker_stall MECHANICS (the helper still exists as a
        maker-side primitive): a no-op before the stall window opens; inside the window the trigger
        fires but the P3 maturity pre-check refuses a non-final refund; at ``t_rxd`` maturity the
        covenant CSV refund broadcasts. NOTE: that refund pays the MAKER, not the taker — see
        TestMakerStallAssetOnlyRefundIsTakerLoss for why this is NOT a taker recovery. The watchtower
        no longer routes a taker here (FSM finding #2); the safe taker recovery is mutual_refund."""
        s = await _setup_locked_swap(nodes)
        coord = s.coord
        cov_txid = coord.record.radiant_covenant_outpoint.split(":")[0]
        # The coordinator judges maturity as `asset_locked_at_height + t_rxd`; this is the anchor it is given.
        maturity = s.rxd_locked_at + s.t_rxd.value

        async def _stall_refund(now: int):
            assert int(nodes.rxd("getblockcount")) == now
            return await coord.maybe_refund_asset_on_maker_stall(
                now_block_height=now, asset_locked_at_height=s.rxd_locked_at, maker_has_claimed_btc=False
            )

        # 1. The maker has not claimed, but t_rxd is far off: the stall trigger has not fired — a no-op.
        now = int(nodes.rxd("getblockcount"))
        assert now < maturity - coord.config.maker_stall_safety_window_blocks
        rec = await _stall_refund(now)
        assert rec.state is SwapState.BOTH_LOCKED

        # 2. One block short of maturity is inside the stall window, so the trigger FIRES — and the
        #    maturity pre-check refuses to broadcast a refund the chain would reject.
        nodes.rxd_mine(maturity - 1 - now)
        with pytest.raises(NetworkError, match="not yet mature"):
            await _stall_refund(maturity - 1)
        assert coord.record.state is SwapState.BOTH_LOCKED
        assert isinstance(nodes.rxd("gettxout", cov_txid, "0"), dict), "nothing was broadcast"

        # 3. At maturity the covenant CSV refund broadcasts.
        nodes.rxd_mine(1)
        rec = await _stall_refund(maturity)
        assert rec.state is SwapState.ASSET_REFUNDED_TAKER_ACTS

        rxd_spent = nodes.rxd("gettxout", cov_txid, "0")
        assert rxd_spent in (None, ""), "the covenant CSV refund was broadcast (covenant spent) — pays the MAKER"


def _scan_value_for_spk(nodes: _Nodes, spk: bytes) -> int:
    """Total confirmed UTXO value (sats) currently paying ``spk`` on the RXD chain."""
    res = nodes.rxd("scantxoutset", "start", json.dumps([{"desc": f"raw({bytes(spk).hex()})"}]))
    return round(sum(u["amount"] for u in res.get("unspents", [])) * 1e8)


class TestCovenantRefundCsvMaturity:
    """P3 leg-level maturity self-check calibrated against REAL consensus: RadiantCovenantLeg.refund_asset
    must refuse a non-final CSV refund below t_rxd maturity (a real node would reject it) and succeed at
    exactly t_rxd confirmations. Proves the leg's `confs >= t_rxd.value` boundary is neither too strict
    (would waste a block) nor too lax (would emit a tx the node rejects — the failure mode P3 exists to
    avoid). Drives the leg directly to isolate the leg check from the coordinator-side height gate."""

    async def test_refund_asset_boundary_matches_consensus(self, nodes):
        s = await _setup_locked_swap(nodes)
        leg = s.coord.radiant_leg
        rec = s.coord.record
        cov_txid = rec.radiant_covenant_outpoint.split(":")[0]

        async def _confs() -> int:
            return await leg.chain_io.confirmations(cov_txid)

        # Mine to exactly t_rxd - 1 confirmations (one short of CSV maturity).
        nodes.rxd_mine(s.t_rxd.value - 1 - await _confs())
        assert await _confs() == s.t_rxd.value - 1
        # The leg refuses to broadcast a non-final refund — fail-closed, no tx emitted.
        with pytest.raises(NetworkError, match=f"needs {s.t_rxd.value} confirmations, has {s.t_rxd.value - 1}"):
            await leg.refund_asset(rec)

        # One more block → exactly t_rxd confirmations → the CSV refund is final; the node accepts it.
        nodes.rxd_mine(1)
        assert await _confs() == s.t_rxd.value
        txid = await leg.refund_asset(rec)  # broadcasts; a too-lax boundary would raise here (node reject)
        assert len(txid) == 64
        nodes.rxd_mine(1)
        assert nodes.rxd("gettxout", cov_txid, "0") in (None, ""), "the mature CSV refund spent the covenant"


class TestBtcActiveAdversary:
    """P2 for the BTC arm ("the hard case"): the genuinely-separated active-adversary analog of
    test_xchain_eth_active_adversary_e2e, on real bitcoind + radiantd consensus. A SEPARATE adversary
    (its own build_claim_tx, never the honest coordinator's methods) claims the BTC HTLC with p —
    publishing p in the witness on-chain. The honest taker (role=TAKER, never running the maker's
    claim) OBSERVES the reveal via taker_observed_reveal (the BTC path, on real regtest — previously
    only unit-tested with fakes), recovers p FROM the on-chain claim tx, and settles the covenant.
    Safety is asserted from chain-re-derived facts."""

    async def test_A1_active_reveal_honest_taker_recovers_from_chain(self, nodes):
        s = await _setup_locked_swap(nodes, role=SwapRole.TAKER)
        coord = s.coord
        depth = coord.config.margin_policy.btc_claim_reorg_depth.value

        # The ADVERSARY claims the BTC HTLC with p via its OWN build_claim_tx + broadcast — publishing p
        # in the witness on-chain. The honest coordinator never runs maker_claims_btc (the maker's key +
        # p live only in the adversary's construction here).
        claim_raw = bt.build_claim_tx(
            locator=coord.record.btc_locator,
            preimage=s.p_secret.unsafe_raw_bytes(),
            claim_privkey=coord.counter_leg._maker_claim_privkey,
            to_scriptpubkey=coord.counter_leg.claim_to_scriptpubkey,
            fee_sats=coord.counter_leg.fee_sats,
            aux_rand=os.urandom(32),
        )
        claim_txid = nodes.btc("sendrawtransaction", claim_raw.hex())
        nodes.btc_mine(depth)  # bury the adversary's claim to the reorg-safe depth (gate → SAFE)

        # The honest taker OBSERVES the reveal: it fetches the claim tx bytes FROM CHAIN (by the public
        # txid) and taker_observed_reveal verifies sha256(p)==H + that the claim spends OUR HTLC outpoint,
        # then advances BOTH_LOCKED -> SECRET_REVEALED — without the honest side ever holding p.
        claim_bytes = bytes.fromhex(nodes.btc("getrawtransaction", claim_txid))
        rec = await coord.taker_observed_reveal(claim_bytes)
        assert rec.state is SwapState.SECRET_REVEALED

        # Recover p from the chain + reorg-gated covenant claim (CLAIM branch → taker).
        now = int(nodes.rxd("getblockcount"))
        rec = await coord.taker_scrape_and_claim_asset(
            claim_bytes, now_rxd_height=now, asset_locked_at_height=s.rxd_locked_at
        )
        assert rec.state is SwapState.COMPLETED, f"honest taker should settle the covenant, got {rec.state.value}"
        nodes.rxd_mine(1)  # confirm the covenant claim so scantxoutset (confirmed-only) sees the payout

        # SAFETY from chain reads: the covenant is spent to the TAKER holder (asset reached the honest
        # taker) and NOT the maker — atomic COMPLETED, no one-sided loss.
        cov_txid = rec.radiant_covenant_outpoint.split(":")[0]
        assert nodes.rxd("gettxout", cov_txid, "0") in (None, ""), "covenant must be spent (claimed)"
        assert _scan_value_for_spk(nodes, s.cov.taker_holder_script) == s.rxd_amount, (
            "the covenant claim must pay the TAKER holder (asset reached the honest taker)"
        )
        assert _scan_value_for_spk(nodes, s.cov.maker_holder_script) == 0, "the maker must NOT hold the covenant"


class TestMakerStallAssetOnlyRefundIsTakerLoss:
    """ADVERSARIAL (FSM finding #2, 2026-06-09): on the BTC<->RXD runbook the asset-only
    proactive refund (:meth:`maybe_refund_asset_on_maker_stall`) is NOT a taker defense — its
    CSV refund pays the MAKER. A taker driven to run it on a maker stall (which the BTC watchtower
    and runbook once recommended) DESTROYS its only claim on the asset (the claimable covenant) and
    recovers nothing for itself: its own BTC stays in the HTLC, whose claim leaf is maker-only and
    has NO expiry (``claim_leaf_script`` carries no timelock). The maker, still privately holding
    ``p``, then claims that BTC and takes BOTH legs.

    UNDER THE #482 ORDERING THE TAKER'S BTC REFUND HAS ALREADY OPENED BY THEN. ``t_btc`` is the
    short leg, so by the time the covenant's ``t_rxd`` CSV can be mined the taker's refund leaf has
    been spendable for at least the margin, at the policy's nominal intervals. This test used to
    assert the opposite — "the taker's own BTC is still locked until t_btc" — which is true only of
    the exploitable pre-#482 layout. Opening is not spending: until the taker broadcasts its own
    refund, the maker's claim leaf spends the same output, and the loss below is the taker that
    acted on the maker's covenant instead of on its own leg.

    Contrast :meth:`TestCrossChainSwap.test_mutual_refund_when_maker_never_claims`, which unwinds
    BOTH legs safely — the recovery the ETH path already mandates."""

    async def test_asset_only_refund_gifts_asset_to_maker_then_maker_takes_btc(self, nodes):
        s = await _setup_locked_swap(nodes)
        coord = s.coord
        policy = coord.config.margin_policy
        loc = coord.record.btc_locator
        cov_value = s.rxd_amount

        # Sanity: before the refund, the asset sits in the covenant; neither party's holder
        # script holds it yet.
        assert _scan_value_for_spk(nodes, s.cov.maker_holder_script) == 0
        assert _scan_value_for_spk(nodes, s.cov.taker_holder_script) == 0

        # 1. Maker stalls (never claims BTC; p stays private). Advance Radiant to the covenant's CSV
        #    maturity — the first height the asset-only refund can be mined — and BTC by the same
        #    wall clock. (Run from an unset-role coordinator: since the P3 role guard a TAKER-role
        #    coordinator refuses this primitive outright, and this test is the reason why.)
        rxd_to_go = s.rxd_locked_at + s.t_rxd.value - int(nodes.rxd("getblockcount"))
        nodes.rxd_mine(rxd_to_go)
        nodes.btc_mine(_btc_blocks_during(policy, rxd_to_go))
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

        # 3. The #482 ordering: the taker's BTC refund leaf opened BEFORE the covenant's CSV did...
        assert _btc_confs(nodes, loc.funding_outpoint.txid) >= s.t_btc.value, (
            "the counter leg is the SHORT one: its refund must already be open when t_rxd matures"
        )
        # ...but opening is not spending. The asset-only refund never touched the taker's BTC.
        assert isinstance(nodes.btc("gettxout", loc.funding_outpoint.txid, str(loc.funding_outpoint.vout)), dict), (
            "the taker's BTC HTLC is still unspent after the asset-only refund"
        )

        # 4. The adversarial maker, still holding p, claims the BTC directly (bypassing the honest
        #    coordinator — the FSM is terminal). The claim leaf is maker-only and has no expiry, so it
        #    spends the output the taker left unrefunded.
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
# The tower's window is blocks_left = deadline - tip, with deadline = covenant height + t_rxd (so
# t_rxd - cov_confs + 1). The thresholds are the coordinator's, and a test that needs one derives it
# from `_claim_floor_blocks` rather than restating it: a SAFE claim needs the BTC claim
# `btc_claim_reorg_depth` deep and room left to mine and bury the taker's own claim; a shallow claim
# WAITs only while there is ALSO room for the BTC claim to reach that depth first, else SQUEEZES; a
# maker stall pages a refund once blocks_left <= `maker_stall_safety_window_blocks`. This comment used
# to spell those thresholds as numbers, and they went stale when #511 added the claim-inclusion blocks.


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
    on both chains. (blocks_left = t_rxd - cov_confs + 1; thresholds as in the section comment above.)"""

    async def _tick_one(self, reconciler: Reconciler):
        results = await reconciler.tick()
        assert len(results) == 1, "exactly one swap is being watched"
        return results[0]

    async def test_happy_path_watch_then_wait_then_page_claim(self, nodes):
        """Wide t_rxd window: pre-reveal WATCH → maker reveals shallow (gate WAIT → still WATCH, the
        headline 'never claim on a reorg-unsafe BTC claim' invariant) → bury deep (gate SAFE) →
        PAGE_CLAIM with the deadline + the named coordinator step."""
        s = await _setup_locked_swap(nodes)
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

        # Re-page backoff: PAGE_CLAIM is CRITICAL, and a CRITICAL situation deliberately RE-pages
        # on the tick-count backoff (default repage_critical_every_ticks=1) so a single missed page
        # cannot silently lose funds. This assertion previously read "must not re-page an unchanged
        # situation" — the pre-#239 semantics; the re-page backoff landed after this suite was
        # written and, being -m integration, it never went red in CI. The authority for the
        # behaviour is tests/test_watch_alerts.py::test_critical_intent_repages_each_tick_by_default.
        r = await self._tick_one(reconciler)
        assert r.decision.intent is Intent.PAGE_CLAIM
        assert len(channel.pages) == 2, "a CRITICAL claim race must RE-page each tick, not dedup away"
        assert channel.pages[1].intent is Intent.PAGE_CLAIM
        assert channel.pages[1].severity is Severity.CRITICAL

    async def test_maker_stall_watch_then_page_refund(self, nodes):
        """Maker locks the asset then stalls (never reveals p). As t_rxd nears, the tower pages the
        safe both-legs recovery — mutual_refund (WARN — recoverable, not a race), NOT the asset-only
        refund that pays the maker (FSM finding #2). The page names the coordinator step, and fires
        exactly when blocks_left reaches the coordinator's ``maker_stall_safety_window_blocks``.

        This pins the STALL page. It says nothing about the earliest moment the taker could act:
        under the #482 ordering the taker's own BTC refund (``t_btc``, the short leg) opens well
        before this page fires, and the tower's BOTH_LOCKED branch does not read it."""
        s = await _setup_locked_swap(nodes)
        coord = s.coord
        reconciler, channel = _watchtower(nodes, coord)
        window = coord.config.maker_stall_safety_window_blocks

        # 1. Just locked: the deadline is far off → WATCH.
        r = await self._tick_one(reconciler)
        assert r.decision.intent is Intent.WATCH
        assert channel.pages == []
        deadline = r.decision.deadline_rxd_height
        assert deadline is not None

        # 2. One block before the stall window opens: still WATCH.
        nodes.rxd_mine(deadline - window - 1 - int(nodes.rxd("getblockcount")))
        r = await self._tick_one(reconciler)
        assert r.decision.intent is Intent.WATCH, "the stall page must not fire before its window"
        assert channel.pages == []

        # 3. The window opens (blocks_left == window) → PAGE_REFUND naming mutual_refund.
        nodes.rxd_mine(1)
        r = await self._tick_one(reconciler)
        assert r.decision.intent is Intent.PAGE_REFUND
        assert r.decision.recommended_action == "mutual_refund"
        assert r.decision.deadline_rxd_height == deadline
        assert r.alert_delivered is True
        assert len(channel.pages) == 1
        assert channel.pages[0].severity is Severity.WARN  # a stall refund is recoverable, not a race
        assert channel.pages[0].low_corroboration is True

    async def test_reveal_with_closing_window_pages_squeezed(self, nodes):
        """A shallow reveal into a CLOSING t_rxd window: there is no longer room to wait for a
        reorg-safe burial before the maker's CSV refund opens → the gate SQUEEZES → a
        decision-required PAGE_SQUEEZED (winner-take-all vs accept loss), never a silent claim or a
        silent wait.

        The window is closed by MINING towards the deadline, not by negotiating a short ``t_rxd``:
        a window that short cannot carry the margin, and the fund-time gate refuses it (#482). With
        the two regtest chains mined independently, this is a maker that reveals late; at these
        derived timelocks, in wall clock, that is after the taker's own BTC refund has opened.

        The WAIT floor is ASKED of ``assess_claim_finality`` (``_fewest_blocks_left_that_wait``)
        rather than restated, because it is chain-specific — the counter chain's reorg depth is
        converted into Radiant blocks at its own interval — and because the restated version here
        went stale when #511 added the claim-inclusion blocks."""
        s = await _setup_locked_swap(nodes)
        coord = s.coord
        reconciler, channel = _watchtower(nodes, coord)
        squeeze_left = _fewest_blocks_left_that_wait(coord.config.margin_policy) - 2  # 2 under the WAIT floor
        assert squeeze_left > coord.config.maker_stall_safety_window_blocks, (
            "the squeeze window must sit outside the stall page, or the pre-reveal tick is a refund page"
        )

        # 1. Pre-reveal, deadline far off → WATCH.
        r = await self._tick_one(reconciler)
        assert r.decision.intent is Intent.WATCH
        assert channel.pages == []
        deadline = r.decision.deadline_rxd_height

        # 2. The maker stays silent while the window closes to `squeeze_left` blocks — still outside
        #    the stall window, so still WATCH.
        nodes.rxd_mine(deadline - squeeze_left - int(nodes.rxd("getblockcount")))
        r = await self._tick_one(reconciler)
        assert r.decision.intent is Intent.WATCH
        assert channel.pages == []

        # 3. Maker reveals p with ~1 conf and blocks_left = squeeze_left (< the WAIT floor): SQUEEZED.
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

        # Derived like every other swap here (the pair was spelled 6/3 — the pre-#482 layout, which
        # NegotiatedTerms refuses at construction below).
        policy = _policy()
        t_btc, t_rxd = _derive_timelocks(policy, t_rxd_blocks=_shortest_t_rxd_blocks(policy))
        h = hashlib.sha256(os.urandom(32)).digest()
        maker_btc = coincurve.PrivateKey(os.urandom(32))
        taker_kp = generate_keypair(_BTC_HRP)
        refund_priv = bytes(taker_kp._privkey.unsafe_raw_bytes())
        refund_xo = coincurve.PublicKeyXOnly.from_secret(refund_priv).format()
        claim_xo = coincurve.PublicKeyXOnly.from_secret(maker_btc.secret).format()
        htlc = bt.build_htlc(
            hashlock=h, claim_pubkey_xonly=claim_xo, refund_pubkey_xonly=refund_xo, timeout=t_btc, network=_BTC_HRP
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
            network=_BTC_HRP,
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
        swap_id, btc_sats, fee = "dust1", 50_000, 2_000
        # Derived, as for every swap here. Spelled 6/3 until now, which the harness's own ordering
        # check refuses ("--t-rxd must be > --t-btc").
        policy = _policy()
        t_btc, t_rxd = (tl.value for tl in _derive_timelocks(policy, t_rxd_blocks=_shortest_t_rxd_blocks(policy)))

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
                    _BTC_HRP,
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
            network=_BTC_HRP,
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
