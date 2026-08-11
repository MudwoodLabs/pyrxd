"""RSWP orderbook end-to-end on a REAL radiant-core regtest node with ``-swapindex=1``.

Proves against real consensus + the real swap index what the unit suites prove
offline (design note: docs/plans/2026-07-05-rswp-orderbook-design.md):

* HAPPY PATH (FT→RXD): maker mints a consensus-valid FT UTXO, posts an RSWP v2
  advert, the order appears in ``getopenorders`` and the OrderbookClient reports
  it FILLABLE; the taker completes via ``take_rswp_order``; the node accepts +
  mines it; the index then drops the order (offered UTXO spent = settlement).
* HAPPY PATH (RXD→FT): the mirror direction.
* DOUBLE-TAKE: a second completion of the same order is a double-spend —
  rejected by the node (single-winner is consensus, not client courtesy).
* CANCEL-vs-TAKE: after the maker's cancel self-spend confirms, a completion is
  rejected — cancel is the hard revocation.
* TAMPER: inflating the maker's demanded output after signing fails script
  verification at the node (SINGLE binds output[0] exactly).

The FT here is "minted" by spending an outpoint into an FT script carrying that
outpoint as its ref — consensus enforces ref induction/uniqueness, not Glyph
mint provenance (see tests/test_htlc_regtest_e2e.py R1), so this is a REAL
FT-locked UTXO as far as the chain is concerned.

Gating (repo convention): ``@pytest.mark.integration`` + opt-in ``RSWP_REGTEST=1``.
Skips if docker or the radiant-core image is unavailable. Manages its OWN
isolated container, never touches a live node, moves no real value.

Run it:  RSWP_REGTEST=1 pytest tests/test_rswp_regtest_e2e.py -m integration -s
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time

import pytest

from pyrxd.constants import Network
from pyrxd.glyph.script import build_ft_locking_script
from pyrxd.glyph.types import GlyphRef
from pyrxd.gravity.fee_policy import DeadlineFeePolicy
from pyrxd.keys import PrivateKey
from pyrxd.script.script import Script
from pyrxd.script.type import P2PKH
from pyrxd.security.types import Hex20, Txid
from pyrxd.swap import Asset, FundingInput
from pyrxd.swap.rswp import (
    OrderbookClient,
    build_advert_tx,
    build_cancel_tx,
    create_rswp_order,
    decode_rswp_order,
    swap_token_id,
    take_rswp_order,
)
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_input import TransactionInput
from pyrxd.transaction.transaction_output import TransactionOutput

pytestmark = pytest.mark.integration

_IMAGE = "radiant-core:v3.1.1-amd64"
_CONTAINER = "rswp-regtest-pytest"
_FEE = 1_000_000  # 0.01 RXD — comfortably above THIS node's relay floor for sub-kB txs

#: This suite's node runs at the LEGACY 0.01 RXD/kB floor, a tenth of mainnet's — the
#: one Radiant regtest lane still deliberately below the mainnet rate.
#:
#: Declared and asserted (``_Node.start`` passes it and checks ``getmempoolinfo``
#: reports it back) rather than inherited from the node's default, so the rate `_FEE`
#: and `_NODE_POLICY` are sized for cannot silently desync from the rate the node
#: enforces. The shared harness in ``test_htlc_regtest_e2e`` moved to the mainnet floor;
#: this one did not, because what it proves is orderbook and covenant SEMANTICS, and its
#: carriers (e.g. the 8 000 000-photon v3 reservation whose remainder a case asserts on
#: chain) are sized around `_FEE`. The fee floors of these very builders — the v3
#: covenant cancel and refund paths — ARE proven at the mainnet floor, on a node started
#: there, in ``tests/test_fee_floor_boundary_regtest_e2e.py``.
_MIN_RELAY_RXD_PER_KB = "0.01"

# The fee-gated builders (`take_rswp_order` / `accept_offer` / the v3 covenant
# builders / `build_cancel_tx`) default to the MAINNET relay floor, 0.10 RXD/kB. This
# node relays at a tenth of that, and `_FEE` is sized for THIS node — which is the
# point of an e2e — so the gate has to be told which node it is judging.
#
# `allow_below_protocol_floor` because that advertised rate IS below the protocol
# floor: this node is exactly the case the escape hatch exists for.
_NODE_POLICY = DeadlineFeePolicy(relay_fee_per_kb=1_000_000, allow_below_protocol_floor=True)
_RXD_TOKEN_HEX = "00" * 32


class _Node:
    """Self-managed isolated radiant-core regtest node with the swap index enabled."""

    def __init__(self) -> None:
        self.user = "rt_user"
        self.password = os.urandom(12).hex()
        self.mine_addr = ""

    def cli(self, *args: str, wallet: bool = False) -> object:
        base = [
            "docker",
            "exec",
            _CONTAINER,
            "radiant-cli",
            "-regtest",
            f"-rpcuser={self.user}",
            f"-rpcpassword={self.password}",
        ]
        if wallet:
            base.append("-rpcwallet=rswp")
        r = subprocess.run(base + list(args), capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            raise RuntimeError(f"radiant-cli {args[0]} failed: {r.stderr.strip()}")
        out = r.stdout.strip()
        try:
            return json.loads(out)
        except json.JSONDecodeError:
            return out

    def mine(self, n: int = 1) -> None:
        self.cli("generatetoaddress", str(n), self.mine_addr)

    def accepts(self, raw_hex: str) -> dict:
        res = self.cli("testmempoolaccept", json.dumps([raw_hex]))
        return res[0] if isinstance(res, list) else res

    def send_and_mine(self, tx: Transaction) -> str:
        txid = str(self.cli("sendrawtransaction", tx.serialize().hex()))
        self.mine(1)
        return txid

    def start(self) -> None:
        subprocess.run(["docker", "rm", "-f", _CONTAINER], capture_output=True)
        up = subprocess.run(
            [
                "docker",
                "run",
                "-d",
                "--name",
                _CONTAINER,
                "--entrypoint",
                "radiantd",
                _IMAGE,
                "-regtest",
                "-server",
                "-txindex=1",
                "-swapindex=1",
                "-disablewallet=0",
                "-fallbackfee=0.001",
                f"-minrelaytxfee={_MIN_RELAY_RXD_PER_KB}",
                f"-rpcuser={self.user}",
                f"-rpcpassword={self.password}",
                "-rpcbind=0.0.0.0",
                "-rpcallowip=0.0.0.0/0",
            ],
            capture_output=True,
            text=True,
        )
        if up.returncode != 0:
            raise RuntimeError(f"failed to start regtest container: {up.stderr.strip()}")
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            try:
                info = self.cli("getblockchaininfo")
                if isinstance(info, dict) and info.get("chain") == "regtest":
                    break
            except RuntimeError:
                time.sleep(0.5)
        else:
            raise RuntimeError("regtest RPC did not become ready")
        assert self.cli("getblockchaininfo")["chain"] == "regtest", "node is NOT regtest — aborting"
        # The rate `_FEE` and `_NODE_POLICY` are sized for, confirmed by the node itself
        # before anything is proved against it. `effective_minrelaytxfee`, not
        # `minrelaytxfee`: only the first is what AcceptToMemoryPool checks.
        advertised = float(self.cli("getmempoolinfo")["effective_minrelaytxfee"])
        assert advertised == float(_MIN_RELAY_RXD_PER_KB), (
            f"node advertises effective_minrelaytxfee {advertised} RXD/kB, not the "
            f"{_MIN_RELAY_RXD_PER_KB} this suite's fees are sized for"
        )
        info = self.cli("getswapindexinfo")
        assert info.get("enabled") is True, f"swap index not enabled: {info}"
        self.cli("createwallet", "rswp")
        self.mine_addr = str(self.cli("getnewaddress", wallet=True))
        self.mine(101)

    def stop(self) -> None:
        subprocess.run(["docker", "rm", "-f", _CONTAINER], capture_output=True)


@pytest.fixture(scope="module")
def node():
    if not os.environ.get("RSWP_REGTEST"):
        pytest.skip("RSWP_REGTEST not set (opt-in for the live regtest e2e)")
    if shutil.which("docker") is None:
        pytest.skip("docker not available")
    if subprocess.run(["docker", "image", "inspect", _IMAGE], capture_output=True).returncode != 0:
        pytest.skip(f"{_IMAGE} image not available")
    n = _Node()
    n.start()
    try:
        yield n
    finally:
        n.stop()


# --------------------------------------------------------------------------- funding helpers


def _fund_key(node: _Node, key: PrivateKey, photons: int) -> tuple[Transaction, int]:
    """Wallet-pay ``photons`` to the key's P2PKH address; return the REAL (funding tx, vout)."""
    addr_spk = P2PKH().lock(key.public_key().hash160()).serialize()
    # Radiant regtest shares the testnet address prefix.
    addr = key.public_key().address(network=Network.TESTNET)
    txid = str(node.cli("sendtoaddress", addr, f"{photons / 1e8:.8f}", wallet=True))
    node.mine(1)
    raw = str(node.cli("getrawtransaction", txid))
    tx = Transaction.from_hex(bytes.fromhex(raw))
    assert tx is not None and tx.txid() == txid
    vout = next(i for i, o in enumerate(tx.outputs) if o.locking_script.serialize() == addr_spk)
    return tx, vout


def _mint_ft(node: _Node, owner: PrivateKey, units: int) -> tuple[Transaction, GlyphRef]:
    """Create a consensus-valid FT UTXO at vout 0: ref = the spent outpoint (genesis induction)."""
    fund_tx, fund_vout = _fund_key(node, owner, units + 10_000_000)
    ref = GlyphRef(txid=Txid(fund_tx.txid()), vout=fund_vout)
    pkh = owner.public_key().hash160()
    tx = Transaction()
    tx.add_input(
        TransactionInput(
            source_transaction=fund_tx,
            source_output_index=fund_vout,
            unlocking_script_template=P2PKH().unlock(owner),
        )
    )
    tx.add_output(TransactionOutput(Script(build_ft_locking_script(Hex20(pkh), ref)), units))
    change = fund_tx.outputs[fund_vout].satoshis - units - _FEE
    tx.add_output(TransactionOutput(P2PKH().lock(pkh), change))
    tx.sign(bypass=True)
    node.send_and_mine(tx)
    return tx, ref


class _CliSource:
    """OrderbookSource over the node's CLI — the regtest incarnation of the Protocol."""

    def __init__(self, node: _Node) -> None:
        self._node = node

    # NB: radiant-cli lacks client-side type conversion for the swap RPCs, so the
    # numeric limit/offset args cannot be passed as strings — token-only calls
    # use the server defaults (limit 100, offset 0), plenty for these tests.

    async def get_open_orders(self, token_id_hex: str, *, limit: int = 100, offset: int = 0) -> list[dict]:
        rows = self._node.cli("getopenorders", token_id_hex)
        return rows if isinstance(rows, list) else []

    async def get_open_orders_by_want(self, want_token_id_hex: str, *, limit: int = 100, offset: int = 0) -> list[dict]:
        rows = self._node.cli("getopenordersbywant", want_token_id_hex)
        return rows if isinstance(rows, list) else []

    async def get_transaction(self, txid) -> bytes:
        return bytes.fromhex(str(self._node.cli("getrawtransaction", str(txid))))

    async def is_unspent(self, txid: str, vout: int) -> bool:
        out = self._node.cli("gettxout", txid, str(vout), "true")
        return isinstance(out, dict)  # null/empty stdout => spent


# --------------------------------------------------------------------------- scenarios


def _post_ft_for_rxd_order(node: _Node, maker: PrivateKey, units: int, demand_photons: int):
    """Maker mints an FT, posts an order offering it for RXD. Returns (order, ft_source_tx, ref)."""
    mk_pkh = maker.public_key().hash160()
    ft_tx, ref = _mint_ft(node, maker, units)
    post = create_rswp_order(
        give_source_tx=ft_tx,
        give_vout=0,
        maker_key=maker,
        receive=Asset("rxd", demand_photons),
        maker_receive_pkh=mk_pkh,
    )
    advert_fund_tx, advert_vout = _fund_key(node, maker, 20_000_000)
    advert = build_advert_tx(
        advert_script=post.advert_script,
        funding=[FundingInput(advert_fund_tx, advert_vout, maker)],
        change_pkh=mk_pkh,
        fee=_FEE,
    )
    node.send_and_mine(advert)
    return decode_rswp_order(post.advert_script), ft_tx, ref


async def test_happy_path_ft_for_rxd_post_browse_take_settle(node) -> None:
    maker, taker = PrivateKey(), PrivateKey()
    tk_pkh = taker.public_key().hash160()
    order, ft_tx, ref = _post_ft_for_rxd_order(node, maker, units=100_000, demand_photons=9_000_000)

    # The index sees the order under the FT's swap token id.
    token_hex = swap_token_id(ref).hex()
    rows = node.cli("getopenorders", token_hex)
    assert isinstance(rows, list) and len(rows) == 1
    assert rows[0]["utxo"]["txid"] == ft_tx.txid()

    # The OrderbookClient's hostile-input pipeline marks it fillable.
    entries = await OrderbookClient(_CliSource(node)).orders_offering(ref)
    assert len(entries) == 1 and entries[0].fillable, entries[0].problem

    # Taker completes from the DECODED advert + a txid-verified source fetch.
    fund_tx, fund_vout = _fund_key(node, taker, 20_000_000)
    completion = take_rswp_order(
        order,
        give_source_tx=ft_tx,
        funding=[FundingInput(fund_tx, fund_vout, taker)],
        taker_receive_pkh=tk_pkh,
        taker_change_pkh=tk_pkh,
        fee=_FEE,
        fee_policy=_NODE_POLICY,
    )
    verdict = node.accepts(completion.serialize().hex())
    assert verdict.get("allowed") is True, verdict
    txid = node.send_and_mine(completion)

    # Settlement: taker owns the FT at completion:1; index dropped the order.
    got = node.cli("gettxout", txid, "1", "true")
    assert isinstance(got, dict) and round(got["value"] * 1e8) == 100_000
    assert node.cli("getopenorders", token_hex) == []


async def test_happy_path_rxd_for_ft_mirror(node) -> None:
    """Maker offers RXD, demands the taker's FT — the book's other side."""
    maker, taker = PrivateKey(), PrivateKey()
    mk_pkh, tk_pkh = maker.public_key().hash160(), taker.public_key().hash160()

    # Taker owns an FT; maker owns a clean exact-amount RXD UTXO.
    taker_ft_tx, ref = _mint_ft(node, taker, 50_000)
    offered_tx, offered_vout = _fund_key(node, maker, 11_000_000)

    post = create_rswp_order(
        give_source_tx=offered_tx,
        give_vout=offered_vout,
        maker_key=maker,
        receive=Asset("ft", 50_000, ref),
        maker_receive_pkh=mk_pkh,
    )
    advert_fund, af_vout = _fund_key(node, maker, 20_000_000)
    node.send_and_mine(
        build_advert_tx(
            advert_script=post.advert_script,
            funding=[FundingInput(advert_fund, af_vout, maker)],
            change_pkh=mk_pkh,
            fee=_FEE,
        )
    )

    # Discoverable by WANT side (the FT's book).
    entries = await OrderbookClient(_CliSource(node)).orders_wanting(ref)
    assert len(entries) == 1 and entries[0].fillable, entries[0].problem

    fee_fund, ff_vout = _fund_key(node, taker, 20_000_000)
    completion = take_rswp_order(
        decode_rswp_order(post.advert_script),
        give_source_tx=offered_tx,
        funding=[FundingInput(taker_ft_tx, 0, taker), FundingInput(fee_fund, ff_vout, taker)],
        taker_receive_pkh=tk_pkh,
        taker_change_pkh=tk_pkh,
        fee=_FEE,
        fee_policy=_NODE_POLICY,
    )
    verdict = node.accepts(completion.serialize().hex())
    assert verdict.get("allowed") is True, verdict
    node.send_and_mine(completion)


async def test_double_take_single_winner(node) -> None:
    """Two independent takers complete the same order; consensus lets exactly one win."""
    maker, taker1, taker2 = PrivateKey(), PrivateKey(), PrivateKey()
    order, ft_tx, _ref = _post_ft_for_rxd_order(node, maker, units=70_000, demand_photons=8_000_000)

    completions = []
    for taker in (taker1, taker2):
        fund_tx, fund_vout = _fund_key(node, taker, 20_000_000)
        completions.append(
            take_rswp_order(
                order,
                give_source_tx=ft_tx,
                funding=[FundingInput(fund_tx, fund_vout, taker)],
                taker_receive_pkh=taker.public_key().hash160(),
                taker_change_pkh=taker.public_key().hash160(),
                fee=_FEE,
                fee_policy=_NODE_POLICY,
            )
        )

    node.send_and_mine(completions[0])
    second = node.accepts(completions[1].serialize().hex())
    assert second.get("allowed") is False
    assert "missing-inputs" in str(second) or "txn-mempool-conflict" in str(second)
    # replay of the winner is equally dead
    replay = node.accepts(completions[0].serialize().hex())
    assert replay.get("allowed") is False


async def test_cancel_beats_take(node) -> None:
    """After the maker's cancel self-spend confirms, the pre-signed completion is worthless."""
    maker, taker = PrivateKey(), PrivateKey()
    order, ft_tx, ref = _post_ft_for_rxd_order(node, maker, units=60_000, demand_photons=7_000_000)

    fund_tx, fund_vout = _fund_key(node, taker, 20_000_000)
    completion = take_rswp_order(
        order,
        give_source_tx=ft_tx,
        funding=[FundingInput(fund_tx, fund_vout, taker)],
        taker_receive_pkh=taker.public_key().hash160(),
        taker_change_pkh=taker.public_key().hash160(),
        fee=_FEE,
        fee_policy=_NODE_POLICY,
    )

    fee_fund, ff_vout = _fund_key(node, maker, 20_000_000)
    cancel = build_cancel_tx(
        offered_source_tx=ft_tx,
        offered_vout=0,
        maker_key=maker,
        refund_pkh=maker.public_key().hash160(),
        fee=_FEE,
        fee_policy=_NODE_POLICY,
        funding=[FundingInput(fee_fund, ff_vout, maker)],
    )
    node.send_and_mine(cancel)

    verdict = node.accepts(completion.serialize().hex())
    assert verdict.get("allowed") is False  # hard revocation
    token_hex = swap_token_id(ref).hex()
    assert node.cli("getopenorders", token_hex) == []  # index shows it gone


async def test_tampered_demand_rejected_by_consensus(node) -> None:
    """Client checks aside, the CHAIN rejects a completion whose output[0] was inflated."""
    maker, taker = PrivateKey(), PrivateKey()
    order, ft_tx, _ = _post_ft_for_rxd_order(node, maker, units=40_000, demand_photons=6_000_000)

    fund_tx, fund_vout = _fund_key(node, taker, 20_000_000)
    completion = take_rswp_order(
        order,
        give_source_tx=ft_tx,
        funding=[FundingInput(fund_tx, fund_vout, taker)],
        taker_receive_pkh=taker.public_key().hash160(),
        taker_change_pkh=taker.public_key().hash160(),
        fee=_FEE,
        fee_policy=_NODE_POLICY,
    )
    completion.outputs[0].satoshis -= 1  # steal one photon from the maker's demand
    verdict = node.accepts(completion.serialize().hex())
    assert verdict.get("allowed") is False
    assert "mandatory-script-verify-flag-failed" in str(verdict)
