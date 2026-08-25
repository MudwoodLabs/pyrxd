"""END-TO-END RXD↔USDC atomic swap on real chains — the first proof the token corridor COMPOSES.

Everything in the ERC-20 corridor has been proven SEPARATELY. `test_erc20_leg_fork_integration.py`
drives `Erc20HtlcLeg` against a forked mainnet — the real USDC proxy, its real blacklist, a real
claim inside the gas budget. The regtest e2e drives a whole swap through the real `SwapCoordinator`
— but with the NATIVE ETH leg, zero ERC-20 references.

Nothing has ever run the two together, and until this file existed, `Erc20HtlcLeg` was constructed
nowhere outside its own tests: the corridor had no production caller at all. Nine adversarial review
rounds found real defects by READING this code. Not one of them could have found a defect that only
appears when the pieces meet.

What is real here:

* **USDC is the real contract** on a mainnet fork — 6 decimals, the real issuer blacklist, the real
  transfer semantics. A mock token is worthless for exactly the two things most likely to be wrong.
* **The Radiant leg is a real covenant** on a radiant-core regtest node, with a real CSV refund.
* **The coordinator is the production one**, driven NEGOTIATED → COMPLETED, plus the refund path.

Moves no real value: anvil is a local fork with public deterministic keys, Radiant is a
self-managed regtest container, and the USDC is conjured by impersonating a holder ON THE FORK.

Run it::

    XCHAIN_ERC20_E2E=1 PYRXD_ETH_FORK_RPC=https://ethereum-rpc.publicnode.com \\
        .venv/bin/pytest tests/test_xchain_erc20_usdc_lifecycle_e2e.py -m integration -s

No RPC key is needed — see `test_erc20_leg_fork_integration.py`'s header for the working endpoints
and for why probing them from Python makes it look like one is.

NOTE: the regtest fixture `docker rm -f`s a FIXED container name, so this cannot run beside another
regtest suite — serialise them.
"""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import shutil
import socket
import subprocess
import time
import urllib.request

import pytest

pytest.importorskip("web3")
pytest.importorskip("eth_keys")

from pyrxd.btc_wallet import taproot as bt
from pyrxd.eth_wallet.erc20_leg import Erc20HtlcLeg
from pyrxd.eth_wallet.rpc import EthRpc
from pyrxd.eth_wallet.tokens import token_for
from pyrxd.gravity.eth_leg import EthLeg
from pyrxd.gravity.eth_rxd_timelock import CrossClockMargin
from pyrxd.gravity.htlc_covenant import build_htlc_covenant_rxd
from pyrxd.gravity.radiant_leg import RadiantChainIO, RadiantCovenantLeg
from pyrxd.gravity.record_sink import FileFundLock, JsonFileRecordSink
from pyrxd.gravity.swap_coordinator import CoordinatorConfig, MarginPolicy, SwapCoordinator
from pyrxd.gravity.swap_state import NegotiatedTerms, SwapRecord, SwapState
from pyrxd.keys import PrivateKey
from pyrxd.security.secrets import PrivateKeyMaterial, SecretBytes
from pyrxd.security.types import Hex20
from tests.test_swap_coordinator import FakeIndexer
from tests.test_xchain_swap_regtest_e2e import (
    _FeeSource,
    _RadiantCliClient,
    _rxd_pay,
)

pytestmark = pytest.mark.integration

_RXD_IMAGE = "radiant-core:v3.1.1-amd64"
_MAINNET = 1
_USDC = token_for("USDC", _MAINNET)
#: A large holder to impersonate — avoids deriving the balances storage slot, whose packed layout
#: is exactly the sort of detail a test should not encode.
_WHALE = "0x28C6c06298d514Db089934071355E5743bf21d60"
#: Anvil's deterministic PUBLIC dev keys. Local fork only; no real value.
_KEY_TAKER = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
_ADDR_TAKER = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
_ADDR_MAKER = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
#: 12.345678 USDC. Non-round on purpose: a 6-vs-18 decimal bug cannot hide in a round number.
_AMOUNT = 12_345_678
_RXD_CARRIER = 100_000


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _rpc(url: str, method: str, params=None):
    req = urllib.request.Request(
        url,
        data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params or []}).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())


def _mine(url: str, n: int = 1) -> None:
    for _ in range(n):
        _rpc(url, "evm_mine")


def _now(url: str) -> int:
    return int(_rpc(url, "eth_getBlockByNumber", ["latest", False])["result"]["timestamp"], 16)


@pytest.fixture(scope="module")
def env(tmp_path_factory):
    """A Radiant regtest node + an anvil fork of mainnet, with the taker holding real USDC."""
    fork_rpc = os.environ.get("PYRXD_ETH_FORK_RPC", "")
    if not os.environ.get("XCHAIN_ERC20_E2E"):
        pytest.skip("XCHAIN_ERC20_E2E not set (opt-in for the RXD↔USDC lifecycle e2e)")
    if not fork_rpc:
        pytest.skip("PYRXD_ETH_FORK_RPC not set — needs a mainnet endpoint to fork (no key required)")
    for tool in ("docker", "anvil"):
        if shutil.which(tool) is None:
            pytest.skip(f"{tool} not available")
    if subprocess.run(["docker", "image", "inspect", _RXD_IMAGE], capture_output=True).returncode != 0:
        pytest.skip(f"{_RXD_IMAGE} image not available")

    from tests.test_xchain_eth_swap_regtest_e2e import _RxdNode

    node = _RxdNode()
    node.start()
    port = _free_port()
    url = f"http://127.0.0.1:{port}"
    # `--slots-in-an-epoch 1` so the `finalized` checkpoint tracks latest-2. Without a consensus
    # layer anvil pins it at 0, the ETH-claim finality verdict is never FINAL, and the reorg gate
    # never returns SAFE — the swap would stall for a reason that has nothing to do with the code.
    anvil = subprocess.Popen(
        [
            "anvil",
            "--fork-url",
            fork_rpc,
            "--port",
            str(port),
            "--chain-id",
            str(_MAINNET),
            "--slots-in-an-epoch",
            "1",
            "--silent",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        for _ in range(160):
            try:
                _rpc(url, "eth_chainId")
                break
            except Exception:
                time.sleep(0.25)
        else:  # pragma: no cover
            pytest.fail("anvil fork did not become ready")
        # Give the taker USDC by impersonating a holder — no storage-slot derivation.
        # The anvil dev addresses carry EIP-7702 delegation designators on a mainnet fork; they are
        # deliberately left in place, because the token leg's ERC-20 sweep calls the token and never
        # the recipient, so it must work WITH them present (#478).
        _rpc(url, "anvil_impersonateAccount", [_WHALE])
        _rpc(url, "anvil_setBalance", [_WHALE, hex(10**18)])
        for who in (_ADDR_TAKER, _ADDR_MAKER):
            _rpc(url, "anvil_setBalance", [who, hex(10**19)])
        transfer = "0xa9059cbb" + _ADDR_TAKER[2:].rjust(64, "0") + hex(_AMOUNT * 10)[2:].rjust(64, "0")
        _rpc(url, "eth_sendTransaction", [{"from": _WHALE, "to": _USDC.address, "data": transfer}])
        yield node, url, tmp_path_factory.mktemp("erc20e2e")
    finally:
        anvil.terminate()
        try:
            anvil.wait(timeout=10)
        except subprocess.TimeoutExpired:  # pragma: no cover
            anvil.kill()
        node.stop()


class _RecordingEthLeg:
    """Captures the maker's claim tx hash on the way past.

    `maker_claims_btc` discards it — the record has no field for it — so the taker cannot be handed
    the transaction it must scrape `p` from. That is a real gap, filed separately; here the wrapper
    stands in for whatever the operator would otherwise have to recover by hand.
    """

    def __init__(self, inner) -> None:
        self._inner = inner
        self.claim_tx_hash: str | None = None

    async def claim(self, locator, preimage):
        self.claim_tx_hash = await self._inner.claim(locator, preimage)
        return self.claim_tx_hash

    def __getattr__(self, name):
        return getattr(self._inner, name)


class _InMemSeen:
    """Single-process H-freshness. The coordinator refuses a value-bearing swap on a non-durable
    store unless told to accept it, which this run does consciously: one process, one shot, a fresh
    H each time."""

    def __init__(self) -> None:
        self._seen: set[bytes] = set()

    def has_seen(self, h: bytes) -> bool:
        return bytes(h) in self._seen

    def reserve(self, h: bytes) -> bool:
        if bytes(h) in self._seen:
            return False
        self._seen.add(bytes(h))
        return True

    def mark_seen(self, h: bytes) -> None:
        self._seen.add(bytes(h))


def _policy():
    """A dust-shaped policy: the economics gates are opt-out here, not because they do not matter
    but because this run proves COMPOSITION, and a measured policy would gate on numbers no test
    can measure."""
    return MarginPolicy(
        margin=bt.Timelock(6, bt.TimeUnit.BLOCKS),
        block_interval_s=600.0,
        is_measured=False,
        # Regtest mines on demand, so a real interval is meaningless — but these two numbers
        # DIVIDE into a block reserve (768/600 = 2 blocks), and a tiny interval would demand a
        # ~768-block t_rxd for no reason. Kept mainnet-shaped so the arithmetic is the real one.
        rxd_block_interval_s=600.0,
        btc_claim_reorg_depth=bt.Timelock(2, bt.TimeUnit.BLOCKS),
        rxd_claim_burial=bt.Timelock(2, bt.TimeUnit.BLOCKS),
        eth_finalization_window_s=768,  # 2 post-Merge epochs; the policy enforces this floor
        cross_clock_margin=CrossClockMargin(
            eth_reorg_finality_s=768,
            rxd_claim_burial_s=1800,
            rxd_confirm_slack_s=600,
            rounding_slack_s=300,
        ),
        max_covenant_confirm_wait_s=600,
        accept_flat_burial=True,
    )


def _build(node, url, workdir, *, t_rxd_blocks=60):
    """Covenant + BOTH real legs + the production coordinator, wired for RXD↔USDC."""
    p_secret = SecretBytes(os.urandom(32))
    h = hashlib.sha256(p_secret.unsafe_raw_bytes()).digest()
    t_rxd = bt.Timelock(t_rxd_blocks, bt.TimeUnit.BLOCKS)
    eth_timeout = _now(url) + 50_000

    taker_rxd, maker_rxd = PrivateKey(os.urandom(32)), PrivateKey(os.urandom(32))
    taker_pkh = bytes(Hex20(taker_rxd.public_key().hash160()))
    maker_pkh = bytes(Hex20(maker_rxd.public_key().hash160()))
    cov = build_htlc_covenant_rxd(
        amount=_RXD_CARRIER, taker_pkh=taker_pkh, maker_pkh=maker_pkh, hashlock=h, refund_csv=t_rxd_blocks
    )

    terms = NegotiatedTerms(
        hashlock=h,
        # Vestigial on an ETH swap — `value_amount` carries the real counter-leg amount — but the
        # record still requires it positive. Matches the native ETH e2e rather than inventing a
        # different convention.
        btc_sats=100_000,
        radiant_amount=_RXD_CARRIER,
        t_btc=bt.Timelock(t_rxd_blocks + 40, bt.TimeUnit.BLOCKS),
        t_rxd=t_rxd,
        asset_variant="rxd",
        genesis_ref=b"",
        taker_dest_hash=cov.expected_taker_hash,
        maker_dest_hash=cov.expected_maker_hash,
        btc_claim_pubkey_xonly=b"\x00" * 32,
        btc_refund_pubkey_xonly=b"\x00" * 32,
        counter_chain="eth",
        eth_timeout_unix_s=eth_timeout,
        # THE token fields. `value_amount` is 6-decimal USDC base units, NOT wei — the whole reason
        # the record is chain-tagged, and the distinction a mock token cannot exercise.
        value_amount=_AMOUNT,
        token_address=_USDC.address,
    )

    rpc = EthRpc(url, expected_chain_id=_MAINNET)
    artifact = json.loads((pathlib.Path(__file__).parent / "fixtures" / "Erc20Htlc.json").read_text())
    contract_leg = Erc20HtlcLeg(
        token=_USDC,
        rpc=rpc,
        signing_key=PrivateKeyMaterial(bytes.fromhex(_KEY_TAKER)),
        chain_id=_MAINNET,
        artifact=artifact,
    )
    eth_leg = _RecordingEthLeg(
        EthLeg(
            contract_leg=contract_leg,
            network="mainnet",
            claim_to=_ADDR_MAKER,  # the maker claims the USDC
            refund_to=_ADDR_TAKER,  # the taker gets it back on refund
            eth_timeout_unix_s=eth_timeout,
            audit_cleared=True,  # a forked devnet; no real value moves
        )
    )
    rxd_leg = RadiantCovenantLeg(
        network="bcrt",
        taker_pkh=taker_pkh,
        maker_pkh=maker_pkh,
        chain_io=RadiantChainIO(_RadiantCliClient(node)),
        fee_source=_FeeSource(node),
        min_confirmations=1,
    )
    keys = str(workdir / "swap")
    coord = SwapCoordinator(
        record=SwapRecord(state=SwapState.NEGOTIATED, terms=terms),
        counter_leg=eth_leg,
        radiant_leg=rxd_leg,
        indexer=FakeIndexer(),
        seen_store=_InMemSeen(),
        persist=JsonFileRecordSink(keys + ".swaprec.json"),
        config=CoordinatorConfig(
            margin_policy=_policy(),
            accept_estimated_eth_margins=True,
            accept_nondurable_seen=True,  # single-process, fresh-H-per-run
            fund_lock=FileFundLock(keys),
        ),
    )
    return coord, cov, p_secret, eth_leg, rxd_leg, taker_rxd, maker_rxd


def _usdc_balance(url: str, who: str) -> int:
    call = {"to": _USDC.address, "data": "0x70a08231" + who[2:].rjust(64, "0")}
    return int(_rpc(url, "eth_call", [call, "latest"])["result"], 16)


async def test_rxd_usdc_swap_runs_end_to_end(env):
    """THE test. NEGOTIATED → COMPLETED with a real USDC HTLC and a real Radiant covenant.

    Every component here has been proven separately and never together. What only this can catch is
    a defect that lives in the seam: the two-transaction fund against a real mempool, the 6-decimal
    amount surviving the record round trip, the chain-tagged locator reaching the claim path, the
    covenant and the token HTLC agreeing about the same preimage.
    """
    node, url, workdir = env
    coord, cov, p_secret, eth_leg, _rxd_leg, _tk, _mk = _build(node, url, workdir)

    maker_before = _usdc_balance(url, _ADDR_MAKER)

    # 1. MAKER locks the Radiant asset first, and it is mined. The taker will not fund until it has
    #    read this off the chain — HZ-1, enforced by pre_btc_lock_check step 5.
    _rxd_pay(node, cov.funded_spk, _RXD_CARRIER)
    node.rxd_mine(3)

    # 2. TAKER funds the USDC counter leg. Two transactions: deploy, then a plain transfer.
    rec = await coord.taker_funds_btc(coord.record.terms, now_unix_s=_now(url))
    assert rec.state is SwapState.BTC_LOCKED
    loc = rec.counterchain_locator
    assert loc is not None
    # Read the tag off the PERSISTED record, not off the locator object. `loc.CHAIN_TAG` is a class
    # attribute, so asserting it only proves the class was imported — a first version of this line
    # did exactly that, and forcing `to_dict` to write "eth" for a token swap left the test GREEN.
    # What matters is the bytes that reach disk, because those are what a later reader decodes.
    on_disk = json.loads((workdir / "swap.swaprec.json").read_text())
    tag = on_disk["counterchain_locator"]["chain"]
    assert tag == "eth-erc20", f"persisted tag is {tag!r} — a reader would take 6-decimal units for wei"
    assert on_disk["counterchain_locator"]["locator"]["amount_wei"] == _AMOUNT
    assert loc.amount_wei == _AMOUNT, "the 6-decimal amount did not survive into the locator"
    assert _usdc_balance(url, loc.contract_address) == _AMOUNT, "the HTLC does not hold the USDC"

    # 3. MAKER revalidates and the swap is BOTH_LOCKED.
    rec = await coord.post_asset_lock_revalidate(cov.funded_spk, now_unix_s=_now(url))
    assert rec.state is SwapState.BOTH_LOCKED

    # 4. MAKER claims the USDC, revealing p on Ethereum.
    rec = await coord.maker_claims_btc(p_secret)
    assert rec.state is SwapState.SECRET_REVEALED
    assert _usdc_balance(url, _ADDR_MAKER) - maker_before == _AMOUNT, "the maker was not paid the USDC"
    _mine(url, 4)  # let the claim finalize so the reorg gate can return SAFE

    # 5. TAKER scrapes p from the maker's real claim and takes the Radiant asset.
    claim_tx = eth_leg.claim_tx_hash
    assert claim_tx, "the maker's claim tx hash was not captured — the taker cannot scrape p"
    node.rxd_mine(2)
    rec = await coord.taker_scrape_and_claim_asset(
        claim_tx, now_rxd_height=_rxd_height(node), asset_locked_at_height=_rxd_height(node) - 5
    )
    assert rec.state is SwapState.COMPLETED, f"the swap did not complete: {rec.state}"


def _rxd_height(node) -> int:
    return int(node.rxd("getblockcount"))


async def test_mutual_refund_returns_the_usdc_and_the_rxd(env):
    """The guaranteed-safe failure, on real chains: neither side suffers a one-sided loss.

    Both legs are funded and NOBODY claims — the maker never reveals `p`. Each leg must come back to
    the party that funded it: the USDC to the taker (the HTLC's immutable refundee), the Radiant
    covenant to the maker via its CSV branch.

    This is the path the happy-path run does not touch at all, and it is the one an operator
    actually needs when a counterparty goes quiet. It also exercises `mutual_refund`'s repair from
    this session: the two refunds are independent, so a failure in one must not skip the other.
    """
    node, url, workdir = env
    coord, cov, _p_secret, _eth_leg, _rxd_leg, _tk, _mk = _build(node, url, workdir, t_rxd_blocks=8)
    terms = coord.record.terms

    taker_before = _usdc_balance(url, _ADDR_TAKER)
    maker_before = _usdc_balance(url, _ADDR_MAKER)

    # Both legs funded, exactly as the happy path — a stalling maker still has to LOCK; "never locks
    # at all" is refused before any taker value moves.
    _rxd_pay(node, cov.funded_spk, terms.radiant_amount)
    node.rxd_mine(3)
    rec = await coord.taker_funds_btc(terms, now_unix_s=_now(url))
    assert rec.state is SwapState.BTC_LOCKED
    htlc = rec.counterchain_locator.contract_address
    assert _usdc_balance(url, htlc) == _AMOUNT
    rec = await coord.post_asset_lock_revalidate(cov.funded_spk, now_unix_s=_now(url))
    assert rec.state is SwapState.BOTH_LOCKED

    # Nobody claims. Mature the Radiant CSV, and warp past the ETH deadline.
    node.rxd_mine(terms.t_rxd.value + 1)
    _rpc(url, "evm_setNextBlockTimestamp", [terms.eth_timeout_unix_s + 1])
    _mine(url, 1)

    rec = await coord.mutual_refund()
    assert rec.state is SwapState.MUTUAL_REFUND, f"mutual refund did not complete: {rec.state}"

    # The USDC is back with the TAKER, who funded it — and the maker gained nothing.
    assert _usdc_balance(url, htlc) == 0, "the HTLC still holds USDC after the refund"
    # NET ZERO, not +_AMOUNT: `taker_before` is the balance BEFORE funding, so the taker paid the
    # USDC out and got it back. Being made WHOLE is the property — an earlier version of this line
    # expected a gain, which no refund path should ever produce.
    assert _usdc_balance(url, _ADDR_TAKER) == taker_before, "the taker was not made whole by the refund"
    assert _usdc_balance(url, _ADDR_MAKER) == maker_before, "the maker gained USDC on a refund path"

    # And the Radiant covenant is spent — refunded to the maker via the CSV branch.
    spent = node.rxd("gettxout", coord.record.radiant_covenant_outpoint.split(":")[0], "0")
    assert spent in (None, ""), "the Radiant covenant was not refunded"
