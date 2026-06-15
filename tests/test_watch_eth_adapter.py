"""Tests for the production ETH counter-leg transport (``gravity.watch.eth_adapters``)
and the read-only ``EthRpc.get_logs`` / ``get_transaction_receipt`` primitives it is built on.

Coverage:
* ``EthRpc.get_logs`` — filter shape, transport-failure → NetworkError, entry-count bound.
* ``EthRpc.get_transaction_receipt`` — non-blocking fetch, not-found → None, error → NetworkError.
* ``RpcEthChainSource.claim_status`` — SELECTOR-AGNOSTIC, fail-toward-paging detection: canonical
  Claimed wins, Refunded-only is not a claim, an unrecognised event still pages (never a silent miss),
  unclaimed/pending-deploy, tx-hash normalisation, the eth_getLogs filter args (no topic filter).
* ``RpcEthChainSource.claim_finality_verdict`` — the verdict branches, the non-blocking not-found
  branch, RPC-error propagation, AND a DIFFERENTIAL PARITY test asserting the VERDICT LOGIC agrees
  with the audited ``EthHtlcContractLeg.claim_finality_verdict`` for any given receipt (the parity is
  over the verdict LOGIC, not the receipt-fetch strategy — the tower polls non-blocking by design).
* protocol conformance + an end-to-end ChainObserver→decide run through the REAL adapter.

The tower is ALERT-ONLY: these reads hold no key, sign nothing, and never read the preimage ``p``.
"""

from __future__ import annotations

import pytest

from pyrxd.eth_wallet.htlc_leg import EthHtlcContractLeg
from pyrxd.eth_wallet.rpc import _MAX_LOG_ENTRIES, EthRpc
from pyrxd.gravity.finality import CounterClaimState
from pyrxd.gravity.swap_state import SwapState
from pyrxd.gravity.watch import ChainObserver, EthChainSource, Intent, RpcEthChainSource, decide
from pyrxd.gravity.watch.eth_adapters import CLAIMED_TOPIC0, REFUNDED_TOPIC0, _to_0x_hash
from pyrxd.security.errors import NetworkError
from pyrxd.security.secrets import PrivateKeyMaterial
from tests.test_watch_quorum import FakeRxd, _eth_policy, _eth_record

_CONTRACT = "0x" + "ab" * 20
_DEPLOY = "0x" + "cd" * 32
_CLAIM_HASH = "0x" + "12" * 32
_OTHER_HASH = "0x" + "99" * 32


# ─────────────────────────────────────────────────────────── fakes ──


class _FakeEthRpc:
    """Minimal fake exposing the read-only methods ``RpcEthChainSource`` uses (plus ``wait_receipt``
    so the audited leg can run against the SAME fake in the parity test).

    ``claim_status`` drivers: ``deploy_block`` (None = unmined deploy) + ``logs``.
    ``claim_finality_verdict`` drivers: ``receipt_found`` (False ⇒ get_transaction_receipt None),
    ``receipt_error`` / ``finalized_error`` (raise), ``status`` / ``block`` / ``finalized`` /
    ``block_hash`` (None ⇒ receipt omits blockHash) / ``canonical`` (None ⇒ node returns empty hash).
    ``canonical_block_hash`` is HEIGHT-SENSITIVE: it returns the configured hash ONLY at ``block``,
    a non-matching hash at any other height — so a wrong-height bind fails the parity test."""

    def __init__(
        self,
        *,
        deploy_block: int | None = 10,
        logs: list | None = None,
        receipt_found: bool = True,
        receipt_error: Exception | None = None,
        finalized_error: Exception | None = None,
        status: int = 1,
        block: int = 100,
        finalized: int = 120,
        block_hash: bytes | None = b"\x11" * 32,
        canonical: bytes | None = b"\x11" * 32,
        head: int | None = None,
    ) -> None:
        self._deploy_block = deploy_block
        self._logs = logs if logs is not None else []
        self._receipt_found, self._receipt_error = receipt_found, receipt_error
        self._finalized_error = finalized_error
        self._status, self._block, self._finalized = status, block, finalized
        self._bh, self._canonical = block_hash, canonical
        # `head` drives finality_checkpoint()'s latest-head read (eth_blockNumber). Defaults to
        # finalized + 200 so a frozen finalized with a climbing head is the natural stall scenario.
        self._head = head if head is not None else finalized + 200
        self.get_logs_calls: list[dict] = []

    async def get_transaction(self, tx_hash):
        return {"blockNumber": self._deploy_block}

    async def get_logs(self, *, address, topics=None, from_block="earliest", to_block="latest"):
        self.get_logs_calls.append(
            {"address": address, "topics": topics, "from_block": from_block, "to_block": to_block}
        )
        return list(self._logs)

    def _receipt(self) -> dict:
        r: dict = {"status": self._status, "blockNumber": self._block}
        if self._bh is not None:
            r["blockHash"] = self._bh
        return r

    async def get_transaction_receipt(self, tx_hash):  # non-blocking — the adapter uses this
        if self._receipt_error is not None:
            raise self._receipt_error
        return self._receipt() if self._receipt_found else None

    async def wait_receipt(self, tx_hash):  # blocking — the audited leg uses this (parity oracle)
        return self._receipt()

    async def canonical_block_hash(self, n):
        if n != self._block:
            return b"\x99" * 32  # wrong height → non-matching hash (catches a wrong-height bind)
        return self._canonical if self._canonical is not None else b""

    async def finalized_block_number(self):
        if self._finalized_error is not None:
            raise self._finalized_error
        return self._finalized

    async def block_number(self):  # eth_blockNumber — the latest head for finality_checkpoint()
        return self._head


class _FakeEthNs:
    def __init__(self, *, logs=None, exc=None, receipt=None, receipt_exc=None):
        self._logs = logs if logs is not None else []
        self._exc = exc
        self._receipt = receipt
        self._receipt_exc = receipt_exc
        self.last_filter: dict | None = None

    async def get_logs(self, filt):
        self.last_filter = filt
        if self._exc is not None:
            raise self._exc
        return self._logs

    async def get_transaction_receipt(self, tx_hash):
        if self._receipt_exc is not None:
            raise self._receipt_exc
        return self._receipt


class _FakeW3:
    def __init__(self, **kw):
        self.eth = _FakeEthNs(**kw)


def _rpc_with(**kw) -> EthRpc:
    """A real EthRpc with its web3 swapped for a fake (no network); construction does not connect.

    Constructing EthRpc requires web3 (the optional ``eth`` extra), which CI does not install — these
    EthRpc-I/O tests therefore SKIP there (the same pattern as the keccak tests), exactly like the
    rest of EthRpc's transport methods. The security-critical ADAPTER logic is web3-free (fakes) and
    is covered in CI; here we exercise the thin get_logs / get_transaction_receipt wrappers locally."""
    pytest.importorskip("web3")
    r = EthRpc("http://localhost:8545", expected_chain_id=1)
    r._w3 = _FakeW3(**kw)
    return r


def _leg(rpc) -> EthHtlcContractLeg:
    # Mirrors test_finality_verdict.py::_leg — the audited keyed leg, used as the parity oracle.
    return EthHtlcContractLeg(
        rpc=rpc,
        signing_key=PrivateKeyMaterial.generate(),
        chain_id=11155111,
        artifact={"abi": [], "bytecode": "0x00", "runtime_bytecode": "0x00"},
    )


def _log(topic0: str | None, tx_hash: object = _CLAIM_HASH) -> dict:
    log: dict = {"transactionHash": tx_hash}
    if topic0 is not None:
        log["topics"] = [topic0]
    return log


# ───────────────────────────────────────────────────── pinned selectors ──


def test_event_selectors_match_keccak():
    web3 = pytest.importorskip("web3")
    assert web3.Web3.to_hex(web3.Web3.keccak(text="Claimed(bytes32)")) == CLAIMED_TOPIC0
    assert web3.Web3.to_hex(web3.Web3.keccak(text="Refunded()")) == REFUNDED_TOPIC0


def test_to_0x_hash_normalises_forms_and_rejects_others():
    assert _to_0x_hash("0xdeadbeef") == "0xdeadbeef"
    assert _to_0x_hash("deadbeef") == "0xdeadbeef"
    assert _to_0x_hash(b"\xab" * 32) == "0x" + "ab" * 32

    class _HexBytes(bytes):  # web3 returns tx hashes as HexBytes — a bytes subclass
        pass

    assert _to_0x_hash(_HexBytes(b"\xcd" * 32)) == "0x" + "cd" * 32
    # an unexpected type fails loudly here, not as a confusing downstream ValidationError
    with pytest.raises(NetworkError):
        _to_0x_hash(None)
    with pytest.raises(NetworkError):
        _to_0x_hash(12345)


# ─────────────────────────────────────────────────── EthRpc.get_logs ──


async def test_get_logs_returns_dicts_and_builds_filter():
    rpc = _rpc_with(logs=[{"transactionHash": b"\x12" * 32, "x": 1}])
    out = await rpc.get_logs(address=_CONTRACT, topics=[CLAIMED_TOPIC0], from_block=5, to_block="latest")
    assert out == [{"transactionHash": b"\x12" * 32, "x": 1}]
    assert rpc._w3.eth.last_filter == {
        "address": _CONTRACT,
        "fromBlock": 5,
        "toBlock": "latest",
        "topics": [CLAIMED_TOPIC0],
    }


async def test_get_logs_omits_topics_when_none():
    rpc = _rpc_with(logs=[])
    await rpc.get_logs(address=_CONTRACT, from_block=0)
    assert "topics" not in rpc._w3.eth.last_filter


async def test_get_logs_wraps_transport_error_as_network_error():
    rpc = _rpc_with(exc=RuntimeError("boom"))
    with pytest.raises(NetworkError):
        await rpc.get_logs(address=_CONTRACT)


async def test_get_logs_bounds_entry_count():
    rpc = _rpc_with(logs=[{} for _ in range(_MAX_LOG_ENTRIES + 1)])
    with pytest.raises(NetworkError):
        await rpc.get_logs(address=_CONTRACT)


# ───────────────────────────────────────── EthRpc.get_transaction_receipt ──


async def test_get_transaction_receipt_returns_dict():
    rpc = _rpc_with(receipt={"status": 1, "blockNumber": 100})
    assert await rpc.get_transaction_receipt(_CLAIM_HASH) == {"status": 1, "blockNumber": 100}


async def test_get_transaction_receipt_none_on_not_found():
    web3 = pytest.importorskip("web3")
    rpc = _rpc_with(receipt_exc=web3.exceptions.TransactionNotFound("nope"))
    assert await rpc.get_transaction_receipt(_CLAIM_HASH) is None  # non-blocking; not a 300s wait


async def test_get_transaction_receipt_wraps_other_error():
    rpc = _rpc_with(receipt_exc=RuntimeError("boom"))
    with pytest.raises(NetworkError):
        await rpc.get_transaction_receipt(_CLAIM_HASH)


# ───────────────────────────────────────── claim_status (detection) ──


async def test_claim_status_detects_canonical_claimed_and_scans_selector_agnostic():
    fake = _FakeEthRpc(deploy_block=10, logs=[_log(CLAIMED_TOPIC0, _CLAIM_HASH)])
    status = await RpcEthChainSource(fake).claim_status(_CONTRACT, _DEPLOY)
    assert status.claimed is True
    assert status.claim_tx_hash == _CLAIM_HASH
    # bounded to the contract lifetime, NO topic filter (selector-agnostic — mirrors the audited path)
    assert fake.get_logs_calls == [{"address": _CONTRACT, "topics": None, "from_block": 10, "to_block": "latest"}]


async def test_claim_status_prefers_claimed_log_over_refunded():
    fake = _FakeEthRpc(deploy_block=10, logs=[_log(REFUNDED_TOPIC0, _OTHER_HASH), _log(CLAIMED_TOPIC0, _CLAIM_HASH)])
    status = await RpcEthChainSource(fake).claim_status(_CONTRACT, _DEPLOY)
    assert status.claimed is True
    assert status.claim_tx_hash == _CLAIM_HASH  # the Claimed log, not just the newest


async def test_claim_status_refunded_only_is_not_a_claim():
    fake = _FakeEthRpc(deploy_block=10, logs=[_log(REFUNDED_TOPIC0, _OTHER_HASH)])
    status = await RpcEthChainSource(fake).claim_status(_CONTRACT, _DEPLOY)
    assert status.claimed is False  # maker refunded — never revealed p


async def test_claim_status_unrecognised_event_fails_toward_paging():
    # An event from OUR per-swap contract with a non-Claimed/non-Refunded selector must NOT be a
    # silent miss — a differently-shaped claim event still pages (over-page is a false alarm only).
    fake = _FakeEthRpc(deploy_block=10, logs=[_log("0x" + "77" * 32, _CLAIM_HASH)])
    status = await RpcEthChainSource(fake).claim_status(_CONTRACT, _DEPLOY)
    assert status.claimed is True
    assert status.claim_tx_hash == _CLAIM_HASH


async def test_claim_status_log_without_topics_fails_toward_paging():
    fake = _FakeEthRpc(deploy_block=10, logs=[_log(None, _CLAIM_HASH)])
    status = await RpcEthChainSource(fake).claim_status(_CONTRACT, _DEPLOY)
    assert status.claimed is True


async def test_claim_status_unclaimed_when_no_logs():
    fake = _FakeEthRpc(deploy_block=10, logs=[])
    status = await RpcEthChainSource(fake).claim_status(_CONTRACT, _DEPLOY)
    assert status.claimed is False
    assert status.claim_tx_hash is None


async def test_claim_status_pending_deploy_is_unclaimed_and_skips_log_scan():
    fake = _FakeEthRpc(deploy_block=None, logs=[_log(CLAIMED_TOPIC0, _CLAIM_HASH)])
    status = await RpcEthChainSource(fake).claim_status(_CONTRACT, _DEPLOY)
    assert status.claimed is False
    assert fake.get_logs_calls == []  # no point scanning a contract that isn't mined yet


async def test_claim_status_normalises_hexbytes_tx_hash():
    fake = _FakeEthRpc(deploy_block=10, logs=[_log(CLAIMED_TOPIC0, b"\x34" * 32)])
    status = await RpcEthChainSource(fake).claim_status(_CONTRACT, _DEPLOY)
    assert status.claimed is True
    assert status.claim_tx_hash == "0x" + "34" * 32  # bytes → 0x-hex, satisfies EthClaimStatus


async def test_claim_status_missing_tx_hash_raises_typed_error():
    fake = _FakeEthRpc(deploy_block=10, logs=[{"topics": [CLAIMED_TOPIC0]}])  # no transactionHash
    with pytest.raises(NetworkError):
        await RpcEthChainSource(fake).claim_status(_CONTRACT, _DEPLOY)


# ──────────────────────────────────── claim_finality_verdict branches ──

_FINAL = CounterClaimState.FINAL
_LIVE = CounterClaimState.NOT_YET_FINAL_LIVE

_VERDICT_MATRIX = [
    ("reverted", {"status": 0}, _LIVE),
    ("final_buried", {"status": 1, "block": 100, "finalized": 120}, _FINAL),
    ("final_boundary", {"status": 1, "block": 120, "finalized": 120}, _FINAL),
    ("not_yet_final", {"status": 1, "block": 200, "finalized": 120}, _LIVE),
    ("missing_blockhash", {"status": 1, "block": 100, "finalized": 120, "block_hash": None}, _LIVE),
    ("empty_canonical", {"status": 1, "block": 100, "finalized": 120, "canonical": None}, _LIVE),
    ("canonical_mismatch", {"status": 1, "block": 100, "finalized": 120, "canonical": b"\x22" * 32}, _LIVE),
]


@pytest.mark.parametrize("name,kw,expected", _VERDICT_MATRIX, ids=[m[0] for m in _VERDICT_MATRIX])
async def test_finality_verdict_branches(name, kw, expected):
    verdict = await RpcEthChainSource(_FakeEthRpc(**kw)).claim_finality_verdict(_CLAIM_HASH)
    assert verdict.state is expected
    assert verdict.confirmations is None and verdict.required_depth is None  # ETH = depth-less checkpoint


@pytest.mark.parametrize("name,kw,expected", _VERDICT_MATRIX, ids=[m[0] for m in _VERDICT_MATRIX])
async def test_finality_verdict_parity_with_audited_leg(name, kw, expected):
    # The keyless adapter's VERDICT LOGIC MUST agree with the audited keyed leg on every receipt —
    # this is what makes reproducing the logic (instead of extracting it from eth_wallet) safe: a
    # drift fails this test. The height-sensitive fake also forces the correct canonical-bind height.
    adapter_state = (await RpcEthChainSource(_FakeEthRpc(**kw)).claim_finality_verdict(_CLAIM_HASH)).state
    leg_state = (await _leg(_FakeEthRpc(**kw)).claim_finality_verdict(_CLAIM_HASH)).state
    assert adapter_state is leg_state is expected


async def test_finality_verdict_receipt_not_found_is_not_yet_final():
    # A reorg-orphaned / not-yet-mined claim tx: the NON-BLOCKING read returns None (no 300s wait) and
    # the verdict is NOT_YET_FINAL_LIVE → WATCH, re-detected next tick (fixes the tick-wedge finding).
    verdict = await RpcEthChainSource(_FakeEthRpc(receipt_found=False)).claim_finality_verdict(_CLAIM_HASH)
    assert verdict.state is CounterClaimState.NOT_YET_FINAL_LIVE


async def test_finality_verdict_propagates_receipt_error_fail_closed():
    src = RpcEthChainSource(_FakeEthRpc(receipt_error=NetworkError("rpc down")))
    with pytest.raises(NetworkError):
        await src.claim_finality_verdict(_CLAIM_HASH)


async def test_finality_verdict_propagates_finalized_error_fail_closed():
    # finalized_block_number raises (e.g. the finalized>head incoherence guard) → propagates, never FINAL.
    src = RpcEthChainSource(_FakeEthRpc(status=1, block=100, finalized_error=NetworkError("incoherent")))
    with pytest.raises(NetworkError):
        await src.claim_finality_verdict(_CLAIM_HASH)


# ───────────────────────────────── protocol conformance + integration ──


def test_rpc_eth_chain_source_satisfies_protocol():
    assert isinstance(RpcEthChainSource(_FakeEthRpc()), EthChainSource)


async def test_real_adapter_through_chain_observer_final_pages_claim():
    # Drive the REAL ChainObserver + RpcEthChainSource (over a fake EthRpc) end-to-end: a claimed +
    # FINAL ETH counter-leg, observed at a safe RXD window, must PAGE_CLAIM (mirrors the FakeEth
    # routing test, but through the production adapter wiring).
    fake = _FakeEthRpc(deploy_block=10, logs=[_log(CLAIMED_TOPIC0, _CLAIM_HASH)], block=100, finalized=120)
    rec = _eth_record(state=SwapState.SECRET_REVEALED)
    obs = await ChainObserver(eth=RpcEthChainSource(fake), rxd=FakeRxd(tip=150, cov_confs=51)).observe("s", rec)
    assert obs.eth_claim_detected is True
    assert obs.eth_claim_finality is CounterClaimState.FINAL
    d = decide(record=rec, observations=obs, policy=_eth_policy(), safety_window_blocks=6)
    assert d.intent is Intent.PAGE_CLAIM
    assert d.recommended_action == "taker_scrape_and_claim_asset"
    assert d.low_corroboration is True  # single-source ETH RPC + RXD


async def test_real_adapter_through_chain_observer_not_final_waits():
    fake = _FakeEthRpc(deploy_block=10, logs=[_log(CLAIMED_TOPIC0, _CLAIM_HASH)], block=100, finalized=0)
    rec = _eth_record(state=SwapState.SECRET_REVEALED)
    obs = await ChainObserver(eth=RpcEthChainSource(fake), rxd=FakeRxd(tip=150, cov_confs=51)).observe("s", rec)
    assert obs.eth_claim_detected is True
    assert obs.eth_claim_finality is CounterClaimState.NOT_YET_FINAL_LIVE
    d = decide(record=rec, observations=obs, policy=_eth_policy(), safety_window_blocks=6)
    assert d.intent is Intent.WATCH


async def test_real_adapter_unclaimed_through_chain_observer():
    fake = _FakeEthRpc(deploy_block=10, logs=[])
    rec = _eth_record(state=SwapState.BOTH_LOCKED)
    obs = await ChainObserver(eth=RpcEthChainSource(fake), rxd=FakeRxd(tip=200, cov_confs=101)).observe("s", rec)
    assert obs.eth_claim_detected is False
    assert obs.eth_claim_finality is None


# ─────────────────────────────── A8: finality_checkpoint() + across-time stall via real adapter ──


async def test_finality_checkpoint_returns_head_and_finalized():
    # finality_checkpoint() surfaces (head, finalized) for the stall tracker; finalized <= head holds.
    fake = _FakeEthRpc(deploy_block=10, finalized=900, head=1100)
    head, finalized = await RpcEthChainSource(fake).finality_checkpoint()
    assert (head, finalized) == (1100, 900)


async def test_finality_checkpoint_clamps_a_head_that_regressed_below_finalized():
    # A reorg/lagging-replica race where the head read comes back BELOW finalized must not yield an
    # incoherent pair the tracker would reject — head is clamped up to finalized (gap 0 = no stall).
    fake = _FakeEthRpc(deploy_block=10, finalized=1000, head=990)
    head, finalized = await RpcEthChainSource(fake).finality_checkpoint()
    assert finalized == 1000 and head == 1000  # clamped, finalized <= head holds


async def test_real_adapter_sustained_stall_upgrades_to_not_finalizing_across_ticks():
    # End-to-end through the REAL adapter: finalized frozen while the head climbs past the tracker's
    # patience window upgrades NOT_YET_FINAL_LIVE -> COUNTER_CHAIN_NOT_FINALIZING, and decide() SQUEEZES.
    # The point-in-time branch returns FINAL only when the claim tx_block <= finalized; here the claim
    # is at block 100 while finalized is frozen at 50, so the point-in-time verdict stays
    # NOT_YET_FINAL_LIVE every tick and only the across-time stall can upgrade it.
    fake = _FakeEthRpc(deploy_block=10, logs=[_log(CLAIMED_TOPIC0, _CLAIM_HASH)], block=100, finalized=50, head=60)
    observer = ChainObserver(eth=RpcEthChainSource(fake), rxd=FakeRxd(tip=150, cov_confs=51))
    rec = _eth_record(state=SwapState.SECRET_REVEALED)

    obs = await observer.observe("s", rec)  # establish the frozen-finalized run (gap 10, head 60)
    assert obs.eth_claim_finality is CounterClaimState.NOT_YET_FINAL_LIVE
    fake._head = 60 + 130  # head climbs +130 past patience while finalized(50) stays frozen; gap now 140
    obs = await observer.observe("s", rec)
    assert obs.eth_claim_finality is CounterClaimState.COUNTER_CHAIN_NOT_FINALIZING
    d = decide(record=rec, observations=obs, policy=_eth_policy(), safety_window_blocks=6)
    assert d.intent is Intent.PAGE_SQUEEZED
