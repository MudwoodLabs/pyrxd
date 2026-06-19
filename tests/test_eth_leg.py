"""Tests for the EthLeg coordinator adapter (Tier-1 B3). No web3 / no chain.

EthLeg wraps a real EthHtlcContractLeg (so the isinstance gate passes); the network methods
are monkeypatched to record delegation, and the pure paths (commitment, locked_amount,
scrape_secret) are tested for real.
"""

from __future__ import annotations

import hashlib
import os

import pytest

from pyrxd.eth_wallet.htlc_leg import EthHtlcContractLeg
from pyrxd.eth_wallet.locator import EthHtlcLocator
from pyrxd.gravity.eth_leg import EthLeg
from pyrxd.gravity.finality import CounterClaimFinality, CounterClaimState
from pyrxd.security.errors import ValidationError
from pyrxd.security.secrets import PrivateKeyMaterial

_ART = {"abi": [], "bytecode": "0x00", "runtime_bytecode": "0x00"}
_MAKER = "0x" + "11" * 20
_TAKER = "0x" + "22" * 20
_TIMEOUT = 1779710245


def _contract_leg() -> EthHtlcContractLeg:
    return EthHtlcContractLeg(rpc=object(), signing_key=PrivateKeyMaterial.generate(), chain_id=11155111, artifact=_ART)


def _eth_leg(contract_leg=None, *, network="anvil", audit_cleared=True) -> EthLeg:
    return EthLeg(
        contract_leg=contract_leg or _contract_leg(),
        network=network,
        claim_to=_MAKER,
        refund_to=_TAKER,
        eth_timeout_unix_s=_TIMEOUT,
        audit_cleared=audit_cleared,
    )


class _Terms:  # minimal duck-typed NegotiatedTerms
    def __init__(self, hashlock: bytes, value_amount: int):
        self.hashlock = hashlock
        self.value_amount = value_amount


def _locator(amount_wei: int = 10**15) -> EthHtlcLocator:
    return EthHtlcLocator(
        chain_id=11155111,
        contract_address="0x" + "ab" * 20,
        deploy_tx_hash="0x" + "cd" * 32,
        hashlock="0x" + "ef" * 32,
        claimant=_MAKER,
        refundee=_TAKER,
        timeout=_TIMEOUT,
        amount_wei=amount_wei,
    )


# -- ctor / gate ----------------------------------------------------------------------


def test_ctor_rejects_non_contract_leg_and_bad_args():
    with pytest.raises(ValidationError):
        EthLeg(contract_leg=object(), network="anvil", claim_to=_MAKER, refund_to=_TAKER, eth_timeout_unix_s=1)
    with pytest.raises(ValidationError):
        _eth_leg(network="")
    with pytest.raises(ValidationError):
        EthLeg(
            contract_leg=_contract_leg(),
            network="anvil",
            claim_to=_MAKER,
            refund_to=_TAKER,
            eth_timeout_unix_s=0,
            audit_cleared=True,
        )


def test_audit_gate_no_longer_blocks_value_network():
    # 0.9.0: the audit gate is retained for backward-compat but no longer raises —
    # the leg constructs on a value-bearing network with or without the opt-in.
    leg = _eth_leg(network="mainnet", audit_cleared=False)
    assert leg.network == "mainnet"
    leg = _eth_leg(network="mainnet", audit_cleared=True)
    assert leg.network == "mainnet"


# -- pure paths -----------------------------------------------------------------------


def test_commitment_deterministic_and_derive_equals_promised():
    leg = _eth_leg()
    terms = _Terms(hashlib.sha256(b"x").digest(), 10**15)
    assert leg.derive_funding_scriptpubkey(terms) == leg.promised_funding_scriptpubkey(terms)
    # commitment changes with the binding inputs
    other = _Terms(hashlib.sha256(b"y").digest(), 10**15)
    assert leg.derive_funding_scriptpubkey(terms) != leg.derive_funding_scriptpubkey(other)


def test_locked_amount_is_wei():
    assert _eth_leg().locked_amount(_locator(amount_wei=12345)) == 12345


def test_scrape_secret_recovers_by_hashlock():
    leg = _eth_leg()
    p = os.urandom(32)
    h = hashlib.sha256(p).digest()
    artifacts = [os.urandom(4) + b"\x00" * 28 + p, os.urandom(40)]  # p in calldata after a selector
    assert leg.scrape_secret(artifacts, h) == p
    with pytest.raises(ValidationError):
        leg.scrape_secret([os.urandom(40)], h)  # absent → fail-closed


# -- delegation (network methods monkeypatched) ---------------------------------------


async def test_fund_derives_kwargs_and_runs_verify(monkeypatch):
    cl = _contract_leg()
    loc = _locator(10**15)
    calls = {}

    async def fake_fund(**kw):
        calls["fund"] = kw
        return loc

    async def fake_verify(locator, *, expected_amount_wei, block_identifier=None):
        calls["verify"] = (locator, expected_amount_wei)

    monkeypatch.setattr(cl, "fund", fake_fund)
    monkeypatch.setattr(cl, "verify_funded", fake_verify)
    leg = _eth_leg(cl)
    h = hashlib.sha256(os.urandom(32)).digest()

    out = await leg.fund(_Terms(h, 10**15))
    assert out is loc
    assert calls["fund"] == {
        "hashlock": h,
        "claimant": _MAKER,
        "refundee": _TAKER,
        "timeout": _TIMEOUT,
        "amount_wei": 10**15,
    }
    assert calls["verify"] == (loc, 10**15)  # post-deploy binding gate ran


def test_expected_locator_built_from_own_config():
    """The maker's expected_locator binds the contract to the MAKER's OWN payout config + terms —
    NOT a counterparty-supplied locator (red-team CRITICAL maker-verify gate)."""
    leg = _eth_leg()
    h = hashlib.sha256(os.urandom(32)).digest()
    exp = leg.expected_locator(_Terms(h, 10**15), contract_address="0x" + "99" * 20)
    assert exp.claimant.lower() == _MAKER.lower()  # the maker MUST be paid on claim
    assert exp.refundee.lower() == _TAKER.lower()
    assert exp.hashlock_bytes == h
    assert exp.amount_wei == 10**15
    assert exp.timeout == _TIMEOUT
    assert exp.chain_id == 11155111
    assert exp.contract_address.lower() == ("0x" + "99" * 20).lower()


async def test_verify_counterparty_funded_uses_expected_locator(monkeypatch):
    """verify_counterparty_funded calls verify_funded with the MAKER's expected locator (built from
    own config), so a contract whose on-chain claimant != the maker is caught by verify_funded."""
    cl = _contract_leg()
    seen = {}

    async def fake_verify(locator, *, expected_amount_wei, block_identifier=None):
        seen["locator"] = locator
        seen["amount"] = expected_amount_wei

    monkeypatch.setattr(cl, "verify_funded", fake_verify)
    leg = _eth_leg(cl)
    h = hashlib.sha256(os.urandom(32)).digest()
    out = await leg.verify_counterparty_funded("0x" + "99" * 20, _Terms(h, 10**15))
    # the locator handed to verify_funded carries the MAKER's expected claimant, at the taker address
    assert seen["locator"].claimant.lower() == _MAKER.lower()
    assert seen["locator"].contract_address.lower() == ("0x" + "99" * 20).lower()
    assert seen["amount"] == 10**15
    assert out is seen["locator"]


async def test_verify_counterparty_funded_propagates_mismatch(monkeypatch):
    """A hostile taker's contract (claimant != maker / underfunded) makes verify_funded raise; the
    maker-side gate propagates it fail-closed so the maker never locks the asset."""
    cl = _contract_leg()

    async def fake_verify(locator, *, expected_amount_wei, block_identifier=None):
        raise ValidationError("on-chain claimant != negotiated maker")

    monkeypatch.setattr(cl, "verify_funded", fake_verify)
    leg = _eth_leg(cl)
    with pytest.raises(ValidationError, match="claimant"):
        await leg.verify_counterparty_funded("0x" + "99" * 20, _Terms(hashlib.sha256(b"x").digest(), 10**15))


async def test_claim_refund_fetch_verdict_delegate(monkeypatch):
    cl = _contract_leg()
    loc = _locator()
    seen = {}

    async def fake_claim(locator, preimage):
        seen["claim"] = (locator, preimage)
        return "0xclaim"

    async def fake_refund(locator):
        seen["refund"] = locator
        return "0xrefund"

    async def fake_fetch(tx_hash):
        seen["fetch"] = tx_hash
        return [b"blob"]

    async def fake_verdict(tx_hash):
        seen["verdict"] = tx_hash
        return CounterClaimFinality(state=CounterClaimState.FINAL)

    monkeypatch.setattr(cl, "claim", fake_claim)
    monkeypatch.setattr(cl, "refund", fake_refund)
    monkeypatch.setattr(cl, "fetch_claim_artifacts", fake_fetch)
    monkeypatch.setattr(cl, "claim_finality_verdict", fake_verdict)
    leg = _eth_leg(cl)

    assert await leg.claim(loc, b"\x01" * 32) == "0xclaim"
    assert seen["claim"] == (loc, b"\x01" * 32)
    # refund ignores the BTC-shaped relative Timelock the coordinator passes
    assert await leg.refund(loc, timeout="ignored-relative-timelock") == "0xrefund"
    assert seen["refund"] is loc
    assert await leg.fetch_claim_artifacts("0xtx") == [b"blob"]
    assert seen["fetch"] == "0xtx"
    v = await leg.claim_finality_verdict("0xtx")
    assert v.state is CounterClaimState.FINAL and seen["verdict"] == "0xtx"


# -- R6 provenance gate (real EthHtlcContractLeg logic, injected fake rpc) -------------

import hashlib as _hashlib

from pyrxd.eth_wallet.htlc_leg import _addr, _b

_CONTRACT = "0x" + "ab" * 20


class _FakeRpc:
    def __init__(self, *, to, status=1, logs=None):
        self._to = to
        self._status = status
        self._logs = logs if logs is not None else []

    async def get_transaction(self, tx_hash):
        return {"to": self._to, "input": "0x"}

    async def wait_receipt(self, tx_hash):
        return {"status": self._status, "blockNumber": 10, "logs": self._logs}


def _leg_with_rpc(rpc) -> EthHtlcContractLeg:
    return EthHtlcContractLeg(rpc=rpc, signing_key=PrivateKeyMaterial.generate(), chain_id=11155111, artifact=_ART)


# The deployed contract emits Claimed(bytes32 preimage) — the SECRET p in non-indexed log
# DATA, never the public hashlock H (H is a constructor immutable). The gate binds p, not H.
def _p() -> bytes:
    return os.urandom(32)


def _claimed_log_with_p(p, *, address=_CONTRACT):
    # Claimed(bytes32 preimage): non-indexed → p lives in log data (topics[0] is the selector).
    return {"address": address, "topics": ["0x" + "cc" * 32], "data": "0x" + p.hex()}


async def test_provenance_accepts_claimed_event_carrying_p():
    p = _p()
    leg = _leg_with_rpc(_FakeRpc(to=_CONTRACT, logs=[_claimed_log_with_p(p)]))
    await leg.assert_claim_provenance("0xtx", contract_address=_CONTRACT, preimage=p)  # no raise


async def test_provenance_accepts_p_in_a_topic_too():
    # Defensive: a contract that indexed the preimage would put p in a topic — still bound.
    p = _p()
    log = {"address": _CONTRACT, "topics": ["0x" + "cc" * 32, "0x" + p.hex()], "data": "0x"}
    leg = _leg_with_rpc(_FakeRpc(to=_CONTRACT, logs=[log]))
    await leg.assert_claim_provenance("0xtx", contract_address=_CONTRACT, preimage=p)  # no raise


async def test_provenance_rejects_H_only_log_not_p():
    # THE AUDIT REGRESSION (HIGH-2): a log carrying the PUBLIC hashlock H but NOT the secret p
    # must be REFUSED. H is public + reused on both legs, so an H-match proves nothing; the real
    # Claimed(p) event carries p, never H. The old gate accepted this; the fixed gate rejects it.
    p = _p()
    h = _hashlib.sha256(p).digest()
    log = {"address": _CONTRACT, "topics": ["0x" + "cc" * 32, "0x" + h.hex()], "data": "0x"}
    leg = _leg_with_rpc(_FakeRpc(to=_CONTRACT, logs=[log]))
    with pytest.raises(ValidationError, match="carries the revealed preimage"):
        await leg.assert_claim_provenance("0xtx", contract_address=_CONTRACT, preimage=p)


async def test_provenance_accepts_smart_contract_wallet_claim_diff_to():
    """A claim routed through a smart-contract wallet / multicall has tx.to != our HTLC, but the
    INNER call still emits Claimed(p) FROM our contract — must be ACCEPTED (red-team MEDIUM: the
    old tx.to== check wrongly rejected this). The log-emitter binding is what pins the swap."""
    p = _p()
    leg = _leg_with_rpc(_FakeRpc(to="0x" + "cd" * 20, logs=[_claimed_log_with_p(p)]))  # to = the wallet, not our HTLC
    await leg.assert_claim_provenance("0xtx", contract_address=_CONTRACT, preimage=p)  # no raise


async def test_provenance_rejects_cross_swap_log_from_other_contract():
    """A Claimed(p) log emitted by a DIFFERENT contract (a cross-swap claim, even one reusing H)
    is REJECTED — only a log FROM our per-swap contract counts."""
    p = _p()
    other = "0x" + "cd" * 20
    leg = _leg_with_rpc(_FakeRpc(to=other, logs=[_claimed_log_with_p(p, address=other)]))
    with pytest.raises(ValidationError, match="no Claimed"):
        await leg.assert_claim_provenance("0xtx", contract_address=_CONTRACT, preimage=p)


# -- claim_finality_verdict canonical-hash binding FAILS CLOSED (red-team MEDIUM) ------


class _FakeFinalityRpc:
    """Fake RPC for claim_finality_verdict: a receipt whose blockHash can be omitted, a canonical
    hash that can be empty/mismatched, and a finalized height — to drive the fail-closed binding."""

    def __init__(self, *, block_number=10, block_hash=b"\xaa" * 32, canonical=b"\xaa" * 32, finalized=20, status=1):
        self._bn, self._bh, self._canon, self._fin, self._status = (
            block_number,
            block_hash,
            canonical,
            finalized,
            status,
        )

    async def wait_receipt(self, tx_hash):
        r = {"status": self._status, "blockNumber": self._bn, "logs": []}
        if self._bh is not None:  # None => simulate an RPC that OMITS blockHash
            r["blockHash"] = self._bh
        return r

    async def canonical_block_hash(self, n):
        return self._canon

    async def finalized_block_number(self):
        return self._fin


def _finality_leg(rpc) -> EthHtlcContractLeg:
    return EthHtlcContractLeg(rpc=rpc, signing_key=PrivateKeyMaterial.generate(), chain_id=11155111, artifact=_ART)


async def test_finality_verdict_final_when_canonical_binds_and_buried():
    # blockHash == canonical AND tx_block(10) <= finalized(20) -> the only path to FINAL.
    v = await _finality_leg(
        _FakeFinalityRpc(block_hash=b"\xaa" * 32, canonical=b"\xaa" * 32, finalized=20)
    ).claim_finality_verdict("0xtx")
    assert v.state is CounterClaimState.FINAL


async def test_finality_verdict_fails_closed_on_missing_blockhash():
    # red-team MEDIUM: a lying RPC OMITS receipt.blockHash. tx_block <= finalized would have read
    # FINAL, but with no hash to bind we cannot prove canonicality -> NOT_YET_FINAL_LIVE.
    v = await _finality_leg(_FakeFinalityRpc(block_hash=None, finalized=20)).claim_finality_verdict("0xtx")
    assert v.state is CounterClaimState.NOT_YET_FINAL_LIVE


async def test_finality_verdict_fails_closed_on_empty_canonical_hash():
    # red-team MEDIUM: canonical_block_hash returns b"" (no hash at the claimed height) -> cannot bind.
    v = await _finality_leg(_FakeFinalityRpc(canonical=b"", finalized=20)).claim_finality_verdict("0xtx")
    assert v.state is CounterClaimState.NOT_YET_FINAL_LIVE


async def test_finality_verdict_not_final_on_canonical_hash_mismatch():
    # A fabricated receipt height whose blockHash != the canonical hash -> not in the canonical chain.
    v = await _finality_leg(
        _FakeFinalityRpc(block_hash=b"\xaa" * 32, canonical=b"\xbb" * 32, finalized=20)
    ).claim_finality_verdict("0xtx")
    assert v.state is CounterClaimState.NOT_YET_FINAL_LIVE


async def test_provenance_rejects_failed_status():
    p = _p()
    leg = _leg_with_rpc(_FakeRpc(to=_CONTRACT, status=0, logs=[_claimed_log_with_p(p)]))
    with pytest.raises(ValidationError, match="did not succeed"):
        await leg.assert_claim_provenance("0xtx", contract_address=_CONTRACT, preimage=p)


async def test_provenance_rejects_p_only_from_foreign_contract():
    p = _p()
    # A log from our contract WITHOUT p, and a p-bearing log from a FOREIGN contract.
    logs = [
        {"address": _CONTRACT, "topics": ["0x" + "11" * 32], "data": "0x"},
        _claimed_log_with_p(p, address="0x" + "ee" * 20),
    ]
    leg = _leg_with_rpc(_FakeRpc(to=_CONTRACT, logs=logs))
    with pytest.raises(ValidationError, match="carries the revealed preimage"):
        await leg.assert_claim_provenance("0xtx", contract_address=_CONTRACT, preimage=p)


async def test_provenance_rejects_bad_preimage_len():
    leg = _leg_with_rpc(_FakeRpc(to=_CONTRACT))
    with pytest.raises(ValidationError, match="32 bytes"):
        await leg.assert_claim_provenance("0xtx", contract_address=_CONTRACT, preimage=b"\x01" * 31)


def test_helpers_b_and_addr():
    assert _b(None) == b"" and _b("0x0a0b") == b"\x0a\x0b" and _b(b"\x01") == b"\x01"
    assert _b("0a0b") == b"\x0a\x0b"  # bare hex (no 0x)
    assert _addr(None) == "" and _addr("0xAbCd") == "0xabcd"


async def test_eth_leg_delegates_provenance(monkeypatch):
    cl = _contract_leg()
    seen = {}

    async def fake_prov(tx_hash, *, contract_address, preimage):
        seen["args"] = (tx_hash, contract_address, preimage)

    monkeypatch.setattr(cl, "assert_claim_provenance", fake_prov)
    leg = _eth_leg(cl)
    p = _p()
    await leg.assert_claim_provenance("0xtx", contract_address=_CONTRACT, preimage=p)
    assert seen["args"] == ("0xtx", _CONTRACT, p)


async def test_fund_rejects_timeout_mismatch_with_terms(monkeypatch):
    # Wave C consistency: the leg's absolute deadline must equal the negotiated term the
    # coordinator's ordering gate validated.
    cl = _contract_leg()

    async def fake_fund(**kw):
        return _locator()

    async def fake_verify(locator, *, expected_amount_wei, block_identifier=None):
        pass

    monkeypatch.setattr(cl, "fund", fake_fund)
    monkeypatch.setattr(cl, "verify_funded", fake_verify)
    leg = _eth_leg(cl)  # leg eth_timeout = _TIMEOUT (1779710245)

    class _TermsMismatch:
        hashlock = hashlib.sha256(b"x").digest()
        value_amount = 10**15
        eth_timeout_unix_s = 999  # != leg's _TIMEOUT

    with pytest.raises(ValidationError, match="must agree"):
        await leg.fund(_TermsMismatch())


# -- LOW-R1: verify_funded must pin the EOA get_code + balance reads to the SAME block ------


class _RecordingRpc:
    """Fake EthRpc recording the block_identifier each read is pinned to. Returns values that pass
    verify_funded (claimant/refundee EOAs => empty code; balance == expected; immutables match)."""

    def __init__(self, locator, amount_wei):
        self._loc = locator
        self._amount = amount_wei
        self.code_block_ids: dict[str, object] = {}
        self.balance_block_id: object = "UNSET"
        from web3 import Web3

        loc = locator

        class _Getter:
            def __init__(self, val):
                self._val = val

            async def call(self, *, block_identifier=None):
                return self._val

        class _Functions:
            def hashlock(self):
                return _Getter(loc.hashlock_bytes)

            def claimant(self):
                return _Getter(Web3.to_checksum_address(loc.claimant))

            def refundee(self):
                return _Getter(Web3.to_checksum_address(loc.refundee))

            def timeout(self):
                return _Getter(loc.timeout)

        class _Eth:
            def contract(self, address=None, abi=None):
                class _C:
                    functions = _Functions()

                return _C()

        class _W3:
            eth = _Eth()

        self.w3 = _W3()

    async def assert_chain(self):
        return None

    async def get_code(self, address, block_identifier=None):
        self.code_block_ids[address] = block_identifier
        return b"\x60\x00" if address == self._loc.contract_address else b""  # contract has code; EOAs empty

    async def get_balance(self, address, block_identifier=None):
        self.balance_block_id = block_identifier
        return self._amount


async def test_verify_funded_pins_eoa_and_balance_reads_to_the_block():
    pytest.importorskip("web3")  # verify_funded requires web3 (optional dep; absent in the base CI env)
    from web3 import Web3

    loc = EthHtlcLocator(
        chain_id=11155111,
        contract_address=Web3.to_checksum_address("0x" + "33" * 20),
        deploy_tx_hash="0x" + "de" * 32,
        hashlock="0x" + "ab" * 32,
        claimant=Web3.to_checksum_address("0x" + "11" * 20),
        refundee=Web3.to_checksum_address("0x" + "22" * 20),
        timeout=4_000_000_000,
        amount_wei=10**15,
    )
    rpc = _RecordingRpc(loc, loc.amount_wei)
    leg = EthHtlcContractLeg(rpc=rpc, signing_key=PrivateKeyMaterial.generate(), chain_id=11155111, artifact=_ART)
    leg._runtime_code_matches = lambda code: True  # bypass artifact-bytecode match; we test the PINNING

    await leg.verify_funded(loc, expected_amount_wei=loc.amount_wei, block_identifier="finalized")

    # The fix: the two EOA code reads AND the balance read honour the pin (were 'latest'/None before).
    assert rpc.code_block_ids[loc.claimant] == "finalized"
    assert rpc.code_block_ids[loc.refundee] == "finalized"
    assert rpc.balance_block_id == "finalized"
    assert rpc.code_block_ids[loc.contract_address] == "finalized"  # the core code read (already pinned)


def test_runtime_code_mask_gap_documented_and_empty_code_fails_closed():
    """Pin the EXACT shape of the _runtime_code_matches masking gap (audit eth_leg_web3 LOW /
    MEDIUM-1 residual): every committed-ZERO byte is masked — a superset of the immutable slots —
    so a contract whose logic differs ONLY at committed-zero positions passes this gate. That is
    why the gate alone cannot prove "no modified logic" and the 'finalized' verify pin is the live
    backstop (staged for real in test_eth_leg_anvil_integration.py's reorg test). Also pins the
    fail-closed cases the backstop relies on: empty code (a reorged-out deploy read at the
    finalized checkpoint) and any non-zero-position or length deviation must be rejected."""
    # offsets:                0     1     2     3     4
    runtime = bytes.fromhex("600060ff00")  # committed zeros at offsets 1 and 4
    art = {"abi": [], "bytecode": "0x00", "runtime_bytecode": "0x" + runtime.hex()}
    leg = EthHtlcContractLeg(rpc=object(), signing_key=PrivateKeyMaterial.generate(), chain_id=1, artifact=art)

    assert leg._runtime_code_matches(runtime)  # exact match passes
    # THE GAP: a byte swapped in at a committed-zero position is NOT verified (masked superset).
    assert leg._runtime_code_matches(bytes.fromhex("604260ff00"))
    assert leg._runtime_code_matches(bytes.fromhex("600060ff42"))
    # Fail-closed: non-zero-position deviation, length mismatch, and the reorged-out empty read.
    assert not leg._runtime_code_matches(bytes.fromhex("600060fe00"))
    assert not leg._runtime_code_matches(runtime + b"\x00")
    assert not leg._runtime_code_matches(b"")
