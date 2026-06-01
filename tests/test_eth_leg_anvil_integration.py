"""Anvil-backed integration proof of the pyrxd ETH HTLC leg (Phase 4 — the live-chain gate).

Deploys the REAL ``EthHtlc.sol`` (the per-swap model the leg targets) on a local Anvil and
drives the full leg lifecycle against a live EVM — converting the DESIGNED-AND-UNPROVEN network
methods (fund / verify_funded / claim / refund / fetch_claim_artifacts / recover_secret /
assert_claim_provenance / claim_finality_verdict) into PROVEN. In particular this exercises the
audit-hardened paths against reality: the R6 provenance gate against a genuine ``Claimed(p)``
event (not a hand-crafted log), verify_funded's immutables-by-getter + EOA-only + balance
binding, and the per-swap-unique-contract-address provenance.

Marked ``@integration`` (excluded from the default suite; needs the ``anvil`` binary + web3 +
eth-keys). Anvil's deterministic dev keys are PUBLIC and control ONLY the local devnet — no real
value (cf. the weak-key lesson: these are full-entropy published anvil defaults, not hand-rolled).
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
if shutil.which("anvil") is None:  # pragma: no cover - environment gate
    pytest.skip("anvil binary not available", allow_module_level=True)

from pyrxd.eth_wallet.htlc_leg import EthHtlcContractLeg
from pyrxd.eth_wallet.rpc import EthRpc
from pyrxd.security.errors import ValidationError
from pyrxd.security.secrets import PrivateKeyMaterial

pytestmark = pytest.mark.integration

_CHAIN_ID = 31337
# Anvil's deterministic, PUBLIC dev keys (local devnet only — no real value).
_KEY_TAKER = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"  # acct 0 — deploys/funds/refunds
_KEY_MAKER = "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"  # acct 1 — claims
_ADDR_MAKER = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
_ADDR_TAKER = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
_AMOUNT_WEI = 10**15  # 0.001 ETH

_ARTIFACT = json.loads((pathlib.Path(__file__).parent / "fixtures" / "EthHtlc.json").read_text())


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture()
def anvil_url():
    """Start a fresh, isolated anvil per test (so evm_increaseTime cannot leak across tests)."""
    port = _free_port()
    url = f"http://127.0.0.1:{port}"
    proc = subprocess.Popen(
        ["anvil", "--port", str(port), "--chain-id", str(_CHAIN_ID), "--silent"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        body = b'{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}'
        for _ in range(100):
            try:
                req = urllib.request.Request(url, data=body, headers={"content-type": "application/json"})
                urllib.request.urlopen(req, timeout=0.5).read()
                break
            except Exception:
                time.sleep(0.1)
        else:  # pragma: no cover
            pytest.fail("anvil did not become ready")
        yield url
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()


def _legs(url: str):
    """A shared rpc + a taker leg (funds/refunds) and a maker leg (claims)."""
    rpc = EthRpc(url, expected_chain_id=_CHAIN_ID)
    taker = EthHtlcContractLeg(
        rpc=rpc, signing_key=PrivateKeyMaterial(bytes.fromhex(_KEY_TAKER)), chain_id=_CHAIN_ID, artifact=_ARTIFACT
    )
    maker = EthHtlcContractLeg(
        rpc=rpc, signing_key=PrivateKeyMaterial(bytes.fromhex(_KEY_MAKER)), chain_id=_CHAIN_ID, artifact=_ARTIFACT
    )
    return rpc, taker, maker


async def _now_plus(rpc, seconds: int) -> int:
    block = await rpc.w3.eth.get_block("latest")
    return int(block["timestamp"]) + seconds


async def _advance_time(rpc, seconds: int) -> None:
    await rpc.w3.provider.make_request("evm_increaseTime", [seconds])
    await rpc.w3.provider.make_request("evm_mine", [])


def _secret():
    p = os.urandom(32)
    return p, hashlib.sha256(p).digest()


async def test_deploy_verify_claim_scrape_provenance(anvil_url):
    rpc, taker, maker = _legs(anvil_url)
    try:
        p, h = _secret()
        timeout = await _now_plus(rpc, 3600)
        # TAKER deploys + funds (claimant=maker, refundee=taker).
        locator = await taker.fund(
            hashlock=h, claimant=_ADDR_MAKER, refundee=_ADDR_TAKER, timeout=timeout, amount_wei=_AMOUNT_WEI
        )
        assert locator.contract_address.startswith("0x") and locator.amount_wei == _AMOUNT_WEI

        # Pre-RXD-lock binding gate against the REAL contract (immutables-by-getter + EOA + balance).
        await taker.verify_funded(locator, expected_amount_wei=_AMOUNT_WEI)

        # MAKER claims with p (emits the real Claimed(p) event, pays the maker).
        claim_tx = await maker.claim(locator, p)

        # Scrape p from the on-chain claim (calldata + log data), recover by sha256==H.
        artifacts = await maker.fetch_claim_artifacts(claim_tx)
        recovered = maker.recover_secret(artifacts, h)
        assert recovered == p

        # R6 provenance against a GENUINE Claimed(p) log — binds the secret p + the per-swap address.
        await taker.assert_claim_provenance(claim_tx, contract_address=locator.contract_address, preimage=p)

        # Finality verdict (anvil mines instantly; the claim is at/under the chain head).
        verdict = await taker.claim_finality_verdict(claim_tx)
        assert verdict.state.value in {"final", "not_yet_final_live"}
    finally:
        await rpc.close()


async def test_verify_funded_rejects_wrong_amount(anvil_url):
    rpc, taker, _ = _legs(anvil_url)
    try:
        _, h = _secret()
        timeout = await _now_plus(rpc, 3600)
        locator = await taker.fund(
            hashlock=h, claimant=_ADDR_MAKER, refundee=_ADDR_TAKER, timeout=timeout, amount_wei=_AMOUNT_WEI
        )
        # Binding gate fails closed when the expected amount != the funded balance.
        with pytest.raises(ValidationError, match="funded balance"):
            await taker.verify_funded(locator, expected_amount_wei=_AMOUNT_WEI + 1)
    finally:
        await rpc.close()


async def test_provenance_rejects_foreign_contract_claim(anvil_url):
    """R6 on a real chain: a claim on contract A does NOT pass provenance for contract B (the
    per-swap-unique address is the binding), even with the same H/p."""
    rpc, taker, maker = _legs(anvil_url)
    try:
        p, h = _secret()
        timeout = await _now_plus(rpc, 3600)
        loc_a = await taker.fund(
            hashlock=h, claimant=_ADDR_MAKER, refundee=_ADDR_TAKER, timeout=timeout, amount_wei=_AMOUNT_WEI
        )
        loc_b = await taker.fund(
            hashlock=h, claimant=_ADDR_MAKER, refundee=_ADDR_TAKER, timeout=timeout, amount_wei=_AMOUNT_WEI
        )
        assert loc_a.contract_address != loc_b.contract_address  # fresh CREATE per swap
        claim_a = await maker.claim(loc_a, p)
        await taker.assert_claim_provenance(claim_a, contract_address=loc_a.contract_address, preimage=p)  # ok
        with pytest.raises(ValidationError, match="not this swap's HTLC contract"):
            await taker.assert_claim_provenance(claim_a, contract_address=loc_b.contract_address, preimage=p)
    finally:
        await rpc.close()


async def test_refund_after_timeout_and_claim_blocked_when_expired(anvil_url):
    rpc, taker, maker = _legs(anvil_url)
    try:
        p, h = _secret()
        timeout = await _now_plus(rpc, 100)
        locator = await taker.fund(
            hashlock=h, claimant=_ADDR_MAKER, refundee=_ADDR_TAKER, timeout=timeout, amount_wei=_AMOUNT_WEI
        )
        # Fast-forward past the timeout.
        await _advance_time(rpc, 200)
        # A claim is now expired — the contract reverts; the leg's eth_call preflight catches it.
        with pytest.raises(ValidationError):
            await maker.claim(locator, p)
        # The taker's unilateral refund now succeeds (pays the refundee).
        refund_tx = await taker.refund(locator)
        receipt = await rpc.wait_receipt(refund_tx)
        assert int(receipt.get("status", 0)) == 1
    finally:
        await rpc.close()
