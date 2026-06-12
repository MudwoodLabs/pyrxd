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


def _start_anvil(*extra_args: str, chain_id: int = _CHAIN_ID):
    """Start a fresh, isolated anvil (so evm_increaseTime cannot leak across tests); yield its URL."""
    port = _free_port()
    url = f"http://127.0.0.1:{port}"
    proc = subprocess.Popen(
        ["anvil", "--port", str(port), "--chain-id", str(chain_id), "--silent", *extra_args],
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


@pytest.fixture()
def anvil_url():
    yield from _start_anvil()


@pytest.fixture()
def anvil_url_fast_finality():
    """Anvil with a 1-slot epoch so the 'finalized' tag lags the head by only ~2 blocks —
    small enough to drive finality forward with a few evm_mine calls (default epoch = 32
    slots → a 64-block lag), while still leaving a real non-finalized window at the tip
    for the reorg test to attack."""
    yield from _start_anvil("--slots-in-an-epoch", "1")


def _legs(url: str, chain_id: int = _CHAIN_ID):
    """A shared rpc + a taker leg (funds/refunds) and a maker leg (claims)."""
    rpc = EthRpc(url, expected_chain_id=chain_id)
    taker = EthHtlcContractLeg(
        rpc=rpc, signing_key=PrivateKeyMaterial(bytes.fromhex(_KEY_TAKER)), chain_id=chain_id, artifact=_ARTIFACT
    )
    maker = EthHtlcContractLeg(
        rpc=rpc, signing_key=PrivateKeyMaterial(bytes.fromhex(_KEY_MAKER)), chain_id=chain_id, artifact=_ARTIFACT
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
        # Provenance now binds on the LOG EMITTER (red-team MEDIUM: tx.to dropped). claim_a's logs are
        # emitted by loc_a, so no log from loc_b carries p -> fail-closed with the cross-swap message.
        with pytest.raises(ValidationError, match="cross-swap claim tx"):
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


async def test_finalized_pin_rejects_reorg_swapped_in_contract(anvil_url_fast_finality):
    """MEDIUM-1 residual (whole-stack audit 2026-06-10): stage the verify→lock reorg substitution
    on a real EVM and prove the 'finalized' pin is the live backstop for the runtime-mask gap.

    Attack model: the taker's deploy is reorged out inside the verify→lock window and a DIFFERENT
    deployment lands at the SAME (deployer, nonce) CREATE address. _runtime_code_matches masks
    every committed-zero byte (see test_eth_leg.py's mask-gap test), so a swapped-in contract can
    evade the 'latest' checks — the maker's pre-lock re-verify at 'finalized' is what closes this.

    Asserts: (a) 'latest' ACCEPTS the swapped-in contract (it cannot tell the substitution
    happened); (b) 'finalized' REJECTS it — the checkpoint predates the replacement, the code
    read returns empty, fail closed; (c) the balance read honours the pin too (LOW-R1 residual);
    (d) once the replacement itself finalizes, the SAME pinned verify passes — (b) rejected the
    reorg, not a broken tag."""
    rpc, taker, _maker = _legs(anvil_url_fast_finality)
    try:
        _, h = _secret()
        timeout = await _now_plus(rpc, 3600)
        snap = (await rpc.w3.provider.make_request("evm_snapshot", []))["result"]
        locator = await taker.fund(
            hashlock=h, claimant=_ADDR_MAKER, refundee=_ADDR_TAKER, timeout=timeout, amount_wei=_AMOUNT_WEI
        )
        # The taker's fund-time self-verify at 'latest' (the real protocol step) passes.
        await taker.verify_funded(locator, expected_amount_wei=_AMOUNT_WEI)

        # REORG: revert to the pre-deploy snapshot — the deploy is un-mined, nonce restored.
        assert (await rpc.w3.provider.make_request("evm_revert", [snap]))["result"] is True
        assert await rpc.get_code(locator.contract_address) == b""  # the honest deploy is gone

        # The replacement: same negotiated immutables (so the getter binding cannot see it) but
        # over-funded by 1 wei — a provably DIFFERENT deployment (different tx hash) at the SAME
        # (deployer, nonce) CREATE address.
        replacement = await taker.fund(
            hashlock=h, claimant=_ADDR_MAKER, refundee=_ADDR_TAKER, timeout=timeout, amount_wei=_AMOUNT_WEI + 1
        )
        assert replacement.contract_address == locator.contract_address
        assert replacement.deploy_tx_hash != locator.deploy_tx_hash

        # Precondition for (b): the finalized checkpoint predates the replacement's block.
        fin = await rpc.w3.eth.get_block("finalized")
        rec = await rpc.w3.eth.get_transaction_receipt(replacement.deploy_tx_hash)
        assert int(fin["number"]) < int(rec["blockNumber"])

        # (a) 'latest' accepts the swapped-in contract against the ORIGINAL locator — blind.
        await taker.verify_funded(locator, expected_amount_wei=_AMOUNT_WEI)
        # (b) 'finalized' fails closed: empty code at the checkpoint → runtime-logic mismatch.
        with pytest.raises(ValidationError, match="runtime logic"):
            await taker.verify_funded(locator, expected_amount_wei=_AMOUNT_WEI, block_identifier="finalized")
        # (c) LOW-R1 residual: the balance read honours the pin (0 at the checkpoint, funded at tip).
        assert await rpc.get_balance(locator.contract_address, "finalized") == 0
        assert await rpc.get_balance(locator.contract_address) == _AMOUNT_WEI + 1

        # (d) Control: mine past the finality lag; the same pinned verify now passes — proving
        # (b)'s rejection came from the reorg window, not from a broken/always-stale tag.
        for _ in range(4):
            await rpc.w3.provider.make_request("evm_mine", [])
        fin2 = await rpc.w3.eth.get_block("finalized")
        assert int(fin2["number"]) >= int(rec["blockNumber"])
        await taker.verify_funded(locator, expected_amount_wei=_AMOUNT_WEI, block_identifier="finalized")
    finally:
        await rpc.close()


@pytest.fixture()
def anvil_url_base_sepolia():
    """Anvil presenting the Base Sepolia chain id — proves the leg machinery is
    chain-id-agnostic across the EVM family (Tier 2.3: Base as a counter chain)."""
    from pyrxd.eth_wallet.chains import KNOWN_EVM_CHAINS

    yield from _start_anvil(chain_id=KNOWN_EVM_CHAINS["base-sepolia"].chain_id)


async def test_full_lifecycle_on_base_chain_id(anvil_url_base_sepolia):
    """Tier 2.3 (Base, EVM-family path): the SAME proven EthHtlc machinery — deploy/fund,
    verify_funded binding gate, claim(p), secret scrape, R6 provenance — runs unmodified
    against a node presenting Base Sepolia's chain id (84532). The chain is pinned at
    every layer: EthRpc refuses a wrong chain id, the leg signs EIP-155-bound txs, and
    the locator records chain_id for the durable SwapRecord."""
    from pyrxd.eth_wallet.chains import KNOWN_EVM_CHAINS, evm_chain_by_id

    base = KNOWN_EVM_CHAINS["base-sepolia"]
    rpc, taker, maker = _legs(anvil_url_base_sepolia, chain_id=base.chain_id)
    try:
        p, h = _secret()
        timeout = await _now_plus(rpc, 3600)
        locator = await taker.fund(
            hashlock=h, claimant=_ADDR_MAKER, refundee=_ADDR_TAKER, timeout=timeout, amount_wei=_AMOUNT_WEI
        )
        assert locator.chain_id == base.chain_id  # the durable record pins the chain
        await taker.verify_funded(locator, expected_amount_wei=_AMOUNT_WEI)
        claim_tx = await maker.claim(locator, p)
        artifacts = await maker.fetch_claim_artifacts(claim_tx)
        assert maker.recover_secret(artifacts, h) == p
        await taker.assert_claim_provenance(claim_tx, contract_address=locator.contract_address, preimage=p)
        # The registry's finality knob exists and respects the L1 floor (the safety contract
        # a MarginPolicy for this chain is seeded from).
        assert evm_chain_by_id(base.chain_id).finalization_window_s >= 768
    finally:
        await rpc.close()


async def test_wrong_chain_id_refused(anvil_url_base_sepolia):
    """The cross-chain pin fails closed: a leg negotiated for Ethereum L1 (chain id 1)
    pointed at a Base-chain-id node refuses at assert_chain — a swap can never silently
    run against the wrong EVM chain."""
    rpc, taker, _maker = _legs(anvil_url_base_sepolia, chain_id=1)
    try:
        _, h = _secret()
        with pytest.raises(ValidationError, match="wrong network"):
            await taker.fund(
                hashlock=h, claimant=_ADDR_MAKER, refundee=_ADDR_TAKER, timeout=4_000_000_000, amount_wei=_AMOUNT_WEI
            )
    finally:
        await rpc.close()
