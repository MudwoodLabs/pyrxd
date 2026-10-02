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
from pyrxd.eth_wallet.locator import EthHtlcLocator
from pyrxd.eth_wallet.rpc import EthRpc
from pyrxd.security.errors import NetworkError, PreRevealAbort, ValidationError
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


async def test_forged_immutable_copy_is_rejected_by_verify_funded(anvil_url):
    """FUND-SAFETY regression (proven exploit → fix). Solidity splices each immutable into 2–3
    SEPARATE runtime offsets; ``claimant`` (ref id 6) has copies at 1224 and 1418. The getter — and
    therefore verify_funded's claimant() bind — reads 1418, while ``claim()``'s value send reads
    1224. The old value-masked compare wildcarded every committed-zero byte and never checked the
    copies agreed, so a hostile TAKER could deploy a runtime with 1418=maker (getter honest) and
    1224=attacker: verify_funded passed, then claim(p) drained the whole balance to the attacker
    while revealing p (handing the taker the RXD leg too).

    Here: deploy the honest contract, read its real spliced runtime, forge ONLY the 1224 copy, place
    it at a fresh address via anvil_setCode + fund it, then run the MAKER's real verify_funded. The
    slot-exact compare must REJECT it (before the fix, verify_funded passed and the maker was robbed)."""
    from eth_utils import to_checksum_address

    rpc, taker, maker = _legs(anvil_url)
    try:
        _p, h = _secret()
        timeout = await _now_plus(rpc, 3600)
        honest = await taker.fund(
            hashlock=h, claimant=_ADDR_MAKER, refundee=_ADDR_TAKER, timeout=timeout, amount_wei=_AMOUNT_WEI
        )
        runtime = bytearray(await rpc.get_code(honest.contract_address))
        attacker = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"  # taker's own second address
        runtime[1224 : 1224 + 32] = b"\x00" * 12 + bytes.fromhex(attacker[2:])  # forge the claim() copy only
        faddr = to_checksum_address("0x" + "c0de" * 10)
        await rpc.w3.provider.make_request("anvil_setCode", [faddr, "0x" + bytes(runtime).hex()])
        await rpc.w3.provider.make_request("anvil_setBalance", [faddr, hex(_AMOUNT_WEI)])
        forged_loc = EthHtlcLocator(
            chain_id=_CHAIN_ID,
            contract_address=faddr,
            deploy_tx_hash="0x" + "00" * 32,
            hashlock="0x" + h.hex(),
            claimant=_ADDR_MAKER,
            refundee=_ADDR_TAKER,
            timeout=timeout,
            amount_wei=_AMOUNT_WEI,
        )
        # The getter copy (1418) is still the honest maker, so every immutable-by-getter bind passes;
        # only the exact runtime compare stands between the maker and revealing p to a robbing contract.
        with pytest.raises(ValidationError, match="does not EXACTLY equal"):
            await maker.verify_funded(forged_loc, expected_amount_wei=_AMOUNT_WEI)
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
        # P3 gas pre-check: a refund BEFORE the timeout is refused (the contract would revert anyway),
        # so no gas is burned on a guaranteed-revert tx. NetworkError = transient/retryable (wait for the
        # timeout), consistent with the BTC/covenant legs — not a fatal ValidationError.
        with pytest.raises(NetworkError, match="not yet mature"):
            await taker.refund(locator)
        # Fast-forward past the timeout.
        await _advance_time(rpc, 200)
        # A claim is now expired. This used to expect ValidationError, on the reasoning that the
        # contract reverts and the leg's eth_call preflight catches it. The claim-deadline guard
        # made that stale and STRICTER: it refuses on the timestamp before building anything, so
        # no preflight, no gas, and nothing reaches a provider. PreRevealAbort is the right type —
        # it means the preimage is still secret and the swap is refundable — and it is
        # deliberately not a ValidationError, so the old assertion could not see it.
        #
        # That distinction is the whole point on this path: a claim that mines late still publishes
        # p in its calldata while paying nothing, handing the counterparty both legs.
        with pytest.raises(PreRevealAbort, match="refusing to build a claim"):
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
    deployment lands at the SAME (deployer, nonce) CREATE address. The 'finalized' pin is a
    defence-in-depth backstop for that reorg substitution; the runtime compare is now slot-exact
    (see test_forged_immutable_copy_is_rejected_by_verify_funded below), so this test's replacement
    is a genuine honest deploy with identical immutables (over-funded by 1 wei) that 'latest' still
    accepts because its runtime is byte-identical.

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
        # (b) 'finalized' fails closed. It used to report this as a runtime-logic mismatch, which
        # conflated two different states: EMPTY code at the checkpoint (the deploy simply has not
        # finalized yet — wait) and DIFFERENT code (someone else's contract — you have been
        # robbed). During a live mainnet run the empty case fired the second message, which reads
        # as a theft alert when the truth was "retry in ~13 minutes". The refusal is the property
        # under test and it is unchanged; only the diagnosis is now honest about which state it saw.
        with pytest.raises(ValidationError, match="NOT YET FINALIZED") as exc:
            await taker.verify_funded(locator, expected_amount_wei=_AMOUNT_WEI, block_identifier="finalized")
        assert "runtime logic" not in str(exc.value), (
            "empty code at the checkpoint must not be reported as a wrong/attacker contract — "
            "that is the conflation this diagnosis was split to remove"
        )
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


# ---------------------------------------------------------------------------
# Erc20Htlc: the REAL contract through the exact runtime compare, and the immutable_names map
# checked by EXECUTING each getter.
# ---------------------------------------------------------------------------

_ERC20_ARTIFACT = json.loads((pathlib.Path(__file__).parent / "fixtures" / "Erc20Htlc.json").read_text())

#: A hand-assembled STUB token, placed with anvil_setCode: ``decimals()`` (0x313ce567) returns 6 and
#: every other call returns 10**12, so ``balanceOf`` reports any address as holding 10**12 base
#: units. It exists only so the token leg's decimals and balance reads have something to answer
#: them. It is NOT a model of a real token: no transfer moves anything and there is no freeze list.
#: What these tests are about is the HTLC's runtime; the real USDC path is the fork suite's job.
#:
#:   PUSH0 CALLDATALOAD PUSH1 0xe0 SHR PUSH4 0x313ce567 EQ PUSH1 0x1a JUMPI
#:   PUSH5 10**12 PUSH0 MSTORE PUSH1 0x20 PUSH0 RETURN
#:   0x1a: JUMPDEST PUSH1 6 PUSH0 MSTORE PUSH1 0x20 PUSH0 RETURN
_STUB_TOKEN_RUNTIME = "0x5f3560e01c63313ce56714601a5764e8d4a510005f5260205ff35b60065f5260205ff3"
_STUB_TOKEN_ADDR = "0x" + "70ce" * 10
_ERC20_AMOUNT = 12_345_678  # base units; non-round so an encoding slip cannot hide in zeros


async def _stub_token(rpc):
    from eth_utils import to_checksum_address

    from pyrxd.eth_wallet.tokens import Erc20Token

    await rpc.w3.provider.make_request("anvil_setCode", [to_checksum_address(_STUB_TOKEN_ADDR), _STUB_TOKEN_RUNTIME])
    return Erc20Token("STUB", _STUB_TOKEN_ADDR, 6, _CHAIN_ID, has_blacklist=False)


def _erc20_legs(rpc, token):
    from pyrxd.eth_wallet.erc20_leg import Erc20HtlcLeg

    def leg(key):
        return Erc20HtlcLeg(
            token=token,
            rpc=rpc,
            signing_key=PrivateKeyMaterial(bytes.fromhex(key)),
            chain_id=_CHAIN_ID,
            artifact=_ERC20_ARTIFACT,
        )

    return leg(_KEY_TAKER), leg(_KEY_MAKER)


async def test_a_real_Erc20Htlc_deploy_verifies_and_every_forged_copy_is_refused(anvil_url):
    """The token leg's counterpart of the forged-copy test above, against the REAL ``Erc20Htlc``.

    (a) The honest path: the taker's ``fund`` deploys the real contract and the maker's
    ``verify_funded`` accepts it, with the on-chain runtime EXACTLY equal to ``_expected_runtime``.
    That equality is the only thing that proves the token leg's own encodings — ``token`` as a
    right-aligned address word, ``amount`` as a big-endian uint — are the bytes the compiler
    splices; no unit test can, because every unit fake splices with the same encoder.

    (b) Every single copy of every immutable is bound: forge ONE copy at a time (the last byte of
    its word flipped) at a fresh address and the maker's real ``verify_funded`` refuses it. Each
    immutable has 2 or 3 copies and a getter reads only one, so this is the whole class the old
    value-masked compare missed, not only the ``claimant`` instance that was demonstrated."""
    import dataclasses

    from eth_utils import to_checksum_address

    rpc = EthRpc(anvil_url, expected_chain_id=_CHAIN_ID)
    try:
        token = await _stub_token(rpc)
        taker, maker = _erc20_legs(rpc, token)
        _p, h = _secret()
        timeout = await _now_plus(rpc, 3600)
        loc = await taker.fund(
            hashlock=h, claimant=_ADDR_MAKER, refundee=_ADDR_TAKER, timeout=timeout, amount_wei=_ERC20_AMOUNT
        )
        await maker.verify_funded(loc, expected_amount_wei=_ERC20_AMOUNT)
        honest = bytes(await rpc.get_code(loc.contract_address))
        assert honest == maker._expected_runtime(loc)

        forged_count = 0
        for slots in _ERC20_ARTIFACT["immutableReferences"].values():
            for slot in slots:
                forged = bytearray(honest)
                forged[slot["start"] + 31] ^= 0x01
                faddr = to_checksum_address("0x" + "cc" * 18 + f"{forged_count + 1:04x}")
                await rpc.w3.provider.make_request("anvil_setCode", [faddr, "0x" + bytes(forged).hex()])
                with pytest.raises(ValidationError, match="does not EXACTLY equal"):
                    await maker.verify_funded(
                        dataclasses.replace(loc, contract_address=faddr), expected_amount_wei=_ERC20_AMOUNT
                    )
                forged_count += 1
        # Non-vacuity: every slot of every immutable was forged and refused.
        assert forged_count == sum(len(s) for s in _ERC20_ARTIFACT["immutableReferences"].values()) >= 12
    finally:
        await rpc.close()


@pytest.mark.parametrize("artifact", [_ARTIFACT, _ERC20_ARTIFACT], ids=["EthHtlc", "Erc20Htlc"])
async def test_immutable_names_match_what_each_getter_RETURNS(anvil_url, artifact):
    """The id -> name map, checked by EXECUTION rather than by reading bytecode. Each
    ``immutableReferences`` group gets its own sentinel word in every one of its slots; the runtime
    is placed with anvil_setCode and each getter the map names is called. The getter must return
    exactly its group's sentinel. (Sentinels are 12 zero bytes + 20 distinct bytes, so an address
    getter's masking cannot change them.) The default-suite derivation in
    ``test_eth_htlc_immutable_names.py`` checks the same map from the bytecode alone."""
    from eth_utils import keccak, to_checksum_address

    rpc = EthRpc(anvil_url, expected_chain_id=_CHAIN_ID)
    try:
        runtime = bytearray(bytes.fromhex(artifact["runtime_bytecode"].removeprefix("0x")))
        sentinel = {}
        for n, (ref_id, slots) in enumerate(sorted(artifact["immutableReferences"].items())):
            sentinel[ref_id] = b"\x00" * 12 + bytes([0xA0 + n]) * 20
            for slot in slots:
                runtime[slot["start"] : slot["start"] + 32] = sentinel[ref_id]
        addr = to_checksum_address("0x" + "5e" * 20)
        await rpc.w3.provider.make_request("anvil_setCode", [addr, "0x" + bytes(runtime).hex()])
        returned = {}
        for ref_id, name in artifact["immutable_names"].items():
            data = "0x" + keccak(text=name + "()")[:4].hex()
            out = bytes(await rpc.w3.eth.call({"to": addr, "data": data}))
            returned[ref_id] = out
        assert len(returned) == len(artifact["immutableReferences"]) >= 4
        assert returned == sentinel
    finally:
        await rpc.close()


# ---------------------------------------------------------------------------
# Storage: a contract whose CODE is exact but whose `settled` flag is already set.
# ---------------------------------------------------------------------------


async def _deploy_presettled(rpc, runtime: bytes, *, value: int) -> str:
    """Create a contract carrying ``runtime`` verbatim with storage slot 0 already set to 1."""
    from eth_account import Account

    prefix = bytes.fromhex("6001600055" + f"61{len(runtime):04x}" + "80" + "610012" + "6000" + "39" + "6000" + "f3")
    assert len(prefix) == 0x12
    acct = Account.from_key(bytes.fromhex(_KEY_TAKER))
    tx = {
        "from": _ADDR_TAKER,
        "nonce": await rpc.w3.eth.get_transaction_count(_ADDR_TAKER),
        "value": value,
        "data": "0x" + (prefix + runtime).hex(),
        "gas": 3_000_000,
        "chainId": _CHAIN_ID,
        "maxFeePerGas": 10**10,
        "maxPriorityFeePerGas": 10**9,
    }
    receipt = await rpc.w3.eth.wait_for_transaction_receipt(
        await rpc.w3.eth.send_raw_transaction(acct.sign_transaction(tx).raw_transaction)
    )
    assert receipt["status"] == 1
    return receipt["contractAddress"]


async def test_SETTLED_SLOT_is_the_flag_an_honest_claim_sets(anvil_url):
    """The behavioural half of ``test_eth_htlc_settled_slot.py``: on the REAL contract, slot
    ``SETTLED_SLOT`` is zero after funding and non-zero after a claim. If the flag lived anywhere
    else, the leg's settled check would be reading the wrong word."""
    from pyrxd.eth_wallet.htlc_leg import SETTLED_SLOT

    rpc, taker, maker = _legs(anvil_url)
    try:
        p, h = _secret()
        loc = await taker.fund(
            hashlock=h,
            claimant=_ADDR_MAKER,
            refundee=_ADDR_TAKER,
            timeout=await _now_plus(rpc, 3600),
            amount_wei=_AMOUNT_WEI,
        )
        assert not any(bytes(await rpc.w3.eth.get_storage_at(loc.contract_address, SETTLED_SLOT)))
        await maker.claim(loc, p)
        assert any(bytes(await rpc.w3.eth.get_storage_at(loc.contract_address, SETTLED_SLOT)))
    finally:
        await rpc.close()


async def test_a_PRE_SETTLED_exact_runtime_is_refused_and_the_private_claim_never_broadcasts(anvil_url):
    """A contract with the exact runtime and full balance but its ``settled`` word set is refused
    by ``verify_funded``, and a claim against it is refused before any transaction from the maker
    exists — on the private path too, where there is no preflight."""
    import dataclasses

    rpc, taker, maker = _legs(anvil_url)
    try:
        p, h = _secret()
        honest = await taker.fund(
            hashlock=h,
            claimant=_ADDR_MAKER,
            refundee=_ADDR_TAKER,
            timeout=await _now_plus(rpc, 3600),
            amount_wei=_AMOUNT_WEI,
        )
        settled_addr = await _deploy_presettled(rpc, maker._expected_runtime(honest), value=_AMOUNT_WEI)
        settled = dataclasses.replace(honest, contract_address=settled_addr)
        # The code IS exact — this is what makes it the storage check's job and nobody else's.
        assert bytes(await rpc.get_code(settled_addr)) == maker._expected_runtime(settled)

        with pytest.raises(ValidationError, match="ALREADY SETTLED"):
            await maker.verify_funded(settled, expected_amount_wei=_AMOUNT_WEI)
        # Control: the honest contract beside it still verifies.
        await maker.verify_funded(honest, expected_amount_wei=_AMOUNT_WEI)

        class _ForwardingSubmitter:
            """A private submitter that forwards to the node."""

            async def submit_raw(self, raw):  # pragma: no cover - reaching it is the failure
                return "0x" + bytes(await rpc.w3.eth.send_raw_transaction(raw)).hex()

        private_maker = EthHtlcContractLeg(
            rpc=rpc,
            signing_key=PrivateKeyMaterial(bytes.fromhex(_KEY_MAKER)),
            chain_id=_CHAIN_ID,
            artifact=_ARTIFACT,
            private_submitter=_ForwardingSubmitter(),
        )
        nonce_before = await rpc.w3.eth.get_transaction_count(_ADDR_MAKER)
        with pytest.raises(PreRevealAbort, match="already settled"):
            await private_maker.claim(settled, p)
        assert await rpc.w3.eth.get_transaction_count(_ADDR_MAKER) == nonce_before  # nothing was sent
    finally:
        await rpc.close()


async def test_a_leg_signing_for_another_chain_never_reaches_the_node(anvil_url):
    """A chain-1 leg over a 31337-pinned rpc is refused before signing; no bytes reach the node."""
    rpc = EthRpc(anvil_url, expected_chain_id=_CHAIN_ID)
    sent = []
    real_send = rpc.send_raw

    async def spy(raw):  # pragma: no cover - reaching it is the failure
        sent.append(raw)
        return await real_send(raw)

    rpc.send_raw = spy
    leg = EthHtlcContractLeg(
        rpc=rpc, signing_key=PrivateKeyMaterial(bytes.fromhex(_KEY_TAKER)), chain_id=1, artifact=_ARTIFACT
    )
    try:
        _, h = _secret()
        with pytest.raises(ValidationError, match="its rpc is pinned to chain 31337"):
            await leg.fund(
                hashlock=h,
                claimant=_ADDR_MAKER,
                refundee=_ADDR_TAKER,
                timeout=await _now_plus(rpc, 3600),
                amount_wei=_AMOUNT_WEI,
            )
        assert sent == []
    finally:
        await rpc.close()


# ---------------------------------------------------------------------------
# The response scrub must not change an honest response, whatever the URL's query looks like.
# Offline twin: test_eth_rpc_scrub_keeps_honest_responses.py.
# ---------------------------------------------------------------------------


def _reverting_runtime(revert_data: bytes) -> str:
    """Runtime that reverts with *revert_data*: CODECOPY it to memory 0, then REVERT."""
    n = len(revert_data)
    assert n < 256
    return "0x" + f"60{n:02x}600c600039" + f"60{n:02x}6000fd" + revert_data.hex()


@pytest.fixture(params=[False, True], ids=["int-ids", "string-ids"])
def anvil_proxy(anvil_url, request):
    """Anvil behind a pass-through HTTP proxy that ignores the path and query, so any URL shape can
    reach a real node. With ``string-ids`` the proxy sends each request id as a string."""
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    string_ids = request.param

    class _H(BaseHTTPRequestHandler):
        def do_POST(self):
            req = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
            if string_ids:
                for r in req if isinstance(req, list) else [req]:
                    r["id"] = str(r["id"])
            up = urllib.request.Request(
                anvil_url, data=json.dumps(req).encode(), headers={"content-type": "application/json"}
            )
            body = urllib.request.urlopen(up, timeout=10).read()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), _H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{srv.server_port}", anvil_url, string_ids
    finally:
        srv.shutdown()
        srv.server_close()


@pytest.mark.parametrize("suffix", ["/?v=2", "/?debug=0", "/?x=message", "/?x=code", "/?id=1"])
def test_honest_anvil_responses_are_identical_through_the_scrubbing_provider(anvil_proxy, suffix):
    import asyncio

    import web3
    from eth_abi import encode

    base, direct, string_ids = anvil_proxy
    reason_to = web3.Web3.to_checksum_address("0x" + "ae" * 20)
    custom_to = web3.Web3.to_checksum_address("0x" + "ce" * 20)

    async def setup():
        w3 = web3.AsyncWeb3(web3.AsyncWeb3.AsyncHTTPProvider(direct))
        try:
            reason = bytes.fromhex("08c379a0") + encode(["string"], ["nope"])
            await w3.provider.make_request("anvil_setCode", [reason_to, _reverting_runtime(reason)])
            await w3.provider.make_request("anvil_setCode", [custom_to, _reverting_runtime(bytes.fromhex("560ff900"))])
            h = await w3.eth.send_transaction({"from": _ADDR_TAKER, "to": _ADDR_MAKER, "value": 1})
            await w3.eth.wait_for_transaction_receipt(h)
            return h
        finally:
            await w3.provider.disconnect()

    tx = asyncio.run(setup())

    async def batch(w3):
        async with w3.batch_requests() as b:
            b.add(w3.eth.get_block(1))
            b.add(w3.eth.get_transaction_receipt(tx))
            return await b.async_execute()

    calls = {
        "chain_id": lambda w3: w3.eth.chain_id,
        "block": lambda w3: w3.eth.get_block(1),
        "receipt": lambda w3: w3.eth.get_transaction_receipt(tx),
        "revert-reason": lambda w3: w3.eth.call({"to": reason_to, "data": "0x"}),
        "custom-error": lambda w3: w3.eth.call({"to": custom_to, "data": "0x"}),
        "batch": batch,
    }

    def outcome(make_w3, call):
        async def go():
            w3 = make_w3()
            try:
                return await call(w3)
            finally:
                await w3.provider.disconnect()

        try:
            return ("ok", repr(asyncio.run(go())))
        except Exception as exc:  # the exception IS the outcome being compared
            return (type(exc).__name__, str(exc))

    url = base + suffix
    for name, call in calls.items():
        plain = outcome(lambda: web3.AsyncWeb3(web3.AsyncWeb3.AsyncHTTPProvider(url)), call)
        ours = outcome(lambda: EthRpc(url, expected_chain_id=_CHAIN_ID).w3, call)
        assert ours == plain, (name, suffix)
        if not string_ids:
            expected = {"revert-reason": "ContractLogicError", "custom-error": "ContractCustomError"}.get(name, "ok")
            assert plain[0] == expected, (name, plain)
