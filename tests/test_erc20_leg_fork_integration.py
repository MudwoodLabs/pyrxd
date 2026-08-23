"""End-to-end USDC counter-leg against a MAINNET FORK and the real USDC proxy.

**This is the test class that was missing, and its absence cost a critical bug.** Every earlier
test built locators by hand, so the chain-tag mechanism was fully covered while both production
producers returned the wrong type — 9,442 tests green, and a real token swap would have persisted
6-decimal base units under the native `"eth"` tag. Nothing but driving the real producer catches
that, so that is what this does.

A mock token is likewise worthless here: the 6-decimal arithmetic and the issuer blacklist are the
two things most likely to be wrong, and only the real contract has them.

Run it with a fork RPC::

    PYRXD_ETH_FORK_RPC=https://... .venv/bin/pytest tests/test_erc20_leg_fork_integration.py -m integration

It skips cleanly without one. CI has no key, so this is a local/manual gate rather than a
per-push one — stated plainly rather than pretended otherwise.
"""

from __future__ import annotations

import asyncio
import json
import os
import pathlib
import shutil
import socket
import subprocess
import time
import urllib.request

import pytest

pytest.importorskip("web3", reason="needs the eth extra: pip install 'pyrxd[eth]'")
if shutil.which("anvil") is None:  # pragma: no cover - environment gate
    pytest.skip("anvil binary not available", allow_module_level=True)

_FORK_RPC = os.environ.get("PYRXD_ETH_FORK_RPC", "")
if not _FORK_RPC:  # pragma: no cover - environment gate
    pytest.skip("set PYRXD_ETH_FORK_RPC to a mainnet RPC to run the fork suite", allow_module_level=True)

from pyrxd.eth_wallet.erc20 import assert_not_frozen_before_reveal, balance_of
from pyrxd.eth_wallet.erc20_leg import Erc20HtlcLeg
from pyrxd.eth_wallet.locator import Erc20HtlcLocator
from pyrxd.eth_wallet.rpc import EthRpc
from pyrxd.eth_wallet.tokens import token_for
from pyrxd.security.secrets import PrivateKeyMaterial

pytestmark = pytest.mark.integration

_MAINNET = 1
_USDC = token_for("USDC", _MAINNET)
#: A large holder to impersonate. Avoids deriving the balances storage slot, whose layout packs the
#: blacklist flag into the top bit on FiatToken v2.2.
_WHALE = "0x28C6c06298d514Db089934071355E5743bf21d60"
_KEY_TAKER = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"  # anvil dev key 0
_ADDR_TAKER = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
_ADDR_MAKER = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
_AMOUNT = 12_345_678  # 12.345678 USDC — non-round, so a scale bug cannot hide in a round number

_ARTIFACT = json.loads((pathlib.Path(__file__).parent / "fixtures" / "Erc20Htlc.json").read_text())


def _rpc_call(url: str, method: str, params: list) -> dict:
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(url, data=body, headers={"content-type": "application/json"})
    return json.loads(urllib.request.urlopen(req, timeout=30).read())


@pytest.fixture(scope="module")
def fork_url():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    url = f"http://127.0.0.1:{port}"
    proc = subprocess.Popen(
        ["anvil", "--fork-url", _FORK_RPC, "--port", str(port), "--silent"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        for _ in range(200):
            try:
                _rpc_call(url, "eth_chainId", [])
                break
            except Exception:
                time.sleep(0.25)
        else:  # pragma: no cover
            pytest.fail("anvil fork did not become ready")
        # Give the taker USDC by impersonating a holder — no storage-slot derivation needed.
        # NOTE: the delegations are deliberately LEFT IN PLACE. On a mainnet fork both anvil dev
        # addresses carry an EIP-7702 delegation designator (0xef0100 + delegate) — 23 bytes of
        # code — because they are well-known addresses someone has delegated. An earlier version of
        # this fixture cleared them with anvil_setCode to get past `verify_funded`'s EOA-only
        # check. That check is now correctly relaxed for the token leg (#478), whose ERC-20 sweep
        # calls the token and never the recipient, so the suite must pass WITH the delegations
        # present. If this ever needs clearing again, the relaxation has regressed.
        _rpc_call(url, "anvil_impersonateAccount", [_WHALE])
        _rpc_call(url, "anvil_setBalance", [_WHALE, hex(10**18)])
        transfer = "0xa9059cbb" + _ADDR_TAKER[2:].rjust(64, "0") + hex(_AMOUNT * 10)[2:].rjust(64, "0")
        _rpc_call(url, "eth_sendTransaction", [{"from": _WHALE, "to": _USDC.address, "data": transfer}])
        yield url
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:  # pragma: no cover
            proc.kill()


def _leg(fork_url: str) -> Erc20HtlcLeg:
    return Erc20HtlcLeg(
        token=_USDC,
        rpc=EthRpc(fork_url, expected_chain_id=_MAINNET),
        signing_key=PrivateKeyMaterial(bytes.fromhex(_KEY_TAKER)),
        chain_id=_MAINNET,
        artifact=_ARTIFACT,
    )


def test_the_real_producer_emits_a_TAGGED_locator(fork_url: str) -> None:
    """THE regression test for the critical bug. `fund()` returned the plain `EthHtlcLocator`, so
    the durable record said `chain: "eth"` while carrying 6-decimal base units. Hand-built
    locators could never have caught it; only calling the producer does."""
    import hashlib
    import os as _os

    leg = _leg(fork_url)
    preimage = _os.urandom(32)
    hashlock = hashlib.sha256(preimage).digest()

    locator = asyncio.run(
        leg.fund(
            hashlock=hashlock,
            claimant=_ADDR_MAKER,
            refundee=_ADDR_TAKER,
            timeout=int(time.time()) + 3600,
            amount_wei=_AMOUNT,
        )
    )

    assert isinstance(locator, Erc20HtlcLocator), f"got {type(locator).__name__} — record would say 'eth'"
    assert locator.CHAIN_TAG == "eth-erc20"
    assert locator.token_address == _USDC.address
    assert locator.amount_base_units == _AMOUNT

    # The tokens really landed, in the real contract, in base units.
    held = asyncio.run(balance_of(leg._rpc, _USDC, locator.contract_address))
    assert held == _AMOUNT, "exact delta against the real 6-decimal contract"

    # And the counterparty's binding gate passes against what was actually funded.
    asyncio.run(leg.verify_funded(locator, expected_amount_wei=_AMOUNT))


def test_verify_funded_refuses_an_underfunded_contract(fork_url: str) -> None:
    """The honest-path pair above proves it accepts; this proves it still refuses."""
    import hashlib
    import os as _os

    from pyrxd.security.errors import ValidationError

    leg = _leg(fork_url)
    locator = asyncio.run(
        leg.fund(
            hashlock=hashlib.sha256(_os.urandom(32)).digest(),
            claimant=_ADDR_MAKER,
            refundee=_ADDR_TAKER,
            timeout=int(time.time()) + 3600,
            amount_wei=_AMOUNT,
        )
    )
    with pytest.raises(ValidationError, match="under-funded|stored amount"):
        asyncio.run(leg.verify_funded(locator, expected_amount_wei=_AMOUNT * 2))


def test_the_freeze_gate_runs_against_the_real_blacklist(fork_url: str) -> None:
    """Not frozen -> the gate permits. The refusal side is covered on the Solidity side, where the
    blacklister can be impersonated; here the point is that the real `isBlacklisted` is reachable
    and answers, rather than the gate silently passing because a call failed."""
    leg = _leg(fork_url)
    asyncio.run(
        assert_not_frozen_before_reveal(
            leg._rpc, _USDC, htlc_address="0x" + "11" * 20, parties={"claimant": _ADDR_MAKER}
        )
    )


_KEY_MAKER = "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"  # anvil dev key 1


def _maker_leg(fork_url: str) -> Erc20HtlcLeg:
    """A leg signing as the CLAIMANT — claiming is the maker's action."""
    return Erc20HtlcLeg(
        token=_USDC,
        rpc=EthRpc(fork_url, expected_chain_id=_MAINNET),
        signing_key=PrivateKeyMaterial(bytes.fromhex(_KEY_MAKER)),
        chain_id=_MAINNET,
        artifact=_ARTIFACT,
    )


def test_a_real_claim_pays_the_claimant_and_fits_the_gas_budget(fork_url: str) -> None:
    """The suite stopped at `verify_funded` and never broadcast a claim, so the gas budget was
    never exercised on the token path — the parent builds at 120,000, a limit sized for a native
    ETH send. A token claim additionally does an SSTORE, a `balanceOf` and a full ERC-20 transfer
    into a cold recipient slot.

    That gap matters more than an ordinary one: if a claim ever exceeded the limit it would revert
    **after** the preimage was already in public calldata, so the counterparty takes the other leg
    while this one is dead. This drives the whole path against the real contract.
    """
    import hashlib
    import os as _os

    taker = _leg(fork_url)
    preimage = _os.urandom(32)
    hashlock = hashlib.sha256(preimage).digest()

    locator = asyncio.run(
        taker.fund(
            hashlock=hashlock,
            claimant=_ADDR_MAKER,
            refundee=_ADDR_TAKER,
            timeout=int(time.time()) + 3600,
            amount_wei=_AMOUNT,
        )
    )

    before = asyncio.run(balance_of(taker._rpc, _USDC, _ADDR_MAKER))
    tx_hash = asyncio.run(_maker_leg(fork_url).claim(locator, preimage))
    assert tx_hash

    receipt = _rpc_call(fork_url, "eth_getTransactionReceipt", [tx_hash])["result"]
    assert int(receipt["status"], 16) == 1, "the claim reverted — check the gas budget"
    used = int(receipt["gasUsed"], 16)
    assert used < 120_000, f"claim used {used} gas against the inherited 120,000 limit"

    after = asyncio.run(balance_of(taker._rpc, _USDC, _ADDR_MAKER))
    assert after - before == _AMOUNT, "the claimant must be paid the exact amount, in base units"
    assert asyncio.run(balance_of(taker._rpc, _USDC, locator.contract_address)) == 0, "swept"


def test_the_preimage_is_recoverable_from_the_real_claim(fork_url: str) -> None:
    """The counter-leg's whole purpose: `p` must be scrapeable from the claim. This is what the
    un-indexed `Claimed(bytes32)` event and the identical calldata shape exist for, and it is only
    truly proven against a real broadcast."""
    import hashlib
    import os as _os

    from pyrxd.cli.swap_recovery import recover_preimage_from_eth_claim

    taker = _leg(fork_url)
    preimage = _os.urandom(32)
    hashlock = hashlib.sha256(preimage).digest()
    locator = asyncio.run(
        taker.fund(
            hashlock=hashlock,
            claimant=_ADDR_MAKER,
            refundee=_ADDR_TAKER,
            timeout=int(time.time()) + 3600,
            amount_wei=_AMOUNT,
        )
    )
    tx_hash = asyncio.run(_maker_leg(fork_url).claim(locator, preimage))

    tx = _rpc_call(fork_url, "eth_getTransactionByHash", [tx_hash])["result"]
    receipt = _rpc_call(fork_url, "eth_getTransactionReceipt", [tx_hash])["result"]
    rec = recover_preimage_from_eth_claim(
        hashlock=hashlock,
        contract_address=locator.contract_address,
        claim_tx=tx,
        logs=receipt.get("logs", []),
    )
    assert bytes.fromhex(rec.preimage_hex) == preimage
