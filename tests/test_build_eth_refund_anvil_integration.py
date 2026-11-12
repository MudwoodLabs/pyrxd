"""``pyrxd swap build-eth-refund`` against a REAL EthHtlc / Erc20Htlc on a local anvil (#818).

The command signs ``refund()`` and prints it; it never sends. These tests drive the real click
command over a real ``EthRpc`` to anvil and prove both halves on the chain itself:

* nothing reached the node: the sender's nonce did not move and the node does not know the hash;
* what it printed is the refund: broadcasting the printed bytes by hand settles the contract and
  pays the refundee.

Each refusal is paired with that honest path: before the timeout, after the contract settled, a
record whose contract is not the one on chain, a record already holding a pending refund, and an
ERC-20 contract refunded with a key the contract would refuse (``NotRefunder``).

Anvil's dev keys are PUBLIC and control only the local devnet. Marked ``integration``; runs in the
Anvil step of ``.github/workflows/integration.yml``.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import pathlib
import shutil

import pytest

pytest.importorskip("web3")
pytest.importorskip("eth_keys")
if shutil.which("anvil") is None:  # pragma: no cover - environment gate
    pytest.skip("anvil binary not available", allow_module_level=True)

from click.testing import CliRunner

import pyrxd.cli.main  # noqa: F401 - registers the swap subcommands on the group
from pyrxd.cli import swap_cmds
from pyrxd.cli.config import Config
from pyrxd.cli.context import CliContext
from pyrxd.eth_wallet.htlc_leg import EthHtlcContractLeg
from pyrxd.eth_wallet.rpc import EthRpc
from pyrxd.gravity.htlc_covenant import build_htlc_covenant_rxd
from pyrxd.gravity.swap_state import RecordRole
from pyrxd.keys import PrivateKey
from pyrxd.security.secrets import PrivateKeyMaterial
from tests._anvil import start_anvil
from tests._eth_refund_records import eth_record, write_record

pytestmark = pytest.mark.integration

_CHAIN_ID = 31337
_KEY_TAKER = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"  # acct 0: deploys, refunds
_ADDR_TAKER = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
_ADDR_MAKER = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"  # acct 1
_KEY_THIRD = "5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a"  # acct 2: neither party
_AMOUNT_WEI = 10**15
_FIXTURES = pathlib.Path(__file__).parent / "fixtures"
_ETH_ARTIFACT = _FIXTURES / "EthHtlc.json"
_ERC20_ARTIFACT = _FIXTURES / "Erc20Htlc.json"


@pytest.fixture()
def anvil_url():
    with start_anvil(["--chain-id", str(_CHAIN_ID)], ready_timeout_s=10) as url:
        yield url


def _run(coro):
    return asyncio.run(coro)


def _rpc(url: str) -> EthRpc:
    return EthRpc(url, expected_chain_id=_CHAIN_ID)


async def _call(url: str, method: str, params: list) -> object:
    rpc = _rpc(url)
    try:
        resp = await rpc.w3.provider.make_request(method, params)
        assert "error" not in resp, resp
        return resp["result"]
    finally:
        await rpc.close()


async def _head_ts(url: str) -> int:
    rpc = _rpc(url)
    try:
        return int((await rpc.w3.eth.get_block("latest"))["timestamp"])
    finally:
        await rpc.close()


async def _advance(url: str, seconds: int) -> None:
    await _call(url, "evm_increaseTime", [seconds])
    await _call(url, "evm_mine", [])


async def _fund_native(url: str, hashlock: bytes, timeout: int):
    rpc = _rpc(url)
    try:
        leg = EthHtlcContractLeg(
            rpc=rpc,
            signing_key=PrivateKeyMaterial(bytes.fromhex(_KEY_TAKER)),
            chain_id=_CHAIN_ID,
            artifact=json.loads(_ETH_ARTIFACT.read_text()),
        )
        return await leg.fund(
            hashlock=hashlock, claimant=_ADDR_MAKER, refundee=_ADDR_TAKER, timeout=timeout, amount_wei=_AMOUNT_WEI
        )
    finally:
        await rpc.close()


def _swap_file(tmp_path: pathlib.Path, hashlock: bytes, *, key_hex: str | None = _KEY_TAKER) -> pathlib.Path:
    """The recovery file ``scripts/eth_swap_run.py`` writes, with the fields this command reads."""
    taker, maker = PrivateKey(), PrivateKey()
    cov = build_htlc_covenant_rxd(
        amount=100_000,
        taker_pkh=bytes(taker.public_key().hash160()),
        maker_pkh=bytes(maker.public_key().hash160()),
        hashlock=hashlock,
        refund_csv=20,
    )
    doc = {
        "eth_chain": "anvil",
        "eth_chain_id": _CHAIN_ID,
        "rxd_network": "bc",
        "hashlock_H": hashlock.hex(),
        "rxd_covenant_spk": cov.funded_spk.hex(),
        "t_rxd_blocks": 20,
        "taker_rxd_wif": taker.wif(),
        "eth_refund_to": _ADDR_TAKER,
    }
    if key_hex is not None:
        doc["eth_key_hex"] = key_hex
    path = tmp_path / "eth_swap_run_keys.json"
    path.write_text(json.dumps(doc))
    path.chmod(0o600)
    return path


def _invoke(swap_file: pathlib.Path, url: str, artifact: pathlib.Path = _ETH_ARTIFACT, *extra: str):
    path = pathlib.Path("/tmp/_pyrxd_eth_refund_test")
    ctx = CliContext(
        config=Config(network="mainnet", electrumx="wss://test/", fee_rate=10_000, wallet_path=path),
        network="mainnet",
        electrumx_url="wss://test/",
        wallet_path=path,
        output_mode="json",
        yes=True,
    )
    args = ["build-eth-refund", "--swap-file", str(swap_file), "--eth-rpc-url", url, "--artifact", str(artifact)]
    return CliRunner().invoke(swap_cmds.swap_group, [*args, *extra], obj=ctx)


def _secret() -> tuple[bytes, bytes]:
    p = os.urandom(32)
    return p, hashlib.sha256(p).digest()


async def _nonce(url: str, addr: str, tag: str = "pending") -> int:
    return int(await _call(url, "eth_getTransactionCount", [addr, tag]), 16)


async def _balance(url: str, addr: str) -> int:
    return int(await _call(url, "eth_getBalance", [addr, "latest"]), 16)


async def _send_and_wait(url: str, raw_hex: str, *, timeout_s: float = 20.0) -> dict:
    """Broadcast *raw_hex* by hand (as the operator would) and wait, bounded, for its receipt."""
    rpc = _rpc(url)
    try:
        h = await rpc.w3.eth.send_raw_transaction(raw_hex)
        return dict(await rpc.w3.eth.wait_for_transaction_receipt(h, timeout=timeout_s))
    finally:
        await rpc.close()


# ── the honest path, and that nothing was sent ──────────────────────────────────────────────────


def test_after_the_timeout_it_prints_a_refund_it_did_not_send_and_that_refund_settles_the_contract(
    anvil_url, tmp_path
) -> None:
    _, h = _secret()
    timeout = _run(_head_ts(anvil_url)) + 600
    locator = _run(_fund_native(anvil_url, h, timeout))
    swap_file = _swap_file(tmp_path, h)
    write_record(swap_file, eth_record(locator))
    _run(_advance(anvil_url, 601))

    nonce_before = _run(_nonce(anvil_url, _ADDR_TAKER))
    res = _invoke(swap_file, anvil_url)
    assert res.exit_code == 0, res.output
    out = json.loads(res.output)
    assert out["broadcast"] is False
    assert out["contract_address"].lower() == locator.contract_address.lower()
    assert out["refundee"].lower() == _ADDR_TAKER.lower()
    assert out["sender"].lower() == _ADDR_TAKER.lower()
    assert out["contract_balance"] == _AMOUNT_WEI
    assert out["nonce"] == nonce_before

    # Nothing reached the node: no nonce consumed, no transaction known by that hash.
    assert _run(_nonce(anvil_url, _ADDR_TAKER)) == nonce_before
    assert _run(_call(anvil_url, "eth_getTransactionByHash", [out["tx_hash"]])) is None

    # What it printed IS the refund: sent by hand, it settles the contract and pays the refundee.
    receipt = _run(_send_and_wait(anvil_url, out["raw_hex"]))
    assert "0x" + bytes(receipt["transactionHash"]).hex().removeprefix("0x") == out["tx_hash"].lower()
    assert receipt["status"] == 1
    assert _run(_balance(anvil_url, locator.contract_address)) == 0

    # And afterwards: settled, so it refuses and points at status, signing nothing.
    again = _invoke(swap_file, anvil_url)
    assert again.exit_code == 1, again.output
    assert "already SETTLED" in again.output
    assert "raw_hex" not in again.output


def test_before_the_timeout_it_refuses_and_signs_nothing(anvil_url, tmp_path) -> None:
    _, h = _secret()
    timeout = _run(_head_ts(anvil_url)) + 3600
    locator = _run(_fund_native(anvil_url, h, timeout))
    swap_file = _swap_file(tmp_path, h)
    write_record(swap_file, eth_record(locator))

    res = _invoke(swap_file, anvil_url)
    assert res.exit_code == 1, res.output
    assert f"refund() opens at unix {timeout}" in res.output
    assert "raw_hex" not in res.output

    # Honest pair: the same record, once the timeout has passed, signs.
    _run(_advance(anvil_url, 3601))
    ok = _invoke(swap_file, anvil_url)
    assert ok.exit_code == 0, ok.output


def test_a_record_naming_terms_the_contract_does_not_hold_is_refused(anvil_url, tmp_path) -> None:
    """The record's locator says claimant = a third account, which the recovery file does not record,
    and the contract on chain says otherwise: the exact runtime differs, so nothing is signed for a
    contract the record does not describe. (A refundee the recovery file contradicts is refused
    before any read; tests/cli/test_swap_eth_refund.py.)"""
    import dataclasses

    _, h = _secret()
    timeout = _run(_head_ts(anvil_url)) + 600
    locator = _run(_fund_native(anvil_url, h, timeout))
    forged = dataclasses.replace(locator, claimant="0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC")
    swap_file = _swap_file(tmp_path, h)
    write_record(swap_file, eth_record(forged))
    _run(_advance(anvil_url, 601))

    res = _invoke(swap_file, anvil_url)
    assert res.exit_code == 1, res.output
    assert "does not EXACTLY equal the runtime" in res.output
    assert "raw_hex" not in res.output

    # Honest pair: the record as funded signs.
    write_record(swap_file, eth_record(locator))
    assert _invoke(swap_file, anvil_url).exit_code == 0


def test_a_refund_already_pending_on_the_record_is_not_signed_again(anvil_url, tmp_path) -> None:
    """The coordinator recorded a refund that is still in the node's mempool (automine off): a new
    one at the next nonce could only revert, so nothing is signed. Once the pending one has been
    DROPPED (its nonce is free again), the command signs."""
    _, h = _secret()
    timeout = _run(_head_ts(anvil_url)) + 600
    locator = _run(_fund_native(anvil_url, h, timeout))
    swap_file = _swap_file(tmp_path, h)
    _run(_advance(anvil_url, 601))

    write_record(swap_file, eth_record(locator))
    first = json.loads(_invoke(swap_file, anvil_url).output)
    _run(_call(anvil_url, "evm_setAutomine", [False]))
    _run(_call(anvil_url, "eth_sendRawTransaction", [first["raw_hex"]]))
    write_record(
        swap_file,
        eth_record(locator, counter_refund_tx_hash=first["tx_hash"].lower(), counter_refund_nonce=first["nonce"]),
    )

    res = _invoke(swap_file, anvil_url)
    assert res.exit_code == 1, res.output
    assert "still pending" in res.output
    assert "raw_hex" not in res.output

    # Honest pair: drop it from the node; the record's refund now reads "dropped" and a new one is signed.
    _run(_call(anvil_url, "anvil_dropTransaction", [first["tx_hash"]]))
    ok = _invoke(swap_file, anvil_url)
    assert ok.exit_code == 0, ok.output
    assert json.loads(ok.output)["earlier_refund"]["progress"] == "dropped"


def test_a_maker_record_is_refused(anvil_url, tmp_path) -> None:
    _, h = _secret()
    timeout = _run(_head_ts(anvil_url)) + 600
    locator = _run(_fund_native(anvil_url, h, timeout))
    swap_file = _swap_file(tmp_path, h)
    _run(_advance(anvil_url, 601))
    write_record(swap_file, eth_record(locator, role=RecordRole.MAKER))
    res = _invoke(swap_file, anvil_url)
    assert res.exit_code == 1, res.output
    assert "written by the MAKER" in res.output


# ── ERC-20 ──────────────────────────────────────────────────────────────────────────────────────


def test_an_erc20_refund_signs_for_the_deployer_and_refuses_a_key_the_contract_would_refuse(
    anvil_url, tmp_path
) -> None:
    from tests.test_eth_leg_anvil_integration import _erc20_leg, _moving_token, _token_balance

    _, h = _secret()

    async def fund():
        rpc = _rpc(anvil_url)
        try:
            token = await _moving_token(rpc, mint_to=_ADDR_TAKER, amount=5_000_000)
            leg = _erc20_leg(rpc, token, _KEY_TAKER)
            ts = int((await rpc.w3.eth.get_block("latest"))["timestamp"]) + 600
            loc = await leg.fund(
                hashlock=h, claimant=_ADDR_MAKER, refundee=_ADDR_TAKER, timeout=ts, amount_wei=1_000_000
            )
            return token, loc
        finally:
            await rpc.close()

    token, locator = _run(fund())
    _run(_advance(anvil_url, 601))

    # A third account: Erc20Htlc.refund reverts NotRefunder for it, so the leg refuses before signing.
    third = _swap_file(tmp_path, h, key_hex=_KEY_THIRD)
    write_record(third, eth_record(locator))
    res = _invoke(third, anvil_url, _ERC20_ARTIFACT)
    assert res.exit_code == 1, res.output
    assert "cannot refund the HTLC" in res.output
    assert "raw_hex" not in res.output

    # The native artifact for a token contract is refused by name.
    wrong = _invoke(third, anvil_url, _ETH_ARTIFACT)
    assert wrong.exit_code == 1 and "ERC-20 HTLC" in wrong.output

    # Honest: the deploying key signs, and the printed refund returns the tokens when sent.
    own = tmp_path / "own"
    own.mkdir()
    swap_file = _swap_file(own, h)
    write_record(swap_file, eth_record(locator))
    ok = _invoke(swap_file, anvil_url, _ERC20_ARTIFACT)
    assert ok.exit_code == 0, ok.output
    out = json.loads(ok.output)
    assert out["contract_balance"] == 1_000_000
    assert _run(_send_and_wait(anvil_url, out["raw_hex"]))["status"] == 1

    async def balances():
        rpc = _rpc(anvil_url)
        try:
            return await _token_balance(rpc, token, locator.contract_address), await _token_balance(
                rpc, token, _ADDR_TAKER
            )
        finally:
            await rpc.close()

    assert _run(balances()) == (0, 5_000_000)
