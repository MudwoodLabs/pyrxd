"""The ERC-20 counter leg has a PRODUCTION caller, and it carries the right token.

Until this wiring existed, `Erc20HtlcLeg` was constructed by nothing outside the test suite: the
swap runner and the CLI could only fund a native-ETH counter leg, so a USDC swap was unreachable
except from pytest. Every ERC-20 test passed while the corridor could not actually be executed.

These drive the runner's REAL argument parser and its real leg factory rather than calling the
token registry directly, because the defect this guards against is not "the registry is wrong" —
it is "nothing asks the registry". A test that imports `token_for` itself would keep passing with
the runner wired back to native.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

from pyrxd.eth_wallet.erc20_leg import Erc20HtlcLeg
from pyrxd.eth_wallet.htlc_leg import EthHtlcContractLeg
from pyrxd.security.errors import ValidationError

_RUNNER = Path(__file__).resolve().parent.parent / "scripts" / "eth_swap_run.py"

_BASE_SEPOLIA = 84532
#: Circle's published Base Sepolia USDC. Pinned here as an INDEPENDENT copy: if this and the
#: registry ever disagree, one of them is wrong, and a silent agreement is what we are testing for.
_USDC_BASE_SEPOLIA = "0x036cbd53842c5426634e7929541ec2318f3dcf7e"


@pytest.fixture(scope="module")
def runner():
    spec = importlib.util.spec_from_file_location("eth_swap_run_under_test", _RUNNER)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _parse(runner, *argv):
    saved = sys.argv
    try:
        sys.argv = ["eth_swap_run.py", "--stage", "dry-run", *argv]
        return runner._args()
    finally:
        sys.argv = saved


def _contract_leg(leg):
    """Unwrap EthLeg (and the runner's capturing wrapper) down to the contract leg."""
    while hasattr(leg, "_leg"):
        leg = leg._leg
    return leg


def _make_leg(runner, args):
    # An unreachable URL on purpose: constructing the leg must not require a live node, and this
    # test is about which CLASS gets built, not about talking to a chain.
    _rpc, leg = runner._eth_leg(
        args,
        rpc_url="http://127.0.0.1:1",
        chain_id=int(args.eth_chain_id),
        key_hex="11" * 32,
        claim_to="0x" + "11" * 20,
        refund_to="0x" + "22" * 20,
        eth_timeout=2**31,
        network="base-sepolia",
    )
    return _contract_leg(leg)


def test_counter_asset_usdc_builds_an_erc20_leg_bound_to_the_pinned_token(runner):
    args = _parse(runner, "--counter-asset", "usdc", "--eth-chain-id", str(_BASE_SEPOLIA))
    leg = _make_leg(runner, args)

    assert isinstance(leg, Erc20HtlcLeg), (
        f"the runner built {type(leg).__name__}: selecting --counter-asset usdc still funds a "
        "NATIVE leg, so the swap would pay ETH while the record says USDC"
    )
    assert leg._token.address.lower() == _USDC_BASE_SEPOLIA, (
        f"bound to {leg._token.address}, not Circle's Base Sepolia USDC"
    )
    assert leg._token.decimals == 6
    assert leg._token.chain_id == _BASE_SEPOLIA


def test_native_still_builds_a_native_leg(runner):
    """The honest-path pair. A wiring change that routed EVERYTHING through the token leg would
    satisfy the test above and break every native swap that already works."""
    args = _parse(runner, "--counter-asset", "native", "--eth-chain-id", str(_BASE_SEPOLIA))
    leg = _make_leg(runner, args)
    assert isinstance(leg, EthHtlcContractLeg)
    assert not isinstance(leg, Erc20HtlcLeg), "a native run must not deploy a token HTLC"


def test_the_amount_is_read_from_the_right_flag_for_each_asset(runner):
    """--token-amount is BASE UNITS, --eth-amount-wei is wei. Reading the wrong one is the
    10^12 error the chain tag exists to prevent, arriving through the front door."""
    args = _parse(
        runner,
        "--counter-asset",
        "usdc",
        "--eth-chain-id",
        str(_BASE_SEPOLIA),
        "--token-amount",
        "1000000",
        "--eth-amount-wei",
        "100000000000000",
    )
    assert runner._counter_value(args) == 1_000_000, "a USDC run must not size itself in wei"

    native = _parse(runner, "--counter-asset", "native", "--eth-amount-wei", "100000000000000")
    assert runner._counter_value(native) == 100_000_000_000_000


def test_usdc_on_a_chain_with_no_pinned_token_is_refused(runner):
    """Fail closed rather than falling back to an address from somewhere else. USDC on the wrong
    chain id is a different contract, and on most chain ids it is nothing at all."""
    args = _parse(runner, "--counter-asset", "usdc", "--eth-chain-id", "999999")
    with pytest.raises(ValidationError, match="no pinned"):
        runner._counter_token(args)
