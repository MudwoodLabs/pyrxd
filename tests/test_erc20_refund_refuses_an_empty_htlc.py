"""``Erc20HtlcLeg.refund`` refuses, before signing, a refund the contract would revert as empty.

``Erc20Htlc.refund`` reverts ``NothingToRefund`` on a zero balance and stays unsettled, so tokens
that arrive later remain refundable. The leg names that case with its own exception instead of
sending it into the eth_call preflight. These tests pin the ORDER of its checks — settled, then the
timeout, then the balance, the contract's own order — and that every other case still reaches the
parent unchanged. The behaviour against the real contract is in the Anvil suite
(``tests/test_eth_leg_anvil_integration.py``); here the reads are faked so each branch can be
forced, and the parent's ``refund`` is replaced by a recorder so "nothing was sent" is observable.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from pyrxd.eth_wallet import erc20_leg as erc20_leg_mod
from pyrxd.eth_wallet.erc20_leg import Erc20HtlcLeg
from pyrxd.eth_wallet.htlc_leg import EthHtlcContractLeg
from pyrxd.eth_wallet.locator import Erc20HtlcLocator
from pyrxd.eth_wallet.tokens import Erc20Token
from pyrxd.security.errors import NetworkError, NothingToRefund, ValidationError
from pyrxd.security.secrets import PrivateKeyMaterial

_ARTIFACT = json.loads((Path(__file__).parent / "fixtures" / "Erc20Htlc.json").read_text())
_TOKEN = Erc20Token("TKN", "0x" + "70" * 20, 6, 31337, has_blacklist=False)
_TIMEOUT = 2_000_000_000


class _Rpc:
    def __init__(self, now: int) -> None:
        self.now = now

    async def assert_chain(self) -> None:
        return None

    async def latest_block_timestamp_min(self) -> int:
        return self.now


def _locator() -> Erc20HtlcLocator:
    return Erc20HtlcLocator(
        chain_id=31337,
        contract_address="0x" + "c0" * 20,
        deploy_tx_hash="0x" + "11" * 32,
        hashlock="0x" + "22" * 32,
        claimant="0x" + "44" * 20,
        refundee="0x" + "55" * 20,
        timeout=_TIMEOUT,
        amount_wei=1_000_000,
        token_address=_TOKEN.address,
    )


@pytest.fixture()
def rig(monkeypatch):
    """A leg whose clock, settled flag and token balance are set per test, and whose parent
    ``refund`` (the maturity check and the broadcast) only records that it was reached."""
    state = {"now": _TIMEOUT, "settled": False, "balance": 0, "parent_calls": 0, "reads": 0}

    leg = Erc20HtlcLeg(
        token=_TOKEN,
        rpc=_Rpc(0),
        signing_key=PrivateKeyMaterial(os.urandom(32)),
        chain_id=31337,
        artifact=_ARTIFACT,
    )

    async def _settled_word(self, locator, block_identifier):
        return (b"\x00" * 31) + (b"\x01" if state["settled"] else b"\x00")

    async def _balance_of(rpc, token, owner, block_identifier=None, *, combine=min):
        state["reads"] += 1
        answer = getattr(rpc, "balance", state["balance"])  # a fake endpoint carries its own answer
        if isinstance(answer, Exception):
            raise answer
        return answer

    async def _parent_refund(self, locator):
        state["parent_calls"] += 1
        return "0x" + "ee" * 32

    monkeypatch.setattr(Erc20HtlcLeg, "_settled_word", _settled_word)
    monkeypatch.setattr(erc20_leg_mod, "balance_of", _balance_of)
    monkeypatch.setattr(EthHtlcContractLeg, "refund", _parent_refund)

    state["leg"] = leg

    def run(*, now: int, settled: bool = False, balance: int = 0):
        state.update(now=now, settled=settled, balance=balance)
        leg._rpc.now = now
        return leg.refund(_locator())

    return run, state


async def test_a_matured_unsettled_EMPTY_htlc_raises_NothingToRefund_and_sends_nothing(rig) -> None:
    run, state = rig
    with pytest.raises(NothingToRefund, match="nothing to refund") as e:
        await run(now=_TIMEOUT, balance=0)
    assert state["parent_calls"] == 0, "nothing may be signed or sent"
    assert e.value.contract_address == _locator().contract_address
    assert "Do not record this swap as refunded" in str(e.value)
    # A ValidationError, so a driver stops rather than retrying a refusal that cannot change.
    assert isinstance(e.value, ValidationError) and not isinstance(e.value, NetworkError)


async def test_HONEST_path_a_matured_funded_htlc_reaches_the_parent_refund(rig) -> None:
    run, state = rig
    assert await run(now=_TIMEOUT, balance=1) == "0x" + "ee" * 32
    assert state["parent_calls"] == 1


class _Endpoint:
    def __init__(self, balance):
        self.balance = balance


class _MultiRpc(_Rpc):
    """A multi-source rpc as the leg sees it: ``sources`` lists every configured endpoint."""

    def __init__(self, now: int, balances) -> None:
        super().__init__(now)
        self.sources = [_Endpoint(b) for b in balances]


@pytest.mark.parametrize(
    ("balances", "outcome"),
    [
        ((0, 5, 0), "refund"),  # one endpoint sees tokens: go ahead (the preflight decides)
        ((0, 0, 0), "empty"),  # every endpoint answered 0: NothingToRefund
        ((0, NetworkError("timeout"), 0), "unknown"),  # one did not answer: unknown, retryable
        ((NetworkError("down"), 0, 0), "unknown"),
    ],
)
async def test_EVERY_endpoint_must_answer_before_the_balance_is_called_empty(rig, balances, outcome) -> None:
    """Review finding (LOW): with MAX over only the endpoints that answered, an unreachable endpoint
    holding the real balance and two lagging ones answering 0 made a funded contract read as empty.
    "Empty" now needs every configured endpoint to answer 0; a missing answer is unknown, never a vote."""
    _run, state = rig
    run_leg = state["leg"]
    run_leg._rpc = _MultiRpc(_TIMEOUT, balances)
    if outcome == "refund":
        assert await run_leg.refund(_locator()) == "0x" + "ee" * 32
        assert state["parent_calls"] == 1
    elif outcome == "empty":
        with pytest.raises(NothingToRefund):
            await run_leg.refund(_locator())
        assert state["parent_calls"] == 0
    else:
        with pytest.raises(NetworkError, match="did not answer") as e:
            await run_leg.refund(_locator())
        assert not isinstance(e.value, NothingToRefund) and state["parent_calls"] == 0
    assert state["reads"] == 3, "every configured endpoint must be read"


async def test_a_NOT_YET_MATURE_empty_htlc_gets_the_parents_answer_not_NothingToRefund(rig) -> None:
    """The contract checks the timeout before the balance, so the leg does too: before the timeout
    the answer is the parent's transient not-yet-mature refusal, whatever the balance."""
    run, state = rig
    await run(now=_TIMEOUT - 1, balance=0)
    assert state["parent_calls"] == 1
    assert state["reads"] == 0, "the balance must not be read before the timeout"


async def test_a_SETTLED_htlc_is_left_to_the_parent_not_reported_as_empty(rig) -> None:
    """After a refund that already succeeded the balance is 0 too. That is "already settled",
    which the contract reports first; calling it "nothing to refund" would misdescribe it."""
    run, state = rig
    await run(now=_TIMEOUT, settled=True, balance=0)
    assert state["parent_calls"] == 1
    assert state["reads"] == 0


async def test_the_real_parent_reports_not_yet_mature_as_a_NetworkError(monkeypatch) -> None:
    """The branch above relies on the parent's own maturity refusal; check it, unfaked."""
    leg = Erc20HtlcLeg(
        token=_TOKEN,
        rpc=_Rpc(_TIMEOUT - 10),
        signing_key=PrivateKeyMaterial(os.urandom(32)),
        chain_id=31337,
        artifact=_ARTIFACT,
    )
    with pytest.raises(NetworkError, match="not yet mature"):
        await leg.refund(_locator())
