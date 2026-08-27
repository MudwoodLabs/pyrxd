"""A deployed HTLC must be referenced by the durable record before value moves into it.

`taker_funds_btc` persists an intent record before broadcasting, and its comment says that record
"knows WHERE the HTLC address is". That is true for BTC — a P2TR funding address is derived from
terms before anything is broadcast — and it was false for ETH, where a CREATE address depends on
the deployer's nonce and does not exist until the deploy receipt returns.

The ERC-20 path makes it worst, because funding is TWO transactions: deploy, then a plain
`transfer`. A crash after the push but before the locator is returned left real USDC in a contract
whose only reference was an exception string. `refund()` recovers it after the timeout — but only
for an operator who still knows the address, and reconstructing a CREATE address by hand is not a
recovery procedure.

The leg now awaits `on_deploy(address)` as soon as the deploy confirms and, for the token leg,
strictly BEFORE the tokens are pushed.
"""

from __future__ import annotations

import asyncio
import json
import os
import pathlib
import time

import pytest

pytest.importorskip("web3", reason="needs the eth extra: pip install 'pyrxd[eth]'")

from pyrxd.eth_wallet.erc20_leg import Erc20HtlcLeg, _create_address
from pyrxd.eth_wallet.locator import PendingDeploy
from pyrxd.eth_wallet.tokens import token_for
from pyrxd.security.errors import NetworkError, ValidationError
from pyrxd.security.secrets import PrivateKeyMaterial

_ART = json.loads((pathlib.Path(__file__).parent / "fixtures" / "Erc20Htlc.json").read_text())
#: The RESUME fixture's address. A resume takes the address from the durable RECORD — the deploy
#: already happened and no receipt is being trusted — so an arbitrary value is honest there.
_DEPLOYED = "0x" + "77" * 20
#: A FRESH deploy is different. A deploy receipt cannot name an arbitrary address: `contractAddress`
#: IS `keccak(rlp([sender, nonce]))[12:]`, and the leg now derives it rather than trusting the
#: endpoint that reports it. A fake returning `0x7777...` modelled a chain that cannot exist, so
#: every test here passed against a scenario production never produces. Each leg now computes
#: the address its own key and nonce really imply, and `lying_receipt=` opts into the forgery.
_USDC = token_for("USDC", 1)
#: Evaluated ONCE so the fake's on-chain immutable and the value `_fund` sends agree; computing
#: `time.time()` at each call made them differ and the real immutable bind refused, correctly.
_FUND_TIMEOUT = int(time.time()) + 86_400


def _leg(
    *,
    push_fails: bool = False,
    order: list,
    initial_held: int = 0,
    inflight: int = 0,
    frozen: tuple[str, ...] = (),
    lying_receipt: str | None = None,
    key: PrivateKeyMaterial | None = None,
):
    """A token leg whose deploy always succeeds; the push may fail.

    `initial_held` is what the HTLC already holds — 0 for a fresh deploy, non-zero to model a
    resume after a push whose receipt was lost. The balance TRACKS the push, because a fake that
    reports a constant balance cannot tell "already funded" from "not funded yet", which is the
    exact distinction the resume path turns on.
    """
    state = {"held": int(initial_held), "sent": []}
    _key = key or PrivateKeyMaterial(os.urandom(32))
    from pyrxd.eth_wallet.keys import derive_address

    _sender = derive_address(_key)

    class _Call:
        def __init__(self, v):
            self._v = v

        async def call(self, *a, **k):
            return self._v

    class _Fns:
        def transfer(self, _to, amount):
            class _B:
                async def build_transaction(self_b, tx):
                    state["pending_transfer"] = int(amount)
                    state["push_nonce_used"] = tx.get("nonce")
                    return dict(tx)

            return _B()

        def symbol(self, *a, **k):
            return _Call("USDC")

        def decimals(self, *a, **k):
            return _Call(6)

        def balanceOf(self, *a, **k):
            return _Call(state["held"])

        def isBlacklisted(self, addr, *a, **k):
            # The pre-fund gate reads this. Default is "not frozen", so every pre-existing test
            # exercises the HONEST path; a test that wants a refusal passes `frozen=(...)`.
            return _Call(str(addr).lower() in {a.lower() for a in frozen})

    class _Ctor:
        async def build_transaction(self, tx):
            state["deploy_nonce"] = tx.get("nonce")
            return dict(tx)

    class _Contract:
        functions = _Fns()

        def constructor(self, *a, **k):
            return _Ctor()

    class _Eth:
        def contract(self, *a, **k):
            return _Contract()

    class _W3:
        eth = _Eth()

    class _Rpc:
        w3 = _W3()

        write_w3 = w3  # the fake builds transactions against the same object it reads from

        async def latest_block_timestamp(self):
            return int((await self.w3.eth.get_block("latest"))["timestamp"])

        async def latest_block_timestamp_min(self):
            # The multi-source class aggregates this the other way for the staleness and
            # refund-maturity guards; one endpoint has one answer, so the fake mirrors it.
            return await self.latest_block_timestamp()

        async def latest_block_timestamp_quorum(self):
            # The staleness abort reads the QUORUM-th head: MIN lets one lagging endpoint
            # declare a healthy chain halted, MAX lets one liar hide a real halt. A single
            # source has one answer, so all three coincide here.
            return await self.latest_block_timestamp()

        async def assert_chain(self):
            return None

        async def fee_fields(self):
            return {"maxPriorityFeePerGas": 1, "maxFeePerGas": 3}

        async def get_transaction_count(self, _a, block="pending"):
            return inflight if block == "pending" else 0

        async def wait_receipt(self, tx_hash, **_k):
            if tx_hash == "0xdeploy":
                real = _create_address(_sender, int(state["deploy_nonce"]))
                state["deployed"] = real
                return {"status": 1, "contractAddress": lying_receipt or real, "logs": []}
            if push_fails:
                return {"status": 0, "logs": []}
            state["held"] += state.pop("pending_transfer", 0)
            return {"status": 1, "logs": []}

    leg = Erc20HtlcLeg(token=_USDC, rpc=_Rpc(), signing_key=_key, chain_id=1, artifact=_ART)

    sends = {"n": 0}

    async def _sign_and_send(*a, **k):
        sends["n"] += 1
        if sends["n"] == 1 and initial_held == 0 and "resumed" not in state:
            return "0xdeploy"
        order.append("tokens-pushed")
        state["sent"].append(state.get("pending_transfer"))
        return "0xpush"

    leg._sign_and_send = _sign_and_send
    leg._test_state = state
    return leg


def _fund(leg, on_deploy, resume_from=None):
    return asyncio.run(
        leg.fund(
            resume_from=resume_from,
            hashlock=b"\x33" * 32,
            claimant="0x" + "44" * 20,
            refundee="0x" + "55" * 20,
            timeout=_FUND_TIMEOUT,
            amount_wei=12_345_678,
            on_deploy=on_deploy,
        )
    )


class TestTheAddressIsDurableBeforeTheTokensMove:
    def test_on_deploy_fires_BEFORE_the_token_push(self) -> None:
        """The ordering IS the fix. Persisting after the push leaves a window in which real value
        sits in a contract nothing references — exactly the case being closed."""
        order: list = []

        async def _remember(addr: str, tx: str) -> None:
            order.append(f"persisted:{addr}")
            assert tx == "0xdeploy", "the deploy tx hash must ride along; a resume needs it"

        leg = _leg(push_fails=False, order=order)
        _fund(leg, _remember)
        assert order == [f"persisted:{leg._test_state['deployed']}", "tokens-pushed"], order

    def test_a_FAILED_push_still_leaves_the_address_recorded(self) -> None:
        """The crash-consistency case. The push reverts, `fund` raises and returns no locator —
        but the operator must still hold the address, because the contract exists and a later
        retry or refund needs somewhere to point."""
        seen: list = []

        async def _remember(addr: str, tx: str) -> None:
            seen.append(addr)

        leg = _leg(push_fails=True, order=[])
        with pytest.raises(NetworkError):
            _fund(leg, _remember)
        assert seen == [leg._test_state["deployed"]], "the deployed address was lost when the push failed"

    def test_a_caller_that_cannot_PERSIST_stops_before_the_tokens_move(self) -> None:
        """If the record cannot be written, pushing would create precisely the untracked value
        this exists to prevent. Awaiting the hook — rather than firing and forgetting — is what
        makes the failure stop the push."""
        order: list = []

        async def _broken(_addr: str, _tx: str) -> None:
            raise NetworkError("record store unavailable")

        with pytest.raises(NetworkError, match="record store unavailable"):
            _fund(_leg(push_fails=False, order=order), _broken)
        assert "tokens-pushed" not in order, "tokens were pushed despite the address not being durable"

    def test_fund_without_a_hook_still_works(self) -> None:
        """A guard that refuses valid work is a bug: `on_deploy` is optional, and a caller that
        passes nothing keeps the previous behaviour."""
        order: list = []
        leg = _leg(push_fails=False, order=order)
        loc = _fund(leg, None)
        assert loc.contract_address.lower() == leg._test_state["deployed"].lower()
        assert order == ["tokens-pushed"]


_AMOUNT = 12_345_678
_PENDING = PendingDeploy(address=_DEPLOYED, deploy_tx_hash="0xdeploy")


def _stub_verify(leg, order: list):
    """Record that the immutable check ran, and WHEN. `verify_funded` needs a full node fake
    (get_code plus every immutable getter); the point being pinned here is the ORDER and the
    waiver, both of which a recording stub captures exactly. That it genuinely refuses is pinned
    separately by `test_a_resume_REFUSES_a_contract_that_is_not_this_swap`."""

    async def _v(locator, *, expected_amount_wei, require_balance=True, **_k):
        assert require_balance is False, "a resume must waive the balance floor, and only that"
        order.append(f"verified:{locator.contract_address.lower()}:{expected_amount_wei}")

    leg.verify_funded = _v
    return leg


class TestResumeCompletesTheFundInsteadOfStartingASecondOne:
    """The retry half of the crash story. `reserve(H)` commits before the broadcast, so after a
    mid-fund crash a plain retry is refused forever — and the only knob an operator had was calling
    `fund` again, which DEPLOYS A SECOND CONTRACT and pushes a second full amount.
    """

    def test_a_resume_does_not_deploy_a_second_contract(self) -> None:
        order: list = []
        leg = _leg(order=order)
        leg._test_state["resumed"] = True
        _stub_verify(leg, order)
        loc = _fund(leg, None, resume_from=_PENDING)
        assert loc.contract_address.lower() == _DEPLOYED.lower(), "resume funded a different contract"
        # Verified first, then exactly one push, and NO deploy.
        assert order == [f"verified:{_DEPLOYED.lower()}:{_AMOUNT}", "tokens-pushed"], order

    def test_a_resume_after_a_LOST_RECEIPT_sends_nothing(self) -> None:
        """The push landed; the process died before seeing the receipt. Re-sending the full amount
        on that reading is the double-fund this exists to prevent — the tokens are already there,
        so the correct action is to send NOTHING and bind the locator."""
        order: list = []
        leg = _leg(order=order, initial_held=_AMOUNT)
        _stub_verify(leg, order)
        loc = _fund(leg, None, resume_from=_PENDING)
        assert "tokens-pushed" not in order, f"a fully funded HTLC was topped up again: {order}"
        assert loc.amount_wei == _AMOUNT

    def test_a_resume_after_a_PARTIAL_fund_sends_only_the_shortfall(self) -> None:
        """Nothing in this protocol guarantees the balance is all-or-nothing — anyone can send
        tokens to the address. Send the difference, not the whole amount again."""
        order: list = []
        leg = _leg(order=order, initial_held=_AMOUNT - 1_000_000)
        leg._test_state["resumed"] = True
        _stub_verify(leg, order)
        _fund(leg, None, resume_from=_PENDING)
        assert leg._test_state["sent"] == [1_000_000], (
            f"resume sent {leg._test_state['sent']} instead of just the 1,000,000 shortfall"
        )

    def test_a_resume_REFUSES_a_contract_that_is_not_this_swap(self) -> None:
        """A resume is driven by a durable record. Sending tokens to an address out of a record
        without re-deriving what that address actually IS would let a corrupted or tampered record
        redirect the funds anywhere. The immutables are verified before anything is sent."""
        order: list = []
        leg = _leg(order=order)
        leg._test_state["resumed"] = True

        async def _wrong(*_a, **_k):
            raise ValidationError("on-chain hashlock != negotiated hashlock")

        leg.verify_funded = _wrong
        with pytest.raises(ValidationError):
            _fund(leg, None, resume_from=_PENDING)
        assert order == [], "tokens were sent to a contract that was never verified as ours"

    def test_the_immutables_are_verified_with_the_BALANCE_REQUIREMENT_WAIVED(self) -> None:
        """`expected_amount_wei=0` is the whole trick: a half-finished fund is legitimately allowed
        to be short, so the balance is the ONE check a resume must waive — and every other check
        (hashlock, claimant, refundee, timeout, token, runtime code) must still run. Waiving more
        would let a resume send tokens to a contract that is not this swap."""
        order: list = []
        leg = _leg(order=order)
        leg._test_state["resumed"] = True
        _stub_verify(leg, order)
        _fund(leg, None, resume_from=_PENDING)
        verified = [e for e in order if e.startswith("verified:")]
        # The REAL negotiated amount, not 0. Round 6: passing 0 to mean "waive the balance" also
        # inverted the contract's `amount` immutable bind, so every resume raised before a token
        # moved. The amount is now asserted and only the balance floor is waived.
        assert verified == [f"verified:{_DEPLOYED.lower()}:{_AMOUNT}"], verified
        assert order.index(verified[0]) < order.index("tokens-pushed"), "verified AFTER sending tokens"


# ---------------------------------------------------------------------------
# The gap that let two CRITICALs through round 6: every resume test above stubs
# `verify_funded`, so none of them ever ran the check that makes a resume safe. These drive the
# REAL method against a fake node serving real immutables.
# ---------------------------------------------------------------------------

_CLAIMANT = "0x" + "44" * 20
_REFUNDEE = "0x" + "55" * 20
_TIMEOUT = _FUND_TIMEOUT


def _real_verify_leg(
    *,
    on_chain: dict,
    held: int,
    order: list,
    inflight: int = 0,
    settled: int = 0,
    frozen: tuple[str, ...] = (),
):
    """A leg whose `verify_funded` is the PRODUCTION one, backed by a node fake serving the
    contract's immutables. `on_chain` overrides let a test deploy a contract that is NOT this
    swap's and watch the real check refuse it."""
    imm = {
        "hashlock": b"\x33" * 32,
        "claimant": _CLAIMANT,
        "refundee": _REFUNDEE,
        "timeout": _TIMEOUT,
        "amount": _AMOUNT,
        "token": _USDC.address,
        **on_chain,
    }
    state = {"held": int(held)}

    class _Call:
        def __init__(self, v):
            self._v = v

        async def call(self, *a, **k):
            return self._v

    class _Fns:
        def transfer(self, _to, amount):
            class _B:
                async def build_transaction(self_b, tx):
                    state["push_nonce_used"] = tx.get("nonce")
                    state["pending"] = int(amount)
                    return dict(tx)

            return _B()

        def hashlock(self, *a, **k):
            return _Call(imm["hashlock"])

        def claimant(self, *a, **k):
            return _Call(imm["claimant"])

        def refundee(self, *a, **k):
            return _Call(imm["refundee"])

        def timeout(self, *a, **k):
            return _Call(imm["timeout"])

        def amount(self, *a, **k):
            return _Call(imm["amount"])

        def token(self, *a, **k):
            return _Call(imm["token"])

        def balanceOf(self, *a, **k):
            return _Call(state["held"])

        def symbol(self, *a, **k):
            return _Call("USDC")

        def decimals(self, *a, **k):
            return _Call(6)

        def isBlacklisted(self, addr, *a, **k):
            # The pre-fund gate reads this. Default is "not frozen", so every pre-existing test
            # exercises the HONEST path; a test that wants a refusal passes `frozen=(...)`.
            return _Call(str(addr).lower() in {a.lower() for a in frozen})

    class _Contract:
        functions = _Fns()

    class _Eth:
        def contract(self, *a, **k):
            return _Contract()

    class _W3:
        eth = _Eth()

    class _Rpc:
        w3 = _W3()

        write_w3 = w3  # the fake builds transactions against the same object it reads from

        async def latest_block_timestamp(self):
            return int((await self.w3.eth.get_block("latest"))["timestamp"])

        async def latest_block_timestamp_min(self):
            # The multi-source class aggregates this the other way for the staleness and
            # refund-maturity guards; one endpoint has one answer, so the fake mirrors it.
            return await self.latest_block_timestamp()

        async def latest_block_timestamp_quorum(self):
            # The staleness abort reads the QUORUM-th head: MIN lets one lagging endpoint
            # declare a healthy chain halted, MAX lets one liar hide a real halt. A single
            # source has one answer, so all three coincide here.
            return await self.latest_block_timestamp()

        async def assert_chain(self):
            return None

        async def get_code(self, address, *a, **k):
            # Address-AWARE. The HTLC carries the committed runtime bytecode (the parent compares
            # it and refuses a mismatch); the claimant and refundee are EOAs and must return empty,
            # or the recipient-policy check refuses them as contracts.
            if str(address).lower() == _DEPLOYED.lower():
                return bytes.fromhex(_ART["runtime_bytecode"].removeprefix("0x"))
            return b""

        async def get_balance(self, *a, **k):
            # NATIVE ether balance. Zero for a token HTLC, which is why the token leg passes 0 to
            # the parent's balance assertion and makes the real one against the token itself.
            return 0

        async def fee_fields(self):
            return {"maxPriorityFeePerGas": 1, "maxFeePerGas": 3}

        async def get_transaction_count(self, _a, block="pending"):
            # `inflight` models transactions sitting in the mempool: they advance the PENDING
            # nonce while remaining invisible to a balance read at `latest`.
            return inflight if block == "pending" else settled

        async def wait_receipt(self, *a, **k):
            state["held"] += state.pop("pending", 0)
            return {"status": 1, "logs": []}

    leg = Erc20HtlcLeg(
        token=_USDC, rpc=_Rpc(), signing_key=PrivateKeyMaterial(os.urandom(32)), chain_id=1, artifact=_ART
    )

    async def _sign_and_send(*a, **k):
        order.append("tokens-pushed")
        return "0xpush"

    leg._sign_and_send = _sign_and_send
    leg._state = state
    return leg


class TestTheRealVerifyFundedRunsOnResume:
    def test_a_resume_against_a_GENUINE_contract_completes(self) -> None:
        """The check every earlier resume test stubbed away. Round 6 found `expected_amount_wei=0`
        also inverted the contract's `amount` IMMUTABLE bind — always non-zero — so every resume
        raised before a token moved and the feature was dead. Nothing caught it because no test
        ran the real method."""
        order: list = []
        leg = _real_verify_leg(on_chain={}, held=0, order=order)
        loc = _fund(leg, None, resume_from=_PENDING)
        assert order == ["tokens-pushed"]
        assert loc.contract_address.lower() == _DEPLOYED.lower()

    @pytest.mark.parametrize(
        ("label", "override"),
        [
            ("a different hashlock", {"hashlock": b"\x99" * 32}),
            ("a different claimant", {"claimant": "0x" + "99" * 20}),
            ("a different refundee", {"refundee": "0x" + "99" * 20}),
            ("a different timeout", {"timeout": _TIMEOUT + 1}),
            ("a different amount", {"amount": _AMOUNT + 1}),
        ],
    )
    def test_a_resume_REFUSES_a_contract_whose_immutables_differ(self, label: str, override: dict) -> None:
        """The real safety property, against the real check: a record pointing at a contract that
        is not this swap must not receive tokens. The AMOUNT case is the one the broken waiver
        would have silently skipped had it been waived instead of asserted."""
        order: list = []
        leg = _real_verify_leg(on_chain=override, held=0, order=order)
        with pytest.raises(ValidationError):
            _fund(leg, None, resume_from=_PENDING)
        assert order == [], f"{label}: tokens were sent to a contract that is not this swap"

    @pytest.mark.parametrize(
        ("label", "override"),
        [("a different token", {"token": "0x" + "99" * 20})],
    )
    def test_a_resume_REFUSES_a_contract_denominated_in_ANOTHER_TOKEN(self, label, override) -> None:
        """The `token()` immutable bind — the one asset check that is not self-consistent.

        `locator.token_address` is compared against `self._token` on the maker path by a locator the
        maker itself built from `self._token`, so that check compares the leg against itself. The
        contract's OWN `token()` is the only real bind, and nothing exercised it: the parametrised
        immutable list covered hashlock/claimant/refundee/timeout/amount and not this. Planting
        `if False and ...` on it left the whole suite green, so a hostile taker could deploy an HTLC
        denominated in a worthless token and the maker would lock RXD against it.
        """
        order: list = []
        leg = _real_verify_leg(on_chain=override, held=0, order=order)
        with pytest.raises(ValidationError):
            _fund(leg, None, resume_from=_PENDING)
        assert order == [], f"{label}: tokens were sent to a contract holding another asset"

    def test_the_balance_FLOOR_refuses_when_the_contract_is_genuinely_SHORT(self) -> None:
        """The maker's only proof the HTLC actually HOLDS the negotiated amount.

        Every fixture that drove `verify_funded` set balanceOf EQUAL to the expected amount, so the
        comparison could never be false — planting `if False and held < expected` left 9,780 tests
        green. The fork test that looks like it covers this passes `expected*2`, which trips the
        `amount()` immutable bind FIRST, and its regex accepts either message.

        So this one deliberately makes the balance the ONLY thing wrong: every immutable matches and
        the contract is one base unit short.
        """
        order: list = []
        leg = _real_verify_leg(on_chain={}, held=_AMOUNT - 1, order=order)
        with pytest.raises(ValidationError, match="under-funded"):
            asyncio.run(
                leg.verify_funded(
                    leg._locator_for(
                        address=_DEPLOYED,
                        deploy_hash="0xdeploy",
                        hashlock=b"\x33" * 32,
                        claimant="0x" + "44" * 20,
                        refundee="0x" + "55" * 20,
                        timeout=_FUND_TIMEOUT,
                        amount_wei=_AMOUNT,
                    ),
                    expected_amount_wei=_AMOUNT,
                )
            )

    def test_the_balance_floor_ACCEPTS_an_exactly_funded_contract(self) -> None:
        """The honest-path pair. A floor that refused everything would satisfy the test above."""
        order: list = []
        leg = _real_verify_leg(on_chain={}, held=_AMOUNT, order=order)
        asyncio.run(
            leg.verify_funded(
                leg._locator_for(
                    address=_DEPLOYED,
                    deploy_hash="0xdeploy",
                    hashlock=b"\x33" * 32,
                    claimant="0x" + "44" * 20,
                    refundee="0x" + "55" * 20,
                    timeout=_FUND_TIMEOUT,
                    amount_wei=_AMOUNT,
                ),
                expected_amount_wei=_AMOUNT,
            )
        )

    def test_the_balance_floor_is_the_ONLY_thing_the_resume_waives(self) -> None:
        """A half-finished fund is legitimately short, so the balance must be waived — and nothing
        else may be. Holding zero must still resume; that is what `require_balance=False` buys."""
        order: list = []
        leg = _real_verify_leg(on_chain={}, held=0, order=order)
        assert _fund(leg, None, resume_from=_PENDING) is not None
        assert order == ["tokens-pushed"]


class TestAResumeRefusesWhileAPushIsStillInFlight:
    """The single-process half of the double-fund. `balance_of` reads at `latest`, so a transfer
    still in the mempool is invisible — while the nonce for the next transaction comes from
    `pending`, so the resume's transfer gets a NEW nonce rather than replacing it. Both mine, and
    the HTLC ends holding twice the negotiated amount, which claim sweeps to the counterparty.

    The receipt wait is 300s by default, so this window is wide, and no concurrency is needed to
    hit it — one process, crash, resume.
    """

    def test_it_refuses_when_the_sender_has_a_transaction_in_flight(self) -> None:
        order: list = []
        leg = _real_verify_leg(on_chain={}, held=0, order=order, inflight=1)
        with pytest.raises(NetworkError, match="still in flight"):
            _fund(leg, None, resume_from=_PENDING)
        assert order == [], "a second transfer was sent while the first was still pending"

    def test_it_proceeds_once_nothing_is_in_flight(self) -> None:
        """Paired honest path — a settled mempool must not block a legitimate resume."""
        order: list = []
        leg = _real_verify_leg(on_chain={}, held=0, order=order, inflight=0)
        assert _fund(leg, None, resume_from=_PENDING) is not None
        assert order == ["tokens-pushed"]


# ---------------------------------------------------------------------------
# The NATIVE leg's resume. Round 6 made it refuse `resume_from`; round 7 found that turned a
# transient post-deploy error into an unrecoverable swap — the record keeps a pending handle, every
# retry takes the resume branch, and the leg rejected it forever while H was spent and the ETH sat
# in the contract. It now re-verifies and returns the locator. NOTHING drove the real method with a
# non-None `resume_from` before this, so both the old refusal and the new behaviour were untested.
# ---------------------------------------------------------------------------

_NATIVE_ART = json.loads((pathlib.Path(__file__).parent / "fixtures" / "EthHtlc.json").read_text())
_NATIVE_WEI = 10**15


def _native_leg(
    *,
    on_chain: dict,
    balance: int,
    deployed: list,
    lying_receipt: str | None = None,
    key: PrivateKeyMaterial | None = None,
):
    from pyrxd.eth_wallet.htlc_leg import EthHtlcContractLeg
    from pyrxd.eth_wallet.keys import derive_address

    # The same correction the TOKEN fake above already carries. A deploy receipt cannot name an
    # arbitrary address — `contractAddress` IS `keccak(rlp([sender, nonce]))[12:]` — so a fake
    # returning a fixed `0x7777...` modelled a chain that cannot exist, and the native tests were
    # passing against it. This one derives the address its own key and nonce really imply;
    # `lying_receipt=` opts into the forgery.
    _key = key or PrivateKeyMaterial(os.urandom(32))
    _sender = derive_address(_key)
    state: dict = {}

    imm = {
        "hashlock": b"\x33" * 32,
        "claimant": _CLAIMANT,
        "refundee": _REFUNDEE,
        "timeout": _FUND_TIMEOUT,
        **on_chain,
    }

    class _Call:
        def __init__(self, v):
            self._v = v

        async def call(self, *a, **k):
            return self._v

    class _Fns:
        def hashlock(self, *a, **k):
            return _Call(imm["hashlock"])

        def claimant(self, *a, **k):
            return _Call(imm["claimant"])

        def refundee(self, *a, **k):
            return _Call(imm["refundee"])

        def timeout(self, *a, **k):
            return _Call(imm["timeout"])

    class _Ctor:
        async def build_transaction(self, tx):
            state["deploy_nonce"] = tx.get("nonce")
            return dict(tx)

    class _Contract:
        functions = _Fns()

        def constructor(self, *a, **k):
            return _Ctor()

    class _Eth:
        def contract(self, *a, **k):
            return _Contract()

    class _W3:
        eth = _Eth()

    class _Rpc:
        w3 = _W3()

        write_w3 = w3  # the fake builds transactions against the same object it reads from

        async def latest_block_timestamp(self):
            return int((await self.w3.eth.get_block("latest"))["timestamp"])

        async def latest_block_timestamp_min(self):
            # The multi-source class aggregates this the other way for the staleness and
            # refund-maturity guards; one endpoint has one answer, so the fake mirrors it.
            return await self.latest_block_timestamp()

        async def latest_block_timestamp_quorum(self):
            # The staleness abort reads the QUORUM-th head: MIN lets one lagging endpoint
            # declare a healthy chain halted, MAX lets one liar hide a real halt. A single
            # source has one answer, so all three coincide here.
            return await self.latest_block_timestamp()

        async def assert_chain(self):
            return None

        async def get_code(self, address, *a, **k):
            if str(address).lower() == _DEPLOYED.lower():
                return bytes.fromhex(_NATIVE_ART["runtime_bytecode"].removeprefix("0x"))
            return b""

        async def get_balance(self, *a, **k):
            return balance

        async def fee_fields(self):
            return {"maxPriorityFeePerGas": 1, "maxFeePerGas": 3}

        async def get_transaction_count(self, _a, block="pending"):
            return 0

        async def wait_receipt(self, *a, **k):
            # The deploy confirms and the payable constructor now HOLDS the ETH — which is the
            # whole reason a persist failure after this point must not discard the fund.
            real = _create_address(_sender, int(state["deploy_nonce"]))
            state["deployed"] = real
            return {"status": 1, "contractAddress": lying_receipt or real, "logs": []}

    leg = EthHtlcContractLeg(rpc=_Rpc(), signing_key=_key, chain_id=1, artifact=_NATIVE_ART)

    async def _sign_and_send(*a, **k):
        deployed.append("DEPLOYED")
        return "0x" + "ee" * 32

    leg._sign_and_send = _sign_and_send
    leg._test_state = state
    return leg


def _native_fund(leg, resume_from):
    return asyncio.run(
        leg.fund(
            hashlock=b"\x33" * 32,
            claimant=_CLAIMANT,
            refundee=_REFUNDEE,
            timeout=_FUND_TIMEOUT,
            amount_wei=_NATIVE_WEI,
            resume_from=resume_from,
        )
    )


class TestTheNativeLegResumesInsteadOfRedeploying:
    def test_a_resume_returns_the_EXISTING_contract_and_deploys_NOTHING(self) -> None:
        """Deploying again is the one thing that must not happen: the payable constructor would put
        a SECOND full amount of ETH into a SECOND contract while the first still holds the original."""
        deployed: list = []
        leg = _native_leg(on_chain={}, balance=_NATIVE_WEI, deployed=deployed)
        loc = _native_fund(leg, _PENDING)
        assert deployed == [], "the native leg redeployed on a resume — a second full amount of ETH"
        assert loc.contract_address.lower() == _DEPLOYED.lower()
        assert loc.amount_wei == _NATIVE_WEI

    def test_a_resume_REFUSES_a_contract_that_is_not_this_swap(self) -> None:
        leg = _native_leg(on_chain={"hashlock": b"\x99" * 32}, balance=_NATIVE_WEI, deployed=[])
        with pytest.raises(ValidationError):
            _native_fund(leg, _PENDING)

    def test_a_resume_REFUSES_a_contract_that_does_not_HOLD_the_value(self) -> None:
        """Unlike the token leg there is no half-funded state to tolerate: the constructor is
        payable, so a contract short of the amount is not this swap's funded HTLC and must not be
        reported as one."""
        leg = _native_leg(on_chain={}, balance=_NATIVE_WEI - 1, deployed=[])
        with pytest.raises(ValidationError):
            _native_fund(leg, _PENDING)

    def test_a_FRESH_native_fund_DEPLOYS_rather_than_taking_the_resume_branch(self) -> None:
        """The resume must fire only when a handle is passed. If it leaked into the fresh path it
        would report a locator for a contract this call never deployed — the branch's whole purpose
        is to return WITHOUT deploying, which is precisely wrong when there is nothing to resume."""
        deployed: list = []
        leg = _native_leg(on_chain={}, balance=_NATIVE_WEI, deployed=deployed)
        loc = _native_fund(leg, None)
        assert deployed == ["DEPLOYED"], "a fresh fund returned a locator without deploying anything"
        assert loc.contract_address.lower() == leg._test_state["deployed"].lower()


class TestALyingNativeDeployReceiptCannotRedirectTheFunding:
    """The same defect as the token leg's, in the leg that has already carried real value.

    The token fix was applied only where the bug had been demonstrated, so the NATIVE `fund` went
    on doing `addr = receipt["contractAddress"]`. It is the worse of the two: the constructor is
    payable, so the ETH is inside the contract the instant the deploy confirms — there is no
    second transaction to withhold once the address turns out to be someone else's.

    `wait_receipt` is primary-only by design, so one endpoint alone named the address, and every
    downstream check still passed because the ETH really was there. Deploying the same bytecode is
    no obstacle to an attacker who owns the claim key.
    """

    def test_a_receipt_naming_a_DIFFERENT_contract_is_refused(self) -> None:
        deployed: list = []
        leg = _native_leg(on_chain={}, balance=_NATIVE_WEI, deployed=deployed, lying_receipt="0x" + "ab" * 20)
        with pytest.raises(ValidationError, match="CREATE"):
            _native_fund(leg, None)

    def test_the_refusal_names_BOTH_addresses(self) -> None:
        """An operator holding a locator that does not match the chain needs the two values to
        compare. A refusal that says only 'mismatch' cannot be acted on."""
        leg = _native_leg(on_chain={}, balance=_NATIVE_WEI, deployed=[], lying_receipt="0x" + "ab" * 20)
        with pytest.raises(ValidationError) as ei:
            _native_fund(leg, None)
        msg = str(ei.value).lower()
        assert "0x" + "ab" * 20 in msg, "the address the endpoint named is missing from the refusal"
        assert leg._test_state["deployed"].lower() in msg, "the derived address is missing from the refusal"

    def test_the_refusal_is_not_merely_a_CHECKSUM_disagreement(self) -> None:
        """The honest-path pair. Providers differ on EIP-55 casing, and a correct address in the
        wrong case is an honest receipt — refusing it would strand a fund whose ETH is already in
        the contract, which is strictly worse than the attack.

        THE SAME KEY for both legs, because two random keys deploy to two different addresses and
        the 'honest lowercase' of one is a forgery to the other: the test would then pass by
        triggering the very refusal it claims to rule out.
        """
        shared = PrivateKeyMaterial(os.urandom(32))
        probe = _native_leg(on_chain={}, balance=_NATIVE_WEI, deployed=[], key=shared)
        _native_fund(probe, None)
        honest_lowercase = probe._test_state["deployed"].lower()

        deployed: list = []
        leg = _native_leg(
            on_chain={},
            balance=_NATIVE_WEI,
            deployed=deployed,
            lying_receipt=honest_lowercase,
            key=shared,
        )
        loc = _native_fund(leg, None)
        assert deployed == ["DEPLOYED"], "a correct address in lowercase was refused"
        assert loc.contract_address.lower() == honest_lowercase


class TestTheInFlightGuardDoesNotBlockAFreshFund:
    """The guard belongs to the resume and only to it.

    On a fresh deploy the HTLC address was created by the transaction that just confirmed, so no
    transfer to it can possibly be pending — the hazard is structurally impossible. Applying the
    guard there would abort a legitimate fund AFTER the deploy had spent gas and consumed the
    hashlock reservation, merely because the same key had some unrelated transaction in flight (a
    fee bump, a second swap, an approval). A guard that refuses honest work is a defect, and this
    one did until round 7.
    """

    def test_a_fresh_fund_proceeds_with_unrelated_transactions_pending(self) -> None:
        order: list = []
        leg = _leg(order=order, inflight=3)
        loc = _fund(leg, None)
        assert order == ["tokens-pushed"], f"a fresh fund was blocked by unrelated pending txs: {order}"
        assert loc.contract_address.lower() == leg._test_state["deployed"].lower()

    def test_a_RESUME_is_still_blocked_by_the_same_pending_transactions(self) -> None:
        """The pairing: identical mempool state, opposite verdict, because only the resume can be
        misled by it."""
        order: list = []
        leg = _real_verify_leg(on_chain={}, held=0, order=order, inflight=3)
        with pytest.raises(NetworkError, match="still in flight"):
            _fund(leg, None, resume_from=_PENDING)
        assert order == []

    def test_a_resume_with_NOTHING_LEFT_TO_SEND_is_not_blocked_by_pending_txs(self) -> None:
        """The push whose receipt was lost has MINED — the HTLC already holds the full amount, so
        there is no second transfer to send and no way to double-fund. Refusing here stranded a
        taker whose fund actually completed: its USDC is claimable with `p` while its own
        coordinator would not acknowledge the fund, and a stuck transaction on that key keeps
        `pending != latest` indefinitely."""
        order: list = []
        leg = _real_verify_leg(on_chain={}, held=_AMOUNT, order=order, inflight=3)
        loc = _fund(leg, None, resume_from=_PENDING)
        assert order == [], "a fully funded HTLC was topped up again"
        assert loc.amount_wei == _AMOUNT


class TestThePushNonceIsPinnedAndReused:
    """Nonce pinning is what makes funding idempotent WITHOUT a distributed lock.

    Measured against anvil on 2026-08-24: a second transaction at an already-used sender nonce is
    rejected ("nonce too low" once mined, "transaction already imported" while pending), and a
    higher-priced one REPLACES rather than adds. So two resumers — or a resume racing its own
    still-pending push — deliver the value exactly once. That is a property of the chain, so unlike
    `flock` it holds across hosts, filesystems, and a copied keys directory.

    See docs/solutions/design-decisions/nonce-pinning-makes-erc20-funding-idempotent.md.
    """

    def test_a_fresh_fund_REPORTS_the_nonce_it_pinned(self) -> None:
        """The pin is worthless unless the caller can make it durable before the broadcast — a pin
        recorded after the send is the one thing a crash destroys."""
        order: list = []
        reported: list = []

        async def _remember(nonce: int) -> None:
            reported.append(nonce)

        leg = _leg(order=order)
        asyncio.run(
            leg.fund(
                hashlock=b"\x33" * 32,
                claimant=_CLAIMANT,
                refundee=_REFUNDEE,
                timeout=_FUND_TIMEOUT,
                amount_wei=_AMOUNT,
                on_push_nonce=_remember,
            )
        )
        assert reported, "the push nonce was never reported, so no retry could reuse it"
        assert reported[0] == leg._test_state["push_nonce_used"], (
            f"reported {reported[0]} but built the push with {leg._test_state['push_nonce_used']}"
        )

    def test_a_RESUME_reuses_the_recorded_pin_rather_than_a_fresh_nonce(self) -> None:
        """THE property. A fresh nonce would be additive — both transactions mine and the HTLC ends
        holding twice the amount. Reusing the pin makes the second send a replacement."""
        order: list = []
        leg = _real_verify_leg(on_chain={}, held=0, order=order)
        asyncio.run(
            leg.fund(
                hashlock=b"\x33" * 32,
                claimant=_CLAIMANT,
                refundee=_REFUNDEE,
                timeout=_FUND_TIMEOUT,
                amount_wei=_AMOUNT,
                resume_from=_PENDING,
                push_nonce=41,
            )
        )
        assert leg._state["push_nonce_used"] == 41, (
            f"the resume built its push at nonce {leg._state['push_nonce_used']} instead of the "
            "recorded pin 41 — a fresh nonce is ADDITIVE and funds the HTLC twice"
        )

    def test_a_STOLEN_pin_is_detected_and_fails_closed(self) -> None:
        """The failure mode the spike surfaced. Any other transaction from the same key can take
        the pinned slot; once it mines the pin is spent forever. Re-pinning silently would be the
        double-fund again, because two resumers can re-pin to DIFFERENT nonces and both land."""
        order: list = []
        leg = _real_verify_leg(on_chain={}, held=0, order=order, inflight=0, settled=99)
        with pytest.raises(NetworkError, match="already been consumed"):
            asyncio.run(
                leg.fund(
                    hashlock=b"\x33" * 32,
                    claimant=_CLAIMANT,
                    refundee=_REFUNDEE,
                    timeout=_FUND_TIMEOUT,
                    amount_wei=_AMOUNT,
                    resume_from=_PENDING,
                    push_nonce=41,
                )
            )
        assert order == [], "value was sent against a pin that another transaction had consumed"


class TestAPersistFailureDoesNotDiscardACommittedNativeFund:
    """Making the persist hook mandatory created a regression on the NATIVE leg.

    Its constructor is payable, so the ETH is in the contract the instant the deploy confirms.
    Aborting on a persist failure cannot un-move it — it only discards the address, leaving it in an
    exception string. The rule "if the caller cannot persist it, we must not push" is right for the
    TOKEN leg, where nothing has moved yet and stopping genuinely prevents untracked value, and
    inverted here.
    """

    def test_the_native_fund_survives_a_failing_persist_hook(self) -> None:
        deployed: list = []
        leg = _native_leg(on_chain={}, balance=_NATIVE_WEI, deployed=deployed)

        async def _broken(_addr: str, _tx: str) -> None:
            raise NetworkError("read-only filesystem")

        # The DEPLOY path — the resume path never calls on_deploy at all, so testing through it
        # would prove nothing about this fix.
        loc = asyncio.run(
            leg.fund(
                hashlock=b"\x33" * 32,
                claimant=_CLAIMANT,
                refundee=_REFUNDEE,
                timeout=_FUND_TIMEOUT,
                amount_wei=_NATIVE_WEI,
                on_deploy=_broken,
            )
        )
        assert deployed == ["DEPLOYED"], "the deploy never happened, so the hook was never reached"
        assert loc.contract_address.lower() == leg._test_state["deployed"].lower(), (
            "a persist failure discarded a fund whose ETH is already in the contract"
        )

    def test_the_TOKEN_leg_still_refuses_to_push_when_it_cannot_persist(self) -> None:
        """The pairing. Narrowing the native rule must not disarm the token one, where the abort is
        the only thing preventing value from moving into a contract nothing references."""
        order: list = []

        async def _broken(_addr: str, _tx: str) -> None:
            raise NetworkError("read-only filesystem")

        with pytest.raises(NetworkError, match="read-only filesystem"):
            _fund(_leg(order=order), _broken)
        assert "tokens-pushed" not in order


class TestALyingDeployReceiptCannotRedirectTheFunding:
    """`contractAddress` is reported by ONE endpoint and was believed without question.

    `wait_receipt` is primary-only by design — a receipt is a single-node artifact and the quorum'd
    `get_transaction_receipt` is called zero times during a fund. So the primary alone chose where
    the entire counter-leg amount went, and every downstream check still passed, because the tokens
    really were at the address it named. Verifying the code at that address does not help either:
    an attacker deploys the same bytecode and simply owns the claim keys.

    The address was never something to be told. `keccak(rlp([sender, nonce]))[12:]` derives it from
    two values the deployer already holds.
    """

    def test_a_receipt_naming_a_DIFFERENT_contract_is_refused(self) -> None:
        order: list = []
        leg = _leg(push_fails=False, order=order, lying_receipt="0x" + "ab" * 20)
        with pytest.raises(ValidationError, match="CREATE"):
            _fund(leg, None)
        assert "tokens-pushed" not in order, "tokens were pushed to an address the endpoint invented"

    def test_the_refusal_is_not_merely_a_CHECKSUM_disagreement(self) -> None:
        """The honest-path pair for the guard above. A receipt reporting the RIGHT address in the
        wrong case is honest, and refusing it would be a bug — endpoints differ on EIP-55 casing.
        Nothing may be pushed on a forgery; everything must proceed on a case difference."""
        order: list = []
        # THE SAME KEY for both legs. Two random keys deploy to two different addresses, so the
        # "honest lowercase" of one is a forgery to the other — the test would have passed by
        # triggering the very refusal it claims to rule out.
        shared = PrivateKeyMaterial(os.urandom(32))
        probe = _leg(push_fails=False, order=[], key=shared)
        _fund(probe, None)
        honest_lowercase = probe._test_state["deployed"].lower()

        leg = _leg(push_fails=False, order=order, lying_receipt=honest_lowercase, key=shared)
        loc = _fund(leg, None)
        assert order == ["tokens-pushed"], "a correct address in lowercase was refused"
        assert loc.contract_address.lower() == honest_lowercase

    @pytest.mark.parametrize("nonce", [0, 1, 127, 128, 255, 256, 65535, 1_000_000, 2**32])
    def test_it_matches_an_INDEPENDENT_rlp_encoder(self, nonce: int) -> None:
        """Differential check against a real RLP library, not against itself.

        `_create_address` hand-rolls minimal RLP to avoid a dependency, and a derivation verified
        only by a fake that calls the same function proves the two agree, not that either is right.
        `rlp.encode` is an independent implementation of the encoding the yellow paper specifies,
        so agreeing with it across every nonce branch is a real check on the arithmetic.

        A wrong branch here does not raise — it names a valid-looking address that nobody controls,
        and the tokens go there.
        """
        import rlp
        from eth_utils import keccak, to_checksum_address

        sender = "0x" + os.urandom(20).hex()
        expected = to_checksum_address(keccak(rlp.encode([bytes.fromhex(sender[2:]), nonce]))[12:])
        assert _create_address(sender, nonce) == expected

    @pytest.mark.parametrize("nonce", [0, 1, 127, 128, 255, 256, 65535, 1_000_000])
    def test_every_RLP_nonce_branch_yields_a_distinct_valid_address(self, nonce: int) -> None:
        """Minimal RLP encodes the nonce three different ways (empty string, single byte, length-
        prefixed). A bug in any branch silently sends funds somewhere real and unrecoverable, so
        sweep the boundaries rather than the one value the tests happen to use."""
        from eth_utils import is_checksum_address

        sender = "0x" + os.urandom(20).hex()
        addr = _create_address(sender, nonce)
        assert is_checksum_address(addr), addr
        assert addr != _create_address(sender, nonce + 1)


def _fresh_deploy_address(key: PrivateKeyMaterial, nonce: int = 0) -> str:
    """Where a leg holding `key` will deploy on its FIRST fund — CREATE(sender, nonce).

    Exposed because a test that wants to act on the deployed contract (freeze it, blacklist it)
    has to name the address the leg will really use. Naming a fixture constant instead let the
    fake hand the gate its own answer, so the check passed without the gate doing anything.
    """
    from pyrxd.eth_wallet.keys import derive_address

    return _create_address(derive_address(key), nonce)
