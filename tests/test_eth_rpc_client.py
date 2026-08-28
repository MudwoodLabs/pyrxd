"""Direct tests for ``eth_wallet/rpc.py`` — the layer every EVM fund-safety decision sits on.

The first mutation run over this module scored **9% killed** (30 of 303), the worst in the
codebase. The obvious explanation — "it is covered by the anvil/fork integration tests the
mutation harness does not run" — was checked and is **false**: re-running the group with
``test_eth_leg_anvil_integration.py`` and friends included changed the score by nothing. Those
suites drive the *leg*; they route through this client but never assert on it, so a mutation
inside it still produces a working end-to-end result on a short happy-path chain.

So the tests here look at the client itself, and at the two things a caller cannot see from
above:

* **the request** it constructs — which block a read is pinned to, what filter an
  ``eth_getLogs`` actually asks for, what timeout a receipt wait is given;
* **the classification** of a failure — ``NetworkError`` (retry) vs ``ValidationError``
  (permanent) vs ``None`` (not mined). Getting that wrong is not cosmetic: a transport blip
  mapped to "not mined" tells a claim poller the claim FAILED.

Every guard below is tested in **both** directions. A guard that refuses honest input is a
defect in its own right, and ``finalized_block_number``'s ``fin > head`` is exactly that shape —
ten mutants survived on that one line, among them ``fin >= head``, which rejects a node whose
finalized checkpoint has legitimately caught up with its head.

The fake node answers at the shape web3 hands back, not at the shape that would be convenient:
block heights are the hex quantity a node puts on the wire, parsed with ``int(s, 16)`` exactly as
web3's ``to_integer_if_hex`` does (``web3/_utils/method_formatters.py:129``). That is load-bearing
in one place — see ``test_a_caught_up_finalized_checkpoint_is_accepted_at_MAINNET_height``.
"""

from __future__ import annotations

import asyncio
import sys
from typing import Any

import pytest

pytest.importorskip("web3", reason="needs the eth extra: pip install 'pyrxd[eth]'")

import web3
from hexbytes import HexBytes
from web3.datastructures import AttributeDict

from pyrxd.eth_wallet import rpc as rpc_mod
from pyrxd.eth_wallet.rpc import EthRpc
from pyrxd.network import bitcoin as btc_client
from pyrxd.security.errors import NetworkError, ValidationError

_URL = "http://127.0.0.1:8545"
_ADDR = "0x" + "77" * 20  # the per-swap HTLC
_MISSING = object()

# A real deployed HTLC's runtime bytecode is a few hundred bytes; EIP-170 caps it at 24_576. The
# size cap in this client therefore only ever fires on a hostile or broken endpoint — which is
# what it is for ("a bounded response size", mirroring the BTC client).
_REALISTIC_CODE = bytes.fromhex("6080604052348015600e575f80fd5b50") * 40  # 640 bytes


def _run(coro):
    return asyncio.run(coro)


class _Node:
    """One fake endpoint: dictated answers plus a log of what was ASKED.

    An answer may be a value (returned), an exception instance (raised), or a callable (invoked
    with the call's arguments). A method with no dictated answer is a test bug, not a default —
    it raises, so a test cannot accidentally pass against a call it never modelled.
    """

    def __init__(self, **answers: Any) -> None:
        self.calls: list[tuple[str, tuple, dict]] = []
        self._answers = dict(answers)
        self.eth = _Eth(self)

    def answer(self, name: str, *args: Any, **kwargs: Any) -> Any:
        self.calls.append((name, args, kwargs))
        a = self._answers.get(name, _MISSING)
        if a is _MISSING:
            raise AssertionError(f"the client called {name}{args!r}, which this test did not dictate")
        if isinstance(a, BaseException):
            raise a
        if callable(a):
            return a(*args, **kwargs)
        return a

    def asked(self, name: str) -> list[tuple[tuple, dict]]:
        return [(a, k) for n, a, k in self.calls if n == name]


class _Eth:
    """``AsyncWeb3.eth``: coroutine methods, and the three reads web3 exposes as *awaitable
    properties* rather than calls (``chain_id``, ``block_number``, ``max_priority_fee``)."""

    def __init__(self, node: _Node) -> None:
        self._node = node

    def _coro(self, name: str, *args: Any, **kwargs: Any):
        node = self._node

        async def _run_it():
            return node.answer(name, *args, **kwargs)

        return _run_it()

    @property
    def chain_id(self):
        return self._coro("chain_id")

    @property
    def block_number(self):
        return self._coro("block_number")

    @property
    def max_priority_fee(self):
        return self._coro("max_priority_fee")

    async def get_block(self, which, *a, **k):
        return self._node.answer("get_block", which, *a, **k)

    async def get_code(self, *a, **k):
        return self._node.answer("get_code", *a, **k)

    async def get_balance(self, *a, **k):
        return self._node.answer("get_balance", *a, **k)

    async def get_transaction_count(self, *a, **k):
        return self._node.answer("get_transaction_count", *a, **k)

    async def call(self, *a, **k):
        return self._node.answer("call", *a, **k)

    async def send_raw_transaction(self, *a, **k):
        return self._node.answer("send_raw_transaction", *a, **k)

    async def wait_for_transaction_receipt(self, *a, **k):
        return self._node.answer("wait_for_transaction_receipt", *a, **k)

    async def get_transaction(self, *a, **k):
        return self._node.answer("get_transaction", *a, **k)

    async def get_transaction_receipt(self, *a, **k):
        return self._node.answer("get_transaction_receipt", *a, **k)

    async def get_logs(self, *a, **k):
        return self._node.answer("get_logs", *a, **k)


def _client(*, expected_chain_id: int = 1, **answers: Any) -> tuple[EthRpc, _Node]:
    """A real ``EthRpc`` (so the constructor's own validation runs) wired to a fake node."""
    client = EthRpc(_URL, expected_chain_id=expected_chain_id)
    node = _Node(**answers)
    client._w3 = node
    return client, node


def _block(number_hex: str, **extra: Any) -> AttributeDict:
    """A block as web3 hands it back: the node's hex quantity through ``to_integer_if_hex``."""
    return AttributeDict({"number": int(number_hex, 16), **extra})


# --------------------------------------------------------------------------------------------
# Construction
# --------------------------------------------------------------------------------------------


class TestConstruction:
    def test_an_honest_endpoint_and_chain_id_construct(self) -> None:
        client = EthRpc(_URL, expected_chain_id=1)  # 1 == Ethereum mainnet
        assert client.w3 is not None

    @pytest.mark.parametrize(
        "url",
        [
            "",  # a config field left blank
            None,  # an unset env var read straight through
            b"http://127.0.0.1:8545",  # bytes from a file read in binary mode
        ],
    )
    def test_an_unusable_rpc_url_is_refused_before_any_network_call(self, url) -> None:
        with pytest.raises(ValidationError):
            EthRpc(url, expected_chain_id=1)

    @pytest.mark.parametrize(
        "cid",
        [
            0,  # "unset"
            -1,
            1.0,  # a chain id read out of JSON, where every number is a float
            "1",  # ...or out of an env var, where every value is a string
        ],
    )
    def test_a_chain_id_that_is_not_a_positive_int_is_refused(self, cid) -> None:
        with pytest.raises(ValidationError):
            EthRpc(_URL, expected_chain_id=cid)

    def test_chain_id_ONE_is_accepted_the_bound_is_lt_zero_not_lt_one(self) -> None:
        # Ethereum mainnet is chain 1. A `<= 1` bound would lock the client out of it — the
        # cheapest possible example of a guard that refuses valid work.
        assert EthRpc(_URL, expected_chain_id=1) is not None

    def test_the_chain_id_cannot_be_passed_POSITIONALLY(self) -> None:
        # It is keyword-only on purpose: `EthRpc(url, 1)` reads as harmless and would let a
        # caller swap two arguments without the reader noticing.
        with pytest.raises(TypeError):
            EthRpc(_URL, 1)  # type: ignore[misc]

    def test_w3_and_write_w3_are_the_SAME_object_on_the_single_source_client(self) -> None:
        # `write_w3` exists to name build-vs-read at the call sites; on this class the two
        # coincide, and both must stay ATTRIBUTES (a lost @property makes `.w3.eth` a bound
        # method, which fails far away from here).
        client, node = _client()
        assert client.w3 is node
        assert client.write_w3 is node


class TestTheEthExtraIsOptional:
    def test_a_checkout_without_web3_gets_the_install_hint_not_a_raw_ImportError(self, monkeypatch) -> None:
        # `None` in sys.modules is what the import machinery uses to mean "this import fails",
        # so `import web3` raises ImportError exactly as it would with the package absent.
        monkeypatch.setitem(sys.modules, "web3", None)
        with pytest.raises(ValidationError):
            rpc_mod._require_web3()

    def test_with_the_extra_present_it_returns_the_module(self) -> None:
        assert rpc_mod._require_web3() is web3


# --------------------------------------------------------------------------------------------
# assert_chain — the fail-closed "am I even on the right network" check
# --------------------------------------------------------------------------------------------


class TestAssertChain:
    def test_the_expected_chain_passes(self) -> None:
        client, _ = _client(expected_chain_id=1, chain_id=1)
        assert _run(client.assert_chain()) is None

    def test_a_matching_chain_id_is_compared_BY_VALUE_not_by_identity(self) -> None:
        # web3 parses `eth_chainId` out of a hex string, so the int it returns is a FRESH object.
        # An identity comparison would pass on a devnet (small ints are interned) and refuse
        # Base mainnet — the swap would abort on a perfectly healthy endpoint.
        parsed = int("0x2105", 16)  # Base mainnet, 8453; above the small-int cache, so a new object
        client, _ = _client(expected_chain_id=8453, chain_id=parsed)
        assert _run(client.assert_chain()) is None

    @pytest.mark.parametrize(
        ("expected", "actual"),
        [
            (8453, 1),  # pointed at mainnet while the swap was negotiated for Base
            (1, 8453),  # ...and the other way round
            (1, 11_155_111),  # mainnet keys against Sepolia
        ],
    )
    def test_any_other_chain_is_refused_in_both_directions(self, expected: int, actual: int) -> None:
        client, _ = _client(expected_chain_id=expected, chain_id=actual)
        with pytest.raises(ValidationError):
            _run(client.assert_chain())

    def test_an_unreachable_endpoint_is_a_NetworkError_not_a_wrong_chain(self) -> None:
        # The distinction matters: a wrong chain is permanent, a dead endpoint is retryable.
        client, _ = _client(chain_id=ConnectionResetError("connection reset by peer"))
        with pytest.raises(NetworkError):
            _run(client.assert_chain())


# --------------------------------------------------------------------------------------------
# get_code — the contract-identity read, and the response cap
# --------------------------------------------------------------------------------------------


class TestGetCode:
    def test_no_block_identifier_asks_for_ONE_argument_leaving_web3_its_default(self) -> None:
        client, node = _client(get_code=HexBytes(_REALISTIC_CODE))
        assert _run(client.get_code(_ADDR)) == _REALISTIC_CODE
        assert node.asked("get_code") == [((_ADDR,), {})]

    def test_a_block_identifier_is_FORWARDED_so_the_read_is_pinned(self) -> None:
        # This is the TOCTOU fix: a maker re-verifying before it locks must read the code at a
        # block a reorg cannot take back. Dropping the argument silently un-pins the read.
        client, node = _client(get_code=HexBytes(_REALISTIC_CODE))
        assert _run(client.get_code(_ADDR, "finalized")) == _REALISTIC_CODE
        assert node.asked("get_code") == [((_ADDR, "finalized"), {})]

    def test_block_ZERO_is_a_real_pin_and_is_not_mistaken_for_unset(self) -> None:
        # `if block_identifier:` instead of `is None` would drop genesis. It is a legitimate
        # value, and `0` is the one int that would go missing.
        client, node = _client(get_code=HexBytes(b""))
        assert _run(client.get_code(_ADDR, 0)) == b""
        assert node.asked("get_code") == [((_ADDR, 0), {})]

    def test_an_empty_result_is_returned_as_empty_bytes_not_an_error(self) -> None:
        # "nothing deployed here" is an ANSWER, and the identity check above needs to see it.
        client, _ = _client(get_code=HexBytes(b""))
        assert _run(client.get_code(_ADDR)) == b""

    def test_a_realistic_contract_is_well_under_the_cap_and_passes_through_unchanged(self) -> None:
        client, _ = _client(get_code=HexBytes(_REALISTIC_CODE))
        got = _run(client.get_code(_ADDR))
        assert got == _REALISTIC_CODE
        assert type(got) is bytes  # a plain bytes, not the HexBytes web3 handed over

    def test_a_response_of_EXACTLY_the_cap_is_still_served(self) -> None:
        # The boundary is `>`, not `>=`. Sized from a literal rather than from the module
        # constant on purpose — a test that measures its own fixture with the value under test
        # cannot see the value move.
        client, _ = _client(get_code=HexBytes(b"\x00" * (10 * 1024 * 1024)))
        assert len(_run(client.get_code(_ADDR))) == 10 * 1024 * 1024

    def test_one_byte_over_the_cap_is_refused(self) -> None:
        # EIP-170 caps deployed code at 24_576 bytes, so nothing honest is anywhere near this;
        # the cap exists so a hostile or broken endpoint cannot make the client allocate without
        # bound. Both fixtures are that endpoint.
        client, _ = _client(get_code=HexBytes(b"\x00" * (10 * 1024 * 1024 + 1)))
        with pytest.raises(NetworkError):
            _run(client.get_code(_ADDR))

    def test_a_transport_failure_is_a_NetworkError(self) -> None:
        client, _ = _client(get_code=TimeoutError("read timeout"))
        with pytest.raises(NetworkError):
            _run(client.get_code(_ADDR))


# --------------------------------------------------------------------------------------------
# get_balance — funding verification
# --------------------------------------------------------------------------------------------


class TestGetBalance:
    def test_no_block_identifier_asks_for_ONE_argument(self) -> None:
        client, node = _client(get_balance=10**18)
        assert _run(client.get_balance(_ADDR)) == 10**18
        assert node.asked("get_balance") == [((_ADDR,), {})]

    def test_a_block_identifier_is_FORWARDED(self) -> None:
        # Funding is verified at `finalized` so a reorg cannot un-fund what was just checked.
        client, node = _client(get_balance=10**18)
        assert _run(client.get_balance(_ADDR, "finalized")) == 10**18
        assert node.asked("get_balance") == [((_ADDR, "finalized"), {})]

    def test_block_ZERO_is_a_real_pin(self) -> None:
        client, node = _client(get_balance=0)
        assert _run(client.get_balance(_ADDR, 0)) == 0
        assert node.asked("get_balance") == [((_ADDR, 0), {})]

    def test_an_unfunded_account_reads_zero_rather_than_failing(self) -> None:
        client, _ = _client(get_balance=0)
        assert _run(client.get_balance(_ADDR)) == 0

    def test_a_transport_failure_is_a_NetworkError_not_a_zero_balance(self) -> None:
        # The whole point. "I could not read the balance" must never arrive as "the balance is
        # zero", which is what a swallowed exception would look like to the funding gate.
        client, _ = _client(get_balance=ConnectionError("endpoint down"))
        with pytest.raises(NetworkError):
            _run(client.get_balance(_ADDR))


class TestGetTransactionCount:
    def test_the_default_block_is_PENDING_so_an_in_flight_tx_is_counted(self) -> None:
        client, node = _client(get_transaction_count=7)
        assert _run(client.get_transaction_count(_ADDR)) == 7
        assert node.asked("get_transaction_count") == [((_ADDR, "pending"), {})]

    def test_LATEST_can_be_asked_for_explicitly_which_is_what_makes_the_pair_useful(self) -> None:
        # `pending != latest` is how the resume guard tells "the HTLC holds nothing" apart from
        # "the HTLC holds nothing YET". Both reads have to be reachable for that to work.
        client, node = _client(get_transaction_count=6)
        assert _run(client.get_transaction_count(_ADDR, "latest")) == 6
        assert node.asked("get_transaction_count") == [((_ADDR, "latest"), {})]

    def test_a_transport_failure_is_a_NetworkError_not_a_nonce_of_zero(self) -> None:
        client, _ = _client(get_transaction_count=ConnectionError("endpoint down"))
        with pytest.raises(NetworkError):
            _run(client.get_transaction_count(_ADDR))


# --------------------------------------------------------------------------------------------
# fee_fields — claim pricing, which is what decides whether a deadline-bound tx gets included
# --------------------------------------------------------------------------------------------


class TestFeeFields:
    # Base mainnet magnitudes: a base fee in the single-digit mwei and a tip around 0.001 gwei.
    # The two DIFFER by a factor that no rearrangement of `base * 2 + tip` reproduces, which is
    # the point — equal or round values let a wrong formula agree with the right one.
    _BASE = 8_123_456
    _TIP = 1_000_003

    def test_the_ceiling_is_two_base_fees_plus_the_tip(self) -> None:
        client, node = _client(
            get_block=lambda which, *a, **k: AttributeDict({"baseFeePerGas": self._BASE}),
            max_priority_fee=self._TIP,
        )
        fees = _run(client.fee_fields())
        assert fees == {
            "maxPriorityFeePerGas": self._TIP,
            "maxFeePerGas": self._BASE * 2 + self._TIP,
        }
        # ...and it is priced off the PENDING block, not the mined head: the tx will be included
        # against the next block's base fee, not the last one's.
        assert node.asked("get_block") == [(("pending",), {})]

    def test_the_headroom_is_a_DOUBLING_not_an_addition(self) -> None:
        # EIP-1559 lets the base fee rise 12.5% per block; 2x is roughly six blocks of head-room.
        # A `+` where the `*` belongs would price a claim at base + 2, and it would sit in the
        # mempool until the HTLC timed out.
        client, _ = _client(
            get_block=lambda *a, **k: AttributeDict({"baseFeePerGas": self._BASE}),
            max_priority_fee=self._TIP,
        )
        fees = _run(client.fee_fields())
        assert fees["maxFeePerGas"] - fees["maxPriorityFeePerGas"] == 2 * self._BASE

    def test_a_chain_with_no_baseFeePerGas_field_prices_at_the_tip_alone(self) -> None:
        # A pre-EIP-1559 chain (or a node that omits the field on `pending`) must not be given a
        # fabricated base fee. The default is 0, so the ceiling collapses to the tip.
        client, _ = _client(get_block=lambda *a, **k: AttributeDict({}), max_priority_fee=self._TIP)
        assert _run(client.fee_fields()) == {
            "maxPriorityFeePerGas": self._TIP,
            "maxFeePerGas": self._TIP,
        }

    def test_a_NULL_baseFeePerGas_is_treated_as_zero_not_propagated(self) -> None:
        # Nodes do return `"baseFeePerGas": null` on non-1559 blocks; `or 0` is what stops that
        # None reaching the arithmetic.
        client, _ = _client(
            get_block=lambda *a, **k: AttributeDict({"baseFeePerGas": None}), max_priority_fee=self._TIP
        )
        assert _run(client.fee_fields())["maxFeePerGas"] == self._TIP

    def test_a_zero_tip_still_pays_the_base_fee_headroom(self) -> None:
        # Legitimate on an L2 with no priority auction.
        client, _ = _client(get_block=lambda *a, **k: AttributeDict({"baseFeePerGas": self._BASE}), max_priority_fee=0)
        assert _run(client.fee_fields()) == {"maxPriorityFeePerGas": 0, "maxFeePerGas": self._BASE * 2}

    def test_a_failed_fee_estimate_is_a_NetworkError_not_a_free_transaction(self) -> None:
        client, _ = _client(get_block=ConnectionError("endpoint down"), max_priority_fee=self._TIP)
        with pytest.raises(NetworkError):
            _run(client.fee_fields())

    def test_a_failed_TIP_estimate_is_also_a_NetworkError(self) -> None:
        client, _ = _client(
            get_block=lambda *a, **k: AttributeDict({"baseFeePerGas": self._BASE}),
            max_priority_fee=ValueError("eth_maxPriorityFeePerGas not supported"),
        )
        with pytest.raises(NetworkError):
            _run(client.fee_fields())


# --------------------------------------------------------------------------------------------
# preflight — a gas-saving optimisation that must never become a permanent block on the exit
# --------------------------------------------------------------------------------------------


_CLAIM_TX = {
    "from": "0x" + "aa" * 20,
    "to": _ADDR,
    "value": 0,
    "data": "0x1e83409a" + "11" * 32,
    "gas": 120_000,
    "nonce": 4,
    "chainId": 1,
    "maxFeePerGas": 17_246_915,
    "maxPriorityFeePerGas": 1_000_003,
}


class TestPreflight:
    def test_a_tx_the_node_accepts_passes_and_only_call_shaped_fields_are_sent(self) -> None:
        client, node = _client(call=HexBytes(b""))  # an eth_call that returns nothing, as web3 does
        assert _run(client.preflight(_CLAIM_TX)) is None
        (args, _kwargs) = node.asked("call")[0]
        assert args[0] == {k: _CLAIM_TX[k] for k in ("from", "to", "value", "data")}

    @pytest.mark.parametrize(
        "exc",
        [
            web3.exceptions.ContractLogicError("execution reverted: NotYetExpired"),
            web3.exceptions.ContractCustomError("0x59912c06"),
            web3.exceptions.ContractPanicError("Panic error 0x11"),
        ],
    )
    def test_a_TYPED_revert_is_permanent_and_stops_the_broadcast(self, exc) -> None:
        client, _ = _client(call=exc)
        with pytest.raises(ValidationError):
            _run(client.preflight(_CLAIM_TX))

    @pytest.mark.parametrize(
        "exc",
        [
            ConnectionError("connection reset by peer"),
            TimeoutError("read timeout"),
            # A lying endpoint stuffing the word into a TRANSPORT failure. Classified on the
            # TYPE, so the text buys the attacker nothing: were it substring-matched, a hostile
            # provider could make the honest taker refund — the only exit — look permanent.
            ValueError("execution reverted: revert revert revert"),
        ],
    )
    def test_an_UNTYPED_failure_is_retryable_however_it_is_worded(self, exc) -> None:
        client, _ = _client(call=exc)
        with pytest.raises(NetworkError):
            _run(client.preflight(_CLAIM_TX))


# --------------------------------------------------------------------------------------------
# send_raw / wait_receipt / get_transaction
# --------------------------------------------------------------------------------------------


class TestSendRaw:
    def test_the_returned_hash_is_the_HEX_of_the_bytes_web3_hands_back(self) -> None:
        # web3 returns HexBytes. `str()` of that object is the bytes REPR, not a hash, and a repr
        # travelling on as a transaction identifier would be a nasty thing to debug.
        #
        # Asserted as a round trip rather than as one exact string because the 0x prefix belongs
        # to hexbytes, not to us: `.hex()` is unprefixed under the currently resolved hexbytes
        # 2.0.0 and was prefixed under 1.x. Either form is accepted downstream — web3's request
        # munger normalises both to `0x…` on the wire — so pinning one would couple this test to
        # a transitive dependency's convention rather than to the client's own behaviour.
        raw_hash = bytes.fromhex("ab" * 32)
        client, node = _client(send_raw_transaction=HexBytes(raw_hash))
        got = _run(client.send_raw(b"\x02\xf8\x6f"))
        assert isinstance(got, str)
        assert bytes.fromhex(got.removeprefix("0x")) == raw_hash
        assert node.asked("send_raw_transaction") == [((b"\x02\xf8\x6f",), {})]

    def test_a_rejected_broadcast_is_a_NetworkError(self) -> None:
        client, _ = _client(send_raw_transaction=ValueError("replacement transaction underpriced"))
        with pytest.raises(NetworkError):
            _run(client.send_raw(b"\x02\xf8\x6f"))


class TestWaitReceipt:
    _RECEIPT = AttributeDict({"status": 1, "blockNumber": 23_487_072, "transactionHash": HexBytes(b"\xab" * 32)})

    def test_the_default_wait_is_five_minutes(self) -> None:
        # The budget a caller inherits when it does not name one. It is not decoration: a claim
        # poller that gives up early reports a mined claim as unconfirmed.
        client, node = _client(wait_for_transaction_receipt=self._RECEIPT)
        assert _run(client.wait_receipt("0x" + "ab" * 32))["status"] == 1
        assert node.asked("wait_for_transaction_receipt") == [(("0x" + "ab" * 32,), {"timeout": 300.0})]

    def test_an_explicit_timeout_is_forwarded(self) -> None:
        client, node = _client(wait_for_transaction_receipt=self._RECEIPT)
        _run(client.wait_receipt("0x" + "ab" * 32, timeout_s=45.0))
        assert node.asked("wait_for_transaction_receipt")[0][1] == {"timeout": 45.0}

    def test_the_timeout_cannot_be_passed_POSITIONALLY(self) -> None:
        # Keyword-only so it cannot be mistaken for a second identifier at a call site.
        client, _ = _client(wait_for_transaction_receipt=self._RECEIPT)
        with pytest.raises(TypeError):
            _run(client.wait_receipt("0x" + "ab" * 32, 45.0))  # type: ignore[misc]

    def test_the_receipt_arrives_as_a_plain_dict(self) -> None:
        client, _ = _client(wait_for_transaction_receipt=self._RECEIPT)
        got = _run(client.wait_receipt("0x" + "ab" * 32))
        assert type(got) is dict
        assert got["blockNumber"] == 23_487_072

    def test_a_timed_out_wait_is_a_NetworkError(self) -> None:
        client, _ = _client(wait_for_transaction_receipt=web3.exceptions.TimeExhausted("not mined in 300s"))
        with pytest.raises(NetworkError):
            _run(client.wait_receipt("0x" + "ab" * 32))


class TestGetTransaction:
    def test_a_known_transaction_comes_back_as_a_plain_dict(self) -> None:
        client, _ = _client(get_transaction=AttributeDict({"input": "0x1e83409a", "blockNumber": 23_487_072}))
        got = _run(client.get_transaction("0x" + "ab" * 32))
        assert type(got) is dict
        assert got["input"] == "0x1e83409a"

    def test_a_transport_failure_is_a_NetworkError(self) -> None:
        client, _ = _client(get_transaction=ConnectionError("endpoint down"))
        with pytest.raises(NetworkError):
            _run(client.get_transaction("0x" + "ab" * 32))


# --------------------------------------------------------------------------------------------
# get_transaction_receipt — "not mined" and "I could not tell" must never be the same answer
# --------------------------------------------------------------------------------------------


class TestGetTransactionReceipt:
    def test_a_mined_transaction_returns_its_receipt(self) -> None:
        client, _ = _client(get_transaction_receipt=AttributeDict({"status": 1, "blockNumber": 23_487_072}))
        got = _run(client.get_transaction_receipt("0x" + "ab" * 32))
        assert type(got) is dict
        assert got == {"status": 1, "blockNumber": 23_487_072}

    def test_a_REVERTED_transaction_still_returns_its_receipt(self) -> None:
        # status 0 is an answer, not an absence — the claim confirmation needs to see it.
        client, _ = _client(get_transaction_receipt=AttributeDict({"status": 0, "blockNumber": 23_487_072}))
        assert _run(client.get_transaction_receipt("0x" + "ab" * 32)) == {"status": 0, "blockNumber": 23_487_072}

    def test_an_unmined_transaction_returns_None_rather_than_blocking_or_raising(self) -> None:
        # Pending, or reorg-orphaned back into the mempool. A poller must get an answer it can
        # loop on.
        client, _ = _client(get_transaction_receipt=web3.exceptions.TransactionNotFound("not found"))
        assert _run(client.get_transaction_receipt("0x" + "ab" * 32)) is None

    def test_a_TRANSPORT_failure_is_a_NetworkError_and_NOT_a_None(self) -> None:
        # The fund-relevant half. `None` means "not mined"; a dead endpoint answering `None`
        # tells a claim poller the claim did not land, when it may well have.
        client, _ = _client(get_transaction_receipt=ConnectionError("endpoint down"))
        with pytest.raises(NetworkError):
            _run(client.get_transaction_receipt("0x" + "ab" * 32))


# --------------------------------------------------------------------------------------------
# finalized_block_number — the reorg pin. Ten mutants survived on its one guard line.
# --------------------------------------------------------------------------------------------


def _heights(fin_hex: str, head_hex: str):
    """Answer `finalized` and `latest` the way a node does — as separate hex quantities."""

    def _get_block(which, *a, **k):
        if which == "finalized":
            return _block(fin_hex)
        if which == "latest":
            return _block(head_hex)
        raise AssertionError(f"unexpected block tag {which!r}")

    return _get_block


class TestFinalizedBlockNumber:
    def test_the_normal_case_finalized_lagging_the_head_by_two_epochs(self) -> None:
        # ~64 blocks behind is what Ethereum mainnet looks like on any ordinary day.
        client, _ = _client(get_block=_heights("0x1666260", "0x16662a0"))
        assert _run(client.finalized_block_number()) == 23_487_072

    def test_a_caught_up_finalized_checkpoint_is_accepted_at_MAINNET_height(self) -> None:
        # THE guard-refusing-valid-work case. `finalized == head` is legitimate — it is the
        # steady state on an instant-finality L2 and happens on any chain whose checkpoint has
        # caught up — and `fin >= head` would fail-closed on it, stalling an honest swap at the
        # reorg gate. Mainnet-scale heights on purpose: web3 parses each tag's hex separately, so
        # these two ints are equal and NOT the same object, which is also what makes an identity
        # comparison here wrong.
        client, _ = _client(get_block=_heights("0x1666260", "0x1666260"))
        assert _run(client.finalized_block_number()) == 23_487_072

    def test_a_caught_up_checkpoint_is_accepted_at_DEVNET_height_too(self) -> None:
        # The mirror of the above: small heights parse to interned ints, so `fin` and `head` ARE
        # the same object here. A fresh OP-stack devnet at block 8 with instant finality looks
        # exactly like this, and it must not be refused either.
        client, _ = _client(get_block=_heights("0x8", "0x8"))
        assert _run(client.finalized_block_number()) == 8

    def test_a_genesis_only_chain_reports_zero_rather_than_being_refused(self) -> None:
        # `fin < 0` is the bound, not `fin < 1` and not `fin != 0`: height 0 is a real answer on
        # a chain that has only its genesis block.
        client, _ = _client(get_block=_heights("0x0", "0x0"))
        assert _run(client.finalized_block_number()) == 0

    def test_a_finalized_height_AHEAD_of_the_head_is_refused_fail_closed(self) -> None:
        # The attack this guard is for: a naive lying RPC over-reporting `finalized` so a
        # non-final claim looks FINAL. finalized <= head always.
        client, _ = _client(get_block=_heights("0x16662a0", "0x1666260"))
        with pytest.raises(NetworkError):
            _run(client.finalized_block_number())

    def test_one_block_ahead_of_the_head_is_already_incoherent(self) -> None:
        # The refusal boundary is exactly `>`, so the smallest possible lie is caught.
        client, _ = _client(get_block=_heights("0x1666261", "0x1666260"))
        with pytest.raises(NetworkError):
            _run(client.finalized_block_number())

    def test_a_NEGATIVE_finalized_height_is_refused(self) -> None:
        # Reachable, not theoretical: web3's block formatter is
        # `apply_formatter_if(is_string, hex_to_integer)`, so a non-string value in `number`
        # passes through UNCONVERTED. A hostile server answering a bare JSON `-1` lands here,
        # and `-1` compares "below" every real height at every gate downstream.
        client, _ = _client(
            get_block=lambda which, *a, **k: AttributeDict({"number": -1 if which == "finalized" else 100})
        )
        with pytest.raises(NetworkError):
            _run(client.finalized_block_number())

    def test_a_transport_failure_is_a_NetworkError(self) -> None:
        client, _ = _client(get_block=ConnectionError("endpoint down"))
        with pytest.raises(NetworkError):
            _run(client.finalized_block_number())

    def test_BOTH_tags_are_read_from_the_SAME_endpoint(self) -> None:
        # The coherence check is only meaningful if the two heights come from one provider;
        # comparing one node's finalized against another's head proves nothing.
        client, node = _client(get_block=_heights("0x1666260", "0x16662a0"))
        _run(client.finalized_block_number())
        assert [a[0] for a, _k in node.asked("get_block")] == ["finalized", "latest"]


class TestBlockNumber:
    def test_the_head_is_read_from_eth_blockNumber(self) -> None:
        client, _ = _client(block_number=23_487_072)
        assert _run(client.block_number()) == 23_487_072

    def test_a_transport_failure_is_a_NetworkError(self) -> None:
        client, _ = _client(block_number=ConnectionError("endpoint down"))
        with pytest.raises(NetworkError):
            _run(client.block_number())


# --------------------------------------------------------------------------------------------
# canonical_block_hash — what binds a receipt's claimed height to the chain that really exists
# --------------------------------------------------------------------------------------------


class TestCanonicalBlockHash:
    _HASH = HexBytes(bytes.fromhex("cd" * 32))

    def test_a_mainnet_height_returns_the_canonical_hash_as_bytes(self) -> None:
        client, node = _client(get_block=lambda n, *a, **k: AttributeDict({"hash": self._HASH}))
        got = _run(client.canonical_block_hash(23_487_072))
        assert got == bytes.fromhex("cd" * 32)
        assert type(got) is bytes
        assert node.asked("get_block") == [((23_487_072,), {})]

    def test_GENESIS_is_a_legitimate_height(self) -> None:
        # `block_number < 0` is the bound. `< 1`, `== 0`, `<= 0` and `!= 0` all refuse height 0,
        # and a chain's genesis hash is a perfectly ordinary thing to want.
        client, _ = _client(get_block=lambda n, *a, **k: AttributeDict({"hash": self._HASH}))
        assert _run(client.canonical_block_hash(0)) == bytes.fromhex("cd" * 32)

    def test_a_block_with_no_hash_yet_is_empty_bytes_not_a_crash(self) -> None:
        # A pending block carries `"hash": null`. The caller compares the result against the
        # receipt's blockHash, so empty bytes fails the binding closed, which is correct.
        client, _ = _client(get_block=lambda n, *a, **k: AttributeDict({"hash": None}))
        assert _run(client.canonical_block_hash(23_487_072)) == b""

    @pytest.mark.parametrize(
        "bad",
        [
            -1,  # a height derived by subtracting a confirmation depth near genesis
            23_487_072.0,  # a height that went through JSON, where numbers are floats
            "23487072",  # ...or through an env var / CLI argument
            None,
        ],
    )
    def test_a_height_that_is_not_a_non_negative_int_is_refused(self, bad) -> None:
        # The node is given a WORKING answer on purpose: if the guard let one of these through,
        # the read would succeed and the test would pass for the wrong reason. The `calls` check
        # is what makes the refusal load-bearing — it must happen before any network call.
        client, node = _client(get_block=lambda n, *a, **k: AttributeDict({"hash": self._HASH}))
        with pytest.raises(NetworkError):
            _run(client.canonical_block_hash(bad))
        assert node.calls == []

    def test_a_BOOL_is_refused_even_though_python_calls_it_an_int(self) -> None:
        # `True` is `1`. Without the explicit bool check it would silently fetch block 1's hash
        # and hand it to a comparison that thinks it is looking at the receipt's block.
        client, node = _client(get_block=lambda n, *a, **k: AttributeDict({"hash": self._HASH}))
        with pytest.raises(NetworkError):
            _run(client.canonical_block_hash(True))
        assert node.calls == []

    def test_a_transport_failure_is_a_NetworkError(self) -> None:
        client, _ = _client(get_block=ConnectionError("endpoint down"))
        with pytest.raises(NetworkError):
            _run(client.canonical_block_hash(23_487_072))


# --------------------------------------------------------------------------------------------
# get_logs — how a claim is PROVEN to have happened
# --------------------------------------------------------------------------------------------

_CLAIMED_TOPIC = "0x" + "3c" * 32
_LOG = AttributeDict({"address": _ADDR, "topics": [HexBytes(bytes.fromhex("3c" * 32))], "data": "0x" + "11" * 32})


class TestGetLogs:
    def test_the_default_filter_scans_the_whole_chain_for_ONE_address(self) -> None:
        client, node = _client(get_logs=[_LOG])
        got = _run(client.get_logs(address=_ADDR))
        assert [type(x) for x in got] == [dict]
        assert node.asked("get_logs") == [(({"address": _ADDR, "fromBlock": "earliest", "toBlock": "latest"},), {})]

    def test_an_int_from_block_is_forwarded_unchanged_to_bound_the_scan(self) -> None:
        # The deploy block. web3 hex-encodes it on the way out; pre-encoding here would double it.
        client, node = _client(get_logs=[])
        _run(client.get_logs(address=_ADDR, from_block=23_487_072))
        assert node.asked("get_logs")[0][0][0]["fromBlock"] == 23_487_072

    def test_detection_reads_to_LATEST_so_a_just_mined_claim_is_not_missed(self) -> None:
        # Deliberate: a watchtower that only looked as far as `finalized` would learn about a
        # claim it has to race two epochs late. Reorg-safety is asserted separately.
        client, node = _client(get_logs=[])
        _run(client.get_logs(address=_ADDR, from_block=23_487_072))
        assert node.asked("get_logs")[0][0][0]["toBlock"] == "latest"

    def test_an_explicit_to_block_is_forwarded(self) -> None:
        client, node = _client(get_logs=[])
        _run(client.get_logs(address=_ADDR, from_block=23_486_000, to_block=23_487_072))
        assert node.asked("get_logs")[0][0][0]["toBlock"] == 23_487_072

    def test_topics_are_included_when_given(self) -> None:
        client, node = _client(get_logs=[_LOG])
        _run(client.get_logs(address=_ADDR, topics=[_CLAIMED_TOPIC]))
        assert node.asked("get_logs")[0][0][0]["topics"] == [_CLAIMED_TOPIC]

    def test_topics_are_OMITTED_entirely_when_not_given(self) -> None:
        # Not sent as `"topics": null`. Nodes differ on what they do with an explicit null, and
        # the difference between "no topic filter" and "a null filter" is the difference between
        # seeing every event this contract emitted and seeing an implementation-defined subset.
        client, node = _client(get_logs=[_LOG])
        _run(client.get_logs(address=_ADDR))
        assert "topics" not in node.asked("get_logs")[0][0][0]

    def test_an_empty_result_is_an_answer_not_an_error(self) -> None:
        # "no Claimed(p) yet" is what a watchtower sees on every poll but the last one.
        client, _ = _client(get_logs=[])
        assert _run(client.get_logs(address=_ADDR)) == []

    def test_a_handful_of_entries_passes_through_well_under_the_cap(self) -> None:
        client, _ = _client(get_logs=[_LOG, _LOG, _LOG])
        assert len(_run(client.get_logs(address=_ADDR))) == 3

    def test_EXACTLY_the_cap_is_still_served(self) -> None:
        client, _ = _client(get_logs=[_LOG] * 10_000)
        assert len(_run(client.get_logs(address=_ADDR))) == 10_000

    def test_one_entry_over_the_cap_is_refused(self) -> None:
        # A per-contract query yields a handful; ten thousand and one is an endpoint trying to
        # make the tower allocate. Refusing is safe — the tower retries — where an OOM is not.
        client, _ = _client(get_logs=[_LOG] * 10_001)
        with pytest.raises(NetworkError):
            _run(client.get_logs(address=_ADDR))

    def test_a_transport_failure_is_a_NetworkError_and_NOT_an_empty_result(self) -> None:
        # An empty list means "no claim happened". A dead endpoint must not be able to say that.
        client, _ = _client(get_logs=ConnectionError("endpoint down"))
        with pytest.raises(NetworkError):
            _run(client.get_logs(address=_ADDR))

    def test_the_filter_arguments_are_all_keyword_only(self) -> None:
        # `get_logs(addr, topics, from, to)` would be four unlabelled values, two of which are
        # block bounds that are trivially swappable.
        client, _ = _client(get_logs=[])
        with pytest.raises(TypeError):
            _run(client.get_logs(_ADDR))  # type: ignore[misc]


# --------------------------------------------------------------------------------------------
# The head-timestamp trio, and close()
# --------------------------------------------------------------------------------------------


class TestLatestBlockTimestamp:
    def test_all_three_accessors_coincide_on_a_single_source_client(self) -> None:
        # The names exist so `MultiSourceEthRpc` can aggregate the same read in three different
        # directions. One endpoint has one answer, so here they must agree — a leg that reads
        # the "min" variant has to keep working when it is handed this class.
        client, node = _client(get_block=lambda *a, **k: AttributeDict({"timestamp": 1_700_000_000}))
        assert _run(client.latest_block_timestamp()) == 1_700_000_000
        assert _run(client.latest_block_timestamp_quorum()) == 1_700_000_000
        assert _run(client.latest_block_timestamp_min()) == 1_700_000_000
        assert {a[0] for a, _k in node.asked("get_block")} == {"latest"}


class TestClose:
    def test_a_provider_session_is_disconnected(self) -> None:
        closed: list[bool] = []

        class _Provider:
            async def disconnect(self):
                closed.append(True)

        client, node = _client()
        node.provider = _Provider()  # type: ignore[attr-defined]
        _run(client.close())
        assert closed == [True]

    def test_a_provider_with_nothing_to_close_is_left_alone(self) -> None:
        class _Provider:
            pass

        client, node = _client()
        node.provider = _Provider()  # type: ignore[attr-defined]
        assert _run(client.close()) is None

    def test_a_failing_disconnect_does_not_raise_out_of_close(self) -> None:
        # Best-effort cleanup. A swap that has just claimed must not have its teardown turn into
        # an exception that loses the result.
        class _Provider:
            async def disconnect(self):
                raise ConnectionResetError("connection already gone")

        client, node = _client()
        node.provider = _Provider()  # type: ignore[attr-defined]
        assert _run(client.close()) is None


# --------------------------------------------------------------------------------------------
# The two response bounds, pinned to what they claim to be
# --------------------------------------------------------------------------------------------


class TestResponseBounds:
    def test_the_byte_cap_is_the_SAME_10MB_the_BTC_client_uses(self) -> None:
        # The module says "matching the BTC client". This asserts that relationship rather than
        # a magic number, so the two cannot drift apart silently.
        assert rpc_mod._MAX_RESPONSE_BYTES == btc_client._MAX_RESPONSE_BYTES
        assert rpc_mod._MAX_RESPONSE_BYTES == 10 * 1024 * 1024

    def test_the_log_entry_cap_is_ten_thousand(self) -> None:
        # Four orders of magnitude above the handful a per-contract query returns, so it cannot
        # refuse honest work, and small enough to bound the allocation.
        assert rpc_mod._MAX_LOG_ENTRIES == 10_000
