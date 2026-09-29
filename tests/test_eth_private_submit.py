"""Tests for the optional private-inclusion (Flashbots) transport for the ETH claim.

The claim is the one tx that reveals p; an injected ``private_submitter`` keeps it off the public
mempool. We verify the routing (claim → submitter when present; public fallback when absent; only
the claim is private) with a fake submitter + fake rpc, and the FlashbotsSubmitter's input guards.
No real relay is contacted.
"""

from __future__ import annotations

import json
import time

import pytest

from pyrxd.eth_wallet.htlc_leg import EthHtlcContractLeg
from pyrxd.eth_wallet.locator import EthHtlcLocator
from pyrxd.eth_wallet.private_submit import FlashbotsSubmitter, PrivateSubmitter
from pyrxd.security.errors import NetworkError, ValidationError
from pyrxd.security.secrets import PrivateKeyMaterial

pytest.importorskip("web3")
pytest.importorskip("eth_account")

_ARTIFACT = {
    "abi": [{"type": "function", "name": "claim", "inputs": [{"type": "bytes32"}]}],
    "bytecode": "0x00",
    "runtime_bytecode": "0x00",
}


class _FakeSubmitter:
    """Records the raw tx it was handed and returns a sentinel private tx hash."""

    def __init__(self):
        self.calls: list[bytes] = []

    async def submit_raw(self, raw_tx: bytes) -> str:
        self.calls.append(bytes(raw_tx))
        return "0x" + "ab" * 32


class _FakeRpc:
    """Minimal rpc that records send_raw and serves the bits claim() touches."""

    def __init__(self):
        self.public_sends: list[bytes] = []

        class _W3Eth:
            async def get_block(self_inner, _which):
                # The claim path reads the clock to refuse a claim too close to the HTLC timeout —
                # a late claim still mines with the preimage in its calldata. Round 5 additionally
                # cross-checks the head against LOCAL time (a lagging provider under-reports "now",
                # which is the direction that makes the guard pass when it should refuse), so this
                # must return a REALISTIC head rather than a synthetic epoch. These tests are about
                # private-submit ROUTING, so report now and let the locator sit a day out.
                return {"timestamp": int(time.time())}

            def contract(self_inner, address, abi):
                class _Fns:
                    def claim(self_fns, preimage):
                        class _Built:
                            async def build_transaction(self_b, base):
                                return {**base, "to": address, "data": "0x"}

                        return _Built()

                class _C:
                    functions = _Fns()

                return _C()

        class _W3:
            eth = _W3Eth()

        self.w3 = _W3()
        self.write_w3 = self.w3

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

    async def wait_receipt(self, tx_hash, **_k):
        # `claim` CONFIRMS before reporting success (status == 1 + a Claimed(p) log from this
        # swap's own contract), so a routing test must serve a receipt or the honest path fails.
        # Routing is still what is under test: both paths reach here identically.
        return {
            "status": 1,
            "logs": [{"address": "0x" + "11" * 20, "topics": [], "data": "0x" + (b"\x01" * 32).hex()}],
        }

    async def assert_chain(self):
        return None

    async def preflight(self, tx):
        return None

    async def fee_fields(self):
        return {"maxFeePerGas": 1, "maxPriorityFeePerGas": 1}

    async def get_transaction_count(self, addr, block="pending"):
        return 0

    async def send_raw(self, raw_tx):
        self.public_sends.append(bytes(raw_tx))
        # A real node returns keccak OF THE BYTES IT WAS GIVEN. The canned "0xcdcd..." modelled a
        # node echoing a hash unrelated to what it broadcast, which cannot happen — and the leg now
        # checks it, because the hash is derivable from what we signed.
        from eth_utils import keccak

        return "0x" + keccak(bytes(raw_tx)).hex()


def _locator():
    return EthHtlcLocator(
        chain_id=11155111,
        contract_address="0x" + "11" * 20,
        deploy_tx_hash="0x" + "00" * 32,
        hashlock="0x" + "22" * 32,
        claimant="0x" + "33" * 20,
        refundee="0x" + "44" * 20,
        timeout=int(time.time()) + 86_400,
        amount_wei=10**14,
    )


def _leg(rpc, *, submitter=None):
    return EthHtlcContractLeg(
        rpc=rpc,
        signing_key=PrivateKeyMaterial.generate(),
        chain_id=11155111,
        artifact=_ARTIFACT,
        private_submitter=submitter,
    )


# ──────────────────────────────────────────────── routing ──


async def test_claim_routes_through_private_submitter_when_injected():
    rpc, sub = _FakeRpc(), _FakeSubmitter()
    leg = _leg(rpc, submitter=sub)
    tx_hash = await leg.claim(_locator(), b"\x01" * 32)
    assert tx_hash == "0x" + "ab" * 32  # came from the private submitter
    assert len(sub.calls) == 1  # the claim went private
    assert rpc.public_sends == []  # NOT the public mempool


async def test_claim_falls_back_to_public_when_no_submitter():
    rpc = _FakeRpc()
    leg = _leg(rpc, submitter=None)
    tx_hash = await leg.claim(_locator(), b"\x01" * 32)
    from eth_utils import keccak

    assert tx_hash == "0x" + keccak(rpc.public_sends[0]).hex()  # public send_raw, hash of our bytes
    assert len(rpc.public_sends) == 1


async def test_ctor_rejects_bad_submitter():
    with pytest.raises(ValidationError, match="submit_raw"):
        EthHtlcContractLeg(
            rpc=_FakeRpc(),
            signing_key=PrivateKeyMaterial.generate(),
            chain_id=11155111,
            artifact=_ARTIFACT,
            private_submitter=object(),  # no submit_raw
        )


def test_fake_submitter_satisfies_protocol():
    assert isinstance(_FakeSubmitter(), PrivateSubmitter)


# ──────────────────────────────────────────────── FlashbotsSubmitter guards ──


def test_flashbots_submitter_validates_inputs():
    key = PrivateKeyMaterial.generate()
    with pytest.raises(ValidationError, match="relay_url"):
        FlashbotsSubmitter(relay_url="ftp://bad", auth_key=key)
    with pytest.raises(ValidationError, match="auth_key"):
        FlashbotsSubmitter(relay_url="https://rpc.flashbots.net/fast", auth_key=object())  # type: ignore[arg-type]
    with pytest.raises(ValidationError, match="timeout_s"):
        FlashbotsSubmitter(relay_url="https://rpc.flashbots.net/fast", auth_key=key, timeout_s=0)


async def test_flashbots_submitter_rejects_empty_raw():
    s = FlashbotsSubmitter(relay_url="https://rpc.flashbots.net/fast", auth_key=PrivateKeyMaterial.generate())
    with pytest.raises(ValidationError, match="raw_tx"):
        await s.submit_raw(b"")


def test_flashbots_submitter_builds_auth_header():
    # The X-Flashbots-Signature header is "<addr>:0x<sig>" — verify it forms without a relay call.
    s = FlashbotsSubmitter(relay_url="https://rpc.flashbots.net/fast", auth_key=PrivateKeyMaterial.generate())
    header = s._sign_header('{"jsonrpc":"2.0"}')
    addr, _, sig = header.partition(":")
    assert addr.startswith("0x") and len(addr) == 42
    assert sig.startswith("0x") and len(sig) == 132  # 65-byte sig hex


# ──────────────────────────────────────────────── FlashbotsSubmitter.submit_raw over a fake relay ──
#
# Everything above stops at the input guards: until these tests, the HTTP half of submit_raw — the
# request it builds, the auth header a relay checks, and every reason it must refuse a relay's
# answer — ran under no test at all (mutation run 2026-09-29: private_submit 54/154 killed). The
# relay is replaced at `aiohttp.ClientSession`, so the module's own `_require_aiohttp` and the real
# `aiohttp.ClientTimeout` still run and nothing leaves the process.

_RELAY = "https://relay.example/fast"
# Any non-empty bytes: the submitter never parses the tx, it only hex-encodes it and binds the
# relay's returned hash to keccak256 of exactly these bytes.
_RAW = bytes.fromhex("02f86c0101") + b"\x5a" * 40


def _keccak_hex(data: bytes) -> str:
    from eth_utils import keccak

    return "0x" + keccak(data).hex()


class _FakeContent:
    def __init__(self, body: bytes):
        self._body = body
        self.read_sizes: list[int] = []

    async def read(self, n: int = -1) -> bytes:
        # aiohttp's StreamReader.read(n) returns AT MOST n bytes — the submitter's size cap relies
        # on asking for one byte more than it accepts, so the fake must honour n.
        self.read_sizes.append(n)
        return self._body if n < 0 else self._body[:n]


class _FakeResponse:
    def __init__(self, status: int, body: bytes):
        self.status = status
        self.content = _FakeContent(body)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


class _Relay:
    """Stands in for aiohttp.ClientSession; records the one POST and serves a canned answer."""

    def __init__(self, *, status: int = 200, body: bytes | None = None, raise_exc: Exception | None = None):
        self.status = status
        self.body = body
        self.raise_exc = raise_exc
        self.posts: list[tuple[str, str, dict]] = []
        self.timeouts: list = []

    def session_factory(self, *, timeout=None, **_kw):
        relay = self
        relay.timeouts.append(timeout)

        class _Session:
            async def __aenter__(self_s):
                return self_s

            async def __aexit__(self_s, *exc):
                return False

            def post(self_s, url, *, data, headers):
                relay.posts.append((url, data, headers))
                if relay.raise_exc is not None:
                    raise relay.raise_exc
                return _FakeResponse(relay.status, relay.body)

        return _Session()


def _ok_body(result) -> bytes:
    return json.dumps({"jsonrpc": "2.0", "id": 1, "result": result}).encode()


@pytest.fixture
def relay(monkeypatch):
    def install(**kw) -> _Relay:
        r = _Relay(**kw)
        import aiohttp

        monkeypatch.setattr(aiohttp, "ClientSession", r.session_factory)
        return r

    return install


def _submitter(key=None, **kw) -> FlashbotsSubmitter:
    return FlashbotsSubmitter(relay_url=_RELAY, auth_key=key or PrivateKeyMaterial.generate(), **kw)


async def test_submit_raw_posts_the_private_rpc_request_and_returns_the_bound_hash(relay):
    r = relay(body=_ok_body(_keccak_hex(_RAW)))
    s = _submitter(timeout_s=7)
    assert await s.submit_raw(_RAW) == _keccak_hex(_RAW)

    assert len(r.posts) == 1
    url, data, headers = r.posts[0]
    assert url == _RELAY
    # The one method a Flashbots-style relay keeps private; eth_sendRawTransaction would publish p.
    assert json.loads(data) == {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_sendPrivateRawTransaction",
        "params": ["0x" + _RAW.hex()],
    }
    assert headers["Content-Type"] == "application/json"
    assert r.timeouts[0].total == 7.0


async def test_submit_raw_accepts_a_bytearray_and_an_upper_case_hash(relay):
    # Honest-path pair for the hash-binding refusal below: case is not a mismatch.
    relay(body=_ok_body(_keccak_hex(_RAW).upper().replace("0X", "0x")))
    got = await _submitter().submit_raw(bytearray(_RAW))
    assert got.lower() == _keccak_hex(_RAW)


async def test_auth_header_is_the_auth_key_signing_the_prefixed_keccak_of_the_exact_body(relay):
    """Flashbots verifies `<addr>:<sig>` where sig = personal_sign("0x" + keccak(body).hex()).

    Signing the UNPREFIXED hex (what this web3's `.hex()` returns) or any other body makes a real
    relay reject every private claim — the defense silently turns off. Recover the signer here.
    """
    from eth_account import Account
    from eth_account.messages import encode_defunct
    from eth_utils import keccak

    from pyrxd.eth_wallet.keys import derive_address

    key = PrivateKeyMaterial.generate()
    r = relay(body=_ok_body(_keccak_hex(_RAW)))
    await _submitter(key).submit_raw(_RAW)
    _url, data, headers = r.posts[0]
    addr, sep, sig = headers["X-Flashbots-Signature"].partition(":")
    assert sep == ":"
    assert addr == derive_address(key)
    assert sig.startswith("0x") and len(sig) == 132
    message = encode_defunct(text="0x" + keccak(text=data).hex())
    assert Account.recover_message(message, signature=sig) == addr


@pytest.mark.parametrize("wrong", ["0x" + "00" * 32, "0x" + "ff" * 32])
async def test_submit_raw_refuses_a_hash_that_is_not_keccak_of_the_bytes(relay, wrong):
    # Both orderings: a mismatch is a mismatch whichever way the wrong hash sorts.
    relay(body=_ok_body(wrong))
    with pytest.raises(NetworkError, match=r"!= keccak256\(raw_tx\)"):
        await _submitter().submit_raw(_RAW)


@pytest.mark.parametrize(
    "result",
    [None, 123, "", "ab" * 32],  # missing, not a string, empty, unprefixed
)
async def test_submit_raw_refuses_a_response_without_a_0x_hash(relay, result):
    relay(body=_ok_body(result) if result is not None else json.dumps({"jsonrpc": "2.0", "id": 1}).encode())
    with pytest.raises(NetworkError, match="no tx hash"):
        await _submitter().submit_raw(_RAW)


async def test_submit_raw_refuses_a_relay_error_even_alongside_a_result(relay):
    # A JSON-RPC error is a refusal, whatever else the body carries.
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "error": {"code": -32000}, "result": _keccak_hex(_RAW)})
    relay(body=body.encode())
    with pytest.raises(NetworkError, match="flashbots relay error"):
        await _submitter().submit_raw(_RAW)


async def test_submit_raw_refuses_non_json(relay):
    relay(body=b"<html>bad gateway</html>")
    with pytest.raises(NetworkError, match="non-JSON"):
        await _submitter().submit_raw(_RAW)


@pytest.mark.parametrize("status", [201, 400, 500, 503])
async def test_submit_raw_refuses_any_non_200_even_with_a_valid_body(relay, status):
    # The body is a CORRECT answer, so only the status check stands between it and a false reveal.
    relay(status=status, body=_ok_body(_keccak_hex(_RAW)))
    with pytest.raises(NetworkError, match=f"HTTP {status}"):
        await _submitter().submit_raw(_RAW)


async def test_submit_raw_size_cap_is_exactly_64_kib(relay):
    from pyrxd.eth_wallet import private_submit as ps

    assert ps._MAX_RESP_BYTES == 65536
    good = _ok_body(_keccak_hex(_RAW))
    # Pad with JSON whitespace so the body stays VALID: only the cap can refuse it.
    at_cap = good + b" " * (65536 - len(good))
    over_cap = at_cap + b" "

    relay(body=at_cap)
    assert await _submitter().submit_raw(_RAW) == _keccak_hex(_RAW)

    r = relay(body=over_cap)
    with pytest.raises(NetworkError) as ei:
        await _submitter().submit_raw(_RAW)
    # Raised as-is, not re-wrapped by the generic transport handler.
    assert str(ei.value) == "flashbots response exceeds size cap"
    assert ei.value.__cause__ is None
    assert r.posts  # it did reach the relay


async def test_submit_raw_wraps_a_transport_failure_as_network_error(relay):
    boom = OSError("connection reset")
    relay(raise_exc=boom)
    with pytest.raises(NetworkError, match="private submit failed: connection reset") as ei:
        await _submitter().submit_raw(_RAW)
    assert ei.value.__cause__ is boom


def test_flashbots_submitter_accepts_plain_http_and_an_int_timeout():
    # Honest-path pair for the ctor refusals above (a local relay is http; timeouts are often ints).
    s = FlashbotsSubmitter(relay_url="http://127.0.0.1:8545", auth_key=PrivateKeyMaterial.generate(), timeout_s=3)
    assert s._timeout_s == 3.0 and isinstance(s._timeout_s, float)
    sub_second = FlashbotsSubmitter(relay_url=_RELAY, auth_key=PrivateKeyMaterial.generate(), timeout_s=0.5)
    assert sub_second._timeout_s == 0.5
    with pytest.raises(ValidationError, match="timeout_s"):
        FlashbotsSubmitter(relay_url=_RELAY, auth_key=PrivateKeyMaterial.generate(), timeout_s=-1)
    with pytest.raises(ValidationError, match="timeout_s"):
        FlashbotsSubmitter(relay_url=_RELAY, auth_key=PrivateKeyMaterial.generate(), timeout_s="5")  # type: ignore[arg-type]
