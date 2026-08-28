"""A broadcast claim is not a successful claim.

`send_raw` and a Flashbots `submit_raw` both return on SUBMISSION — no receipt, no status. The
claim path returned that hash as success, so a transaction that REVERTED was reported as a
completed claim: the coordinator advanced to SECRET_REVEALED, zeroized the preimage and persisted.

The failure mode is the worst one available. A reverted claim is still MINED with `p` in its
calldata — this codebase's own `fetch_claim_artifacts` scrapes `p` from exactly such a
transaction — so the secret is public, the counterparty can take the other leg, this side
collected nothing, and its own state machine believes the swap succeeded.

The claim deadline guard removes the most likely cause (no inclusion head-room). It does not
remove the class: a fee spike, a reorg, an unexpected revert or a gas underestimate all still land
here. Confirmation is the other half of that fix.
"""

from __future__ import annotations

import asyncio
import json
import os
import pathlib
import time

import pytest

pytest.importorskip("web3", reason="needs the eth extra: pip install 'pyrxd[eth]'")

from pyrxd.eth_wallet.htlc_leg import EthHtlcContractLeg
from pyrxd.eth_wallet.locator import EthHtlcLocator
from pyrxd.security.errors import ClaimNotConfirmed, NetworkError, ValidationError
from pyrxd.security.secrets import PrivateKeyMaterial

_ART = json.loads((pathlib.Path(__file__).parent / "fixtures" / "EthHtlc.json").read_text())
_CONTRACT = "0x" + "11" * 20
_P = b"\x11" * 32


def _locator() -> EthHtlcLocator:
    return EthHtlcLocator(
        chain_id=1,
        contract_address=_CONTRACT,
        deploy_tx_hash="0x" + "22" * 32,
        hashlock="0x" + "33" * 32,
        claimant="0x" + "44" * 20,
        refundee="0x" + "55" * 20,
        timeout=int(time.time()) + 86_400,
        amount_wei=10**15,
    )


def _leg(receipt, *, sent: list):
    """`receipt` is the dict wait_receipt returns, or an Exception to raise."""

    class _Fn:
        async def build_transaction(self, tx):
            return dict(tx)

    class _Fns:
        def claim(self, *a, **k):
            return _Fn()

    class _Contract:
        functions = _Fns()

    class _Eth:
        def contract(self, *a, **k):
            return _Contract()

        async def get_block(self, _w):
            return {"timestamp": int(time.time())}

    class _W3:
        eth = _Eth()

    class _Rpc:
        w3 = _W3()

        # The write path is a SEPARATE accessor: a multi-source RPC has no single `w3` to
        # sign against, so `w3` raises there and `write_w3` returns the primary's. One
        # source means they are the same object here.
        write_w3 = w3

        async def latest_block_timestamp(self):
            # The deadline guard reads the LATEST head any endpoint admits to; the staleness abort
            # reads the QUORUM-th. One source has one answer, so all three coincide here. `claim`
            # used to reach through `w3.eth.get_block` directly, which a multi-source RPC cannot serve.
            return int((await self.w3.eth.get_block("latest"))["timestamp"])

        async def latest_block_timestamp_quorum(self):
            return await self.latest_block_timestamp()

        async def latest_block_timestamp_min(self):
            return await self.latest_block_timestamp()

        async def assert_chain(self):
            return None

        async def wait_receipt(self, tx_hash, **_k):
            if isinstance(receipt, Exception):
                raise receipt
            return receipt

    leg = EthHtlcContractLeg(rpc=_Rpc(), signing_key=PrivateKeyMaterial(os.urandom(32)), chain_id=1, artifact=_ART)

    async def _base_tx(*a, **k):
        return {}

    async def _sign_and_send(*a, **k):
        sent.append(True)
        return "0x" + "ab" * 32

    leg._base_tx = _base_tx
    leg._sign_and_send = _sign_and_send
    return leg


def _good_receipt() -> dict:
    return {"status": 1, "logs": [{"address": _CONTRACT, "topics": [], "data": "0x" + _P.hex()}]}


class TestASubmittedClaimIsNotASuccessfulClaim:
    def test_a_REVERTED_claim_is_not_reported_as_success(self) -> None:
        """status == 0. The tx mined, so `p` is public — but nothing was collected."""
        sent: list = []
        leg = _leg({"status": 0, "logs": []}, sent=sent)
        with pytest.raises(ClaimNotConfirmed):
            asyncio.run(leg.claim(_locator(), _P))
        assert sent == [True], "the tx really was broadcast; this is a post-reveal failure"

    def test_a_claim_with_NO_Claimed_log_is_not_reported_as_success(self) -> None:
        """status == 1 but our contract emitted nothing — not our claim, or not a claim at all."""
        leg = _leg({"status": 1, "logs": []}, sent=[])
        with pytest.raises(ClaimNotConfirmed):
            asyncio.run(leg.claim(_locator(), _P))

    def test_a_Claimed_log_from_ANOTHER_contract_does_not_count(self) -> None:
        """A cross-swap claim reusing the same H emits from a DIFFERENT per-swap contract."""
        other = {"status": 1, "logs": [{"address": "0x" + "99" * 20, "topics": [], "data": "0x" + _P.hex()}]}
        leg = _leg(other, sent=[])
        with pytest.raises(ClaimNotConfirmed):
            asyncio.run(leg.claim(_locator(), _P))

    def test_an_UNCONFIRMED_claim_is_not_reported_as_success(self) -> None:
        """No receipt before the deadline. The outcome is unknown, which is not success — and on
        the private path a dropped bundle looks exactly like this."""
        leg = _leg(NetworkError("wait_for_transaction_receipt failed: timeout"), sent=[])
        with pytest.raises(ClaimNotConfirmed):
            asyncio.run(leg.claim(_locator(), _P))

    def test_the_failure_carries_the_TX_HASH(self) -> None:
        """The only handle an operator has on a claim that may be public but did not pay. Without
        it there is nothing to investigate, and the swap cannot be resolved by hand."""
        leg = _leg({"status": 0, "logs": []}, sent=[])
        with pytest.raises(ClaimNotConfirmed) as ei:
            asyncio.run(leg.claim(_locator(), _P))
        assert ei.value.tx_hash == "0x" + "ab" * 32

    def test_a_GENUINELY_successful_claim_still_returns_its_hash(self) -> None:
        """The honest path. A guard that refuses valid work is a bug: a real claim — status 1 with
        a Claimed(p) log from this swap's own contract — must still succeed and return the hash."""
        sent: list = []
        leg = _leg(_good_receipt(), sent=sent)
        assert asyncio.run(leg.claim(_locator(), _P)) == "0x" + "ab" * 32
        assert sent == [True]


# ---------------------------------------------------------------------------------------------
# The confirmation must not rest on the one endpoint that could have fabricated it.
#
# `wait_receipt` forwards to `self.primary` — correctly, it is a liveness signal about one node's
# view — and `assert_claim_provenance` used it as the EVIDENCE. By the time that gate runs `p` is
# already public in the claim calldata, so a hostile or MITM'd primary composes `status: 1` plus a
# `Claimed(p)` log from our own contract address at no cost, and the gate written to stop
# "submitted != succeeded" accepts it. The maker advances to SECRET_REVEALED believing it
# collected, stops pursuing, and the counterparty takes the other leg with the public preimage.
#
# The quorum'd `get_transaction_receipt` existed for exactly this question — did it succeed, and in
# which block — and was called zero times on this path.
# ---------------------------------------------------------------------------------------------

_CLAIMED_SELECTOR = "0x" + "cc" * 32


def _mined_receipt(*, status=1, logs=None, block=4_242_000, block_hash=b"\xaa" * 32) -> dict:
    """A receipt shaped like one a real node returns for a mined claim."""
    return {
        "status": status,
        "blockNumber": block,
        "blockHash": block_hash,
        "logs": [] if logs is None else logs,
    }


def _claimed_log(p: bytes = _P, address: str = _CONTRACT) -> dict:
    """`Claimed(bytes32 preimage)` — the preimage is NOT indexed, so it rides in the log data."""
    return {"address": address, "topics": [_CLAIMED_SELECTOR], "data": "0x" + p.hex()}


class _Source:
    """One endpoint. `receipts` is the sequence of answers `get_transaction_receipt` gives, so a
    source can be BEHIND for a poll or two before catching up — which is what a real second
    provider does, and what the retry loop has to tolerate."""

    def __init__(self, *, waited: dict, receipts: list) -> None:
        self._waited = waited
        self._receipts = list(receipts)
        self.receipt_calls = 0

        class _Fn:
            async def build_transaction(self, tx):
                return dict(tx)

        class _Fns:
            def claim(self, *a, **k):
                return _Fn()

        class _Eth:
            def contract(self, *a, **k):
                class _C:
                    functions = _Fns()

                return _C()

            async def get_block(self, _w):
                return {"timestamp": int(time.time())}

        class _W3:
            eth = _Eth()

        self.w3 = _W3()

    async def assert_chain(self):
        return None

    async def latest_block_timestamp(self):
        return int((await self.w3.eth.get_block("latest"))["timestamp"])

    async def wait_receipt(self, tx_hash, **_k):
        return self._waited

    async def get_transaction_receipt(self, tx_hash):
        self.receipt_calls += 1
        return self._receipts[min(self.receipt_calls - 1, len(self._receipts) - 1)]


def _multi_leg(sources, *, sent: list):
    from pyrxd.eth_wallet.multi_rpc import MultiSourceEthRpc

    rpc = MultiSourceEthRpc(sources)
    leg = EthHtlcContractLeg(rpc=rpc, signing_key=PrivateKeyMaterial(os.urandom(32)), chain_id=1, artifact=_ART)

    async def _base_tx(*a, **k):
        return {}

    async def _sign_and_send(*a, **k):
        sent.append(True)
        return "0x" + "ab" * 32

    leg._base_tx = _base_tx
    leg._sign_and_send = _sign_and_send
    return leg


@pytest.fixture(autouse=True)
def _no_quorum_backoff(monkeypatch):
    """The propagation window is 60s in production and irrelevant to what these assert. A test that
    cares about the WAIT sets it back itself."""
    monkeypatch.setattr("pyrxd.eth_wallet.htlc_leg.CLAIM_RECEIPT_QUORUM_WAIT_S", 0.0)
    monkeypatch.setattr("pyrxd.eth_wallet.htlc_leg.CLAIM_RECEIPT_QUORUM_POLL_S", 0.0)


class TestOneEndpointCannotConfirmAClaimByItself:
    def test_a_primary_that_fabricates_SUCCESS_over_a_reverted_claim_is_refused(self) -> None:
        """The claim mined and REVERTED — so `p` is public and nothing was collected. The primary
        reports status 1 with a Claimed(p) log; the honest endpoints report the revert. A reverted
        claim emits no logs, which is why the two stories cannot both be true."""
        liar = _Source(
            waited=_mined_receipt(logs=[_claimed_log()]),
            receipts=[_mined_receipt(logs=[_claimed_log()])],
        )
        honest = [_Source(waited=_mined_receipt(status=0), receipts=[_mined_receipt(status=0)]) for _ in range(2)]
        sent: list = []
        leg = _multi_leg([liar, *honest], sent=sent)
        with pytest.raises(ClaimNotConfirmed):
            asyncio.run(leg.claim(_locator(), _P))
        assert sent == [True], "the tx really was broadcast; this is a post-reveal failure"

    def test_a_primary_that_invents_a_receipt_for_a_tx_NOBODY_ELSE_HAS_is_refused(self) -> None:
        """The lazier attack: never broadcast the claim at all, then answer for it. No other
        endpoint has ever seen the hash, so their honest answer is `None`."""
        liar = _Source(
            waited=_mined_receipt(logs=[_claimed_log()]),
            receipts=[_mined_receipt(logs=[_claimed_log()])],
        )
        honest = [_Source(waited=_mined_receipt(), receipts=[None]) for _ in range(2)]
        leg = _multi_leg([liar, *honest], sent=[])
        with pytest.raises(ClaimNotConfirmed):
            asyncio.run(leg.claim(_locator(), _P))

    def test_a_primary_that_fabricates_ONLY_THE_LOG_is_refused(self) -> None:
        """The subtle one, and the reason this read agrees on the logs and not only on
        status/blockNumber/blockHash.

        `send_raw` returns a hash the PRIMARY chose. Point it at some other transaction that really
        did succeed in that block and every endpoint agrees it succeeded — status, block number and
        block hash all corroborate. The only thing separating that from our claim is the
        `Claimed(p)` event from our per-swap contract, which is exactly the field a receipt quorum
        that compares 'did it succeed, and where' leaves single-source.
        """
        real_other_tx = _mined_receipt(logs=[{"address": "0x" + "99" * 20, "topics": [], "data": "0x"}])
        liar = _Source(
            waited=_mined_receipt(logs=[_claimed_log()]),
            receipts=[_mined_receipt(logs=[_claimed_log()])],
        )
        honest = [_Source(waited=real_other_tx, receipts=[real_other_tx]) for _ in range(2)]
        leg = _multi_leg([liar, *honest], sent=[])
        with pytest.raises(ClaimNotConfirmed):
            asyncio.run(leg.claim(_locator(), _P))

    def test_a_REAL_claim_that_every_endpoint_corroborates_still_succeeds(self) -> None:
        """The honest-path pair for all three refusals above. A quorum that cannot confirm a
        genuine claim is a worse failure than the single-source read it replaced: the maker holds a
        public preimage, has been paid, and is told it has not."""
        good = _mined_receipt(logs=[_claimed_log()])
        sources = [_Source(waited=good, receipts=[good]) for _ in range(3)]
        sent: list = []
        leg = _multi_leg(sources, sent=sent)
        assert asyncio.run(leg.claim(_locator(), _P)) == "0x" + "ab" * 32
        assert sent == [True]
        assert all(s.receipt_calls == 1 for s in sources), "every endpoint must be asked, not just the primary"

    def test_endpoints_differing_only_in_FORMATTING_still_corroborate(self) -> None:
        """Providers are not byte-identical: addresses come back in EIP-55 case or lowercase, topics
        and data as `HexBytes` or as '0x' strings, block numbers as ints or hex, and log ORDER is a
        client artifact. Every one of those is an honest difference, and refusing on one would take
        a working swap down."""
        p_hex = _P.hex()
        a = _mined_receipt(
            block=4_242_000,
            logs=[
                {"address": _CONTRACT.upper().replace("0X", "0x"), "topics": [_CLAIMED_SELECTOR], "data": "0x" + p_hex},
                {"address": "0x" + "99" * 20, "topics": [], "data": "0x"},
            ],
        )
        b = _mined_receipt(
            block="0x40ba50",  # 4_242_000 in hex, as a raw JSON-RPC node reports it
            logs=[
                {"address": "0x" + "99" * 20, "topics": [], "data": b""},
                {"address": _CONTRACT.lower(), "topics": [bytes.fromhex(_CLAIMED_SELECTOR[2:])], "data": _P},
            ],
        )
        assert int("0x40ba50", 16) == 4_242_000, "the hex fixture must be the same height, not a different one"
        leg = _multi_leg([_Source(waited=a, receipts=[a]), _Source(waited=b, receipts=[b])], sent=[])
        assert asyncio.run(leg.claim(_locator(), _P)) == "0x" + "ab" * 32

    def test_an_endpoint_that_is_merely_BEHIND_is_waited_for(self, monkeypatch) -> None:
        """Propagation is not an attack. The primary can see a mined tx a beat before its peers,
        and failing closed on the first poll would refuse a claim that is simply young."""
        monkeypatch.setattr("pyrxd.eth_wallet.htlc_leg.CLAIM_RECEIPT_QUORUM_WAIT_S", 5.0)
        good = _mined_receipt(logs=[_claimed_log()])
        primary = _Source(waited=good, receipts=[good])
        lagging = _Source(waited=good, receipts=[None, None, good])
        leg = _multi_leg([primary, lagging], sent=[])
        assert asyncio.run(leg.claim(_locator(), _P)) == "0x" + "ab" * 32
        assert lagging.receipt_calls == 3, "the lagging endpoint was not re-asked"

    def test_an_endpoint_that_never_catches_up_ends_as_UNCONFIRMED(self) -> None:
        """The bound on the tolerance above. 'We could not get a quorum' is not success and not
        failure — it is unknown, and unknown must not advance the swap."""
        good = _mined_receipt(logs=[_claimed_log()])
        leg = _multi_leg([_Source(waited=good, receipts=[good]), _Source(waited=good, receipts=[None])], sent=[])
        with pytest.raises(ClaimNotConfirmed, match="could not be confirmed"):
            asyncio.run(leg.claim(_locator(), _P))

    def test_a_SINGLE_SOURCE_rpc_still_confirms_a_real_claim(self) -> None:
        """There is nothing to corroborate with, and pretending otherwise would break every
        single-endpoint operator. `EthRpc` has no quorum, so the waited receipt stands — honestly
        single-source, which is what it always was."""
        leg = _leg(_good_receipt(), sent=[])
        assert asyncio.run(leg.claim(_locator(), _P)) == "0x" + "ab" * 32


# ---------------------------------------------------------------------------------------------
# The exception taxonomy at the secrecy boundary.
# ---------------------------------------------------------------------------------------------


def _leg_with_preflight(reverts: bool, *, sends: list):
    """A leg whose REAL `_sign_and_send` runs — so the preflight is the real one, and the failure
    surfaces from the production path rather than from a stub raising what the test chose."""

    class _Fn:
        async def build_transaction(self, tx):
            return dict(tx)

    class _Fns:
        def claim(self, *a, **k):
            return _Fn()

    class _Eth:
        def contract(self, *a, **k):
            class _C:
                functions = _Fns()

            return _C()

        async def get_block(self, _w):
            return {"timestamp": int(time.time())}

    class _W3:
        eth = _Eth()

    class _Rpc:
        w3 = _W3()
        write_w3 = w3

        async def assert_chain(self):
            return None

        async def latest_block_timestamp(self):
            return int((await self.w3.eth.get_block("latest"))["timestamp"])

        async def latest_block_timestamp_quorum(self):
            return await self.latest_block_timestamp()

        async def latest_block_timestamp_min(self):
            return await self.latest_block_timestamp()

        async def fee_fields(self):
            return {"maxPriorityFeePerGas": 1, "maxFeePerGas": 3}

        async def get_transaction_count(self, _a, block="pending"):
            return 0

        async def preflight(self, tx):
            # What a node really answers for `claim(wrong_preimage)` against a funded HTLC: the
            # `eth_call` reverts, and `EthRpc.preflight` types that as a ValidationError.
            if reverts:
                raise ValidationError("tx would revert (preflight eth_call): execution reverted")

        async def send_raw(self, raw):
            sends.append(bytes(raw))
            return "0x" + "ab" * 32

        async def wait_receipt(self, tx_hash, **_k):
            return _good_receipt()

    return EthHtlcContractLeg(rpc=_Rpc(), signing_key=PrivateKeyMaterial(os.urandom(32)), chain_id=1, artifact=_ART)


class TestAFailureAtTheSubmitIsReportedAsPastTheBoundary:
    """`claim`'s own comment says failures past `_sign_and_send` are NOT `PreRevealAbort`, and
    `ClaimNotConfirmed` documents itself as "the exact inverse". But the call sat outside every
    `try` in BOTH directions, so the most likely failure there — a preflight revert — came out as a
    bare `ValidationError`: neither marker, and no guidance.

    Nothing moves across the boundary here. The preflight always was on the public side: it sends
    the claim calldata, which CONTAINS `p`, to the provider. What changes is that the exception now
    says so, at the one moment an operator needs to be told the secret is out.
    """

    def test_a_reverting_preflight_is_a_ClaimNotConfirmed(self) -> None:
        sends: list = []
        leg = _leg_with_preflight(True, sends=sends)
        with pytest.raises(ClaimNotConfirmed) as ei:
            asyncio.run(leg.claim(_locator(), _P))
        assert sends == [], "nothing was broadcast — but the preflight already carried p to the provider"
        assert "PUBLIC" in str(ei.value)

    def test_it_is_NOT_reported_as_a_pre_reveal_abort(self) -> None:
        """The property that matters to the caller. `SwapCoordinator.maker_claims_btc` KEEPS the
        preimage on `PreRevealAbort`, on the promise that nothing left the process. Labelling a
        preflight revert that way would be a false promise about a secret already handed to an RPC."""
        from pyrxd.security.errors import PreRevealAbort

        leg = _leg_with_preflight(True, sends=[])
        with pytest.raises(ClaimNotConfirmed) as ei:
            asyncio.run(leg.claim(_locator(), _P))
        assert not isinstance(ei.value, PreRevealAbort)

    def test_the_HONEST_preflight_still_broadcasts_and_returns(self) -> None:
        """The pair. A preflight that passes must go on to send, confirm and return the hash —
        turning the taxonomy fix into a refusal would cost the swap."""
        sends: list = []
        leg = _leg_with_preflight(False, sends=sends)
        assert asyncio.run(leg.claim(_locator(), _P)) == "0x" + "ab" * 32
        assert len(sends) == 1, "the signed transaction never reached the node"
