"""Boundaries of the native-ETH HTLC leg (`eth_wallet/htlc_leg.py`) that no test pinned.

Every test here kills a mutant the 2026-09-29 `ethleg` mutation run showed surviving the whole
group's test list. They are grouped by the decision they protect, and each is a BEHAVIOUR of the
leg — when it lets a claim, a refund or a "funded"/"final" verdict through — not a restatement of
the source:

* the claim deadline and staleness guards at their exact edges (a claim that mines late publishes
  ``p`` for nothing), and the fee ceiling the claim is priced at;
* refund maturity at ``now == timeout``;
* ``is_final`` / ``claim_finality_verdict`` at ``block == finalized``;
* ``verify_funded`` tolerating over-funding, checking BOTH recipients, and reading every immutable
  at the pinned checkpoint;
* the claim-artifact size caps and the provenance scan's skip-don't-stop rules;
* the CREATE-address derivation, differentially against the ``rlp`` package.

No network: every RPC is a local fake, and time is pinned where a guard reads the clock.
"""

from __future__ import annotations

import hashlib
import os
import types

import pytest

from pyrxd.eth_wallet import htlc_leg as hl
from pyrxd.eth_wallet.htlc_leg import (
    CLAIM_BASEFEE_HEADROOM,
    CLAIM_INCLUSION_BUDGET_S,
    EthHtlcContractLeg,
    _b,
    _int_or_none,
    create_address,
    is_eip7702_delegation,
)
from pyrxd.eth_wallet.locator import EthHtlcLocator
from pyrxd.gravity.finality import CounterClaimState
from pyrxd.security.errors import NetworkError, PreRevealAbort, PreRevealExpired, ValidationError
from pyrxd.security.secrets import PrivateKeyMaterial

pytest.importorskip("web3")
pytest.importorskip("eth_account")

#: The smallest immutable layout the leg's constructor accepts (one 32-byte slot). These tests are
#: about other things; the layout checks themselves live in test_eth_leg.py.
_ART = {
    "abi": [{"type": "function", "name": "claim", "inputs": [{"type": "bytes32"}]}],
    "bytecode": "0x00",
    "runtime_bytecode": "0x" + "00" * 32,
    "immutableReferences": {"1": [{"start": 0, "length": 32}]},
    "immutable_names": {"1": "hashlock"},
}
_CONTRACT = "0x" + "11" * 20
#: Odd, with low bits set: the messages below state computed gaps ("96s before", "97s stale"), and
#: a round timestamp makes `deadline - now` coincide with `deadline ^ now`, hiding a wrong formula.
_NOW = 1_800_000_077


def _locator(*, timeout: int = _NOW + 86_400, amount_wei: int = 10**15) -> EthHtlcLocator:
    return EthHtlcLocator(
        chain_id=11155111,
        contract_address=_CONTRACT,
        deploy_tx_hash="0x" + "00" * 32,
        hashlock="0x" + "22" * 32,
        claimant="0x" + "33" * 20,
        refundee="0x" + "44" * 20,
        timeout=timeout,
        amount_wei=amount_wei,
    )


@pytest.fixture
def frozen_clock(monkeypatch):
    """Pin the leg's local clock. `claim` compares the chain head against `time.time()`, and a
    test that computes "96 s stale" from the real clock straddles a second boundary one run in N."""
    fake = types.SimpleNamespace(time=lambda: float(_NOW), monotonic=lambda: 0.0)
    monkeypatch.setattr(hl, "time", fake)
    return fake


async def _unsettled_storage(*_a, **_k) -> bytes:
    """`eth_getStorageAt` for an HTLC whose `settled` flag (slot 0) is clear — every honest one."""
    return b"\x00" * 32


class _Rpc:
    """A single-source EthRpc double for the claim/refund/send paths.

    Records the tx fields each call builds on and what was broadcast; serves a successful claim
    receipt carrying `p` from the swap's own contract, so the honest path confirms.
    """

    def __init__(self, *, head_ts: int = _NOW, max_fee: int = 40, tip: int = 2, echo=None, preimage=b"\x01" * 32):
        self.head_ts = head_ts
        self.fees = {"maxFeePerGas": max_fee, "maxPriorityFeePerGas": tip}
        self.echo = echo  # None = the honest keccak of what was sent
        self.built: list[dict] = []
        self.sent: list[bytes] = []
        self.preimage = preimage
        rpc = self

        class _Built:
            async def build_transaction(self_b, base):
                rpc.built.append(dict(base))
                return {**base, "to": _CONTRACT, "data": "0x"}

        class _Fns:
            def claim(self_f, preimage):
                return _Built()

            def refund(self_f):
                return _Built()

        class _Eth:
            async def get_storage_at(self, *_a, **_k):
                return b"\x00" * 32  # `settled` (slot 0) clear: an unsettled HTLC

            def contract(self_e, address=None, abi=None, **_k):
                return types.SimpleNamespace(functions=_Fns())

        self.write_w3 = types.SimpleNamespace(eth=_Eth())
        self.w3 = self.write_w3

    async def assert_chain(self):
        return None

    async def latest_block_timestamp(self):
        return self.head_ts

    async def latest_block_timestamp_quorum(self):
        return self.head_ts

    async def latest_block_timestamp_min(self):
        return self.head_ts

    async def fee_fields(self):
        return dict(self.fees)

    async def get_transaction_count(self, addr, block="pending"):
        return 7

    async def preflight(self, tx):
        return None

    async def send_raw(self, raw):
        from eth_utils import keccak

        self.sent.append(bytes(raw))
        return self.echo if self.echo is not None else "0x" + keccak(bytes(raw)).hex()

    async def wait_receipt(self, tx_hash, **_k):
        return {"status": 1, "logs": [{"address": _CONTRACT, "topics": [], "data": "0x" + self.preimage.hex()}]}


def _leg(rpc, **kw) -> EthHtlcContractLeg:
    return EthHtlcContractLeg(
        rpc=rpc, signing_key=PrivateKeyMaterial.generate(), chain_id=11155111, artifact=_ART, **kw
    )


# ── the claim deadline, the staleness abort, and the claim's fee ceiling ────────────────────────


async def test_the_claim_budget_is_eight_blocks_and_the_fee_ceiling_covers_exactly_that():
    # 1.125 per block is EIP-1559's maximum basefee step; 96 s is 8 twelve-second blocks.
    assert CLAIM_INCLUSION_BUDGET_S == 96
    assert pytest.approx(1.125**8) == CLAIM_BASEFEE_HEADROOM


async def test_claim_is_refused_at_exactly_the_budget_before_the_timeout(frozen_clock):
    rpc = _Rpc()
    with pytest.raises(PreRevealExpired, match=r"refusing to build a claim 96s before the HTLC timeout"):
        await _leg(rpc).claim(_locator(timeout=_NOW + 96), b"\x01" * 32)
    assert rpc.sent == []


async def test_claim_is_allowed_one_second_past_the_budget(frozen_clock):
    # The honest-path pair: 97 s of head-room is enough, so the claim goes out.
    rpc = _Rpc()
    await _leg(rpc).claim(_locator(timeout=_NOW + 97), b"\x01" * 32)
    assert len(rpc.sent) == 1


async def test_a_head_exactly_at_the_staleness_limit_is_still_usable(frozen_clock):
    rpc = _Rpc(head_ts=_NOW - 96)
    await _leg(rpc).claim(_locator(), b"\x01" * 32)
    assert len(rpc.sent) == 1


async def test_a_head_one_second_past_the_staleness_limit_aborts_and_says_how_stale(frozen_clock):
    rpc = _Rpc(head_ts=_NOW - 97)
    with pytest.raises(PreRevealAbort, match=r"the chain head is 97s stale \(limit 96s\)") as ei:
        await _leg(rpc).claim(_locator(), b"\x01" * 32)
    assert not isinstance(ei.value, PreRevealExpired)  # transient: retry, do not refund
    assert rpc.sent == []


async def test_the_claim_is_priced_to_survive_its_whole_budget(frozen_clock):
    # maxFeePerGas = basefee share x 1.125**8 + tip; the tip itself is never scaled. The tip (3)
    # shares no bit pattern with the fee that would make `-` and `^` agree on this fixture.
    rpc = _Rpc(max_fee=2_000_000_004, tip=3)
    await _leg(rpc).claim(_locator(), b"\x01" * 32)
    (base,) = rpc.built
    assert base["maxPriorityFeePerGas"] == 3
    assert base["maxFeePerGas"] == int(2_000_000_001 * 1.125**8) + 3
    assert base["gas"] == 120_000


async def test_a_refund_is_priced_at_the_nodes_own_fee(frozen_clock):
    # Only the deadline-bound claim carries head-room; a refund has no deadline to survive.
    rpc = _Rpc(max_fee=2_000_000_002, tip=2)
    await _leg(rpc).refund(_locator(timeout=_NOW))
    (base,) = rpc.built
    assert (base["maxFeePerGas"], base["maxPriorityFeePerGas"]) == (2_000_000_002, 2)
    assert base["gas"] == 100_000  # a field of the signed refund


async def test_a_claim_quoted_a_fee_BELOW_its_tip_is_priced_at_the_tip(frozen_clock):
    # A node reporting maxFeePerGas < tip leaves no basefee share to scale: the share floors at
    # 0, so the claim goes out at exactly the tip, never below it and never scaled above it.
    rpc = _Rpc(max_fee=1, tip=5)
    await _leg(rpc).claim(_locator(), b"\x01" * 32)
    (base,) = rpc.built
    assert (base["maxFeePerGas"], base["maxPriorityFeePerGas"]) == (5, 5)


async def test_a_refund_quoted_a_fee_BELOW_its_tip_is_not_repriced(frozen_clock):
    # Only the claim is re-priced. A refund's fee fields are the node's, unchanged, even when the
    # pair is inconsistent. This pins what the code does; it is not a claim the pair is valid.
    rpc = _Rpc(max_fee=1, tip=5)
    await _leg(rpc).refund(_locator(timeout=_NOW))
    (base,) = rpc.built
    assert (base["maxFeePerGas"], base["maxPriorityFeePerGas"]) == (1, 5)


async def test_a_32_character_string_is_not_a_preimage():
    with pytest.raises(ValidationError, match="preimage must be 32 bytes"):
        await _leg(_Rpc()).claim(_locator(), "a" * 32)  # type: ignore[arg-type]


# ── refund maturity ─────────────────────────────────────────────────────────────────────────────


async def test_refund_is_allowed_at_exactly_the_timeout():
    # The contract's refund() requires block.timestamp >= timeout, so `now == timeout` is mature.
    rpc = _Rpc(head_ts=_NOW)
    await _leg(rpc).refund(_locator(timeout=_NOW))
    assert len(rpc.sent) == 1


async def test_refund_three_seconds_early_is_refused_and_says_how_long_to_wait():
    rpc = _Rpc(head_ts=_NOW - 3)
    with pytest.raises(NetworkError, match=rf"matures at unix {_NOW}, now {_NOW - 3} \(3s to go\)"):
        await _leg(rpc).refund(_locator(timeout=_NOW))
    assert rpc.sent == []


# ── the broadcast echo ──────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("echo", ["0x" + "00" * 32, "0x" + "ff" * 32])
async def test_a_node_echoing_ANY_other_hash_is_refused(echo):
    # Both orderings: a mismatch is a mismatch whether the wrong hash sorts above or below ours.
    with pytest.raises(NetworkError, match="node reported tx hash"):
        await _leg(_Rpc(head_ts=_NOW, echo=echo)).refund(_locator(timeout=_NOW))


# ── finality ────────────────────────────────────────────────────────────────────────────────────


class _FinalityRpc:
    def __init__(self, *, status=1, block=10, finalized=10, block_hash=None, canonical=None):
        self.status, self.block, self.finalized = status, block, finalized
        self.block_hash = block_hash if block_hash is not None else bytearray(b"\xaa" * 32)
        self.canonical = canonical if canonical is not None else bytes(bytearray(b"\xaa" * 32))

    async def wait_receipt(self, tx_hash, **_k):
        return {"status": self.status, "blockNumber": self.block, "blockHash": self.block_hash, "logs": []}

    async def canonical_block_hash(self, n):
        return self.canonical

    async def finalized_block_number(self):
        return self.finalized


@pytest.mark.parametrize(("block", "final"), [(9, True), (10, True), (11, False)])
async def test_is_final_is_at_or_under_the_finalized_checkpoint(block, final):
    assert await _leg(_FinalityRpc(block=block, finalized=10)).is_final("0xtx") is final


@pytest.mark.parametrize("status", [0, 2, 0xFF, None])
async def test_is_final_never_reports_a_failed_or_statusless_tx_final(status):
    # EIP-658 defines 0 and 1 only, and the receipt comes from an untrusted RPC: anything but 1
    # is not a success, including a value above it.
    rpc = _FinalityRpc(status=status, block=1, finalized=10)
    if status is None:

        async def _no_status(tx_hash, **_k):
            return {"blockNumber": 1, "logs": []}

        rpc.wait_receipt = _no_status
    assert await _leg(rpc).is_final("0xtx") is False


@pytest.mark.parametrize("status", [0, 2, 0xFF])
async def test_a_claim_whose_status_is_not_one_is_never_FINAL(status):
    # Buried well under the checkpoint, so only the status can decide.
    v = await _leg(_FinalityRpc(status=status, block=5, finalized=10)).claim_finality_verdict("0xtx")
    assert v.state is CounterClaimState.NOT_YET_FINAL_LIVE
    v = await _leg(_FinalityRpc(status=1, block=5, finalized=10)).claim_finality_verdict("0xtx")
    assert v.state is CounterClaimState.FINAL


async def test_a_claim_in_the_finalized_block_itself_is_FINAL():
    v = await _leg(_FinalityRpc(block=10, finalized=10)).claim_finality_verdict("0xtx")
    assert v.state is CounterClaimState.FINAL
    v = await _leg(_FinalityRpc(block=11, finalized=10)).claim_finality_verdict("0xtx")
    assert v.state is CounterClaimState.NOT_YET_FINAL_LIVE


async def test_the_canonical_binding_compares_hash_VALUES_not_objects():
    # web3 hands back HexBytes; bytes(HexBytes) is a new object. Equal bytes must bind.
    from hexbytes import HexBytes

    rpc = _FinalityRpc(block=5, finalized=10, block_hash=HexBytes(b"\xab" * 32), canonical=bytes([0xAB] * 32))
    assert (await _leg(rpc).claim_finality_verdict("0xtx")).state is CounterClaimState.FINAL


# ── verify_funded ───────────────────────────────────────────────────────────────────────────────


class _FundedRpc:
    """Serves a correctly-deployed contract; `recipient_code` puts code at a recipient address."""

    def __init__(self, loc, *, balance, recipient_code=None):
        from web3 import Web3

        self.loc, self.balance = loc, balance
        self.recipient_code = {k.lower(): v for k, v in (recipient_code or {}).items()}
        self.immutable_reads: list = []
        rpc = self
        values = {
            "hashlock": loc.hashlock_bytes,
            "claimant": Web3.to_checksum_address(loc.claimant),
            "refundee": Web3.to_checksum_address(loc.refundee),
            "timeout": loc.timeout,
        }

        class _Getter:
            def __init__(self, name):
                self.name = name

            async def call(self, *, block_identifier):
                rpc.immutable_reads.append((self.name, block_identifier))
                return values[self.name]

        class _Fns:
            def __getattr__(self, name):
                return lambda: _Getter(name)

        self.w3 = types.SimpleNamespace(
            eth=types.SimpleNamespace(
                contract=lambda **_k: types.SimpleNamespace(functions=_Fns()), get_storage_at=_unsettled_storage
            )
        )

    async def assert_chain(self):
        return None

    async def get_code(self, address, block_identifier=None):
        if address.lower() == self.loc.contract_address.lower():
            return b"\x60\x00"
        return self.recipient_code.get(address.lower(), b"")

    async def get_balance(self, address, block_identifier=None):
        return self.balance


def _verifying_leg(rpc) -> EthHtlcContractLeg:
    leg = _leg(rpc)
    leg._expected_runtime = lambda loc: b"\x60\x00"  # the artifact compare has its own tests
    return leg


async def test_an_over_funded_contract_is_accepted_and_an_under_funded_one_is_not():
    loc = _locator(amount_wei=1000)
    await _verifying_leg(_FundedRpc(loc, balance=1001)).verify_funded(loc, expected_amount_wei=1000)
    await _verifying_leg(_FundedRpc(loc, balance=1000)).verify_funded(loc, expected_amount_wei=1000)
    with pytest.raises(ValidationError, match="under-funded"):
        await _verifying_leg(_FundedRpc(loc, balance=999)).verify_funded(loc, expected_amount_wei=1000)


async def test_the_REFUNDEE_is_checked_even_when_the_claimant_is_a_plain_EOA():
    loc = _locator()
    rpc = _FundedRpc(loc, balance=loc.amount_wei, recipient_code={loc.refundee: b"\x60\x00\x60\x00"})
    with pytest.raises(ValidationError, match="refundee .* has contract code"):
        await _verifying_leg(rpc).verify_funded(loc, expected_amount_wei=loc.amount_wei)


@pytest.mark.parametrize(("pin", "want"), [(None, "latest"), ("finalized", "finalized"), (123, 123)])
async def test_every_immutable_is_read_at_the_pinned_checkpoint(pin, want):
    loc = _locator()
    rpc = _FundedRpc(loc, balance=loc.amount_wei)
    await _verifying_leg(rpc).verify_funded(loc, expected_amount_wei=loc.amount_wei, block_identifier=pin)
    assert sorted(rpc.immutable_reads) == sorted((n, want) for n in ("hashlock", "claimant", "refundee", "timeout"))


def test_a_23_byte_code_is_a_7702_delegation_only_with_the_ef0100_prefix():
    assert is_eip7702_delegation(b"\xef\x01\x00" + b"\x22" * 20)
    assert not is_eip7702_delegation(b"\x60\x80\x60" + b"\x22" * 20)
    assert not is_eip7702_delegation(b"\xef\x01\x00" + b"\x22" * 21)


# ── claim artifacts and provenance ──────────────────────────────────────────────────────────────


class _ArtifactRpc:
    def __init__(self, *, calldata, logs):
        self.calldata, self.logs = calldata, logs

    async def get_transaction(self, tx_hash):
        return {"input": self.calldata}

    async def wait_receipt(self, tx_hash, **_k):
        return {"status": 1, "logs": self.logs}


async def test_claim_artifacts_are_the_calldata_and_every_present_log_data():
    p = os.urandom(32)
    rpc = _ArtifactRpc(
        calldata="0x" + (b"\xbd\x66\x52\x8a" + p).hex(),
        logs=[{"data": ""}, {"data": bytes(p)}, {"data": None}, {}, {"data": "0x" + p.hex()}],
    )
    got = await _leg(rpc).fetch_claim_artifacts("0xtx")
    # Absent/empty data is skipped; bytes and 0x-hex are both decoded to the same blob.
    assert got == [b"\xbd\x66\x52\x8a" + p, p, p]
    assert _leg(rpc).recover_secret(got, hashlib.sha256(p).digest()) == p


async def test_a_single_artifact_is_capped_at_exactly_64_kib():
    cap = 64 * 1024
    ok = await _leg(_ArtifactRpc(calldata=b"\x00" * cap, logs=[])).fetch_claim_artifacts("0xtx")
    assert [len(b) for b in ok] == [cap]
    with pytest.raises(NetworkError, match=f"blob {cap + 1} B exceeds cap {cap}"):
        await _leg(_ArtifactRpc(calldata=b"\x00" * (cap + 1), logs=[])).fetch_claim_artifacts("0xtx")


async def test_the_artifact_total_is_capped_at_exactly_256_kib():
    blob = b"\x00" * (64 * 1024)
    at_cap = [{"data": blob}] * 3  # calldata + 3 logs = 4 x 64 KiB = 256 KiB exactly
    ok = await _leg(_ArtifactRpc(calldata=blob, logs=at_cap)).fetch_claim_artifacts("0xtx")
    assert sum(map(len, ok)) == 256 * 1024
    with pytest.raises(NetworkError, match=f"total {256 * 1024 + 1} B exceeds cap {256 * 1024}"):
        await _leg(_ArtifactRpc(calldata=blob, logs=[*at_cap, {"data": b"\x01"}])).fetch_claim_artifacts("0xtx")


class _ProvenanceRpc:
    def __init__(self, logs, status=1):
        self.logs, self.status = logs, status

    async def wait_receipt(self, tx_hash, **_k):
        return {"status": self.status, "logs": self.logs}


@pytest.mark.parametrize("status", [0, 2, 0xFF])
async def test_provenance_refuses_any_claim_status_but_one(status):
    # The log from our own contract carries p, so only the status stands between this receipt and
    # "the maker collected".
    p = os.urandom(32)
    logs = [{"address": _CONTRACT, "topics": [], "data": "0x" + p.hex()}]
    with pytest.raises(ValidationError, match="did not succeed"):
        await _leg(_ProvenanceRpc(logs, status)).assert_claim_provenance("0xtx", contract_address=_CONTRACT, preimage=p)
    await _leg(_ProvenanceRpc(logs, 1)).assert_claim_provenance("0xtx", contract_address=_CONTRACT, preimage=p)


async def test_provenance_keeps_scanning_past_a_foreign_log_and_a_malformed_one():
    # A multicall claim: the wallet's own log first, then a garbage one from our contract, then
    # the real Claimed(p). Neither of the first two may end the scan.
    p = os.urandom(32)
    logs = [
        {"address": "0x" + "99" * 20, "topics": [], "data": "0x" + p.hex()},
        {"address": _CONTRACT, "topics": ["0xnothex"], "data": "0x"},
        {"address": _CONTRACT.upper().replace("0X", "0x"), "topics": ["0x" + "cc" * 32], "data": "0x" + p.hex()},
    ]
    await _leg(_ProvenanceRpc(logs)).assert_claim_provenance("0xtx", contract_address=_CONTRACT, preimage=p)


async def test_provenance_refuses_a_33_byte_preimage():
    with pytest.raises(ValidationError, match="preimage must be 32 bytes"):
        await _leg(_ProvenanceRpc([])).assert_claim_provenance("0xtx", contract_address=_CONTRACT, preimage=bytes(33))


def test_a_non_hex_log_field_is_a_typed_network_error():
    with pytest.raises(NetworkError, match="non-hex log field"):
        _b("0xzz")


@pytest.mark.parametrize(("raw", "want"), [(None, None), (16, 16), ("0x10", 16), ("16", 16)])
def test_receipt_integers_normalise_from_every_honest_encoding(raw, want):
    assert _int_or_none(raw) == want


# ── construction and funding inputs ─────────────────────────────────────────────────────────────


@pytest.mark.parametrize("chain_id", [0, -1, "1", 1.0])
def test_the_leg_refuses_a_chain_id_that_is_not_a_positive_int(chain_id):
    with pytest.raises(ValidationError, match="chain_id must be a positive int"):
        EthHtlcContractLeg(rpc=object(), signing_key=PrivateKeyMaterial.generate(), chain_id=chain_id, artifact=_ART)


@pytest.mark.parametrize("hashlock", [bytes(31), bytes(33), "22" * 32])
async def test_fund_refuses_a_hashlock_that_is_not_32_bytes(hashlock):
    with pytest.raises(ValidationError, match="hashlock must be 32 bytes"):
        await _leg(object()).fund(
            hashlock=hashlock, claimant="0x" + "33" * 20, refundee="0x" + "44" * 20, timeout=_NOW, amount_wei=1
        )


@pytest.mark.parametrize("amount", [0, -1])
async def test_fund_refuses_a_non_positive_amount(amount):
    with pytest.raises(ValidationError, match="amount_wei must be > 0"):
        await _leg(object()).fund(
            hashlock=bytes(32), claimant="0x" + "33" * 20, refundee="0x" + "44" * 20, timeout=_NOW, amount_wei=amount
        )


# ── CREATE address, differentially against an independent RLP encoder ──────────────────────────


@pytest.mark.parametrize("nonce", [0, 1, 0x7F, 0x80, 0xFF, 0x100, 0xFFFF, 0x1_0000, 2**32, 2**56 + 3])
def test_create_address_matches_keccak_of_the_rlp_package_encoding(nonce):
    rlp = pytest.importorskip("rlp")
    from eth_utils import keccak, to_checksum_address

    sender = "0x" + os.urandom(20).hex()
    want = to_checksum_address(keccak(rlp.encode([bytes.fromhex(sender[2:]), nonce]))[12:])
    assert create_address(sender, nonce) == want
    assert create_address(sender[2:], nonce) == want  # bare hex too


@pytest.mark.parametrize("n", [19, 21])
def test_create_address_refuses_a_sender_that_is_not_20_bytes(n):
    with pytest.raises(ValidationError, match=f"sender must be a 20-byte address, got {n}"):
        create_address("0x" + "ab" * n, 0)


# ── second pass: survivors of the first after-run ───────────────────────────────────────────────


async def test_refund_is_allowed_well_AFTER_the_timeout():
    # Maturity is a lower bound. A refund an hour late is the ordinary case, not an edge.
    rpc = _Rpc(head_ts=_NOW + 3600)
    await _leg(rpc).refund(_locator(timeout=_NOW))
    assert len(rpc.sent) == 1


class _PrivateRecorder:
    def __init__(self):
        self.calls = []

    async def submit_raw(self, raw):
        self.calls.append(raw)
        return "0x" + "ab" * 32


async def test_only_the_claim_goes_private_a_refund_is_public_and_preflighted():
    sub = _PrivateRecorder()
    rpc = _Rpc(head_ts=_NOW)
    preflights = []

    async def _preflight(tx):
        preflights.append(tx)

    rpc.preflight = _preflight
    await _leg(rpc, private_submitter=sub).refund(_locator(timeout=_NOW))
    assert sub.calls == [] and len(rpc.sent) == 1
    assert len(preflights) == 1  # a refund carries no secret, so it keeps its revert check


@pytest.mark.parametrize("n", [31, 33])
async def test_claim_refuses_a_preimage_of_the_wrong_length(n):
    with pytest.raises(ValidationError, match="preimage must be 32 bytes"):
        await _leg(_Rpc()).claim(_locator(), bytes(n))


@pytest.mark.parametrize("field", ["hashlock", "claimant", "refundee", "timeout"])
@pytest.mark.parametrize("direction", ["below", "above"])
async def test_every_immutable_mismatch_is_refused_whichever_way_it_sorts(field, direction):
    loc = _locator()
    rpc = _FundedRpc(loc, balance=loc.amount_wei)
    lo, hi = {
        "hashlock": (b"\x00" * 32, b"\xff" * 32),
        "claimant": ("0x" + "00" * 20, "0x" + "ff" * 20),
        "refundee": ("0x" + "00" * 20, "0x" + "ff" * 20),
        "timeout": (loc.timeout - 1, loc.timeout + 1),
    }[field]
    _override(rpc, field, lo if direction == "below" else hi)
    with pytest.raises(ValidationError, match=f"on-chain {field} !="):
        await _verifying_leg(rpc).verify_funded(loc, expected_amount_wei=loc.amount_wei)


def _override(rpc, name, value):
    real = rpc.w3.eth.contract

    def contract(**k):
        c = real(**k)
        inner = c.functions

        class _Fns:
            def __getattr__(self, n):
                if n != name:
                    return getattr(inner, n)

                class _G:
                    async def call(self, *, block_identifier):
                        return value

                return lambda: _G()

        return types.SimpleNamespace(functions=_Fns())

    rpc.w3 = types.SimpleNamespace(eth=types.SimpleNamespace(contract=contract, get_storage_at=_unsettled_storage))


async def test_the_timeout_bind_compares_values_not_int_objects():
    # web3 decodes a fresh int; an identity comparison would refuse every honest contract.
    loc = _locator(timeout=_NOW + 10**6)
    rpc = _FundedRpc(loc, balance=loc.amount_wei)
    _override(rpc, "timeout", int(str(loc.timeout)))
    await _verifying_leg(rpc).verify_funded(loc, expected_amount_wei=loc.amount_wei)


async def test_a_delegated_claimant_does_not_excuse_a_contract_refundee():
    loc = _locator()
    delegation = b"\xef\x01\x00" + b"\x22" * 20
    rpc = _FundedRpc(loc, balance=loc.amount_wei, recipient_code={loc.claimant: delegation, loc.refundee: b"\x60\x00"})
    with pytest.raises(ValidationError, match="refundee .* has contract code"):
        await _verifying_leg(rpc).verify_funded(
            loc, expected_amount_wei=loc.amount_wei, allow_delegated_eoa_recipients=True
        )


def test_expected_runtime_is_exact_and_substitutes_every_immutable_offset():
    """The slot-accurate compare builds the expected runtime by substituting the negotiated value
    into EVERY immutableReferences offset — no byte is wildcarded, so a forged immutable copy or a
    modified logic byte (even a committed-zero one) DIFFERS from it. Uses a synthetic 2-copy artifact.
    This checks the construction only; ``test_eth_verify_funded_real_runtime.py`` drives the real
    ``verify_funded`` compare over the committed artifacts."""
    # Synthetic runtime: 96 bytes. immutable `claimant` (ref id "6") at offsets 0 and 64 (two
    # copies, as Solidity splices); byte at offset 40 is a non-zero LOGIC byte between them.
    runtime = bytearray(96)
    runtime[40] = 0xFE
    art = {
        "abi": [],
        "bytecode": "0x00",
        "runtime_bytecode": "0x" + bytes(runtime).hex(),
        "immutableReferences": {"6": [{"start": 0, "length": 32}, {"start": 64, "length": 32}]},
        "immutable_names": {"6": "claimant"},
    }
    leg = EthHtlcContractLeg(rpc=object(), signing_key=PrivateKeyMaterial.generate(), chain_id=1, artifact=art)
    loc = _locator()  # claimant == 0x33..33
    expected = leg._expected_runtime(loc)
    word = b"\x00" * 12 + bytes.fromhex("33" * 20)
    assert expected[0:32] == word and expected[64:96] == word  # BOTH copies substituted
    assert expected[40] == 0xFE  # the logic byte is preserved exactly
    # Forging ONLY the second (claim/refund) copy differs — the getter would read the first.
    forged = bytearray(expected)
    forged[64:96] = b"\x00" * 12 + bytes.fromhex("3C44CdDdB6a900fa2b585dd299e03d12FA4293BC")
    assert bytes(forged) != expected
    # So does a flipped logic byte (the old mask ignored higher/lower committed-zero bytes).
    lower = bytearray(expected)
    lower[40] = 0x5F
    higher = bytearray(expected)
    higher[40] = 0xFF
    assert bytes(lower) != expected and bytes(higher) != expected


def test_a_23_byte_code_with_a_higher_prefix_is_not_a_delegation():
    assert not is_eip7702_delegation(b"\xff\x00\x00" + b"\x22" * 20)
    assert not is_eip7702_delegation(b"\xef\x01\x01" + b"\x22" * 20)


async def test_a_receipt_hash_that_sorts_ABOVE_the_canonical_one_is_not_final():
    rpc = _FinalityRpc(block=5, finalized=10, block_hash=b"\xbb" * 32, canonical=b"\xaa" * 32)
    assert (await _leg(rpc).claim_finality_verdict("0xtx")).state is CounterClaimState.NOT_YET_FINAL_LIVE


async def test_a_receipt_without_a_status_is_never_final_nor_a_valid_claim():
    class _NoStatus(_FinalityRpc):
        async def wait_receipt(self, tx_hash, **_k):
            return {"blockNumber": 5, "blockHash": b"\xaa" * 32, "logs": []}

    rpc = _NoStatus(block=5, finalized=10)
    assert (await _leg(rpc).claim_finality_verdict("0xtx")).state is CounterClaimState.NOT_YET_FINAL_LIVE
    p = os.urandom(32)

    class _NoStatusClaim:
        async def wait_receipt(self, tx_hash, **_k):
            return {"logs": [{"address": _CONTRACT, "topics": [], "data": "0x" + p.hex()}]}

    with pytest.raises(ValidationError, match="did not succeed"):
        await _leg(_NoStatusClaim()).assert_claim_provenance("0xtx", contract_address=_CONTRACT, preimage=p)


async def test_a_foreign_log_that_sorts_BELOW_our_contract_cannot_prove_a_claim():
    p = os.urandom(32)
    logs = [{"address": "0x" + "00" * 20, "topics": [], "data": "0x" + p.hex()}]
    with pytest.raises(ValidationError, match="no Claimed"):
        await _leg(_ProvenanceRpc(logs)).assert_claim_provenance("0xtx", contract_address=_CONTRACT, preimage=p)


def test_endpoints_that_disagree_only_about_log_TOPICS_do_not_agree():
    from pyrxd.eth_wallet.htlc_leg import _agree_receipt_facts

    base = {"status": 1, "blockHash": "0x" + "aa" * 32, "blockNumber": 5}
    a = {**base, "logs": [{"address": _CONTRACT, "topics": ["0x" + "01" * 32], "data": "0x"}]}
    b = {**base, "logs": [{"address": _CONTRACT, "topics": ["0x" + "02" * 32], "data": "0x"}]}
    assert _agree_receipt_facts([a, dict(a)]) is a
    with pytest.raises(NetworkError, match="disagree"):
        _agree_receipt_facts([a, b])


async def test_an_uncorroborated_claim_receipt_gives_up_after_the_quorum_wait(monkeypatch):
    """A multi-source rpc whose endpoints never agree must end in 'unconfirmed', on schedule."""
    clock = {"t": 1000.0}
    polls = []

    async def _sleep(s):
        polls.append(s)
        clock["t"] += s

    monkeypatch.setattr(hl, "time", types.SimpleNamespace(time=lambda: float(_NOW), monotonic=lambda: clock["t"]))
    monkeypatch.setattr(hl.asyncio, "sleep", _sleep)

    class _Split:
        async def wait_receipt(self, tx_hash, **_k):
            return {"status": 1, "logs": []}

        async def eth_call_quorum(self, make_call, *, label, combine):
            raise NetworkError("endpoints disagree")

    with pytest.raises(NetworkError, match="no quorum of endpoints corroborated"):
        await _leg(_Split()).assert_claim_provenance("0xtx", contract_address=_CONTRACT, preimage=os.urandom(32))
    # 60 s at a 2 s poll: thirty re-asks, not an unbounded spin.
    assert len(polls) == 30 and set(polls) == {2.0}


async def test_a_quorum_that_forms_just_inside_the_60s_wait_is_accepted(monkeypatch):
    """The honest-path pair: endpoints that only agree after 59.5 s are still in time."""
    clock = {"t": 1000.0}
    p = os.urandom(32)
    agreed = {"status": 1, "logs": [{"address": _CONTRACT, "topics": [], "data": "0x" + p.hex()}]}
    reads = []

    async def _sleep(s):
        clock["t"] += s

    monkeypatch.setattr(hl, "time", types.SimpleNamespace(time=lambda: float(_NOW), monotonic=lambda: clock["t"]))
    monkeypatch.setattr(hl.asyncio, "sleep", _sleep)

    class _SlowThenAgreed:
        async def wait_receipt(self, tx_hash, **_k):
            return agreed

        async def eth_call_quorum(self, make_call, *, label, combine):
            reads.append(clock["t"])
            if len(reads) == 1:
                clock["t"] += 57.5  # one slow read: the endpoints answer, but do not yet agree
            if len(reads) < 3:
                raise NetworkError("endpoints disagree")
            return agreed

    await _leg(_SlowThenAgreed()).assert_claim_provenance("0xtx", contract_address=_CONTRACT, preimage=p)
    assert reads == [1000.0, 1059.5, 1061.5]


# ── fund: the deploy receipt ────────────────────────────────────────────────────────────────────


def _funding_leg(receipt_status=1, *, lie=None, statusless=False):
    from pyrxd.eth_wallet.keys import derive_address

    key = PrivateKeyMaterial.generate()
    sender = derive_address(key)
    deploy_hash = "0x" + "de" * 32

    class _Ctor:
        async def build_transaction(self, tx):
            return dict(tx)

    class _Rpc:
        write_w3 = types.SimpleNamespace(
            eth=types.SimpleNamespace(contract=lambda **_k: types.SimpleNamespace(constructor=lambda *a: _Ctor()))
        )

        async def assert_chain(self):
            return None

        async def fee_fields(self):
            return {"maxFeePerGas": 3, "maxPriorityFeePerGas": 1}

        async def get_transaction_count(self, addr, block="pending"):
            return 5

        async def wait_receipt(self, tx_hash, **_k):
            r = {"contractAddress": lie or create_address(sender, 5), "logs": []}
            if not statusless:
                r["status"] = receipt_status
            return r

    leg = EthHtlcContractLeg(rpc=_Rpc(), signing_key=key, chain_id=11155111, artifact=_ART)
    signed: list[dict] = []

    async def _send(built, *, preflight=True, private=False, on_signed=None):
        assert preflight is False  # a deploy has no `to`, so there is nothing to eth_call
        signed.append(built)
        return deploy_hash

    leg._sign_and_send = _send
    return leg, sender, deploy_hash, signed


_FUND_ARGS = dict(hashlock=b"\x22" * 32, claimant="0x" + "33" * 20, refundee="0x" + "44" * 20, timeout=_NOW)


async def test_fund_returns_a_locator_carrying_the_deploy_hash_verbatim():
    leg, sender, deploy_hash, signed = _funding_leg()
    loc = await leg.fund(amount_wei=1, **_FUND_ARGS)  # one wei is a valid amount
    assert loc.deploy_tx_hash == deploy_hash
    assert loc.contract_address == create_address(sender, 5)
    assert loc.amount_wei == 1
    (deploy,) = signed
    assert (deploy["gas"], deploy["value"]) == (800_000, 1)  # fields of the signed deploy


@pytest.mark.parametrize("kw", [{"receipt_status": 0}, {"receipt_status": 2}, {"statusless": True}])
async def test_fund_never_returns_a_locator_for_a_reverted_or_statusless_deploy(kw):
    leg, _, _, _ = _funding_leg(**kw)
    with pytest.raises(NetworkError, match="deploy tx reverted"):
        await leg.fund(amount_wei=10**15, **_FUND_ARGS)


@pytest.mark.parametrize("lie", ["0x" + "00" * 20, "0x" + "ff" * 20])
async def test_fund_refuses_a_receipt_naming_ANY_other_address(lie):
    leg, _, _, _ = _funding_leg(lie=lie)
    with pytest.raises(ValidationError, match="deploy receipt names contract"):
        await leg.fund(amount_wei=10**15, **_FUND_ARGS)
