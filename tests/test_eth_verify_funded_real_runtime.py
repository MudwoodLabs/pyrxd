"""``verify_funded`` driven over the REAL artifact runtime, offline — the per-PR regression for #798.

Every other offline ``verify_funded`` test either stubs ``_expected_runtime`` or serves the honest
runtime, and the forged-copy tests in ``test_eth_leg.py`` compare two byte strings the test built
itself. So deleting the exact runtime compare (``if bytes(code) != self._expected_runtime(...)``)
left the whole default suite green: measured by the 2026-09-30 panel, 19103 passed, 0 failed. Only
the Anvil module caught it, and that runs nightly, not per PR.

These tests serve the committed artifacts' runtime with the negotiated immutables spliced in (by
this file's own splice, not the leg's), then forge one thing at a time and run the leg's real
``verify_funded``. Nothing on the leg is stubbed.

They also pin the storage half, which the exact compare cannot see: a contract whose
code is exact but whose ``settled`` flag is already set can never pay out, and must be
refused both by ``verify_funded`` and at the tip right before a claim reveals ``p``.
"""

from __future__ import annotations

import asyncio
import json
import os
import pathlib
import time

import pytest

pytest.importorskip("web3", reason="needs the eth extra: pip install 'pyrxd[eth]'")

from pyrxd.eth_wallet.erc20_leg import Erc20HtlcLeg
from pyrxd.eth_wallet.htlc_leg import SETTLED_SLOT, EthHtlcContractLeg
from pyrxd.eth_wallet.locator import Erc20HtlcLocator, EthHtlcLocator
from pyrxd.eth_wallet.tokens import token_for
from pyrxd.security.errors import ClaimNotConfirmed, PreRevealAbort, ValidationError
from pyrxd.security.secrets import PrivateKeyMaterial

_FIX = pathlib.Path(__file__).parent / "fixtures"
_NATIVE_ART = json.loads((_FIX / "EthHtlc.json").read_text())
_TOKEN_ART = json.loads((_FIX / "Erc20Htlc.json").read_text())

_HTLC = "0x" + "11" * 20
_CLAIMANT = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
_REFUNDEE = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
_ATTACKER = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"
_HASHLOCK = "0x" + "33" * 32
_TIMEOUT = 4_000_000_000  # far past any run of this suite, so the claim deadline guard never refuses
_AMOUNT = 12_345_678
_USDC = token_for("USDC", 1)

_UNSETTLED = b"\x00" * 32


def _word(addr: str) -> bytes:
    return b"\x00" * 12 + bytes.fromhex(addr.removeprefix("0x"))


def _values() -> dict[str, bytes]:
    return {
        "hashlock": bytes.fromhex(_HASHLOCK[2:]),
        "claimant": _word(_CLAIMANT),
        "refundee": _word(_REFUNDEE),
        "timeout": _TIMEOUT.to_bytes(32, "big"),
        "token": _word(_USDC.address),
        "amount": _AMOUNT.to_bytes(32, "big"),
    }


def _honest_runtime(art: dict) -> bytes:
    """The runtime an honest deploy for these terms carries: every immutable copy spliced."""
    out = bytearray(bytes.fromhex(art["runtime_bytecode"].removeprefix("0x")))
    vals = _values()
    for ref_id, offsets in art["immutableReferences"].items():
        for ref in offsets:
            out[ref["start"] : ref["start"] + 32] = vals[art["immutable_names"][str(ref_id)]]
    return bytes(out)


class _Rpc:
    """Serves one HTLC whose GETTERS are always honest; the code and the storage are what vary.

    The getter copy of each immutable always reads as negotiated, so only the exact runtime compare
    (or the storage read) can tell the contract differs from the expected one.
    """

    def __init__(self, runtime: bytes, *, settled: bytes = _UNSETTLED) -> None:
        self.runtime = runtime
        self.settled = settled
        self.storage_reads: list[tuple[str, int, object]] = []
        self.preflights: list[dict] = []
        rpc = self
        getters = {
            "hashlock": bytes.fromhex(_HASHLOCK[2:]),
            "claimant": _CLAIMANT,
            "refundee": _REFUNDEE,
            "timeout": _TIMEOUT,
            "token": _USDC.address,
            "amount": _AMOUNT,
            "balanceOf": _AMOUNT,
            "decimals": _USDC.decimals,
            "isBlacklisted": False,
        }

        class _Call:
            def __init__(self, v):
                self._v = v

            async def call(self, *_a, **_k):
                return self._v

            async def build_transaction(self, base):
                return {**base, "to": _HTLC, "data": "0x"}

        class _Fns:
            def __getattr__(self, name):
                if name == "claim":
                    return lambda _p: _Call(None)
                return lambda *_a: _Call(getters[name])

        class _Eth:
            def contract(self, *_a, **_k):
                return type("C", (), {"functions": _Fns()})()

            async def get_storage_at(self, address, slot, block_identifier=None):
                rpc.storage_reads.append((address, slot, block_identifier))
                return rpc.settled

        class _W3:
            eth = _Eth()

        self.w3 = _W3()
        self.write_w3 = self.w3

    async def assert_chain(self):
        return None

    async def get_code(self, addr, block_identifier=None):
        return self.runtime if addr == _HTLC else b""

    async def get_balance(self, *_a, **_k):
        return _AMOUNT

    async def latest_block_timestamp(self):
        return int(time.time())  # a fresh head, so the staleness abort is not what refuses

    latest_block_timestamp_quorum = latest_block_timestamp
    latest_block_timestamp_min = latest_block_timestamp

    async def fee_fields(self):
        return {"maxFeePerGas": 2 * 10**9, "maxPriorityFeePerGas": 10**9}

    async def get_transaction_count(self, *_a, **_k):
        return 0

    async def preflight(self, tx):
        self.preflights.append(tx)


def _native(rpc, **kw) -> EthHtlcContractLeg:
    return EthHtlcContractLeg(
        rpc=rpc, signing_key=PrivateKeyMaterial(os.urandom(32)), chain_id=1, artifact=_NATIVE_ART, **kw
    )


def _token(rpc, **kw) -> Erc20HtlcLeg:
    return Erc20HtlcLeg(
        token=_USDC, rpc=rpc, signing_key=PrivateKeyMaterial(os.urandom(32)), chain_id=1, artifact=_TOKEN_ART, **kw
    )


def _native_loc() -> EthHtlcLocator:
    return EthHtlcLocator(
        chain_id=1,
        contract_address=_HTLC,
        deploy_tx_hash="0x" + "22" * 32,
        hashlock=_HASHLOCK,
        claimant=_CLAIMANT,
        refundee=_REFUNDEE,
        timeout=_TIMEOUT,
        amount_wei=_AMOUNT,
    )


def _token_loc() -> Erc20HtlcLocator:
    return Erc20HtlcLocator(
        chain_id=1,
        contract_address=_HTLC,
        deploy_tx_hash="0x" + "22" * 32,
        hashlock=_HASHLOCK,
        claimant=_CLAIMANT,
        refundee=_REFUNDEE,
        timeout=_TIMEOUT,
        amount_wei=_AMOUNT,
        token_address=_USDC.address,
    )


_KINDS = {
    "native": (_NATIVE_ART, _native, _native_loc),
    "erc20": (_TOKEN_ART, _token, _token_loc),
}


def _verify(kind: str, rpc, **kw) -> None:
    _art, build, loc = _KINDS[kind]
    asyncio.run(build(rpc).verify_funded(loc(), expected_amount_wei=_AMOUNT, **kw))


def _every_copy() -> list[tuple[str, str, int]]:
    """(leg kind, immutable name, offset) for EVERY immutable copy in both artifacts — derived."""
    out = []
    for kind, (art, _b, _l) in _KINDS.items():
        for ref_id, offsets in art["immutableReferences"].items():
            for ref in offsets:
                out.append((kind, art["immutable_names"][str(ref_id)], ref["start"]))
    return out


_COPIES = _every_copy()


def test_the_copy_set_is_not_vacuous_and_some_immutable_has_several_copies():
    """The forged-copy tests below matter because an immutable has more than one copy (a getter
    reads one, claim() another). If the artifacts ever stop having that, they test nothing new."""
    assert len(_COPIES) >= 20, len(_COPIES)
    for kind in _KINDS:
        names = [n for k, n, _o in _COPIES if k == kind]
        assert any(names.count(n) >= 2 for n in set(names)), kind


# ── #798: the exact runtime compare, through the real verify_funded ─────────────────────────────


@pytest.mark.parametrize("kind", list(_KINDS))
def test_the_honest_runtime_is_ACCEPTED(kind):
    """The honest path for every refusal below — and the proof that this file's splice agrees with
    the leg's, so the refusals are about the forgery and not about a mismatched fixture."""
    _verify(kind, _Rpc(_honest_runtime(_KINDS[kind][0])))


@pytest.mark.parametrize("kind,name,offset", _COPIES, ids=[f"{k}-{n}@{o}" for k, n, o in _COPIES])
def test_forging_ANY_single_immutable_copy_is_refused_by_verify_funded(kind, name, offset):
    """#798, every instance of the class rather than the one demonstrated (``claimant`` at 1224).

    One copy of one immutable is replaced with an attacker word; every getter still answers the
    negotiated value. The old value-masked compare passed exactly this and the ETH was drained on
    claim. A deleted or weakened exact compare makes these fail per PR, not only nightly.
    """
    forged = bytearray(_honest_runtime(_KINDS[kind][0]))
    assert forged[offset : offset + 32] != _word(_ATTACKER)  # the forgery really changes the copy
    forged[offset : offset + 32] = _word(_ATTACKER)
    with pytest.raises(ValidationError, match="does not EXACTLY equal"):
        _verify(kind, _Rpc(bytes(forged)))


@pytest.mark.parametrize("kind", list(_KINDS))
def test_a_flipped_LOGIC_byte_the_old_mask_ignored_is_refused(kind):
    """A committed-zero byte outside every immutable window — the mask wildcarded these too."""
    art = _KINDS[kind][0]
    honest = _honest_runtime(art)
    windows = {
        i for offs in art["immutableReferences"].values() for r in offs for i in range(r["start"], r["start"] + 32)
    }
    pos = next(i for i, b in enumerate(honest) if b == 0 and i not in windows)
    tampered = bytearray(honest)
    tampered[pos] = 0x42
    with pytest.raises(ValidationError, match="does not EXACTLY equal"):
        _verify(kind, _Rpc(bytes(tampered)))


# ── storage: a pre-settled contract with EXACT code ─────────────────────────────────────────────


@pytest.mark.parametrize("kind", list(_KINDS))
@pytest.mark.parametrize(
    "word",
    [b"\x00" * 31 + b"\x01", b"\x01" + b"\x00" * 31, b"\x01"],
    ids=["settled=true", "high-byte-set", "short-answer"],
)
def test_a_PRE_SETTLED_contract_with_exact_code_is_refused(kind, word):
    """Exact code, honest getters, full balance — and the ``settled`` word set. ``claim()`` and
    ``refund()`` both revert ``AlreadySettled`` on such a contract, so it is refused. Any non-zero
    word is refused, however it is padded."""
    rpc = _Rpc(_honest_runtime(_KINDS[kind][0]), settled=word)
    with pytest.raises(ValidationError, match="ALREADY SETTLED"):
        _verify(kind, rpc)
    assert [s for _a, s, _b in rpc.storage_reads] == [SETTLED_SLOT]


@pytest.mark.parametrize("kind", list(_KINDS))
@pytest.mark.parametrize("bid,expected", [(None, "latest"), ("finalized", "finalized"), (123, 123)])
def test_the_settled_read_is_pinned_to_the_same_block_as_every_other_read(kind, bid, expected):
    """The maker re-verifies at ``'finalized'`` so a reorg cannot swap the contract between verify
    and the lock. A storage read at the tip would reopen that window for this check."""
    rpc = _Rpc(_honest_runtime(_KINDS[kind][0]))
    _verify(kind, rpc, block_identifier=bid)
    assert rpc.storage_reads == [(_HTLC, SETTLED_SLOT, expected)]


# ── the claim re-reads it at the tip, before p can leave ────────────────────────────────────────


class _PrivateSubmitter:
    """A private submitter; records what reaches it and stops there."""

    def __init__(self) -> None:
        self.submitted: list[bytes] = []

    async def submit_raw(self, raw: bytes) -> str:
        self.submitted.append(raw)
        raise RuntimeError("stop here: the claim reached the submitter")


@pytest.mark.parametrize("kind", list(_KINDS))
def test_a_claim_against_a_contract_SETTLED_AT_THE_TIP_is_refused_before_reveal(kind):
    """On the private path there is no ``eth_call`` preflight, so a claim against a settled
    contract is mined reverted with ``p`` in its calldata. Refusing to BUILD it is the only defence
    that keeps ``p`` in the process. Nothing may reach the submitter or a preflight."""
    sub = _PrivateSubmitter()
    rpc = _Rpc(_honest_runtime(_KINDS[kind][0]), settled=b"\x00" * 31 + b"\x01")
    _art, build, loc = _KINDS[kind]
    leg = build(rpc, private_submitter=sub)
    with pytest.raises(PreRevealAbort, match="already settled") as exc:
        asyncio.run(leg.claim(loc(), os.urandom(32)))
    assert sub.submitted == [] and rpc.preflights == []
    # Its own message, not the generic "claim abandoned" wrapper's, and it must not claim p is
    # still secret in the case where OUR earlier claim is what settled the contract.
    assert "If a claim from this address already succeeded" in str(exc.value)
    assert rpc.storage_reads[-1] == (_HTLC, SETTLED_SLOT, "latest")


@pytest.mark.parametrize("kind", list(_KINDS))
def test_an_UNSETTLED_contract_still_reaches_the_submitter(kind):
    """The honest path for the refusal above: the tip read must not stop a legitimate claim."""
    sub = _PrivateSubmitter()
    rpc = _Rpc(_honest_runtime(_KINDS[kind][0]))
    _art, build, loc = _KINDS[kind]
    leg = build(rpc, private_submitter=sub)
    with pytest.raises(ClaimNotConfirmed, match="reached the submitter"):
        asyncio.run(leg.claim(loc(), os.urandom(32)))
    assert len(sub.submitted) == 1
