"""``Erc20HtlcLeg`` — structure and construction guards.

Behavioural coverage of fund/claim/refund lives in the Anvil integration suite; per the RXinDexer
lesson a typed fake would hide exactly the layer worth testing. What is asserted here is the
STRUCTURE: that the token leg reuses the audited native path rather than reimplementing it, and
that the pieces which must not diverge cannot.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pyrxd.eth_wallet.erc20_leg import Erc20HtlcLeg
from pyrxd.eth_wallet.htlc_leg import EthHtlcContractLeg
from pyrxd.eth_wallet.tokens import Erc20Token, token_for
from pyrxd.security.errors import ValidationError
from pyrxd.security.secrets import PrivateKeyMaterial

_ARTIFACT = json.loads((Path(__file__).parent / "fixtures" / "Erc20Htlc.json").read_text())


def _key() -> PrivateKeyMaterial:
    import os

    return PrivateKeyMaterial(os.urandom(32))  # never a hand-written test key


class _Rpc:
    """Minimal stand-in; no call reaches it in these structural tests."""


def _leg(*, token: Erc20Token | None = None, chain_id: int = 1) -> Erc20HtlcLeg:
    return Erc20HtlcLeg(
        token=token if token is not None else token_for("USDC", chain_id),
        rpc=_Rpc(),
        signing_key=_key(),
        chain_id=chain_id,
        artifact=_ARTIFACT,
    )


class TestItReusesTheAuditedNativePathRatherThanReimplementingIt:
    """The native leg has moved real value on mainnet. Adding a token must not edit it."""

    def test_it_is_a_subclass_not_a_fork(self) -> None:
        assert issubclass(Erc20HtlcLeg, EthHtlcContractLeg)

    @pytest.mark.parametrize(
        "method",
        ["claim", "refund", "fetch_claim_artifacts", "assert_claim_provenance", "is_final", "claim_finality_verdict"],
    )
    def test_the_settlement_and_secret_paths_are_inherited_UNCHANGED(self, method: str) -> None:
        """These work untouched only because Erc20Htlc.sol was given the same claim(bytes32) /
        refund() signatures and the same un-indexed Claimed(bytes32) event. If a future contract
        change broke that symmetry, this pin is what would notice."""
        assert getattr(Erc20HtlcLeg, method) is getattr(EthHtlcContractLeg, method)

    def test_only_funding_and_verification_are_overridden(self) -> None:
        overridden = {
            name
            for name in dir(EthHtlcContractLeg)
            if not name.startswith("__")
            and callable(getattr(EthHtlcContractLeg, name, None))
            and getattr(Erc20HtlcLeg, name, None) is not getattr(EthHtlcContractLeg, name, None)
        }
        assert overridden == {"fund", "verify_funded"}, f"unexpected divergence: {overridden}"

    def test_it_still_satisfies_the_counter_chain_port(self) -> None:
        from pyrxd.gravity.counter_chain_leg import CounterChainLeg

        assert issubclass(Erc20HtlcLeg, CounterChainLeg)


class TestConstructionBindsTheAssetToTheChain:
    def test_a_token_pinned_to_another_chain_is_refused(self) -> None:
        """A token address means nothing without its chain id — the same string is a different
        asset elsewhere, and locking it would hand the counterparty something they did not price."""
        base_usdc = token_for("USDC", 8453)
        with pytest.raises(ValidationError, match="pinned to chain id"):
            _leg(token=base_usdc, chain_id=1)

    def test_a_non_registry_token_is_refused(self) -> None:
        with pytest.raises(ValidationError, match="Erc20Token"):
            _leg(token="0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")  # type: ignore[arg-type]

    def test_the_honest_path_constructs(self) -> None:
        """A guard that refuses valid work is a bug: matching token and chain must just work."""
        for chain_id in (1, 8453, 11155111):
            leg = _leg(chain_id=chain_id)
            assert leg.token.chain_id == chain_id
            assert leg.token.decimals == 6

    def test_the_signing_key_guard_is_inherited(self) -> None:
        """Plaintext keys are refused by the parent; the subclass must not have opened a hole."""
        with pytest.raises(ValidationError, match="PrivateKeyMaterial"):
            Erc20HtlcLeg(
                token=token_for("USDC", 1),
                rpc=_Rpc(),
                signing_key="deadbeef",  # type: ignore[arg-type]
                chain_id=1,
                artifact=_ARTIFACT,
            )


class TestTheArtifactAndTheRegistryAgree:
    def test_the_constructor_takes_the_token_and_amount_the_leg_passes(self) -> None:
        """`fund` passes six constructor args. A mismatch here is an ABI encode error at runtime,
        on the funding path, with gas already spent."""
        (ctor,) = [e for e in _ARTIFACT["abi"] if e.get("type") == "constructor"]
        assert [i["type"] for i in ctor["inputs"]] == [
            "bytes32",
            "address",
            "address",
            "uint256",
            "address",
            "uint256",
        ]


class TestATokenSwapIsReachableThroughTheRealStack:
    """Reachability, asserted rather than assumed.

    Merging code nothing can reach is the pattern behind #468 and the `pyrxd[eth]` bug, so the
    question "can a caller actually drive a USDC swap?" gets a test rather than a claim. The
    answer is yes via the library: `Erc20HtlcLeg` -> `EthLeg` -> coordinator. There is deliberately
    no CLI path — the shipped CLI has zero broadcast surface for the cross-chain stack, which a
    four-reviewer panel chose to keep until the audit clears.
    """

    def test_the_token_leg_composes_into_the_coordinator_shaped_adapter(self) -> None:
        from pyrxd.gravity.eth_leg import EthLeg

        leg = _leg()
        adapter = EthLeg(
            contract_leg=leg,
            network="mainnet",
            claim_to="0x" + "44" * 20,
            refund_to="0x" + "55" * 20,
            eth_timeout_unix_s=1_800_000_000,
        )
        assert adapter is not None, "EthLeg must accept a token contract leg unmodified"

    def test_the_adapter_reports_a_token_amount_in_base_units(self) -> None:
        """`locked_amount` feeds the coordinator's bind against `terms.value_amount`. Both are the
        token's base units, so the comparison is unit-consistent end to end."""
        from pyrxd.eth_wallet.locator import Erc20HtlcLocator
        from pyrxd.gravity.eth_leg import EthLeg

        adapter = EthLeg(
            contract_leg=_leg(),
            network="mainnet",
            claim_to="0x" + "44" * 20,
            refund_to="0x" + "55" * 20,
            eth_timeout_unix_s=1_800_000_000,
        )
        loc = Erc20HtlcLocator(
            chain_id=1,
            contract_address="0x" + "11" * 20,
            deploy_tx_hash="0x" + "22" * 32,
            hashlock="0x" + "33" * 32,
            claimant="0x" + "44" * 20,
            refundee="0x" + "55" * 20,
            timeout=1_800_000_000,
            amount_wei=12_345_678,  # 12.345678 USDC
            token_address="0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
        )
        assert adapter.locked_amount(loc) == 12_345_678
