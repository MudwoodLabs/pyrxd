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
        ["refund", "fetch_claim_artifacts", "assert_claim_provenance", "is_final", "claim_finality_verdict"],
    )
    def test_the_settlement_and_secret_paths_are_inherited_UNCHANGED(self, method: str) -> None:
        """These work untouched only because Erc20Htlc.sol was given the same claim(bytes32) /
        refund() signatures and the same un-indexed Claimed(bytes32) event. If a future contract
        change broke that symmetry, this pin is what would notice."""
        assert getattr(Erc20HtlcLeg, method) is getattr(EthHtlcContractLeg, method)

    def test_claim_WRAPS_the_parent_rather_than_reimplementing_it(self) -> None:
        """`claim` is the one settlement method that diverges, and only to add a precondition.

        It must still delegate: the audited claim path — private submission, receipt handling,
        the whole thing — is the parent's. What the override adds is the pre-reveal freeze gate,
        which sits here because broadcasting claim(preimage) IS the reveal.
        """
        import inspect

        src = inspect.getsource(Erc20HtlcLeg.claim)
        assert "assert_not_frozen_before_reveal" in src, "the gate must run before the reveal"
        assert "super().claim(" in src, "settlement must delegate, not be reimplemented"

    def test_only_funding_verification_and_the_gated_claim_are_overridden(self) -> None:
        overridden = {
            name
            for name in dir(EthHtlcContractLeg)
            if not name.startswith("__")
            and callable(getattr(EthHtlcContractLeg, name, None))
            and getattr(Erc20HtlcLeg, name, None) is not getattr(EthHtlcContractLeg, name, None)
        }
        assert overridden == {"fund", "verify_funded", "claim"}, f"unexpected divergence: {overridden}"

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


class TestTheTokenLegAcceptsEip7702DelegatedRecipients:
    """#478. The EOA-only check is load-bearing for the NATIVE leg — an ETH send executes the
    recipient's code, so a delegate that reverts on receive locks the funds. It is meaningless for
    the TOKEN leg, whose payout calls the token contract and never the recipient.

    An EIP-7702 delegated EOA carries 23 bytes of code (`0xef0100` + delegate) and is an ordinary
    EOA the user holds the key to. Both anvil dev addresses carry one on mainnet today, so this is
    a live population, not a hypothetical.
    """

    def test_the_token_leg_admits_delegates_but_NOT_arbitrary_contracts(self) -> None:
        """The fix must not outgrow the finding. Delegated EOAs are admitted; a contract recipient
        stays refused, because that is a different thing that was never the problem."""
        import inspect

        src = inspect.getsource(Erc20HtlcLeg.verify_funded)
        # Wiring pin ONLY — the behaviour lives in `test_eoa_recipient_policy.py`, which drives
        # verify_funded with real delegation and contract bytecode. A sibling assertion here used
        # to check `"require_eoa_recipients=False" not in src` for a parameter that had already
        # been renamed away, so it could never fail. A vacuous assertion beside a real one is worse
        # than none: it reads as coverage.
        assert "allow_delegated_eoa_recipients=True" in src

    def test_the_native_default_is_unchanged(self) -> None:
        """The native leg must keep the check: nothing about that corridor may loosen."""
        import inspect

        from pyrxd.eth_wallet.htlc_leg import EthHtlcContractLeg

        param = inspect.signature(EthHtlcContractLeg.verify_funded).parameters["allow_delegated_eoa_recipients"]
        assert param.default is False, "the native leg must not admit delegates by default"

    def test_the_native_refusal_names_eip_7702_when_that_is_what_it_found(self) -> None:
        """The old message said "not an EOA", which is actively wrong for a delegated account and
        would send an operator looking for a bug that is not there."""
        import inspect

        from pyrxd.eth_wallet.htlc_leg import EthHtlcContractLeg

        src = inspect.getsource(EthHtlcContractLeg.verify_funded)
        assert "EIP-7702" in src, "the message must name what it actually found"
        assert "is_eip7702_delegation(" in src, "detection must go through the shared predicate"


class TestOnlyTheExactDelegationShapeIsAdmitted:
    """Executes the PRODUCTION predicate rather than re-deriving its rule.

    The first version of this class recomputed `len(code) == 23 and code[:3] == 0xef0100` inline
    and asserted on that — a test of the test. It would have passed against the **prefix-only**
    check an earlier commit on this branch actually shipped, because the production code never ran.
    That is why the rule now lives in a named predicate: so this can call it.
    """

    @pytest.mark.parametrize(
        ("label", "code", "is_delegation"),
        [
            ("7702 designator, exactly 23 bytes", b"\xef\x01\x00" + b"\x11" * 20, True),
            ("7702 prefix but longer — a contract", b"\xef\x01\x00" + b"\x11" * 40, False),
            ("7702 prefix but shorter", b"\xef\x01\x00" + b"\x11" * 5, False),
            ("ordinary contract bytecode", b"\x60\x80\x60\x40" * 10, False),
            ("empty — a plain EOA", b"", False),
        ],
    )
    def test_the_production_predicate_matches_only_the_exact_shape(self, label, code, is_delegation) -> None:
        from pyrxd.eth_wallet.htlc_leg import is_eip7702_delegation

        assert is_eip7702_delegation(code) is is_delegation, label

    def test_a_prefix_only_rule_would_fail_this(self) -> None:
        """Names the specific regression: prefix-matching admits a contract that starts 0xEF.
        EIP-3541 forbids DEPLOYING such code, but the check must not depend on that — a length
        test is what makes the shape unforgeable here."""
        from pyrxd.eth_wallet.htlc_leg import is_eip7702_delegation

        impostor = b"\xef\x01\x00" + b"\x11" * 40
        assert impostor[:3] == b"\xef\x01\x00", "the impostor does match on prefix"
        assert is_eip7702_delegation(impostor) is False, "but must not be treated as a delegation"

    def test_verify_funded_uses_the_predicate_rather_than_its_own_copy(self) -> None:
        """Two copies of a security rule drift. This pins that there is one."""
        import inspect

        from pyrxd.eth_wallet.htlc_leg import EthHtlcContractLeg

        src = inspect.getsource(EthHtlcContractLeg.verify_funded)
        assert "is_eip7702_delegation(" in src
        assert "0xef" not in src.lower().replace("0xef0100", ""), "no second inline copy of the rule"
