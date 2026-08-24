"""The durable-record half of the ERC-20 counter-leg.

The hazard this file exists to prevent, stated plainly: a token swap whose amount is denominated
in USDC's 6 decimals, read by a binary that believes ETH amounts are wei, is a 10^12 error in the
funded-amount bind. The defence is the **chain tag**, and nothing else — `schema_version` is
written but never read back, so bumping it would accomplish nothing.
"""

from __future__ import annotations

import dataclasses
import pytest

from pyrxd.eth_wallet.locator import Erc20HtlcLocator, EthHtlcLocator
from pyrxd.gravity.swap_state import SwapRecord
from pyrxd.security.errors import ValidationError


def _erc20_locator(**over) -> Erc20HtlcLocator:
    kw = dict(
        chain_id=1,
        contract_address="0x" + "11" * 20,
        deploy_tx_hash="0x" + "22" * 32,
        hashlock="0x" + "33" * 32,
        claimant="0x" + "44" * 20,
        refundee="0x" + "55" * 20,
        timeout=1_800_000_000,
        amount_wei=12_345_678,  # 12.345678 USDC in BASE UNITS, not wei
        token_address="0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
    )
    kw.update(over)
    return Erc20HtlcLocator(**kw)


class TestAnOlderBinaryCannotMisreadATokenRecord:
    def test_a_token_record_does_NOT_serialise_as_chain_eth(self) -> None:
        """THE test. `Erc20HtlcLocator` subclasses `EthHtlcLocator`, so an isinstance branch in
        `to_dict` would have tagged it "eth" — and a reader that knows only "eth" would decode the
        6-decimal amount as wei without complaint. Reading `CHAIN_TAG` off the locator is what
        makes a missing branch impossible."""
        from pyrxd.gravity.swap_state import SwapState

        rec = SwapRecord(state=SwapState.NEGOTIATED, terms=_token_terms(), counterchain_locator=_erc20_locator())
        tag = rec.to_dict()["counterchain_locator"]["chain"]
        assert tag == "eth-erc20", tag
        assert tag != "eth", "a token record tagged 'eth' is the 10^12 misread"

    def test_an_unknown_tag_is_REFUSED_which_is_what_protects_old_readers(self) -> None:
        """A binary predating this change lands in the else and refuses. That refusal is the whole
        backward-compatibility story — `schema_version` is never read, so it protects nothing."""
        from pyrxd.gravity.swap_state import SwapState

        d = SwapRecord(
            state=SwapState.NEGOTIATED, terms=_token_terms(), counterchain_locator=_erc20_locator()
        ).to_dict()
        d["counterchain_locator"]["chain"] = "eth-something-newer"
        with pytest.raises(ValidationError, match="unknown counterchain_locator chain"):
            SwapRecord.from_dict(d)

    def test_a_native_eth_record_is_unchanged_byte_for_byte(self) -> None:
        """Existing swaps must serialise exactly as before — this change must be invisible to them."""
        from pyrxd.gravity.swap_state import SwapState

        native = EthHtlcLocator(
            chain_id=1,
            contract_address="0x" + "11" * 20,
            deploy_tx_hash="0x" + "22" * 32,
            hashlock="0x" + "33" * 32,
            claimant="0x" + "44" * 20,
            refundee="0x" + "55" * 20,
            timeout=1_800_000_000,
            amount_wei=10**15,
        )
        d = SwapRecord(state=SwapState.NEGOTIATED, terms=_terms(), counterchain_locator=native).to_dict()
        assert d["counterchain_locator"]["chain"] == "eth"
        assert d["schema_version"] == 2, "the ETH wire form must not shift under existing swaps"
        assert "token_address" not in d["counterchain_locator"]["locator"]

    def test_a_token_record_round_trips(self) -> None:
        from pyrxd.gravity.swap_state import SwapState

        rec = SwapRecord(state=SwapState.NEGOTIATED, terms=_token_terms(), counterchain_locator=_erc20_locator())
        back = SwapRecord.from_dict(rec.to_dict())
        assert isinstance(back.counterchain_locator, Erc20HtlcLocator)
        assert back.counterchain_locator == rec.counterchain_locator
        assert back.counterchain_locator.amount_base_units == 12_345_678


class TestTheLocatorCannotBeAmbiguousAboutItsAsset:
    def test_the_token_address_is_required(self) -> None:
        """An amount without the token it is denominated in is not interpretable."""
        with pytest.raises(ValidationError, match="token_address"):
            _erc20_locator(token_address="")

    def test_a_malformed_token_address_is_refused(self) -> None:
        with pytest.raises(ValidationError):
            _erc20_locator(token_address="0xnothex")

    def test_the_address_is_normalised_so_comparison_cannot_miss_on_case(self) -> None:
        loc = _erc20_locator()
        assert loc.token_address == loc.token_address.lower()

    def test_it_still_satisfies_every_eth_locator_site(self) -> None:
        """Six of seven isinstance sites in the coordinator are settlement/finality paths that
        genuinely apply to a token swap. Subclassing is what lets them stay untouched."""
        assert isinstance(_erc20_locator(), EthHtlcLocator)


def _terms():
    """An ETH-counter-chain terms object. ``value_amount`` is in the TOKEN's base units here —
    12.345678 USDC — which is exactly the number an older reader would take for wei."""
    import hashlib
    import os

    from pyrxd.gravity import swap_state as t
    from pyrxd.gravity.swap_state import NegotiatedTerms

    return NegotiatedTerms(
        hashlock=hashlib.sha256(os.urandom(32)).digest(),
        btc_sats=100_000,
        radiant_amount=1_000,
        t_btc=t.Timelock(144, t.TimeUnit.BLOCKS),
        t_rxd=t.Timelock(72, t.TimeUnit.BLOCKS),
        asset_variant="rxd",
        genesis_ref=b"",
        taker_dest_hash=b"\x11" * 32,
        maker_dest_hash=b"\x22" * 32,
        btc_claim_pubkey_xonly=b"\x00" * 32,  # an ETH swap requires the zero placeholder
        btc_refund_pubkey_xonly=b"\x00" * 32,
        counter_chain="eth",
        value_amount=12_345_678,
        eth_timeout_unix_s=1_800_000_000,
    )


class TestTheTermsCarryTheAssetSoTheUnitIsKnowable:
    """`counter_chain` alone cannot tell you the unit: a USDC swap is still "eth" while its amount
    is in 6-decimal base units rather than wei. The token address is what closes that gap, and it
    is NEGOTIATED rather than derived from the locator because both parties must agree the asset
    before either funds anything."""

    def test_a_native_eth_swap_carries_no_token_and_serialises_unchanged(self) -> None:
        d = _terms().to_dict()
        assert "token_address" not in d, "the native wire form must not grow a field"

    def test_a_token_swap_round_trips_the_asset(self) -> None:
        from pyrxd.gravity.swap_state import NegotiatedTerms

        usdc = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
        terms = _terms_with_token(usdc)
        assert terms.token_address == usdc.lower(), "normalised so comparison cannot miss on case"
        back = NegotiatedTerms.from_dict(terms.to_dict())
        assert back.token_address == usdc.lower()

    def test_a_token_on_a_btc_counter_chain_is_refused(self) -> None:
        """The combination cannot mean anything — a BTC leg has no ERC-20."""
        import dataclasses

        with pytest.raises(ValidationError, match="only meaningful on an ETH counter chain"):
            dataclasses.replace(_terms(), counter_chain="btc", value_amount=100_000, token_address="0x" + "11" * 20)

    @pytest.mark.parametrize("bad", ["0xnothex" + "0" * 34, "not-an-address", "0x1234"])
    def test_a_malformed_token_address_is_refused(self, bad: str) -> None:
        import dataclasses

        with pytest.raises(ValidationError, match="token_address"):
            dataclasses.replace(_terms(), token_address=bad)

    def test_legacy_records_without_the_field_still_load(self) -> None:
        """Every persisted swap predates this field. They must deserialise as native legs."""
        from pyrxd.gravity.swap_state import NegotiatedTerms

        d = _terms().to_dict()
        d.pop("token_address", None)
        assert NegotiatedTerms.from_dict(d).token_address == ""


def _terms_with_token(addr: str):
    import dataclasses

    return dataclasses.replace(_terms(), token_address=addr)


class TestTheNoChangeDecisionsAreDeliberateNotAccidental:
    """Several coordinator sites accept the token variant *without edits*, because
    `Erc20HtlcLocator`/`Erc20HtlcLeg` subclass their native counterparts. That is a design choice
    — six of seven isinstance sites are settlement paths that genuinely apply — and choices need
    pinning, otherwise the next person cannot tell them from an oversight.

    Each assertion below is a place the mainnet-proven coordinator was deliberately NOT edited.
    """

    def test_the_coordinators_fund_return_check_admits_a_token_locator(self) -> None:
        """`swap_coordinator.py:1435` isinstance-checks fund()'s return. No edit needed."""
        from pyrxd.gravity.swap_state import BtcHtlcLocator

        assert isinstance(_erc20_locator(), (BtcHtlcLocator, EthHtlcLocator))

    def test_the_EthLeg_adapter_accepts_a_token_contract_leg(self) -> None:
        """`EthLeg.__init__` isinstance-checks contract_leg. No edit needed."""
        from pyrxd.eth_wallet.erc20_leg import Erc20HtlcLeg
        from pyrxd.eth_wallet.htlc_leg import EthHtlcContractLeg

        assert issubclass(Erc20HtlcLeg, EthHtlcContractLeg)

    def test_locked_amount_and_the_bind_stay_in_ONE_unit(self) -> None:
        """The coordinator compares `locked_amount(locator)` to `terms.value_amount`. Both are the
        token's base units for a token swap, so the bind is unit-consistent with no edit — this is
        the assertion that would fail if either side were ever converted."""
        loc = _erc20_locator(amount_wei=12_345_678)
        terms = _terms()  # value_amount 12_345_678, the same base units
        assert loc.amount_base_units == terms.value_amount
        assert loc.amount_wei == loc.amount_base_units, "one storage field, two names, one unit"

    def test_the_maker_verify_gate_is_extended_by_OVERRIDE_not_by_editing_the_coordinator(self) -> None:
        """`EthLeg` calls `self._leg.verify_funded(...)`, so a token leg's override — which binds
        the on-chain token address, asserts decimals and checks the TOKEN balance — runs through
        the existing FSM-enforced gate with no coordinator change."""
        from pyrxd.eth_wallet.erc20_leg import Erc20HtlcLeg
        from pyrxd.eth_wallet.htlc_leg import EthHtlcContractLeg

        assert Erc20HtlcLeg.verify_funded is not EthHtlcContractLeg.verify_funded


class TestTheColdRecoveryPathAlreadyCoversATokenHtlc:
    """The offline recovery toolkit (#374) needs no token-specific code, and this proves it.

    `recover_preimage_from_eth_claim` binds provenance to the per-swap CONTRACT ADDRESS and scrapes
    `p` from calldata and contract-emitted logs. Both are byte-identical for a token HTLC because
    `Erc20Htlc.sol` keeps `claim(bytes32)` and the un-indexed `Claimed(bytes32)` event — the same
    symmetry that let the leg inherit its settlement methods.

    Worth an explicit test because the ORPHAN case is real and pre-existing: `fund()` returns a
    locator only after funding lands, so a crash in between leaves a funded contract the record
    does not reference. The native leg has the identical window (deploy → receipt → return). The
    cold path is how an operator recovers from it, and it must work for the new asset too.
    """

    def test_p_is_recovered_from_a_token_htlc_claim(self) -> None:
        import hashlib
        import os

        from pyrxd.cli.swap_recovery import recover_preimage_from_eth_claim

        p = os.urandom(32)
        h = hashlib.sha256(p).digest()
        contract = "0x" + "ab" * 20

        rec = recover_preimage_from_eth_claim(
            hashlock=h,
            contract_address=contract,
            claim_tx={"hash": "0x" + "cd" * 32, "to": contract, "input": "0xaabbccdd" + p.hex()},
            logs=[{"address": contract, "data": "0x" + p.hex(), "topics": ["0x" + "11" * 32]}],
        )
        assert bytes.fromhex(rec.preimage_hex) == p
        assert rec.hashlock_hex == h.hex()

    def test_a_claim_on_someone_elses_contract_is_still_refused(self) -> None:
        """The provenance bind is the per-swap address, and it must not weaken for tokens: a
        decoy that shares the hashlock but belongs to another swap has to be refused."""
        import hashlib
        import os

        from pyrxd.cli.swap_recovery import ProvenanceRefused, recover_preimage_from_eth_claim

        p = os.urandom(32)
        h = hashlib.sha256(p).digest()
        with pytest.raises(ProvenanceRefused):
            recover_preimage_from_eth_claim(
                hashlock=h,
                contract_address="0x" + "ab" * 20,
                claim_tx={"hash": "0x" + "cd" * 32, "to": "0x" + "ff" * 20, "input": "0xaabbccdd" + p.hex()},
                logs=[{"address": "0x" + "ff" * 20, "data": "0x" + p.hex(), "topics": []}],
            )


_USDC_MAINNET = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"


def _token_terms():
    """Terms that NAME the asset, which is what a real token swap carries. Pairing a token locator
    with native terms is now refused at record construction — the guard that would have caught the
    producers returning the wrong locator type."""
    import dataclasses

    return dataclasses.replace(_terms(), token_address=_USDC_MAINNET)


class TestTheProducersEmitTheTaggedLocator:
    """THE regression class for the critical bug this branch shipped with.

    The tag mechanism was correct and fully tested — against locators built BY HAND in tests.
    Neither production producer ever emitted one: `Erc20HtlcLeg.fund` and `EthLeg.expected_locator`
    both returned the plain parent, because `fund` was written before the token locator existed and
    nothing went back to update it. So every real token swap would have persisted as `chain: "eth"`
    carrying 6-decimal base units in a field every reader takes for wei — the exact 10^12 error the
    feature was built to prevent, as the DEFAULT behaviour.

    9,442 tests passed with that bug in place. These assert the PRODUCERS, not the mechanism.
    """

    def test_the_maker_side_producer_emits_a_token_locator(self) -> None:
        import os

        from pyrxd.eth_wallet.erc20_leg import Erc20HtlcLeg
        from pyrxd.eth_wallet.tokens import token_for
        from pyrxd.gravity.eth_leg import EthLeg
        from pyrxd.security.secrets import PrivateKeyMaterial

        artifact = _artifact()
        leg = Erc20HtlcLeg(
            token=token_for("USDC", 1),
            rpc=object(),
            signing_key=PrivateKeyMaterial(os.urandom(32)),
            chain_id=1,
            artifact=artifact,
        )
        adapter = EthLeg(
            contract_leg=leg,
            network="mainnet",
            claim_to="0x" + "44" * 20,
            refund_to="0x" + "55" * 20,
            eth_timeout_unix_s=1_800_000_000,
        )
        loc = adapter.expected_locator(_token_terms(), contract_address="0x" + "11" * 20)
        assert isinstance(loc, Erc20HtlcLocator), f"got {type(loc).__name__} — the tag would say 'eth'"
        assert loc.CHAIN_TAG == "eth-erc20"
        assert loc.token_address == _USDC_MAINNET.lower()

    def test_a_native_leg_still_emits_a_native_locator(self) -> None:
        """The honest path: nothing about the native corridor may change."""
        import os

        from pyrxd.eth_wallet.htlc_leg import EthHtlcContractLeg
        from pyrxd.gravity.eth_leg import EthLeg
        from pyrxd.security.secrets import PrivateKeyMaterial

        leg = EthHtlcContractLeg(
            rpc=object(),
            signing_key=PrivateKeyMaterial(os.urandom(32)),
            chain_id=1,
            artifact=_native_artifact(),
        )
        adapter = EthLeg(
            contract_leg=leg,
            network="mainnet",
            claim_to="0x" + "44" * 20,
            refund_to="0x" + "55" * 20,
            eth_timeout_unix_s=1_800_000_000,
        )
        loc = adapter.expected_locator(_terms(), contract_address="0x" + "11" * 20)
        assert type(loc) is EthHtlcLocator
        assert loc.CHAIN_TAG == "eth"

    def test_a_token_leg_refuses_terms_naming_a_DIFFERENT_token(self) -> None:
        import dataclasses
        import os

        from pyrxd.eth_wallet.erc20_leg import Erc20HtlcLeg
        from pyrxd.eth_wallet.tokens import token_for
        from pyrxd.gravity.eth_leg import EthLeg
        from pyrxd.security.secrets import PrivateKeyMaterial

        leg = Erc20HtlcLeg(
            token=token_for("USDC", 1),
            rpc=object(),
            signing_key=PrivateKeyMaterial(os.urandom(32)),
            chain_id=1,
            artifact=_artifact(),
        )
        adapter = EthLeg(
            contract_leg=leg,
            network="mainnet",
            claim_to="0x" + "44" * 20,
            refund_to="0x" + "55" * 20,
            eth_timeout_unix_s=1_800_000_000,
        )
        other = dataclasses.replace(_token_terms(), token_address="0x" + "99" * 20)
        with pytest.raises(ValidationError, match="pinned to"):
            adapter.expected_locator(other, contract_address="0x" + "11" * 20)


def _artifact() -> dict:
    import json
    from pathlib import Path

    return json.loads((Path(__file__).parent / "fixtures" / "Erc20Htlc.json").read_text())


def _native_artifact() -> dict:
    import json
    from pathlib import Path

    return json.loads((Path(__file__).parent / "fixtures" / "EthHtlc.json").read_text())


class TestTheRecordRefusesAnAssetDisagreementBeforeItIsDurable:
    """The `SwapRecord.__post_init__` asset-agreement guard had NO test until round 5.

    Chain agreement is not asset agreement: both legs are `counter_chain == "eth"`, so the
    chain check cannot tell a native leg from a token leg. This guard is the record-level
    chokepoint that made the round-1 CRITICAL (producers returning the parent locator type)
    unrepresentable rather than merely fixed at the two call sites that existed that day.
    Deleting the whole block used to pass the suite, which is how the class recurs.
    """

    def test_a_token_locator_with_no_named_token_is_refused(self) -> None:
        """Empty `terms.token_address` describes the swap as native ETH while the locator holds
        USDC — the 10^12 misread, written straight to disk."""
        from pyrxd.gravity.swap_state import SwapState

        with pytest.raises(ValidationError, match="a token locator requires"):
            SwapRecord(
                state=SwapState.NEGOTIATED,
                terms=dataclasses.replace(_token_terms(), token_address=""),
                counterchain_locator=_erc20_locator(),
            )

    def test_a_token_locator_naming_a_DIFFERENT_token_is_refused(self) -> None:
        """Terms say one asset, the funded contract holds another. The record would misdescribe
        what was funded, and every later reader — including refund — trusts the record."""
        from pyrxd.gravity.swap_state import SwapState

        with pytest.raises(ValidationError, match="would misdescribe what was funded"):
            SwapRecord(
                state=SwapState.NEGOTIATED,
                terms=dataclasses.replace(_token_terms(), token_address="0x" + "99" * 20),
                counterchain_locator=_erc20_locator(),
            )

    def test_a_NATIVE_locator_under_token_terms_is_refused(self) -> None:
        """The exact shape of the round-1 CRITICAL: `fund()` returned the parent `EthHtlcLocator`
        for a token swap. Its `amount_wei` would persist 6-decimal base units as wei."""
        from pyrxd.gravity.swap_state import SwapState

        native = EthHtlcLocator(
            chain_id=1,
            contract_address="0x" + "11" * 20,
            deploy_tx_hash="0x" + "22" * 32,
            hashlock="0x" + "33" * 32,
            claimant="0x" + "44" * 20,
            refundee="0x" + "55" * 20,
            timeout=1_800_000_000,
            amount_wei=12_345_678,
        )
        with pytest.raises(ValidationError, match="the locator is a NATIVE"):
            SwapRecord(
                state=SwapState.NEGOTIATED,
                terms=_token_terms(),
                counterchain_locator=native,
            )

    def test_the_HONEST_pairing_still_constructs(self) -> None:
        """A guard that refuses valid work is a bug. Terms and locator naming the same token —
        including in differing case, since both sides normalise — must still build."""
        from pyrxd.gravity.swap_state import SwapState

        rec = SwapRecord(
            state=SwapState.NEGOTIATED,
            terms=dataclasses.replace(_token_terms(), token_address=_USDC_MAINNET.upper().replace("0X", "0x")),
            counterchain_locator=_erc20_locator(token_address=_USDC_MAINNET.lower()),
        )
        assert rec.counterchain_locator is not None
