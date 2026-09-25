"""pyrxd pays the WAVE registration fee by default: the library half.

The decision is the maintainer's: registering a WAVE name pays the protocol's registration
fee, as the published WAVE protocol and Photonic do, and the only way out is an explicit
``pay_registration_fee=False`` (``--no-wave-registration-fee`` on the CLI). Every builder that
can register a name RETURNS the fee output for its caller to add; ``pyrxd glyph mint-nft`` PAYS
it (``tests/cli/test_wave_registration_fee_cli.py``). The fee is funded at REVEAL time from a plain
wallet input, as Photonic does — never from the commit.

What the fee IS comes from two sources pyrxd did not write, transcribed below and cited in
``src/pyrxd/glyph/wave_rules.py``:

- Photonic Wallet at ``becf41a731e78ab98fdd88652527d7dda12784c6``: ``calculateNameCost``
  (``packages/lib/src/wave.ts:55-66``) and the register page, which pays it to
  ``1GrwkQNJfjbEJjH25heszNZLpbZou8nfXG`` (``packages/app/src/pages/WaveRegister.tsx:132-152``);
- RXinDexer at ``ca8a6a4e77ef0ad3f24ec6f41cb0a73eb5f3651e``: ``wave_name_price``
  (``electrumx/server/wave_index.py:73-86``), ``WAVE_TREASURY_ADDRESS_DEFAULT``
  (``wave_index.py:65``) and ``validate_wave_name`` (``wave_index.py:287-310``), which decides
  what REGISTERS — and so what owes the fee.

And from one thing on chain: mainnet claim ``f644794b…`` (``fixtures/wave_update_chain_mainnet.json``)
pays the 6+ tier to that treasury at vout 2, funded by a third input from its commit
transaction. Every upstream file cited here is digest-pinned in
``fixtures/photonic_upstream_pin.json`` or ``fixtures/rxindexer_upstream_pin.json`` and watched by
``scripts/check_photonic_drift.py``.

The set of paths is DERIVED from the code (``TestThePathSetIsDerived``), not trusted to the door
table below.
"""

from __future__ import annotations

import ast
import asyncio
import dataclasses
import inspect
import json
import pathlib
from collections.abc import Callable
from typing import Any

import cbor2
import pytest

from pyrxd.cli import glyph_cmds
from pyrxd.constants import Network
from pyrxd.fee_models import SatoshisPerKilobyte
from pyrxd.glyph import builder as builder_module
from pyrxd.glyph.builder import CommitParams, CommitResult, GlyphBuilder, RevealParams
from pyrxd.glyph.fees import (
    MIN_COMMIT_OVERHEAD,
    REVEAL_SIG_PREFIX_BYTES,
    REVEAL_SIZE_SLACK_BYTES,
    assert_reveal_balances,
    check_reveal_funding,
    commit_value_for_reveal,
    estimate_reveal_fee,
    estimate_reveal_fee_for_metadata,
    measure_reveal_fee,
)
from pyrxd.glyph.inspector import GlyphInspector
from pyrxd.glyph.mint import (
    PENDING_MINT_SCHEMA_VERSION_WITH_WAVE_FEE,
    GlyphMinter,
    JsonFilePendingStore,
    PendingMint,
    UnsafeNullPendingStore,
)
from pyrxd.glyph.payload import build_mutable_scriptsig, build_reveal_scriptsig_suffix, encode_payload
from pyrxd.glyph.script import build_commit_locking_script, build_nft_locking_script, hash_payload
from pyrxd.glyph.types import GlyphMetadata, GlyphProtocol, GlyphRef
from pyrxd.glyph.wave import build_wave_metadata
from pyrxd.glyph.wave_rules import (
    FEE_DECLINED,
    WAVE_TREASURY_ADDRESS,
    WaveRegistrationFee,
    format_rxd,
    registered_label_in_scriptsig,
    wave_registered_label,
    wave_registration_fee_for,
    wave_registration_price,
)
from pyrxd.keys import PrivateKey
from pyrxd.script.type import P2PKH
from pyrxd.security.errors import InsufficientFundsError, ValidationError
from pyrxd.security.types import Hex20, Txid
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_output import TransactionOutput

_FIXTURE = pathlib.Path(__file__).parent / "fixtures" / "wave_update_chain_mainnet.json"
_MINT = next(t for t in json.loads(_FIXTURE.read_text())["transactions"] if t["txid"].startswith("f644794b"))
_MINT_TX = Transaction.from_hex(_MINT["raw"])
_MINT_CBOR: bytes = GlyphInspector().extract_reveal_cbor(_MINT_TX.inputs[0].unlocking_script.serialize())
_MINT_DICT: dict = cbor2.loads(_MINT_CBOR)
TARGET = _MINT_DICT["attrs"]["target"]
PKH = Hex20(bytes(range(20)))
TXID = "ab" * 32
_SRC = pathlib.Path(__file__).resolve().parent.parent / "src" / "pyrxd"


# ───────────────────────────────────────── the two sources, transcribed ──


def _photonic_calculate_name_cost(full_name: str) -> int:
    """``calculateNameCost``, ``packages/lib/src/wave.ts:55-66`` at ``becf41a7``, line for line."""
    name = full_name.split(".")[0]
    if not name:
        return 0
    length = len(name)
    if length <= 3:
        return 10_000_000_000
    if length == 4:
        return 5_000_000_000
    if length == 5:
        return 1_000_000_000
    return 500_000_000


def _rxindexer_wave_name_price(bare_name: str) -> int:
    """``wave_name_price``, ``electrumx/server/wave_index.py:73-86`` at ``ca8a6a4e``, line for line."""
    length = len(bare_name)
    if length <= 3:
        return 10_000_000_000
    if length == 4:
        return 5_000_000_000
    if length == 5:
        return 1_000_000_000
    return 500_000_000


_WAVE_CHARS = "abcdefghijklmnopqrstuvwxyz0123456789-"  # wave_index.py:37


def _rxindexer_validate_wave_name(name: str) -> bool:
    """``validate_wave_name``, ``electrumx/server/wave_index.py:287-310`` at ``ca8a6a4e``."""
    if not name:
        return False
    if len(name) > 63:
        return False
    if name.startswith("-") or name.endswith("-"):
        return False
    if "--" in name and not name.lower().startswith("xn--"):
        return False
    return all(char in _WAVE_CHARS for char in name.lower())


#: ``const feeAddress = "1GrwkQNJfjbEJjH25heszNZLpbZou8nfXG";`` (``WaveRegister.tsx:133``)
_PHOTONIC_FEE_ADDRESS = "1GrwkQNJfjbEJjH25heszNZLpbZou8nfXG"
#: ``WAVE_TREASURY_ADDRESS_DEFAULT = '1GrwkQNJfjbEJjH25heszNZLpbZou8nfXG'`` (``wave_index.py:65``)
_RXINDEXER_TREASURY = "1GrwkQNJfjbEJjH25heszNZLpbZou8nfXG"
#: The script the mainnet claim actually paid, read off the chain rather than built here.
_TREASURY_SCRIPT_ON_CHAIN: bytes = _MINT_TX.outputs[2].locking_script.serialize()


# ─────────────────────────────────────────────────────────────────── helpers ──


def _claim(label: str = "alice", *, p: list[int] | None = None, **extra: Any) -> dict:
    """A WAVE claim in Photonic's shape (``createWaveNameMetadata``)."""
    d: dict = {
        "v": 2,
        "p": p if p is not None else [GlyphProtocol.NFT, GlyphProtocol.MUT, GlyphProtocol.WAVE],
        "name": f"{label}.rxd",
        "type": "wave_name",
        "attrs": {"name": label, "domain": "rxd", "target": TARGET, "target_type": "address"},
    }
    d.update(extra)
    return d


def _metadata(d: dict) -> GlyphMetadata:
    return build_wave_metadata(qualified_name=d["name"], target=TARGET)


_OTHER_REF = GlyphRef(txid=Txid("cd" * 32), vout=0)
_OTHER_SCRIPT = build_nft_locking_script(PKH, _OTHER_REF)

#: Every pyrxd path that builds a registering reveal's pieces or prices it, fed a claim and extra
#: keyword arguments, returning the fee that path reports. Which reveal builders EXIST is derived
#: in ``TestThePathSetIsDerived``; this table must cover what that finds.
_DOORS: dict[str, Callable[[dict, dict], WaveRegistrationFee | None]] = {
    "prepare_reveal": lambda d, kw: (
        GlyphBuilder()
        .prepare_reveal(
            RevealParams(
                commit_txid=TXID,
                commit_vout=0,
                commit_value=10_000,
                cbor_bytes=cbor2.dumps(d),
                owner_pkh=PKH,
                is_nft=True,
                **kw,
            )
        )
        .registration_fee_output
    ),
    "prepare_mutable_reveal": lambda d, kw: (
        GlyphBuilder().prepare_mutable_reveal(TXID, 0, cbor2.dumps(d), PKH, **kw).registration_fee_output
    ),
    "prepare_wave_reveal": lambda d, kw: (
        GlyphBuilder().prepare_wave_reveal(TXID, 0, cbor2.dumps(d), PKH, d["name"], **kw).registration_fee_output
    ),
    "prepare_container_reveal": lambda d, kw: (
        GlyphBuilder()
        .prepare_container_reveal(TXID, 0, cbor2.dumps({**d, "p": [*d["p"], GlyphProtocol.CONTAINER]}), PKH, **kw)
        .registration_fee_output
    ),
    "prepare_authority_gated_reveal": lambda d, kw: (
        GlyphBuilder()
        .prepare_authority_gated_reveal(TXID, 0, cbor2.dumps(d), PKH, _OTHER_REF, _OTHER_SCRIPT, **kw)
        .registration_fee_output
    ),
    "prepare_container_child_reveal": lambda d, kw: (
        GlyphBuilder()
        .prepare_container_child_reveal(
            TXID,
            0,
            cbor2.dumps({**d, "in": [_OTHER_REF.to_bytes()]}),
            PKH,
            _OTHER_REF,
            container_script=_OTHER_SCRIPT,
            **kw,
        )
        .registration_fee_output
    ),
    "estimate_reveal_fee": lambda d, kw: (
        estimate_reveal_fee(cbor_bytes=cbor2.dumps(d), is_nft=True, **kw).registration_fee
    ),
    "estimate_reveal_fee_for_metadata": lambda d, kw: (
        estimate_reveal_fee_for_metadata(_metadata(d), **kw).registration_fee
    ),
}

#: One label per price tier, the tier edges included: 3 (the "<= 3" tier), 4, 5, 6 (the first
#: "6+") and 63 (the longest the indexer registers).
_TIER_LABELS = ["abc", "abcd", "abcde", "abcdef", "a" * 63]


# ─────────────────────────────────────────────────────────────── (1) the price ──


class TestThePrice:
    @pytest.mark.parametrize(
        ("label", "photons"),
        [
            ("a", 10_000_000_000),
            ("ab", 10_000_000_000),
            ("abc", 10_000_000_000),
            ("abcd", 5_000_000_000),
            ("abcde", 1_000_000_000),
            ("abcdef", 500_000_000),
            ("a" * 63, 500_000_000),
        ],
    )
    def test_each_tier_is_both_sources_value(self, label: str, photons: int) -> None:
        assert wave_registration_price(label) == photons
        assert _photonic_calculate_name_cost(f"{label}.rxd") == photons
        assert _rxindexer_wave_name_price(label) == photons

    @pytest.mark.parametrize("label", _TIER_LABELS)
    def test_the_qualified_name_prices_as_its_label(self, label: str) -> None:
        """Photonic prices ``fullName`` by the text before the first ``.``."""
        assert wave_registration_price(f"{label}.rxd") == wave_registration_price(label)

    def test_a_1_or_2_character_name_the_indexer_registers_costs_100_rxd(self) -> None:
        """RXinDexer registers 1-2 character labels (``WAVE_MIN_NAME_LENGTH`` is 1), and both
        sources price "3 or fewer" at 100 RXD: never less. pyrxd will not WRITE such a label,
        but when one is revealed it owes the top tier."""
        for label in ("a", "ab", "7"):
            assert _rxindexer_validate_wave_name(label)
            assert wave_registration_price(label) == 100 * 100_000_000

    def test_upper_case_is_priced_the_indexer_lower_cases_it(self) -> None:
        assert _rxindexer_validate_wave_name("ALICE")
        assert wave_registration_price("ALICE") == wave_registration_price("alice") == 1_000_000_000

    @pytest.mark.parametrize("bad", ["a" * 64, "", "-abc", "abc-", "a--b", "sub.alice.rxd", "alice.eth", b"alice", 5])
    def test_a_name_the_indexer_refuses_has_no_price(self, bad: object) -> None:
        if isinstance(bad, str) and "." not in bad:
            assert not _rxindexer_validate_wave_name(bad)
        with pytest.raises(ValidationError):
            wave_registration_price(bad)  # type: ignore[arg-type]

    def test_rxd_is_formatted_exactly(self) -> None:
        assert [format_rxd(wave_registration_price(label)) for label in _TIER_LABELS] == [
            "100 RXD",
            "50 RXD",
            "10 RXD",
            "5 RXD",
            "5 RXD",
        ]
        assert format_rxd(1) == "0.00000001 RXD"


# ────────────────────────────────────────────────────────────── (2) the treasury ──


class TestTheTreasury:
    def test_it_is_both_sources_address(self) -> None:
        assert WAVE_TREASURY_ADDRESS == _PHOTONIC_FEE_ADDRESS == _RXINDEXER_TREASURY

    def test_the_fee_script_is_the_one_the_mainnet_claim_paid(self) -> None:
        fee = WaveRegistrationFee("alice")
        assert fee.locking_script == _TREASURY_SCRIPT_ON_CHAIN
        assert fee.locking_script == P2PKH().lock(WAVE_TREASURY_ADDRESS).serialize()
        assert fee.is_published_treasury

    def test_value_and_script_are_derived_and_cannot_be_passed(self) -> None:
        with pytest.raises(TypeError):
            WaveRegistrationFee("alice", value=1)  # type: ignore[call-arg]
        with pytest.raises(TypeError):
            WaveRegistrationFee("alice", locking_script=b"\x51")  # type: ignore[call-arg]

    def test_a_named_treasury_is_paid_instead(self) -> None:
        addr = PrivateKey().public_key().address(network=Network.TESTNET)
        fee = WaveRegistrationFee("alice", addr)
        assert fee.locking_script == P2PKH().lock(addr).serialize() != _TREASURY_SCRIPT_ON_CHAIN
        assert not fee.is_published_treasury
        assert fee.value == wave_registration_price("alice")

    @pytest.mark.parametrize("bad", ["", "not-an-address", "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy", 5, None])
    def test_a_treasury_that_is_not_a_p2pkh_address_is_refused(self, bad: object) -> None:
        with pytest.raises(ValidationError, match="registration treasury"):
            WaveRegistrationFee("alice", bad)  # type: ignore[arg-type]


# ──────────────────────────────────────── (3) the mainnet claim, and where it pays ──


class TestTheMainnetClaimPaysItAtVout2:
    """``f644794b…``: a registration the public indexer resolves (see
    ``test_wave_claim_registers_with_the_indexer.py``)."""

    def test_vout_2_is_the_treasury_p2pkh_at_the_6_plus_tier(self) -> None:
        label = _MINT_DICT["attrs"]["name"]
        assert (label, len(label)) == ("custodian-gate-x7f3", 19)
        fee = WaveRegistrationFee(label)
        assert _MINT_TX.outputs[2].satoshis == fee.value == 500_000_000
        assert _MINT_TX.outputs[2].locking_script.serialize() == fee.locking_script

    def test_it_is_the_only_treasury_output_and_comes_after_the_token_outputs(self) -> None:
        """Photonic's order: token outputs (NFT, then the mutable contract), then the extra
        outputs, then change (``packages/lib/src/mint.ts:877-881``, ``:905-907``)."""
        outs = [(o.satoshis, o.locking_script.serialize()) for o in _MINT_TX.outputs]
        assert [len(script) for _, script in outs[:2]] == [63, 174]  # NFT singleton, mutable contract
        assert [i for i, (_, script) in enumerate(outs) if script == _TREASURY_SCRIPT_ON_CHAIN] == [2]
        assert len(outs) == 4  # vout 3 is change

    def test_the_fee_was_funded_by_a_third_input_from_the_commit_transaction(self) -> None:
        """Read from the chain: inputs 0 and 1 are the commit and the mutable seed, input 2 the
        commit transaction's vout 2 — not the commit output. That vout 2 is the commit's CHANGE is
        inferred from Photonic's code (its commit outputs are commit, seed, change, ``mint.ts:818``;
        the change joins the reveal's spendable set, ``:827``): the fixture does not hold the
        commit transaction, so this test cannot see it."""
        commit_txid = _MINT_TX.inputs[0].source_txid
        assert [(i.source_txid, i.source_output_index) for i in _MINT_TX.inputs] == [
            (commit_txid, 0),
            (commit_txid, 1),
            (commit_txid, 2),
        ]
        assert len(_MINT_TX.inputs[2].unlocking_script.serialize()) < 110  # a plain P2PKH unlock

    def test_what_pyrxd_builds_for_that_name_is_that_output(self) -> None:
        scripts = GlyphBuilder().prepare_wave_reveal(TXID, 0, _MINT_CBOR, PKH, _MINT_DICT["name"])
        fee = scripts.registration_fee_output
        assert fee is not None
        assert (fee.value, fee.locking_script) == (
            _MINT_TX.outputs[2].satoshis,
            _MINT_TX.outputs[2].locking_script.serialize(),
        )


# ─────────────────────────────────── (4) on every path, by default, exactly ──


class TestEveryPathReturnsTheFeeByDefault:
    @pytest.mark.parametrize("door", sorted(_DOORS))
    @pytest.mark.parametrize("label", _TIER_LABELS, ids=lambda s: f"len{len(s)}")
    def test_the_fee_is_there_with_the_treasury_script_and_the_tier_value(self, door: str, label: str) -> None:
        fee = _DOORS[door](_claim(label), {})
        assert fee is not None, f"{door} registers {label}.rxd and reports no registration fee"
        assert fee.label == label
        assert fee.locking_script == _TREASURY_SCRIPT_ON_CHAIN
        assert fee.value == _photonic_calculate_name_cost(f"{label}.rxd") == _rxindexer_wave_name_price(label)

    @pytest.mark.parametrize("door", sorted(_DOORS))
    def test_a_payload_that_registers_nothing_owes_nothing(self, door: str) -> None:
        """The honest half: a mutable NFT with no WAVE marker is not charged."""
        if door == "estimate_reveal_fee_for_metadata":
            md = GlyphMetadata(protocol=[GlyphProtocol.NFT, GlyphProtocol.MUT], name="plain")
            assert estimate_reveal_fee_for_metadata(md).registration_fee is None
            return
        if door == "prepare_wave_reveal":
            # Refuses anything not marked WAVE outright, so it cannot charge one.
            with pytest.raises(ValidationError, match="must include GlyphProtocol.WAVE"):
                _DOORS[door](_claim("alice", p=[GlyphProtocol.NFT, GlyphProtocol.MUT]), {})
            return
        assert _DOORS[door](_claim("alice", p=[GlyphProtocol.NFT, GlyphProtocol.MUT]), {}) is None

    def test_the_commit_carries_nothing_for_the_fee(self) -> None:
        """The fee is funded at reveal time from the wallet, so the commit knows nothing of it:
        CommitParams takes no fee arguments and CommitResult reports none, exactly as on main."""
        assert "pay_registration_fee" not in CommitParams.__dataclass_fields__
        assert "registration_treasury" not in CommitParams.__dataclass_fields__
        assert "registration_fee_output" not in CommitResult.__dataclass_fields__
        md = build_wave_metadata(qualified_name="alice.rxd", target=TARGET)
        result = GlyphBuilder().prepare_commit(
            CommitParams(metadata=md, owner_pkh=PKH, change_pkh=PKH, funding_satoshis=10_000)
        )
        assert wave_registration_fee_for(result.cbor_bytes) == WaveRegistrationFee("alice")

    def test_the_recovery_of_a_0_24_commit_owes_nothing(self) -> None:
        """``allow_unregistrable_wave=True`` reveals ≤0.24.0's dotted ``alice.rxd``, which the
        indexer's ``validate_wave_name`` REFUSES: no name registers, so no fee is owed."""
        old = {**_claim(), "attrs": {**_claim()["attrs"], "name": "alice.rxd"}}
        del old["name"], old["v"], old["type"]
        assert not _rxindexer_validate_wave_name("alice.rxd")
        assert wave_registered_label(old) is None
        scripts = GlyphBuilder().prepare_wave_reveal(
            TXID, 0, cbor2.dumps(old), PKH, "alice.rxd", allow_unregistrable_wave=True
        )
        assert scripts.registration_fee_output is None
        assert estimate_reveal_fee(cbor_bytes=cbor2.dumps(old), is_nft=True).registration_fee is None


class TestTheIndexerRuleDecidesWhatOwesTheFee:
    """L1: ``allow_unregistrable_wave=True`` must not waive the fee for a payload the indexer DOES
    register. pyrxd's write rule is stricter than the indexer's; the fee follows the indexer."""

    @pytest.mark.parametrize(
        ("claim", "registers"),
        [
            (_claim("ab"), "ab"),  # 2 characters: the indexer's minimum is 1
            (_claim("ALICE"), "ALICE"),  # the indexer lower-cases before its check
            (_claim("alice", name="bob.rxd"), "alice"),  # the live path ignores the top-level name
            (_claim("alice", app={"data": {"name": "bob"}}), "alice"),  # attrs.name is read first
            (  # attrs.name empty: the indexer falls back to app.data.name
                {**_claim(""), "app": {"data": {"name": "carol"}}},
                "carol",
            ),
        ],
        ids=["2-chars", "upper-case", "other-top-level-name", "other-app-data-name", "app-data-fallback"],
    )
    def test_a_payload_the_indexer_registers_owes_the_fee_through_the_escape(self, claim: dict, registers: str) -> None:
        read = claim["attrs"].get("name") or claim.get("app", {}).get("data", {}).get("name")
        assert read == registers and _rxindexer_validate_wave_name(read)
        assert wave_registered_label(claim) == registers
        scripts = GlyphBuilder().prepare_mutable_reveal(TXID, 0, cbor2.dumps(claim), PKH, allow_unregistrable_wave=True)
        assert scripts.registration_fee_output == WaveRegistrationFee(registers)
        assert scripts.registration_fee_output.value == _rxindexer_wave_name_price(registers)

    @pytest.mark.parametrize("label", ["alice.rxd", "a" * 64, "-abc", "a--b", 5])
    def test_only_what_the_indexer_refuses_is_waived(self, label: object) -> None:
        claim = _claim("x")
        claim["attrs"]["name"] = label
        assert wave_registered_label(claim) is None

    def test_the_label_is_read_from_the_envelope_as_the_indexer_reads_it(self) -> None:
        suffix = build_reveal_scriptsig_suffix(cbor2.dumps(_claim("abcd")), registration_fee=None)
        assert registered_label_in_scriptsig(b"\x47" + b"\x00" * 71 + suffix) == "abcd"
        dat = b"\x03gly\x03dat" + bytes([len(cbor2.dumps(_claim("abcd")))]) + cbor2.dumps(_claim("abcd"))
        assert registered_label_in_scriptsig(dat) is None  # the indexer does not read a DAT envelope


# ───────────────────────────────────────────────────────────── (5) the opt-out ──


class TestTheOptOutIsExplicit:
    @pytest.mark.parametrize("door", sorted(_DOORS))
    def test_false_removes_it(self, door: str) -> None:
        assert _DOORS[door](_claim(), {"pay_registration_fee": False}) is None

    @pytest.mark.parametrize("door", sorted(_DOORS))
    def test_true_is_what_saying_nothing_means(self, door: str) -> None:
        said = _DOORS[door](_claim(), {"pay_registration_fee": True})
        assert said is not None and said == _DOORS[door](_claim(), {})

    @pytest.mark.parametrize("door", sorted(_DOORS))
    @pytest.mark.parametrize("bad", ["False", 0, 1, None], ids=repr)
    def test_anything_but_a_bool_is_refused(self, door: str, bad: object) -> None:
        """``"False"`` is truthy and would pay; ``0`` is falsy and would opt out without saying so."""
        with pytest.raises(ValidationError, match="pay_registration_fee must be True or False"):
            _DOORS[door](_claim(), {"pay_registration_fee": bad})

    @pytest.mark.parametrize("door", sorted(_DOORS))
    def test_a_named_treasury_is_paid_on_every_path(self, door: str) -> None:
        addr = PrivateKey().public_key().address(network=Network.TESTNET)
        fee = _DOORS[door](_claim(), {"registration_treasury": addr})
        assert fee is not None and fee.treasury_address == addr

    @pytest.mark.parametrize("door", sorted(_DOORS))
    def test_a_treasury_with_the_opt_out_is_refused(self, door: str) -> None:
        with pytest.raises(ValidationError, match="nothing would be paid to it"):
            _DOORS[door](_claim(), {"pay_registration_fee": False, "registration_treasury": WAVE_TREASURY_ADDRESS})

    def test_every_default_is_to_pay_and_nothing_hides_behind_kwargs(self) -> None:
        """Derived: every function or params class in the builder and the CLI that takes
        ``pay_registration_fee`` defaults it to True or requires it, and none takes ``**kwargs``."""
        found: list[str] = []
        for module in (builder_module, glyph_cmds):
            for name, obj in vars(module).items():
                targets = [obj]
                if inspect.isclass(obj):
                    targets = [getattr(obj, m) for m in vars(obj) if callable(getattr(obj, m, None))] + [obj]
                for target in targets:
                    try:
                        params = inspect.signature(target).parameters
                    except (TypeError, ValueError):
                        continue
                    if "pay_registration_fee" in params:
                        found.append(f"{name}.{getattr(target, '__name__', '')}")
                        default = params["pay_registration_fee"].default
                        assert default is True or default is inspect.Parameter.empty, (name, target)
                        assert all(p.kind is not p.VAR_KEYWORD for p in params.values()), (name, target)
        for fn in (estimate_reveal_fee, estimate_reveal_fee_for_metadata, wave_registration_fee_for):
            assert inspect.signature(fn).parameters["pay_registration_fee"].default is True
        # Non-vacuity: the scan reached the builders, the params class and the CLI.
        assert {"RevealParams.RevealParams", "_mint_nft_inner._mint_nft_inner"} <= set(found), found
        assert len(found) >= 8, found


# ─────────────────────────── (6) the raw envelope writers: say what you pay ──


class TestTheRawWritersRequireAStatement:
    """``build_reveal_scriptsig_suffix`` and ``build_mutable_scriptsig`` are the narrowest point
    every reveal and update crosses. They write bytes and cannot add an output, so they refuse a
    payload that registers a name until the caller has said what it pays."""

    def test_a_reveal_that_says_nothing_is_refused_and_the_message_names_the_fee(self) -> None:
        with pytest.raises(ValidationError) as exc:
            build_reveal_scriptsig_suffix(cbor2.dumps(_claim("abcd")))
        message = str(exc.value)
        assert "abcd.rxd" in message and "50 RXD" in message and WAVE_TREASURY_ADDRESS in message
        assert "registers the WAVE name abcd.rxd if the name is free" in message

    def test_an_update_that_says_nothing_is_told_it_is_a_duplicate_or_a_renewal(self) -> None:
        """L4: a WAVE-marked update of a live name is a DUPLICATE to the indexer, and a treasury
        payment in a transaction spending the claim token is a RENEWAL — not a registration."""
        with pytest.raises(ValidationError) as exc:
            build_mutable_scriptsig("mod", cbor2.dumps(_claim("abcd")), 1, 1, 0, 0)
        message = str(exc.value)
        assert "a duplicate it does not register while that name is held and live" in message
        assert "RENEWAL" in message
        assert "registers the WAVE name" not in message

    @pytest.mark.parametrize("writer", ["reveal", "mutable"])
    def test_a_stated_fee_or_an_explicit_none_is_accepted(self, writer: str) -> None:
        cbor = cbor2.dumps(_claim("abcd"))
        for stated in (wave_registration_fee_for(cbor), None):
            if writer == "reveal":
                assert build_reveal_scriptsig_suffix(cbor, registration_fee=stated)
            else:
                assert build_mutable_scriptsig("mod", cbor, 1, 1, 0, 0, registration_fee=stated)

    def test_a_fee_for_another_name_is_refused(self) -> None:
        with pytest.raises(ValidationError, match="registers 'abcd'"):
            build_reveal_scriptsig_suffix(cbor2.dumps(_claim("abcd")), registration_fee=WaveRegistrationFee("abcde"))

    def test_a_fee_for_a_payload_that_registers_nothing_is_refused(self) -> None:
        cbor = encode_payload(GlyphMetadata(protocol=[GlyphProtocol.NFT], name="plain"))[0]
        with pytest.raises(ValidationError, match="registers no WAVE name"):
            build_reveal_scriptsig_suffix(cbor, registration_fee=WaveRegistrationFee("alice"))

    def test_a_payload_that_registers_nothing_needs_no_statement(self) -> None:
        cbor = encode_payload(GlyphMetadata(protocol=[GlyphProtocol.NFT, GlyphProtocol.MUT], name="plain"))[0]
        assert build_reveal_scriptsig_suffix(cbor)
        assert build_mutable_scriptsig("mod", cbor2.dumps({"attrs": {"target": TARGET}}), 1, 1, 0, 0)

    def test_an_ft_deploy_cannot_carry_a_claim(self) -> None:
        """``FtDeployRevealScripts`` has no fee field; the FT path refuses a WAVE claim rather
        than returning one without its fee."""
        cbor = cbor2.dumps(_claim(p=[GlyphProtocol.FT, GlyphProtocol.MUT, GlyphProtocol.WAVE]))
        assert wave_registered_label(cbor) == "alice"  # the indexer would register it
        with pytest.raises(ValidationError, match="cannot carry a WAVE claim"):
            GlyphBuilder().prepare_ft_deploy_reveal(TXID, 0, 10_000, cbor, PKH, 1_000)


# ────────────────────────────────── (7) the estimator, the measurement, the gate ──


def _fee_funding(key: PrivateKey, value: int) -> Any:
    return glyph_cmds._FeeFunding(txid="ef" * 32, vout=1, value=value, address=key.address(), key=key)


def _reveal_with(
    fee: WaveRegistrationFee | None,
    cbor: bytes,
    *,
    commit_value: int,
    funding_value: int = 0,
    pay: bool | None = None,
) -> Transaction:
    """A reveal assembled by ``pyrxd glyph mint-nft``'s own ``_build_reveal_tx``."""
    key = PrivateKey()
    pkh = Hex20(key.public_key().hash160())
    commit_script = build_commit_locking_script(hash_payload(cbor), pkh, is_nft=True)
    scripts = GlyphBuilder().prepare_reveal(
        RevealParams(
            commit_txid=TXID,
            commit_vout=0,
            commit_value=commit_value,
            cbor_bytes=cbor,
            owner_pkh=pkh,
            is_nft=True,
            pay_registration_fee=(fee is not None) if pay is None else pay,
        )
    )
    return glyph_cmds._build_reveal_tx(
        commit_txid=TXID,
        commit_value=commit_value,
        commit_script=commit_script,
        reveal_locking_script=scripts.locking_script,
        carrier_value=546,
        change_locking=P2PKH().lock(key.address()),
        funding_key=key,
        scriptsig_suffix=scripts.scriptsig_suffix,
        registration_fee=fee,
        fee_funding=_fee_funding(key, funding_value) if fee is not None else None,
    )


class TestTheEstimatorSizesTheFundingInputAndNotTheCommit:
    CBOR = cbor2.dumps(_claim("abcdef"))

    def test_the_input_and_output_are_sized_and_the_value_is_the_inputs_not_the_commits(self) -> None:
        paid = estimate_reveal_fee(cbor_bytes=self.CBOR, is_nft=True)
        declined = estimate_reveal_fee(cbor_bytes=self.CBOR, is_nft=True, pay_registration_fee=False)
        # The fee output: 8-byte value + 1-byte script length + the 25-byte P2PKH. The funding
        # input: 32-byte txid + 4-byte vout + 1-byte scriptSig length + the P2PKH unlock + 4-byte
        # sequence.
        output_bytes = 8 + 1 + len(_TREASURY_SCRIPT_ON_CHAIN)
        input_bytes = 32 + 4 + 1 + REVEAL_SIG_PREFIX_BYTES + 4
        assert paid.size_bytes - declined.size_bytes == output_bytes + input_bytes == 34 + 148
        # SatoshisPerKilobyte rounds each fee UP (a float ceil), so the difference is those
        # bytes' worth to within one photon.
        assert abs((paid.fee - declined.fee) - (output_bytes + input_bytes) * paid.fee_rate) <= 1
        assert paid.registration_fee_value == 500_000_000 and declined.registration_fee_value == 0
        assert paid.required_funding_value == 500_000_000 and declined.required_funding_value == 0
        # The commit pays the reveal's MINER fee, never the registration fee.
        assert paid.required_commit_value(546) == 546 + paid.fee
        assert declined.required_commit_value(546) == 546 + declined.fee

    def test_the_commit_value_is_carrier_plus_miner_fee_with_no_registration_fee_in_it(self) -> None:
        paid = estimate_reveal_fee(cbor_bytes=self.CBOR, is_nft=True)
        expected = 546 + max(MIN_COMMIT_OVERHEAD, paid.fee + REVEAL_SIZE_SLACK_BYTES * paid.fee_rate)
        assert commit_value_for_reveal(546, paid) == expected
        assert commit_value_for_reveal(546, paid) < paid.registration_fee_value

    def test_check_reveal_funding_is_about_the_commit_only(self) -> None:
        paid = estimate_reveal_fee(cbor_bytes=self.CBOR, is_nft=True)
        check_reveal_funding(commit_value=546 + paid.fee, carrier_value=546, estimate=paid)
        with pytest.raises(InsufficientFundsError, match="short by 1"):
            check_reveal_funding(commit_value=546 + paid.fee - 1, carrier_value=546, estimate=paid)


class TestMeasuringAReveal:
    CBOR = cbor2.dumps(_claim("abcdef"))
    FEE = WaveRegistrationFee("abcdef")

    def test_a_reveal_carrying_its_fee_measures_the_same_as_the_estimate(self) -> None:
        tx = _reveal_with(self.FEE, self.CBOR, commit_value=10_000_000, funding_value=600_000_000)
        measured = measure_reveal_fee(tx, registration_fee=self.FEE)
        assert measured.registration_fee == self.FEE
        assert measured.size_bytes == estimate_reveal_fee(cbor_bytes=self.CBOR, is_nft=True).size_bytes

    def test_a_non_wave_reveal_needs_no_statement(self) -> None:
        """L3: the new keyword has a sentinel default, so no existing caller breaks."""
        cbor = encode_payload(GlyphMetadata(protocol=[GlyphProtocol.NFT], name="plain"))[0]
        assert measure_reveal_fee(_reveal_with(None, cbor, commit_value=10_000_000)).registration_fee is None

    def test_saying_nothing_about_a_registering_reveal_is_refused(self) -> None:
        tx = _reveal_with(self.FEE, self.CBOR, commit_value=10_000_000, funding_value=600_000_000)
        with pytest.raises(ValidationError, match="registers the WAVE name abcdef.rxd"):
            measure_reveal_fee(tx)

    def test_none_on_a_registering_reveal_is_refused(self) -> None:
        """L2: ``None`` means "registers nothing"; for a reveal whose own envelope registers a
        name, it passed silently before."""
        tx = _reveal_with(None, self.CBOR, commit_value=10_000_000, pay=False)
        with pytest.raises(ValidationError, match="registers nothing"):
            measure_reveal_fee(tx, registration_fee=None)
        assert measure_reveal_fee(tx, registration_fee=FEE_DECLINED).registration_fee is None

    def test_a_reveal_that_dropped_the_output_is_refused(self) -> None:
        tx = _reveal_with(self.FEE, self.CBOR, commit_value=10_000_000, funding_value=600_000_000)
        tx.outputs = [o for o in tx.outputs if o.locking_script.serialize() != self.FEE.locking_script]
        with pytest.raises(ValidationError, match="does not carry its WAVE registration fee"):
            measure_reveal_fee(tx, registration_fee=self.FEE)

    def test_the_wrong_value_to_the_right_script_is_refused(self) -> None:
        """P4: checking the script and not the VALUE let a 1-photon "fee" through."""
        tx = _reveal_with(self.FEE, self.CBOR, commit_value=10_000_000, funding_value=600_000_000)
        for out in tx.outputs:
            if out.locking_script.serialize() == self.FEE.locking_script:
                out.satoshis = 1
        with pytest.raises(ValidationError, match="pays 1 photons"):
            measure_reveal_fee(tx, registration_fee=self.FEE)

    def test_two_treasury_outputs_are_refused(self) -> None:
        """L2: a doubled fee output passed the old check."""
        tx = _reveal_with(self.FEE, self.CBOR, commit_value=10_000_000, funding_value=1_200_000_000)
        tx.outputs.insert(1, TransactionOutput(P2PKH().lock(WAVE_TREASURY_ADDRESS), self.FEE.value))
        with pytest.raises(ValidationError, match="2 times"):
            measure_reveal_fee(tx, registration_fee=self.FEE)

    def test_a_fee_for_another_name_than_the_envelopes_is_refused(self) -> None:
        tx = _reveal_with(self.FEE, self.CBOR, commit_value=10_000_000, funding_value=600_000_000)
        with pytest.raises(ValidationError, match="envelope registers 'abcdef'"):
            measure_reveal_fee(tx, registration_fee=WaveRegistrationFee("abcdefg"))


class TestTheBalanceGate:
    CBOR = cbor2.dumps(_claim("abcdef"))
    FEE = WaveRegistrationFee("abcdef")

    def test_the_cli_cannot_build_a_fee_without_the_input_that_funds_it(self) -> None:
        """The two go together: a fee output with no funding input would take the fee out of the
        commit (which is not sized for it), and a funding input with no fee is a stray spend."""
        key = PrivateKey()
        pkh = Hex20(key.public_key().hash160())
        common = {
            "commit_txid": TXID,
            "commit_value": 10_000_000,
            "commit_script": build_commit_locking_script(hash_payload(self.CBOR), pkh, is_nft=True),
            "reveal_locking_script": build_nft_locking_script(pkh, GlyphRef(txid=Txid(TXID), vout=0)),
            "carrier_value": 546,
            "change_locking": P2PKH().lock(key.address()),
            "funding_key": key,
            "scriptsig_suffix": b"",
        }
        with pytest.raises(ValueError, match="go together"):
            glyph_cmds._build_reveal_tx(**common, registration_fee=self.FEE, fee_funding=None)
        with pytest.raises(ValueError, match="go together"):
            glyph_cmds._build_reveal_tx(**common, registration_fee=None, fee_funding=_fee_funding(key, 600_000_000))

    def test_a_reveal_funded_by_its_wallet_input_balances(self) -> None:
        tx = _reveal_with(self.FEE, self.CBOR, commit_value=10_000_000, funding_value=600_000_000)
        measured = assert_reveal_balances(tx, registration_fee=self.FEE)
        assert measured.registration_fee == self.FEE

    def test_a_funding_input_short_of_the_fee_is_refused_with_the_numbers(self) -> None:
        tx = _reveal_with(self.FEE, self.CBOR, commit_value=10_000_000, funding_value=400_000_000)
        with pytest.raises(InsufficientFundsError) as exc:
            assert_reveal_balances(tx, registration_fee=self.FEE)
        message = str(exc.value)
        assert "does not balance" in message and "500,000,000 WAVE registration fee for abcdef.rxd" in message
        assert WAVE_TREASURY_ADDRESS in message

    def test_a_reveal_that_would_lose_its_change_is_refused(self) -> None:
        """L2: balancing by dropping the change output is not balancing."""
        probe = _reveal_with(self.FEE, self.CBOR, commit_value=10_000_000, funding_value=600_000_000)
        miner_fee = measure_reveal_fee(probe, registration_fee=self.FEE).fee
        exact = 546 + self.FEE.value + miner_fee  # nothing left for change
        tx = _reveal_with(self.FEE, self.CBOR, commit_value=exact - self.FEE.value, funding_value=self.FEE.value)
        with pytest.raises(InsufficientFundsError, match="only by dropping its change"):
            assert_reveal_balances(tx, registration_fee=self.FEE)

    def test_the_commit_pays_the_miner_and_the_wallet_input_only_the_fee(self) -> None:
        """M1(b): a commit one photon short of its carrier and miner fee is refused even though
        the wallet input could cover it — that input pays the registration fee and nothing more."""
        probe = _reveal_with(self.FEE, self.CBOR, commit_value=10_000_000, funding_value=600_000_000)
        miner_fee = measure_reveal_fee(probe, registration_fee=self.FEE).fee
        honest = _reveal_with(self.FEE, self.CBOR, commit_value=546 + miner_fee, funding_value=600_000_000)
        assert_reveal_balances(honest, registration_fee=self.FEE)
        short = _reveal_with(self.FEE, self.CBOR, commit_value=546 + miner_fee - 1, funding_value=600_000_000)
        with pytest.raises(InsufficientFundsError, match="so the wallet input would pay the miner"):
            assert_reveal_balances(short, registration_fee=self.FEE)

    @pytest.mark.parametrize("signed", [False, True], ids=["dry-run", "signed"])
    def test_a_miner_fee_above_ten_times_the_floor_is_refused(self, signed: bool) -> None:
        """M1(c): the ceiling comes from the relay floor, not from the fee_rate the caller passed,
        which may itself be the mistake. 100,000/byte (exactly 10x) passes; 100,001 does not."""
        for rate, allowed in ((100_000, True), (100_001, False)):
            tx = _reveal_with(self.FEE, self.CBOR, commit_value=1_000_000_000, funding_value=600_000_000)
            if signed:
                tx.fee(SatoshisPerKilobyte(rate * 1000))
            if allowed:
                assert_reveal_balances(tx, fee_rate=rate, registration_fee=self.FEE)
            else:
                with pytest.raises(ValidationError, match="10x the relay floor for its size"):
                    assert_reveal_balances(tx, fee_rate=rate, registration_fee=self.FEE)

    def test_the_signed_reveal_is_held_to_its_real_size(self) -> None:
        tx = _reveal_with(self.FEE, self.CBOR, commit_value=10_000_000, funding_value=600_000_000)
        tx.fee(SatoshisPerKilobyte(10_000_000))
        assert_reveal_balances(tx, registration_fee=self.FEE)  # the honest half: it pays
        change = next(o for o in tx.outputs if o.change)
        change.satoshis += 1_000_000  # the miner is now paid 1,000,000 photons less than fee() set
        with pytest.raises(InsufficientFundsError, match="does not pay its fee"):
            assert_reveal_balances(tx, registration_fee=self.FEE)


# ──────────────────────────── (8) GlyphMinter, which does not register names ──


class _MinterClient:
    def __init__(self) -> None:
        self.broadcasts: list[bytes] = []

    async def broadcast(self, raw: bytes) -> str:
        self.broadcasts.append(bytes(raw))
        return str(Transaction.from_hex(bytes(raw)).txid())

    async def get_transaction_verbose(self, txid: str) -> dict:
        return {"confirmations": 1}


def _wave_pending(key: PrivateKey, **kw: Any) -> PendingMint:
    cbor = encode_payload(build_wave_metadata(qualified_name="abcdef.rxd", target=TARGET))[0]
    pkh = Hex20(key.public_key().hash160())
    fields: dict[str, Any] = {
        "commit_txid": "12" * 32,
        "commit_vout": 0,
        "commit_value": 10_000_000,
        "commit_script": build_commit_locking_script(hash_payload(cbor), pkh, is_nft=True),
        "cbor_bytes": cbor,
        "owner_pkh": bytes(pkh),
        "is_nft": True,
        "carrier_value": 546,
        "fee_rate": 10_000,
        "funding_address": key.address(),
    }
    fields.update(kw)
    return PendingMint(**fields)


class TestTheRecordKeepsTheFeeDecision:
    """M2: the mint's WAVE fee choice lives in its record, so a recovery cannot lose it."""

    @pytest.mark.parametrize(
        ("choice", "treasury"), [("decline", None), ("pay", None), ("pay", "mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn")]
    )
    def test_it_round_trips_through_the_store_at_version_2(
        self, tmp_path: pathlib.Path, choice: str, treasury: str | None
    ) -> None:
        pending = _wave_pending(PrivateKey(), wave_fee=choice, wave_treasury=treasury)
        d = pending.to_dict()
        assert d["schema_version"] == PENDING_MINT_SCHEMA_VERSION_WITH_WAVE_FEE
        assert (d["wave_fee"], d["wave_treasury"]) == (choice, treasury)
        store = JsonFilePendingStore(tmp_path)
        store.save(pending)
        assert store.load(pending.commit_txid) == pending

    def test_a_decision_on_a_payload_that_registers_nothing_is_refused(self) -> None:
        cbor = encode_payload(GlyphMetadata(protocol=[GlyphProtocol.NFT], name="plain"))[0]
        with pytest.raises(ValidationError, match="registers no WAVE name"):
            _wave_pending(PrivateKey(), cbor_bytes=cbor, wave_fee="pay")

    @pytest.mark.parametrize(("choice", "treasury"), [("decline", WAVE_TREASURY_ADDRESS), ("maybe", None), (None, "x")])
    def test_an_incoherent_decision_is_refused(self, choice: str | None, treasury: str | None) -> None:
        with pytest.raises(ValidationError, match="wave_fee|wave_treasury"):
            _wave_pending(PrivateKey(), wave_fee=choice, wave_treasury=treasury)


@pytest.mark.filterwarnings("ignore:UnsafeNullPendingStore discards")
class TestGlyphMinter:
    """``GlyphMinter`` refuses to COMMIT a WAVE claim, and refuses to reveal a record that
    registers one, since it neither pays the fee nor funds it from the commit."""

    def _minter(self, key: PrivateKey, client: _MinterClient) -> GlyphMinter:
        class _Wallet:
            def privkey_for_address(self, address: str) -> PrivateKey:
                return key

        return GlyphMinter(client, _Wallet(), UnsafeNullPendingStore(), poll_interval_s=0.01)

    def test_the_commit_is_refused(self) -> None:
        key = PrivateKey()
        client = _MinterClient()
        with pytest.raises(ValidationError, match="cannot mint a MUT glyph|cannot mint a WAVE glyph"):
            asyncio.run(
                self._minter(key, client).commit_nft(build_wave_metadata(qualified_name="abcdef.rxd", target=TARGET))
            )
        assert client.broadcasts == []

    def test_a_record_that_registers_a_name_is_refused_with_its_recovery(self) -> None:
        key = PrivateKey()
        cbor = encode_payload(build_wave_metadata(qualified_name="abcdef.rxd", target=TARGET))[0]
        pkh = Hex20(key.public_key().hash160())
        pending = PendingMint(
            commit_txid="12" * 32,
            commit_vout=0,
            commit_value=10_000_000,
            commit_script=build_commit_locking_script(hash_payload(cbor), pkh, is_nft=True),
            cbor_bytes=cbor,
            owner_pkh=bytes(pkh),
            is_nft=True,
            carrier_value=546,
            fee_rate=10_000,
            funding_address=key.address(),
        )
        client = _MinterClient()
        with pytest.raises(ValidationError) as exc:
            asyncio.run(self._minter(key, client).reveal_nft(pending))
        assert "resume-mint" in str(exc.value) and "pay_registration_fee=False" in str(exc.value)
        assert client.broadcasts == []


# ────────────────────────────────────────── (9) the path set is derived ──


def _callers(names: set[str]) -> dict[tuple[str, str], list[ast.Call]]:
    """Every function in src/pyrxd that calls one of ``names``, with those calls."""
    found: dict[tuple[str, str], list[ast.Call]] = {}
    for path in sorted(_SRC.rglob("*.py")):
        for fn in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for node in ast.walk(fn):
                if not isinstance(node, ast.Call):
                    continue
                called = node.func.id if isinstance(node.func, ast.Name) else getattr(node.func, "attr", None)
                if called in names:
                    found.setdefault((str(path.relative_to(_SRC)), fn.name), []).append(node)
    return found


class TestThePathSetIsDerived:
    #: REVIEWED, not derived: every function that calls a WAVE envelope writer, and what it
    #: does about the fee. Pinned exactly, so a new caller fails here until someone says.
    _WRITER_CALLERS = {
        ("glyph/builder.py", "_reveal_envelope"): "STATES — every GlyphBuilder reveal builder gets its suffix here",
        ("glyph/fees.py", "estimate_reveal_fee"): "STATES — sizing only; adds the fee output and its funding input",
        ("glyph/builder.py", "build_reveal_outputs"): "UNSTATED — dMint FT deploys; see the test below",
    }

    def test_the_writer_callers_are_exactly_the_reviewed_ones(self) -> None:
        found = _callers({"build_reveal_scriptsig_suffix", "build_mutable_scriptsig"})
        assert found, "the scan found nothing: it is broken, not the codebase"
        assert set(found) == set(self._WRITER_CALLERS)
        for key, why in self._WRITER_CALLERS.items():
            states = all(any(kw.arg == "registration_fee" for kw in call.keywords) for call in found[key])
            assert states == why.startswith("STATES"), key

    def test_the_unstated_callers_cannot_be_handed_a_claim(self) -> None:
        """The dMint deploy's CBOR comes from a GlyphMetadata with FT, which cannot carry WAVE
        (WAVE needs NFT, and FT excludes NFT); the deploy also refuses one at commit time. Were a
        claim handed to the writer anyway, it refuses it."""
        for protocol in (
            [GlyphProtocol.FT, GlyphProtocol.DMINT, GlyphProtocol.WAVE],
            [GlyphProtocol.FT, GlyphProtocol.NFT, GlyphProtocol.MUT, GlyphProtocol.WAVE],
        ):
            with pytest.raises(ValidationError):
                GlyphMetadata(protocol=protocol, name="x", ticker="X")
        with pytest.raises(ValidationError, match="registers the WAVE name"):
            build_reveal_scriptsig_suffix(cbor2.dumps(_claim()))

    def test_every_reveal_builder_is_a_door(self) -> None:
        """Every GlyphBuilder method that builds a reveal envelope is in the door table, so the
        behavioural tests above reach it."""
        builders = {name for (rel, name) in _callers({"_reveal_envelope"}) if rel == "glyph/builder.py"}
        assert "prepare_reveal" in builders  # non-vacuity
        assert builders <= set(_DOORS), builders - set(_DOORS)

    def test_every_reveal_result_carries_a_required_fee_field(self) -> None:
        """Derived from the dataclasses: every builder result with a reveal envelope has
        ``registration_fee_output`` with NO default, so a builder cannot forget it."""
        exempt = {
            # prepare_ft_deploy_reveal refuses a claim (TestTheRawWritersRequireAStatement).
            "FtDeployRevealScripts",
            # the dMint deploys refuse a claim at commit time, and their reveal states nothing.
            "DmintV1RevealScripts",
        }
        results = {
            name: obj
            for name, obj in vars(builder_module).items()
            if dataclasses.is_dataclass(obj) and "scriptsig_suffix" in {f.name for f in dataclasses.fields(obj)}
        }
        assert {"RevealScripts", "MutableRevealScripts"} <= set(results)  # non-vacuity
        assert exempt <= set(results)
        for name, cls in results.items():
            fields = {f.name: f for f in dataclasses.fields(cls)}
            if name in exempt:
                assert "registration_fee_output" not in fields, name
                continue
            fee = fields.get("registration_fee_output")
            assert fee is not None, f"{name} carries a reveal envelope and no registration_fee_output"
            assert fee.default is dataclasses.MISSING and fee.default_factory is dataclasses.MISSING, name
            assert fee.kw_only, name
