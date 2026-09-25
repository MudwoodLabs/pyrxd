"""pyrxd pays the WAVE registration fee by default, on every path that registers a name.

The decision is the maintainer's: registering a WAVE name pays the protocol's registration
fee, as the published WAVE protocol and Photonic do, and the only way out is an explicit
``pay_registration_fee=False`` (``--no-wave-registration-fee`` on the CLI).

What the fee IS comes from two sources pyrxd did not write, transcribed below and cited in
``src/pyrxd/glyph/wave_rules.py``:

- Photonic Wallet at ``becf41a731e78ab98fdd88652527d7dda12784c6``: ``calculateNameCost``
  (``packages/lib/src/wave.ts:55-66``) and the register page, which pays it to
  ``1GrwkQNJfjbEJjH25heszNZLpbZou8nfXG`` (``packages/app/src/pages/WaveRegister.tsx:132-152``);
- RXinDexer at ``ca8a6a4e77ef0ad3f24ec6f41cb0a73eb5f3651e``: ``wave_name_price``
  (``electrumx/server/wave_index.py:73-86``) and ``WAVE_TREASURY_ADDRESS_DEFAULT``
  (``wave_index.py:65``).

And from one thing on chain: mainnet claim ``f644794b…`` (``fixtures/wave_update_chain_mainnet.json``)
pays the 6+ tier to that treasury at vout 2. Every upstream file cited here is digest-pinned in
``fixtures/photonic_upstream_pin.json`` or ``fixtures/rxindexer_upstream_pin.json`` and watched by
``scripts/check_photonic_drift.py``.

The set of paths is DERIVED from the code (``TestThePathSetIsDerived``), not trusted to the door
table below.
"""

from __future__ import annotations

import ast
import dataclasses
import inspect
import json
import pathlib
from collections.abc import Callable
from typing import Any

import cbor2
import pytest
from click.testing import CliRunner

from pyrxd.cli import glyph_cmds
from pyrxd.cli.main import cli
from pyrxd.constants import Network
from pyrxd.glyph import builder as builder_module
from pyrxd.glyph.builder import CommitParams, GlyphBuilder, RevealParams
from pyrxd.glyph.fees import (
    MIN_COMMIT_OVERHEAD,
    REVEAL_SIZE_SLACK_BYTES,
    check_reveal_funding,
    commit_value_for_reveal,
    estimate_reveal_fee,
    estimate_reveal_fee_for_metadata,
    measure_reveal_fee,
)
from pyrxd.glyph.inspector import GlyphInspector
from pyrxd.glyph.mint import GlyphMinter, PendingMint, UnsafeNullPendingStore
from pyrxd.glyph.payload import build_mutable_scriptsig, build_reveal_scriptsig_suffix, encode_payload
from pyrxd.glyph.script import build_commit_locking_script, build_nft_locking_script, hash_payload
from pyrxd.glyph.types import GlyphMetadata, GlyphProtocol, GlyphRef
from pyrxd.glyph.wave import build_wave_metadata
from pyrxd.glyph.wave_rules import (
    WAVE_TREASURY_ADDRESS,
    WaveRegistrationFee,
    format_rxd,
    wave_registered_label,
    wave_registration_fee_for,
    wave_registration_price,
)
from pyrxd.keys import PrivateKey
from pyrxd.network.electrumx import UtxoRecord
from pyrxd.script.type import P2PKH
from pyrxd.security.errors import InsufficientFundsError, ValidationError
from pyrxd.security.types import Hex20, Txid
from pyrxd.transaction.transaction import Transaction

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

#: Every pyrxd path that registers a WAVE name — builds the transaction's pieces or prices it —
#: fed a claim and extra keyword arguments, returning the fee that path reports. Which paths
#: EXIST is derived in ``TestThePathSetIsDerived``; this table must cover what that finds.
_DOORS: dict[str, Callable[[dict, dict], WaveRegistrationFee | None]] = {
    "prepare_commit": lambda d, kw: (
        GlyphBuilder()
        .prepare_commit(
            CommitParams(metadata=_metadata(d), owner_pkh=PKH, change_pkh=PKH, funding_satoshis=10_000, **kw)
        )
        .registration_fee_output
    ),
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

#: One label per price tier, the tier edges included: 3 (the "<= 3" tier, which pyrxd's 3-63
#: rule makes exactly 3), 4, 5, 6 (the first "6+") and 63 (the longest pyrxd writes).
_TIER_LABELS = ["abc", "abcd", "abcde", "abcdef", "a" * 63]


# ─────────────────────────────────────────────────────────────── (1) the price ──


class TestThePrice:
    @pytest.mark.parametrize(
        ("label", "photons"),
        [
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

    def test_under_three_characters_is_refused_not_priced(self) -> None:
        """Both sources price 1-2 character names at the 3-character tier. pyrxd writes no
        label under 3 characters (#733), so it prices none: "<= 3" is exactly 3 here."""
        assert _photonic_calculate_name_cost("ab.rxd") == _rxindexer_wave_name_price("ab") == 10_000_000_000
        with pytest.raises(ValidationError, match="is 2 characters"):
            wave_registration_price("ab")

    @pytest.mark.parametrize("bad", ["a" * 64, "Alice", "sub.alice.rxd", "alice.eth", b"alice"])
    def test_a_name_pyrxd_will_not_write_has_no_price(self, bad: object) -> None:
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

    def test_what_pyrxd_builds_for_that_name_is_that_output(self) -> None:
        scripts = GlyphBuilder().prepare_wave_reveal(TXID, 0, _MINT_CBOR, PKH, _MINT_DICT["name"])
        fee = scripts.registration_fee_output
        assert fee is not None
        assert (fee.value, fee.locking_script) == (
            _MINT_TX.outputs[2].satoshis,
            _MINT_TX.outputs[2].locking_script.serialize(),
        )


# ─────────────────────────────────── (4) on every path, by default, exactly ──


class TestEveryPathPaysByDefault:
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
        if door in ("prepare_commit", "estimate_reveal_fee_for_metadata"):
            md = GlyphMetadata(protocol=[GlyphProtocol.NFT, GlyphProtocol.MUT], name="plain")
            fee = (
                GlyphBuilder()
                .prepare_commit(CommitParams(metadata=md, owner_pkh=PKH, change_pkh=PKH, funding_satoshis=10_000))
                .registration_fee_output
                if door == "prepare_commit"
                else estimate_reveal_fee_for_metadata(md).registration_fee
            )
        elif door == "prepare_wave_reveal":
            # Refuses anything not marked WAVE outright, so it cannot charge one.
            with pytest.raises(ValidationError, match="must include GlyphProtocol.WAVE"):
                _DOORS[door](_claim("alice", p=[GlyphProtocol.NFT, GlyphProtocol.MUT]), {})
            return
        else:
            fee = _DOORS[door](_claim("alice", p=[GlyphProtocol.NFT, GlyphProtocol.MUT]), {})
        assert fee is None

    def test_the_recovery_of_a_0_24_commit_owes_nothing(self) -> None:
        """``allow_unregistrable_wave=True`` reveals a claim the indexer skips: no name, no fee."""
        old = {**_claim(), "attrs": {**_claim()["attrs"], "name": "alice.rxd"}}
        del old["name"], old["v"], old["type"]
        assert wave_registered_label(old) is None
        scripts = GlyphBuilder().prepare_wave_reveal(
            TXID, 0, cbor2.dumps(old), PKH, "alice.rxd", allow_unregistrable_wave=True
        )
        assert scripts.registration_fee_output is None
        assert estimate_reveal_fee(cbor_bytes=cbor2.dumps(old), is_nft=True).registration_fee is None

    def test_a_registrable_claim_revealed_through_the_escape_still_pays(self) -> None:
        scripts = GlyphBuilder().prepare_wave_reveal(
            TXID, 0, cbor2.dumps(_claim()), PKH, "alice.rxd", allow_unregistrable_wave=True
        )
        assert scripts.registration_fee_output == WaveRegistrationFee("alice")


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
        # Non-vacuity: the scan reached the builders, the params classes and the CLI.
        assert {"CommitParams.CommitParams", "RevealParams.RevealParams", "_mint_nft_inner._mint_nft_inner"} <= set(
            found
        ), found
        assert len(found) >= 8, found


# ─────────────────────────── (6) the raw envelope writers: say what you pay ──


class TestTheRawWritersRequireAStatement:
    """``build_reveal_scriptsig_suffix`` and ``build_mutable_scriptsig`` are the narrowest point
    every reveal and update crosses. They write bytes and cannot add an output, so they refuse a
    payload that registers a name until the caller has said what it pays."""

    @pytest.mark.parametrize("writer", ["reveal", "mutable"])
    def test_saying_nothing_is_refused_and_the_message_names_the_fee(self, writer: str) -> None:
        cbor = cbor2.dumps(_claim("abcd"))
        with pytest.raises(ValidationError) as exc:
            if writer == "reveal":
                build_reveal_scriptsig_suffix(cbor)
            else:
                build_mutable_scriptsig("mod", cbor, 1, 1, 0, 0)
        message = str(exc.value)
        assert "abcd.rxd" in message and "50 RXD" in message and WAVE_TREASURY_ADDRESS in message

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


# ────────────────────────────────── (7) the estimator and the funding checks ──


def _reveal_with(fee: WaveRegistrationFee | None, cbor: bytes, *, commit_value: int) -> Transaction:
    """A reveal assembled the way ``pyrxd glyph mint-nft`` assembles it."""
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
            pay_registration_fee=fee is not None,
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
    )


class TestTheEstimatorAndTheFundingChecksCountIt:
    CBOR = cbor2.dumps(_claim("abcdef"))

    def test_the_output_is_sized_and_its_value_is_required(self) -> None:
        paid = estimate_reveal_fee(cbor_bytes=self.CBOR, is_nft=True)
        declined = estimate_reveal_fee(cbor_bytes=self.CBOR, is_nft=True, pay_registration_fee=False)
        # 8-byte value + 1-byte script length + the 25-byte P2PKH.
        assert paid.size_bytes - declined.size_bytes == 8 + 1 + len(_TREASURY_SCRIPT_ON_CHAIN) == 34
        # SatoshisPerKilobyte rounds each fee UP (a float ceil: 404 B came to 4,040,001), so the
        # difference is 34 bytes' worth to within that one photon.
        assert abs((paid.fee - declined.fee) - 34 * paid.fee_rate) <= 1
        assert paid.registration_fee_value == 500_000_000 and declined.registration_fee_value == 0
        assert paid.required_commit_value(546) == 546 + paid.fee + 500_000_000
        assert declined.required_commit_value(546) == 546 + declined.fee

    def test_the_commit_value_carries_it_outside_the_floor(self) -> None:
        paid = estimate_reveal_fee(cbor_bytes=self.CBOR, is_nft=True)
        expected = 546 + 500_000_000 + max(MIN_COMMIT_OVERHEAD, paid.fee + REVEAL_SIZE_SLACK_BYTES * paid.fee_rate)
        assert commit_value_for_reveal(546, paid) == expected
        assert commit_value_for_reveal(546, paid) >= paid.required_commit_value(546)

    def test_a_shortfall_names_the_fee_and_the_treasury(self) -> None:
        paid = estimate_reveal_fee(cbor_bytes=self.CBOR, is_nft=True)
        enough_without_it = 546 + paid.fee + REVEAL_SIZE_SLACK_BYTES * paid.fee_rate
        with pytest.raises(InsufficientFundsError) as exc:
            check_reveal_funding(commit_value=enough_without_it, carrier_value=546, estimate=paid)
        assert "500,000,000 WAVE registration fee for abcdef.rxd" in str(exc.value)
        assert WAVE_TREASURY_ADDRESS in str(exc.value)
        # ...and the honest half: the same commit funds the reveal that declined the fee.
        declined = estimate_reveal_fee(cbor_bytes=self.CBOR, is_nft=True, pay_registration_fee=False)
        check_reveal_funding(commit_value=enough_without_it, carrier_value=546, estimate=declined)

    def test_measuring_a_reveal_that_dropped_the_output_is_refused(self) -> None:
        fee = WaveRegistrationFee("abcdef")
        commit_value = 1_000_000_000
        with pytest.raises(ValidationError, match="does not carry its WAVE registration fee"):
            measure_reveal_fee(_reveal_with(None, self.CBOR, commit_value=commit_value), registration_fee=fee)
        measured = measure_reveal_fee(_reveal_with(fee, self.CBOR, commit_value=commit_value), registration_fee=fee)
        assert measured.registration_fee == fee
        assert measured.required_commit_value(546) == 546 + measured.fee + fee.value

    def test_the_measurement_agrees_with_the_estimate(self) -> None:
        """The shim's added output is the one the real reveal carries: same size to the byte."""
        fee = WaveRegistrationFee("abcdef")
        measured = measure_reveal_fee(_reveal_with(fee, self.CBOR, commit_value=1_000_000_000), registration_fee=fee)
        assert measured.size_bytes == estimate_reveal_fee(cbor_bytes=self.CBOR, is_nft=True).size_bytes


# ───────────────────────────── (8) through the production entry point: the CLI ──


class _Net:
    """The two ElectrumX calls ``glyph mint-nft`` makes; every broadcast is recorded."""

    def __init__(self) -> None:
        self.broadcasts: list[bytes] = []

    async def __aenter__(self) -> _Net:
        return self

    async def __aexit__(self, *exc: object) -> bool:
        return False

    async def broadcast(self, raw: bytes) -> str:
        self.broadcasts.append(bytes(raw))
        return str(Transaction.from_hex(bytes(raw)).txid())

    async def get_transaction_verbose(self, txid: str) -> dict:
        return {"confirmations": 1}


def _wire_cli(monkeypatch: pytest.MonkeyPatch, *, funding: int = 20_000_000_000) -> tuple[_Net, PrivateKey]:
    """A fake wallet and network around the REAL command: metadata parsing, the builder, the
    commit sizing, the dry-run measurement, both transactions and the JSON result all run."""
    for var in ("PYRXD_NETWORK", "PYRXD_ELECTRUMX", "PYRXD_FEE_RATE", "PYRXD_WALLET_PATH"):
        monkeypatch.delenv(var, raising=False)  # hermetic: the fee rate is the default relay floor
    key = PrivateKey()
    net = _Net()
    utxo = UtxoRecord(tx_hash="ef" * 32, tx_pos=0, value=funding, height=100)

    class _Wallet:
        async def collect_spendable(self, client: object) -> list:
            return [(utxo, key.address(), key)]

    monkeypatch.setattr(glyph_cmds, "_load_wallet", lambda ctx, **kw: _Wallet())
    monkeypatch.setattr(glyph_cmds.CliContext, "make_client", lambda self: net)
    return net, key


def _wave_metadata_file(tmp_path: pathlib.Path, label: str) -> pathlib.Path:
    """A metadata.json that registers ``label``.rxd, in the file format ``mint-nft`` reads."""
    path = tmp_path / "wave.json"
    path.write_text(
        json.dumps(
            {
                "protocol": ["NFT", "MUT", "WAVE"],
                "name": f"{label}.rxd",
                "token_type": "wave_name",
                "attrs": {"name": label, "domain": "rxd", "target": TARGET, "target_type": "address"},
            }
        )
    )
    return path


def _global_args(tmp_path: pathlib.Path, network: str = "mainnet") -> list[str]:
    # --config at a path that does not exist: defaults only, never the developer's own file.
    return ["--config", str(tmp_path / "absent.toml"), "--network", network, "--wallet", str(tmp_path / "w.dat")]


def _mint(tmp_path: pathlib.Path, label: str, *extra: str, network: str = "mainnet") -> Any:
    args = [*_global_args(tmp_path, network), "--json", "--yes"]
    return CliRunner().invoke(cli, [*args, "glyph", "mint-nft", str(_wave_metadata_file(tmp_path, label)), *extra])


class TestThroughTheCli:
    @pytest.mark.parametrize("label", ["abcd", "custodian-gate-x7f3"])
    def test_the_reveal_pays_the_treasury_the_tier_value_at_vout_1(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch, label: str
    ) -> None:
        net, _key = _wire_cli(monkeypatch)
        result = _mint(tmp_path, label)
        assert result.exit_code == 0, result.output
        commit, reveal = (Transaction.from_hex(raw) for raw in net.broadcasts)
        price = _photonic_calculate_name_cost(f"{label}.rxd")
        assert price == _rxindexer_wave_name_price(label)
        # vout 0 the NFT, vout 1 the fee, then change: Photonic's order, minus the contract.
        assert reveal.outputs[1].locking_script.serialize() == _TREASURY_SCRIPT_ON_CHAIN
        assert reveal.outputs[1].satoshis == price
        assert [o.locking_script.serialize() for o in reveal.outputs].count(_TREASURY_SCRIPT_ON_CHAIN) == 1
        # The commit funded it, and the reveal still pays its own fee out of what is left (the
        # reveal's only input is the commit output, so its fee is that value less its outputs).
        reveal_fee = commit.outputs[0].satoshis - sum(o.satoshis for o in reveal.outputs)
        assert reveal_fee >= len(reveal.serialize()) * 10_000  # the mainnet relay floor, per byte
        # The registration the indexer would read is the one that was paid for.
        assert (
            wave_registered_label(GlyphInspector().extract_reveal_cbor(reveal.inputs[0].unlocking_script.serialize()))
            == label
        )

    def test_the_json_and_the_disclosure_show_the_fee_in_rxd_and_the_treasury(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _wire_cli(monkeypatch)
        result = _mint(tmp_path, "abcde")
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["wave_registration"] == {
            "name": "abcde.rxd",
            "fee_paid": True,
            "fee": {
                "name": "abcde.rxd",
                "photons": 1_000_000_000,
                "rxd": "10",
                "treasury": WAVE_TREASURY_ADDRESS,
                "published_treasury": True,
                "locking_script": _TREASURY_SCRIPT_ON_CHAIN.hex(),
            },
            "fee_vout": 1,
        }
        # --yes still discloses; --json sends the disclosure to stderr.
        assert "WAVE registration fee" in result.stderr
        assert "10.00000000 RXD" in result.stderr and WAVE_TREASURY_ADDRESS in result.stderr

    def test_the_opt_out_removes_it_and_says_so(self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> None:
        net, _key = _wire_cli(monkeypatch)
        result = _mint(tmp_path, "abcde", "--no-wave-registration-fee")
        assert result.exit_code == 0, result.output
        reveal = Transaction.from_hex(net.broadcasts[1])
        assert _TREASURY_SCRIPT_ON_CHAIN not in [o.locking_script.serialize() for o in reveal.outputs]
        assert json.loads(result.stdout)["wave_registration"]["fee_paid"] is False
        assert "NOT PAID" in result.stderr and "renewing it" in result.stderr

    def test_a_plain_nft_is_untouched(self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> None:
        net, _key = _wire_cli(monkeypatch)
        meta = tmp_path / "nft.json"
        meta.write_text(json.dumps({"protocol": ["NFT"], "name": "plain"}))
        result = CliRunner().invoke(cli, [*_global_args(tmp_path), "--json", "--yes", "glyph", "mint-nft", str(meta)])
        assert result.exit_code == 0, result.output
        assert "wave_registration" not in json.loads(result.stdout)
        assert len(Transaction.from_hex(net.broadcasts[1]).outputs) == 2  # NFT + change

    @pytest.mark.parametrize("network", ["regtest", "testnet"])
    def test_off_mainnet_it_needs_a_treasury_or_the_opt_out(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch, network: str
    ) -> None:
        net, _key = _wire_cli(monkeypatch)
        result = _mint(tmp_path, "abcde", network=network)
        assert result.exit_code != 0
        assert f"no WAVE treasury is published for {network}" in result.output
        assert net.broadcasts == []

    def test_off_mainnet_a_named_treasury_is_paid(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        net, _key = _wire_cli(monkeypatch)
        treasury = PrivateKey().public_key().address(network=Network.TESTNET)
        result = _mint(tmp_path, "abcde", "--wave-treasury", treasury, network="regtest")
        assert result.exit_code == 0, result.output
        reveal = Transaction.from_hex(net.broadcasts[1])
        assert reveal.outputs[1].locking_script.serialize() == P2PKH().lock(treasury).serialize()
        assert reveal.outputs[1].satoshis == 1_000_000_000
        assert json.loads(result.stdout)["wave_registration"]["fee"]["published_treasury"] is False

    def test_a_treasury_on_the_wrong_network_is_refused(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        net, _key = _wire_cli(monkeypatch)
        result = _mint(tmp_path, "abcde", "--wave-treasury", WAVE_TREASURY_ADDRESS, network="regtest")
        assert result.exit_code != 0 and "--wave-treasury" in result.output
        assert net.broadcasts == []

    def test_a_funding_shortfall_names_the_fee(self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """A UTXO that would fund the plain mint cannot fund the name, and the refusal says why."""
        net, _key = _wire_cli(monkeypatch, funding=100_000_000)
        result = _mint(tmp_path, "abc")
        assert result.exit_code != 0
        assert "100 RXD WAVE registration fee for abc.rxd" in result.output
        assert net.broadcasts == []
        # The honest half: the same UTXO mints the same name with the fee declined.
        result = _mint(tmp_path, "abc", "--no-wave-registration-fee")
        assert result.exit_code == 0, result.output

    def test_a_reveal_assembler_that_drops_the_fee_is_caught_before_the_commit(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The dry-run measurement is the backstop for the assembler: planted here, the CLI's
        own reveal builder loses the output, and nothing is broadcast."""
        net, _key = _wire_cli(monkeypatch)
        real = glyph_cmds._build_reveal_tx
        monkeypatch.setattr(glyph_cmds, "_build_reveal_tx", lambda **kw: real(**{**kw, "registration_fee": None}))
        result = _mint(tmp_path, "abcde")
        assert result.exit_code != 0
        assert "does not carry its WAVE registration fee" in result.output
        assert net.broadcasts == []


# ──────────────────────────── (9) GlyphMinter, which does not commit WAVE ──


class _MinterClient:
    def __init__(self) -> None:
        self.broadcasts: list[bytes] = []

    async def broadcast(self, raw: bytes) -> str:
        self.broadcasts.append(bytes(raw))
        return str(Transaction.from_hex(bytes(raw)).txid())

    async def get_transaction_verbose(self, txid: str) -> dict:
        return {"confirmations": 1}


@pytest.mark.filterwarnings("ignore:UnsafeNullPendingStore discards")
class TestGlyphMinter:
    """``GlyphMinter`` refuses to COMMIT a WAVE claim. A pending record it did not write can still
    reach its reveal; the reveal then carries the fee, and is refused unfunded."""

    def _pending(self, key: PrivateKey, commit_value: int) -> PendingMint:
        cbor = encode_payload(build_wave_metadata(qualified_name="abcdef.rxd", target=TARGET))[0]
        pkh = Hex20(key.public_key().hash160())
        return PendingMint(
            commit_txid="12" * 32,
            commit_vout=0,
            commit_value=commit_value,
            commit_script=build_commit_locking_script(hash_payload(cbor), pkh, is_nft=True),
            cbor_bytes=cbor,
            owner_pkh=bytes(pkh),
            is_nft=True,
            carrier_value=546,
            fee_rate=10_000,
            funding_address=key.address(),
        )

    def _minter(self, key: PrivateKey, client: _MinterClient) -> GlyphMinter:
        class _Wallet:
            def privkey_for_address(self, address: str) -> PrivateKey:
                return key

        return GlyphMinter(client, _Wallet(), UnsafeNullPendingStore(), poll_interval_s=0.01)

    def test_the_commit_is_refused(self) -> None:
        import asyncio

        key = PrivateKey()
        client = _MinterClient()
        with pytest.raises(ValidationError, match="cannot mint a MUT glyph|cannot mint a WAVE glyph"):
            asyncio.run(
                self._minter(key, client).commit_nft(build_wave_metadata(qualified_name="abcdef.rxd", target=TARGET))
            )
        assert client.broadcasts == []

    def test_its_reveal_assembler_includes_the_fee(self) -> None:
        key = PrivateKey()
        pending = self._pending(key, 1_000_000_000)
        tx = self._minter(key, _MinterClient())._build_reveal_tx(pending, key, P2PKH().lock(key.address()))
        assert tx.outputs[1].locking_script.serialize() == _TREASURY_SCRIPT_ON_CHAIN
        assert tx.outputs[1].satoshis == 500_000_000

    def test_an_unfunded_reveal_is_refused_naming_the_fee(self) -> None:
        import asyncio

        key = PrivateKey()
        client = _MinterClient()
        with pytest.raises(ValidationError, match="registration fee"):
            asyncio.run(self._minter(key, client).reveal_nft(self._pending(key, 5_000_546)))
        assert client.broadcasts == []


# ────────────────────────────────────────── (10) the path set is derived ──


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
        ("glyph/fees.py", "estimate_reveal_fee"): "STATES — sizing only; adds the fee output",
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
        (WAVE needs NFT, and FT excludes NFT). Were it handed one anyway, the writer refuses it."""
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
            # build_reveal_outputs states nothing, so the writer refuses a claim (above).
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
        commit_fee = {f.name: f for f in dataclasses.fields(builder_module.CommitResult)}["registration_fee_output"]
        assert commit_fee.default is dataclasses.MISSING
