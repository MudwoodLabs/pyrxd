"""``pyrxd.glyph.transfer.build_nft_transfer`` — the funded NFT transfer path.

This path was reachable only through ``cli/glyph_cmds.py`` until it was extracted, so
nothing outside the CLI could move an NFT at all. The importable builder that *looks*
like the way to do it, :meth:`~pyrxd.glyph.builder.GlyphBuilder.build_nft_transfer_tx`,
spends the singleton alone and takes the fee out of its own value — which refuses
outright on a dust-valued NFT, i.e. on essentially every NFT.

``TestWhyTheSelfFundedBuilderIsNotUsed`` measures that rather than asserting it. The
distinction matters here: the FT side of :mod:`pyrxd.glyph.transfer` carried a
similar-sounding claim that turned out to describe a defect **already fixed** in #393,
quoted in the present tense from another module's history note. This file exists so
the NFT claim cannot decay the same way — if the builder ever learns to take funding,
these tests fail and the comments get rewritten.

Every refusal case below is paired with an honest case that must still pass. Radiant
has neither RBF nor CPFP, so a build refused late costs an aborted send, but a build
admitted wrongly cannot be repaired at all.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from pyrxd.glyph.script import build_nft_locking_script, extract_ref_from_nft_script
from pyrxd.glyph.transfer import build_nft_transfer, nft_transfer_funding_bar
from pyrxd.glyph.types import GlyphRef
from pyrxd.keys import PrivateKey
from pyrxd.network.electrumx import UtxoRecord
from pyrxd.script.script import Script
from pyrxd.script.type import P2PKH
from pyrxd.security.errors import InsufficientFundsError, ValidationError
from pyrxd.security.types import Hex20
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_output import TransactionOutput

FEE_RATE = 10_000  # Radiant's relay floor, not a token test rate
NFT_VALUE = 1_000


def _src(vout: int, spk: bytes, value: int) -> bytes:
    outs = [TransactionOutput(Script(b""), 0) for _ in range(vout)]
    outs.append(TransactionOutput(Script(spk), value))
    return Transaction(tx_inputs=[], tx_outputs=outs).serialize()


class _Harness:
    """A wallet holding one NFT and one plain-RXD UTXO, over FRESH keys.

    Fresh keys per construction on purpose: signing is RFC 6979, so whether a given
    transaction underpays is a fixed property of that transaction rather than a flake.
    A fixed-key fixture signs one message forever and cannot see a defect that lands
    on a fraction of real sends.
    """

    def __init__(self, *, fund_value: int, hold_nft: bool = True) -> None:
        self.owner_key = PrivateKey()
        self.fund_key = PrivateKey()
        self.ref = GlyphRef(txid="aa" * 32, vout=0)
        self.nft_script = build_nft_locking_script(Hex20(self.owner_key.public_key().hash160()), self.ref)
        self.fund_spk = P2PKH().lock(self.fund_key.address()).serialize()

        self.nft_utxo = UtxoRecord(tx_hash="bb" * 32, tx_pos=1, value=NFT_VALUE, height=100)
        self.fund_utxo = UtxoRecord(tx_hash="cc" * 32, tx_pos=1, value=fund_value, height=100)

        txmap = {
            "bb" * 32: _src(1, self.nft_script, NFT_VALUE),
            "cc" * 32: _src(1, self.fund_spk, fund_value),
        }
        triples = [
            (self.fund_utxo, self.fund_key.address(), self.fund_key),
        ]
        if hold_nft:
            triples.insert(0, (self.nft_utxo, self.owner_key.address(), self.owner_key))

        harness = self

        class _Wallet:
            async def collect_spendable(self, client):
                return triples

        self.wallet = _Wallet()
        self.client = MagicMock()
        self.client.get_transaction = AsyncMock(side_effect=lambda t: txmap[str(t)])
        self.recipient_pkh = Hex20(PrivateKey().public_key().hash160())
        self.bar = nft_transfer_funding_bar(build_nft_locking_script(harness.recipient_pkh, harness.ref), FEE_RATE)

    async def build(self):
        return await build_nft_transfer(
            self.wallet, self.ref, self.recipient_pkh, client=self.client, fee_rate=FEE_RATE
        )


class TestTheHonestPath:
    @pytest.mark.asyncio
    async def test_the_singleton_keeps_its_value_and_its_ref(self) -> None:
        """The property that makes this path necessary at all.

        ``build_nft_transfer_tx`` pays the fee out of the singleton, shrinking it every
        hop until it can no longer move. Here the fee comes from plain RXD, so the
        carrier's value crosses unchanged.
        """
        h = _Harness(fund_value=h_fund_value())
        build = await h.build()

        nft_out = build.tx.outputs[0]
        assert nft_out.satoshis == NFT_VALUE, "the fee was taken out of the singleton"
        assert extract_ref_from_nft_script(nft_out.locking_script.serialize()) == h.ref

    @pytest.mark.asyncio
    async def test_the_recipient_owns_the_new_lock(self) -> None:
        h = _Harness(fund_value=h_fund_value())
        build = await h.build()
        expected = build_nft_locking_script(h.recipient_pkh, h.ref)
        assert build.tx.outputs[0].locking_script.serialize() == expected

    @pytest.mark.asyncio
    async def test_the_fee_comes_from_the_funding_input(self) -> None:
        """Two inputs, and the fee is the funding UTXO's shortfall — not the NFT's."""
        h = _Harness(fund_value=h_fund_value())
        build = await h.build()
        assert len(build.tx.inputs) == 2
        assert build.fee > 0
        assert build.has_change is True

    @pytest.mark.asyncio
    async def test_it_pays_for_its_own_size_at_the_relay_floor(self) -> None:
        """The check that has to hold on the bytes actually broadcast."""
        h = _Harness(fund_value=h_fund_value())
        build = await h.build()
        assert build.fee >= len(build.serialize()) * FEE_RATE

    @pytest.mark.asyncio
    async def test_serialize_returns_bytes(self) -> None:
        """``ElectrumXClient.broadcast`` takes bytes. The FT sibling was annotated
        ``-> str`` and documented as hex while returning bytes, and that same wrong
        belief made the change guard halve every size it judged."""
        h = _Harness(fund_value=h_fund_value())
        build = await h.build()
        assert isinstance(build.serialize(), bytes)


class TestTheRefusals:
    @pytest.mark.asyncio
    async def test_an_nft_this_wallet_does_not_hold_is_refused(self) -> None:
        h = _Harness(fund_value=h_fund_value(), hold_nft=False)
        with pytest.raises(InsufficientFundsError, match="not held by this wallet"):
            await h.build()

    @pytest.mark.asyncio
    async def test_a_wrong_ref_finds_nothing_rather_than_mislocking(self) -> None:
        """The ref in the new lock is the caller's, so this is the check that stops it
        diverging from the coin's: selection parses the on-chain script and matches."""
        h = _Harness(fund_value=h_fund_value())
        with pytest.raises(InsufficientFundsError, match="not held by this wallet"):
            await build_nft_transfer(
                h.wallet,
                GlyphRef(txid="dd" * 32, vout=7),
                h.recipient_pkh,
                client=h.client,
                fee_rate=FEE_RATE,
            )

    @pytest.mark.asyncio
    async def test_funding_one_photon_under_the_bar_is_refused_before_signing(self) -> None:
        h = _Harness(fund_value=1)
        with pytest.raises(InsufficientFundsError, match="no plain-RXD UTXO large enough"):
            await h.build()

    @pytest.mark.asyncio
    async def test_funding_exactly_at_the_bar_is_accepted(self) -> None:
        """The paired honest case. A bar that refuses funding the node would in fact
        accept is its own fund-safety bug, and the bar is modelled on the no-change
        shape precisely so this holds."""
        h = _Harness(fund_value=1)
        h2 = _Harness(fund_value=h.bar)
        build = await h2.build()
        assert build.fee >= len(build.serialize()) * FEE_RATE


class TestWhyTheSelfFundedBuilderIsNotUsed:
    """The differential that justifies the extraction, measured rather than argued.

    Without this, a later "simplification" routes the CLI back onto
    ``build_nft_transfer_tx`` — it is the obvious-looking API — and NFT transfers stop
    working for every ordinary token. Same guard-rail as the FT case: the module
    docstring records the measured numbers so the decision cannot be undone by someone
    reading only the type signatures.
    """

    def _self_funded(self, value: int):
        import os

        from pyrxd.glyph.builder import GlyphBuilder, TransferParams

        key = PrivateKey()
        ref = GlyphRef(txid="aa" * 32, vout=0)
        return GlyphBuilder().build_nft_transfer_tx(
            TransferParams(
                nft_utxo_txid=os.urandom(32).hex(),
                nft_utxo_vout=0,
                nft_utxo_value=value,
                nft_script=build_nft_locking_script(Hex20(key.public_key().hash160()), ref),
                new_owner_pkh=Hex20(PrivateKey().public_key().hash160()),
                private_key=key,
                fee_rate=FEE_RATE,
            )
        )

    @pytest.mark.parametrize("carried", [546, 1_000, 10_000, 1_000_000])
    def test_it_cannot_move_an_ordinary_dust_carrying_nft(self, carried: int) -> None:
        """Measured at the relay floor: it refuses below ~2,330,546 photons, because
        the fee (~2.33 RXD-photons worth of bytes) comes out of the singleton itself.
        An NFT singleton carries dust, so this is every ordinary NFT."""
        with pytest.raises(ValueError, match="too small to cover transfer"):
            self._self_funded(carried)

    def test_the_funded_path_moves_exactly_that_nft(self) -> None:
        """The pairing that makes the point: same 1,000-photon singleton, and this
        module's path moves it, because the fee comes from plain RXD instead."""
        h = _Harness(fund_value=h_fund_value())
        assert h.nft_utxo.value == NFT_VALUE == 1_000

        import asyncio

        build = asyncio.run(h.build())
        assert build.tx.outputs[0].satoshis == 1_000

    def test_when_it_does_build_it_erodes_the_carrier(self) -> None:
        """Why 'fund it better' is not the answer either: the value it takes is gone
        from the singleton, so a carrier funded to survive one hop may not survive two."""
        carried = 5_000_000
        result = self._self_funded(carried)
        assert result.fee > 2_000_000
        assert result.tx.outputs[0].satoshis == carried - result.fee


def h_fund_value() -> int:
    """Comfortably above the bar, so the honest-path tests exercise the change branch."""
    return 50_000_000


class TestFtSelectionDoesNotRefuseWhatItPicked:
    """Selection must not construct a spend the next call then rejects.

    `FtUtxoSet` signs every input with one key, so `single_ft_signing_key` refuses a
    selection spanning addresses. Selection used to sort the WHOLE wallet by amount and
    take greedily, which produced exactly such selections — and the user was told to
    "consolidate the token to one address first" even when one address already covered
    the amount on its own. A guard refusing valid work is its own bug; this one refused
    work it had itself constructed.
    """

    @staticmethod
    def _wallet_with(holdings: dict[str, list[int]], ref):
        """`{address_seed: [unit amounts]}` -> (wallet, client) over real scripts."""
        from unittest.mock import AsyncMock, MagicMock

        from pyrxd.glyph.script import build_ft_locking_script

        triples, txmap = [], {}
        for i, (_seed, amounts) in enumerate(sorted(holdings.items())):
            key = PrivateKey()
            spk = build_ft_locking_script(Hex20(key.public_key().hash160()), ref)
            for j, amt in enumerate(amounts):
                txid = f"{i:02x}{j:02x}" + "0" * 60
                triples.append((UtxoRecord(tx_hash=txid, tx_pos=0, value=amt, height=1), key.address(), key))
                txmap[txid] = _src(0, spk, amt)

        wallet = MagicMock()
        wallet.collect_spendable = AsyncMock(return_value=triples)
        client = MagicMock()
        client.get_transaction = AsyncMock(side_effect=lambda t: txmap[str(t)])
        return wallet, client

    @pytest.mark.asyncio
    async def test_it_uses_the_address_that_can_cover_alone(self) -> None:
        """THE regression case: A=100+100, B=150, amount=200.

        Old behaviour sorted by amount (B=150 first, then A=100), spanned two
        addresses, and was refused. A alone covers 200 exactly.
        """
        from pyrxd.glyph.transfer import select_ft_inputs, single_ft_signing_key

        ref = GlyphRef(txid="aa" * 32, vout=0)
        wallet, client = self._wallet_with({"A": [100, 100], "B": [150]}, ref)

        selected = await select_ft_inputs(wallet, ref, 200, client)

        assert sum(t[0].ft_amount for t in selected) >= 200
        assert len({t[1] for t in selected}) == 1, "selection spans addresses and will be refused"
        single_ft_signing_key(selected, "FT transfer")  # must not raise

    @pytest.mark.asyncio
    async def test_no_single_address_covers_says_so_precisely(self) -> None:
        """When consolidation really IS required, the message must say why.

        The wallet total is sufficient; no single address is. That is a genuinely
        different situation from "you do not have enough", and it gets its own wording.
        """
        from pyrxd.glyph.transfer import select_ft_inputs

        ref = GlyphRef(txid="aa" * 32, vout=0)
        wallet, client = self._wallet_with({"A": [100], "B": [100]}, ref)

        with pytest.raises(InsufficientFundsError) as exc:
            await select_ft_inputs(wallet, ref, 150, client)
        msg = str(exc.value)
        assert "any single address" in msg
        assert "Consolidate" in msg

    @pytest.mark.asyncio
    async def test_it_prefers_fewer_inputs_over_a_smaller_holding(self) -> None:
        """The fee-funding bar scales with input COUNT, so holding size is the wrong
        tie-breaker.

        Found by an adversarial reviewer against the first version of this fix, which
        took the smallest sufficient total: for amount=1000 it preferred an address
        holding 500+500 (two inputs) over one holding 1,000,000 (one input) — a more
        expensive transaction that `ft_funding` can then refuse for fee funding the
        one-input build would not have needed.
        """
        from pyrxd.glyph.transfer import select_ft_inputs

        ref = GlyphRef(txid="aa" * 32, vout=0)
        wallet, client = self._wallet_with({"many_small": [500, 500], "one_big": [1_000_000]}, ref)

        selected = await select_ft_inputs(wallet, ref, 1000, client)
        assert len(selected) == 1, "picked the multi-input address; the fee bar scales per input"

    @pytest.mark.asyncio
    async def test_a_non_positive_amount_is_refused_at_the_public_entry_point(self) -> None:
        """`select_ft_inputs` is public API; only `build_ft_transfer` used to validate."""
        from pyrxd.glyph.transfer import select_ft_inputs

        ref = GlyphRef(txid="aa" * 32, vout=0)
        wallet, client = self._wallet_with({"A": [100]}, ref)
        for bad in (0, -5):
            with pytest.raises(ValidationError, match="positive int"):
                await select_ft_inputs(wallet, ref, bad, client)

    @pytest.mark.asyncio
    async def test_it_does_not_fragment_a_large_holding(self) -> None:
        """Best fit, not first fit: a 10,000-unit address is not raided for 50 units
        when a 100-unit address can serve it."""
        from pyrxd.glyph.transfer import select_ft_inputs

        ref = GlyphRef(txid="aa" * 32, vout=0)
        wallet, client = self._wallet_with({"big": [10_000], "small": [100]}, ref)

        selected = await select_ft_inputs(wallet, ref, 50, client)
        assert sum(t[0].ft_amount for t in selected) == 100, "raided the large holding"
