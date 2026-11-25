"""A wallet spend that moves a Glyph token reads where the server lists tokens.

A Radiant ElectrumX lists a token output under the token script's hash with its refs zeroed
(``script_hash_for_output``), never under the owner's P2PKH hash. That was measured against
both public mainnet servers on 2026-09-29 (#782), and the gap-limit scan and ``glyph list``
were moved onto those hashes (#787). ``HdWallet.collect_spendable`` was not: it reads the
P2PKH hash only. The token spends selected their token from its result, so on a real server

* ``build_nft_transfer`` (``pyrxd glyph transfer-nft``, ``GlyphClient.transfer_nft``) and
* ``build_ft_transfer`` / ``build_ft_airdrop`` (``transfer-ft``, ``airdrop-ft``, the client)

raised ``NoHoldingsError`` for a token ``glyph list`` had just listed at the same address.
Their unit tests stubbed ``collect_spendable`` with the token mixed in, so nothing saw it.

Every test here uses the real ``HdWallet`` and the one fake that lists each output where a
Radiant ElectrumX lists it (``_ElectrumX`` from the ``glyph list`` tests). Each refusal case
is paired with the honest case, and the fee-funding cases check that putting token outputs
into the collection did not let one be spent as fee.
"""

from __future__ import annotations

import pytest
from test_balance_and_glyph_list_scan_by_default import _ElectrumX, _ft, _nft, _plain

from pyrxd.glyph.ft import AirdropRecipient
from pyrxd.glyph.scanner import GlyphScanner
from pyrxd.glyph.script import build_ft_locking_script, build_nft_locking_script
from pyrxd.glyph.transfer import (
    NoFeeFundingError,
    NoHoldingsError,
    build_ft_airdrop,
    build_ft_transfer,
    build_nft_transfer,
)
from pyrxd.glyph.types import GlyphFt, GlyphNft, GlyphRef
from pyrxd.hd.bip39 import mnemonic_from_entropy
from pyrxd.hd.wallet import HdWallet
from pyrxd.keys import PrivateKey
from pyrxd.network.electrumx import script_hash_for_output
from pyrxd.security.errors import NetworkError
from pyrxd.security.types import Hex20, Txid

_FEE_RATE = 10_000  # photons/byte: mainnet's relay floor (pyrxd.fee_sizing)
_FT_UNITS = 5_000


def _wallet() -> HdWallet:
    # A fresh random mnemonic per test (repo rule: never hand-write key material).
    return HdWallet.from_mnemonic(mnemonic_from_entropy())


def _recipient() -> Hex20:
    return Hex20(PrivateKey().public_key().hash160())


def _ref(salt: str) -> GlyphRef:
    return GlyphRef(txid=Txid(salt * 32), vout=0)


def _spent_outpoints(tx) -> set[tuple[str, int]]:
    return {(str(i.source_txid), i.source_output_index) for i in tx.inputs}


# --------------------------------------------------------------------------- the collection


class TestCollectSpendableIncludeTokens:
    async def test_default_lists_plain_outputs_only(self):
        """The default is unchanged: what a plain-RXD spend chooses from."""
        w = _wallet()
        a0 = w.derive_address(0, 0)
        plain, (nft_tx, _ref_nft) = _plain(a0), _nft(w, 0, 0, "ab")
        server = _ElectrumX({a0: [plain, nft_tx]})

        got = await w.collect_spendable(server)

        assert [u.tx_hash for u, _a, _k in got] == [plain.txid()]

    async def test_include_tokens_adds_the_token_outputs(self):
        w = _wallet()
        a0 = w.derive_address(0, 0)
        plain, (nft_tx, _r1), (ft_tx, _r2) = _plain(a0), _nft(w, 0, 0, "ab"), _ft(w, 0, 0, "cd", _FT_UNITS)
        server = _ElectrumX({a0: [plain, nft_tx, ft_tx]})

        got = await w.collect_spendable(server, include_tokens=True)

        assert sorted(u.tx_hash for u, _a, _k in got) == sorted([plain.txid(), nft_tx.txid(), ft_tx.txid()])
        # Each triple carries the key of the address the output is held at.
        assert {k.public_key().address() for _u, _a, k in got} == {a0}

    async def test_a_token_only_address_is_read(self):
        """The case that matters most: the scan marks the address used from its token history
        (#787), and only the token hashes list anything there."""
        w = _wallet()
        a0, a1 = w.derive_address(0, 0), w.derive_address(0, 1)
        nft_tx, _r = _nft(w, 0, 1, "ab")
        server = _ElectrumX({a0: [_plain(a0)], a1: [nft_tx]})

        got = await w.collect_spendable(server, include_tokens=True)

        assert (nft_tx.txid(), a1) in {(u.tx_hash, a) for u, a, _k in got}

    async def test_a_failed_token_read_is_a_network_error_not_an_empty_address(self):
        """Strict by default, like the P2PKH read: "not held" after a failed read would be false."""
        w = _wallet()
        a0 = w.derive_address(0, 0)
        nft_tx, _r = _nft(w, 0, 0, "ab")
        server = _ElectrumX({a0: [_plain(a0), nft_tx]})
        nft_hash = bytes(script_hash_for_output(nft_tx.outputs[0].locking_script.serialize()))
        real_get_utxos = server.get_utxos

        async def _token_read_fails(script_hash):
            if bytes(script_hash) == nft_hash:
                raise NetworkError("simulated: the token-hash read failed")
            return await real_get_utxos(script_hash)

        server.get_utxos = _token_read_fails

        with pytest.raises(NetworkError, match="address reads failed"):
            await w.collect_spendable(server, include_tokens=True)
        # Honest path: the same server without the failure answers.
        server.get_utxos = real_get_utxos
        assert len(await w.collect_spendable(server, include_tokens=True)) == 2


# --------------------------------------------------------------------------- NFT transfer


class TestNftTransferFindsAListedNft:
    async def test_the_nft_glyph_list_shows_can_be_transferred(self):
        w = _wallet()
        a0, a1 = w.derive_address(0, 0), w.derive_address(0, 1)
        nft_tx, _label = _nft(w, 0, 1, "ab")
        server = _ElectrumX({a0: [_plain(a0)], a1: [nft_tx]})
        to = _recipient()

        # What `glyph list` reads shows the NFT at a1 ...
        listed = await GlyphScanner(server).scan_address(a1)
        assert [type(i) for i in listed] == [GlyphNft]

        # ... and the transfer finds it there.
        build = await build_nft_transfer(w, _ref("ab"), to, client=server, fee_rate=_FEE_RATE)

        assert (nft_tx.txid(), 0) in _spent_outpoints(build.tx)
        assert build.tx.outputs[0].locking_script.serialize() == build_nft_locking_script(to, _ref("ab"))
        assert build.tx.outputs[0].satoshis == nft_tx.outputs[0].satoshis
        assert build.from_address == a1

    async def test_a_wallet_without_the_nft_is_still_refused(self):
        w = _wallet()
        a0 = w.derive_address(0, 0)
        nft_tx, _label = _nft(w, 0, 0, "ab")
        server = _ElectrumX({a0: [_plain(a0), nft_tx]})

        with pytest.raises(NoHoldingsError, match="not held by this wallet"):
            await build_nft_transfer(w, _ref("ef"), _recipient(), client=server, fee_rate=_FEE_RATE)

    async def test_another_token_is_not_taken_as_the_fee(self):
        """With token outputs now in the collection, the fee input must still be plain RXD.
        The only large output here is an FT, so the build refuses for want of funding."""
        w = _wallet()
        a0 = w.derive_address(0, 0)
        nft_tx, _l1 = _nft(w, 0, 0, "ab")
        ft_tx, _l2 = _ft(w, 0, 0, "cd", 100 * 100_000_000)
        server = _ElectrumX({a0: [nft_tx, ft_tx]})

        with pytest.raises(NoFeeFundingError):
            await build_nft_transfer(w, _ref("ab"), _recipient(), client=server, fee_rate=_FEE_RATE)


# --------------------------------------------------------------------------- FT transfer / airdrop


class TestFtSpendsFindListedUnits:
    async def test_the_ft_glyph_list_shows_can_be_transferred(self):
        w = _wallet()
        a0, a1 = w.derive_address(0, 0), w.derive_address(0, 1)
        ft_tx, _label = _ft(w, 0, 1, "cd", _FT_UNITS)
        # The fee input sits at a different address from the token, as it may in any wallet.
        server = _ElectrumX({a0: [_plain(a0)], a1: [ft_tx]})
        to = _recipient()

        listed = await GlyphScanner(server).scan_address(a1)
        assert [type(i) for i in listed] == [GlyphFt]

        build = await build_ft_transfer(w, _ref("cd"), 250, to, client=server, fee_rate=_FEE_RATE)

        assert (ft_tx.txid(), 0) in _spent_outpoints(build.tx)
        out0 = build.tx.outputs[0]
        assert out0.locking_script.serialize() == build_ft_locking_script(to, _ref("cd"))
        assert out0.satoshis == 250
        # Units in == units out: the change carries the rest and nothing is burned.
        ft_out = [o for o in build.tx.outputs if o.locking_script.serialize()[25:27] == b"\xbd\xd0"]
        assert sum(o.satoshis for o in ft_out) == _FT_UNITS

    async def test_an_airdrop_finds_the_units_too(self):
        w = _wallet()
        a0 = w.derive_address(0, 0)
        ft_tx, _label = _ft(w, 0, 0, "cd", _FT_UNITS)
        server = _ElectrumX({a0: [_plain(a0), ft_tx]})
        recipients = [AirdropRecipient(pkh=_recipient(), amount=100), AirdropRecipient(pkh=_recipient(), amount=200)]

        build = await build_ft_airdrop(w, _ref("cd"), recipients, client=server, fee_rate=_FEE_RATE)

        assert (ft_tx.txid(), 0) in _spent_outpoints(build.tx)
        assert [o.satoshis for o in build.tx.outputs[:2]] == [100, 200]

    async def test_a_wallet_without_the_ft_is_still_refused(self):
        w = _wallet()
        a0 = w.derive_address(0, 0)
        ft_tx, _label = _ft(w, 0, 0, "cd", _FT_UNITS)
        server = _ElectrumX({a0: [_plain(a0), ft_tx]})

        with pytest.raises(NoHoldingsError, match="no FT holdings"):
            await build_ft_transfer(w, _ref("ef"), 250, _recipient(), client=server, fee_rate=_FEE_RATE)

    async def test_the_token_is_not_taken_as_its_own_fee(self):
        """The FT is large enough to clear the fee bar on value alone; it must still be refused
        as fee, because spending it as plain RXD would burn every unit on it."""
        w = _wallet()
        a0 = w.derive_address(0, 0)
        big_ft, _l1 = _ft(w, 0, 0, "cd", 100 * 100_000_000)
        other_ft, _l2 = _ft(w, 0, 0, "ee", 100 * 100_000_000)
        server = _ElectrumX({a0: [big_ft, other_ft]})

        with pytest.raises(NoFeeFundingError):
            await build_ft_transfer(w, _ref("cd"), 250, _recipient(), client=server, fee_rate=_FEE_RATE)


# --------------------------------------------------------------------------- swap take (FT demand)


class TestSwapTakeFtFundingReadsTokens:
    """``pyrxd swap take`` of an FT-demand order pays the demand from the wallet's FT UTXOs
    (``_ft_funding``), chosen from ``_collect_funds``. The command passes
    ``include_tokens=True`` for an FT demand; this checks the two helpers it composes."""

    async def test_ft_funding_finds_listed_units(self, monkeypatch):
        from pyrxd.cli import swap_book_cmds as mod

        w = _wallet()
        a0 = w.derive_address(0, 0)
        ft_tx, _label = _ft(w, 0, 0, "cd", _FT_UNITS)
        server = _ElectrumX({a0: [_plain(a0), ft_tx]})
        monkeypatch.setattr(mod, "_load_wallet", lambda ctx: w)

        funds = await mod._collect_funds(object(), server, include_tokens=True)
        picked = await mod._ft_funding(server, funds, _ref("cd"), 250)

        assert [(p.source_tx.txid(), p.vout) for p in picked] == [(ft_tx.txid(), 0)]
        # Plain funding still skips the token output.
        plain = await mod._rxd_funding(server, funds, 1_000)
        assert all(p.source_tx.txid() != ft_tx.txid() for p in plain)

    async def test_without_tokens_the_ft_is_not_found(self, monkeypatch):
        """The refusal half: the default collection holds no FT, so the demand cannot be funded."""
        from pyrxd.cli import swap_book_cmds as mod
        from pyrxd.cli.errors import UserError

        w = _wallet()
        a0 = w.derive_address(0, 0)
        ft_tx, _label = _ft(w, 0, 0, "cd", _FT_UNITS)
        server = _ElectrumX({a0: [_plain(a0), ft_tx]})
        monkeypatch.setattr(mod, "_load_wallet", lambda ctx: w)

        funds = await mod._collect_funds(object(), server)
        with pytest.raises(UserError, match="cannot fund 250 units"):
            await mod._ft_funding(server, funds, _ref("cd"), 250)


# --------------------------------------------------------------------------- duck-typed wallets


class TestDuckTypedWalletsAreCalledAsBefore:
    """``GlyphClient`` takes "anything exposing ``collect_spendable(client)``" (its docstring),
    and ``pyrxd.testing.RegtestWallet`` and the examples are such wallets. Passing them
    ``include_tokens`` would raise ``TypeError`` in code that worked before this change."""

    async def test_a_wallet_without_the_keyword_is_asked_the_old_way(self):
        w = _wallet()
        a0 = w.derive_address(0, 0)
        nft_tx, _label = _nft(w, 0, 0, "ab")
        server = _ElectrumX({a0: [_plain(a0), nft_tx]})
        everything = await w.collect_spendable(server, include_tokens=True)
        calls: list[tuple] = []

        class _OwnWallet:
            async def collect_spendable(self, client):  # no include_tokens: it lists what it lists
                calls.append((client,))
                return list(everything)

        build = await build_nft_transfer(_OwnWallet(), _ref("ab"), _recipient(), client=server, fee_rate=_FEE_RATE)

        assert calls == [(server,)]
        assert (nft_tx.txid(), 0) in _spent_outpoints(build.tx)

    async def test_a_wallet_that_takes_the_keyword_is_passed_it(self):
        seen: list[dict] = []

        class _KwWallet:
            async def collect_spendable(self, client, **kwargs):
                seen.append(kwargs)
                return []

        from pyrxd.glyph.transfer import collect_spendable_with_tokens

        assert await collect_spendable_with_tokens(_KwWallet(), object()) == []
        assert seen == [{"include_tokens": True}]
