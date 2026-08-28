"""The freeze predicate is named per token, because issuers do not agree on the name.

Measured 2026-08-25 against the live mainnet contracts:

    USDC 0xA0b8…eB48   isBlacklisted -> ok        isBlackListed -> reverts
    USDT 0xdAC1…1ec7   isBlacklisted -> reverts   isBlackListed -> ok

Mutually exclusive. A single hardcoded name in the shared ABI meant the pre-reveal gate reverted on
whichever token it was not written for. `is_blacklisted` turns that into a refusal rather than a
false "not frozen", so the swap was never UNSAFE — it was simply impossible, permanently, for every
USDT swap. A guard that refuses honest work is still a bug.

The fake here models the real failure. It answers only the names the CONTRACT actually has, so an
ABI naming something else reverts exactly as `eth_call` does. The pre-existing freeze-gate fake
hardcodes an `isBlacklisted` method, which is precisely why it stayed green through this change:
a double shaped to the old name cannot notice the name being wrong.
"""

from __future__ import annotations

import pytest

from pyrxd.eth_wallet.erc20 import _freeze_abi, assert_not_frozen_before_reveal, is_blacklisted
from pyrxd.eth_wallet.tokens import Erc20Token, token_for
from pyrxd.security.errors import NetworkError, ValidationError

_HTLC = "0x" + "ab" * 20
_WHO = "0x" + "cd" * 20


class _Chain:
    """A contract that answers ONLY the function names it really has."""

    def __init__(self, real_fns: set[str], frozen: bool = False) -> None:
        self._real = set(real_fns)
        self._frozen = frozen
        self.asked: list[str] = []

    def _functions(self, abi):
        chain = self

        class _Fns:
            def __getattr__(self, name):
                # web3 exposes exactly what the ABI declares; anything else is not an attribute.
                if name not in {e["name"] for e in abi}:
                    raise AttributeError(name)
                chain.asked.append(name)

                def _bound(_addr):
                    class _Call:
                        async def call(self, **_kw):
                            if name not in chain._real:
                                # The ABI named a function this contract does not implement:
                                # eth_call reverts. This is the mismatched-pin case.
                                raise Exception(f"execution reverted: no function {name}")
                            return chain._frozen

                    return _Call()

                return _bound

        return _Fns()

    # -- the rpc surface erc20._contract drives -------------------------------
    @property
    def w3(self):
        chain = self

        class _Eth:
            def contract(self, address=None, abi=None):
                class _C:
                    functions = chain._functions(abi)

                return _C()

        class _W3:
            eth = _Eth()

            class Web3:
                @staticmethod
                def to_checksum_address(a):
                    return a

        return _W3()


class _Rpc:
    def __init__(self, chain: _Chain) -> None:
        self.w3 = chain.w3


def _run(coro):
    import asyncio

    return asyncio.run(coro)


class TestTheNameComesFromTheToken:
    def test_usdc_is_asked_isBlacklisted(self):
        chain = _Chain({"isBlacklisted"})
        assert _run(is_blacklisted(_Rpc(chain), token_for("USDC", 1), _WHO)) is False
        assert chain.asked == ["isBlacklisted"]

    def test_usdt_is_asked_isBlackListed(self):
        """The regression. Before this, USDT was asked `isBlacklisted`, which its contract does not
        implement, so the gate reverted and every USDT swap refused to reveal."""
        chain = _Chain({"isBlackListed"})
        assert _run(is_blacklisted(_Rpc(chain), token_for("USDT", 1), _WHO)) is False
        assert chain.asked == ["isBlackListed"], "USDT must be asked by ITS name, not USDC's"

    def test_a_frozen_address_is_reported_frozen_under_either_name(self):
        for token, fn in ((token_for("USDC", 1), "isBlacklisted"), (token_for("USDT", 1), "isBlackListed")):
            chain = _Chain({fn}, frozen=True)
            assert _run(is_blacklisted(_Rpc(chain), token, _WHO)) is True


class TestTheHonestPathStillPasses:
    """Pairing every refusal with a proof the legitimate case still completes. The bug this fixes
    WAS a refusal of honest work, so a fix that merely refuses differently is no fix."""

    @pytest.mark.parametrize("symbol,fn", [("USDC", "isBlacklisted"), ("USDT", "isBlackListed")])
    def test_an_unfrozen_swap_reaches_the_reveal(self, symbol, fn):
        chain = _Chain({fn})
        token = token_for(symbol, 1)
        _run(assert_not_frozen_before_reveal(_Rpc(chain), token, htlc_address=_HTLC, parties={"maker": _WHO}))
        assert chain.asked == [fn, fn], "the contract AND the party are both checked"


class TestAMismatchedPinFailsClosed:
    def test_wrong_name_raises_rather_than_reporting_not_frozen(self):
        """If a future entry pins the wrong spelling, the call reverts. That must not be read as
        'not frozen' — it is the one gate standing in front of an unrecoverable loss."""
        token = Erc20Token("FAKE", "0x" + "11" * 20, 6, 1, blacklist_fn="isBlacklisted")
        chain = _Chain({"isBlackListed"})  # the contract has the OTHER spelling
        with pytest.raises(NetworkError, match="could not determine"):
            _run(is_blacklisted(_Rpc(chain), token, _WHO))

    def test_the_gate_refuses_so_the_preimage_stays_secret(self):
        token = Erc20Token("FAKE", "0x" + "11" * 20, 6, 1, blacklist_fn="isBlacklisted")
        chain = _Chain({"isBlackListed"})
        with pytest.raises(NetworkError):
            _run(assert_not_frozen_before_reveal(_Rpc(chain), token, htlc_address=_HTLC))


class TestTheNameCannotBeFreeFormText:
    """It is interpolated into an ABI, so it is validated at construction rather than at use."""

    @pytest.mark.parametrize("bad", ["", "has space", "1leading", "with-dash", "a(b)", None, 7])
    def test_a_non_identifier_is_refused(self, bad):
        with pytest.raises(ValidationError, match="identifier"):
            Erc20Token("X", "0x" + "11" * 20, 6, 1, blacklist_fn=bad)

    def test_the_abi_declares_exactly_one_function_and_it_is_the_pinned_name(self):
        abi = _freeze_abi(token_for("USDT", 1))
        assert len(abi) == 1
        assert abi[0]["name"] == "isBlackListed"
        assert abi[0]["stateMutability"] == "view", "the freeze read must never be able to mutate"


class TestAPinnedNonFreezableTokenIsNotProbed:
    def test_no_call_is_made_at_all(self):
        """has_blacklist=False is a claim, and the point of pinning it is to avoid a probe whose
        failure is indistinguishable from an answer."""
        token = Erc20Token("NOFREEZE", "0x" + "22" * 20, 18, 1, has_blacklist=False)
        chain = _Chain(set())
        assert _run(is_blacklisted(_Rpc(chain), token, _WHO)) is False
        assert chain.asked == []


class TestTheRegistryOnlyPinsWhatWasVerified:
    """Pins the outcome of the 2026-08-25 probe of every supported chain, so a later "just add the
    other chains" edit has to confront what that probe found."""

    def test_arbitrum_usdt0_is_refused_by_name(self):
        """0xFd086bC7… reports symbol "USD\u20ae0", not "USDT" — an omnichain variant, a different
        asset. Resolving it as USDT would fund a swap in something nobody priced."""
        from pyrxd.eth_wallet.tokens import token_by_address

        with pytest.raises(ValidationError, match="USDT0"):
            token_by_address("0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9", 42161)

    def test_usdt_is_pinned_only_where_the_admin_surface_was_read(self):
        """Ethereum (freezable, `isBlackListed`) plus the two OP-stack bridged tokens whose
        IMMUTABILITY was positively established — not merely "no freeze function answered"."""
        from pyrxd.eth_wallet.tokens import KNOWN_TOKENS

        usdt_chains = sorted(cid for sym, cid in KNOWN_TOKENS if sym == "USDT")
        assert usdt_chains == [1, 10, 8453], (
            f"USDT pinned on {usdt_chains}. Linea is deliberately absent: it is an EIP-1967 proxy "
            "with a live admin, so it can be UPGRADED into a token that freezes."
        )

    def test_the_bridged_tokens_are_pinned_as_non_freezable(self):
        """Justified by disassembly (no DELEGATECALL/SELFDESTRUCT, not a proxy, no owner/pause),
        not by a probe returning nothing."""
        from pyrxd.eth_wallet.tokens import token_for

        for cid in (10, 8453):
            assert token_for("USDT", cid).has_blacklist is False
        assert token_for("USDT", 1).has_blacklist is True, "L1 USDT can freeze and must stay pinned so"

    def test_linea_usdt_is_not_pinned_because_it_is_upgradeable(self):
        from pyrxd.eth_wallet.tokens import token_for

        with pytest.raises(ValidationError, match="no pinned"):
            token_for("USDT", 59144)

    def test_every_pinned_token_names_a_usable_freeze_predicate(self):
        from pyrxd.eth_wallet.tokens import KNOWN_TOKENS

        for (sym, cid), tok in KNOWN_TOKENS.items():
            assert tok.blacklist_fn.isidentifier(), f"{sym}/{cid} has an unusable blacklist_fn"
            if tok.has_blacklist:
                assert tok.blacklist_fn, f"{sym}/{cid} claims it can freeze but names no predicate"
