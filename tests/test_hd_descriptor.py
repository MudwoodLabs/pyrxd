"""Output-script descriptor export (BIP380 subset) for watch-only import.

Two things are load-bearing here and are tested explicitly rather than by
inspection:

1. The BIP380 checksum is the *real* polymod, proven against the BIP's own
   published vector. An approximated checksum would be worse than none — it
   would be silently rejected by the very Bitcoin-lineage tools the flag
   exists to serve.
2. The key-origin field carries the **master** fingerprint, not the account
   xpub's *parent* fingerprint. Both produce descriptors that derive the
   correct addresses, so a wrong one looks fine right up until a consumer
   tries to match the descriptor to a signing device.
"""

from __future__ import annotations

import os

import pytest

from pyrxd.hd.bip32 import Xprv, Xpub, master_xprv_from_seed
from pyrxd.hd.bip39 import mnemonic_from_entropy, seed_from_mnemonic
from pyrxd.hd.descriptor import (
    CHECKSUM_CHARSET,
    EXTERNAL_CHAIN,
    INPUT_CHARSET,
    INTERNAL_CHAIN,
    account_descriptors,
    append_checksum,
    descriptor_checksum,
    key_origin,
    normalize_path,
    pkh_descriptor,
    verify_checksum,
)
from pyrxd.hd.wallet import HdWallet
from pyrxd.security.errors import KeyMaterialError, ValidationError

# The published BIP39 all-zero-entropy test mnemonic. It is the same vector the
# rest of this suite uses (tests/test_hd_wallet.py, tests/test_agent_signer.py);
# it is world-known and must never hold value. NOT a hand-written key — every
# freshly generated wallet below uses os.urandom entropy.
PUBLISHED_TEST_MNEMONIC = (
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
)


def _fresh_wallet(**kwargs: object) -> HdWallet:
    """A wallet from real entropy. Never funded, never persisted."""
    return HdWallet.from_mnemonic(mnemonic_from_entropy(os.urandom(16)), **kwargs)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# BIP380 checksum


class TestBip380Checksum:
    def test_charset_constants(self) -> None:
        # The charsets ARE the algorithm; a transcription slip would change
        # every checksum we emit while still "looking right".
        assert len(INPUT_CHARSET) == 95
        assert len(set(INPUT_CHARSET)) == 95
        assert len(CHECKSUM_CHARSET) == 32
        assert len(set(CHECKSUM_CHARSET)) == 32

    def test_published_bip380_vector(self) -> None:
        """The only checksum vector BIP380 publishes: raw(deadbeef)#89f8spxm."""
        assert descriptor_checksum("raw(deadbeef)") == "89f8spxm"
        assert append_checksum("raw(deadbeef)") == "raw(deadbeef)#89f8spxm"
        assert verify_checksum("raw(deadbeef)#89f8spxm") is True

    @pytest.mark.parametrize(
        ("bad", "why"),
        [
            ("raw(deadbeef)", "no checksum at all"),
            ("raw(deadbeef)#", "empty checksum"),
            ("raw(deadbeef)#89f8spxmx", "9 chars — too long"),
            ("raw(deadbeef)#89f8spx", "7 chars — too short"),
            ("raw(deedbeef)#89f8spxm", "error in the payload"),
            ("raw(deedbeef)##9f8spxm", "error in the checksum"),
            ("raw(Ü)#00000000", "character outside the input charset"),
        ],
    )
    def test_published_bip380_negative_vectors(self, bad: str, why: str) -> None:
        assert verify_checksum(bad) is False, why

    def test_verify_checksum_never_raises_on_junk(self) -> None:
        for junk in ("", "#", "########", "a" * 200, "\x00\x01", "pkh()#zzzzzzzz"):
            assert verify_checksum(junk) is False

    def test_round_trip_on_real_descriptors(self) -> None:
        wallet = _fresh_wallet()
        for desc in (wallet.descriptors().receive, wallet.descriptors().change):
            assert verify_checksum(desc) is False  # unchecksummed by default
            assert verify_checksum(append_checksum(desc)) is True

    def test_single_character_edit_breaks_the_checksum(self) -> None:
        """A checksum that does not detect edits is decoration, not a checksum."""
        wallet = _fresh_wallet()
        good = append_checksum(wallet.descriptors().receive)
        body, _, tail = good.rpartition("#")
        # Flip one base58 character in the xpub body.
        idx = body.index("xpub") + 10
        swapped = "a" if body[idx] != "a" else "b"
        corrupted = f"{body[:idx]}{swapped}{body[idx + 1 :]}#{tail}"
        assert verify_checksum(corrupted) is False

    @pytest.mark.parametrize("length", [1, 2, 3, 4, 5, 6, 7])
    def test_handles_every_input_length_modulo_three(self, length: int) -> None:
        """BIP380 expands characters in groups of 3, with a distinct tail case
        for a remainder of 1 and of 2. Both tails must round-trip."""
        payload = "a" * length
        assert verify_checksum(append_checksum(payload)) is True

    def test_rejects_already_checksummed_input(self) -> None:
        with pytest.raises(ValidationError, match="already contains"):
            descriptor_checksum("raw(deadbeef)#89f8spxm")

    def test_rejects_out_of_charset(self) -> None:
        with pytest.raises(ValidationError, match="input charset"):
            descriptor_checksum("raw(Ü)")

    def test_a_doubly_checksummed_descriptor_is_rejected(self) -> None:
        """``#`` is a member of INPUT_CHARSET, so ``raw(deadbeef)#89f8spxm#4x0avkn4``
        polymods correctly and ``verify_checksum`` returned True for it — while
        Bitcoin Core's ``descsum_check`` rejects it and ``descriptor_checksum``
        already refuses to *create* one. Accepting what we will not emit, and what
        the consumer will not take, is the wrong half to be lenient in."""
        doubled = "raw(deadbeef)#89f8spxm#4x0avkn4"
        # Sanity: the vector really is a valid polymod over the inner string, so
        # the only thing rejecting it is the new one-`#` rule.
        assert doubled.startswith(append_checksum("raw(deadbeef)"))
        assert verify_checksum(doubled) is False

    def test_a_checksum_embedded_mid_string_is_rejected(self) -> None:
        assert verify_checksum("raw(dead#beef)#89f8spxm") is False


# ---------------------------------------------------------------------------
# Path + key origin


class TestNormalizePath:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("m/44'/512'/0'", "44h/512h/0h"),
            ("m/44h/512h/0h", "44h/512h/0h"),
            ("m/44H/512H/0H", "44h/512h/0h"),
            ("44'/512'/0'", "44h/512h/0h"),
            ("m/44'/0'/3'", "44h/0h/3h"),
            ("m/0/1", "0/1"),
            ("m", ""),
            ("m/", ""),
        ],
    )
    def test_normalization(self, raw: str, expected: str) -> None:
        assert normalize_path(raw) == expected

    def test_idempotent(self) -> None:
        once = normalize_path("m/44'/512'/0'")
        assert normalize_path(once) == once

    @pytest.mark.parametrize("bad", ["m/44x", "m/-1", "m/44''", "m/foo", "m/1.5", "m/2147483648'"])
    def test_malformed_rejected(self, bad: str) -> None:
        with pytest.raises(ValidationError):
            normalize_path(bad)


class TestKeyOrigin:
    def test_shape(self) -> None:
        assert key_origin(bytes.fromhex("bbba2473"), "m/44'/512'/0'") == "[bbba2473/44h/512h/0h]"

    def test_master_only(self) -> None:
        assert key_origin(bytes.fromhex("00112233"), "m") == "[00112233]"

    @pytest.mark.parametrize("bad", [b"", b"\x01\x02\x03", b"\x01\x02\x03\x04\x05"])
    def test_wrong_fingerprint_length_rejected(self, bad: bytes) -> None:
        with pytest.raises(ValidationError, match="exactly 4 bytes"):
            key_origin(bad, "m/44'/512'/0'")

    def test_non_bytes_fingerprint_rejected(self) -> None:
        with pytest.raises(ValidationError, match="must be bytes"):
            key_origin("bbba2473", "m/44'/512'/0'")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# pkh() construction


class TestPkhDescriptor:
    def test_shape(self) -> None:
        wallet = _fresh_wallet()
        xpub = wallet.account_xpub()
        desc = pkh_descriptor(
            xpub,
            master_fingerprint=wallet.master_fingerprint(),
            account_path="m/44'/512'/0'",
            chain=EXTERNAL_CHAIN,
        )
        assert desc == f"pkh([{wallet.master_fingerprint().hex()}/44h/512h/0h]{xpub}/0/*)"

    def test_hardened_marker_is_h_not_apostrophe(self) -> None:
        """`h` and `'` both parse, but `'` cannot be pasted inside a shell's single quotes."""
        desc = _fresh_wallet().descriptors().receive
        assert "'" not in desc
        assert "44h/512h/0h" in desc

    def test_accepts_xpub_string(self) -> None:
        wallet = _fresh_wallet()
        as_obj = pkh_descriptor(
            wallet.account_xpub(),
            master_fingerprint=wallet.master_fingerprint(),
            account_path=wallet.account_path,
            chain=0,
        )
        as_str = pkh_descriptor(
            str(wallet.account_xpub()),
            master_fingerprint=wallet.master_fingerprint(),
            account_path=wallet.account_path,
            chain=0,
        )
        assert as_obj == as_str

    def test_refuses_xprv(self) -> None:
        """An xprv in a descriptor exports spending authority. Must fail closed."""
        wallet = _fresh_wallet()
        xprv_str = wallet._xprv.serialize()
        assert xprv_str.startswith("xprv")
        with pytest.raises(ValidationError, match="PUBLIC"):
            pkh_descriptor(
                xprv_str,
                master_fingerprint=wallet.master_fingerprint(),
                account_path=wallet.account_path,
                chain=0,
            )

    def test_refuses_non_key_junk(self) -> None:
        wallet = _fresh_wallet()
        junk_values: tuple[object, ...] = (
            "",
            "not-a-key",
            "1LADBdBEtB1QCRPsWhfrAv4RFeAzAiSeWM",
            None,
            42,
            b"\x00" * 78,  # right length, wrong type — must not sneak through
            ["xpub"],
        )
        for junk in junk_values:
            with pytest.raises(ValidationError):
                pkh_descriptor(
                    junk,  # type: ignore[arg-type]
                    master_fingerprint=wallet.master_fingerprint(),
                    account_path=wallet.account_path,
                    chain=0,
                )

    @pytest.mark.parametrize("bad_chain", [-1, 2**31, 2**32, True, False, "0", 1.0, None])
    def test_rejects_bad_chain(self, bad_chain: object) -> None:
        wallet = _fresh_wallet()
        with pytest.raises(ValidationError):
            pkh_descriptor(
                wallet.account_xpub(),
                master_fingerprint=wallet.master_fingerprint(),
                account_path=wallet.account_path,
                chain=bad_chain,  # type: ignore[arg-type]
            )

    def test_checksum_flag(self) -> None:
        wallet = _fresh_wallet()
        kwargs = {
            "master_fingerprint": wallet.master_fingerprint(),
            "account_path": wallet.account_path,
            "chain": 0,
        }
        bare = pkh_descriptor(wallet.account_xpub(), **kwargs)  # type: ignore[arg-type]
        checked = pkh_descriptor(wallet.account_xpub(), checksum=True, **kwargs)  # type: ignore[arg-type]
        assert checked == append_checksum(bare)
        assert verify_checksum(checked) is True


class TestAccountDescriptors:
    def test_both_chains_present_and_distinct(self) -> None:
        wallet = _fresh_wallet()
        d = account_descriptors(
            wallet.account_xpub(),
            master_fingerprint=wallet.master_fingerprint(),
            account_path=wallet.account_path,
        )
        assert d.receive.endswith("/0/*)")
        assert d.change.endswith("/1/*)")
        assert d.receive != d.change
        assert d.account_path == "44h/512h/0h"
        assert d.master_fingerprint == wallet.master_fingerprint().hex()

    def test_as_dict_keys(self) -> None:
        d = _fresh_wallet().descriptors().as_dict()
        assert set(d) == {
            "descriptor_receive",
            "descriptor_change",
            "master_fingerprint",
            "descriptor_origin_path",
        }


# ---------------------------------------------------------------------------
# HdWallet integration — the properties that actually matter


class TestWalletMasterFingerprint:
    def test_is_the_master_not_the_parent(self) -> None:
        """Xkey.fingerprint on the account xpub is the PARENT (m/44'/coin') fingerprint.

        Using it in a descriptor is a silent correctness bug: addresses still
        derive correctly, so nothing looks broken, but the descriptor
        misidentifies its own origin.
        """
        wallet = _fresh_wallet()
        master_fp = wallet.master_fingerprint()
        parent_fp = wallet.account_xpub().fingerprint
        assert len(master_fp) == 4
        assert master_fp != parent_fp
        assert master_fp.hex() in wallet.descriptors().receive
        assert parent_fp.hex() not in wallet.descriptors().receive

    def test_matches_independently_derived_master(self) -> None:
        mnemonic = mnemonic_from_entropy(os.urandom(16))
        wallet = HdWallet.from_mnemonic(mnemonic)
        master = master_xprv_from_seed(seed_from_mnemonic(mnemonic))
        assert wallet.master_fingerprint() == master.public_key().hash160()[:4]
        # A master key's own payload fingerprint field is all-zero by BIP32;
        # the *identifier* fingerprint we want is not.
        assert master.fingerprint == b"\x00\x00\x00\x00"

    def test_stable_across_reconstruction(self) -> None:
        mnemonic = mnemonic_from_entropy(os.urandom(16))
        assert HdWallet.from_mnemonic(mnemonic).master_fingerprint() == (
            HdWallet.from_mnemonic(mnemonic).master_fingerprint()
        )

    def test_independent_of_account_and_coin_type(self) -> None:
        """The master fingerprint identifies the SEED, so it must not move with the path."""
        mnemonic = mnemonic_from_entropy(os.urandom(16))
        base = HdWallet.from_mnemonic(mnemonic).master_fingerprint()
        assert HdWallet.from_mnemonic(mnemonic, account=7).master_fingerprint() == base
        assert HdWallet.from_mnemonic(mnemonic, coin_type=0).master_fingerprint() == base

    def test_fails_closed_after_zeroize(self) -> None:
        wallet = _fresh_wallet()
        wallet.zeroize()
        with pytest.raises(KeyMaterialError):
            wallet.master_fingerprint()
        with pytest.raises(KeyMaterialError):
            wallet.descriptors()


class TestDescriptorDerivationAgreement:
    """The property that matters: a descriptor that parses but derives
    different addresses than the wallet is worse than no descriptor at all."""

    @pytest.mark.parametrize("chain", [EXTERNAL_CHAIN, INTERNAL_CHAIN])
    def test_descriptor_xpub_derives_wallet_addresses(self, chain: int) -> None:
        wallet = _fresh_wallet()
        desc = wallet.descriptors().receive if chain == EXTERNAL_CHAIN else wallet.descriptors().change
        # Pull the xpub straight out of the emitted descriptor string — this
        # exercises the actual bytes a consumer would parse, not an internal.
        xpub_str = desc.split("]", 1)[1].split("/", 1)[0]
        branch = Xpub(xpub_str).ckd(chain)
        for index in range(8):
            assert branch.ckd(index).address() == wallet.derive_address(chain, index)

    def test_chain_indices_match_wallet_convention(self) -> None:
        """pyrxd's external chain is 0 and internal (change) is 1."""
        wallet = _fresh_wallet()
        receive_addr = wallet.next_receive_address()
        assert receive_addr == wallet.derive_address(EXTERNAL_CHAIN, 0)
        assert wallet.addresses["0/0"].change == EXTERNAL_CHAIN
        change_index = wallet._next_change_index()
        assert wallet.addresses[f"1/{change_index}"].change == INTERNAL_CHAIN

    def test_coin_type_and_account_flow_into_origin_path(self) -> None:
        mnemonic = mnemonic_from_entropy(os.urandom(16))
        d = HdWallet.from_mnemonic(mnemonic, account=3, coin_type=0).descriptors()
        assert d.account_path == "44h/0h/3h"
        assert "/44h/0h/3h]" in d.receive


class TestNoPrivateMaterialLeaks:
    def test_descriptor_contains_no_xprv_or_seed(self) -> None:
        wallet = _fresh_wallet()
        xprv_str = wallet._xprv.serialize()
        seed_hex = wallet._seed.unsafe_raw_bytes().hex()
        master_xprv = master_xprv_from_seed(wallet._seed.unsafe_raw_bytes()).serialize()
        emitted = " ".join(
            [
                wallet.descriptors().receive,
                wallet.descriptors().change,
                wallet.descriptors(checksum=True).receive,
                wallet.descriptors(checksum=True).change,
                str(wallet.descriptors()),
                repr(wallet.descriptors()),
            ]
        )
        assert "xprv" not in emitted
        assert xprv_str not in emitted
        assert master_xprv not in emitted
        assert seed_hex not in emitted
        # Also: no substring of the seed long enough to matter.
        for start in range(0, len(seed_hex) - 16, 8):
            assert seed_hex[start : start + 16] not in emitted

    def test_descriptor_is_watch_only_by_construction(self) -> None:
        """Everything between the origin and the range suffix must be an xpub."""
        desc = _fresh_wallet().descriptors().receive
        key_part = desc.split("]", 1)[1].split("/", 1)[0]
        assert key_part.startswith("xpub")
        assert isinstance(Xpub(key_part), Xpub)
        with pytest.raises(ValidationError):
            Xprv(key_part)

    def test_a_mutated_Xpub_instance_cannot_smuggle_an_xprv_into_a_descriptor(self) -> None:
        """``_coerce_xpub``'s ``Xpub``-instance branch returned ``str(xpub)`` with no
        re-validation, while the string branch had an explicit raise.
        ``Xkey.payload`` is a plain mutable attribute and ``Xkey.__str__``
        re-encodes it on every call, so an object that passed ``Xpub.__init__``
        could afterwards be made to serialise an **xprv** — and the descriptor
        would carry the wallet's spending key to wherever it was pasted.

        Not reachable from ``src/`` today. This is a key boundary, and the guard
        must be explicit rather than by-construction."""
        wallet = _fresh_wallet()
        master_xprv = master_xprv_from_seed(wallet._seed.unsafe_raw_bytes())
        account_xpub = wallet.account_xpub()

        smuggler = Xpub(str(account_xpub))
        smuggler.payload = master_xprv.payload  # the mutation the guard must catch
        assert str(smuggler).startswith("xprv")  # ...and it really does emit one

        with pytest.raises(ValidationError, match="extended PUBLIC key"):
            pkh_descriptor(
                smuggler,
                master_fingerprint=wallet.master_fingerprint(),
                account_path=wallet.account_path,
                chain=0,
            )

    def test_the_rejection_does_not_echo_the_xprv(self) -> None:
        """The refusal message and its whole cause chain must not carry the key
        it just refused to publish."""
        wallet = _fresh_wallet()
        master_xprv = master_xprv_from_seed(wallet._seed.unsafe_raw_bytes())
        xprv_str = master_xprv.serialize()

        smuggler = Xpub(str(wallet.account_xpub()))
        smuggler.payload = master_xprv.payload

        with pytest.raises(ValidationError) as exc:
            pkh_descriptor(
                smuggler,
                master_fingerprint=wallet.master_fingerprint(),
                account_path=wallet.account_path,
                chain=0,
            )
        node: BaseException | None = exc.value
        while node is not None:
            rendered = f"{node}{node.args!r}"
            for start in range(0, len(xprv_str) - 8):
                assert xprv_str[start : start + 8] not in rendered
            node = node.__cause__ or node.__context__

    def test_a_genuine_Xpub_instance_still_works(self) -> None:
        wallet = _fresh_wallet()
        desc = pkh_descriptor(
            wallet.account_xpub(),
            master_fingerprint=wallet.master_fingerprint(),
            account_path=wallet.account_path,
            chain=0,
        )
        assert "xpub" in desc
        assert "xprv" not in desc


class TestGoldenVector:
    """Fixed published seed → fixed descriptor. Guards against a silent
    derivation change slipping through a future refactor."""

    def test_golden_descriptors(self) -> None:
        wallet = HdWallet.from_mnemonic(PUBLISHED_TEST_MNEMONIC)
        xpub = (
            "xpub6BmWwzAQXJ1dYPpnP3eQNN3XMCYD1Tvvy455NDJ6xDMAqAUfZHEzwZUWrCTgJw7Nr9Phpk"
            "Z9Kc7nNScnuanf7DB7PTEkL78kiaejmenNZpB"
        )
        assert str(wallet.account_xpub()) == xpub
        assert wallet.master_fingerprint().hex() == "73c5da0a"
        d = wallet.descriptors()
        assert d.receive == f"pkh([73c5da0a/44h/512h/0h]{xpub}/0/*)"
        assert d.change == f"pkh([73c5da0a/44h/512h/0h]{xpub}/1/*)"
        checked = wallet.descriptors(checksum=True)
        assert checked.receive == f"pkh([73c5da0a/44h/512h/0h]{xpub}/0/*)#w5v8ec5w"
        assert checked.change == f"pkh([73c5da0a/44h/512h/0h]{xpub}/1/*)#lqfxydyk"
        assert verify_checksum(checked.receive) is True
        assert verify_checksum(checked.change) is True

    def test_golden_first_addresses(self) -> None:
        """Pins the descriptor to concrete addresses, not just to a string."""
        wallet = HdWallet.from_mnemonic(PUBLISHED_TEST_MNEMONIC)
        assert wallet.derive_address(0, 0) == "18qiat9Kff5niCcincht6efD8HhFfzL1AJ"
        assert wallet.account_path == "m/44'/512'/0'"
