"""Replay conformance/bip44-derivation-vectors.json against pyrxd's HD stack.

HONESTY NOTE
------------
For this suite pyrxd is the CONSUMER, not the reference producer -- the inverse
of the dMint V2 contract vectors, where pyrxd's own output is the standard. Every
expected value in the JSON was computed by `bip-utils`, an independent BIP32/39/44
implementation with no shared lineage with `pyrxd.hd`. That independence is the
entire point: pyrxd's own goldens cannot detect a self-consistent derivation bug,
because the goldens were produced by the very code they check. A wrong-but-stable
coin_type, hardened-index, or serialization bug would pass every internal test and
silently derive an unrecoverable wallet.

Known limit, stated plainly: bip-utils and pyrxd share coincurve/libsecp256k1 for
EC point math, so a libsecp256k1 arithmetic bug is invisible to this suite. What
IS independently covered is BIP39 seed derivation and normalization, BIP32
HMAC/CKD construction, hardened-index math, coin_type path assembly, and
xprv/xpub/address/WIF serialization.

The vectors are frozen, so this test needs no third-party package. bip-utils is
deliberately NOT a pyrxd dev dependency -- it pins cbor2<6 while pyrxd requires
cbor2>=6.1. Regenerate out-of-band via scripts/gen-bip44-derivation-vectors.py.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pyrxd.hd.bip32 import ckd, master_xprv_from_seed
from pyrxd.hd.bip39 import seed_from_mnemonic

VECTORS_PATH = Path(__file__).resolve().parent.parent / "conformance" / "bip44-derivation-vectors.json"


def _load() -> dict:
    return json.loads(VECTORS_PATH.read_text(encoding="utf-8"))


_DOC = _load()
_SWEEP = _DOC["radiant_bip44_sweep"]


def _ids(vectors: list[dict]) -> list[str]:
    return [v["id"] for v in vectors]


def test_vector_file_shape() -> None:
    """The suite must actually contain vectors, across all three live coin types."""
    assert _DOC["schema"] == "radiant-bip44-derivation/1"
    assert len(_SWEEP) == _DOC["meta"]["vector_count"] > 0
    assert {v["coin_type"] for v in _SWEEP} == {0, 236, 512}


@pytest.mark.parametrize("vec", _SWEEP, ids=_ids(_SWEEP))
def test_seed_matches_reference(vec: dict) -> None:
    """BIP39: mnemonic (+ passphrase) -> 64-byte seed, byte-identical."""
    seed = seed_from_mnemonic(vec["mnemonic"], passphrase=vec["passphrase"])
    assert seed.hex() == vec["expected"]["seed_hex"]


@pytest.mark.parametrize("vec", _SWEEP, ids=_ids(_SWEEP))
def test_master_and_account_keys_match_reference(vec: dict) -> None:
    """BIP32 master + BIP44 account level serialize identically to the reference."""
    exp = vec["expected"]
    seed = seed_from_mnemonic(vec["mnemonic"], passphrase=vec["passphrase"])
    master = master_xprv_from_seed(seed)

    # Xprv.__str__ is deliberately redacted, so compare the real serialization.
    assert master.serialize() == exp["master_xprv"]
    assert str(master.xpub()) == exp["master_xpub"]

    account_path = f"m/44'/{vec['coin_type']}'/{vec['account']}'"
    acct = ckd(master, account_path)
    assert acct.serialize() == exp["account_xprv"]
    assert str(acct.xpub()) == exp["account_xpub"]


@pytest.mark.parametrize("vec", _SWEEP, ids=_ids(_SWEEP))
def test_leaf_key_address_and_wif_match_reference(vec: dict) -> None:
    """The leaf key, its P2PKH address, and its WIF all match the reference.

    The address is what actually receives funds, so a mismatch here is the
    silent-fund-loss case this whole suite exists to catch.
    """
    exp = vec["expected"]
    seed = seed_from_mnemonic(vec["mnemonic"], passphrase=vec["passphrase"])
    leaf = ckd(master_xprv_from_seed(seed), vec["path"])

    assert leaf.serialize() == exp["leaf_xprv"]
    assert str(leaf.xpub()) == exp["leaf_xpub"]
    assert leaf.address() == exp["address"]
    assert leaf.private_key().wif() == exp["wif"]


@pytest.mark.parametrize("vec", _SWEEP, ids=_ids(_SWEEP))
def test_watch_only_xpub_path_agrees(vec: dict) -> None:
    """Deriving the leaf from the ACCOUNT XPUB must agree with the xprv path.

    Exercises the public-point-addition branch (Xpub.ckd) rather than the scalar
    one -- the code path a watch-only wallet built from an exported xpub relies
    on. A bug here strands a watch-only user without touching the xprv path.
    """
    exp = vec["expected"]
    seed = seed_from_mnemonic(vec["mnemonic"], passphrase=vec["passphrase"])
    master = master_xprv_from_seed(seed)
    acct_xpub = ckd(master, f"m/44'/{vec['coin_type']}'/{vec['account']}'").xpub()

    leaf_pub = acct_xpub.ckd(vec["change"]).ckd(vec["index"])
    assert str(leaf_pub) == exp["leaf_xpub"]
    assert leaf_pub.address() == exp["address"]
