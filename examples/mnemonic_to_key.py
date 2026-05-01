#!/usr/bin/env python3
"""Derive Radiant keys and addresses from a BIP39 mnemonic.

Two flows are demonstrated, in order of how most users will want to
approach the problem:

1. ``HdWallet.from_mnemonic`` — the high-level path. Returns a full HD
   wallet at the correct Radiant BIP44 path (``m/44'/236'/0'``) with
   address tracking, gap-limit discovery, and optional encrypted
   persistence. This is the recommended entry point.

2. ``bip44_derive_xprv_from_mnemonic`` — the low-level path. Returns
   the account xprv so you can derive a single private key at a
   specific child index. Useful when you only want one key, or when
   migrating code from another library that exposed the seed-to-key
   primitives directly.

Radiant note
------------
Radiant uses BIP44 coin type **236**, not 0 (Bitcoin). Code copied
from Bitcoin examples that hardcodes ``m/44'/0'/0'/0/0`` will derive
the wrong addresses. Both helpers here use the correct Radiant path
by default.

Usage
-----
    # Use the demo mnemonic baked into this script:
    python examples/mnemonic_to_key.py

    # Or supply your own (do NOT share a real mnemonic on the command line
    # in production — this is for local testing only):
    MNEMONIC="word1 word2 ... word12" python examples/mnemonic_to_key.py
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from pyrxd.hd import HdWallet, bip44_derive_xprv_from_mnemonic

# A well-known BIP39 test vector mnemonic. NEVER use this for real funds —
# the seed and every key derived from it are public. It is here purely so
# the example runs without configuration.
DEMO_MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"


def high_level(mnemonic: str) -> None:
    """Build a full HD wallet from the mnemonic."""
    print("=== HdWallet.from_mnemonic ===")
    wallet = HdWallet.from_mnemonic(mnemonic)
    print(f"first receive address: {wallet.next_receive_address()}")
    # next_receive_address keeps returning the same address until it is
    # marked used (after a refresh against the network finds history).
    print(f"same again (unused):   {wallet.next_receive_address()}")
    print()


def low_level(mnemonic: str) -> None:
    """Derive a single private key at m/44'/236'/0'/0/0."""
    print("=== bip44_derive_xprv_from_mnemonic ===")
    # Default path is m/44'/236'/0' (Radiant account 0).
    account_xprv = bip44_derive_xprv_from_mnemonic(mnemonic)
    # External chain (change=0), first address (index=0).
    child = account_xprv.ckd(0).ckd(0)
    priv = child.private_key()
    print("path:    m/44'/236'/0'/0/0")
    print(f"WIF:     {priv.wif()}")
    print(f"address: {priv.public_key().address()}")
    print()


def main() -> None:
    mnemonic = os.environ.get("MNEMONIC", DEMO_MNEMONIC)
    if mnemonic == DEMO_MNEMONIC:
        print("Using the public BIP39 test-vector mnemonic. Do not send funds to these addresses.\n")
    high_level(mnemonic)
    low_level(mnemonic)


if __name__ == "__main__":
    main()
