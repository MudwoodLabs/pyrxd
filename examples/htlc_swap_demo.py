#!/usr/bin/env python3
"""HTLC cross-chain swap — the Radiant asset leg, built end to end (no network).

This is the **current** atomic-swap construction in pyrxd: a hash-timelock (HTLC)
swap driven by the chain-neutral :class:`pyrxd.SwapCoordinator`. It SUPERSEDES the
deprecated SPV-oracle swap demoed by the ``gravity_*`` scripts in this directory
(see ``docs/solutions/design-decisions/spv-swap-deprecated-primitive-retained.md``).
Build new swaps on this path, not on the SPV-oracle one.

The script walks the **Radiant side** of a BTC/ETH <-> Glyph-NFT swap: the on-chain
HTLC covenant that holds the NFT, the TAKER's hashlock *claim* spend (which reveals
the secret ``p``), and the MAKER's CSV *refund* spend (after the relative timelock).
It builds the real covenant + spend transactions with the production builders
(:mod:`pyrxd.gravity.htlc_covenant`, :mod:`pyrxd.gravity.htlc_spend`) and
structurally validates them — but it never connects out (synthetic funding UTXOs,
exactly like ``partial_swap_demo.py``). Run it anywhere:

    python examples/htlc_swap_demo.py

What this does NOT do: drive the full two-chain state machine (that is
:class:`pyrxd.SwapCoordinator`, which orchestrates BOTH legs, the reorg-finality
gate, and the durable swap record) or broadcast to any chain. For the live-chain
proof — happy path, mutual-refund, maker-stall, reorg-gate, all on a real regtest
node — see the maintained harnesses:

    RADIANT_REGTEST=1 pytest tests/test_htlc_regtest_e2e.py -m integration
    XCHAIN_REGTEST=1  pytest tests/test_xchain_swap_regtest_e2e.py -m integration

and the how-to: ``docs/how-to/build-a-cross-chain-swap.md``.

> PRE-AUDIT. The swap covenant has not had an external security audit. This script
> moves no value and needs no network, but do not move real value with the swap
> until the audit gate clears — an atomic swap's whole job is to be safe against a
> hostile counterparty, and that is what an audit certifies.
"""

from __future__ import annotations

import os

from pyrxd import build_htlc_covenant_nft, generate_secret
from pyrxd.gravity.htlc_spend import FeeInput, build_htlc_claim_tx, build_htlc_refund_tx
from pyrxd.keys import PrivateKey
from pyrxd.security.types import Hex20


def _hr(title: str) -> None:
    print(f"\n{'-' * 72}\n{title}\n{'-' * 72}")


def _ok(msg: str) -> None:
    print(f"  [ok] {msg}")


def _info(msg: str) -> None:
    print(f"       {msg}")


def _pkh(key: PrivateKey) -> bytes:
    return bytes(Hex20(key.public_key().hash160()))


def _synthetic_fee_input(owner: PrivateKey) -> FeeInput:
    """A throwaway plain-P2PKH fee UTXO.

    NO network — the outpoint is synthetic. The single covenant output carries the
    asset and cannot also pay the miner fee, so every HTLC spend joins a fee input
    the spender owns; in a real spend this is a confirmed RXD UTXO you control.
    """
    pkh = _pkh(owner)
    spk = b"\x76\xa9\x14" + pkh + b"\x88\xac"  # OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
    return FeeInput(txid=os.urandom(32).hex(), vout=0, value=5_000_000, scriptpubkey=spk, wif=owner.wif())


def main() -> None:
    # -- Roles + the shared secret --------------------------------------------
    # MAKER holds the Radiant NFT and wants BTC/ETH. TAKER holds BTC/ETH and wants
    # the NFT. The maker generates the secret; both legs lock to H = SHA256(p).
    _hr("1. The maker's secret (p, H)")
    p, hashlock = generate_secret()  # p is SecretBytes — unpicklable, never persisted
    _ok(f"H = SHA256(p) = {hashlock.hex()}")
    _info("p is wrapped in SecretBytes so it can never be serialised to the durable")
    _info("record; only at claim time is it exposed via p.unsafe_raw_bytes().")

    maker = PrivateKey(os.urandom(32))
    taker = PrivateKey(os.urandom(32))
    _ok(f"maker pkh {_pkh(maker).hex()}")
    _ok(f"taker pkh {_pkh(taker).hex()}")

    # -- The safety invariant -------------------------------------------------
    _hr("2. The ordering + timelock invariant (read before wiring anything)")
    _info("1) maker publishes H        2) taker locks BTC/ETH  FIRST")
    _info("3) maker locks the NFT covenant  SECOND")
    _info("4) maker claims BTC/ETH FIRST, revealing p   5) taker scrapes p, claims the NFT")
    _info("")
    _info("Timelocks MUST satisfy   t_counterchain > t_rxd + margin .  The leg claimed")
    _info("SECOND (Radiant) carries the SHORTER refund window, so the taker has time to")
    _info("scrape p and claim before its own refund opens. SwapCoordinator enforces this")
    _info("fail-closed (assert_timelock_margin) — never route around it.")

    # -- The NFT HTLC covenant (the asset leg) --------------------------------
    _hr("3. Build the NFT HTLC covenant (the asset the maker locks SECOND)")
    # In a real swap the genesis outpoint is the NFT's actual mint ref, resolved and
    # authenticity-checked via verify_ref_authenticity: consensus enforces ref
    # UNIQUENESS, not mint PROVENANCE, so a fake-singleton covenant is accepted by
    # consensus (the R1 case) — verify_ref_authenticity is the only defence.
    genesis_txid = os.urandom(32).hex()
    genesis_vout = 0
    carrier = 1000  # the NFT's carrier photons (a singleton, NOT a fungible "amount")
    refund_csv = 20  # the maker's relative-timelock refund window, in blocks

    cov = build_htlc_covenant_nft(
        genesis_txid=genesis_txid,
        genesis_vout=genesis_vout,
        nft_carrier_value=carrier,
        taker_pkh=_pkh(taker),
        maker_pkh=_pkh(maker),
        hashlock=hashlock,
        refund_csv=refund_csv,
    )
    _ok(f"covenant funded_spk ({len(cov.funded_spk)} bytes): {cov.funded_spk.hex()[:56]}...")
    _info("It pins both spend paths: TAKER claims on hashlock(H)  |  MAKER refunds after")
    _info(f"CSV({refund_csv}). The NFT singleton ref d8<{genesis_txid[:16]}...:{genesis_vout}> rides in the body.")

    # The maker funds the NFT into this SPK; that funding outpoint is what the
    # spends below consume (synthetic here — no broadcast).
    cov_outpoint = f"{os.urandom(32).hex()}:0"

    # -- The TAKER's claim spend (reveal p) -----------------------------------
    _hr("4. TAKER claim spend — reveal p, take the NFT (hashlock branch)")
    claim = build_htlc_claim_tx(
        covenant=cov,
        covenant_outpoint=cov_outpoint,
        carrier_value=carrier,
        preimage=p.unsafe_raw_bytes(),  # raw 32 bytes — only exposed at claim time
        fee=_synthetic_fee_input(taker),
    )
    raw_claim = claim.serialize().hex()
    assert p.unsafe_raw_bytes().hex() in raw_claim, "the claim scriptSig must embed the preimage"
    _ok(
        f"claim tx built + serialised ({len(claim.inputs)} inputs, {len(claim.outputs)} output, {len(raw_claim) // 2} bytes)"
    )
    _info("covenant scriptSig = <preimage push> <OP_0>; the single output pays the TAKER.")
    _info("A WRONG preimage is rejected by REAL consensus (hashlock OP_EQUALVERIFY) —")
    _info("proven in test_htlc_regtest_e2e.py::test_claim_accepted_wrong_preimage_rejected.")

    # -- The MAKER's refund spend (CSV) ---------------------------------------
    _hr("5. MAKER refund spend — reclaim the NFT after the timelock (CSV branch)")
    refund = build_htlc_refund_tx(
        covenant=cov,
        covenant_outpoint=cov_outpoint,
        carrier_value=carrier,
        fee=_synthetic_fee_input(maker),
    )
    cov_in = refund.inputs[0]  # tx_inputs = [covenant_input, fee_input]
    assert refund.version == 2, "BIP68 relative timelocks require tx version 2"
    assert cov_in.sequence == refund_csv, "covenant input nSequence must equal refund_csv"
    _ok(f"refund tx built; version={refund.version}, covenant nSequence={cov_in.sequence}")
    _info("covenant scriptSig = <OP_1> ONLY (no preimage, no sig — gated by the CSV).")
    _info("A PREMATURE refund is rejected (BIP68 non-final); a MATURED one is accepted —")
    _info("test_htlc_regtest_e2e.py::test_premature_refund_rejected_matured_accepted.")

    # -- Where to go next -----------------------------------------------------
    _hr("Next: the full two-chain swap")
    _info("This was the Radiant ASSET leg only. The full cross-chain swap is driven by")
    _info("pyrxd.SwapCoordinator (both legs + the reorg-finality gate + a durable record):")
    _info("  - docs/how-to/build-a-cross-chain-swap.md            (the guide)")
    _info("  - tests/test_xchain_swap_regtest_e2e.py              (BTC <-> RXD, live regtest)")
    _info("  - tests/test_xchain_eth_swap_regtest_e2e.py          (ETH <-> RXD, Anvil + regtest)")
    print()


if __name__ == "__main__":
    main()
