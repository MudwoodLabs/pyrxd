#!/usr/bin/env python3
"""Two-HOST ETH↔RXD swap dry-run harness — the role-split sibling of ``eth_swap_run.py``.

Every swap run so far has been *single-process*: one program plays BOTH the maker and the
taker, holding all keys and the preimage ``p`` in one address space. That proves the plumbing
(the legs broadcast, the FSM advances) but NOT the one property an atomic swap exists for —
safety against a *hostile, untrusted counterparty*. This harness is the PREP for a genuine
two-party run: it splits the EXISTING flow across two operators on two hosts so that

* each operator holds ONLY its own keys (the maker: its RXD refund key + its ETH claim key +
  ``p``; the taker: its RXD claim key + its ETH funding key),
* the only thing that crosses between hosts is the **public negotiation envelope** (and a
  couple of public locators) — copied out-of-band as JSON files,
* the preimage ``p`` NEVER leaves the maker and is NEVER serialised into any exchanged file
  (only the hashlock ``H = SHA256(p)`` ever crosses), and
* the taker INDEPENDENTLY re-derives and verifies the timelock-margin safety invariant from
  the envelope alone and REFUSES to fund if it fails.

It drives the UNCHANGED production ``SwapCoordinator`` + ``EthLeg`` + ``RadiantCovenantLeg`` —
the object graph is byte-for-byte the one ``eth_swap_run.py`` and the regtest e2e build. The
ONLY change is that each process constructs only its own side and the envelope/locators cross
via files instead of shared Python memory. Nothing here is a new coordinator.

Honest scope — this is the PREP, not the run:
  * **Testnet / regtest ONLY.** RXD runs on a Radiant *regtest* node (``bcrt``); ETH runs on a
    local *anvil* or *Sepolia*. The audit gate (``require_audit_cleared`` /
    ``AUDIT_CLEARED_NETWORKS``) fails closed on any value-bearing network, exactly as the
    shipped legs do — there is no mainnet wiring and ``--audit-cleared`` is the only way to
    even name Sepolia (a pre-audit opt-in on a free testnet).
  * **The ``--self-check`` mode needs NO chain.** It exercises the security-critical seam — the
    maker writes the envelope, the taker reads it back and runs the independent margin check,
    and we assert ``p`` is absent from every serialised artifact — entirely offline. That is
    the part this PREP commit validates. The live two-host run (``--role maker|taker`` against
    real Sepolia + a regtest Radiant ElectrumX, with a funded fee UTXO per side) is the operator
    runbook in ``docs/how-to/run-a-two-host-swap-dry-run.md`` and is NOT exercised here.

Files exchanged out-of-band (the ENTIRE cross-host surface — all public, no secret):
  1. ``taker_intro.json``  (taker -> maker)  : the taker's public RXD pubkey-hash + ETH addresses.
  2. ``envelope.json``     (maker -> taker)  : ``NegotiatedTerms`` (H only) + the maker's public
                                               ETH/RXD payout config + the funded covenant SPK.
  3. ``taker_funding.json``(taker -> maker)  : the funded ETH HTLC locator (``EthHtlcLocator`` —
                                               carries H, never p).
  4. ``maker_claim.json``  (maker -> taker)  : the maker's ETH claim tx hash (after the maker
                                               claims ETH and reveals p ON-CHAIN — the taker
                                               scrapes p from the chain, never from this file).

Usage (see the how-to for the full runbook):
  # offline, no chain — the validatable self-check:
  python scripts/eth_swap_two_host.py --self-check

  # live two-host dry-run (each operator on their own host, exchanging the files above):
  # taker, step 1 — publish intro:
  python scripts/eth_swap_two_host.py --role taker --phase intro     --io ./swapdir ...
  # maker, step 1 — assemble + publish the envelope:
  python scripts/eth_swap_two_host.py --role maker --phase envelope  --io ./swapdir ...
  # taker, step 2 — verify margin, fund ETH, publish the funding locator:
  python scripts/eth_swap_two_host.py --role taker --phase fund       --io ./swapdir ...
  # maker, step 2 — verify the ETH HTLC, lock RXD, claim ETH (reveal p):
  python scripts/eth_swap_two_host.py --role maker --phase lock-claim --io ./swapdir ...
  # taker, step 3 — scrape p from the maker's ETH claim + claim the RXD covenant:
  python scripts/eth_swap_two_host.py --role taker --phase claim      --io ./swapdir ...
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _dust_swap_shared import atomic_write_mode_600, confirm

from pyrxd.btc_wallet import taproot as bt
from pyrxd.btc_wallet.htlc_leg import AUDIT_CLEARED_NETWORKS
from pyrxd.eth_wallet.htlc_leg import EthHtlcContractLeg, load_artifact
from pyrxd.eth_wallet.locator import EthHtlcLocator
from pyrxd.eth_wallet.rpc import EthRpc
from pyrxd.gravity.eth_leg import EthLeg
from pyrxd.gravity.eth_rxd_timelock import CrossClockMargin
from pyrxd.gravity.htlc_covenant import build_htlc_covenant_rxd
from pyrxd.gravity.radiant_leg import RadiantChainIO, RadiantCovenantLeg
from pyrxd.gravity.seen_store import DurableSeenStore
from pyrxd.gravity.swap_coordinator import (
    CoordinatorConfig,
    MarginPolicy,
    SwapCoordinator,
    assert_timelock_margin,
)
from pyrxd.gravity.swap_state import NegotiatedTerms, SwapRecord, SwapState
from pyrxd.keys import PrivateKey
from pyrxd.network.electrumx import ElectrumXClient
from pyrxd.security.secrets import PrivateKeyMaterial, SecretBytes
from pyrxd.security.types import Hex20

_DEFAULT_ARTIFACT = Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "EthHtlc.json"
_SEPOLIA_CHAIN_ID = 11155111

# The only ETH networks this PREP harness will name. ``anvil`` is a local devnet (free); ``sepolia``
# is a free testnet that needs the pre-audit opt-in (it is not in AUDIT_CLEARED_NETWORKS). Mainnet is
# deliberately absent — there is no value-bearing path here.
_ALLOWED_ETH_NETWORKS = frozenset({"anvil", "sepolia"})


# ---------------------------------------------------------------------------
# File exchange (the cross-host surface — all public, never the preimage p)
# ---------------------------------------------------------------------------
#
# Every writer asserts that no secret material is present before serialising, and every reader is
# read-only. These four files are the ENTIRE communication channel between the two hosts.

_SECRET_FORBIDDEN_KEYS = ("preimage", "preimage_p", "preimage_p_hex", "p_hex", "wif", "secret", "privkey")


def _assert_public_only(doc: dict, *, what: str) -> None:
    """Fail-closed: refuse to write a cross-host file that smuggles a secret.

    The whole point of the split is that ``p`` (and any private key) stays party-local. This is a
    belt-and-suspenders guard on the SERIALISER so a future edit cannot silently start leaking a
    secret into the out-of-band channel. Scans keys recursively, case-insensitively.
    """

    def _walk(node: object, path: str) -> None:
        if isinstance(node, dict):
            for k, v in node.items():
                kl = str(k).lower()
                if any(bad in kl for bad in _SECRET_FORBIDDEN_KEYS):
                    raise SystemExit(f"REFUSING to write {what}: key {path}{k!r} looks like a secret ({kl})")
                _walk(v, f"{path}{k}.")
        elif isinstance(node, list):
            for i, v in enumerate(node):
                _walk(v, f"{path}{i}.")

    _walk(doc, "")


def _write_public(io_dir: Path, name: str, doc: dict) -> Path:
    _assert_public_only(doc, what=name)
    path = io_dir / name
    path.write_text(json.dumps(doc, indent=2))
    print(f"  wrote public exchange file -> {path}")
    return path


def _read_public(io_dir: Path, name: str) -> dict:
    path = io_dir / name
    if not path.exists():
        raise SystemExit(f"expected exchange file not found: {path} (has the counterparty published it yet?)")
    return json.loads(path.read_text())


# ---------------------------------------------------------------------------
# Shared builders (BOTH roles must agree on terms + the covenant from public inputs)
# ---------------------------------------------------------------------------


def _cross_clock_margin(args: argparse.Namespace) -> CrossClockMargin:
    return CrossClockMargin(
        eth_reorg_finality_s=args.eth_finalization_window_s,
        rxd_claim_burial_s=args.rxd_claim_burial_s,
        rxd_confirm_slack_s=args.rxd_confirm_slack_s,
        rounding_slack_s=args.rounding_slack_s,
    )


def _margin_policy(args: argparse.Namespace) -> MarginPolicy:
    """The ESTIMATED margin policy (is_measured=False). A real-value run MUST use
    ``MarginPolicy.measured(...)``; this is a regtest/testnet PREP, so flat burial + estimated
    margins are the documented dust-grade hatch — the audit gate still blocks real value."""
    return MarginPolicy(
        margin=bt.Timelock(args.margin_blocks, bt.TimeUnit.BLOCKS),
        block_interval_s=args.btc_block_interval_s,
        is_measured=False,
        rxd_block_interval_s=args.rxd_block_interval_s,
        eth_finalization_window_s=args.eth_finalization_window_s,
        cross_clock_margin=_cross_clock_margin(args),
        max_covenant_confirm_wait_s=args.max_covenant_confirm_wait_s,
        accept_flat_burial=True,
    )


def _terms_from_public(
    *,
    hashlock: bytes,
    rxd_photons: int,
    eth_amount_wei: int,
    t_rxd_blocks: int,
    margin_blocks: int,
    eth_timeout_unix_s: int,
    taker_pkh: bytes,
    maker_pkh: bytes,
) -> tuple[NegotiatedTerms, object]:
    """Build the plain-RXD HTLC covenant + the chain-agnostic ``NegotiatedTerms`` from PUBLIC
    inputs only (both pkhs are public; H is public; ``p`` is not used here). Returns
    ``(terms, covenant)``. BOTH roles call this with the SAME public inputs and MUST get the
    identical covenant SPK + dest hashes — that mutual re-derivation is the trust anchor."""
    t_rxd = bt.Timelock(t_rxd_blocks, bt.TimeUnit.BLOCKS)
    # t_btc is decorative for an ETH swap (the real ETH deadline is eth_timeout_unix_s), but it must
    # stay > t_rxd so the same-unit ordering guard in NegotiatedTerms passes; keep it well clear.
    t_btc = bt.Timelock(t_rxd_blocks + margin_blocks + 4, bt.TimeUnit.BLOCKS)
    cov = build_htlc_covenant_rxd(
        amount=rxd_photons,
        taker_pkh=bytes(Hex20(taker_pkh)),
        maker_pkh=bytes(Hex20(maker_pkh)),
        hashlock=hashlock,
        refund_csv=t_rxd.value,
    )
    terms = NegotiatedTerms(
        hashlock=hashlock,
        btc_sats=rxd_photons,
        radiant_amount=rxd_photons,
        t_btc=t_btc,
        t_rxd=t_rxd,
        asset_variant="rxd",
        genesis_ref=b"",
        taker_dest_hash=cov.expected_taker_hash,
        maker_dest_hash=cov.expected_maker_hash,
        btc_claim_pubkey_xonly=b"\x00" * 32,
        btc_refund_pubkey_xonly=b"\x00" * 32,
        counter_chain="eth",
        value_amount=eth_amount_wei,
        eth_timeout_unix_s=eth_timeout_unix_s,
    )
    return terms, cov


def _eth_network_guard(network: str, *, audit_cleared: bool) -> None:
    """Pin the ETH network to a testnet this PREP harness is allowed to drive, fail-closed."""
    if network not in _ALLOWED_ETH_NETWORKS:
        raise SystemExit(
            f"ETH network {network!r} is not allowed by the two-host PREP harness "
            f"(testnet only: {sorted(_ALLOWED_ETH_NETWORKS)}). There is no mainnet path here."
        )
    if network == "sepolia" and not audit_cleared:
        raise SystemExit(
            "ETH network 'sepolia' is a free testnet but it is NOT in AUDIT_CLEARED_NETWORKS — pass "
            "--audit-cleared to consciously opt in to a PRE-AUDIT dry-run on it (the swap primitive "
            "has not been externally audited; never move real value)."
        )


def _eth_leg(args, *, claim_to: str, refund_to: str, eth_timeout: int):
    """Construct the REAL EthLeg (network-gated). claim_to = maker's address (receives ETH on
    claim); refund_to = taker's address (receives ETH on refund)."""
    network = "anvil" if args.eth_chain_id == 31337 else args.eth_network
    _eth_network_guard(network, audit_cleared=args.audit_cleared)
    rpc = EthRpc(args.eth_rpc_url, expected_chain_id=args.eth_chain_id)
    contract_leg = EthHtlcContractLeg(
        rpc=rpc,
        signing_key=PrivateKeyMaterial(bytes.fromhex(args.eth_key_hex)),
        chain_id=args.eth_chain_id,
        artifact=load_artifact(args.eth_artifact),
    )
    leg = EthLeg(
        contract_leg=contract_leg,
        network=network,
        claim_to=claim_to,
        refund_to=refund_to,
        eth_timeout_unix_s=eth_timeout,
        # Sepolia is gated above behind --audit-cleared; anvil/regtest pass the leg's own gate freely.
        audit_cleared=args.audit_cleared,
    )
    return rpc, leg


def _radiant_leg(args, *, taker_pkh: bytes, maker_pkh: bytes, fee_source):
    """Construct the REAL RadiantCovenantLeg over an ElectrumX client on a REGTEST node.

    The RXD network is pinned to a regtest HRP (``bcrt``) which is in AUDIT_CLEARED_NETWORKS, so the
    leg's audit gate passes without any opt-in — and a non-regtest RXD network fails closed."""
    if args.rxd_network not in AUDIT_CLEARED_NETWORKS:
        raise SystemExit(
            f"RXD network {args.rxd_network!r} is not a cleared test chain "
            f"({sorted(AUDIT_CLEARED_NETWORKS)}); this PREP harness is regtest/testnet only."
        )
    client = ElectrumXClient(urls=[args.rxd_electrumx_url], allow_insecure=args.rxd_electrumx_insecure)
    return RadiantCovenantLeg(
        network=args.rxd_network,
        taker_pkh=bytes(Hex20(taker_pkh)),
        maker_pkh=bytes(Hex20(maker_pkh)),
        chain_io=RadiantChainIO(client),
        fee_source=fee_source,
        min_confirmations=1,
    )


class _OperatorFeeSource:
    """A ``FeeUtxoSource`` built from a single operator-supplied regtest fee UTXO.

    Each operator owns their OWN fee UTXO (the covenant output carries the asset and cannot also
    pay the fee). The taker supplies a fee UTXO for the RXD CLAIM; the maker supplies one for the
    RXD REFUND. This keeps the WIF party-local (it is NEVER serialised into an exchange file)."""

    def __init__(self, *, txid: str, vout: int, value: int, scriptpubkey_hex: str, wif: str) -> None:
        from pyrxd.gravity.htlc_spend import FeeInput

        self._fee = FeeInput(
            txid=txid,
            vout=vout,
            value=value,
            scriptpubkey=bytes.fromhex(scriptpubkey_hex),
            wif=wif,
        )

    def next_fee_input(self):
        return self._fee


def _fee_source_from_args(args):
    """Build the operator's fee source from --fee-* flags, or None if not supplied (the broadcast
    steps then refuse with a per-step message). The fee WIF is party-local and never serialised."""
    if not (args.fee_txid and args.fee_wif and args.fee_spk_hex):
        return None
    return _OperatorFeeSource(
        txid=args.fee_txid,
        vout=args.fee_vout,
        value=args.fee_value,
        scriptpubkey_hex=args.fee_spk_hex,
        wif=args.fee_wif,
    )


# ---------------------------------------------------------------------------
# Role: TAKER
# ---------------------------------------------------------------------------


async def taker_phase_intro(args: argparse.Namespace) -> None:
    """TAKER step 1: generate the taker's OWN keys, publish only the PUBLIC half (pkh + ETH addrs).

    The taker's RXD private key + ETH key stay on the taker's host (persisted mode-600 locally,
    never exchanged). Only the public pubkey-hash + ETH addresses cross to the maker so the maker
    can bind the covenant's taker holder + the ETH HTLC's claim/refund addresses."""
    io_dir = _io_dir(args)
    taker_rxd = PrivateKey(os.urandom(32))
    taker_pkh = bytes(Hex20(taker_rxd.public_key().hash160()))
    # Persist the taker's PRIVATE state locally (mode 600), out of the exchange channel entirely.
    _persist_local_secret(
        args,
        {
            "role": "taker",
            "taker_rxd_wif": taker_rxd.wif(),
            "taker_pkh_hex": taker_pkh.hex(),
            "eth_key_hex": args.eth_key_hex,
            "eth_taker_refund_addr": args.eth_taker_addr,
            "note": "TAKER-LOCAL private state. Never copy to the other host. mode 600.",
        },
    )
    _write_public(
        io_dir,
        "taker_intro.json",
        {
            "taker_pkh_hex": taker_pkh.hex(),
            "eth_taker_refund_addr": args.eth_taker_addr,  # receives ETH on refund()
            "eth_maker_claim_addr": args.eth_maker_addr,  # the maker's address (taker proposes/echoes)
        },
    )
    print("  TAKER intro published. Hand taker_intro.json to the maker out-of-band.")


async def taker_phase_fund(args: argparse.Namespace) -> None:
    """TAKER step 2: read the maker's envelope, INDEPENDENTLY verify the timelock margin, re-derive
    the covenant from the envelope's public terms, then fund the ETH HTLC FIRST and publish the
    funding locator. The taker NEVER trusts the maker's covenant SPK blindly — it rebuilds it."""
    io_dir = _io_dir(args)
    local = _load_local_secret(args)
    env = _read_public(io_dir, "envelope.json")
    terms = NegotiatedTerms.from_dict(env["terms"])

    # --- THE safety gate: verify t_counterchain - t_rxd >= margin from the envelope ALONE. ---
    # The taker uses its OWN margin policy (not a maker-supplied one) and REFUSES to fund on failure.
    policy = _margin_policy(args)
    try:
        assert_timelock_margin(terms.t_btc, terms.t_rxd, policy)
    except Exception as exc:
        raise SystemExit(
            f"REFUSING to fund: independent timelock-margin check FAILED ({exc}). "
            "A hostile maker may have set a too-tight refund window; aborting before any value moves."
        ) from None
    print(f"  margin OK: t_rxd={terms.t_rxd.value} blk, margin={policy.margin.value} blk (independent check passed)")

    # Re-derive the covenant from the envelope's PUBLIC terms + both pkhs, and assert it matches the
    # SPK the maker advertised. A mismatch means the maker's advertised SPK does not follow from the
    # agreed terms — refuse.
    taker_pkh = bytes.fromhex(local["taker_pkh_hex"])
    maker_pkh = bytes.fromhex(env["maker_pkh_hex"])
    _terms2, cov = _terms_from_public(
        hashlock=terms.hashlock,
        rxd_photons=terms.radiant_amount,
        eth_amount_wei=terms.value_amount,
        t_rxd_blocks=terms.t_rxd.value,
        margin_blocks=args.margin_blocks,
        eth_timeout_unix_s=int(terms.eth_timeout_unix_s),
        taker_pkh=taker_pkh,
        maker_pkh=maker_pkh,
    )
    if cov.funded_spk.hex() != env["covenant_spk_hex"]:
        raise SystemExit(
            "REFUSING to fund: the maker's advertised covenant SPK does not match the SPK re-derived "
            "from the agreed public terms — the maker is committing to a covenant inconsistent with H/"
            "amounts/keys. Aborting."
        )
    print("  covenant SPK re-derived from public terms == the maker's advertised SPK (consistent).")

    # Build the taker's side of the coordinator: the REAL EthLeg + RadiantCovenantLeg. The taker
    # funds the ETH HTLC (claim_to = maker, refund_to = taker), exactly the production object graph.
    rpc, eth_leg = _eth_leg(
        args,
        claim_to=env["eth_maker_claim_addr"],
        refund_to=local["eth_taker_refund_addr"],
        eth_timeout=int(terms.eth_timeout_unix_s),
    )
    fee_source = _fee_source_from_args(args)
    if fee_source is None:
        raise SystemExit(
            "taker fund/claim needs a regtest fee UTXO: pass --fee-txid/--fee-vout/--fee-value/--fee-spk-hex/--fee-wif"
        )
    rxd_leg = _radiant_leg(args, taker_pkh=taker_pkh, maker_pkh=maker_pkh, fee_source=fee_source)
    coord = _coordinator(args, terms=terms, eth_leg=eth_leg, rxd_leg=rxd_leg, keys_out=args.local_out)

    try:
        confirm("taker_funds_btc: deploy+fund the ETH HTLC (taker pays gas; claim pays the maker)", auto_yes=args.yes)
        rec = await coord.taker_funds_btc(terms, now_unix_s=int(time.time()))
        if rec.state is not SwapState.BTC_LOCKED:
            raise SystemExit(f"taker_funds_btc landed in {rec.state.value}, expected btc_locked")
        loc: EthHtlcLocator = rec.counterchain_locator  # type: ignore[assignment]
        print(f"  -> {rec.state.value}; ETH HTLC at {loc.contract_address}")
        # Publish the funded locator (public: carries H, claimant/refundee addrs, amount — never p).
        _write_public(io_dir, "taker_funding.json", {"eth_locator": loc.to_dict()})
        print("  TAKER funding published. Hand taker_funding.json to the maker out-of-band.")
        # Stash the locator + the height the asset will be measured against, locally for the claim.
        _update_local_secret(args, {"eth_contract_address": loc.contract_address})
    finally:
        await rpc.close()


async def taker_phase_claim(args: argparse.Namespace) -> None:
    """TAKER step 3: the maker has claimed ETH on-chain (revealing p). Scrape p FROM THE CHAIN (via
    the maker's claim tx hash, exchanged in maker_claim.json — the hash is public; p is read off the
    chain, never from a file) and claim the RXD covenant before its refund window opens."""
    io_dir = _io_dir(args)
    local = _load_local_secret(args)
    env = _read_public(io_dir, "envelope.json")
    terms = NegotiatedTerms.from_dict(env["terms"])
    claim_doc = _read_public(io_dir, "maker_claim.json")
    eth_claim_tx = claim_doc["eth_claim_tx_hash"]

    taker_pkh = bytes.fromhex(local["taker_pkh_hex"])
    maker_pkh = bytes.fromhex(env["maker_pkh_hex"])
    rpc, eth_leg = _eth_leg(
        args,
        claim_to=env["eth_maker_claim_addr"],
        refund_to=local["eth_taker_refund_addr"],
        eth_timeout=int(terms.eth_timeout_unix_s),
    )
    fee_source = _fee_source_from_args(args)
    if fee_source is None:
        raise SystemExit("taker claim needs a regtest fee UTXO (see --fee-* flags)")
    rxd_leg = _radiant_leg(args, taker_pkh=taker_pkh, maker_pkh=maker_pkh, fee_source=fee_source)
    # Rebuild the coordinator with the funded counter-leg locator attached (so the FSM is at
    # BOTH_LOCKED/SECRET_REVEALED — the resume seam mirrors dust_swap_resume.py).
    loc = EthHtlcLocator.from_dict(_read_public(io_dir, "taker_funding.json")["eth_locator"])
    record = SwapRecord(state=SwapState.SECRET_REVEALED, terms=terms).with_counter_lock(loc)
    coord = _coordinator(args, terms=terms, eth_leg=eth_leg, rxd_leg=rxd_leg, keys_out=args.local_out, record=record)

    try:
        deadline = time.monotonic() + args.resume_deadline_s
        print(
            f"  scraping p from the maker's ETH claim {eth_claim_tx} + reorg-gated RXD claim (deadline {args.resume_deadline_s:.0f}s)"
        )
        # taker_scrape_and_claim_asset dispatches to the ETH path: the coordinator fetches the claim
        # tx's calldata+logs through the leg, scrapes p by sha256==H, runs the provenance + reorg
        # gates, then fires the Radiant claim on SAFE. p is read OFF-CHAIN from the tx, never a file.
        while True:
            if time.monotonic() >= deadline:
                raise SystemExit(
                    f"deadline exceeded; operator must intervene (p is public on-chain). claim {eth_claim_tx}"
                )
            now_rxd = await _rxd_height(args)
            confirm("taker_scrape_and_claim_asset: claim the RXD covenant with the scraped p", auto_yes=args.yes)
            rec = await coord.taker_scrape_and_claim_asset(
                eth_claim_tx, now_rxd_height=now_rxd, asset_locked_at_height=args.asset_locked_at_height
            )
            if rec.state is SwapState.COMPLETED:
                print(f"  -> {rec.state.value} — RXD covenant claimed; cross-chain swap COMPLETE")
                break
            if rec.state is SwapState.SECRET_REVEALED:
                print("  reorg gate: WAIT (ETH claim not yet final); retrying...")
                await asyncio.sleep(args.poll_interval_s)
                continue
            if rec.state is SwapState.ASSET_VULNERABLE:
                print("  reorg gate SQUEEZED -> ASSET_VULNERABLE; attempting winner-take-all claim.")
                confirm(
                    "taker_claim_asset_from_vulnerable: best-effort claim (accepts residual reorg risk)",
                    auto_yes=args.yes,
                )
                rec = await coord.taker_claim_asset_from_vulnerable(eth_claim_tx)
                print(f"  -> {rec.state.value}")
                break
            raise SystemExit(f"unexpected state {rec.state.value}; operator must intervene")
    finally:
        await rpc.close()


# ---------------------------------------------------------------------------
# Role: MAKER
# ---------------------------------------------------------------------------


async def maker_phase_envelope(args: argparse.Namespace) -> None:
    """MAKER step 1: generate (p, H), read the taker's intro, assemble the covenant + terms, and
    publish the PUBLIC envelope (H only). p is held in memory + persisted to the maker's LOCAL
    mode-600 file and is asserted ABSENT from the envelope."""
    io_dir = _io_dir(args)
    intro = _read_public(io_dir, "taker_intro.json")
    taker_pkh = bytes.fromhex(intro["taker_pkh_hex"])

    p_secret = SecretBytes(os.urandom(32))
    h = hashlib.sha256(p_secret.unsafe_raw_bytes()).digest()
    maker_rxd = PrivateKey(os.urandom(32))
    maker_pkh = bytes(Hex20(maker_rxd.public_key().hash160()))
    # The ETH refund deadline starts now; the whole window is available for the swap.
    eth_timeout = int(time.time()) + args.eth_timeout_s

    terms, cov = _terms_from_public(
        hashlock=h,
        rxd_photons=args.rxd_photons,
        eth_amount_wei=args.eth_amount_wei,
        t_rxd_blocks=args.t_rxd_blocks,
        margin_blocks=args.margin_blocks,
        eth_timeout_unix_s=eth_timeout,
        taker_pkh=taker_pkh,
        maker_pkh=maker_pkh,
    )

    # Persist the maker's PRIVATE state locally (mode 600) — incl. p. NEVER exchanged.
    _persist_local_secret(
        args,
        {
            "role": "maker",
            "hashlock_H_hex": h.hex(),
            "preimage_p_hex": p_secret.unsafe_raw_bytes().hex(),  # MAKER-LOCAL ONLY — never crosses hosts
            "maker_rxd_wif": maker_rxd.wif(),
            "maker_pkh_hex": maker_pkh.hex(),
            "taker_pkh_hex": taker_pkh.hex(),
            "eth_key_hex": args.eth_key_hex,
            "eth_maker_claim_addr": args.eth_maker_addr,
            "eth_taker_refund_addr": intro["eth_taker_refund_addr"],
            "eth_timeout_unix_s": eth_timeout,
            "covenant_spk_hex": cov.funded_spk.hex(),
            "note": "MAKER-LOCAL private state incl preimage p. Never copy to the other host. mode 600.",
        },
    )

    # The PUBLIC envelope: NegotiatedTerms (H only) + the maker's public payout config + the SPK the
    # taker must independently re-derive. _assert_public_only() rejects any secret key before write.
    envelope = {
        "schema": "eth_rxd_two_host_envelope_v1",
        "terms": terms.to_dict(),  # carries hashlock H; to_dict() never emits p (see swap_state.py)
        "maker_pkh_hex": maker_pkh.hex(),  # public — needed to re-derive the covenant
        "eth_maker_claim_addr": args.eth_maker_addr,  # receives ETH on claim()
        "eth_taker_refund_addr": intro["eth_taker_refund_addr"],  # receives ETH on refund()
        "eth_chain_id": args.eth_chain_id,
        "rxd_network": args.rxd_network,
        "covenant_spk_hex": cov.funded_spk.hex(),  # the maker will fund THIS; taker re-derives + checks
    }
    _write_public(io_dir, "envelope.json", envelope)
    print(f"\n  ENVELOPE published (H={h.hex()[:16]}…). p is held LOCALLY only; it is NOT in the envelope.")
    print(f"  Fund the RXD covenant SPK on regtest as the maker (>= 1 conf):\n    {cov.funded_spk.hex()}")
    print("  Hand envelope.json to the taker out-of-band, then run --phase lock-claim once the taker has funded ETH.")


async def maker_phase_lock_claim(args: argparse.Namespace) -> None:
    """MAKER step 2: verify the taker's ETH HTLC binds to terms, lock RXD (operator funds the SPK),
    re-validate, then CLAIM the ETH — revealing p on-chain. Publishes the claim tx hash."""
    io_dir = _io_dir(args)
    local = _load_local_secret(args)
    env = _read_public(io_dir, "envelope.json")
    terms = NegotiatedTerms.from_dict(env["terms"])
    funding = _read_public(io_dir, "taker_funding.json")
    eth_loc = EthHtlcLocator.from_dict(funding["eth_locator"])

    p_secret = SecretBytes(bytes.fromhex(local["preimage_p_hex"]))
    if hashlib.sha256(p_secret.unsafe_raw_bytes()).digest() != terms.hashlock:
        raise SystemExit("local preimage p does not hash to the envelope's H — wrong local file?")
    maker_pkh = bytes.fromhex(local["maker_pkh_hex"])
    taker_pkh = bytes.fromhex(local["taker_pkh_hex"])
    # The covenant SPK is PUBLIC — source it from the public envelope, never from the secret-bearing
    # ``local`` dict (which also holds the preimage p). Reading public display values out of the
    # secret file is what makes a clear-text log of them taint-flagged (CodeQL py/clear-text-logging);
    # sourcing them from the public envelope keeps the secret file write-only for actual secrets.
    covenant_spk_hex = env["covenant_spk_hex"]

    rpc, raw_eth_leg = _eth_leg(
        args,
        claim_to=local["eth_maker_claim_addr"],
        refund_to=local["eth_taker_refund_addr"],
        eth_timeout=int(terms.eth_timeout_unix_s),
    )
    # Wrap so the coordinator's discarded claim() return (the tx hash the taker needs to scrape p)
    # is captured — same pattern as eth_swap_run.py's _CapturingEthLeg.
    eth_leg = _CapturingEthLeg(raw_eth_leg)
    fee_source = _fee_source_from_args(args)  # only needed if the maker must refund
    rxd_leg = _radiant_leg(args, taker_pkh=taker_pkh, maker_pkh=maker_pkh, fee_source=fee_source or _NoFeeSource())
    # The maker ENTERS the flow at the point the taker has already funded the counter leg: rebuild the
    # in-flight record at BTC_LOCKED with the taker's funded locator attached (the resume seam, exactly
    # as dust_swap_resume.py rebuilds an in-flight record). post_asset_lock_revalidate requires
    # BTC_LOCKED; the maker never ran taker_funds_btc (that happened in the TAKER's process).
    record = (
        SwapRecord(state=SwapState.NEGOTIATED, terms=terms).with_counter_lock(eth_loc).with_state(SwapState.BTC_LOCKED)
    )
    coord = _coordinator(args, terms=terms, eth_leg=eth_leg, rxd_leg=rxd_leg, keys_out=args.local_out, record=record)

    try:
        # 1. Verify the taker-deployed ETH HTLC binds to terms (claimant=maker, refundee=taker, H,
        #    timeout, funded) BEFORE locking RXD. Fail-closed if a hostile taker mis-deployed.
        confirm("maker_verify_counter_funding: verify the taker's on-chain ETH HTLC pays the maker", auto_yes=args.yes)
        rec = await coord.maker_verify_counter_funding(eth_loc.contract_address)
        print("  -> verified (claimant=maker, refundee=taker, H, timeout, funded)")

        # 2. Lock the RXD covenant: the operator funds the SPK out-of-band, then we re-validate.
        print(f"\n  Fund the RXD covenant SPK on regtest now (>= 1 conf):\n    {covenant_spk_hex}")
        confirm("you have funded the RXD covenant SPK on regtest and it has >= 1 conf", auto_yes=args.yes)
        rec = await coord.post_asset_lock_revalidate(
            bytes.fromhex(covenant_spk_hex), now_unix_s=int(time.time())
        )
        if rec.state is not SwapState.BOTH_LOCKED:
            raise SystemExit(f"covenant/timing mismatch -> {rec.state.value}; refund the ETH HTLC after its timeout")
        print(f"  -> {rec.state.value}")

        # 3. Claim the ETH, revealing p on-chain. The taker scrapes p from THIS tx.
        confirm("maker_claims_btc: broadcast the ETH claim (reveals p on-chain)", auto_yes=args.yes)
        rec = await coord.maker_claims_btc(p_secret)
        claim_tx = eth_leg.last_claim_tx
        if not claim_tx:
            raise SystemExit("did not capture the ETH claim tx hash; the taker needs it to scrape p")
        print(f"  -> {rec.state.value}; ETH claim tx {claim_tx}")
        _write_public(io_dir, "maker_claim.json", {"eth_claim_tx_hash": claim_tx})
        print("  Hand maker_claim.json to the taker out-of-band; the taker scrapes p from this tx on-chain.")
    finally:
        await rpc.close()


class _NoFeeSource:
    """A fee source that fails loudly if a spend is actually attempted (the maker only needs a real
    fee source to REFUND; the happy path never has the maker spend the covenant)."""

    def next_fee_input(self):
        raise SystemExit("a maker covenant REFUND needs a regtest fee UTXO (pass --fee-* flags)")


class _CapturingEthLeg:
    """Captures the maker's claim tx hash (the coordinator discards claim()'s return). Mirrors the
    wrapper in eth_swap_run.py."""

    def __init__(self, inner: EthLeg) -> None:
        self._inner = inner
        self.last_claim_tx: str | None = None

    def __getattr__(self, name):
        return getattr(self._inner, name)

    async def claim(self, locator, preimage):
        self.last_claim_tx = await self._inner.claim(locator, preimage)
        return self.last_claim_tx


# ---------------------------------------------------------------------------
# Coordinator + local-secret + chain helpers
# ---------------------------------------------------------------------------


def _coordinator(args, *, terms, eth_leg, rxd_leg, keys_out, record=None):
    """Build the REAL SwapCoordinator — the SAME object graph as eth_swap_run.py / the e2e, only
    each process constructs its own side. Durable seen-store by default."""
    if record is None:
        record = SwapRecord(state=SwapState.NEGOTIATED, terms=terms)
    return SwapCoordinator(
        record=record,
        counter_leg=eth_leg,
        radiant_leg=rxd_leg,
        indexer=None,  # plain RXD has no genesis ref → no ref-authenticity indexer needed
        seen_store=DurableSeenStore(str(Path(keys_out).expanduser()) + ".seen.sqlite"),
        config=CoordinatorConfig(margin_policy=_margin_policy(args), accept_estimated_eth_margins=True),
    )


def _io_dir(args) -> Path:
    d = Path(args.io).expanduser()
    d.mkdir(parents=True, exist_ok=True)
    return d


def _persist_local_secret(args, doc: dict) -> None:
    """Write the role's PRIVATE state mode-600 LOCALLY. This file holds the WIF (+ p for the maker)
    and MUST NEVER be copied to the other host — it is not part of the exchange channel."""
    path = Path(args.local_out).expanduser()
    if path.exists():
        raise SystemExit(f"local secret file already exists: {path} — move it or pass a fresh --local-out")
    doc = {"created_unix": int(time.time()), **doc}
    atomic_write_mode_600(path, json.dumps(doc, indent=2))
    print(f"  local private state -> {path} (mode 600; NEVER copy to the other host)")


def _load_local_secret(args) -> dict:
    path = Path(args.local_out).expanduser()
    if not path.exists():
        raise SystemExit(f"local secret file not found: {path} — run the role's intro/envelope phase first")
    return json.loads(path.read_text())


def _update_local_secret(args, extra: dict) -> None:
    path = Path(args.local_out).expanduser()
    doc = json.loads(path.read_text())
    doc.update(extra)
    path.write_text(json.dumps(doc, indent=2))


async def _rxd_height(args) -> int:
    client = ElectrumXClient(urls=[args.rxd_electrumx_url], allow_insecure=args.rxd_electrumx_insecure)
    try:
        return int(await client.get_tip_height())
    finally:
        await client.close()


# ---------------------------------------------------------------------------
# Self-check (NO chain) — the validatable deliverable of this PREP commit
# ---------------------------------------------------------------------------


def run_self_check() -> None:
    """Offline round-trip of the security-critical seam: the maker assembles + serialises the
    envelope; the taker reads it back, re-derives the covenant, and runs the INDEPENDENT margin
    check — and we ASSERT the preimage p never appears in any serialised artifact. No chain."""
    print("=== two-host swap PREP self-check (NO chain) ===")
    p_secret = SecretBytes(os.urandom(32))
    p_hex = p_secret.unsafe_raw_bytes().hex()
    h = hashlib.sha256(p_secret.unsafe_raw_bytes()).digest()

    taker_rxd = PrivateKey(os.urandom(32))
    maker_rxd = PrivateKey(os.urandom(32))
    taker_pkh = bytes(Hex20(taker_rxd.public_key().hash160()))
    maker_pkh = bytes(Hex20(maker_rxd.public_key().hash160()))
    eth_timeout = int(time.time()) + 86_400

    # --- MAKER side: assemble terms + covenant, serialise the envelope. ---
    terms, cov = _terms_from_public(
        hashlock=h,
        rxd_photons=1000,
        eth_amount_wei=10**14,
        t_rxd_blocks=60,
        margin_blocks=36,
        eth_timeout_unix_s=eth_timeout,
        taker_pkh=taker_pkh,
        maker_pkh=maker_pkh,
    )
    envelope = {
        "schema": "eth_rxd_two_host_envelope_v1",
        "terms": terms.to_dict(),
        "maker_pkh_hex": maker_pkh.hex(),
        "eth_maker_claim_addr": "0x" + "11" * 20,
        "eth_taker_refund_addr": "0x" + "22" * 20,
        "eth_chain_id": _SEPOLIA_CHAIN_ID,
        "rxd_network": "bcrt",
        "covenant_spk_hex": cov.funded_spk.hex(),
    }
    # The serialiser guard must accept this (it is public) and the bytes must NOT contain p.
    _assert_public_only(envelope, what="envelope.json")
    envelope_json = json.dumps(envelope, indent=2)
    assert p_hex not in envelope_json, "FAIL: preimage p leaked into the envelope JSON"
    assert "preimage" not in envelope_json.lower(), "FAIL: 'preimage' appears in the envelope JSON"
    assert maker_rxd.wif() not in envelope_json, "FAIL: maker WIF leaked into the envelope"
    assert taker_rxd.wif() not in envelope_json, "FAIL: taker WIF leaked into the envelope"
    print("  [ok] envelope serialises H only — no p, no WIF (asserted by string scan + the key guard)")

    # The guard must REJECT a doc that tries to smuggle p.
    try:
        _assert_public_only({"terms": {"preimage_p_hex": p_hex}}, what="evil.json")
        raise AssertionError("FAIL: the public-only guard did not reject a smuggled preimage")
    except SystemExit:
        print("  [ok] the serialiser guard REJECTS a doc carrying a preimage/secret key")

    # --- TAKER side: read the envelope back, re-derive, run the independent margin check. ---
    env2 = json.loads(envelope_json)
    terms2 = NegotiatedTerms.from_dict(env2["terms"])
    assert terms2.hashlock == h, "FAIL: H did not round-trip"
    assert terms2.to_dict().get("hashlock") == h.hex()
    # Re-derive the covenant from public terms; it MUST equal the maker's advertised SPK.
    _t3, cov2 = _terms_from_public(
        hashlock=terms2.hashlock,
        rxd_photons=terms2.radiant_amount,
        eth_amount_wei=terms2.value_amount,
        t_rxd_blocks=terms2.t_rxd.value,
        margin_blocks=36,
        eth_timeout_unix_s=int(terms2.eth_timeout_unix_s),
        taker_pkh=taker_pkh,
        maker_pkh=maker_pkh,
    )
    assert cov2.funded_spk.hex() == env2["covenant_spk_hex"], "FAIL: taker re-derived a different covenant SPK"
    print("  [ok] taker re-derives the SAME covenant SPK from the envelope's public terms")

    # The independent margin check passes for honest terms (t_btc - t_rxd = 40 >= margin 36)...
    policy = MarginPolicy(
        margin=bt.Timelock(36, bt.TimeUnit.BLOCKS),
        block_interval_s=600.0,
        is_measured=False,
        rxd_block_interval_s=300.0,
        eth_finalization_window_s=768,
        cross_clock_margin=CrossClockMargin(
            eth_reorg_finality_s=768, rxd_claim_burial_s=1800, rxd_confirm_slack_s=600, rounding_slack_s=300
        ),
        max_covenant_confirm_wait_s=600,
        accept_flat_burial=True,
    )
    assert_timelock_margin(terms2.t_btc, terms2.t_rxd, policy)
    print("  [ok] taker's INDEPENDENT timelock-margin check passes for honest terms")

    # ...and REFUSES a hostile too-tight envelope (t_btc - t_rxd < margin).
    hostile = NegotiatedTerms(
        hashlock=h,
        btc_sats=1000,
        radiant_amount=1000,
        t_btc=bt.Timelock(61, bt.TimeUnit.BLOCKS),  # only 1 block over t_rxd — far below margin 36
        t_rxd=bt.Timelock(60, bt.TimeUnit.BLOCKS),
        asset_variant="rxd",
        genesis_ref=b"",
        taker_dest_hash=cov.expected_taker_hash,
        maker_dest_hash=cov.expected_maker_hash,
        btc_claim_pubkey_xonly=b"\x00" * 32,
        btc_refund_pubkey_xonly=b"\x00" * 32,
        counter_chain="eth",
        value_amount=10**14,
        eth_timeout_unix_s=eth_timeout,
    )
    try:
        assert_timelock_margin(hostile.t_btc, hostile.t_rxd, policy)
        raise AssertionError("FAIL: the margin check accepted a hostile too-tight envelope")
    except Exception as exc:
        if isinstance(exc, AssertionError):
            raise
        print("  [ok] taker REFUSES a hostile too-tight envelope (independent margin check rejects it)")

    print(
        "\n  SELF-CHECK PASSED: envelope carries H only; p never serialised; taker independently "
        "re-derives the covenant + verifies the margin and rejects a hostile envelope. NO chain touched."
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Two-host ETH↔RXD swap dry-run PREP harness (Sepolia/anvil ↔ RXD-regtest)")
    ap.add_argument(
        "--self-check", action="store_true", help="run the offline envelope round-trip self-check (NO chain) and exit"
    )
    ap.add_argument("--role", choices=["maker", "taker"])
    ap.add_argument(
        "--phase",
        choices=["intro", "envelope", "fund", "lock-claim", "claim"],
        help="taker: intro|fund|claim ; maker: envelope|lock-claim",
    )
    ap.add_argument("--io", default="./swapdir", help="directory holding the out-of-band exchange files")
    ap.add_argument("--local-out", default="", help="this role's LOCAL mode-600 private-state file (never exchanged)")
    ap.add_argument("--yes", action="store_true", help="auto-confirm broadcasts (unattended only)")
    ap.add_argument(
        "--audit-cleared", action="store_true", help="pre-audit opt-in required only to name Sepolia (a free testnet)"
    )
    # ETH
    ap.add_argument("--eth-rpc-url", default="")
    ap.add_argument("--eth-key-hex", default="", help="this role's ETH signing key (taker: funder; maker: claimer)")
    ap.add_argument("--eth-chain-id", type=int, default=_SEPOLIA_CHAIN_ID)
    ap.add_argument(
        "--eth-network", default="sepolia", help="ETH network tag (anvil|sepolia); auto-anvil when chain-id 31337"
    )
    ap.add_argument("--eth-amount-wei", type=int, default=10**14)  # 0.0001 ETH dust
    ap.add_argument("--eth-maker-addr", default="", help="maker's ETH address (receives ETH on claim)")
    ap.add_argument("--eth-taker-addr", default="", help="taker's ETH address (receives ETH on refund)")
    ap.add_argument("--eth-artifact", default=str(_DEFAULT_ARTIFACT))
    ap.add_argument("--eth-timeout-s", type=int, default=86_400)
    # RXD (regtest only)
    ap.add_argument(
        "--rxd-network", default="bcrt", help="Radiant network HRP (regtest only: must be in AUDIT_CLEARED_NETWORKS)"
    )
    ap.add_argument("--rxd-electrumx-url", default="", help="regtest Radiant ElectrumX/Fulcrum ws/wss URL")
    ap.add_argument("--rxd-electrumx-insecure", action="store_true")
    ap.add_argument("--rxd-photons", type=int, default=100_000)
    ap.add_argument("--t-rxd-blocks", type=int, default=60)
    ap.add_argument(
        "--asset-locked-at-height",
        type=int,
        default=0,
        help="RXD height the covenant was funded at (for the reorg gate)",
    )
    # the operator's OWN regtest fee UTXO (party-local; WIF never serialised into an exchange file)
    ap.add_argument("--fee-txid", default="")
    ap.add_argument("--fee-vout", type=int, default=0)
    ap.add_argument("--fee-value", type=int, default=0)
    ap.add_argument("--fee-spk-hex", default="")
    ap.add_argument("--fee-wif", default="")
    # margin / cross-clock
    ap.add_argument("--margin-blocks", type=int, default=36)
    ap.add_argument("--btc-block-interval-s", type=float, default=600.0)
    ap.add_argument("--rxd-block-interval-s", type=float, default=300.0)
    ap.add_argument("--eth-finalization-window-s", type=int, default=None)
    ap.add_argument("--rxd-claim-burial-s", type=int, default=1800)
    ap.add_argument("--rxd-confirm-slack-s", type=int, default=600)
    ap.add_argument("--rounding-slack-s", type=int, default=300)
    ap.add_argument("--max-covenant-confirm-wait-s", type=int, default=600)
    # ops
    ap.add_argument("--poll-interval-s", type=float, default=10.0)
    ap.add_argument("--resume-deadline-s", type=float, default=3600.0)
    args = ap.parse_args()
    # Resolve the ETH finalization window from the chain registry when not pinned (vetted per-chain).
    if args.eth_finalization_window_s is None:
        from pyrxd.eth_wallet.chains import evm_chain_by_id
        from pyrxd.gravity.swap_coordinator import _MIN_ETH_FINALIZATION_WINDOW_S
        from pyrxd.security.errors import ValidationError

        try:
            args.eth_finalization_window_s = evm_chain_by_id(args.eth_chain_id).finalization_window_s
        except ValidationError:
            args.eth_finalization_window_s = _MIN_ETH_FINALIZATION_WINDOW_S
    # Default the per-role local secret file next to the io dir if unset.
    if not args.local_out and args.role:
        args.local_out = str(Path(args.io).expanduser() / f".{args.role}_local_secret.json")
    return args


_DISPATCH = {
    ("taker", "intro"): taker_phase_intro,
    ("taker", "fund"): taker_phase_fund,
    ("taker", "claim"): taker_phase_claim,
    ("maker", "envelope"): maker_phase_envelope,
    ("maker", "lock-claim"): maker_phase_lock_claim,
}


def main() -> None:
    args = _args()
    if args.self_check:
        run_self_check()
        return
    if not args.role or not args.phase:
        raise SystemExit("specify --self-check, or both --role and --phase (see --help)")
    fn = _DISPATCH.get((args.role, args.phase))
    if fn is None:
        raise SystemExit(
            f"invalid (role, phase) = ({args.role}, {args.phase}); taker: intro|fund|claim, maker: envelope|lock-claim"
        )
    asyncio.run(fn(args))


if __name__ == "__main__":
    main()
