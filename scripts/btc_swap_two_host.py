#!/usr/bin/env python3
"""Two-HOST BTC↔RXD swap dry-run harness — the BTC-arm sibling of ``eth_swap_two_host.py``.

Every BTC↔RXD swap run so far has been *single-process* (``dust_swap_run.py`` / the regtest e2e):
one program plays BOTH the maker and the taker, holding all keys and the preimage ``p`` in one
address space. That proves the plumbing (the legs broadcast, the FSM advances) but NOT the one
property an atomic swap exists for — safety against a *hostile, untrusted counterparty*. This
harness is the PREP for a genuine two-party BTC run: it splits the EXISTING flow across two
operators on two hosts so that

* each operator holds ONLY its own keys (the maker: its RXD refund key + its BTC claim key + ``p``;
  the taker: its RXD claim key + its BTC funding + refund keys),
* the only thing that crosses between hosts is the **public negotiation envelope** (+ a couple of
  public locators / the maker's on-chain BTC claim tx) — copied out-of-band as JSON files,
* the preimage ``p`` NEVER leaves the maker and is NEVER serialised into any exchanged file (only
  ``H = SHA256(p)`` ever crosses; on the BTC arm ``p`` is revealed in the maker's on-chain claim
  WITNESS, which the taker scrapes FROM THE CHAIN — never from a file), and
* the taker INDEPENDENTLY re-derives + verifies the timelock-margin safety invariant and the
  covenant SPK from the envelope alone and REFUSES to fund if they fail; symmetrically the MAKER
  re-derives the expected BTC HTLC scriptPubKey from terms and REFUSES to lock RXD unless the
  taker funded exactly that HTLC with the agreed amount (else a hostile taker funds a bad/absent
  HTLC and the honest maker locks RXD for nothing).

It drives the UNCHANGED production ``SwapCoordinator`` + ``BitcoinTaprootLeg`` +
``RadiantCovenantLeg`` — the object graph the regtest e2e / ``dust_swap_run.py`` build; the ONLY
change is that each process constructs only its own side and the envelope/locators cross via files
instead of shared Python memory. Nothing here is a new coordinator or a new leg.

Honest scope — this is the PREP, not the run:
  * **Regtest ONLY.** RXD runs on a Radiant *regtest* node (``bcrt``) via ElectrumX; BTC runs on a
    Bitcoin Core *regtest* node via JSON-RPC (``BitcoinCoreRpcSource`` +
    ``BitcoinCoreFundingReader`` + ``BitcoinCoreBroadcaster``). Both legs' audit gates fail closed on
    any value-bearing network; there is no mainnet wiring here.
  * **The ``--self-check`` mode needs NO chain.** It exercises the security-critical seam — the maker
    writes the envelope, the taker reads it back and runs the independent margin + covenant re-
    derivation, the maker re-derives the expected BTC HTLC SPK, and we assert ``p`` is absent from
    every serialised artifact — entirely offline. That is the part this PREP commit validates (a
    ``test_btc_two_host_self_check`` covers it). The live two-host run (``--role maker|taker`` against
    real regtest nodes with a funded taker BTC UTXO + a per-side RXD fee UTXO) is the operator runbook
    and is NOT exercised in CI.

Files exchanged out-of-band (the ENTIRE cross-host surface — all public, never the preimage p):
  1. ``taker_intro.json``   (taker -> maker) : taker's public RXD pubkey-hash + BTC refund x-only key.
  2. ``envelope.json``      (maker -> taker) : ``NegotiatedTerms`` (H only) + the maker's public RXD
                                               pkh + BTC claim x-only key + the funded covenant SPK.
  3. ``taker_funding.json`` (taker -> maker) : the funded BTC HTLC locator (``BtcHtlcLocator`` —
                                               carries the HTLC tree + funding outpoint, never p).
  4. ``maker_claim.json``   (maker -> taker) : the maker's RAW BTC claim tx hex (after the maker
                                               claims BTC and reveals p in the WITNESS on-chain — the
                                               taker scrapes p from those bytes, verified vs H).

Usage (see the how-to for the full runbook):
  # offline, no chain — the validatable self-check:
  python scripts/btc_swap_two_host.py --self-check

  # live two-host dry-run (each operator on their own host, exchanging the files above):
  #   taker  --phase intro       ; maker --phase envelope
  #   taker  --phase fund        ; maker --phase lock-claim
  #   taker  --phase claim
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

import coincurve

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _dust_swap_shared import CapturingBroadcaster, atomic_write_mode_600, confirm

from pyrxd.btc_wallet import taproot as bt
from pyrxd.btc_wallet.htlc_leg import (
    AUDIT_CLEARED_NETWORKS,
    BitcoinCoreBroadcaster,
    BitcoinTaprootLeg,
    FundingPolicy,
)
from pyrxd.btc_wallet.keys import generate_keypair
from pyrxd.btc_wallet.payment import BtcUtxo
from pyrxd.gravity.htlc_covenant import build_htlc_covenant_rxd
from pyrxd.gravity.radiant_leg import RadiantChainIO, RadiantCovenantLeg
from pyrxd.gravity.seen_store import DurableSeenStore
from pyrxd.gravity.swap_coordinator import (
    CoordinatorConfig,
    MarginPolicy,
    SwapCoordinator,
    assert_timelock_margin,
)
from pyrxd.gravity.swap_state import NegotiatedTerms, SwapRecord, SwapRole, SwapState
from pyrxd.keys import PrivateKey
from pyrxd.network.bitcoin import BitcoinCoreFundingReader, BitcoinCoreRpcSource
from pyrxd.network.electrumx import ElectrumXClient
from pyrxd.security.errors import ValidationError
from pyrxd.security.types import Hex20

# Regtest-only: both HRPs are in AUDIT_CLEARED_NETWORKS so the legs' audit gates pass without an
# opt-in, and any non-regtest network fails closed. There is deliberately NO mainnet path here.
_RXD_REGTEST = "bcrt"
_BTC_REGTEST = "bcrt"


# ---------------------------------------------------------------------------
# File exchange (the cross-host surface — all public, never the preimage p)
# ---------------------------------------------------------------------------

# Substring markers for secret-bearing key names (review MEDIUM). Uses "priv" (NOT "privkey") so
# private_key / priv_key / privatekey all match despite the separator, and "entropy"/"xprv"/"seed"/
# "mnemonic" cover raw entropy and BIP32/BIP39 material. KEEP IN SYNC with eth_swap_two_host.py and with
# swap_run_verify._SECRET_FORBIDDEN_KEYS (a parity test enforces it); "preimage" already covers
# preimage_p/preimage_p_hex, "priv"/"secret"/"wif" cover privkey/secret_key.
_SECRET_FORBIDDEN_KEYS = (
    "preimage",
    "p_hex",
    "wif",
    "secret",
    "priv",
    "signing_key",
    "eth_key",
    "seed",
    "mnemonic",
    "xprv",
    "xpriv",
    "entropy",
)


def _looks_like_wif(s: str) -> bool:
    """A base58 WIF-shaped VALUE (51-52 chars, 5/K/L lead) — catches a WIF stored under an innocuous key
    name (review LOW: the key-name markers alone miss that). Distinguishable from hex spk/pkh/txid values
    (which fill every public doc), so scanning values for this can't false-positive on them."""
    if not (51 <= len(s) <= 52) or s[0] not in "5KL":
        return False
    return all(c in "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz" for c in s)


def _assert_public_only(doc: dict, *, what: str) -> None:
    """Fail-closed: refuse to write a cross-host file that smuggles a secret (recursive, case-insensitive) —
    by key NAME (private-material markers) and by VALUE shape (a WIF under a benign key)."""

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
        elif isinstance(node, str) and _looks_like_wif(node):
            raise SystemExit(f"REFUSING to write {what}: value at {path} is WIF-shaped (a smuggled private key)")

    _walk(doc, "")


def _io_dir(args) -> Path:
    d = Path(args.io).expanduser()
    d.mkdir(parents=True, exist_ok=True)
    return d


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


def _persist_local_secret(args, doc: dict) -> None:
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


# ---------------------------------------------------------------------------
# Shared builders (BOTH roles must agree on terms + the covenant from public inputs)
# ---------------------------------------------------------------------------


def _margin_policy(args) -> MarginPolicy:
    """The ESTIMATED regtest margin policy. A real-value run MUST use ``MarginPolicy.measured(...)``;
    this is a regtest PREP, so flat burial + estimated margins are the documented dust-grade hatch —
    the audit gate still blocks real value."""
    return MarginPolicy(
        margin=bt.Timelock(args.margin_blocks, bt.TimeUnit.BLOCKS),
        block_interval_s=args.btc_block_interval_s,
        is_measured=False,
        rxd_block_interval_s=args.rxd_block_interval_s,
        accept_flat_burial=True,
    )


def _xonly_of(privkey_bytes: bytes) -> bytes:
    """The 32-byte x-only pubkey for a 32-byte secp256k1 secret (the HTLC leaf key format)."""
    return coincurve.PublicKeyXOnly.from_secret(bytes(privkey_bytes)).format()


def _terms_from_public(
    *,
    hashlock: bytes,
    btc_sats: int,
    t_rxd_blocks: int,
    t_btc_blocks: int,
    taker_pkh: bytes,
    maker_pkh: bytes,
    btc_claim_xonly: bytes,
    btc_refund_xonly: bytes,
):
    """Build the plain-RXD HTLC covenant + the chain-agnostic ``NegotiatedTerms`` from PUBLIC inputs
    only (both pkhs + both BTC x-only keys are public; H is public; ``p`` is never used here). BOTH
    roles call this with the SAME public inputs and MUST get the identical covenant SPK + dest hashes
    — that mutual re-derivation is the trust anchor. Returns ``(terms, covenant)``."""
    t_rxd = bt.Timelock(t_rxd_blocks, bt.TimeUnit.BLOCKS)
    t_btc = bt.Timelock(t_btc_blocks, bt.TimeUnit.BLOCKS)  # the REAL counter-leg CSV deadline for BTC
    cov = build_htlc_covenant_rxd(
        amount=btc_sats,
        taker_pkh=bytes(Hex20(taker_pkh)),
        maker_pkh=bytes(Hex20(maker_pkh)),
        hashlock=hashlock,
        refund_csv=t_rxd.value,
    )
    terms = NegotiatedTerms(
        hashlock=hashlock,
        btc_sats=btc_sats,
        radiant_amount=btc_sats,
        t_btc=t_btc,
        t_rxd=t_rxd,
        asset_variant="rxd",
        genesis_ref=b"",
        taker_dest_hash=cov.expected_taker_hash,
        maker_dest_hash=cov.expected_maker_hash,
        btc_claim_pubkey_xonly=bytes(btc_claim_xonly),
        btc_refund_pubkey_xonly=bytes(btc_refund_xonly),
        counter_chain="btc",
    )
    return terms, cov


def _radiant_leg(args, *, taker_pkh: bytes, maker_pkh: bytes, fee_source):
    """Construct the REAL RadiantCovenantLeg over an ElectrumX client on a REGTEST node."""
    if args.rxd_network not in AUDIT_CLEARED_NETWORKS:
        raise SystemExit(
            f"RXD network {args.rxd_network!r} is not a cleared test chain "
            f"({sorted(AUDIT_CLEARED_NETWORKS)}); this PREP harness is regtest only."
        )
    client = ElectrumXClient(urls=[args.rxd_electrumx_url], allow_insecure=args.rxd_electrumx_insecure)
    return RadiantCovenantLeg(
        network=args.rxd_network,
        taker_pkh=bytes(Hex20(taker_pkh)),
        maker_pkh=bytes(Hex20(maker_pkh)),
        chain_io=RadiantChainIO(client),
        fee_source=fee_source,
        # Thread the taker's covenant depth floor into the LEG too (review MEDIUM): --taker-min-rxd-confs
        # gated the pre-lock covenant lookup, but the leg's own spend-side reorg gate stayed hard-pinned at
        # 1, so a deep operator setting still resolved later spends at floor-1. Use the same floor here.
        min_confirmations=max(1, getattr(args, "taker_min_rxd_confs", 1)),
    )


def _btc_source(args) -> BitcoinCoreRpcSource:
    if args.btc_network not in AUDIT_CLEARED_NETWORKS:
        raise SystemExit(
            f"BTC network {args.btc_network!r} is not a cleared test chain "
            f"({sorted(AUDIT_CLEARED_NETWORKS)}); this PREP harness is regtest only."
        )
    return BitcoinCoreRpcSource(args.btc_rpc_url, args.btc_rpc_user, args.btc_rpc_password)


def _btc_leg(
    args,
    source: BitcoinCoreRpcSource,
    *,
    role: str,
    claim_xonly: bytes,
    taker_refund_kp,
    taker_funding_utxo,
    refund_to_spk: bytes,
    claim_to_spk: bytes,
    maker_claim_privkey: bytes | None,
) -> BitcoinTaprootLeg:
    """Construct the REAL BitcoinTaprootLeg over a Bitcoin Core node. The TAKER role funds + refunds
    (no maker_claim_privkey -> the leg physically cannot claim); the MAKER role claims (holds
    maker_claim_privkey). ``taker_funding_utxo`` is the taker's own UTXO to fund the HTLC from (a
    placeholder for the maker, who never funds)."""
    # The maker CLAIMS via the coordinator (which returns no bytes); wrap in CapturingBroadcaster so
    # the harness can recover the raw claim tx to publish for the taker to scrape p from.
    raw_bc = BitcoinCoreBroadcaster(source._rpc)
    broadcaster = CapturingBroadcaster(raw_bc) if role == "maker" else raw_bc
    reader = BitcoinCoreFundingReader(source._rpc)
    return BitcoinTaprootLeg(
        network=args.btc_network,
        taker_keypair=taker_refund_kp,
        funding_utxo=taker_funding_utxo,
        maker_claim_pubkey_xonly=bytes(claim_xonly),
        broadcaster=broadcaster,
        funding_reader=reader,
        refund_to_scriptpubkey=bytes(refund_to_spk),
        claim_to_scriptpubkey=bytes(claim_to_spk),
        policy=FundingPolicy(fee_sats=args.btc_fee_sats, min_confirmations=1, funding_input_type="p2wpkh"),
        maker_claim_privkey=maker_claim_privkey if role == "maker" else None,
    )


class _OperatorFeeSource:
    """A ``FeeUtxoSource`` from a single operator-supplied regtest RXD fee UTXO. Each operator owns
    their OWN fee UTXO (the covenant output carries the asset and cannot also pay the fee): the taker
    supplies one for the RXD CLAIM, the maker for the RXD REFUND. The WIF stays party-local."""

    def __init__(self, *, txid: str, vout: int, value: int, scriptpubkey_hex: str, wif: str) -> None:
        from pyrxd.gravity.htlc_spend import FeeInput

        self._fee = FeeInput(txid=txid, vout=vout, value=value, scriptpubkey=bytes.fromhex(scriptpubkey_hex), wif=wif)

    def next_fee_input(self):
        return self._fee


class _NoFeeSource:
    def next_fee_input(self):
        raise SystemExit("this covenant spend needs a regtest RXD fee UTXO (pass --fee-* flags)")


def _fee_source_from_args(args):
    if not (args.fee_txid and args.fee_wif and args.fee_spk_hex):
        return None
    return _OperatorFeeSource(
        txid=args.fee_txid,
        vout=args.fee_vout,
        value=args.fee_value,
        scriptpubkey_hex=args.fee_spk_hex,
        wif=args.fee_wif,
    )


def _coordinator(args, *, terms, btc_leg, rxd_leg, keys_out, record=None):
    """Build the REAL SwapCoordinator — the SAME object graph as dust_swap_run.py / the e2e, only each
    process constructs its own side. Durable seen-store; role-tagged for the P3 recovery guards."""
    if record is None:
        record = SwapRecord(state=SwapState.NEGOTIATED, terms=terms)
    role = SwapRole.MAKER if args.role == "maker" else SwapRole.TAKER
    return SwapCoordinator(
        record=record,
        counter_leg=btc_leg,
        radiant_leg=rxd_leg,
        indexer=None,  # plain RXD has no genesis ref → no ref-authenticity indexer needed
        seen_store=DurableSeenStore(str(Path(keys_out).expanduser()) + ".seen.sqlite"),
        config=CoordinatorConfig(margin_policy=_margin_policy(args), role=role),
    )


async def _maker_verify_btc_funding(btc_leg: BitcoinTaprootLeg, terms, locator) -> int:
    """MAKER-side fail-closed gate (the BTC analog of the ETH maker_verify_counter_funding): bind the
    taker's advertised funding OUTPOINT to the expected HTLC ON-CHAIN — its actual scriptPubKey, value,
    and unspent status read authoritatively from the node — NOT the self-reported locator fields.

    Security (review finding): comparing the locator's OWN ``scriptpubkey()`` proves nothing — the
    taker controls every field of the deserialized locator and can set a correct HTLC tree while
    pointing ``funding_outpoint`` at any decoy output it owns. The maker MUST re-derive the expected
    HTLC scriptPubKey from terms (its own claim key + the taker's refund key + H + t_btc) and assert
    that the REAL output at ``funding_outpoint`` pays exactly that SPK, carries >= the agreed amount,
    and is still unspent — else it locks its asset against an HTLC whose claim its own sighash cannot
    satisfy (a griefing DoS: RXD locked, maker cannot claim BTC, never reveals p). Returns funded sats;
    raises SystemExit on any mismatch, before any RXD is locked."""
    expected_spk = bytes(btc_leg.derive_funding_scriptpubkey(terms))
    onchain_spk, funded = await btc_leg.funding_reader.read_confirmed_unspent_output(
        locator.funding_outpoint.txid, locator.funding_outpoint.vout
    )
    if bytes(onchain_spk) != expected_spk:
        raise SystemExit(
            "REFUSING to lock RXD: the REAL output at the taker's funding outpoint does NOT pay the BTC "
            "HTLC re-derived from the agreed terms (on-chain scriptPubKey mismatch) — a hostile/mis-funded "
            "counter leg. Aborting."
        )
    if funded < terms.btc_sats:
        raise SystemExit(f"REFUSING to lock RXD: BTC HTLC funded {funded} sats < agreed {terms.btc_sats}. Aborting.")
    return funded


# ---------------------------------------------------------------------------
# Role: TAKER
# ---------------------------------------------------------------------------


async def taker_phase_intro(args) -> None:
    """TAKER step 1: generate the taker's OWN keys, publish only the PUBLIC half (RXD pkh + BTC refund
    x-only). The taker's RXD claim key + BTC refund key + BTC funding key stay LOCAL (mode 600)."""
    io_dir = _io_dir(args)
    taker_rxd = PrivateKey(os.urandom(32))
    taker_pkh = bytes(Hex20(taker_rxd.public_key().hash160()))
    taker_btc_refund = generate_keypair(args.btc_network)
    refund_xonly = _xonly_of(taker_btc_refund._privkey.unsafe_raw_bytes())
    _persist_local_secret(
        args,
        {
            "role": "taker",
            "taker_rxd_wif": taker_rxd.wif(),
            "taker_pkh_hex": taker_pkh.hex(),
            "taker_btc_refund_wif": taker_btc_refund.unsafe_wif(),
            "taker_btc_refund_xonly_hex": refund_xonly.hex(),
            "note": "TAKER-LOCAL private state. Never copy to the other host. mode 600.",
        },
    )
    _write_public(
        io_dir,
        "taker_intro.json",
        {"taker_pkh_hex": taker_pkh.hex(), "taker_btc_refund_xonly_hex": refund_xonly.hex()},
    )
    print("  TAKER intro published. Hand taker_intro.json to the maker out-of-band.")


async def taker_phase_fund(args) -> None:
    """TAKER step 2: read the maker's envelope, INDEPENDENTLY verify the timelock margin + re-derive
    the covenant SPK, then fund the BTC HTLC FIRST and publish the funding locator."""
    io_dir = _io_dir(args)
    local = _load_local_secret(args)
    env = _read_public(io_dir, "envelope.json")
    terms = NegotiatedTerms.from_dict(env["terms"])

    # THE safety gate: independent timelock-margin check from the envelope ALONE (the taker uses its
    # OWN policy, never a maker-supplied one) and REFUSE to fund on failure.
    policy = _margin_policy(args)
    try:
        assert_timelock_margin(terms.t_btc, terms.t_rxd, policy)
    except Exception as exc:
        raise SystemExit(f"REFUSING to fund: independent timelock-margin check FAILED ({exc}). Aborting.") from None
    print(f"  margin OK: t_btc={terms.t_btc.value} / t_rxd={terms.t_rxd.value} blk (independent check passed)")

    taker_pkh = bytes.fromhex(local["taker_pkh_hex"])
    maker_pkh = bytes.fromhex(env["maker_pkh_hex"])
    _t2, cov = _terms_from_public(
        hashlock=terms.hashlock,
        btc_sats=terms.btc_sats,
        t_rxd_blocks=terms.t_rxd.value,
        t_btc_blocks=terms.t_btc.value,
        taker_pkh=taker_pkh,
        maker_pkh=maker_pkh,
        btc_claim_xonly=terms.btc_claim_pubkey_xonly,
        btc_refund_xonly=terms.btc_refund_pubkey_xonly,
    )
    if cov.funded_spk.hex() != env["covenant_spk_hex"]:
        raise SystemExit(
            "REFUSING to fund: the maker's advertised covenant SPK does not match the SPK re-derived "
            "from the agreed public terms. Aborting."
        )
    print("  covenant SPK re-derived from public terms == the maker's advertised SPK (consistent).")

    source = _btc_source(args)
    taker_btc_refund = _reconstruct_btc_kp(local["taker_btc_refund_wif"], args.btc_network)
    funding_utxo = BtcUtxo(txid=args.btc_funding_txid, vout=args.btc_funding_vout, value=args.btc_funding_value)
    # taker-role BTC leg: funds + refunds; NO maker_claim_privkey (physically cannot claim BTC).
    btc_leg = _btc_leg(
        args,
        source,
        role="taker",
        claim_xonly=terms.btc_claim_pubkey_xonly,
        taker_refund_kp=taker_btc_refund,
        taker_funding_utxo=funding_utxo,
        refund_to_spk=bytes.fromhex(args.btc_taker_payout_spk_hex),
        claim_to_spk=bytes.fromhex(env["btc_maker_payout_spk_hex"]),
        maker_claim_privkey=None,
    )
    fee_source = _fee_source_from_args(args)
    if fee_source is None:
        raise SystemExit(
            "taker fund/claim needs a regtest RXD fee UTXO: pass --fee-txid/--fee-vout/--fee-value/--fee-spk-hex/--fee-wif"
        )
    rxd_leg = _radiant_leg(args, taker_pkh=taker_pkh, maker_pkh=maker_pkh, fee_source=fee_source)
    coord = _coordinator(args, terms=terms, btc_leg=btc_leg, rxd_leg=rxd_leg, keys_out=args.local_out)

    try:
        # HARDENING (review F2): confirm the maker ACTUALLY funded the RXD covenant on-chain (with the
        # agreed amount) BEFORE we lock any BTC. Otherwise a hostile maker who never locks RXD can wait
        # for our BTC HTLC and claim it with p -> one-sided taker loss. The maker funds RXD in its
        # envelope step (runbook); we verify it programmatically here and fail closed.
        confirm("verify the maker funded the RXD covenant on-chain before funding BTC", auto_yes=args.yes)
        try:
            fop, fval, _fh = await rxd_leg.chain_io.find_covenant_utxo(
                cov.funded_spk, expected_value=terms.radiant_amount
            )
        except Exception as exc:
            raise SystemExit(
                "REFUSING to fund BTC: the agreed RXD covenant SPK is NOT funded on-chain with the agreed "
                f"amount ({exc}). A hostile maker may not have locked RXD; aborting before our BTC is at risk."
            ) from None
        # DEPTH GATE (review MEDIUM): "funded" is not enough — the funding must be BURIED. find_covenant_utxo
        # can return a 0-conf/mempool UTXO (ElectrumX listunspent includes unconfirmed), and a hostile maker
        # who funds RXD with a replaceable/reorgable tx, waits for our BTC lock, then double-spends the RXD
        # funding away strands our BTC (the maker still claims BTC with p; the vanished covenant is no longer
        # claimable by us -> one-sided taker loss). Require a confirmation floor; fail closed below it.
        fop_txid = fop.split(":")[0]
        try:
            confs = await rxd_leg.chain_io.confirmations(fop_txid)
        except Exception as exc:
            raise SystemExit(f"REFUSING to fund BTC: could not read RXD covenant confirmation depth ({exc}).") from None
        if confs < args.taker_min_rxd_confs:
            raise SystemExit(
                f"REFUSING to fund BTC: the RXD covenant funding {fop_txid} has {confs} confirmation(s) "
                f"(< required {args.taker_min_rxd_confs}) — a shallow/mempool funding is reorgable/replaceable "
                "and could be double-spent after we lock. Wait for it to bury, then retry."
            )
        print(f"  -> RXD covenant confirmed funded on-chain at {fop} ({fval} photons), buried {confs} conf(s)")

        confirm(
            "taker_funds_btc: fund the BTC HTLC (taker's UTXO; claim pays the maker, refund pays the taker)",
            auto_yes=args.yes,
        )
        rec = await coord.taker_funds_btc(terms, now_unix_s=int(time.time()))
        if rec.state is not SwapState.BTC_LOCKED:
            raise SystemExit(f"taker_funds_btc landed in {rec.state.value}, expected btc_locked")
        loc = rec.counterchain_locator
        print(f"  -> {rec.state.value}; BTC HTLC funded at {loc.funding_outpoint.txid}:{loc.funding_outpoint.vout}")
        _write_public(io_dir, "taker_funding.json", {"btc_locator": loc.to_dict()})
        print("  TAKER funding published. Hand taker_funding.json to the maker out-of-band.")
    finally:
        await source.close()


async def taker_phase_claim(args) -> None:
    """TAKER step 3: the maker claimed BTC on-chain, revealing p in the witness. Scrape p FROM THE
    CHAIN (from the maker's raw claim tx, verified vs H) and claim the RXD covenant before its refund
    window opens. The reveal is observed via ``taker_observed_reveal`` (verifies sha256(p)==H + that
    the claim spends OUR HTLC outpoint) BEFORE the reorg-gated covenant claim."""
    io_dir = _io_dir(args)
    local = _load_local_secret(args)
    env = _read_public(io_dir, "envelope.json")
    terms = NegotiatedTerms.from_dict(env["terms"])
    claim_doc = _read_public(io_dir, "maker_claim.json")
    claim_raw = bytes.fromhex(claim_doc["btc_claim_tx_hex"])
    loc = bt.BtcHtlcLocator.from_dict(_read_public(io_dir, "taker_funding.json")["btc_locator"])

    taker_pkh = bytes.fromhex(local["taker_pkh_hex"])
    maker_pkh = bytes.fromhex(env["maker_pkh_hex"])
    source = _btc_source(args)
    taker_btc_refund = _reconstruct_btc_kp(local["taker_btc_refund_wif"], args.btc_network)
    btc_leg = _btc_leg(
        args,
        source,
        role="taker",
        claim_xonly=terms.btc_claim_pubkey_xonly,
        taker_refund_kp=taker_btc_refund,
        taker_funding_utxo=BtcUtxo(
            txid=loc.funding_outpoint.txid, vout=loc.funding_outpoint.vout, value=terms.btc_sats
        ),
        refund_to_spk=bytes.fromhex(args.btc_taker_payout_spk_hex),
        claim_to_spk=bytes.fromhex(env["btc_maker_payout_spk_hex"]),
        maker_claim_privkey=None,
    )
    fee_source = _fee_source_from_args(args)
    if fee_source is None:
        raise SystemExit("taker claim needs a regtest RXD fee UTXO (pass --fee-* flags)")
    rxd_leg = _radiant_leg(args, taker_pkh=taker_pkh, maker_pkh=maker_pkh, fee_source=fee_source)
    # Resume at BOTH_LOCKED with the BTC locator attached; taker_observed_reveal advances to
    # SECRET_REVEALED after verifying the maker's on-chain reveal (never fabricating that state).
    record = SwapRecord(state=SwapState.NEGOTIATED, terms=terms).with_counter_lock(loc).with_state(SwapState.BTC_LOCKED)
    record = record.with_state(SwapState.BOTH_LOCKED)
    coord = _coordinator(args, terms=terms, btc_leg=btc_leg, rxd_leg=rxd_leg, keys_out=args.local_out, record=record)

    try:
        confirm("taker_observed_reveal: verify the maker's on-chain BTC claim reveals THIS swap's p", auto_yes=args.yes)
        rec = await coord.taker_observed_reveal(claim_raw)
        if rec.state is not SwapState.SECRET_REVEALED:
            raise SystemExit(f"taker_observed_reveal landed in {rec.state.value}, expected secret_revealed")
        print("  -> secret_revealed (p verified vs H; the claim spends OUR HTLC outpoint)")

        deadline = time.monotonic() + args.resume_deadline_s
        while True:
            if time.monotonic() >= deadline:
                raise SystemExit("deadline exceeded; operator must intervene (p is public on-chain).")
            now_rxd = await _rxd_height(args)
            confirm("taker_scrape_and_claim_asset: claim the RXD covenant with the scraped p", auto_yes=args.yes)
            rec = await coord.taker_scrape_and_claim_asset(
                claim_raw, now_rxd_height=now_rxd, asset_locked_at_height=args.asset_locked_at_height
            )
            if rec.state is SwapState.COMPLETED:
                print(f"  -> {rec.state.value} — RXD covenant claimed; cross-chain swap COMPLETE")
                break
            if rec.state is SwapState.SECRET_REVEALED:
                print("  reorg gate: WAIT (BTC claim not yet reorg-deep); retrying...")
                await asyncio.sleep(args.poll_interval_s)
                continue
            if rec.state is SwapState.ASSET_VULNERABLE:
                print("  reorg gate SQUEEZED -> ASSET_VULNERABLE; attempting winner-take-all claim.")
                confirm(
                    "taker_claim_asset_from_vulnerable: best-effort claim (accepts residual reorg risk)",
                    auto_yes=args.yes,
                )
                rec = await coord.taker_claim_asset_from_vulnerable(claim_raw)
                print(f"  -> {rec.state.value}")
                break
            raise SystemExit(f"unexpected state {rec.state.value}; operator must intervene")
    finally:
        await source.close()


# ---------------------------------------------------------------------------
# Role: MAKER
# ---------------------------------------------------------------------------


async def maker_phase_envelope(args) -> None:
    """MAKER step 1: generate (p, H), read the taker's intro, assemble the covenant + terms, publish
    the PUBLIC envelope (H only). p is held LOCALLY (mode 600) and asserted ABSENT from the envelope."""
    io_dir = _io_dir(args)
    intro = _read_public(io_dir, "taker_intro.json")
    taker_pkh = bytes.fromhex(intro["taker_pkh_hex"])
    taker_btc_refund_xonly = bytes.fromhex(intro["taker_btc_refund_xonly_hex"])

    from pyrxd.security.secrets import SecretBytes

    p_secret = SecretBytes(os.urandom(32))
    h = hashlib.sha256(p_secret.unsafe_raw_bytes()).digest()
    maker_rxd = PrivateKey(os.urandom(32))
    maker_pkh = bytes(Hex20(maker_rxd.public_key().hash160()))
    maker_btc_claim = coincurve.PrivateKey(os.urandom(32))
    claim_xonly = _xonly_of(maker_btc_claim.secret)

    terms, cov = _terms_from_public(
        hashlock=h,
        btc_sats=args.btc_sats,
        t_rxd_blocks=args.t_rxd_blocks,
        t_btc_blocks=args.t_btc_blocks,
        taker_pkh=taker_pkh,
        maker_pkh=maker_pkh,
        btc_claim_xonly=claim_xonly,
        btc_refund_xonly=taker_btc_refund_xonly,
    )

    _persist_local_secret(
        args,
        {
            "role": "maker",
            "hashlock_H_hex": h.hex(),
            "preimage_p_hex": p_secret.unsafe_raw_bytes().hex(),  # MAKER-LOCAL ONLY — never crosses hosts
            "maker_rxd_wif": maker_rxd.wif(),
            "maker_pkh_hex": maker_pkh.hex(),
            "taker_pkh_hex": taker_pkh.hex(),
            "maker_btc_claim_privkey_hex": maker_btc_claim.secret.hex(),
            "btc_claim_xonly_hex": claim_xonly.hex(),
            "taker_btc_refund_xonly_hex": taker_btc_refund_xonly.hex(),
            "covenant_spk_hex": cov.funded_spk.hex(),
            "note": "MAKER-LOCAL private state incl preimage p. Never copy to the other host. mode 600.",
        },
    )
    _write_public(
        io_dir,
        "envelope.json",
        {
            "schema": "btc_rxd_two_host_envelope_v1",
            "terms": terms.to_dict(),  # carries H; to_dict() never emits p
            "maker_pkh_hex": maker_pkh.hex(),
            "btc_maker_payout_spk_hex": args.btc_maker_payout_spk_hex,  # where the maker's claimed BTC goes
            "rxd_network": args.rxd_network,
            "btc_network": args.btc_network,
            "covenant_spk_hex": cov.funded_spk.hex(),  # the maker funds THIS; the taker re-derives + checks
        },
    )
    print(f"\n  ENVELOPE published (H={h.hex()[:16]}…). p is held LOCALLY only; it is NOT in the envelope.")
    print(f"  Fund the RXD covenant SPK on regtest as the maker (>= 1 conf):\n    {cov.funded_spk.hex()}")
    print("  Hand envelope.json to the taker, then run --phase lock-claim once the taker has funded BTC.")


async def maker_phase_lock_claim(args) -> None:
    """MAKER step 2: re-derive the EXPECTED BTC HTLC SPK and REFUSE to lock RXD unless the taker
    funded exactly that HTLC; lock RXD, re-validate, then CLAIM the BTC — revealing p in the witness
    on-chain. Publishes the raw claim tx for the taker to scrape p from."""
    io_dir = _io_dir(args)
    local = _load_local_secret(args)
    env = _read_public(io_dir, "envelope.json")
    terms = NegotiatedTerms.from_dict(env["terms"])
    loc = bt.BtcHtlcLocator.from_dict(_read_public(io_dir, "taker_funding.json")["btc_locator"])

    from pyrxd.security.secrets import SecretBytes

    p_secret = SecretBytes(bytes.fromhex(local["preimage_p_hex"]))
    if hashlib.sha256(p_secret.unsafe_raw_bytes()).digest() != terms.hashlock:
        raise SystemExit("local preimage p does not hash to the envelope's H — wrong local file?")
    maker_pkh = bytes.fromhex(local["maker_pkh_hex"])
    taker_pkh = bytes.fromhex(local["taker_pkh_hex"])
    covenant_spk_hex = env["covenant_spk_hex"]  # PUBLIC — from the envelope, never the secret-bearing local dict

    source = _btc_source(args)
    maker_btc_claim = bytes.fromhex(local["maker_btc_claim_privkey_hex"])
    # maker-role BTC leg: claims (holds maker_claim_privkey). The taker_keypair/funding_utxo are
    # placeholders (the maker never funds the HTLC); a fresh regtest keypair + the taker's funding
    # outpoint keep the constructor valid without any maker BTC funding key.
    btc_leg = _btc_leg(
        args,
        source,
        role="maker",
        claim_xonly=terms.btc_claim_pubkey_xonly,
        taker_refund_kp=generate_keypair(args.btc_network),
        taker_funding_utxo=BtcUtxo(
            txid=loc.funding_outpoint.txid, vout=loc.funding_outpoint.vout, value=terms.btc_sats
        ),
        refund_to_spk=bytes.fromhex(args.btc_maker_payout_spk_hex),
        claim_to_spk=bytes.fromhex(args.btc_maker_payout_spk_hex),
        maker_claim_privkey=maker_btc_claim,
    )
    fee_source = _fee_source_from_args(args)
    rxd_leg = _radiant_leg(args, taker_pkh=taker_pkh, maker_pkh=maker_pkh, fee_source=fee_source or _NoFeeSource())
    record = SwapRecord(state=SwapState.NEGOTIATED, terms=terms).with_counter_lock(loc).with_state(SwapState.BTC_LOCKED)
    coord = _coordinator(args, terms=terms, btc_leg=btc_leg, rxd_leg=rxd_leg, keys_out=args.local_out, record=record)

    try:
        # 1. Re-derive the expected HTLC SPK and REFUSE to lock RXD if the taker funded a different one.
        confirm(
            "maker BTC-HTLC verify: bind the taker's funding outpoint to the expected HTLC on-chain",
            auto_yes=args.yes,
        )
        funded = await _maker_verify_btc_funding(btc_leg, terms, loc)
        print(
            f"  -> verified: taker funded the agreed HTLC on-chain (SPK match) with {funded} sats (>= {terms.btc_sats})"
        )

        # 2. Lock the RXD covenant (operator funds the SPK out-of-band), then re-validate -> BOTH_LOCKED.
        print(f"\n  Fund the RXD covenant SPK on regtest now (>= 1 conf):\n    {covenant_spk_hex}")
        confirm("you have funded the RXD covenant SPK on regtest and it has >= 1 conf", auto_yes=args.yes)
        rec = await coord.post_asset_lock_revalidate(bytes.fromhex(covenant_spk_hex), now_unix_s=int(time.time()))
        if rec.state is not SwapState.BOTH_LOCKED:
            raise SystemExit(f"covenant/timing mismatch -> {rec.state.value}; refund the BTC HTLC after t_btc")
        print(f"  -> {rec.state.value}")

        # 3. Claim the BTC, revealing p in the witness on-chain. The taker scrapes p from THIS tx.
        confirm("maker_claims_btc: broadcast the BTC claim (reveals p in the witness on-chain)", auto_yes=args.yes)
        rec = await coord.maker_claims_btc(p_secret)
        claim_raw = getattr(btc_leg.broadcaster, "last_raw", None)
        if claim_raw is None:
            raise SystemExit("did not capture the raw BTC claim tx; the taker needs it to scrape p")
        print(f"  -> {rec.state.value}; BTC claim broadcast")
        _write_public(io_dir, "maker_claim.json", {"btc_claim_tx_hex": bytes(claim_raw).hex()})
        print("  Hand maker_claim.json to the taker; the taker scrapes p from this tx's witness on-chain.")
    finally:
        await source.close()


# ---------------------------------------------------------------------------
# Small local helpers
# ---------------------------------------------------------------------------


def _reconstruct_btc_kp(wif: str, network: str):
    """Rebuild a BtcKeypair from its WIF (the taker's refund key, loaded from the local secret file)."""
    from pyrxd.btc_wallet.keys import keypair_from_wif

    return keypair_from_wif(wif, network=network)


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
    envelope; the taker reads it back, re-derives the covenant + runs the INDEPENDENT margin check;
    the maker re-derives the expected BTC HTLC SPK — and we ASSERT p never appears in any serialised
    artifact. No chain."""
    print("=== BTC↔RXD two-host swap PREP self-check (NO chain) ===")
    from pyrxd.security.secrets import SecretBytes

    p_secret = SecretBytes(os.urandom(32))
    p_hex = p_secret.unsafe_raw_bytes().hex()
    h = hashlib.sha256(p_secret.unsafe_raw_bytes()).digest()

    taker_rxd = PrivateKey(os.urandom(32))
    maker_rxd = PrivateKey(os.urandom(32))
    taker_pkh = bytes(Hex20(taker_rxd.public_key().hash160()))
    maker_pkh = bytes(Hex20(maker_rxd.public_key().hash160()))
    taker_btc_refund = generate_keypair(_BTC_REGTEST)
    maker_btc_claim = coincurve.PrivateKey(os.urandom(32))
    refund_xonly = _xonly_of(taker_btc_refund._privkey.unsafe_raw_bytes())
    claim_xonly = _xonly_of(maker_btc_claim.secret)

    # --- MAKER side: assemble terms + covenant, serialise the envelope. ---
    terms, cov = _terms_from_public(
        hashlock=h,
        btc_sats=100_000,
        t_rxd_blocks=20,
        t_btc_blocks=60,  # t_btc - t_rxd = 40 >= margin 36
        taker_pkh=taker_pkh,
        maker_pkh=maker_pkh,
        btc_claim_xonly=claim_xonly,
        btc_refund_xonly=refund_xonly,
    )
    envelope = {
        "schema": "btc_rxd_two_host_envelope_v1",
        "terms": terms.to_dict(),
        "maker_pkh_hex": maker_pkh.hex(),
        "btc_maker_payout_spk_hex": ("00" * 22),
        "rxd_network": _RXD_REGTEST,
        "btc_network": _BTC_REGTEST,
        "covenant_spk_hex": cov.funded_spk.hex(),
    }
    _assert_public_only(envelope, what="envelope.json")
    envelope_json = json.dumps(envelope, indent=2)
    assert p_hex not in envelope_json, "FAIL: preimage p leaked into the envelope JSON"
    assert "preimage" not in envelope_json.lower(), "FAIL: 'preimage' appears in the envelope JSON"
    assert maker_rxd.wif() not in envelope_json, "FAIL: maker WIF leaked into the envelope"
    assert taker_btc_refund.unsafe_wif() not in envelope_json, "FAIL: taker BTC WIF leaked into the envelope"
    assert maker_btc_claim.secret.hex() not in envelope_json, "FAIL: maker BTC claim key leaked into the envelope"
    print("  [ok] envelope serialises H only — no p, no WIF, no BTC claim key (string scan + key guard)")

    try:
        _assert_public_only({"terms": {"preimage_p_hex": p_hex}}, what="evil.json")
        raise AssertionError("FAIL: the public-only guard did not reject a smuggled preimage")
    except SystemExit:
        print("  [ok] the serialiser guard REJECTS a doc carrying a preimage/secret key")

    # --- TAKER side: read back, re-derive, run the independent margin check. ---
    env2 = json.loads(envelope_json)
    terms2 = NegotiatedTerms.from_dict(env2["terms"])
    assert terms2.hashlock == h, "FAIL: H did not round-trip"
    _t3, cov2 = _terms_from_public(
        hashlock=terms2.hashlock,
        btc_sats=terms2.btc_sats,
        t_rxd_blocks=terms2.t_rxd.value,
        t_btc_blocks=terms2.t_btc.value,
        taker_pkh=taker_pkh,
        maker_pkh=maker_pkh,
        btc_claim_xonly=terms2.btc_claim_pubkey_xonly,
        btc_refund_xonly=terms2.btc_refund_pubkey_xonly,
    )
    assert cov2.funded_spk.hex() == env2["covenant_spk_hex"], "FAIL: taker re-derived a different covenant SPK"
    print("  [ok] taker re-derives the SAME covenant SPK from the envelope's public terms")

    policy = MarginPolicy(
        margin=bt.Timelock(36, bt.TimeUnit.BLOCKS),
        block_interval_s=600.0,
        is_measured=False,
        rxd_block_interval_s=300.0,
        accept_flat_burial=True,
    )
    assert_timelock_margin(terms2.t_btc, terms2.t_rxd, policy)
    print("  [ok] taker's INDEPENDENT timelock-margin check passes for honest terms")

    # ...and REFUSES a hostile too-tight envelope (t_btc - t_rxd < margin).
    hostile, _ = _terms_from_public(
        hashlock=h,
        btc_sats=100_000,
        t_rxd_blocks=50,
        t_btc_blocks=60,  # gap 10 < margin 36
        taker_pkh=taker_pkh,
        maker_pkh=maker_pkh,
        btc_claim_xonly=claim_xonly,
        btc_refund_xonly=refund_xonly,
    )
    try:
        assert_timelock_margin(hostile.t_btc, hostile.t_rxd, policy)
        raise AssertionError("FAIL: the margin check did not reject a too-tight hostile envelope")
    except ValidationError:
        print("  [ok] taker REFUSES a hostile too-tight envelope (t_btc - t_rxd < margin)")

    # --- MAKER side: the expected HTLC SPK is deterministically re-derivable from public terms. ---
    htlc = bt.build_htlc(
        hashlock=terms2.hashlock,
        claim_pubkey_xonly=terms2.btc_claim_pubkey_xonly,
        refund_pubkey_xonly=terms2.btc_refund_pubkey_xonly,
        timeout=terms2.t_btc,
        network=_BTC_REGTEST,
    )
    assert isinstance(htlc.scriptpubkey, bytes) and len(htlc.scriptpubkey) > 0, "FAIL: HTLC SPK not derivable"
    print("  [ok] maker re-derives a deterministic BTC HTLC scriptPubKey from public terms (verify anchor)")

    print("\n=== self-check PASSED ===")


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Two-host BTC↔RXD swap dry-run harness (regtest PREP).")
    p.add_argument("--self-check", action="store_true", help="run the offline seam self-check and exit")
    p.add_argument("--role", choices=["taker", "maker"], help="which side this process drives")
    p.add_argument("--phase", choices=["intro", "fund", "claim", "envelope", "lock-claim"], help="the step to run")
    p.add_argument("--io", default="./btc_swapdir", help="the out-of-band exchange directory")
    p.add_argument("--local-out", default="~/.btc_swap_two_host_local.json", help="LOCAL mode-600 secret file")
    p.add_argument("--yes", action="store_true", help="auto-confirm the interactive gates (unattended)")

    # RXD (radiant regtest via ElectrumX)
    p.add_argument("--rxd-network", default=_RXD_REGTEST)
    p.add_argument("--rxd-electrumx-url", default="tcp://127.0.0.1:50001")
    p.add_argument("--rxd-electrumx-insecure", action="store_true")
    p.add_argument("--rxd-block-interval-s", type=float, default=300.0)

    # BTC (bitcoind regtest via JSON-RPC)
    p.add_argument("--btc-network", default=_BTC_REGTEST)
    p.add_argument("--btc-rpc-url", default="http://127.0.0.1:18443")
    p.add_argument("--btc-rpc-user", default="btc_user")
    p.add_argument("--btc-rpc-password", default="")
    p.add_argument("--btc-block-interval-s", type=float, default=600.0)
    p.add_argument("--btc-fee-sats", type=int, default=2_000)
    p.add_argument("--btc-sats", type=int, default=100_000, help="(maker) the BTC HTLC amount")
    p.add_argument("--t-rxd-blocks", type=int, default=20, help="(maker) the RXD covenant CSV")
    p.add_argument("--t-btc-blocks", type=int, default=60, help="(maker) the BTC HTLC CSV (must exceed t_rxd + margin)")
    p.add_argument("--margin-blocks", type=int, default=36)
    p.add_argument(
        "--taker-min-rxd-confs",
        type=int,
        default=1,
        help="(taker) min confirmations the maker's RXD covenant funding must have before we lock BTC "
        "(default 1 = MINED-only, fine for regtest). REAL VALUE must set this DEEP: a shallow/mempool RXD "
        "funding is reorgable/replaceable, and a maker who double-spends it after we lock strands our BTC.",
    )

    # Taker BTC funding UTXO + payout (taker)
    p.add_argument("--btc-funding-txid", default="")
    p.add_argument("--btc-funding-vout", type=int, default=0)
    p.add_argument("--btc-funding-value", type=int, default=0)
    p.add_argument("--btc-taker-payout-spk-hex", default="", help="(taker) where the taker's refunded BTC goes")
    p.add_argument("--btc-maker-payout-spk-hex", default="", help="(maker) where the maker's claimed BTC goes")

    # RXD fee UTXO (party-local; never serialised)
    p.add_argument("--fee-txid", default="")
    p.add_argument("--fee-vout", type=int, default=0)
    p.add_argument("--fee-value", type=int, default=0)
    p.add_argument("--fee-spk-hex", default="")
    p.add_argument("--fee-wif", default="")

    # Taker claim loop
    p.add_argument(
        "--asset-locked-at-height", type=int, default=0, help="(taker) the RXD height the covenant funded at"
    )
    p.add_argument("--resume-deadline-s", type=float, default=1800.0)
    p.add_argument("--poll-interval-s", type=float, default=10.0)
    return p


_DISPATCH = {
    ("taker", "intro"): taker_phase_intro,
    ("taker", "fund"): taker_phase_fund,
    ("taker", "claim"): taker_phase_claim,
    ("maker", "envelope"): maker_phase_envelope,
    ("maker", "lock-claim"): maker_phase_lock_claim,
}


def main(argv: list[str] | None = None) -> None:
    args = _build_parser().parse_args(argv)
    if args.self_check:
        run_self_check()
        return
    # A 0/negative floor would SILENTLY disable the taker depth gate (0 < 0 is false), defeating the fix
    # (review LOW). The gate exists precisely so a 0-conf covenant is refused — never accept below 1-conf.
    if args.taker_min_rxd_confs < 1:
        raise SystemExit("--taker-min-rxd-confs must be >= 1 (a 0/negative floor silently disables the depth gate)")
    if not args.role or not args.phase:
        raise SystemExit("pass --self-check, OR both --role and --phase (see --help)")
    fn = _DISPATCH.get((args.role, args.phase))
    if fn is None:
        raise SystemExit(f"invalid role/phase combination: {args.role}/{args.phase}")
    asyncio.run(fn(args))


if __name__ == "__main__":
    main()
