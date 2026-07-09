#!/usr/bin/env python3
"""swap_run_verify.py — the chain-re-derivation verifier for two-party adversarial swap runs (P1).

THE PROBLEM IT SOLVES. A swap-run harness's own report says what the *coordinator believed* happened —
and `SwapState` advances on BROADCAST, not confirmation (swap_coordinator.py). Scoring a two-party
adversarial run from that self-reported state is a false-pass waiting to happen. This tool ignores every
claim in the parties' journals EXCEPT the cited txids/outpoints, RE-FETCHES each transaction from a chain
source NEITHER party ran, RE-DERIVES which leg paid whom from the fetched bytes, and asserts the global
atomicity truth table:

    PASS  iff (counter_leg, asset_leg) in { (maker-claimed, taker-claimed),   # both complete
                                            (taker-refunded, maker-refunded) } # both unwind
    FAIL  = any mixed corner (one-sided loss — the failure a single-operator run can never produce)
    PENDING = a leg still unspent (never PASS)

It also checks p-reveal provenance (the SAME 32-byte p, by H-match, appears in both the maker's counter
claim and the taker's asset claim, and the revealing tx spends OUR outpoint) and that no journal leaked a
secret. See docs/plans/2026-06-27-two-party-adversarial-swap-run-plan.md §4.

SCOPE (be honest about it):
  * IMPLEMENTED + offline-self-checked: the atomicity engine, the secret-only guard, manifest validation,
    RXD asset-leg disposition (covenant claim->taker vs CSV-refund->maker, re-derived from public terms),
    BTC counter-leg disposition (claim reveals p -> maker; refund spends the outpoint -> taker), ETH
    counter-leg disposition (successful Claimed(p) from OUR contract -> maker; Refunded() -> taker;
    reverted/foreign-contract -> anomalous; mirrors swap_coordinator.assert_claim_provenance R6), the
    independent re-fetch adapters (Esplora / ElectrumX / ETH RPC), the p-link/provenance check, the
    lucky-pass MARGIN grade (a PASS whose asset-claim only just beat the maker CSV refund window is flagged
    MARGINAL), and asset-side VALUE integrity (the covenant must be funded with the agreed amount and pay
    its full carrier to the holder — catches under-funding / short-changed payout).
  * NOT YET (clearly marked TODO): the cross-chain net-of-fees balance "made-whole" ledger (needs balance
    snapshots that can't be re-read at a past height independently — deliberately deferred rather than added
    as a journal-trusted check that would weaken the all-chain-re-derived guarantee); the intent-side
    lucky-pass detector (adversary-plan vs on-chain trigger height); two-instance FSM consistency; FT/NFT
    covenant variants; BTC outpoint->spender scanning (the harness must cite the spend txid). Next-cut.

Run `python scripts/swap_run_verify.py --self-check` for the offline engine tests (no network).
"""

from __future__ import annotations

import argparse
import asyncio
import enum
import hashlib
import json
import sys
from dataclasses import dataclass, field, replace
from pathlib import Path
from urllib.parse import urlparse

# pyrxd is importable from the repo (editable install / src layout).
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from pyrxd.btc_wallet.taproot import (
    Timelock,
    TimeUnit,
    btc_input_outpoints_from_raw,
    btc_spend_fields_from_raw,
    build_htlc,
    scrape_secret,
)
from pyrxd.gravity.htlc_covenant import build_htlc_covenant_rxd
from pyrxd.transaction.transaction import Transaction

# Secret substrings forbidden in any cross-host / journal file (mirrors eth_swap_two_host._assert_public_only).
# NB: "priv" (not "privkey") so `private_key` / `priv_key` / `privatekey` all match despite the separator;
# "key" is deliberately broad (an audit journal names things like txid/height/state/address, never a bare
# "key"), and "xprv"/"entropy" cover BIP32 extended-private-keys and raw seed entropy.
# Private-key-bearing key-name markers (review LOW): the bare substring "key" was too broad — it
# rejected legitimately-PUBLIC journal fields (`pubkey`, `public_key`, `claim_pubkey`, `..._pkh_key`),
# an availability regression. "priv"/"secret"/"xprv"/"wif" already cover privkey/private_key/secret_key,
# so we only additionally need the private signing-key name; "signing_key" cannot match a public field.
_SECRET_FORBIDDEN_KEYS = (
    "preimage",
    "p_hex",
    "wif",
    "secret",
    "priv",
    "signing_key",
    "mnemonic",
    "seed",
    "xprv",
    "entropy",
)


def _looks_like_wif(s: str) -> bool:
    """A base58 WIF-shaped VALUE (51-52 chars, 5/K/L lead). Distinguishable from a 64-hex txid — so scanning
    values for this can't false-positive on the txids that legitimately fill every journal. (A raw 32-byte
    preimage is 64-hex, SHAPE-identical to a txid, so it is caught by key name, not by value scan.)"""
    if not (51 <= len(s) <= 52) or s[0] not in "5KL":
        return False
    return all(c in "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz" for c in s)


def _sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


# --------------------------------------------------------------------------- verdict model


class AssetLeg(enum.Enum):
    TAKER_CLAIMED = "asset:taker-claimed"  # covenant spent to the taker holder (with p) — honest completion
    MAKER_REFUNDED = "asset:maker-refunded"  # covenant CSV-refunded to the maker
    PENDING = "asset:pending"  # covenant still unspent
    ANOMALOUS = "asset:anomalous"  # spent to neither expected holder (covenant broken / wrong SPK)


class CounterLeg(enum.Enum):
    MAKER_CLAIMED = "counter:maker-claimed"  # HTLC claimed revealing p — honest completion
    TAKER_REFUNDED = "counter:taker-refunded"  # HTLC CSV-refunded back to the taker
    PENDING = "counter:pending"  # HTLC still unspent
    ANOMALOUS = "counter:anomalous"  # spent in a way that matches neither path


class Verdict(enum.Enum):
    PASS = "PASS"  # both-complete XOR both-unwind, chain-verified
    FAIL_ONE_SIDED = "FAIL_ONE_SIDED"  # the cardinal failure: an honest party is out a leg
    PENDING = "PENDING"  # a leg is still unspent — not scorable yet, never PASS
    ANOMALOUS = "ANOMALOUS"  # a leg landed somewhere impossible — investigate
    INVALID = "INVALID"  # the run package itself failed validation (secret leak / bad manifest / shared endpoint)


@dataclass
class VerifyResult:
    verdict: Verdict
    asset_leg: AssetLeg | None = None
    counter_leg: CounterLeg | None = None
    reasons: list[str] = field(default_factory=list)
    checks: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "verdict": self.verdict.value,
            "asset_leg": self.asset_leg.value if self.asset_leg else None,
            "counter_leg": self.counter_leg.value if self.counter_leg else None,
            "reasons": self.reasons,
            "checks": self.checks,
        }


# --------------------------------------------------------------------------- run package (public-only)


@dataclass(frozen=True)
class Outpoint:
    txid: str  # display (big-endian) hex, as explorers show
    vout: int

    @classmethod
    def parse(cls, s: str) -> Outpoint:
        txid, _, vout = s.partition(":")
        if len(txid) != 64 or not vout.isdigit():
            raise ValueError(f"bad outpoint {s!r} (want 'txid:vout')")
        return cls(txid=txid.lower(), vout=int(vout))

    def prevout_le_bytes(self) -> bytes:
        return bytes.fromhex(self.txid)[::-1] + int(self.vout).to_bytes(4, "little")


@dataclass(frozen=True)
class RunManifest:
    """The PUBLIC facts the verifier needs — no secrets. Emitted by the run harness alongside the journals.

    `taker_pkh`/`maker_pkh` are 20-byte RXD holder pubkey-hashes (public); the covenant SPK is rebuilt from
    them + H + refund_csv + amount exactly as the coordinator does, so the verifier never trusts the harness's
    SPK. `party_endpoints` lists the hosts the two operators used — the verifier's own endpoints must be
    DISJOINT from these (independence)."""

    swap_id: str
    asset_variant: str  # "rxd" (ft/nft: TODO)
    counter_chain: str  # "btc" | "eth"
    honest_party: str  # "maker" | "taker"
    h_hex: str  # 32-byte hashlock H = SHA256(p)
    taker_pkh_hex: str  # 20-byte
    maker_pkh_hex: str  # 20-byte
    rxd_amount: int  # photons (the covenant carrier value)
    refund_csv: int  # t_rxd in blocks
    covenant_funding: Outpoint  # where the asset was locked (RXD)
    # counter leg identity — exactly one is set per counter_chain:
    counter_funding: Outpoint | None = None  # btc: the HTLC P2TR funding outpoint
    eth_contract: str | None = None  # eth: the per-swap deployed EthHtlc contract address (0x..)
    eth_chain_id: int | None = None  # eth: the chain id the contract lives on
    eth_funding_tx: str | None = None  # eth: the DEPLOY tx hash (payable ctor; its value == the funded wei)
    # counter-leg RECIPIENT binding (review HIGH): the verifier previously inferred "maker claimed" purely
    # from "a spend revealed p", never that the claim actually PAYS THE MAKER — so a malformed counter HTLC
    # whose claim reveals p but pays the TAKER (btc: taker-keyed claim leaf; eth: contract claimant=taker)
    # would score MAKER_CLAIMED while the honest maker lost both legs. These public negotiated terms let the
    # verifier RE-DERIVE the counter HTLC and bind the claim to the maker (symmetry with the asset leg):
    #   btc: rebuild the funding SPK from the two x-only pubkeys + H + t_btc; assert the funding output pays it.
    #   eth: decode the deploy tx's constructor args (claimant/hashlock); assert claimant==maker && hashlock==H.
    btc_claim_xonly_hex: str | None = None  # btc: the MAKER's 32-byte x-only claim pubkey
    btc_refund_xonly_hex: str | None = None  # btc: the TAKER's 32-byte x-only refund pubkey
    t_btc_blocks: int | None = None  # btc: the counter HTLC CSV (blocks)
    eth_maker_claimant: str | None = None  # eth: the MAKER's payout address (the contract's immutable claimant)
    # counter-leg VALUE (review MEDIUM): the agreed amount the counter HTLC must be funded with (btc: sats;
    # eth: wei). When set, the verifier asserts the counter leg was FUNDED with exactly this — BTC from the
    # funding output value, ETH from the deploy tx value (payable constructor, bound to our contract via the
    # deploy receipt's contractAddress) — else an atomic-but-MISPRICED swap would PASS. Optional (None = off).
    counter_amount: int | None = None
    # lucky-pass margin grading (optional): the RXD height the covenant was funded at + the declared minimum
    # slack the honest taker's asset-claim must have had before the maker's CSV refund window opened.
    asset_locked_at_height: int | None = None
    min_margin_blocks: int = 2
    party_endpoints: tuple[str, ...] = ()

    @classmethod
    def from_dict(cls, d: dict) -> RunManifest:
        for k in (
            "swap_id",
            "asset_variant",
            "counter_chain",
            "honest_party",
            "h_hex",
            "taker_pkh_hex",
            "maker_pkh_hex",
            "rxd_amount",
            "refund_csv",
            "covenant_funding",
        ):
            if k not in d:
                raise ValueError(f"manifest missing required key {k!r}")
        if d["asset_variant"] != "rxd":
            raise ValueError(f"first-cut verifier supports asset_variant='rxd' only (got {d['asset_variant']!r})")
        if d["counter_chain"] not in ("btc", "eth"):
            raise ValueError(f"counter_chain must be 'btc' or 'eth' (got {d['counter_chain']!r})")
        if d["honest_party"] not in ("maker", "taker"):
            raise ValueError("honest_party must be 'maker' or 'taker'")
        if len(bytes.fromhex(d["h_hex"])) != 32:
            raise ValueError("h_hex must be 32 bytes")
        if len(bytes.fromhex(d["taker_pkh_hex"])) != 20 or len(bytes.fromhex(d["maker_pkh_hex"])) != 20:
            raise ValueError("taker_pkh_hex / maker_pkh_hex must be 20 bytes")
        counter_funding = eth_contract = eth_chain_id = eth_funding_tx = None
        btc_claim_xonly_hex = btc_refund_xonly_hex = t_btc_blocks = eth_maker_claimant = None
        if d["counter_chain"] == "btc":
            if "counter_funding" not in d:
                raise ValueError("btc counter_chain requires 'counter_funding' (txid:vout)")
            counter_funding = Outpoint.parse(str(d["counter_funding"]))
            # Optional counter-RECIPIENT binding inputs (all three required together, or none).
            _rk = [k for k in ("btc_claim_xonly_hex", "btc_refund_xonly_hex", "t_btc_blocks") if d.get(k) is not None]
            if _rk:
                if len(_rk) != 3:
                    raise ValueError(
                        "btc counter-recipient binding needs ALL of btc_claim_xonly_hex, "
                        "btc_refund_xonly_hex, t_btc_blocks (or none)"
                    )
                btc_claim_xonly_hex = str(d["btc_claim_xonly_hex"]).lower()
                btc_refund_xonly_hex = str(d["btc_refund_xonly_hex"]).lower()
                if len(bytes.fromhex(btc_claim_xonly_hex)) != 32 or len(bytes.fromhex(btc_refund_xonly_hex)) != 32:
                    raise ValueError("btc_claim_xonly_hex / btc_refund_xonly_hex must be 32-byte x-only pubkeys")
                t_btc_blocks = int(d["t_btc_blocks"])
        else:  # eth
            if "eth_contract" not in d or "eth_chain_id" not in d:
                raise ValueError("eth counter_chain requires 'eth_contract' (0x addr) and 'eth_chain_id'")
            eth_contract = str(d["eth_contract"]).lower()
            if not (eth_contract.startswith("0x") and len(eth_contract) == 42):
                raise ValueError("eth_contract must be a 0x-prefixed 20-byte address")
            eth_chain_id = int(d["eth_chain_id"])
            if d.get("eth_funding_tx") is not None:  # optional; required to check counter VALUE + RECIPIENT
                eth_funding_tx = str(d["eth_funding_tx"]).lower()
                if not (eth_funding_tx.startswith("0x") and len(eth_funding_tx) == 66):
                    raise ValueError("eth_funding_tx must be a 0x-prefixed 32-byte tx hash")
            if d.get("eth_maker_claimant") is not None:  # optional counter-RECIPIENT binding
                eth_maker_claimant = str(d["eth_maker_claimant"]).lower()
                if not (eth_maker_claimant.startswith("0x") and len(eth_maker_claimant) == 42):
                    raise ValueError("eth_maker_claimant must be a 0x-prefixed 20-byte address")
        return cls(
            swap_id=str(d["swap_id"]),
            asset_variant=str(d["asset_variant"]),
            counter_chain=str(d["counter_chain"]),
            honest_party=str(d["honest_party"]),
            h_hex=str(d["h_hex"]).lower(),
            taker_pkh_hex=str(d["taker_pkh_hex"]).lower(),
            maker_pkh_hex=str(d["maker_pkh_hex"]).lower(),
            rxd_amount=int(d["rxd_amount"]),
            refund_csv=int(d["refund_csv"]),
            covenant_funding=Outpoint.parse(str(d["covenant_funding"])),
            counter_funding=counter_funding,
            eth_contract=eth_contract,
            eth_chain_id=eth_chain_id,
            eth_funding_tx=eth_funding_tx,
            btc_claim_xonly_hex=btc_claim_xonly_hex,
            btc_refund_xonly_hex=btc_refund_xonly_hex,
            t_btc_blocks=t_btc_blocks,
            eth_maker_claimant=eth_maker_claimant,
            asset_locked_at_height=(
                int(d["asset_locked_at_height"]) if d.get("asset_locked_at_height") is not None else None
            ),
            min_margin_blocks=int(d.get("min_margin_blocks", 2)),
            party_endpoints=tuple(str(e) for e in d.get("party_endpoints", [])),
            counter_amount=(int(d["counter_amount"]) if d.get("counter_amount") is not None else None),
        )


def assert_no_secrets(doc: object, *, what: str) -> None:
    """Fail-closed if any key in the package matches a secret marker (a leaked p/WIF in a 'public' file
    is a HARD FAIL of the run's instrumentation, not just a warning)."""
    if isinstance(doc, dict):
        for k, v in doc.items():
            if any(m in str(k).lower() for m in _SECRET_FORBIDDEN_KEYS):
                raise ValueError(f"{what}: forbidden secret-bearing key {k!r} present in a public file")
            assert_no_secrets(v, what=what)
    elif isinstance(doc, list):
        for v in doc:
            assert_no_secrets(v, what=what)
    elif isinstance(doc, str) and _looks_like_wif(doc):
        # Value-level catch for a WIF stored under an innocuous key ({"note": "L5..."}). Limited to the
        # WIF shape on purpose — a raw preimage/txid is 64-hex and indistinguishable, so those are guarded
        # by key name above rather than by a value scan that would reject every legitimate txid.
        raise ValueError(f"{what}: a WIF-shaped secret value is present in a public file")


def assert_independent_endpoints(verifier_urls: list[str], party_endpoints: tuple[str, ...]) -> None:
    """The verifier's corroboration sources MUST be hosts neither party ran (else it's not independent).

    NB: `party_endpoints` is manifest-supplied (party-declared), so an adversary who runs the "third-party"
    source can simply omit it here and this hostname check passes. This guard is therefore ADVISORY — the
    auditor should still pass endpoints they trust out-of-band. The load-bearing anti-substitution defenses
    are the per-tx txid pins (BTC/RXD: bytes hash to the cited txid) plus the covenant-outpoint provenance
    checks, which hold even against a source that lies about which txid is which."""
    party_hosts = {(urlparse(e).hostname or e).lower() for e in party_endpoints}
    for u in verifier_urls:
        host = (urlparse(u).hostname or u).lower()
        if host in party_hosts:
            raise ValueError(
                f"verifier endpoint {host!r} was ALSO used by a swap party — re-fetch is not independent. "
                f"Point --btc-esplora-url / --rxd-electrumx-url at a third source."
            )


# --------------------------------------------------------------------------- leg re-derivation (pure)


def rxd_expected_scripts(m: RunManifest) -> tuple[bytes, bytes, bytes]:
    """Re-derive (funded_spk, taker_holder_script, maker_holder_script) from PUBLIC terms — the verifier
    never trusts the harness's covenant bytes. Mirrors radiant_leg.expected_covenant_scriptpubkey."""
    cov = build_htlc_covenant_rxd(
        amount=m.rxd_amount,
        taker_pkh=bytes.fromhex(m.taker_pkh_hex),
        maker_pkh=bytes.fromhex(m.maker_pkh_hex),
        hashlock=bytes.fromhex(m.h_hex),
        refund_csv=m.refund_csv,
    )
    return cov.funded_spk, cov.taker_holder_script, cov.maker_holder_script


def _output(raw_tx: bytes, vout: int) -> tuple[bytes, int]:
    """The (scriptPubKey, satoshis) of output `vout` of a NON-segwit (RXD) raw tx."""
    tx = Transaction.from_hex(raw_tx)
    if tx is None:
        raise ValueError("could not parse RXD transaction bytes")
    if not (0 <= vout < len(tx.outputs)):
        raise ValueError(f"vout {vout} out of range (tx has {len(tx.outputs)} outputs)")
    out = tx.outputs[vout]
    return out.locking_script.serialize(), int(out.satoshis)


def _rxd_input_prevouts(raw_tx: bytes) -> set[bytes]:
    """The set of prevout-le-bytes (reversed txid || vout LE) consumed by a NON-segwit RXD tx.

    Parallels ``btc_input_outpoints_from_raw`` for the asset leg so ``verify_asset_leg`` can prove a
    cited spend actually consumes the covenant funding outpoint (provenance) — not merely that some tx
    happens to pay a party's holder address. Matches ``Outpoint.prevout_le_bytes`` exactly.
    """
    tx = Transaction.from_hex(raw_tx)
    if tx is None:
        raise ValueError("could not parse RXD transaction bytes")
    out: set[bytes] = set()
    for inp in tx.inputs:
        out.add(bytes.fromhex(inp.source_txid)[::-1] + int(inp.source_output_index).to_bytes(4, "little"))
    return out


def _output_spk(raw_tx: bytes, vout: int) -> bytes:
    return _output(raw_tx, vout)[0]


def verify_asset_leg(
    m: RunManifest, covenant_funding_tx: bytes, covenant_spend_tx: bytes | None
) -> tuple[AssetLeg, list[str]]:
    """Re-derive the RXD asset-leg disposition from the funding + spending tx bytes.

    1. The funding output MUST pay the re-derived covenant SPK (the asset was locked to the legit covenant).
    2. The spend MUST consume the covenant funding outpoint (provenance) — the cited spend txid is
       journal-supplied, so a party cannot pass off an unrelated tx that merely pays a holder address.
    3. The spend's output[0] decides who got the asset: taker_holder => taker claimed; maker_holder => refund.

    Because the funding SPK is proven to be the real hashlock covenant (check 1) and the confirmed spend
    is proven to consume it (check 2), a confirmed spend to the taker holder necessarily satisfied the
    hashlock branch at consensus (revealing p) — so re-scraping p here would be redundant, and is
    unreliable anyway (RXD is non-segwit; p rides in the scriptSig, not a witness). Provenance + value
    conservation (checks 2 & 4) are the load-bearing gates.
    """
    notes: list[str] = []
    funded_spk, taker_holder, maker_holder = rxd_expected_scripts(m)
    observed_funding_spk, observed_funding_value = _output(covenant_funding_tx, m.covenant_funding.vout)
    if observed_funding_spk != funded_spk:
        return AssetLeg.ANOMALOUS, [
            "covenant funding output SPK does NOT match the covenant re-derived from public terms — "
            "the asset was not locked to the agreed covenant (PARAMS_MISMATCH territory)"
        ]
    # Independent value-integrity: the covenant must carry the agreed amount (catches an under-funded asset —
    # a partial-fill / short-change attack the SPK check alone would miss). Verdict-affecting: a genuine run
    # conserves value, so a mismatch is ANOMALOUS, never a note-only warning that a PASS could sail past.
    if observed_funding_value != m.rxd_amount:
        return AssetLeg.ANOMALOUS, [
            f"covenant funded with {observed_funding_value} photons, agreed {m.rxd_amount} "
            f"(value mismatch — asset under/over-funded)"
        ]
    notes.append("covenant funding SPK == re-derived covenant, carrying the agreed amount")
    if covenant_spend_tx is None:
        return AssetLeg.PENDING, [*notes, "covenant outpoint still unspent"]
    # PROVENANCE (the fix for the false-PASS free-option attack): the cited spend must actually consume the
    # covenant funding outpoint. Mirrors verify_counter_leg_btc's prevout check, which the asset leg lacked.
    if m.covenant_funding.prevout_le_bytes() not in _rxd_input_prevouts(covenant_spend_tx):
        return AssetLeg.ANOMALOUS, [
            *notes,
            "the cited covenant-spend does NOT consume the covenant funding outpoint "
            "(wrong/decoy tx — provenance fail)",
        ]
    notes.append("covenant-spend consumes the covenant funding outpoint")
    spent_to, paid_value = _output(covenant_spend_tx, 0)
    # Made-whole (asset side): the covenant pays its full carrier amount to the holder (the miner fee comes
    # from a separate fee input, never the carrier), so a short-changed payout is a value-integrity failure,
    # not a cosmetic note — ANOMALOUS.
    if paid_value != observed_funding_value:
        return AssetLeg.ANOMALOUS, [
            *notes,
            f"covenant spend paid {paid_value} photons, carrier was {observed_funding_value} "
            f"(value not conserved — short-changed payout)",
        ]
    if spent_to == taker_holder:
        return AssetLeg.TAKER_CLAIMED, [*notes, "covenant spent to the taker holder (hashlock claim)"]
    if spent_to == maker_holder:
        return AssetLeg.MAKER_REFUNDED, [*notes, "covenant spent to the maker holder (CSV refund)"]
    return AssetLeg.ANOMALOUS, [*notes, "covenant spent to NEITHER the taker nor maker holder script"]


def verify_counter_leg_btc(
    m: RunManifest, counter_spend_tx: bytes | None, counter_funding_tx: bytes | None = None
) -> tuple[CounterLeg, bytes | None, list[str]]:
    """Re-derive the BTC counter-leg disposition. The claim leaf reveals p (and pays the maker); the refund
    leaf is a CSV spend back to the taker. We distinguish by whether p is scrapeable, and we require the
    spend to actually consume OUR HTLC funding outpoint (provenance). The middle return element is the
    DIGEST sha256(p) (== manifest H, proven here) — raw preimage bytes never leave this function.

    When ``m.counter_amount`` + ``counter_funding_tx`` are supplied, the counter HTLC's on-chain FUNDING
    output value is asserted to equal the agreed amount (VALUE integrity, review MEDIUM): an atomic-but-
    MISPRICED swap (counter leg funded at the wrong amount) is ANOMALOUS, not a silent PASS. Mirrors the
    asset leg's funding-value check."""
    notes: list[str] = []
    if counter_spend_tx is None:
        return CounterLeg.PENDING, None, ["counter (BTC HTLC) outpoint still unspent"]
    prevouts = btc_input_outpoints_from_raw(counter_spend_tx)
    assert m.counter_funding is not None  # guaranteed by manifest validation for btc
    if m.counter_funding.prevout_le_bytes() not in prevouts:
        return (
            CounterLeg.ANOMALOUS,
            None,
            ["the cited counter-spend does NOT spend our BTC HTLC funding outpoint (wrong/forged tx)"],
        )
    notes.append("counter spend consumes our HTLC funding outpoint")
    if m.counter_amount is not None and counter_funding_tx is not None:
        # BTC funding tx is segwit — parse with the BTC-aware reader (btc_spend_fields_from_raw returns
        # (value, spk) per output, handling marker/flag), NOT the RXD Transaction parser.
        outs = btc_spend_fields_from_raw(counter_funding_tx).outputs
        if m.counter_funding.vout >= len(outs):
            return CounterLeg.ANOMALOUS, None, [*notes, "counter funding vout out of range (forged funding tx)"]
        funded_value = outs[m.counter_funding.vout][0]
        if funded_value != m.counter_amount:
            return (
                CounterLeg.ANOMALOUS,
                None,
                [
                    *notes,
                    f"counter HTLC funded with {funded_value} sats, agreed {m.counter_amount} "
                    "(value mismatch — counter leg under/over-funded / mispriced)",
                ],
            )
        notes.append(f"counter HTLC funded with the agreed {m.counter_amount} sats")
    if m.btc_claim_xonly_hex is not None and counter_funding_tx is not None:
        # RECIPIENT binding (review HIGH): re-derive the counter HTLC funding SPK from the agreed
        # maker-claim + taker-refund x-only keys + H + t_btc, and assert the funding output pays exactly
        # it. This binds the claim LEAF to the MAKER's key — so a claim revealing p is necessarily
        # maker-authorized (pays the maker), closing the "malformed HTLC whose claim pays the taker"
        # false-PASS. Symmetry with the asset leg's covenant SPK re-derivation.
        outs = btc_spend_fields_from_raw(counter_funding_tx).outputs
        if m.counter_funding.vout >= len(outs):
            return CounterLeg.ANOMALOUS, None, [*notes, "counter funding vout out of range (forged funding tx)"]
        expected_spk = build_htlc(
            hashlock=bytes.fromhex(m.h_hex),
            claim_pubkey_xonly=bytes.fromhex(m.btc_claim_xonly_hex),
            refund_pubkey_xonly=bytes.fromhex(m.btc_refund_xonly_hex),
            timeout=Timelock(int(m.t_btc_blocks), TimeUnit.BLOCKS),
        ).scriptpubkey
        if outs[m.counter_funding.vout][1] != bytes(expected_spk):
            return (
                CounterLeg.ANOMALOUS,
                None,
                [
                    *notes,
                    "counter funding output does NOT pay the HTLC re-derived from the agreed maker-claim/"
                    "taker-refund keys + H + t_btc (malformed/hostile counter HTLC — its claim may pay the taker)",
                ],
            )
        notes.append("counter funding output == HTLC re-derived from the agreed keys (claim is maker-authorized)")
    try:
        p = scrape_secret(counter_spend_tx, bytes.fromhex(m.h_hex))
        if _sha256(p) == bytes.fromhex(m.h_hex):
            # Return the DIGEST-level fact only: at this point sha256(p) == the manifest H,
            # so H itself is the digest. Raw preimage bytes never leave the leg verifiers
            # (CodeQL py/clear-text-logging-sensitive-data on PR #273 — the taint path is
            # broken at the source side, not just filtered at the sink).
            return (
                CounterLeg.MAKER_CLAIMED,
                bytes.fromhex(m.h_hex),
                [*notes, "counter claim reveals p with sha256(p)==H -> maker claimed"],
            )
    except Exception:
        pass
    # No valid p in the witness + it spends our outpoint => the CSV refund leaf (back to the taker).
    return CounterLeg.TAKER_REFUNDED, None, [*notes, "no p revealed -> CSV refund leaf -> taker refunded"]


# EthHtlc event topic0 (keccak of the event signature) — from tests/fixtures/EthHtlc.json.
_ETH_CLAIMED_TOPIC = "0xb651fac6b68e9074a2da0835d9a5cb12e8cc45ff91d6e79e31a9627866507cc7"
_ETH_REFUNDED_TOPIC = "0xa4891be4c05fc4b104f07fbbd9f643c3a98d0f9d3c4e616281bdba972991a558"


def _hb(x: object) -> bytes:
    """Normalize a web3 value (HexBytes / '0x..' str / bytes / None) to bytes."""
    if x is None:
        return b""
    if isinstance(x, (bytes, bytearray)):
        return bytes(x)
    if hasattr(x, "hex") and not isinstance(x, str):  # HexBytes
        return bytes(x)
    s = str(x)
    return bytes.fromhex(s[2:] if s.startswith(("0x", "0X")) else s)


def _as_int(x: object) -> int:
    if isinstance(x, int):
        return x
    s = str(x)
    return int(s, 16) if s.startswith(("0x", "0X")) else int(s)


def verify_counter_leg_eth(
    m: RunManifest,
    claim_tx: dict | None,
    claim_receipt: dict | None,
    funding: tuple[dict, dict | None] | None = None,
) -> tuple[CounterLeg, bytes | None, list[str]]:
    """Re-derive the ETH counter-leg disposition from an independently-fetched tx + receipt.

    Mirrors swap_coordinator.assert_claim_provenance (R6): the spend must (a) have SUCCEEDED (status==1 —
    a reverted-but-mined claim leaks p but moved no ETH), and (b) emit a Claimed/Refunded event FROM OUR
    contract instance. A claim's p is recovered from calldata + our-contract log data (recover_secret) and
    must appear in an our-contract log blob (topics||data). p scraped from a DIFFERENT contract is rejected.

    When ``m.counter_amount`` + ``funding`` (the deploy tx + receipt) are supplied, the ETH HTLC's funded
    VALUE is checked (review MEDIUM): the EthHtlc payable constructor funds the contract with the deploy
    tx's ``value``, and the deploy receipt's ``contractAddress`` binds that deploy to OUR contract — so
    ``deploy.value == counter_amount`` proves the counter leg was funded at the agreed wei. A mispriced
    (under/over-funded) counter leg is ANOMALOUS, not a silent PASS. Symmetric with the BTC leg's check."""
    from pyrxd.eth_wallet.secret import recover_secret  # lazy: keep the btc path web3/eth-free

    notes: list[str] = []
    if claim_tx is None or claim_receipt is None:
        return CounterLeg.PENDING, None, ["counter (ETH HTLC) has no cited claim/refund tx (unspent)"]
    assert m.eth_contract is not None  # guaranteed by manifest validation for eth
    contract = m.eth_contract.lower()
    if m.counter_amount is not None and funding is not None:
        f_tx, f_rcpt = funding
        created = str((f_rcpt or {}).get("contractAddress", "") or "").lower()
        if created != contract:
            return (
                CounterLeg.ANOMALOUS,
                None,
                [
                    "cited eth_funding_tx did NOT create our HTLC contract (contractAddress mismatch — wrong/forged funding tx)"
                ],
            )
        funded_wei = _as_int(f_tx.get("value", 0))
        if funded_wei != m.counter_amount:
            return (
                CounterLeg.ANOMALOUS,
                None,
                [
                    f"ETH HTLC funded with {funded_wei} wei, agreed {m.counter_amount} "
                    "(value mismatch — counter leg under/over-funded / mispriced)"
                ],
            )
        notes.append(f"ETH HTLC deploy funded the agreed {m.counter_amount} wei to our contract")
    if m.eth_maker_claimant is not None and funding is not None:
        # RECIPIENT binding (review HIGH): decode the deploy tx's constructor args — last 128 bytes are
        # (hashlock, claimant, refundee, timeout) per `constructor(bytes32,address,address,uint256)` — and
        # assert claimant == the agreed maker payout AND hashlock == H. So a Claimed(p) event means the
        # contract paid THE MAKER (not the taker). Reuses the already-fetched deploy tx (no extra RPC) and
        # does not depend on the contract surviving post-claim.
        f_tx, f_rcpt = funding
        created = str((f_rcpt or {}).get("contractAddress", "") or "").lower()
        if created != contract:
            return (
                CounterLeg.ANOMALOUS,
                None,
                [*notes, "eth_funding_tx did not create our HTLC contract (recipient binding)"],
            )
        deploy_input = _hb(f_tx.get("input"))
        if len(deploy_input) < 128:
            return (
                CounterLeg.ANOMALOUS,
                None,
                [*notes, "eth deploy tx input too short for constructor args (forged funding tx)"],
            )
        args = deploy_input[-128:]
        ctor_hashlock = args[0:32]
        ctor_claimant = "0x" + args[44:64].hex()  # 2nd 32-byte word, low 20 bytes = the claimant address
        if ctor_hashlock != bytes.fromhex(m.h_hex):
            return (
                CounterLeg.ANOMALOUS,
                None,
                [*notes, "eth HTLC constructor hashlock != manifest H (wrong/forged deploy)"],
            )
        if ctor_claimant.lower() != m.eth_maker_claimant.lower():
            return (
                CounterLeg.ANOMALOUS,
                None,
                [
                    *notes,
                    f"eth HTLC claimant {ctor_claimant} != agreed maker {m.eth_maker_claimant} "
                    "(a Claimed(p) would NOT pay the maker — malformed/hostile counter HTLC)",
                ],
            )
        notes.append("eth HTLC constructor binds claimant==maker + hashlock==H (claim pays the maker)")
    if _as_int(claim_receipt.get("status", 0)) != 1:
        return CounterLeg.ANOMALOUS, None, ["counter spend tx REVERTED (status != 1) — moved no ETH"]
    our_logs = [lg for lg in (claim_receipt.get("logs") or []) if str(lg.get("address", "")).lower() == contract]
    if not our_logs:
        return CounterLeg.ANOMALOUS, None, ["no logs from our HTLC contract — wrong/forged tx (cross-swap replay)"]
    topic0s = {(_hb(lg["topics"][0]).hex() if lg.get("topics") else "") for lg in our_logs}
    H = bytes.fromhex(m.h_hex)
    claimed_topic = _ETH_CLAIMED_TOPIC[2:]
    refunded_topic = _ETH_REFUNDED_TOPIC[2:]
    if claimed_topic in topic0s:
        # recover p from calldata + our-contract log data, then bind it to an our-contract log (provenance).
        artifacts = [_hb(claim_tx.get("input"))] + [_hb(lg.get("data")) for lg in our_logs]
        try:
            p = recover_secret(artifacts, H)
        except Exception:
            return CounterLeg.ANOMALOUS, None, [*notes, "Claimed event present but no p recovered with sha256(p)==H"]
        for lg in our_logs:
            blob = b"".join(_hb(t) for t in (lg.get("topics") or [])) + _hb(lg.get("data"))
            if p in blob:
                # Digest-level fact only (sha256(p) == H was enforced by recover_secret);
                # raw p stays local to this verifier — see the BTC leg note.
                return (
                    CounterLeg.MAKER_CLAIMED,
                    H,
                    [*notes, "our HTLC emitted Claimed(p) with sha256(p)==H -> maker claimed"],
                )
        return CounterLeg.ANOMALOUS, None, [*notes, "p not bound to an our-contract log (provenance fail)"]
    if refunded_topic in topic0s:
        return CounterLeg.TAKER_REFUNDED, None, [*notes, "our HTLC emitted Refunded() -> taker refunded"]
    return CounterLeg.ANOMALOUS, None, [*notes, "our contract emitted neither Claimed nor Refunded"]


def atomicity_verdict(
    m: RunManifest,
    asset: AssetLeg,
    counter: CounterLeg,
    asset_p_sha256: bytes | None,
    counter_p_sha256: bytes | None,
) -> VerifyResult:
    """The global truth table. PASS iff both-complete XOR both-unwind; any mixed corner is a one-sided loss."""
    res = VerifyResult(verdict=Verdict.PENDING, asset_leg=asset, counter_leg=counter)

    if asset is AssetLeg.ANOMALOUS or counter is CounterLeg.ANOMALOUS:
        res.verdict = Verdict.ANOMALOUS
        res.reasons.append("a leg landed in an impossible/forged state")
        return res
    if asset is AssetLeg.PENDING or counter is CounterLeg.PENDING:
        res.verdict = Verdict.PENDING
        res.reasons.append("a leg is still unspent — not scorable yet (never a PASS)")
        return res

    both_complete = asset is AssetLeg.TAKER_CLAIMED and counter is CounterLeg.MAKER_CLAIMED
    both_unwind = asset is AssetLeg.MAKER_REFUNDED and counter is CounterLeg.TAKER_REFUNDED

    if both_complete:
        # p-link at DIGEST level: the SAME secret links the two claims (atomicity in
        # action). Each leg verifier only reports CLAIMED after proving sha256(p) == the
        # manifest H, so equal digests <=> equal preimages (collision resistance); raw p
        # never reaches this function.
        if asset_p_sha256 is not None and counter_p_sha256 is not None and asset_p_sha256 != counter_p_sha256:
            res.verdict = Verdict.ANOMALOUS
            res.reasons.append("both legs claimed but with DIFFERENT preimages — broken H-linkage")
            return res
        res.verdict = Verdict.PASS
        res.reasons.append("both legs completed (maker claimed counter, taker claimed asset) with a shared p")
        return res
    if both_unwind:
        res.verdict = Verdict.PASS
        res.reasons.append("both legs unwound (taker refunded counter, maker refunded asset) — no one-sided loss")
        return res

    # Any other (asset, counter) pair is a one-sided outcome.
    res.verdict = Verdict.FAIL_ONE_SIDED
    loser = _identify_loser(asset, counter)
    res.reasons.append(f"ONE-SIDED outcome: asset={asset.value}, counter={counter.value} -> {loser}")
    return res


def _identify_loser(asset: AssetLeg, counter: CounterLeg) -> str:
    # maker holds both: claimed the counter AND got the asset refunded -> taker paid the counter, got nothing.
    if counter is CounterLeg.MAKER_CLAIMED and asset is AssetLeg.MAKER_REFUNDED:
        return "MAKER holds BOTH legs; the TAKER is out the counter leg (the free-option attack succeeded)"
    # taker holds both: claimed the asset AND refunded its counter -> maker locked the asset, got nothing.
    if asset is AssetLeg.TAKER_CLAIMED and counter is CounterLeg.TAKER_REFUNDED:
        return "TAKER holds BOTH legs; the MAKER is out the asset"
    return "mixed/indeterminate one-sided outcome"


def margin_grade(
    m: RunManifest, asset: AssetLeg, counter: CounterLeg, asset_claim_height: int | None
) -> tuple[str, int | None, str]:
    """Lucky-pass detector (runbook §4, detector B). A PASS is not "clean" if the honest taker's asset claim
    only just beat the maker's CSV refund window — a few blocks of variance the other way would have flipped
    it to a one-sided loss. Grades the both-complete case: realized slack = (asset_locked_at + t_rxd) -
    asset_claim_confirm_height, against the declared minimum. Returns (grade, slack, note); grade in
    {CLEAN, MARGINAL, UNKNOWN, N/A}. MARGINAL does not flip PASS->FAIL but flags "re-run with tighter timing"."""
    if not (asset is AssetLeg.TAKER_CLAIMED and counter is CounterLeg.MAKER_CLAIMED):
        return "N/A", None, "margin grading applies to the both-complete (happy) case only"
    if m.asset_locked_at_height is None or asset_claim_height is None:
        return "UNKNOWN", None, "missing asset_locked_at_height or asset-claim confirm height to grade margin"
    rxd_refund_open = m.asset_locked_at_height + m.refund_csv
    slack = rxd_refund_open - asset_claim_height
    if slack < m.min_margin_blocks:
        return (
            "MARGINAL",
            slack,
            (
                f"taker asset claim confirmed only {slack} block(s) before the maker CSV refund opened "
                f"(< declared min {m.min_margin_blocks}) — a clean PASS needs more slack; re-run with tighter adversary timing"
            ),
        )
    return "CLEAN", slack, f"taker asset claim had {slack} block(s) of slack before the maker CSV refund window"


# --------------------------------------------------------------------------- chain re-fetch (independent)


class _BtcFetcher:
    """Re-fetch BTC raw txs from an Esplora the parties did NOT run."""

    def __init__(self, esplora_url: str, *, min_confirmations: int = 1):
        from pyrxd.network.bitcoin import MempoolSpaceSource  # lazy: only needed for a live run

        self._base = esplora_url.rstrip("/")
        self._src = MempoolSpaceSource(base_url=esplora_url)
        self._min_conf = min_confirmations

    async def raw_tx(self, txid: str) -> bytes:
        return bytes(await self._src.get_raw_tx(txid, min_confirmations=self._min_conf))

    async def spend_of(self, op: Outpoint) -> str | None:
        """Independent outpoint->spender discovery (review MEDIUM): so a party CANNOT park a leg at
        PENDING by omitting its spend txid. Esplora ``/tx/{txid}/outspend/{vout}`` returns the spending
        txid; None if the outpoint is still unspent (genuinely PENDING) or the source can't say (fails
        soft to None — a missed discovery degrades to the same PENDING as today, never a false PASS)."""
        import aiohttp

        url = f"{self._base}/tx/{op.txid}/outspend/{op.vout}"
        try:
            async with aiohttp.ClientSession() as s, s.get(url) as r:
                if r.status != 200:
                    return None
                data = await r.json(content_type=None)
            if isinstance(data, dict) and data.get("spent") and isinstance(data.get("txid"), str):
                return str(data["txid"]).lower()
        except Exception:
            return None
        return None

    async def close(self) -> None:
        await self._src.close()


class _RxdFetcher:
    """Re-fetch RXD raw txs from an ElectrumX the parties did NOT run."""

    def __init__(self, electrumx_url: str):
        from pyrxd.network.electrumx import ElectrumXClient  # lazy

        self._url = electrumx_url
        self._client = ElectrumXClient(electrumx_url)

    async def raw_tx(self, txid: str) -> bytes:
        async with self._client as c:
            raw = bytes(await c.get_transaction(txid))
        # Pin the returned bytes to the requested txid (txid == hash(tx) for RXD). Without this a hostile
        # or MITM'd ElectrumX could substitute arbitrary bytes and steer the asset-leg verdict — the sibling
        # BTC/resolve fetchers already do this; the RXD path was the lone outlier.
        parsed = Transaction.from_hex(raw)
        if parsed is None or parsed.txid() != str(txid):
            raise ValueError(f"RXD endpoint returned bytes whose hash != requested txid ({txid})")
        return raw

    async def confirm_height(self, txid: str) -> int | None:
        """The block height a tx confirmed at (tip - confirmations + 1), or None if unconfirmed/unknown."""
        async with self._client as c:
            verbose = await c.get_transaction_verbose(txid)
            confs = int(verbose.get("confirmations", 0) or 0)
            if confs <= 0:
                return None
            tip = int(await c.get_tip_height())
            return tip - confs + 1

    async def confirmations(self, txid: str) -> int:
        """The confirmation depth of `txid` (0 if unconfirmed/unknown) — the reorg-depth oracle."""
        async with self._client as c:
            verbose = await c.get_transaction_verbose(txid)
            confs = int(verbose.get("confirmations", 0) or 0)
            return confs if confs > 0 else 0

    async def spend_of(self, op: Outpoint, spk: bytes) -> str | None:
        """Independent outpoint->spender discovery (review MEDIUM): find the tx that consumed `op` by
        walking the covenant SPK's scripthash history and checking each candidate's inputs — so a party
        CANNOT park the asset leg at PENDING by omitting its spend txid. Fail-soft to None (a missed
        discovery degrades to the same PENDING as today, never a false PASS)."""
        try:
            scripthash = hashlib.sha256(bytes(spk)).digest()[::-1]
            target = op.prevout_le_bytes()
            async with self._client as c:
                hist = await c.get_history(scripthash)
                for entry in hist:
                    cand = str(entry.get("tx_hash") or "")
                    if not cand or cand == op.txid:  # skip the funding tx itself
                        continue
                    try:
                        raw = bytes(await c.get_transaction(cand))
                        if target in _rxd_input_prevouts(raw):
                            return cand.lower()
                    except Exception:  # noqa: S112 — a malformed/unfetchable candidate must not abort the scan
                        continue
        except Exception:
            return None
        return None

    async def close(self) -> None:
        pass


class _EthFetcher:
    """Re-fetch an ETH tx + receipt from an RPC the parties did NOT run."""

    def __init__(self, rpc_url: str, chain_id: int):
        from pyrxd.eth_wallet.rpc import EthRpc  # lazy

        self._rpc = EthRpc(rpc_url, expected_chain_id=chain_id)

    async def tx_and_receipt(self, tx_hash: str) -> tuple[dict, dict | None]:
        tx = await self._rpc.get_transaction(tx_hash)
        rcpt = await self._rpc.get_transaction_receipt(tx_hash)
        return dict(tx), (dict(rcpt) if rcpt is not None else None)

    async def finalized_height(self) -> int | None:
        """The post-Merge ``finalized`` checkpoint block number (the ETH reorg-safety oracle), or None
        if the endpoint can't report it (fail closed at the caller)."""
        try:
            return int(await self._rpc.finalized_block_number())
        except Exception:
            return None

    async def spend_of(self, contract: str) -> str | None:
        """Independent discovery of an OMITTED ETH claim/refund (review — the ETH analog of BTC/RXD spend
        discovery): ``eth_getLogs`` for OUR per-swap contract's ``Claimed``/``Refunded`` events. Returns
        the spending tx hash; None if no such event (genuinely PENDING) or the source can't say
        (fail-soft — a missed discovery degrades to PENDING, never a false PASS)."""
        try:
            logs = await self._rpc.get_logs(address=contract, topics=[[_ETH_CLAIMED_TOPIC, _ETH_REFUNDED_TOPIC]])
            for lg in logs:
                th = lg.get("transactionHash")
                if th is not None:
                    b = _hb(th)  # HexBytes / '0x..' / bytes -> bytes
                    if len(b) == 32:
                        return "0x" + b.hex()
        except Exception:
            return None
        return None

    async def close(self) -> None:
        await self._rpc.close()


async def _fetch_for_live(
    m: RunManifest, cited: dict, btc_url: str, rxd_url: str, eth_url: str | None, *, min_confirmations: int = 1
):
    """Fetch (covenant_funding_tx, covenant_spend_tx|None, counter_obj, counter_funding_tx|None) from
    INDEPENDENT sources.

    `cited` carries the only journal-trusted data: the spend tx ids — but when a spend txid is OMITTED,
    the verifier DISCOVERS the spender independently (outpoint->spender scan), so a party CANNOT park a
    leg at PENDING by withholding it (review MEDIUM). A cited/discovered spend must be buried
    >= `min_confirmations` deep on the independent source; set it deep for real-value runs — a shallow,
    source-TRUSTED disposition is reorgable, and a scored PASS on a 1-conf claim that later reorgs is a
    real one-sided loss (review MEDIUM). counter_obj is raw bytes (btc) or (tx,receipt) (eth)."""
    funded_spk, _tk, _mk = rxd_expected_scripts(m)
    rxd = _RxdFetcher(rxd_url)
    asset_claim_height = None
    try:
        cov_fund = await rxd.raw_tx(m.covenant_funding.txid)
        spend_txid = cited.get("covenant_spend_txid")
        if not spend_txid:
            spend_txid = await rxd.spend_of(m.covenant_funding, funded_spk)  # DISCOVER an omitted spend
            if spend_txid:
                print(f"  discovered covenant spend {spend_txid} independently (was not cited)", file=sys.stderr)
        cov_spend = await rxd.raw_tx(spend_txid) if spend_txid else None
        if spend_txid:
            # Depth gate: a cited/discovered spend must be buried >= min_confirmations. Below that it is
            # unconfirmed (junk scriptSig — never consensus-validated) OR shallow (reorgable); either way
            # scoring it as a settled disposition is a false-PASS window.
            confs = await rxd.confirmations(spend_txid)
            if confs < min_confirmations:
                raise ValueError(
                    f"covenant-spend {spend_txid} has {confs} confirmations (< required {min_confirmations}) "
                    "on the independent RXD source — refusing to score a shallow/unconfirmed (reorgable) "
                    "disposition"
                )
            asset_claim_height = await rxd.confirm_height(spend_txid)
    finally:
        await rxd.close()

    counter_obj = None
    counter_funding = None  # btc: raw funding tx bytes; eth: (deploy_tx, deploy_receipt) — for the VALUE check
    spend_id = cited.get("counter_spend_txid")
    if m.counter_chain == "btc":
        btc = _BtcFetcher(btc_url, min_confirmations=min_confirmations)
        try:
            if m.counter_funding is not None:
                counter_funding = await btc.raw_tx(m.counter_funding.txid)  # for the counter VALUE check
            if not spend_id and m.counter_funding is not None:
                spend_id = await btc.spend_of(m.counter_funding)  # DISCOVER an omitted counter spend
                if spend_id:
                    print(f"  discovered counter spend {spend_id} independently (was not cited)", file=sys.stderr)
            counter_obj = await btc.raw_tx(spend_id) if spend_id else None
        finally:
            await btc.close()
    else:  # eth
        eth = _EthFetcher(eth_url, m.eth_chain_id)  # type: ignore[arg-type]
        try:
            if not spend_id and m.eth_contract is not None:
                spend_id = await eth.spend_of(m.eth_contract)  # DISCOVER an omitted ETH claim/refund
                if spend_id:
                    print(f"  discovered counter (ETH) spend {spend_id} independently (was not cited)", file=sys.stderr)
            if spend_id:
                counter_obj = await eth.tx_and_receipt(spend_id)
                # FINALITY gate (review): the ETH claim/refund must be at/under the `finalized` checkpoint
                # — a mined-but-non-final (reorgable) disposition must NOT be scored as settled. This is
                # the ETH analog of the BTC/RXD confirmation-depth gate (ETH reorg-safety is checkpoint-
                # based, not depth-based), matching swap_coordinator's finalized-checkpoint verdict.
                _tx, rcpt = counter_obj
                claim_block = _as_int((rcpt or {}).get("blockNumber", 0)) if rcpt else 0
                finalized = await eth.finalized_height()
                if finalized is None or claim_block <= 0 or claim_block > finalized:
                    raise ValueError(
                        f"cited/discovered ETH counter-spend {spend_id} is NOT finalized (block {claim_block}, "
                        f"finalized {finalized}) on the independent source — refusing to score a reorgable disposition"
                    )
            if m.eth_funding_tx:
                counter_funding = await eth.tx_and_receipt(m.eth_funding_tx)  # deploy tx: value == funded wei
        finally:
            await eth.close()
    return cov_fund, cov_spend, counter_obj, counter_funding, asset_claim_height


def run_verify(
    m: RunManifest,
    covenant_funding_tx: bytes,
    covenant_spend_tx: bytes | None,
    counter_obj,
    *,
    asset_claim_height: int | None = None,
    counter_funding=None,
) -> VerifyResult:
    """The pure verification core — given re-fetched data, produce the verdict. counter_obj is raw bytes
    (btc) or a (tx_dict, receipt_dict) tuple (eth) or None. Network-free; the offline self-check uses it.
    `asset_claim_height` (the RXD covenant-spend confirm height) drives the lucky-pass margin grade.
    `counter_funding` enables the counter-leg VALUE check when m.counter_amount is set — raw funding-tx
    bytes (btc) or the deploy (tx, receipt) tuple (eth)."""
    asset, asset_notes = verify_asset_leg(m, covenant_funding_tx, covenant_spend_tx)
    if m.counter_chain == "btc":
        counter, counter_p_sha256, counter_notes = verify_counter_leg_btc(m, counter_obj, counter_funding)
    else:
        tx, rcpt = counter_obj if counter_obj else (None, None)
        counter, counter_p_sha256, counter_notes = verify_counter_leg_eth(m, tx, rcpt, funding=counter_funding)
    # Leg verifiers return sha256(p) (== manifest H, proven in-leg), never raw p. The asset-side digest is
    # INTENTIONALLY None: both legs are already bound to the single manifest H (the covenant SPK is rebuilt
    # from H, and the counter claim is checked sha256(p)==H), so equal-H both-complete ⟺ same preimage by
    # collision resistance — the asset_p_sha256 arg is a redundant belt-and-suspenders slot. Do NOT wire a
    # raw scraped preimage back in here (it re-introduces the CodeQL clear-text-secret taint of PR #273).
    res = atomicity_verdict(m, asset, counter, None, counter_p_sha256)
    grade, slack, margin_note = margin_grade(m, asset, counter, asset_claim_height)
    # Counter-leg VALUE + RECIPIENT checks are OPT-IN (they need extra manifest fields). The asset leg's
    # value is always re-derived, so an omitted counter check is an ASYMMETRY the operator must see — a
    # silent PASS would be read as "value/recipient verified" when it was not (review MEDIUM/HIGH). Derive
    # what was actually verifiable and surface it loudly; a PASS that skipped either is flagged in reasons.
    if m.counter_chain == "btc":
        value_verified = m.counter_amount is not None
        recipient_verified = m.btc_claim_xonly_hex is not None
    else:  # eth — both need the deploy tx (eth_funding_tx)
        value_verified = m.counter_amount is not None and m.eth_funding_tx is not None
        recipient_verified = m.eth_maker_claimant is not None and m.eth_funding_tx is not None
    res.checks = {
        "counter_chain": m.counter_chain,
        "asset_leg_notes": asset_notes,
        "counter_leg_notes": counter_notes,
        "honest_party": m.honest_party,
        "counter_value_verified": value_verified,
        "counter_recipient_verified": recipient_verified,
        "margin": {"grade": grade, "slack_blocks": slack, "note": margin_note},
    }
    if res.verdict is Verdict.PASS:
        if grade == "MARGINAL":
            res.reasons.append(f"PASS but MARGINAL: {margin_note}")
        if not value_verified:
            _need = "counter_amount + eth_funding_tx" if m.counter_chain == "eth" else "counter_amount"
            res.reasons.append(
                f"WARNING: counter-leg VALUE was NOT verified (manifest omitted {_need}) — this PASS does "
                "NOT attest the counter leg was funded at the agreed amount (an atomic-but-mispriced swap)"
            )
        if not recipient_verified:
            _need = (
                "btc_claim_xonly_hex + btc_refund_xonly_hex + t_btc_blocks"
                if m.counter_chain == "btc"
                else "eth_maker_claimant + eth_funding_tx"
            )
            res.reasons.append(
                f"WARNING: counter-leg RECIPIENT was NOT verified (manifest omitted {_need}) — this PASS "
                "does NOT attest the counter claim PAYS THE MAKER (a malformed counter HTLC could pay the taker)"
            )
    return res


# --------------------------------------------------------------------------- offline self-check


def _self_check() -> int:
    """Network-free tests of the engine, the secret guard, manifest validation, and RXD disposition.
    Returns process exit code (0 = all green)."""
    from pyrxd.script.script import Script
    from pyrxd.transaction.transaction import Transaction as _Tx
    from pyrxd.transaction.transaction_input import TransactionInput
    from pyrxd.transaction.transaction_output import TransactionOutput

    failures: list[str] = []

    def check(name: str, cond: bool) -> None:
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}")
        if not cond:
            failures.append(name)

    # 1) atomicity truth table — exhaustive over the meaningful combinations.
    m = RunManifest(
        swap_id="sc",
        asset_variant="rxd",
        counter_chain="btc",
        honest_party="taker",
        h_hex="11" * 32,
        taker_pkh_hex="22" * 20,
        maker_pkh_hex="33" * 20,
        rxd_amount=1000,
        refund_csv=48,
        covenant_funding=Outpoint("ab" * 32, 0),
        counter_funding=Outpoint("cd" * 32, 0),
    )
    table = {
        (AssetLeg.TAKER_CLAIMED, CounterLeg.MAKER_CLAIMED): Verdict.PASS,
        (AssetLeg.MAKER_REFUNDED, CounterLeg.TAKER_REFUNDED): Verdict.PASS,
        (AssetLeg.MAKER_REFUNDED, CounterLeg.MAKER_CLAIMED): Verdict.FAIL_ONE_SIDED,  # taker robbed (free option)
        (AssetLeg.TAKER_CLAIMED, CounterLeg.TAKER_REFUNDED): Verdict.FAIL_ONE_SIDED,  # maker robbed
        (AssetLeg.PENDING, CounterLeg.MAKER_CLAIMED): Verdict.PENDING,
        (AssetLeg.TAKER_CLAIMED, CounterLeg.PENDING): Verdict.PENDING,
        (AssetLeg.ANOMALOUS, CounterLeg.MAKER_CLAIMED): Verdict.ANOMALOUS,
    }
    for (a, c), want in table.items():
        got = atomicity_verdict(m, a, c, None, None).verdict
        check(f"truth-table {a.name}+{c.name} -> {want.value}", got is want)

    # p-link: both claimed but different preimages -> ANOMALOUS.
    mismatch = atomicity_verdict(m, AssetLeg.TAKER_CLAIMED, CounterLeg.MAKER_CLAIMED, b"\x01" * 32, b"\x02" * 32)
    check("p-link mismatch -> ANOMALOUS", mismatch.verdict is Verdict.ANOMALOUS)

    # 2) secret guard.
    try:
        assert_no_secrets({"steps": [{"txid": "ab", "taker_rxd_wif": "L1..."}]}, what="journal")
        check("secret guard catches a leaked WIF", False)
    except ValueError:
        check("secret guard catches a leaked WIF", True)
    try:
        assert_no_secrets({"steps": [{"txid": "ab", "state": "COMPLETED"}]}, what="journal")
        check("secret guard passes a clean journal", True)
    except ValueError:
        check("secret guard passes a clean journal", False)

    # 3) independence guard.
    try:
        assert_independent_endpoints(["https://mempool.space/api"], ("https://mempool.space/api",))
        check("independence guard rejects a shared endpoint", False)
    except ValueError:
        check("independence guard rejects a shared endpoint", True)

    # 4) RXD asset-leg disposition against a synthetic covenant funding + claim tx.
    funded_spk, taker_holder, maker_holder = rxd_expected_scripts(m)

    # All self-check manifests lock the asset at this covenant outpoint; a genuine claim/refund CONSUMES it
    # (provenance). `spend_covenant=False` builds a "decoy" that pays a holder address without spending the
    # covenant — the exact free-option forgery the provenance gate now rejects.
    def _rxd_tx(out_spk: bytes, value: int = 1000, *, spend_covenant: bool = True) -> bytes:
        src_txid = "ab" * 32 if spend_covenant else "00" * 32
        tx = _Tx()
        tx.add_input(TransactionInput(source_txid=src_txid, source_output_index=0, unlocking_script=Script(b"")))
        tx.add_output(TransactionOutput(locking_script=Script(out_spk), satoshis=value))
        return tx.serialize()

    funding = _rxd_tx(funded_spk)
    claim = _rxd_tx(taker_holder)
    refund = _rxd_tx(maker_holder)
    wrong = _rxd_tx(b"\x6a")  # OP_RETURN — neither holder

    a1, _ = verify_asset_leg(m, funding, claim)
    check("RXD funding+claim -> TAKER_CLAIMED", a1 is AssetLeg.TAKER_CLAIMED)
    a2, _ = verify_asset_leg(m, funding, refund)
    check("RXD funding+refund -> MAKER_REFUNDED", a2 is AssetLeg.MAKER_REFUNDED)
    a3, _ = verify_asset_leg(m, funding, None)
    check("RXD unspent covenant -> PENDING", a3 is AssetLeg.PENDING)
    a4, _ = verify_asset_leg(m, funding, wrong)
    check("RXD spent to neither holder -> ANOMALOUS", a4 is AssetLeg.ANOMALOUS)
    a5, _ = verify_asset_leg(m, _rxd_tx(b"\x00\x14" + b"\xff" * 20), claim)  # funding to a wrong SPK
    check("RXD wrong funding SPK -> ANOMALOUS", a5 is AssetLeg.ANOMALOUS)
    # PROVENANCE regression (the free-option false-PASS): a decoy paying the taker holder that does NOT
    # spend the covenant must be ANOMALOUS, not TAKER_CLAIMED.
    a_decoy, _ = verify_asset_leg(m, funding, _rxd_tx(taker_holder, spend_covenant=False))
    check("RXD decoy (pays taker, doesn't spend covenant) -> ANOMALOUS", a_decoy is AssetLeg.ANOMALOUS)
    # value integrity is verdict-affecting: under-funded covenant + short-changed payout each ANOMALOUS.
    a6, _ = verify_asset_leg(m, _rxd_tx(funded_spk, value=500), claim)
    check("RXD under-funded covenant -> ANOMALOUS", a6 is AssetLeg.ANOMALOUS)
    a7, _ = verify_asset_leg(m, _rxd_tx(funded_spk, 1000), _rxd_tx(taker_holder, 900))
    check("RXD short-changed payout -> ANOMALOUS", a7 is AssetLeg.ANOMALOUS)

    # 5) full happy-path through verify_from_bytes — manifest H must equal sha256(stub p) so the BTC claim
    #    actually reveals a matching preimage (counter -> MAKER_CLAIMED) and the asset goes to the taker.
    p_stub = b"\xab" * 32
    m2 = RunManifest(
        swap_id="sc2",
        asset_variant="rxd",
        counter_chain="btc",
        honest_party="taker",
        h_hex=_sha256(p_stub).hex(),
        taker_pkh_hex="22" * 20,
        maker_pkh_hex="33" * 20,
        rxd_amount=1000,
        refund_csv=48,
        covenant_funding=Outpoint("ab" * 32, 0),
        counter_funding=Outpoint("cd" * 32, 0),
    )
    f2_spk, t2_holder, _m2_holder = rxd_expected_scripts(m2)
    funding2 = _rxd_tx(f2_spk)
    claim2 = _rxd_tx(t2_holder)
    btc_claim = _btc_claim_stub(m2, p_stub)
    # sanity: scrape must recover p_stub from the stub before we assert the verdict.
    check(
        "BTC stub: scrape recovers p (sha256(p)==H)",
        _sha256(scrape_secret(btc_claim, _sha256(p_stub))) == _sha256(p_stub),
    )
    res = run_verify(m2, funding2, claim2, btc_claim)
    check("end-to-end BTC happy path -> PASS", res.verdict is Verdict.PASS)
    # and a one-sided failure: maker claimed counter (reveals p) but asset got refunded to maker.
    refund2 = _rxd_tx(_m2_holder)
    res_fail = run_verify(m2, funding2, refund2, btc_claim)
    check("end-to-end BTC free-option -> FAIL_ONE_SIDED", res_fail.verdict is Verdict.FAIL_ONE_SIDED)

    # 5b) counter-leg VALUE integrity (review MEDIUM): the counter HTLC funding output must carry the
    # agreed counter_amount — an atomic-but-MISPRICED swap is ANOMALOUS, not a silent PASS. Build a
    # minimal legacy BTC funding tx with a 100_000-sat output at vout 0 (segwit-aware parse in the leg).
    import struct as _struct

    cf_tx = (
        _struct.pack("<i", 1)  # version
        + b"\x01"
        + b"\x00" * 32
        + b"\x00\x00\x00\x00"  # 1 input (prevout)
        + b"\x00"
        + b"\xff\xff\xff\xff"  # empty scriptSig, seq
        + b"\x01"
        + _struct.pack("<q", 100_000)
        + b"\x00"  # 1 output: 100_000 sats, empty spk
        + b"\x00\x00\x00\x00"  # locktime
    )
    cl_ok, _, _ = verify_counter_leg_btc(replace(m2, counter_amount=100_000), btc_claim, cf_tx)
    check("counter value MATCHES agreed -> MAKER_CLAIMED (not anomalous)", cl_ok is CounterLeg.MAKER_CLAIMED)
    cl_bad, _, _ = verify_counter_leg_btc(replace(m2, counter_amount=99_999), btc_claim, cf_tx)
    check("counter value MISMATCH (mispriced) -> ANOMALOUS", cl_bad is CounterLeg.ANOMALOUS)

    # 5d) counter RECIPIENT binding (review HIGH): re-derive the HTLC funding SPK from the agreed keys +
    # H + t_btc; the funding output MUST pay it (so a claim is maker-authorized, not paying the taker).
    import coincurve as _cc

    _cx = _cc.PublicKeyXOnly.from_secret(b"\x11" * 32).format()
    _rx = _cc.PublicKeyXOnly.from_secret(b"\x22" * 32).format()
    _htlc_spk = build_htlc(
        hashlock=bytes.fromhex(m2.h_hex),
        claim_pubkey_xonly=_cx,
        refund_pubkey_xonly=_rx,
        timeout=Timelock(144, TimeUnit.BLOCKS),
    ).scriptpubkey

    def _btc_fund_paying(spk: bytes) -> bytes:
        return (
            _struct.pack("<i", 1)
            + b"\x01"
            + b"\x00" * 32
            + b"\x00\x00\x00\x00"
            + b"\x00"
            + b"\xff\xff\xff\xff"
            + b"\x01"
            + _struct.pack("<q", 100_000)
            + bytes([len(spk)])
            + bytes(spk)
            + b"\x00\x00\x00\x00"
        )

    _m2r = replace(m2, btc_claim_xonly_hex=_cx.hex(), btc_refund_xonly_hex=_rx.hex(), t_btc_blocks=144)
    clr_ok, _, _ = verify_counter_leg_btc(_m2r, btc_claim, _btc_fund_paying(_htlc_spk))
    check("BTC recipient MATCH (funding == re-derived HTLC) -> MAKER_CLAIMED", clr_ok is CounterLeg.MAKER_CLAIMED)
    clr_bad, _, _ = verify_counter_leg_btc(_m2r, btc_claim, _btc_fund_paying(b"\x51\x20" + b"\xff" * 32))
    check("BTC recipient MISMATCH (funding pays a different SPK) -> ANOMALOUS", clr_bad is CounterLeg.ANOMALOUS)

    # 5e) run_verify: a full manifest sets both verified flags true + emits NO NOT_VERIFIED warning; an
    # empty one (the earlier m2 happy path `res`) emits BOTH loud warnings but still PASSes.
    _m2_full = replace(
        m2, counter_amount=100_000, btc_claim_xonly_hex=_cx.hex(), btc_refund_xonly_hex=_rx.hex(), t_btc_blocks=144
    )
    res_full = run_verify(_m2_full, funding2, claim2, btc_claim, counter_funding=_btc_fund_paying(_htlc_spk))
    check(
        "run_verify full counter checks -> PASS, verified flags true, no NOT_VERIFIED warning",
        res_full.verdict is Verdict.PASS
        and res_full.checks["counter_value_verified"] is True
        and res_full.checks["counter_recipient_verified"] is True
        and not any("NOT verified" in r for r in res_full.reasons),
    )
    check(
        "run_verify without counter inputs -> PASS but loud value+recipient NOT_VERIFIED warnings",
        res.verdict is Verdict.PASS
        and res.checks["counter_value_verified"] is False
        and res.checks["counter_recipient_verified"] is False
        and any("VALUE was NOT verified" in r for r in res.reasons)
        and any("RECIPIENT was NOT verified" in r for r in res.reasons),
    )

    # 5c) secret-key guard (review LOW): PRIVATE keys rejected, PUBLIC keys NOT (the bare "key" substring
    # used to false-positive on pubkey/public_key).
    def _rejects(doc: dict) -> bool:
        try:
            assert_no_secrets(doc, what="t")
            return False
        except ValueError:
            return True

    check(
        "secret guard PASSES public-key fields (pubkey/public_key/pkh)",
        not _rejects({"maker_pubkey_hex": "ab" * 33, "claim_public_key": "cd" * 33, "taker_pkh_hex": "ee" * 20}),
    )
    check("secret guard REJECTS a private signing_key", _rejects({"signing_key_hex": "de" * 32}))
    check("secret guard REJECTS a nested privkey", _rejects({"x": {"maker_privkey_hex": "de" * 32}}))

    # 6) ETH counter-leg disposition against synthetic tx/receipt dicts.
    p_eth = b"\xcd" * 32
    h_eth = _sha256(p_eth)
    contract = "0x" + "ab" * 20
    m_eth = RunManifest(
        swap_id="sce",
        asset_variant="rxd",
        counter_chain="eth",
        honest_party="maker",
        h_hex=h_eth.hex(),
        taker_pkh_hex="22" * 20,
        maker_pkh_hex="33" * 20,
        rxd_amount=1000,
        refund_csv=48,
        covenant_funding=Outpoint("ab" * 32, 0),
        eth_contract=contract,
        eth_chain_id=11155111,
    )
    claim_tx = {"input": "0xae1fc8c1" + p_eth.hex(), "to": contract}
    claim_rcpt = {
        "status": 1,
        "logs": [{"address": contract, "topics": [_ETH_CLAIMED_TOPIC], "data": "0x" + p_eth.hex()}],
    }
    refund_rcpt = {"status": 1, "logs": [{"address": contract, "topics": [_ETH_REFUNDED_TOPIC], "data": "0x"}]}
    reverted_rcpt = {"status": 0, "logs": []}
    foreign_rcpt = {
        "status": 1,
        "logs": [{"address": "0x" + "ee" * 20, "topics": [_ETH_CLAIMED_TOPIC], "data": "0x" + p_eth.hex()}],
    }

    e1, e1_digest, _ = verify_counter_leg_eth(m_eth, claim_tx, claim_rcpt)
    check(
        "ETH claim -> MAKER_CLAIMED (digest == H, raw p not returned)",
        e1 is CounterLeg.MAKER_CLAIMED and e1_digest == _sha256(p_eth),
    )
    e2, _, _ = verify_counter_leg_eth(m_eth, {"input": "0x962e097e"}, refund_rcpt)
    check("ETH refund -> TAKER_REFUNDED", e2 is CounterLeg.TAKER_REFUNDED)
    e3, _, _ = verify_counter_leg_eth(m_eth, claim_tx, reverted_rcpt)
    check("ETH reverted claim -> ANOMALOUS", e3 is CounterLeg.ANOMALOUS)
    e4, _, _ = verify_counter_leg_eth(m_eth, claim_tx, foreign_rcpt)
    check("ETH claim from a FOREIGN contract -> ANOMALOUS", e4 is CounterLeg.ANOMALOUS)
    e5, _, _ = verify_counter_leg_eth(m_eth, None, None)
    check("ETH no cited spend -> PENDING", e5 is CounterLeg.PENDING)

    # ETH counter-leg VALUE integrity (review follow-up): the deploy tx's value == the funded wei, bound
    # to OUR contract via the deploy receipt's contractAddress. A mispriced or foreign-contract funding
    # tx is ANOMALOUS, not a silent PASS.
    eth_amt = 10**14
    funding_ok = ({"value": hex(eth_amt)}, {"contractAddress": contract})
    ev1, _, _ = verify_counter_leg_eth(replace(m_eth, counter_amount=eth_amt), claim_tx, claim_rcpt, funding=funding_ok)
    check("ETH counter value MATCHES agreed -> MAKER_CLAIMED", ev1 is CounterLeg.MAKER_CLAIMED)
    ev2, _, _ = verify_counter_leg_eth(
        replace(m_eth, counter_amount=eth_amt + 1), claim_tx, claim_rcpt, funding=funding_ok
    )
    check("ETH counter value MISMATCH (mispriced) -> ANOMALOUS", ev2 is CounterLeg.ANOMALOUS)
    funding_foreign = ({"value": hex(eth_amt)}, {"contractAddress": "0x" + "cc" * 20})
    ev3, _, _ = verify_counter_leg_eth(
        replace(m_eth, counter_amount=eth_amt), claim_tx, claim_rcpt, funding=funding_foreign
    )
    check("ETH funding tx created a DIFFERENT contract -> ANOMALOUS", ev3 is CounterLeg.ANOMALOUS)

    # ETH counter-leg RECIPIENT binding (review HIGH): decode the deploy constructor args (hashlock,
    # claimant, ...) and assert claimant == the agreed maker AND hashlock == H — so a Claimed(p) pays the
    # maker, not the taker. Deploy input = <init code> + 128B args (hashlock, claimant, refundee, timeout).
    _maker_addr = "0x" + "bb" * 20

    def _eth_deploy(hashlock: bytes, claim20: bytes) -> dict:
        args = hashlock + (bytes(12) + claim20) + bytes(32) + (999).to_bytes(32, "big")
        return {"input": "0x" + (b"\xfe" * 20 + args).hex()}

    _m_eth_r = replace(m_eth, eth_maker_claimant=_maker_addr, eth_funding_tx="0x" + "11" * 32)
    evr_ok, _, _ = verify_counter_leg_eth(
        _m_eth_r,
        claim_tx,
        claim_rcpt,
        funding=(_eth_deploy(h_eth, bytes.fromhex("bb" * 20)), {"contractAddress": contract}),
    )
    check("ETH recipient claimant==maker + H match -> MAKER_CLAIMED", evr_ok is CounterLeg.MAKER_CLAIMED)
    evr_bad, _, _ = verify_counter_leg_eth(
        _m_eth_r,
        claim_tx,
        claim_rcpt,
        funding=(_eth_deploy(h_eth, bytes.fromhex("cc" * 20)), {"contractAddress": contract}),
    )
    check("ETH recipient claimant!=maker -> ANOMALOUS", evr_bad is CounterLeg.ANOMALOUS)
    evr_badh, _, _ = verify_counter_leg_eth(
        _m_eth_r,
        claim_tx,
        claim_rcpt,
        funding=(_eth_deploy(b"\x00" * 32, bytes.fromhex("bb" * 20)), {"contractAddress": contract}),
    )
    check("ETH recipient constructor hashlock!=H -> ANOMALOUS", evr_badh is CounterLeg.ANOMALOUS)

    # end-to-end ETH happy path: asset claimed by taker + ETH claimed by maker -> PASS.
    fe_spk, te_holder, me_holder = rxd_expected_scripts(m_eth)
    res_eth = run_verify(m_eth, _rxd_tx(fe_spk), _rxd_tx(te_holder), (claim_tx, claim_rcpt))
    check("end-to-end ETH happy path -> PASS", res_eth.verdict is Verdict.PASS)
    res_eth_fail = run_verify(m_eth, _rxd_tx(fe_spk), _rxd_tx(me_holder), (claim_tx, claim_rcpt))
    check("end-to-end ETH free-option -> FAIL_ONE_SIDED", res_eth_fail.verdict is Verdict.FAIL_ONE_SIDED)

    # 7) lucky-pass margin grade.
    m_marg = RunManifest(
        swap_id="scm",
        asset_variant="rxd",
        counter_chain="btc",
        honest_party="taker",
        h_hex=_sha256(p_stub).hex(),
        taker_pkh_hex="22" * 20,
        maker_pkh_hex="33" * 20,
        rxd_amount=1000,
        refund_csv=48,
        covenant_funding=Outpoint("ab" * 32, 0),
        counter_funding=Outpoint("cd" * 32, 0),
        asset_locked_at_height=1000,
        min_margin_blocks=6,
    )  # rxd_refund_open = 1000 + 48 = 1048
    g_clean, s_clean, _ = margin_grade(m_marg, AssetLeg.TAKER_CLAIMED, CounterLeg.MAKER_CLAIMED, 1030)  # slack 18
    check("margin CLEAN (ample slack)", g_clean == "CLEAN" and s_clean == 18)
    g_marg, s_marg, _ = margin_grade(m_marg, AssetLeg.TAKER_CLAIMED, CounterLeg.MAKER_CLAIMED, 1045)  # slack 3 < 6
    check("margin MARGINAL (slack < min)", g_marg == "MARGINAL" and s_marg == 3)
    g_na, _, _ = margin_grade(m_marg, AssetLeg.MAKER_REFUNDED, CounterLeg.TAKER_REFUNDED, 1030)
    check("margin N/A on the unwind case", g_na == "N/A")
    g_unk, _, _ = margin_grade(m_marg, AssetLeg.TAKER_CLAIMED, CounterLeg.MAKER_CLAIMED, None)
    check("margin UNKNOWN without heights", g_unk == "UNKNOWN")
    # a MARGINAL claim is still a PASS but flagged.
    res_marg = run_verify(
        m_marg,
        _rxd_tx(rxd_expected_scripts(m_marg)[0]),
        _rxd_tx(rxd_expected_scripts(m_marg)[1]),
        _btc_claim_stub(m_marg, p_stub),
        asset_claim_height=1045,
    )
    check(
        "MARGINAL claim still PASS, flagged",
        res_marg.verdict is Verdict.PASS and res_marg.checks["margin"]["grade"] == "MARGINAL",
    )

    print()
    if failures:
        print(f"SELF-CHECK FAILED: {len(failures)} check(s) failed")
        return 1
    print("SELF-CHECK PASSED")
    return 0


def _btc_claim_stub(m: RunManifest, p: bytes) -> bytes:
    """A minimal raw segwit BTC tx that (a) spends our counter funding outpoint and (b) carries `p` in the
    witness so scrape_secret recovers it. Self-check only; `p` is a throwaway test value, not a real key."""
    import struct

    version = struct.pack("<i", 2)
    marker_flag = b"\x00\x01"
    vin = b"\x01" + m.counter_funding.prevout_le_bytes() + b"\x00" + b"\xfd\xff\xff\xff"  # empty scriptSig, nSeq
    vout = b"\x01" + struct.pack("<q", 1000) + b"\x16\x00\x14" + b"\x44" * 20  # 1 P2WPKH-ish output
    witness = b"\x03" + b"\x40" + b"\x55" * 0x40 + b"\x20" + p + b"\x01" + b"\x51"  # [sig, p(32), script]
    locktime = b"\x00\x00\x00\x00"
    return version + marker_flag + vin + vout + witness + locktime


# --------------------------------------------------------------------------- CLI


def _load_json(path: str) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


async def _run_cli(args: argparse.Namespace) -> int:
    manifest_doc = _load_json(args.manifest)
    journals = [_load_json(p) for p in args.journal]
    # 1) validity gate: no secrets anywhere in the public package.
    assert_no_secrets(manifest_doc, what="manifest")
    for i, j in enumerate(journals):
        assert_no_secrets(j, what=f"journal[{i}]")
    m = RunManifest.from_dict(manifest_doc)
    verifier_urls = [args.rxd_electrumx_url] + (
        [args.btc_esplora_url] if m.counter_chain == "btc" else [args.eth_rpc_url]
    )
    assert_independent_endpoints([u for u in verifier_urls if u], m.party_endpoints)

    # 2) the only journal-trusted data: cited spend txids (cross-checked between both journals if present).
    cited = dict(manifest_doc.get("cited", {}))
    for j in journals:
        for k, v in (j.get("cited", {}) or {}).items():
            if k in cited and cited[k] != v:
                print(f"INVALID: parties disagree on cited {k!r} ({cited[k]} vs {v})", file=sys.stderr)
                return 3
            cited.setdefault(k, v)

    # 3) re-fetch from independent sources + verify.
    cov_fund, cov_spend, counter_obj, counter_funding, asset_claim_height = await _fetch_for_live(
        m,
        cited,
        args.btc_esplora_url,
        args.rxd_electrumx_url,
        args.eth_rpc_url,
        min_confirmations=args.min_confirmations,
    )
    res = run_verify(
        m,
        cov_fund,
        cov_spend,
        counter_obj,
        asset_claim_height=asset_claim_height,
        counter_funding=counter_funding,
    )
    print(json.dumps(res.as_dict(), indent=2))
    return (
        0 if res.verdict is Verdict.PASS else (2 if res.verdict in (Verdict.FAIL_ONE_SIDED, Verdict.ANOMALOUS) else 4)
    )


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Chain-re-derivation verifier for two-party adversarial swap runs.")
    ap.add_argument("--self-check", action="store_true", help="run offline engine tests (no network) and exit")
    ap.add_argument("--manifest", help="run manifest JSON (public terms + cited outpoints)")
    ap.add_argument("--journal", action="append", default=[], help="party journal JSON (repeatable; expects 2)")
    ap.add_argument("--rxd-electrumx-url", help="an RXD ElectrumX NEITHER party ran")
    ap.add_argument("--btc-esplora-url", help="an Esplora NEITHER party ran (btc counter leg)")
    ap.add_argument("--eth-rpc-url", help="an ETH RPC NEITHER party ran (eth counter leg)")
    ap.add_argument(
        "--min-confirmations",
        type=int,
        default=1,
        help="min burial depth a cited/discovered spend must have on the independent source before it is "
        "scored (default 1 = MINED-only, fine for regtest/testnet). REAL-VALUE runs MUST set this DEEP "
        "(e.g. 6+ BTC / a value-scaled RXD depth): a shallow, source-trusted disposition is reorgable, so a "
        "PASS on a 1-conf claim that later reorgs is a real one-sided loss.",
    )
    args = ap.parse_args(argv)

    if args.self_check:
        return _self_check()
    if not args.manifest or not args.journal or not args.rxd_electrumx_url:
        ap.error("live verification needs --manifest, --journal (>=1), and --rxd-electrumx-url")
    # the counter-chain source is required for that chain; we can't know which until the manifest is read,
    # so validate inside _run_cli is awkward — peek the counter_chain here.
    cc = _load_json(args.manifest).get("counter_chain")
    if cc == "btc" and not args.btc_esplora_url:
        ap.error("btc counter leg needs --btc-esplora-url (an Esplora neither party ran)")
    if cc == "eth" and not args.eth_rpc_url:
        ap.error("eth counter leg needs --eth-rpc-url (an ETH RPC neither party ran)")
    return asyncio.run(_run_cli(args))


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
